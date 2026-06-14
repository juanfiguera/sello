import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeCbor } from "../../src/cbor.ts";
import { encodeProtectedHeader } from "../../src/cose/protected-header.ts";
import {
  decodeReceiptEnvelope,
  generateEd25519KeyPair,
  signReceiptEnvelope,
} from "../../src/cose/sign1.ts";
import { deriveTokenIdentifiers, sha256, toHex } from "../../src/crypto/identifiers.ts";
import { generateHpkeKeyPair, sealReceiptBody } from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";
import { verifyReceipts } from "../../src/owner/verify.ts";
import { encodeReceiptBody, type ReceiptBody } from "../../src/receipt/body.ts";
import {
  loadSignedRegistry,
  signRegistryJson,
} from "../../src/registry/json-registry.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const otherLogUrl = "https://other-rekor.example.com/api" as CanonicalLogUrl;
const tokenBytes = textEncoder.encode("compact.jws.token");

describe("owner receipt verification", () => {
  it("verifies one receipt end to end", () => {
    const fixture = makeFixture();
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");

    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 1);
    assert.equal(result.receipts[0].status, "valid");
    assert.equal(result.receipts[0].receipt["action-type"], "tools/call");
    assert.equal(result.receipts[0].serviceIdentifier, "github.com/mcp/v1");
    assert.equal(result.receipts[0].logCompleteness, "complete");
  });

  it("rejects receipts returned by a different trusted log than the signed log URL", () => {
    const fixture = makeFixture({ headerLogUrl: otherLogUrl });
    const fakeLog = {
      logUrl,
      queryByTokenRef: () => ({
        completeness: "complete" as const,
        entries: [
          {
            logUrl,
            index: 0,
            integratedTime: "2026-05-28T10:00:02Z",
            envelope: fixture.envelope,
            proof: {
              logUrl,
              index: 0,
              integratedTime: "2026-05-28T10:00:02Z",
              envelopeHash: "",
              proofHash: "",
            },
          },
        ],
      }),
      verifyInclusionProof: () => true,
    };

    const result = verifyReceipts({
      ...fixture.ownerInput(),
      trustedLogs: [fakeLog, new MockTransparencyLog(otherLogUrl)],
    });

    assert.equal(result.receipts.length, 0);
    assert.equal(result.rejected[0].code, "log_url_mismatch");
  });

  it("rejects bad COSE signatures after proof verification", () => {
    const fixture = makeFixture();
    const decoded = decodeReceiptEnvelope(fixture.envelope);
    const badEnvelope = encodeCbor([
      decoded.protectedBytes,
      new Map(),
      textEncoder.encode("tampered payload"),
      decoded.signature,
    ]);
    fixture.log.append(badEnvelope, "2026-05-28T10:00:02Z");

    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.receipts.length, 0);
    assert.equal(result.rejected[0].code, "cose_signature_failed");
  });

  it("returns no receipts for the wrong token", () => {
    const fixture = makeFixture();
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");

    const result = verifyReceipts({
      ...fixture.ownerInput(),
      authorizationTokenBytes: textEncoder.encode("other.compact.jws.token"),
    });

    assert.equal(result.receipts.length, 0);
    assert.equal(result.rejected.length, 0);
  });

  it("rejects revoked keys using integrated time", () => {
    const fixture = makeFixture({
      revokedAt: "2026-05-28T10:00:00Z",
    });
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");

    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.receipts.length, 0);
    assert.equal(result.rejected[0].code, "revoked_key");
  });

  it("reports HPKE open failures", () => {
    const fixture = makeFixture();
    const wrongOwner = generateHpkeKeyPair();
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");

    const result = verifyReceipts({
      ...fixture.ownerInput(),
      ownerPrivateKey: wrongOwner.privateKey,
    });

    assert.equal(result.receipts.length, 0);
    assert.equal(result.rejected[0].code, "hpke_open_failed");
  });

  it("does not print decrypted receipt contents on verification failures", () => {
    const fixture = makeFixture();
    const decoded = decodeReceiptEnvelope(fixture.envelope);
    fixture.log.append(
      encodeCbor([
        decoded.protectedBytes,
        new Map(),
        textEncoder.encode("tampered payload"),
        decoded.signature,
      ]),
      "2026-05-28T10:00:02Z",
    );
    const messages: unknown[][] = [];
    const originalLog = console.log;
    const originalWarn = console.warn;
    const originalError = console.error;

    console.log = (...args: unknown[]) => messages.push(args);
    console.warn = (...args: unknown[]) => messages.push(args);
    console.error = (...args: unknown[]) => messages.push(args);

    try {
      verifyReceipts(fixture.ownerInput());
    } finally {
      console.log = originalLog;
      console.warn = originalWarn;
      console.error = originalError;
    }

    assert.deepEqual(messages, []);
  });

  it("preserves same-second distinct activity", () => {
    const fixture = makeFixture();
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");
    fixture.log.append(
      fixture.createEnvelope({
        receipt: makeReceipt(fixture.identifiers, {
          outputText: "different output",
        }),
      }),
      "2026-05-28T10:00:03Z",
    );

    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 2);
    assert.equal(result.receipts[0].sameSecondActivity, true);
    assert.equal(result.receipts[1].sameSecondActivity, true);
    assert.equal(result.receipts[1].status, "valid");
  });

  it("marks exact duplicates without treating them as cryptographic failures", () => {
    const fixture = makeFixture();
    fixture.log.append(fixture.envelope, "2026-05-28T10:00:02Z");
    fixture.log.append(
      fixture.createEnvelope({ receipt: fixture.receipt }),
      "2026-05-28T10:00:03Z",
    );

    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 2);
    assert.equal(result.receipts[0].status, "valid");
    assert.equal(result.receipts[1].status, "duplicate");
    assert.equal(result.receipts[1].duplicateOf, 0);
  });
});

function makeFixture(options: {
  headerLogUrl?: CanonicalLogUrl;
  revokedAt?: string;
} = {}) {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const kid = textEncoder.encode("svc-key-1");
  const identifiers = deriveTokenIdentifiers(tokenBytes);
  const receipt = makeReceipt(identifiers);
  const log = new MockTransparencyLog(logUrl);
  const serviceIdentifier = "github.com/mcp/v1";

  function createEnvelope(input: { receipt: ReceiptBody }) {
    const protectedHeaderBytes = encodeProtectedHeader({
      kid,
      sello_token_ref: identifiers.sello_token_ref,
      sello_log_url: options.headerLogUrl ?? logUrl,
    });
    const payload = sealReceiptBody({
      plaintext: encodeReceiptBody(input.receipt),
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: identifiers.sello_token_ref,
    });

    return signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });
  }

  const registryValue: Record<string, unknown> = {
    [toHex(kid)]: {
      service_identifier: serviceIdentifier,
      public_key_ed25519: Buffer.from(service.publicKey).toString("base64url"),
    },
  };

  if (options.revokedAt) {
    registryValue.revoked = {
      [toHex(kid)]: {
        revoked_at: options.revokedAt,
      },
    };
  }

  const registryBytes = textEncoder.encode(JSON.stringify(registryValue));
  const registry = loadSignedRegistry({
    registryBytes,
    signatureBase64Url: signRegistryJson(registryBytes, trustRoot.privateKey),
    trustRootPublicKey: trustRoot.publicKey,
  });

  return {
    identifiers,
    receipt,
    envelope: createEnvelope({ receipt }),
    log,
    createEnvelope,
    ownerInput: () => ({
      authorizationTokenBytes: tokenBytes,
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}

function makeReceipt(
  identifiers: ReturnType<typeof deriveTokenIdentifiers>,
  overrides: { outputText?: string } = {},
): ReceiptBody {
  return {
    "agent-identifier": identifiers.agent_identifier,
    "action-type": "tools/call",
    "action-input-hash": sha256(textEncoder.encode("input")),
    "action-output-hash": sha256(textEncoder.encode(overrides.outputText ?? "output")),
    "result-status": "success",
    timestamp: "2026-05-28T10:00:00Z",
  };
}
