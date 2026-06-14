import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { generateEd25519KeyPair } from "../../src/cose/sign1.ts";
import { toHex } from "../../src/crypto/identifiers.ts";
import { generateHpkeKeyPair } from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";
import { verifyReceipts } from "../../src/owner/verify.ts";
import { ZERO_SHA256_DIGEST } from "../../src/receipt/body.ts";
import {
  base64urlEncode,
  signSelloJwsToken,
} from "../../src/token/jws-profile.ts";
import {
  loadSignedRegistry,
  signRegistryJson,
} from "../../src/registry/json-registry.ts";
import {
  createReceipt,
  createReceiptFromJwsToken,
} from "../../src/service/create-receipt.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const otherLogUrl = "https://other-rekor.example.com/api" as CanonicalLogUrl;

describe("service receipt creation", () => {
  it("creates a receipt accepted by owner verification", () => {
    const fixture = makeFixture();

    createReceipt(fixture.createInput());
    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 1);
    assert.equal(result.receipts[0].receipt["result-status"], "success");
  });

  it("creates a receipt from a verified compact JWS token", () => {
    const fixture = makeFixture();

    createReceiptFromJwsToken(fixture.createJwsInput());
    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 1);
    assert.equal(result.receipts[0].receipt["result-status"], "success");
  });

  it("refuses to read token claims when the compact JWS signature fails", () => {
    const fixture = makeFixture();
    const otherIssuer = generateEd25519KeyPair();
    const badToken = signSelloJwsToken({
      issuerPrivateKey: otherIssuer.privateKey,
      payload: {
        owner_hpke_pk: "not-a-key",
        sello_logs: ["https://Rekor.example.com/api"],
      },
    });

    assert.throws(
      () =>
        createReceiptFromJwsToken(
          fixture.createJwsInput({
            authorizationToken: badToken,
          }),
        ),
      /signature verification failed/,
    );
  });

  it("uses fallback trusted logs only when the verified token omits sello_logs", () => {
    const fixture = makeFixture();
    const tokenWithoutLogs = signSelloJwsToken({
      issuerPrivateKey: fixture.tokenIssuer.privateKey,
      payload: {
        owner_hpke_pk: base64urlEncode(fixture.owner.publicKey),
      },
    });

    createReceiptFromJwsToken(
      fixture.createJwsInput({
        authorizationToken: tokenWithoutLogs,
        fallbackSelloLogs: [logUrl],
      }),
    );
    const result = verifyReceipts(
      fixture.ownerInput({
        authorizationTokenBytes: textEncoder.encode(tokenWithoutLogs),
      }),
    );

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 1);
  });

  it("creates denied receipts with an all-zero output hash", () => {
    const fixture = makeFixture();

    const created = createReceipt(
      fixture.createInput({
        resultStatus: "denied",
        actionOutputBytes: textEncoder.encode("ignored output"),
      }),
    );

    assert.deepEqual(created.receiptBody["action-output-hash"], ZERO_SHA256_DIGEST);
  });

  it("refuses malformed owner HPKE public keys", () => {
    const fixture = makeFixture();

    assert.throws(
      () =>
        createReceipt(
          fixture.createInput({
            ownerHpkePublicKey: new Uint8Array(31),
          }),
        ),
      /ownerHpkePublicKey must be a 32-byte Uint8Array/,
    );
  });

  it("refuses malformed sello_logs entries", () => {
    const fixture = makeFixture();

    assert.throws(
      () =>
        createReceipt(
          fixture.createInput({
            selloLogs: ["https://Rekor.example.com/api"],
          }),
        ),
      /host must be lowercase/,
    );
  });

  it("refuses logs not listed in sello_logs", () => {
    const fixture = makeFixture();

    assert.throws(
      () =>
        createReceipt(
          fixture.createInput({
            selloLogs: [otherLogUrl],
          }),
        ),
      /service log must be listed/,
    );
  });

  it("fails explicitly when no owner-trusted log is available", () => {
    const fixture = makeFixture();

    assert.throws(
      () =>
        createReceipt(
          fixture.createInput({
            selloLogs: [],
          }),
        ),
      /at least one owner-trusted log/,
    );
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("svc-key-1");
  const log = new MockTransparencyLog(logUrl);
  const serviceIdentifier = "github.com/mcp/v1";
  const authorizationToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      owner_hpke_pk: base64urlEncode(owner.publicKey),
      sello_logs: [logUrl],
    },
  });
  const registryBytes = textEncoder.encode(
    JSON.stringify({
      [toHex(serviceKid)]: {
        service_identifier: serviceIdentifier,
        public_key_ed25519: Buffer.from(service.publicKey).toString("base64url"),
      },
    }),
  );
  const registry = loadSignedRegistry({
    registryBytes,
    signatureBase64Url: signRegistryJson(registryBytes, trustRoot.privateKey),
    trustRootPublicKey: trustRoot.publicKey,
  });

  return {
    owner,
    tokenIssuer,
    createInput: (
      overrides: Partial<Parameters<typeof createReceipt>[0]> = {},
    ): Parameters<typeof createReceipt>[0] => ({
      authorizationTokenBytes: textEncoder.encode(authorizationToken),
      ownerHpkePublicKey: owner.publicKey,
      selloLogs: [logUrl],
      serviceKid,
      servicePrivateKey: service.privateKey,
      serviceIdentifier,
      log,
      actionType: "tools/call",
      actionInputBytes: textEncoder.encode("input"),
      actionOutputBytes: textEncoder.encode("output"),
      resultStatus: "success",
      timestamp: "2026-05-28T10:00:00Z",
      ...overrides,
    }),
    createJwsInput: (
      overrides: Partial<Parameters<typeof createReceiptFromJwsToken>[0]> = {},
    ): Parameters<typeof createReceiptFromJwsToken>[0] => ({
      authorizationToken,
      tokenIssuerPublicKey: tokenIssuer.publicKey,
      serviceKid,
      servicePrivateKey: service.privateKey,
      serviceIdentifier,
      log,
      actionType: "tools/call",
      actionInputBytes: textEncoder.encode("input"),
      actionOutputBytes: textEncoder.encode("output"),
      resultStatus: "success",
      timestamp: "2026-05-28T10:00:00Z",
      ...overrides,
    }),
    ownerInput: (
      overrides: Partial<Parameters<typeof verifyReceipts>[0]> = {},
    ) => ({
      authorizationTokenBytes: textEncoder.encode(authorizationToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
      ...overrides,
    }),
  };
}
