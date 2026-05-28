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
  loadSignedRegistry,
  signRegistryJson,
} from "../../src/registry/json-registry.ts";
import { createReceipt } from "../../src/service/create-receipt.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const otherLogUrl = "https://other-rekor.example.com/api" as CanonicalLogUrl;
const tokenBytes = textEncoder.encode("compact.jws.token");

describe("service receipt creation", () => {
  it("creates a receipt accepted by owner verification", () => {
    const fixture = makeFixture();

    createReceipt(fixture.createInput());
    const result = verifyReceipts(fixture.ownerInput());

    assert.equal(result.rejected.length, 0);
    assert.equal(result.receipts.length, 1);
    assert.equal(result.receipts[0].receipt["result-status"], "success");
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
  const serviceKid = textEncoder.encode("svc-key-1");
  const log = new MockTransparencyLog(logUrl);
  const serviceIdentifier = "github.com/mcp/v1";
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
    createInput: (
      overrides: Partial<Parameters<typeof createReceipt>[0]> = {},
    ): Parameters<typeof createReceipt>[0] => ({
      authorizationTokenBytes: tokenBytes,
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
    ownerInput: () => ({
      authorizationTokenBytes: tokenBytes,
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}
