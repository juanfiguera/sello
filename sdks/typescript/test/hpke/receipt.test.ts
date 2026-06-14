import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeProtectedHeader } from "../../src/cose/protected-header.ts";
import {
  buildReceiptHpkeInfo,
  generateHpkeKeyPair,
  openReceiptBody,
  sealReceiptBody,
} from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";

const tokenRef = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
const otherTokenRef = Uint8Array.from({ length: 32 }, (_, index) => index);
const serviceIdentifier = "github.com/mcp/v1";
const protectedHeaderBytes = encodeProtectedHeader({
  kid: new TextEncoder().encode("svc-key-1"),
  sello_token_ref: tokenRef,
  sello_log_url: "https://rekor.example.com/api" as CanonicalLogUrl,
});

describe("receipt HPKE sealing", () => {
  it("builds stable Sello HPKE info", () => {
    assert.equal(
      toHex(buildReceiptHpkeInfo(serviceIdentifier, tokenRef)).slice(0, 44),
      "837373656c6c6f2f302e312e302f7265636569707471",
    );
  });

  it("seals and opens a receipt body for the owner key", () => {
    const owner = generateHpkeKeyPair();
    const plaintext = new TextEncoder().encode("encoded receipt body");
    const payload = sealReceiptBody({
      plaintext,
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    const opened = openReceiptBody({
      payload,
      ownerPrivateKey: owner.privateKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    assert.deepEqual(opened, plaintext);
    assert.equal(payload.subarray(0, 32).byteLength, 32);
  });

  it("fails with the wrong owner key", () => {
    const owner = generateHpkeKeyPair();
    const otherOwner = generateHpkeKeyPair();
    const payload = sealReceiptBody({
      plaintext: new TextEncoder().encode("encoded receipt body"),
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    assert.throws(
      () =>
        openReceiptBody({
          payload,
          ownerPrivateKey: otherOwner.privateKey,
          protectedHeaderBytes,
          serviceIdentifier,
          selloTokenRef: tokenRef,
        }),
      /HPKE open failed/,
    );
  });

  it("fails with the wrong protected header AAD", () => {
    const owner = generateHpkeKeyPair();
    const payload = sealReceiptBody({
      plaintext: new TextEncoder().encode("encoded receipt body"),
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    assert.throws(
      () =>
        openReceiptBody({
          payload,
          ownerPrivateKey: owner.privateKey,
          protectedHeaderBytes: new TextEncoder().encode("different protected header"),
          serviceIdentifier,
          selloTokenRef: tokenRef,
        }),
      /HPKE open failed/,
    );
  });

  it("fails with the wrong service identifier in HPKE info", () => {
    const owner = generateHpkeKeyPair();
    const payload = sealReceiptBody({
      plaintext: new TextEncoder().encode("encoded receipt body"),
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    assert.throws(
      () =>
        openReceiptBody({
          payload,
          ownerPrivateKey: owner.privateKey,
          protectedHeaderBytes,
          serviceIdentifier: "github.com/admin/v1",
          selloTokenRef: tokenRef,
        }),
      /HPKE open failed/,
    );
  });

  it("fails with the wrong token ref in HPKE info", () => {
    const owner = generateHpkeKeyPair();
    const payload = sealReceiptBody({
      plaintext: new TextEncoder().encode("encoded receipt body"),
      ownerPublicKey: owner.publicKey,
      protectedHeaderBytes,
      serviceIdentifier,
      selloTokenRef: tokenRef,
    });

    assert.throws(
      () =>
        openReceiptBody({
          payload,
          ownerPrivateKey: owner.privateKey,
          protectedHeaderBytes,
          serviceIdentifier,
          selloTokenRef: otherTokenRef,
        }),
      /HPKE open failed/,
    );
  });

  it("rejects too-short Sello HPKE payloads", () => {
    const owner = generateHpkeKeyPair();

    assert.throws(
      () =>
        openReceiptBody({
          payload: new Uint8Array(48),
          ownerPrivateKey: owner.privateKey,
          protectedHeaderBytes,
          serviceIdentifier,
          selloTokenRef: tokenRef,
        }),
      /at least 49 bytes/,
    );
  });
});

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
