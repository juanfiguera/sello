import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeCbor } from "../../src/cbor.ts";
import { encodeProtectedHeader } from "../../src/cose/protected-header.ts";
import {
  buildSigStructure,
  decodeReceiptEnvelope,
  generateEd25519KeyPair,
  signReceiptEnvelope,
  verifyReceiptEnvelope,
} from "../../src/cose/sign1.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";

const tokenRef = Uint8Array.from({ length: 32 }, (_, index) => index);
const protectedHeaderBytes = encodeProtectedHeader({
  kid: new TextEncoder().encode("svc-key-1"),
  sello_token_ref: tokenRef,
  sello_log_url: "https://rekor.example.com/api" as CanonicalLogUrl,
});
const payload = new TextEncoder().encode("hpke payload bytes");

describe("COSE_Sign1 receipt envelope", () => {
  it("signs and verifies an embedded payload", () => {
    const service = generateEd25519KeyPair();
    const envelope = signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });

    const verified = verifyReceiptEnvelope({
      envelope,
      servicePublicKey: service.publicKey,
    });

    assert.deepEqual(verified.protectedBytes, protectedHeaderBytes);
    assert.deepEqual(verified.payload, payload);
    assert.equal(verified.signature.byteLength, 64);
  });

  it("builds the COSE Sig_structure with empty external AAD", () => {
    assert.equal(
      toHex(buildSigStructure(new Uint8Array([0xa1, 0x01, 0x27]), new Uint8Array([0x01, 0x02]))),
      "846a5369676e61747572653143a1012740420102",
    );
  });

  it("rejects tampered payload bytes", () => {
    const service = generateEd25519KeyPair();
    const envelope = signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });
    const decoded = decodeReceiptEnvelope(envelope);
    const tampered = encodeCbor([
      decoded.protectedBytes,
      new Map(),
      new TextEncoder().encode("tampered"),
      decoded.signature,
    ]);

    assert.throws(
      () =>
        verifyReceiptEnvelope({
          envelope: tampered,
          servicePublicKey: service.publicKey,
        }),
      /signature verification failed/,
    );
  });

  it("rejects tampered protected header bytes", () => {
    const service = generateEd25519KeyPair();
    const envelope = signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });
    const decoded = decodeReceiptEnvelope(envelope);
    const otherProtectedHeader = encodeProtectedHeader({
      kid: new TextEncoder().encode("svc-key-1"),
      sello_token_ref: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
      sello_log_url: "https://rekor.example.com/api" as CanonicalLogUrl,
    });
    const tampered = encodeCbor([
      otherProtectedHeader,
      new Map(),
      decoded.payload,
      decoded.signature,
    ]);

    assert.throws(
      () =>
        verifyReceiptEnvelope({
          envelope: tampered,
          servicePublicKey: service.publicKey,
        }),
      /signature verification failed/,
    );
  });

  it("rejects the wrong service public key", () => {
    const service = generateEd25519KeyPair();
    const otherService = generateEd25519KeyPair();
    const envelope = signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });

    assert.throws(
      () =>
        verifyReceiptEnvelope({
          envelope,
          servicePublicKey: otherService.publicKey,
        }),
      /signature verification failed/,
    );
  });

  it("rejects non-empty unprotected headers", () => {
    const service = generateEd25519KeyPair();
    const envelope = signReceiptEnvelope({
      protectedHeaderBytes,
      payload,
      servicePrivateKey: service.privateKey,
    });
    const decoded = decodeReceiptEnvelope(envelope);
    const withUnprotectedHeader = encodeCbor([
      decoded.protectedBytes,
      new Map([[1, 2]]),
      decoded.payload,
      decoded.signature,
    ]);

    assert.throws(
      () => decodeReceiptEnvelope(withUnprotectedHeader),
      /unprotected header must be empty/,
    );
  });

  it("rejects detached or non-byte payload shapes", () => {
    const signature = new Uint8Array(64);

    assert.throws(
      () =>
        decodeReceiptEnvelope(
          encodeCbor([protectedHeaderBytes, new Map(), "detached", signature]),
        ),
      /payload must be a Uint8Array/,
    );
  });

  it("rejects malformed COSE arrays", () => {
    assert.throws(
      () => decodeReceiptEnvelope(encodeCbor([protectedHeaderBytes, new Map(), payload])),
      /4-element array/,
    );

    assert.throws(
      () => decodeReceiptEnvelope(encodeCbor(new Map())),
      /4-element array/,
    );
  });
});

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
