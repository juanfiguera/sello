import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AGENT_IDENTIFIER_HEX_LENGTH,
  SHA256_DIGEST_LENGTH,
  assertAgentIdentifier,
  assertTokenRef,
  deriveTokenIdentifiers,
  isAgentIdentifier,
  isTokenRef,
  sha256,
  toHex,
} from "../../src/crypto/identifiers.ts";

const textEncoder = new TextEncoder();

function bytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

describe("sha256", () => {
  it("computes the standard SHA-256 digest", () => {
    assert.equal(
      toHex(sha256(bytes("abc"))),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("deriveTokenIdentifiers", () => {
  it("derives a 32-byte token ref and 32-char agent identifier", () => {
    const identifiers = deriveTokenIdentifiers(bytes("header.payload.signature"));

    assert.equal(identifiers.sello_token_ref.byteLength, SHA256_DIGEST_LENGTH);
    assert.equal(
      identifiers.agent_identifier.length,
      AGENT_IDENTIFIER_HEX_LENGTH,
    );
    assert.match(identifiers.agent_identifier, /^[0-9a-f]{32}$/);
  });

  it("is deterministic for the same token bytes", () => {
    const first = deriveTokenIdentifiers(bytes("header.payload.signature"));
    const second = deriveTokenIdentifiers(bytes("header.payload.signature"));

    assert.equal(toHex(first.sello_token_ref), toHex(second.sello_token_ref));
    assert.equal(first.agent_identifier, second.agent_identifier);
  });

  it("changes when the exact token bytes change", () => {
    const first = deriveTokenIdentifiers(bytes("header.payload.signature"));
    const second = deriveTokenIdentifiers(bytes("header.payload.signature "));

    assert.notEqual(toHex(first.sello_token_ref), toHex(second.sello_token_ref));
    assert.notEqual(first.agent_identifier, second.agent_identifier);
  });

  it("derives agent-identifier from the first 16 digest bytes", () => {
    const identifiers = deriveTokenIdentifiers(bytes("header.payload.signature"));
    const expected = toHex(identifiers.sello_token_ref.subarray(0, 16));

    assert.equal(identifiers.agent_identifier, expected);
  });

  it("uses raw bytes rather than JSON reserialization semantics", () => {
    const first = deriveTokenIdentifiers(bytes('{"sub":"agent","scope":"read"}'));
    const second = deriveTokenIdentifiers(bytes('{"scope":"read","sub":"agent"}'));

    assert.notEqual(toHex(first.sello_token_ref), toHex(second.sello_token_ref));
  });

  it("rejects non-byte token input at runtime", () => {
    assert.throws(
      () => deriveTokenIdentifiers("header.payload.signature" as unknown as Uint8Array),
      /authorizationTokenBytes must be a Uint8Array/,
    );
  });
});

describe("token ref validation", () => {
  it("accepts 32-byte token refs", () => {
    const value = new Uint8Array(32);

    assert.equal(isTokenRef(value), true);
    assert.doesNotThrow(() => assertTokenRef(value));
  });

  it("rejects non-32-byte token refs", () => {
    assert.equal(isTokenRef(new Uint8Array(31)), false);
    assert.throws(() => assertTokenRef(new Uint8Array(31)), /32-byte/);
  });
});

describe("agent identifier validation", () => {
  it("accepts 32-character lowercase hex identifiers", () => {
    const value = "0123456789abcdef0123456789abcdef";

    assert.equal(isAgentIdentifier(value), true);
    assert.doesNotThrow(() => assertAgentIdentifier(value));
  });

  it("rejects uppercase, non-hex, and wrong-length identifiers", () => {
    assert.equal(isAgentIdentifier("0123456789ABCDEF0123456789ABCDEF"), false);
    assert.equal(isAgentIdentifier("0123456789abcdef0123456789abcdeg"), false);
    assert.equal(isAgentIdentifier("0123456789abcdef"), false);

    assert.throws(
      () => assertAgentIdentifier("0123456789ABCDEF0123456789ABCDEF"),
      /lowercase hex/,
    );
  });
});
