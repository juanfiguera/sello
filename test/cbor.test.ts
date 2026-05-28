import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { cborTag, decodeCbor, encodeCbor } from "../src/cbor.ts";
import { toHex } from "../src/crypto/identifiers.ts";

describe("deterministic CBOR subset", () => {
  it("encodes common primitive values", () => {
    assert.equal(toHex(encodeCbor(0)), "00");
    assert.equal(toHex(encodeCbor(23)), "17");
    assert.equal(toHex(encodeCbor(24)), "1818");
    assert.equal(toHex(encodeCbor(-1)), "20");
    assert.equal(toHex(encodeCbor("sello")), "6573656c6c6f");
    assert.equal(toHex(encodeCbor(new Uint8Array([1, 2, 3]))), "43010203");
    assert.equal(toHex(encodeCbor(["sello", 1])), "826573656c6c6f01");
  });

  it("encodes tag 0 timestamps", () => {
    assert.equal(
      toHex(encodeCbor(cborTag(0, "2026-05-27T14:32:11Z"))),
      "c074323032362d30352d32375431343a33323a31315a",
    );
  });

  it("sorts map keys by deterministic CBOR key encoding", () => {
    const value = new Map([
      ["b", 2],
      ["a", 1],
    ]);

    assert.equal(toHex(encodeCbor(value)), "a2616101616202");
  });

  it("decodes deterministic maps", () => {
    const decoded = decodeCbor(Uint8Array.from([0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]));

    assert.deepEqual(decoded, new Map([["a", 1], ["b", 2]]));
  });

  it("decodes arrays", () => {
    assert.deepEqual(
      decodeCbor(Uint8Array.from([0x82, 0x65, 0x73, 0x65, 0x6c, 0x6c, 0x6f, 0x01])),
      ["sello", 1],
    );
  });

  it("rejects non-minimal lengths", () => {
    assert.throws(
      () => decodeCbor(Uint8Array.from([0x78, 0x01, 0x61])),
      /not minimally encoded/,
    );
  });

  it("rejects maps not in deterministic order", () => {
    assert.throws(
      () => decodeCbor(Uint8Array.from([0xa2, 0x61, 0x62, 0x02, 0x61, 0x61, 0x01])),
      /deterministic order/,
    );
  });
});
