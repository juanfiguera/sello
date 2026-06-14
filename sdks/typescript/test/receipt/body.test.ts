import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { cborTag, encodeCbor } from "../../src/cbor.ts";
import { sha256, toHex } from "../../src/crypto/identifiers.ts";
import {
  ZERO_SHA256_DIGEST,
  type ReceiptBody,
  decodeReceiptBody,
  encodeReceiptBody,
  validateReceiptBody,
} from "../../src/receipt/body.ts";

const textEncoder = new TextEncoder();

function bytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function digest(value: string): Uint8Array {
  return sha256(bytes(value));
}

function successReceipt(): ReceiptBody {
  return {
    "agent-identifier": "0123456789abcdef0123456789abcdef",
    "action-type": "tools/call",
    "action-input-hash": digest("input"),
    "action-output-hash": digest("output"),
    "result-status": "success",
    timestamp: "2026-05-27T14:32:11Z",
  };
}

describe("receipt body encoding", () => {
  it("round-trips a success receipt", () => {
    const receipt = successReceipt();
    const decoded = decodeReceiptBody(encodeReceiptBody(receipt));

    assert.equal(decoded["agent-identifier"], receipt["agent-identifier"]);
    assert.equal(decoded["action-type"], receipt["action-type"]);
    assert.equal(toHex(decoded["action-input-hash"]), toHex(receipt["action-input-hash"]));
    assert.equal(toHex(decoded["action-output-hash"]), toHex(receipt["action-output-hash"]));
    assert.equal(decoded["result-status"], "success");
    assert.equal(decoded.timestamp, receipt.timestamp);
  });

  it("round-trips an error receipt", () => {
    const receipt: ReceiptBody = {
      ...successReceipt(),
      "action-type": "issues.create",
      "result-status": "error",
    };

    assert.equal(decodeReceiptBody(encodeReceiptBody(receipt))["result-status"], "error");
  });

  it("round-trips a denied receipt with all-zero output hash", () => {
    const receipt: ReceiptBody = {
      ...successReceipt(),
      "action-type": "repo.delete",
      "action-output-hash": ZERO_SHA256_DIGEST,
      "result-status": "denied",
    };

    const decoded = decodeReceiptBody(encodeReceiptBody(receipt));

    assert.equal(decoded["result-status"], "denied");
    assert.equal(toHex(decoded["action-output-hash"]), "00".repeat(32));
  });

  it("emits deterministic CBOR independent of JavaScript construction order", () => {
    const first = successReceipt();
    const second = {
      timestamp: first.timestamp,
      "result-status": first["result-status"],
      "action-output-hash": first["action-output-hash"],
      "action-input-hash": first["action-input-hash"],
      "action-type": first["action-type"],
      "agent-identifier": first["agent-identifier"],
    } as ReceiptBody;

    assert.equal(toHex(encodeReceiptBody(first)), toHex(encodeReceiptBody(second)));
  });

  it("supports service-defined-fields maps", () => {
    const receipt: ReceiptBody = {
      ...successReceipt(),
      "service-defined-fields": new Map([
        ["example.com/tool/v1", new Map([["request-id", "req_123"]])],
      ]),
    };

    const decoded = decodeReceiptBody(encodeReceiptBody(receipt));

    assert.ok(decoded["service-defined-fields"] instanceof Map);
    assert.deepEqual(
      decoded["service-defined-fields"]?.get("example.com/tool/v1"),
      new Map([["request-id", "req_123"]]),
    );
  });
});

describe("receipt body validation", () => {
  it("rejects bad hash lengths", () => {
    assert.throws(
      () => validateReceiptBody({
        ...successReceipt(),
        "action-input-hash": new Uint8Array(31),
      }),
      /32-byte SHA-256 digest/,
    );
  });

  it("rejects bad status values", () => {
    assert.throws(
      () => validateReceiptBody({
        ...successReceipt(),
        "result-status": "partial" as ReceiptBody["result-status"],
      }),
      /success, error, or denied/,
    );
  });

  it("rejects denied receipts with non-zero output hashes", () => {
    assert.throws(
      () => validateReceiptBody({
        ...successReceipt(),
        "result-status": "denied",
      }),
      /all-zero action-output-hash/,
    );
  });

  it("rejects invalid agent identifiers", () => {
    assert.throws(
      () => validateReceiptBody({
        ...successReceipt(),
        "agent-identifier": "0123456789ABCDEF0123456789ABCDEF",
      }),
      /lowercase hex/,
    );
  });

  it("rejects non-UTC timestamps", () => {
    assert.throws(
      () => validateReceiptBody({
        ...successReceipt(),
        timestamp: "2026-05-27T14:32:11-05:00",
      }),
      /RFC 3339 UTC timestamp/,
    );
  });

  it("rejects missing timestamp tag during decode", () => {
    const encoded = encodeCbor(new Map([
      ["agent-identifier", "0123456789abcdef0123456789abcdef"],
      ["action-type", "tools/call"],
      ["action-input-hash", digest("input")],
      ["action-output-hash", digest("output")],
      ["result-status", "success"],
      ["timestamp", "2026-05-27T14:32:11Z"],
    ]));

    assert.throws(() => decodeReceiptBody(encoded), /timestamp must be CBOR tag 0/);
  });

  it("rejects unknown receipt fields", () => {
    const encoded = encodeCbor(new Map([
      ["agent-identifier", "0123456789abcdef0123456789abcdef"],
      ["action-type", "tools/call"],
      ["action-input-hash", digest("input")],
      ["action-output-hash", digest("output")],
      ["result-status", "success"],
      ["timestamp", cborTag(0, "2026-05-27T14:32:11Z")],
      ["surprise", "nope"],
    ]));

    assert.throws(() => decodeReceiptBody(encoded), /unknown field/);
  });
});
