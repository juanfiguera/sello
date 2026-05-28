import {
  type CborMap,
  type CborTagged,
  cborTag,
  decodeCbor,
  encodeCbor,
} from "../cbor.ts";
import { assertAgentIdentifier } from "../crypto/identifiers.ts";

export type ResultStatus = "success" | "error" | "denied";

export type ReceiptBody = {
  "agent-identifier": string;
  "action-type": string;
  "action-input-hash": Uint8Array;
  "action-output-hash": Uint8Array;
  "result-status": ResultStatus;
  timestamp: string;
  "service-defined-fields"?: CborMap;
};

export const ZERO_SHA256_DIGEST = new Uint8Array(32);

const RESULT_STATUSES = new Set<ResultStatus>(["success", "error", "denied"]);
const RECEIPT_KEYS = new Set([
  "agent-identifier",
  "action-type",
  "action-input-hash",
  "action-output-hash",
  "result-status",
  "timestamp",
  "service-defined-fields",
]);

export function encodeReceiptBody(receipt: ReceiptBody): Uint8Array {
  validateReceiptBody(receipt);

  const map: CborMap = new Map([
    ["agent-identifier", receipt["agent-identifier"]],
    ["action-type", receipt["action-type"]],
    ["action-input-hash", receipt["action-input-hash"]],
    ["action-output-hash", receipt["action-output-hash"]],
    ["result-status", receipt["result-status"]],
    ["timestamp", cborTag(0, receipt.timestamp)],
  ]);

  if (receipt["service-defined-fields"]) {
    map.set("service-defined-fields", receipt["service-defined-fields"]);
  }

  return encodeCbor(map);
}

export function decodeReceiptBody(bytes: Uint8Array): ReceiptBody {
  const value = decodeCbor(bytes);

  if (!(value instanceof Map)) {
    throw new TypeError("receipt body must be a CBOR map");
  }

  for (const key of value.keys()) {
    if (typeof key !== "string" || !RECEIPT_KEYS.has(key)) {
      throw new TypeError(`receipt body contains unknown field ${String(key)}`);
    }
  }

  const timestamp = value.get("timestamp");
  const receipt: ReceiptBody = {
    "agent-identifier": expectString(value, "agent-identifier"),
    "action-type": expectString(value, "action-type"),
    "action-input-hash": expectBytes(value, "action-input-hash"),
    "action-output-hash": expectBytes(value, "action-output-hash"),
    "result-status": expectResultStatus(value, "result-status"),
    timestamp: expectTag0Timestamp(timestamp),
  };

  if (value.has("service-defined-fields")) {
    const serviceFields = value.get("service-defined-fields");
    if (!(serviceFields instanceof Map)) {
      throw new TypeError("service-defined-fields must be a CBOR map");
    }
    assertServiceDefinedFields(serviceFields);
    receipt["service-defined-fields"] = serviceFields;
  }

  validateReceiptBody(receipt);
  return receipt;
}

export function validateReceiptBody(receipt: ReceiptBody): void {
  assertObject(receipt, "receipt");
  assertAgentIdentifier(receipt["agent-identifier"], "agent-identifier");
  assertString(receipt["action-type"], "action-type");
  assertSha256Digest(receipt["action-input-hash"], "action-input-hash");
  assertSha256Digest(receipt["action-output-hash"], "action-output-hash");
  assertResultStatus(receipt["result-status"], "result-status");
  assertUtcTimestamp(receipt.timestamp, "timestamp");

  if (
    receipt["result-status"] === "denied" &&
    !bytesEqual(receipt["action-output-hash"], ZERO_SHA256_DIGEST)
  ) {
    throw new TypeError("denied receipts must use all-zero action-output-hash");
  }

  if (receipt["service-defined-fields"] !== undefined) {
    if (!(receipt["service-defined-fields"] instanceof Map)) {
      throw new TypeError("service-defined-fields must be a Map");
    }
    assertServiceDefinedFields(receipt["service-defined-fields"]);
  }
}

function expectString(map: CborMap, key: string): string {
  const value = map.get(key);
  assertString(value, key);
  return value;
}

function expectBytes(map: CborMap, key: string): Uint8Array {
  const value = map.get(key);
  assertSha256Digest(value, key);
  return value;
}

function expectResultStatus(map: CborMap, key: string): ResultStatus {
  const value = map.get(key);
  assertResultStatus(value, key);
  return value;
}

function expectTag0Timestamp(value: unknown): string {
  if (!isTagged(value) || value.tag !== 0 || typeof value.value !== "string") {
    throw new TypeError("timestamp must be CBOR tag 0 containing a string");
  }

  assertUtcTimestamp(value.value, "timestamp");
  return value.value;
}

function assertObject(value: unknown, name: string): asserts value is object {
  if (typeof value !== "object" || value === null) {
    throw new TypeError(`${name} must be an object`);
  }
}

function assertString(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }
}

function assertSha256Digest(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
    throw new TypeError(`${name} must be a 32-byte SHA-256 digest`);
  }
}

function assertResultStatus(value: unknown, name: string): asserts value is ResultStatus {
  if (typeof value !== "string" || !RESULT_STATUSES.has(value as ResultStatus)) {
    throw new TypeError(`${name} must be success, error, or denied`);
  }
}

function assertUtcTimestamp(value: unknown, name: string): asserts value is string {
  assertString(value, name);

  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)) {
    throw new TypeError(`${name} must be an RFC 3339 UTC timestamp`);
  }

  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new TypeError(`${name} must be a valid timestamp`);
  }
}

function assertServiceDefinedFields(value: CborMap): void {
  for (const [key, entryValue] of value.entries()) {
    if (typeof key !== "string") {
      throw new TypeError("service-defined-fields keys must be service identifiers");
    }
    if (!(entryValue instanceof Map)) {
      throw new TypeError("service-defined-fields values must be CBOR maps");
    }
  }
}

function isTagged(value: unknown): value is CborTagged {
  return (
    typeof value === "object" &&
    value !== null &&
    "tag" in value &&
    "value" in value
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let index = 0; index < a.byteLength; index += 1) {
    if (a[index] !== b[index]) {
      return false;
    }
  }

  return true;
}
