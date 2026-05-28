import { createHash } from "node:crypto";

export const SHA256_DIGEST_LENGTH = 32;
export const AGENT_IDENTIFIER_HEX_LENGTH = 32;

export type TokenIdentifiers = {
  sello_token_ref: Uint8Array;
  agent_identifier: string;
};

export function sha256(bytes: Uint8Array): Uint8Array {
  assertUint8Array(bytes, "bytes");
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function deriveTokenIdentifiers(
  authorizationTokenBytes: Uint8Array,
): TokenIdentifiers {
  assertUint8Array(authorizationTokenBytes, "authorizationTokenBytes");

  const digest = sha256(authorizationTokenBytes);

  return {
    sello_token_ref: digest,
    agent_identifier: toHex(digest.subarray(0, 16)),
  };
}

export function isTokenRef(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.byteLength === SHA256_DIGEST_LENGTH;
}

export function assertTokenRef(value: unknown, name = "sello_token_ref"): void {
  if (!isTokenRef(value)) {
    throw new TypeError(`${name} must be a 32-byte Uint8Array`);
  }
}

export function isAgentIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{32}$/.test(value)
  );
}

export function assertAgentIdentifier(
  value: unknown,
  name = "agent_identifier",
): void {
  if (!isAgentIdentifier(value)) {
    throw new TypeError(`${name} must be a 32-character lowercase hex string`);
  }
}

export function toHex(bytes: Uint8Array): string {
  assertUint8Array(bytes, "bytes");
  return Buffer.from(bytes).toString("hex");
}

function assertUint8Array(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}
