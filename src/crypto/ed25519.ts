import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

import { concat } from "../cbor.ts";

export type Ed25519KeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export const ED25519_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

const ED25519_PUBLIC_KEY_SPKI_PREFIX = hex("302a300506032b6570032100");
const ED25519_PRIVATE_KEY_PKCS8_PREFIX = hex("302e020100300506032b657004220420");

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  return {
    publicKey: exportRawEd25519PublicKey(publicKey),
    privateKey: exportRawEd25519PrivateKey(privateKey),
  };
}

export function signEd25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  assertBytes(message, "message");
  assertEd25519PrivateKey(privateKey, "privateKey");

  return new Uint8Array(sign(null, message, createEd25519PrivateKey(privateKey)));
}

export function verifyEd25519Signature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  assertBytes(message, "message");
  assertEd25519Signature(signature, "signature");
  assertEd25519PublicKey(publicKey, "publicKey");

  return verify(null, message, createEd25519PublicKey(publicKey), signature);
}

export function assertEd25519PublicKey(
  value: unknown,
  name = "publicKey",
): asserts value is Uint8Array {
  assertByteLength(value, ED25519_KEY_LENGTH, name);
}

export function assertEd25519PrivateKey(
  value: unknown,
  name = "privateKey",
): asserts value is Uint8Array {
  assertByteLength(value, ED25519_KEY_LENGTH, name);
}

export function assertEd25519Signature(
  value: unknown,
  name = "signature",
): asserts value is Uint8Array {
  assertByteLength(value, ED25519_SIGNATURE_LENGTH, name);
}

function createEd25519PublicKey(rawPublicKey: Uint8Array): ReturnType<typeof createPublicKey> {
  assertEd25519PublicKey(rawPublicKey, "rawPublicKey");
  return createPublicKey({
    key: Buffer.from(concat([ED25519_PUBLIC_KEY_SPKI_PREFIX, rawPublicKey])),
    format: "der",
    type: "spki",
  });
}

function createEd25519PrivateKey(rawPrivateKey: Uint8Array): ReturnType<typeof createPrivateKey> {
  assertEd25519PrivateKey(rawPrivateKey, "rawPrivateKey");
  return createPrivateKey({
    key: Buffer.from(concat([ED25519_PRIVATE_KEY_PKCS8_PREFIX, rawPrivateKey])),
    format: "der",
    type: "pkcs8",
  });
}

function exportRawEd25519PublicKey(key: ReturnType<typeof createPublicKey>): Uint8Array {
  const der = new Uint8Array(key.export({ format: "der", type: "spki" }));
  return new Uint8Array(der.subarray(der.byteLength - ED25519_KEY_LENGTH));
}

function exportRawEd25519PrivateKey(key: ReturnType<typeof createPrivateKey>): Uint8Array {
  const der = new Uint8Array(key.export({ format: "der", type: "pkcs8" }));
  return new Uint8Array(der.subarray(der.byteLength - ED25519_KEY_LENGTH));
}

function assertByteLength(
  value: unknown,
  length: number,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new TypeError(`${name} must be a ${length}-byte Uint8Array`);
  }
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}
