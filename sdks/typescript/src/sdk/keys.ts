import {
  assertEd25519PrivateKey,
  assertEd25519PublicKey,
} from "../crypto/ed25519.ts";

export type KeyInput = string | Uint8Array;

export type ServiceKeyInput =
  | string
  | {
      kid: KeyInput;
      privateKey: KeyInput;
    };

export type NormalizedServiceKey = {
  kid: Uint8Array;
  privateKey: Uint8Array;
};

const textEncoder = new TextEncoder();

export function normalizeServiceKey(
  input: ServiceKeyInput | undefined,
  fallbackKid?: KeyInput,
): NormalizedServiceKey {
  if (input === undefined) {
    throw new TypeError("SELLO_SERVICE_KEY is required");
  }

  if (typeof input === "object" && !(input instanceof Uint8Array)) {
    const kid = normalizeKid(input.kid, "serviceKey.kid");
    const privateKey = normalizeEd25519PrivateKey(
      input.privateKey,
      "serviceKey.privateKey",
    );
    return { kid, privateKey };
  }

  if (typeof input !== "string") {
    throw new TypeError("serviceKey must be a string or { kid, privateKey }");
  }

  const encoded = stripKnownServiceKeyPrefix(input);
  const separator = encoded.indexOf(".");
  if (separator !== -1) {
    const kid = decodeBase64url(encoded.slice(0, separator), "service key kid");
    const privateKey = normalizeEd25519PrivateKey(
      encoded.slice(separator + 1),
      "service key private key",
    );
    return { kid, privateKey };
  }

  if (fallbackKid === undefined) {
    throw new TypeError(
      "SELLO_SERVICE_KEY must include a kid, or SELLO_SERVICE_KID must be set",
    );
  }

  return {
    kid: normalizeKid(fallbackKid, "service kid"),
    privateKey: normalizeEd25519PrivateKey(input, "service key private key"),
  };
}

export function encodeServiceKey(
  kid: Uint8Array,
  privateKey: Uint8Array,
  prefix = "sello_dev",
): string {
  assertBytes(kid, "kid");
  assertEd25519PrivateKey(privateKey, "privateKey");
  return `${prefix}_${base64urlEncode(kid)}.${base64urlEncode(privateKey)}`;
}

export function normalizeKid(input: KeyInput, name = "kid"): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.byteLength === 0) {
      throw new TypeError(`${name} must not be empty`);
    }
    return new Uint8Array(input);
  }

  if (typeof input !== "string" || input.length === 0) {
    throw new TypeError(`${name} must be a non-empty string or Uint8Array`);
  }

  return textEncoder.encode(input);
}

export function normalizeEd25519PrivateKey(
  input: KeyInput,
  name = "privateKey",
): Uint8Array {
  const key = normalizeFixedBase64urlKey(input, 32, name);
  assertEd25519PrivateKey(key, name);
  return key;
}

export function normalizeEd25519PublicKey(
  input: KeyInput,
  name = "publicKey",
): Uint8Array {
  const key = normalizeFixedBase64urlKey(input, 32, name);
  assertEd25519PublicKey(key, name);
  return key;
}

export function normalizeHpkePrivateKey(
  input: KeyInput,
  name = "ownerPrivateKey",
): Uint8Array {
  return normalizeFixedBase64urlKey(stripKnownOwnerKeyPrefix(input), 32, name);
}

export function encodeOwnerKey(privateKey: Uint8Array, prefix = "sello_owner_dev"): string {
  assertByteLength(privateKey, 32, "privateKey");
  return `${prefix}_${base64urlEncode(privateKey)}`;
}

export function base64urlEncode(bytes: Uint8Array): string {
  assertBytes(bytes, "bytes");
  return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64url(value: string, name = "value"): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new TypeError(`${name} must be unpadded base64url`);
  }

  return Uint8Array.from(Buffer.from(value, "base64url"));
}

function normalizeFixedBase64urlKey(
  input: KeyInput,
  length: number,
  name: string,
): Uint8Array {
  if (input instanceof Uint8Array) {
    assertByteLength(input, length, name);
    return new Uint8Array(input);
  }

  if (typeof input !== "string") {
    throw new TypeError(`${name} must be a string or Uint8Array`);
  }

  const decoded = decodeBase64url(input, name);
  assertByteLength(decoded, length, name);
  return decoded;
}

function stripKnownServiceKeyPrefix(input: string): string {
  for (const prefix of ["sello_dev_", "sello_live_local_"]) {
    if (input.startsWith(prefix)) {
      return input.slice(prefix.length);
    }
  }

  return input;
}

function stripKnownOwnerKeyPrefix(input: KeyInput): KeyInput {
  if (typeof input !== "string") {
    return input;
  }

  for (const prefix of ["sello_owner_dev_", "sello_owner_live_"]) {
    if (input.startsWith(prefix)) {
      return input.slice(prefix.length);
    }
  }

  return input;
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
