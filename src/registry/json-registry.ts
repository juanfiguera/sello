import {
  assertEd25519PublicKey,
  assertEd25519Signature,
  signEd25519,
  verifyEd25519Signature,
} from "../crypto/ed25519.ts";
import { toHex } from "../crypto/identifiers.ts";

export type RegistryEntry = {
  kidHex: string;
  serviceIdentifier: string;
  publicKeyEd25519: Uint8Array;
};

export type RevocationEntry = {
  kidHex: string;
  revokedAt: string;
};

export type JsonIdentityRegistry = {
  entries: Map<string, RegistryEntry>;
  revoked: Map<string, RevocationEntry>;
};

export type LoadSignedRegistryInput = {
  registryBytes: Uint8Array;
  signatureBase64Url: string;
  trustRootPublicKey: Uint8Array;
};

const textDecoder = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_32_BYTE_LENGTH = 43;

export function signRegistryJson(
  registryBytes: Uint8Array,
  trustRootPrivateKey: Uint8Array,
): string {
  assertBytes(registryBytes, "registryBytes");
  return base64urlEncode(signEd25519(registryBytes, trustRootPrivateKey));
}

export function loadSignedRegistry(
  input: LoadSignedRegistryInput,
): JsonIdentityRegistry {
  verifyRegistrySignature(
    input.registryBytes,
    input.signatureBase64Url,
    input.trustRootPublicKey,
  );

  return parseRegistry(input.registryBytes);
}

export function verifyRegistrySignature(
  registryBytes: Uint8Array,
  signatureBase64Url: string,
  trustRootPublicKey: Uint8Array,
): void {
  assertBytes(registryBytes, "registryBytes");
  assertEd25519PublicKey(trustRootPublicKey, "trustRootPublicKey");
  const signature = base64urlDecode(signatureBase64Url, "registry signature");
  assertEd25519Signature(signature, "registry signature");

  if (!verifyEd25519Signature(registryBytes, signature, trustRootPublicKey)) {
    throw new TypeError("registry signature verification failed");
  }
}

export function parseRegistry(registryBytes: Uint8Array): JsonIdentityRegistry {
  assertBytes(registryBytes, "registryBytes");
  const parsed = JSON.parse(textDecoder.decode(registryBytes));

  if (!isRecord(parsed)) {
    throw new TypeError("registry must be a JSON object");
  }

  const entries = new Map<string, RegistryEntry>();
  const revoked = parseRevoked(parsed.revoked);

  for (const [kidHex, value] of Object.entries(parsed)) {
    if (kidHex === "revoked") {
      continue;
    }

    assertKidHex(kidHex, "registry kid");

    if (!isRecord(value)) {
      throw new TypeError(`registry entry ${kidHex} must be an object`);
    }

    const serviceIdentifier = value.service_identifier;
    if (typeof serviceIdentifier !== "string" || serviceIdentifier.length === 0) {
      throw new TypeError(`registry entry ${kidHex} service_identifier must be a non-empty string`);
    }

    const encodedPublicKey = value.public_key_ed25519;
    if (typeof encodedPublicKey !== "string") {
      throw new TypeError(`registry entry ${kidHex} public_key_ed25519 must be a string`);
    }

    const publicKeyEd25519 = base64urlDecodeFixed32(
      encodedPublicKey,
      `registry entry ${kidHex} public_key_ed25519`,
    );

    entries.set(kidHex, {
      kidHex,
      serviceIdentifier,
      publicKeyEd25519,
    });
  }

  return { entries, revoked };
}

export function resolveServiceKey(
  registry: JsonIdentityRegistry,
  kid: Uint8Array,
): RegistryEntry {
  const kidHex = toHex(kid);
  const entry = registry.entries.get(kidHex);

  if (!entry) {
    throw new TypeError(`unknown kid ${kidHex}`);
  }

  return {
    kidHex: entry.kidHex,
    serviceIdentifier: entry.serviceIdentifier,
    publicKeyEd25519: new Uint8Array(entry.publicKeyEd25519),
  };
}

export function assertKeyNotRevoked(
  registry: JsonIdentityRegistry,
  kid: Uint8Array,
  integratedTime?: string | Date,
): void {
  const kidHex = toHex(kid);
  const revoked = registry.revoked.get(kidHex);

  if (!revoked) {
    return;
  }

  if (integratedTime === undefined) {
    throw new TypeError(`kid ${kidHex} is revoked and requires verifiable integrated time`);
  }

  const integratedTimeMs =
    integratedTime instanceof Date
      ? integratedTime.getTime()
      : parseUtcTimestamp(integratedTime, "integratedTime");
  const revokedAtMs = parseUtcTimestamp(revoked.revokedAt, `revoked_at for ${kidHex}`);

  if (integratedTimeMs >= revokedAtMs) {
    throw new TypeError(`kid ${kidHex} was revoked at ${revoked.revokedAt}`);
  }
}

function parseRevoked(value: unknown): Map<string, RevocationEntry> {
  const revoked = new Map<string, RevocationEntry>();

  if (value === undefined) {
    return revoked;
  }

  if (!isRecord(value)) {
    throw new TypeError("registry revoked must be an object");
  }

  for (const [kidHex, entry] of Object.entries(value)) {
    assertKidHex(kidHex, "revoked kid");

    if (!isRecord(entry) || typeof entry.revoked_at !== "string") {
      throw new TypeError(`revoked entry ${kidHex} must contain revoked_at`);
    }

    parseUtcTimestamp(entry.revoked_at, `revoked_at for ${kidHex}`);
    revoked.set(kidHex, { kidHex, revokedAt: entry.revoked_at });
  }

  return revoked;
}

function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64urlDecodeFixed32(value: string, name: string): Uint8Array {
  if (value.length !== BASE64URL_32_BYTE_LENGTH) {
    throw new TypeError(`${name} must be base64url encoding of 32 bytes`);
  }

  const decoded = base64urlDecode(value, name);
  assertEd25519PublicKey(decoded, name);
  return decoded;
}

function base64urlDecode(value: string, name: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError(`${name} must be unpadded base64url`);
  }

  return Uint8Array.from(Buffer.from(value, "base64url"));
}

function assertKidHex(value: string, name: string): void {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) {
    throw new TypeError(`${name} must be lowercase even-length hex`);
  }
}

function parseUtcTimestamp(value: string, name: string): number {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new TypeError(`${name} must be an RFC 3339 UTC timestamp`);
  }

  return Date.parse(value);
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
