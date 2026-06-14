import { signEd25519, verifyEd25519Signature } from "../crypto/ed25519.ts";
import { assertCanonicalLogUrl } from "../log/canonical-url.ts";

export type VerifiedSelloJwsToken = {
  authorizationTokenBytes: Uint8Array;
  ownerHpkePublicKey: Uint8Array;
  selloLogs?: readonly string[];
  protectedHeader: Record<string, unknown>;
  payload: Record<string, unknown>;
};

export type VerifySelloJwsTokenInput = {
  authorizationToken: string | Uint8Array;
  issuerPublicKey: Uint8Array;
};

export type SignSelloJwsTokenInput = {
  payload: Record<string, unknown>;
  issuerPrivateKey: Uint8Array;
  protectedHeader?: Record<string, unknown>;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_32_BYTE_LENGTH = 43;

export function verifySelloJwsToken(
  input: VerifySelloJwsTokenInput,
): VerifiedSelloJwsToken {
  const authorizationTokenBytes = normalizeTokenBytes(input.authorizationToken);
  const authorizationToken = textDecoder.decode(authorizationTokenBytes);
  const parts = authorizationToken.split(".");

  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new TypeError("authorization token must be compact JWS");
  }

  const [encodedProtected, encodedPayload, encodedSignature] = parts;
  const protectedHeader = parseJsonObject(
    base64urlDecode(encodedProtected, "JWS protected header"),
    "JWS protected header",
  );

  if (protectedHeader.alg !== "EdDSA") {
    throw new TypeError("JWS alg must be EdDSA");
  }

  if ("crit" in protectedHeader) {
    throw new TypeError("JWS crit is not supported by the v0.1 token profile");
  }

  const signingInput = textEncoder.encode(`${encodedProtected}.${encodedPayload}`);
  const signature = base64urlDecode(encodedSignature, "JWS signature");
  if (!verifyEd25519Signature(signingInput, signature, input.issuerPublicKey)) {
    throw new TypeError("JWS signature verification failed");
  }

  const payload = parseJsonObject(
    base64urlDecode(encodedPayload, "JWS payload"),
    "JWS payload",
  );
  const ownerHpkePublicKey = readOwnerHpkePublicKey(payload);
  const selloLogs = readSelloLogs(payload);

  return {
    authorizationTokenBytes,
    ownerHpkePublicKey,
    ...(selloLogs === undefined ? {} : { selloLogs }),
    protectedHeader,
    payload,
  };
}

export function signSelloJwsToken(input: SignSelloJwsTokenInput): string {
  const protectedHeader = {
    alg: "EdDSA",
    typ: "JWT",
    ...input.protectedHeader,
  };
  const encodedProtected = base64urlEncode(
    textEncoder.encode(JSON.stringify(protectedHeader)),
  );
  const encodedPayload = base64urlEncode(
    textEncoder.encode(JSON.stringify(input.payload)),
  );
  const signingInput = textEncoder.encode(`${encodedProtected}.${encodedPayload}`);
  const signature = signEd25519(signingInput, input.issuerPrivateKey);

  return `${encodedProtected}.${encodedPayload}.${base64urlEncode(signature)}`;
}

export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function readOwnerHpkePublicKey(payload: Record<string, unknown>): Uint8Array {
  const encoded = payload.owner_hpke_pk;

  if (typeof encoded !== "string") {
    throw new TypeError("owner_hpke_pk must be a string");
  }

  if (encoded.length !== BASE64URL_32_BYTE_LENGTH) {
    throw new TypeError("owner_hpke_pk must encode a raw 32-byte X25519 public key");
  }

  const publicKey = base64urlDecode(encoded, "owner_hpke_pk");
  if (publicKey.byteLength !== 32) {
    throw new TypeError("owner_hpke_pk must encode a raw 32-byte X25519 public key");
  }

  return publicKey;
}

function readSelloLogs(payload: Record<string, unknown>): readonly string[] | undefined {
  const value = payload.sello_logs;

  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    throw new TypeError("sello_logs must be an array");
  }

  return value.map((entry) => {
    if (typeof entry !== "string") {
      throw new TypeError("sello_logs entries must be strings");
    }

    assertCanonicalLogUrl(entry, "sello_logs entry");
    return entry;
  });
}

function normalizeTokenBytes(token: string | Uint8Array): Uint8Array {
  if (typeof token === "string") {
    if (!/^[\x21-\x7e]+$/.test(token)) {
      throw new TypeError("authorization token must be visible ASCII");
    }

    return textEncoder.encode(token);
  }

  if (token instanceof Uint8Array) {
    return new Uint8Array(token);
  }

  throw new TypeError("authorizationToken must be a string or Uint8Array");
}

function parseJsonObject(bytes: Uint8Array, name: string): Record<string, unknown> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(textDecoder.decode(bytes));
  } catch {
    throw new TypeError(`${name} must be UTF-8 JSON`);
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TypeError(`${name} must be a JSON object`);
  }

  return parsed as Record<string, unknown>;
}

function base64urlDecode(value: string, name: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new TypeError(`${name} must be unpadded base64url`);
  }

  return Uint8Array.from(Buffer.from(value, "base64url"));
}
