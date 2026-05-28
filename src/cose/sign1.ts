import { type CborMap, type CborValue, decodeCbor, encodeCbor } from "../cbor.ts";
import {
  assertEd25519PrivateKey,
  assertEd25519PublicKey,
  assertEd25519Signature,
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519Signature,
  type Ed25519KeyPair,
} from "../crypto/ed25519.ts";
import { decodeProtectedHeader } from "./protected-header.ts";

export { generateEd25519KeyPair, type Ed25519KeyPair };

export type ReceiptEnvelope = {
  protectedBytes: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
};

export type SignReceiptEnvelopeInput = {
  protectedHeaderBytes: Uint8Array;
  payload: Uint8Array;
  servicePrivateKey: Uint8Array;
};

export type VerifyReceiptEnvelopeInput = {
  envelope: Uint8Array;
  servicePublicKey: Uint8Array;
};

const EMPTY = new Uint8Array();

export function signReceiptEnvelope(input: SignReceiptEnvelopeInput): Uint8Array {
  assertBytes(input.protectedHeaderBytes, "protectedHeaderBytes");
  assertBytes(input.payload, "payload");
  assertEd25519PrivateKey(input.servicePrivateKey, "servicePrivateKey");
  decodeProtectedHeader(input.protectedHeaderBytes);

  const signature = signEd25519(
    buildSigStructure(input.protectedHeaderBytes, input.payload),
    input.servicePrivateKey,
  );

  return encodeCbor([
    input.protectedHeaderBytes,
    new Map(),
    input.payload,
    signature,
  ]);
}

export function verifyReceiptEnvelope(
  input: VerifyReceiptEnvelopeInput,
): ReceiptEnvelope {
  assertBytes(input.envelope, "envelope");
  assertEd25519PublicKey(input.servicePublicKey, "servicePublicKey");

  const decoded = decodeReceiptEnvelope(input.envelope);
  decodeProtectedHeader(decoded.protectedBytes);

  const ok = verifyEd25519Signature(
    buildSigStructure(decoded.protectedBytes, decoded.payload),
    decoded.signature,
    input.servicePublicKey,
  );

  if (!ok) {
    throw new TypeError("COSE_Sign1 signature verification failed");
  }

  return decoded;
}

export function decodeReceiptEnvelope(envelope: Uint8Array): ReceiptEnvelope {
  const decoded = decodeCbor(envelope);

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new TypeError("COSE_Sign1 envelope must be a 4-element array");
  }

  const [protectedBytes, unprotected, payload, signature] = decoded;

  assertBytes(protectedBytes, "COSE_Sign1 protected header");
  assertEmptyUnprotected(unprotected);
  assertBytes(payload, "COSE_Sign1 payload");
  assertEd25519Signature(signature, "COSE_Sign1 signature");

  return {
    protectedBytes: copyBytes(protectedBytes),
    payload: copyBytes(payload),
    signature: copyBytes(signature),
  };
}

export function buildSigStructure(
  protectedHeaderBytes: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  assertBytes(protectedHeaderBytes, "protectedHeaderBytes");
  assertBytes(payload, "payload");

  return encodeCbor(["Signature1", protectedHeaderBytes, EMPTY, payload]);
}

function assertEmptyUnprotected(value: CborValue): asserts value is CborMap {
  if (!(value instanceof Map)) {
    throw new TypeError("COSE_Sign1 unprotected header must be a map");
  }

  if (value.size !== 0) {
    throw new TypeError("COSE_Sign1 unprotected header must be empty");
  }
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}
