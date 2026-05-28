import { encodeCbor } from "../cbor.ts";
import { assertTokenRef } from "../crypto/identifiers.ts";
import {
  generateHpkeKeyPair,
  openHpkeBase,
  sealHpkeBase,
  type HpkeKeyPair,
} from "./base.ts";

export type { HpkeKeyPair };

export type SealReceiptBodyInput = {
  plaintext: Uint8Array;
  ownerPublicKey: Uint8Array;
  protectedHeaderBytes: Uint8Array;
  serviceIdentifier: string;
  selloTokenRef: Uint8Array;
  ephemeralPrivateKey?: Uint8Array;
};

export type OpenReceiptBodyInput = {
  payload: Uint8Array;
  ownerPrivateKey: Uint8Array;
  protectedHeaderBytes: Uint8Array;
  serviceIdentifier: string;
  selloTokenRef: Uint8Array;
};

const HPKE_PAYLOAD_MIN_LENGTH = 49;

export { generateHpkeKeyPair };

export function buildReceiptHpkeInfo(
  serviceIdentifier: string,
  selloTokenRef: Uint8Array,
): Uint8Array {
  if (typeof serviceIdentifier !== "string" || serviceIdentifier.length === 0) {
    throw new TypeError("serviceIdentifier must be a non-empty string");
  }

  assertTokenRef(selloTokenRef, "selloTokenRef");

  return encodeCbor(["sello/0.1.0/receipt", serviceIdentifier, selloTokenRef]);
}

export function sealReceiptBody(input: SealReceiptBodyInput): Uint8Array {
  assertBytes(input.plaintext, "plaintext");
  assertBytes(input.protectedHeaderBytes, "protectedHeaderBytes");

  return sealHpkeBase({
    plaintext: input.plaintext,
    aad: input.protectedHeaderBytes,
    info: buildReceiptHpkeInfo(input.serviceIdentifier, input.selloTokenRef),
    recipientPublicKey: input.ownerPublicKey,
    ephemeralPrivateKey: input.ephemeralPrivateKey,
  });
}

export function openReceiptBody(input: OpenReceiptBodyInput): Uint8Array {
  assertBytes(input.payload, "payload");
  assertBytes(input.protectedHeaderBytes, "protectedHeaderBytes");

  if (input.payload.byteLength < HPKE_PAYLOAD_MIN_LENGTH) {
    throw new TypeError("HPKE payload must be at least 49 bytes");
  }

  return openHpkeBase({
    payload: input.payload,
    aad: input.protectedHeaderBytes,
    info: buildReceiptHpkeInfo(input.serviceIdentifier, input.selloTokenRef),
    recipientPrivateKey: input.ownerPrivateKey,
  });
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}
