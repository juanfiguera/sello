import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
} from "node:crypto";

import { concat } from "../cbor.ts";

export type HpkeKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export type HpkeSealInput = {
  plaintext: Uint8Array;
  aad: Uint8Array;
  info: Uint8Array;
  recipientPublicKey: Uint8Array;
  ephemeralPrivateKey?: Uint8Array;
};

export type HpkeOpenInput = {
  payload: Uint8Array;
  aad: Uint8Array;
  info: Uint8Array;
  recipientPrivateKey: Uint8Array;
};

const KEM_ID_DHKEM_X25519_HKDF_SHA256 = 0x0020;
const KDF_ID_HKDF_SHA256 = 0x0001;
const AEAD_ID_CHACHA20_POLY1305 = 0x0003;

const X25519_KEY_LENGTH = 32;
const HKDF_SHA256_LENGTH = 32;
const CHACHA20_POLY1305_KEY_LENGTH = 32;
const CHACHA20_POLY1305_NONCE_LENGTH = 12;
const CHACHA20_POLY1305_TAG_LENGTH = 16;

const X25519_PUBLIC_KEY_SPKI_PREFIX = hex("302a300506032b656e032100");
const X25519_PRIVATE_KEY_PKCS8_PREFIX = hex("302e020100300506032b656e04220420");
const EMPTY = new Uint8Array();
const HPKE_VERSION = ascii("HPKE-v1");
const KEM_SUITE_ID = concat([
  ascii("KEM"),
  i2osp(KEM_ID_DHKEM_X25519_HKDF_SHA256, 2),
]);
const HPKE_SUITE_ID = concat([
  ascii("HPKE"),
  i2osp(KEM_ID_DHKEM_X25519_HKDF_SHA256, 2),
  i2osp(KDF_ID_HKDF_SHA256, 2),
  i2osp(AEAD_ID_CHACHA20_POLY1305, 2),
]);

export function generateHpkeKeyPair(): HpkeKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");

  return {
    publicKey: exportRawX25519PublicKey(publicKey),
    privateKey: exportRawX25519PrivateKey(privateKey),
  };
}

export function sealHpkeBase(input: HpkeSealInput): Uint8Array {
  assertBytes(input.plaintext, "plaintext");
  assertBytes(input.aad, "aad");
  assertBytes(input.info, "info");
  assertByteLength(input.recipientPublicKey, X25519_KEY_LENGTH, "recipientPublicKey");

  const ephemeralPrivateKey = input.ephemeralPrivateKey ?? generateHpkeKeyPair().privateKey;
  assertByteLength(ephemeralPrivateKey, X25519_KEY_LENGTH, "ephemeralPrivateKey");

  const enc = publicKeyFromPrivateKey(ephemeralPrivateKey);
  const sharedSecret = encap(ephemeralPrivateKey, input.recipientPublicKey, enc);
  const context = keySchedule(sharedSecret, input.info);
  const ciphertext = aeadSeal(context.key, context.baseNonce, input.aad, input.plaintext);

  return concat([enc, ciphertext]);
}

export function openHpkeBase(input: HpkeOpenInput): Uint8Array {
  assertBytes(input.payload, "payload");
  assertBytes(input.aad, "aad");
  assertBytes(input.info, "info");
  assertByteLength(input.recipientPrivateKey, X25519_KEY_LENGTH, "recipientPrivateKey");

  if (input.payload.byteLength < X25519_KEY_LENGTH + CHACHA20_POLY1305_TAG_LENGTH) {
    throw new TypeError("HPKE payload is too short");
  }

  const enc = input.payload.subarray(0, X25519_KEY_LENGTH);
  const ciphertext = input.payload.subarray(X25519_KEY_LENGTH);
  const recipientPublicKey = publicKeyFromPrivateKey(input.recipientPrivateKey);
  const sharedSecret = decap(enc, input.recipientPrivateKey, recipientPublicKey);
  const context = keySchedule(sharedSecret, input.info);

  return aeadOpen(context.key, context.baseNonce, input.aad, ciphertext);
}

function encap(
  ephemeralPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  enc: Uint8Array,
): Uint8Array {
  const dh = x25519(ephemeralPrivateKey, recipientPublicKey);
  return extractAndExpand(dh, concat([enc, recipientPublicKey]));
}

function decap(
  enc: Uint8Array,
  recipientPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
): Uint8Array {
  const dh = x25519(recipientPrivateKey, enc);
  return extractAndExpand(dh, concat([enc, recipientPublicKey]));
}

function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh);
  return labeledExpand(
    KEM_SUITE_ID,
    eaePrk,
    "shared_secret",
    kemContext,
    HKDF_SHA256_LENGTH,
  );
}

function keySchedule(
  sharedSecret: Uint8Array,
  info: Uint8Array,
): { key: Uint8Array; baseNonce: Uint8Array } {
  const pskIdHash = labeledExtract(
    HPKE_SUITE_ID,
    EMPTY,
    "psk_id_hash",
    EMPTY,
  );
  const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
  const keyScheduleContext = concat([Uint8Array.of(0), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);

  return {
    key: labeledExpand(
      HPKE_SUITE_ID,
      secret,
      "key",
      keyScheduleContext,
      CHACHA20_POLY1305_KEY_LENGTH,
    ),
    baseNonce: labeledExpand(
      HPKE_SUITE_ID,
      secret,
      "base_nonce",
      keyScheduleContext,
      CHACHA20_POLY1305_NONCE_LENGTH,
    ),
  };
}

function labeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Uint8Array {
  return hkdfExtract(
    salt,
    concat([HPKE_VERSION, suiteId, ascii(label), ikm]),
  );
}

function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdfExpand(
    prk,
    concat([i2osp(length, 2), HPKE_VERSION, suiteId, ascii(label), info]),
    length,
  );
}

function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const hmacKey = salt.byteLength === 0 ? new Uint8Array(HKDF_SHA256_LENGTH) : salt;
  return new Uint8Array(createHmac("sha256", hmacKey).update(ikm).digest());
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (length > 255 * HKDF_SHA256_LENGTH) {
    throw new RangeError("HKDF output length is too large");
  }

  const blocks: Uint8Array[] = [];
  let previous = EMPTY;
  let remaining = length;

  for (let counter = 1; remaining > 0; counter += 1) {
    previous = new Uint8Array(
      createHmac("sha256", prk)
        .update(previous)
        .update(info)
        .update(Uint8Array.of(counter))
        .digest(),
    );
    blocks.push(previous);
    remaining -= previous.byteLength;
  }

  return concat(blocks).subarray(0, length);
}

function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: CHACHA20_POLY1305_TAG_LENGTH,
  });

  cipher.setAAD(aad);
  const ciphertext = concat([cipher.update(plaintext), cipher.final()]);
  return concat([ciphertext, cipher.getAuthTag()]);
}

function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (ciphertext.byteLength < CHACHA20_POLY1305_TAG_LENGTH) {
    throw new TypeError("HPKE ciphertext is too short");
  }

  const tag = ciphertext.subarray(ciphertext.byteLength - CHACHA20_POLY1305_TAG_LENGTH);
  const body = ciphertext.subarray(0, ciphertext.byteLength - CHACHA20_POLY1305_TAG_LENGTH);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: CHACHA20_POLY1305_TAG_LENGTH,
  });

  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  try {
    return concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new TypeError("HPKE open failed");
  }
}

function x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sharedSecret = new Uint8Array(
    diffieHellman({
      privateKey: createX25519PrivateKey(privateKey),
      publicKey: createX25519PublicKey(publicKey),
    }),
  );

  if (sharedSecret.every((byte) => byte === 0)) {
    throw new TypeError("X25519 shared secret must not be all zero");
  }

  return sharedSecret;
}

function publicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
  return exportRawX25519PublicKey(createPublicKey(createX25519PrivateKey(privateKey)));
}

function createX25519PublicKey(rawPublicKey: Uint8Array): ReturnType<typeof createPublicKey> {
  assertByteLength(rawPublicKey, X25519_KEY_LENGTH, "rawPublicKey");
  return createPublicKey({
    key: Buffer.from(concat([X25519_PUBLIC_KEY_SPKI_PREFIX, rawPublicKey])),
    format: "der",
    type: "spki",
  });
}

function createX25519PrivateKey(rawPrivateKey: Uint8Array): ReturnType<typeof createPrivateKey> {
  assertByteLength(rawPrivateKey, X25519_KEY_LENGTH, "rawPrivateKey");
  return createPrivateKey({
    key: Buffer.from(concat([X25519_PRIVATE_KEY_PKCS8_PREFIX, rawPrivateKey])),
    format: "der",
    type: "pkcs8",
  });
}

function exportRawX25519PublicKey(key: ReturnType<typeof createPublicKey>): Uint8Array {
  const der = new Uint8Array(key.export({ format: "der", type: "spki" }));
  return new Uint8Array(der.subarray(der.byteLength - X25519_KEY_LENGTH));
}

function exportRawX25519PrivateKey(key: ReturnType<typeof createPrivateKey>): Uint8Array {
  const der = new Uint8Array(key.export({ format: "der", type: "pkcs8" }));
  return new Uint8Array(der.subarray(der.byteLength - X25519_KEY_LENGTH));
}

function i2osp(value: number, length: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("I2OSP value must be a non-negative safe integer");
  }

  const out = new Uint8Array(length);
  let remaining = value;

  for (let index = length - 1; index >= 0; index -= 1) {
    out[index] = remaining & 0xff;
    remaining >>= 8;
  }

  if (remaining !== 0) {
    throw new RangeError("I2OSP value does not fit");
  }

  return out;
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

function ascii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}
