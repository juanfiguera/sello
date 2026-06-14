import { type CborMap, type CborValue, decodeCbor, encodeCbor } from "../cbor.ts";
import { assertTokenRef } from "../crypto/identifiers.ts";
import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
} from "../log/canonical-url.ts";

export const COSE_ALG_LABEL = 1;
export const COSE_CRIT_LABEL = 2;
export const COSE_KID_LABEL = 4;
export const SELLO_VERSION_LABEL = -65537;
export const SELLO_TOKEN_REF_LABEL = -65538;
export const SELLO_LOG_URL_LABEL = -65539;

export const COSE_ALG_EDDSA = -8;
export const SELLO_VERSION = "0.1.0";

export type ProtectedHeader = {
  alg?: typeof COSE_ALG_EDDSA;
  kid: Uint8Array;
  crit?: readonly number[];
  sello_version?: typeof SELLO_VERSION;
  sello_token_ref: Uint8Array;
  sello_log_url: CanonicalLogUrl;
};

export type DecodedProtectedHeader = Required<
  Pick<
    ProtectedHeader,
    "alg" | "kid" | "sello_version" | "sello_token_ref" | "sello_log_url"
  >
> &
  Pick<ProtectedHeader, "crit"> & {
    protectedBytes: Uint8Array;
    unknownHeaders: CborMap;
  };

const UNDERSTOOD_LABELS = new Set([
  COSE_ALG_LABEL,
  COSE_CRIT_LABEL,
  COSE_KID_LABEL,
  SELLO_VERSION_LABEL,
  SELLO_TOKEN_REF_LABEL,
  SELLO_LOG_URL_LABEL,
]);

export function encodeProtectedHeader(header: ProtectedHeader): Uint8Array {
  validateProtectedHeaderInput(header);

  const map: CborMap = new Map([
    [COSE_ALG_LABEL, header.alg ?? COSE_ALG_EDDSA],
    [COSE_KID_LABEL, header.kid],
    [SELLO_VERSION_LABEL, header.sello_version ?? SELLO_VERSION],
    [SELLO_TOKEN_REF_LABEL, header.sello_token_ref],
    [SELLO_LOG_URL_LABEL, header.sello_log_url],
  ]);

  if (header.crit !== undefined) {
    map.set(COSE_CRIT_LABEL, [...header.crit]);
  }

  return encodeCbor(map);
}

export function decodeProtectedHeader(bytes: Uint8Array): DecodedProtectedHeader {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("protected header bytes must be a Uint8Array");
  }

  const decoded = decodeCbor(bytes);
  if (!(decoded instanceof Map)) {
    throw new TypeError("protected header must be a CBOR map");
  }

  const alg = readRequired(decoded, COSE_ALG_LABEL, "alg");
  if (alg !== COSE_ALG_EDDSA) {
    throw new TypeError("protected header alg must be -8");
  }

  const kid = readRequired(decoded, COSE_KID_LABEL, "kid");
  assertKid(kid);

  const selloVersion = readRequired(
    decoded,
    SELLO_VERSION_LABEL,
    "sello_version",
  );
  if (selloVersion !== SELLO_VERSION) {
    throw new TypeError(`protected header sello_version must be ${SELLO_VERSION}`);
  }

  const selloTokenRef = readRequired(
    decoded,
    SELLO_TOKEN_REF_LABEL,
    "sello_token_ref",
  );
  assertTokenRef(selloTokenRef, "protected header sello_token_ref");

  const selloLogUrl = readRequired(decoded, SELLO_LOG_URL_LABEL, "sello_log_url");
  assertCanonicalLogUrl(selloLogUrl, "protected header sello_log_url");

  const crit = readCrit(decoded.get(COSE_CRIT_LABEL));
  const unknownHeaders = collectUnknownHeaders(decoded);

  return {
    alg,
    kid: copyBytes(kid),
    ...(crit === undefined ? {} : { crit }),
    sello_version: selloVersion,
    sello_token_ref: copyBytes(selloTokenRef),
    sello_log_url: selloLogUrl,
    protectedBytes: copyBytes(bytes),
    unknownHeaders,
  };
}

function validateProtectedHeaderInput(header: ProtectedHeader): void {
  if (typeof header !== "object" || header === null) {
    throw new TypeError("protected header must be an object");
  }

  if (header.alg !== undefined && header.alg !== COSE_ALG_EDDSA) {
    throw new TypeError("protected header alg must be -8");
  }

  assertKid(header.kid);

  if (
    header.sello_version !== undefined &&
    header.sello_version !== SELLO_VERSION
  ) {
    throw new TypeError(`protected header sello_version must be ${SELLO_VERSION}`);
  }

  assertTokenRef(header.sello_token_ref, "protected header sello_token_ref");
  assertCanonicalLogUrl(header.sello_log_url, "protected header sello_log_url");
  readCrit(header.crit);
}

function readRequired(
  map: CborMap,
  label: number,
  name: string,
): CborValue {
  if (!map.has(label)) {
    throw new TypeError(`protected header is missing ${name}`);
  }

  return map.get(label) as CborValue;
}

function readCrit(value: CborValue | undefined): number[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    throw new TypeError("protected header crit must be an array");
  }

  if (value.length === 0) {
    throw new TypeError("protected header crit must not be empty");
  }

  const seen = new Set<number>();
  const out: number[] = [];

  for (const label of value) {
    if (!Number.isSafeInteger(label)) {
      throw new TypeError("protected header crit labels must be integers");
    }

    if (seen.has(label)) {
      throw new TypeError("protected header crit must not contain duplicates");
    }

    if (!UNDERSTOOD_LABELS.has(label)) {
      throw new TypeError(`unknown critical protected header label ${label}`);
    }

    seen.add(label);
    out.push(label);
  }

  return out;
}

function assertKid(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) {
    throw new TypeError("protected header kid must be non-empty bytes");
  }
}

function collectUnknownHeaders(map: CborMap): CborMap {
  const unknownHeaders: CborMap = new Map();

  for (const [label, value] of map) {
    if (typeof label === "number" && UNDERSTOOD_LABELS.has(label)) {
      continue;
    }

    unknownHeaders.set(label, value);
  }

  return unknownHeaders;
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}
