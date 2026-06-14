import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type CborMap, encodeCbor } from "../../src/cbor.ts";
import {
  COSE_ALG_EDDSA,
  COSE_ALG_LABEL,
  COSE_CRIT_LABEL,
  COSE_KID_LABEL,
  SELLO_LOG_URL_LABEL,
  SELLO_TOKEN_REF_LABEL,
  SELLO_VERSION,
  SELLO_VERSION_LABEL,
  decodeProtectedHeader,
  encodeProtectedHeader,
} from "../../src/cose/protected-header.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";

const kid = new TextEncoder().encode("svc-key-1");
const tokenRef = Uint8Array.from({ length: 32 }, (_, index) => index);
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;

describe("COSE protected header", () => {
  it("encodes and decodes a valid protected header", () => {
    const protectedBytes = encodeProtectedHeader({
      kid,
      sello_token_ref: tokenRef,
      sello_log_url: logUrl,
    });

    const decoded = decodeProtectedHeader(protectedBytes);

    assert.equal(decoded.alg, COSE_ALG_EDDSA);
    assert.deepEqual(decoded.kid, kid);
    assert.equal(decoded.sello_version, SELLO_VERSION);
    assert.deepEqual(decoded.sello_token_ref, tokenRef);
    assert.equal(decoded.sello_log_url, logUrl);
    assert.deepEqual(decoded.protectedBytes, protectedBytes);
    assert.equal(decoded.unknownHeaders.size, 0);
  });

  it("emits deterministic protected header bytes", () => {
    const first = encodeProtectedHeader({
      sello_log_url: logUrl,
      sello_token_ref: tokenRef,
      kid,
    });
    const second = encodeProtectedHeader({
      kid,
      sello_token_ref: tokenRef,
      sello_log_url: logUrl,
    });

    assert.equal(toHex(first), toHex(second));
    assert.equal(
      toHex(first),
      "a5012704497376632d6b65792d313a0001000065302e312e303a000100015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f3a00010002781d68747470733a2f2f72656b6f722e6578616d706c652e636f6d2f617069",
    );
  });

  it("preserves exact protected header bytes after decoding", () => {
    const protectedBytes = encodeProtectedHeader({
      kid,
      crit: [SELLO_LOG_URL_LABEL],
      sello_token_ref: tokenRef,
      sello_log_url: logUrl,
    });

    const decoded = decodeProtectedHeader(protectedBytes);

    decoded.kid[0] = 0xff;
    assert.deepEqual(decoded.protectedBytes, protectedBytes);
  });

  it("accepts known critical protected header labels", () => {
    const decoded = decodeProtectedHeader(
      encodeProtectedHeader({
        kid,
        crit: [SELLO_LOG_URL_LABEL, SELLO_TOKEN_REF_LABEL],
        sello_token_ref: tokenRef,
        sello_log_url: logUrl,
      }),
    );

    assert.deepEqual(decoded.crit, [SELLO_LOG_URL_LABEL, SELLO_TOKEN_REF_LABEL]);
  });

  it("preserves unknown non-critical protected headers separately", () => {
    const map: CborMap = new Map([
      [COSE_ALG_LABEL, COSE_ALG_EDDSA],
      [COSE_KID_LABEL, kid],
      [SELLO_VERSION_LABEL, SELLO_VERSION],
      [SELLO_TOKEN_REF_LABEL, tokenRef],
      [SELLO_LOG_URL_LABEL, logUrl],
      [-70000, "extension"],
    ]);

    const decoded = decodeProtectedHeader(encodeCbor(map));

    assert.equal(decoded.unknownHeaders.get(-70000), "extension");
  });

  it("rejects wrong algorithm", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[COSE_ALG_LABEL, -7]])),
        ),
      /alg must be -8/,
    );
  });

  it("rejects wrong version", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[SELLO_VERSION_LABEL, "0.2.0"]])),
        ),
      /sello_version must be 0\.1\.0/,
    );
  });

  it("rejects empty kid", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[COSE_KID_LABEL, new Uint8Array()]])),
        ),
      /kid must be non-empty bytes/,
    );
  });

  it("rejects short token refs", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[SELLO_TOKEN_REF_LABEL, new Uint8Array(31)]])),
        ),
      /sello_token_ref must be a 32-byte Uint8Array/,
    );
  });

  it("rejects non-canonical log URLs", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(
            validHeaderMap([[SELLO_LOG_URL_LABEL, "https://Rekor.example.com/api"]]),
          ),
        ),
      /host must be lowercase/,
    );
  });

  it("rejects malformed crit values", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[COSE_CRIT_LABEL, []]])),
        ),
      /crit must not be empty/,
    );

    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[COSE_CRIT_LABEL, ["sello_log_url"]]])),
        ),
      /crit labels must be integers/,
    );

    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(
            validHeaderMap([
              [COSE_CRIT_LABEL, [SELLO_LOG_URL_LABEL, SELLO_LOG_URL_LABEL]],
            ]),
          ),
        ),
      /crit must not contain duplicates/,
    );
  });

  it("rejects unknown critical protected header labels", () => {
    assert.throws(
      () =>
        decodeProtectedHeader(
          encodeCbor(validHeaderMap([[COSE_CRIT_LABEL, [-70000]], [-70000, 1]])),
        ),
      /unknown critical protected header label -70000/,
    );
  });

  it("rejects non-map protected headers", () => {
    assert.throws(
      () => decodeProtectedHeader(encodeCbor(["not", "a", "map"])),
      /protected header must be a CBOR map/,
    );
  });
});

function validHeaderMap(overrides: [number, unknown][] = []): CborMap {
  const map: CborMap = new Map([
    [COSE_ALG_LABEL, COSE_ALG_EDDSA],
    [COSE_KID_LABEL, kid],
    [SELLO_VERSION_LABEL, SELLO_VERSION],
    [SELLO_TOKEN_REF_LABEL, tokenRef],
    [SELLO_LOG_URL_LABEL, logUrl],
  ]);

  for (const [label, value] of overrides) {
    map.set(label, value);
  }

  return map;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
