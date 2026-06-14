import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
  isCanonicalLogUrl,
  logUrlsEqual,
} from "../../src/log/canonical-url.ts";

describe("canonical log URL validation", () => {
  it("accepts canonical log URLs", () => {
    assert.doesNotThrow(() => assertCanonicalLogUrl("https://rekor.example.com/api"));
    assert.doesNotThrow(() => assertCanonicalLogUrl("https://rekor.example.com/"));
    assert.doesNotThrow(() => assertCanonicalLogUrl("https://rekor.example.com:8443/api"));
    assert.equal(isCanonicalLogUrl("https://rekor.example.com/api"), true);
  });

  it("requires lowercase https scheme", () => {
    assert.throws(
      () => assertCanonicalLogUrl("HTTPS://rekor.example.com/api"),
      /lowercase https scheme/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("http://rekor.example.com/api"),
      /lowercase https scheme/,
    );
  });

  it("rejects query strings, fragments, and userinfo", () => {
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/api?x=1"),
      /query string/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/api#v1"),
      /fragment/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://user@rekor.example.com/api"),
      /userinfo/,
    );
  });

  it("rejects non-canonical host and port forms", () => {
    assert.throws(
      () => assertCanonicalLogUrl("https://Rekor.Example.com/api"),
      /host must be lowercase/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com:443/api"),
      /omit default port/,
    );
  });

  it("rejects missing path and trailing slash variants", () => {
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com"),
      /path prefix/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/api/"),
      /trailing slash/,
    );
  });

  it("rejects dot segments", () => {
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/api/../v1"),
      /dot segments/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/./api"),
      /dot segments/,
    );
  });

  it("rejects non-canonical percent encoding", () => {
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/%7eapi"),
      /uppercase/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/%7Eapi"),
      /unreserved/,
    );
    assert.throws(
      () => assertCanonicalLogUrl("https://rekor.example.com/%zz"),
      /invalid percent-encoding/,
    );
  });

  it("compares canonical URLs byte-for-byte", () => {
    const a = "https://rekor.example.com/api" as CanonicalLogUrl;
    const b = "https://rekor.example.com/api" as CanonicalLogUrl;
    const c = "https://rekor.example.com/v1" as CanonicalLogUrl;

    assert.equal(logUrlsEqual(a, b), true);
    assert.equal(logUrlsEqual(a, c), false);
  });
});
