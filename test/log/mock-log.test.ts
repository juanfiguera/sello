import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeProtectedHeader } from "../../src/cose/protected-header.ts";
import { generateEd25519KeyPair, signReceiptEnvelope } from "../../src/cose/sign1.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";

const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const otherLogUrl = "https://other-rekor.example.com/api" as CanonicalLogUrl;
const tokenRef = Uint8Array.from({ length: 32 }, (_, index) => index);
const otherTokenRef = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);

describe("mock transparency log", () => {
  it("appends and queries entries by token ref", () => {
    const log = new MockTransparencyLog(logUrl);
    const envelope = signedEnvelope(tokenRef);

    const appended = log.append(envelope, "2026-05-28T10:00:00Z");
    const result = log.queryByTokenRef(tokenRef);

    assert.equal(result.completeness, "complete");
    assert.equal(result.entries.length, 1);
    assert.deepEqual(result.entries[0].envelope, envelope);
    assert.equal(result.entries[0].index, appended.index);
    assert.equal(result.entries[0].integratedTime, "2026-05-28T10:00:00Z");
  });

  it("does not return unrelated token refs", () => {
    const log = new MockTransparencyLog(logUrl);
    log.append(signedEnvelope(tokenRef), "2026-05-28T10:00:00Z");

    assert.equal(log.queryByTokenRef(otherTokenRef).entries.length, 0);
  });

  it("returns the configured canonical log URL", () => {
    const log = new MockTransparencyLog(logUrl);
    const entry = log.append(signedEnvelope(tokenRef), "2026-05-28T10:00:00Z");

    assert.equal(entry.logUrl, logUrl);
    assert.equal(entry.proof.logUrl, logUrl);
  });

  it("binds proof data to the exact envelope bytes and integrated time", () => {
    const log = new MockTransparencyLog(logUrl);
    const entry = log.append(signedEnvelope(tokenRef), "2026-05-28T10:00:00Z");

    assert.equal(log.verifyInclusionProof(entry), true);

    const tamperedEnvelope = {
      ...entry,
      envelope: new Uint8Array(entry.envelope),
    };
    tamperedEnvelope.envelope[tamperedEnvelope.envelope.length - 1] ^= 0xff;
    assert.equal(log.verifyInclusionProof(tamperedEnvelope), false);

    assert.equal(
      log.verifyInclusionProof({
        ...entry,
        integratedTime: "2026-05-28T10:00:01Z",
      }),
      false,
    );
  });

  it("returns multiple receipts for the same token", () => {
    const log = new MockTransparencyLog(logUrl);
    log.append(signedEnvelope(tokenRef, "payload-1"), "2026-05-28T10:00:00Z");
    log.append(signedEnvelope(tokenRef, "payload-2"), "2026-05-28T10:00:01Z");

    const result = log.queryByTokenRef(tokenRef);

    assert.equal(result.entries.length, 2);
    assert.equal(result.entries[0].index, 0);
    assert.equal(result.entries[1].index, 1);
  });

  it("rejects envelopes signed for another log URL", () => {
    const log = new MockTransparencyLog(logUrl);

    assert.throws(
      () =>
        log.append(
          signedEnvelope(tokenRef, "payload", otherLogUrl),
          "2026-05-28T10:00:00Z",
        ),
      /sello_log_url must match/,
    );
  });
});

function signedEnvelope(
  tokenRefForHeader: Uint8Array,
  payloadText = "hpke payload bytes",
  headerLogUrl = logUrl,
): Uint8Array {
  const service = generateEd25519KeyPair();
  const protectedHeaderBytes = encodeProtectedHeader({
    kid: new TextEncoder().encode("svc-key-1"),
    sello_token_ref: tokenRefForHeader,
    sello_log_url: headerLogUrl,
  });

  return signReceiptEnvelope({
    protectedHeaderBytes,
    payload: new TextEncoder().encode(payloadText),
    servicePrivateKey: service.privateKey,
  });
}
