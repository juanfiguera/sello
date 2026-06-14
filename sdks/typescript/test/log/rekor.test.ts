import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeProtectedHeader } from "../../src/cose/protected-header.ts";
import { generateEd25519KeyPair, signReceiptEnvelope } from "../../src/cose/sign1.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { RekorDiscoveryLog } from "../../src/log/rekor.ts";

const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const otherLogUrl = "https://other-rekor.example.com/api" as CanonicalLogUrl;
const tokenRef = Uint8Array.from({ length: 32 }, (_, index) => index);
const otherTokenRef = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);

describe("Rekor discovery log adapter", () => {
  it("returns discovery-only query results by token ref", () => {
    const log = new RekorDiscoveryLog({ logUrl });
    const envelope = signedEnvelope(tokenRef);

    log.addDiscoveredEntry({
      index: 7,
      integratedTime: "2026-05-28T10:00:00Z",
      envelope,
      proof: { kind: "rekor-proof-placeholder" },
    });

    const result = log.queryByTokenRef(tokenRef);

    assert.equal(result.completeness, "discovery-only");
    assert.equal(result.entries.length, 1);
    assert.equal(result.entries[0].logUrl, logUrl);
    assert.equal(result.entries[0].index, 7);
    assert.deepEqual(result.entries[0].envelope, envelope);
    assert.equal(log.queryByTokenRef(otherTokenRef).entries.length, 0);
  });

  it("can use an explicit token ref from an off-log index", () => {
    const log = new RekorDiscoveryLog({ logUrl });
    const envelopeForOtherToken = signedEnvelope(otherTokenRef);

    log.addDiscoveredEntry({
      tokenRef,
      index: 8,
      integratedTime: "2026-05-28T10:00:01Z",
      envelope: envelopeForOtherToken,
      proof: { kind: "off-log-index-candidate" },
    });

    assert.equal(log.queryByTokenRef(tokenRef).entries.length, 1);
    assert.equal(log.queryByTokenRef(otherTokenRef).entries.length, 0);
  });

  it("fails closed unless a proof verifier is provided", () => {
    const log = new RekorDiscoveryLog({ logUrl });
    const entry = log.addDiscoveredEntry({
      index: 9,
      integratedTime: "2026-05-28T10:00:02Z",
      envelope: signedEnvelope(tokenRef),
      proof: { kind: "rekor-proof-placeholder" },
    });

    assert.equal(log.verifyInclusionProof(entry), false);
  });

  it("delegates proof verification while enforcing returning log identity", () => {
    const log = new RekorDiscoveryLog({
      logUrl,
      verifyInclusionProof: (entry) => entry.index === 10,
    });
    const entry = log.addDiscoveredEntry({
      index: 10,
      integratedTime: "2026-05-28T10:00:03Z",
      envelope: signedEnvelope(tokenRef),
      proof: { kind: "rekor-proof-placeholder" },
    });

    assert.equal(log.verifyInclusionProof(entry), true);
    assert.equal(
      log.verifyInclusionProof({ ...entry, logUrl: otherLogUrl }),
      false,
    );
  });
});

function signedEnvelope(
  tokenRefForHeader: Uint8Array,
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
    payload: new TextEncoder().encode("hpke payload bytes"),
    servicePrivateKey: service.privateKey,
  });
}
