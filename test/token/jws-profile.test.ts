import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { generateEd25519KeyPair } from "../../src/cose/sign1.ts";
import { generateHpkeKeyPair } from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import {
  base64urlEncode,
  signSelloJwsToken,
  verifySelloJwsToken,
} from "../../src/token/jws-profile.ts";

const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;

describe("v0.1 JWS token profile", () => {
  it("verifies compact JWS before exposing Sello claims", () => {
    const issuer = generateEd25519KeyPair();
    const owner = generateHpkeKeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      payload: {
        sub: "agent-1",
        owner_hpke_pk: base64urlEncode(owner.publicKey),
        sello_logs: [logUrl],
      },
    });

    const verified = verifySelloJwsToken({
      authorizationToken: token,
      issuerPublicKey: issuer.publicKey,
    });

    assert.deepEqual(verified.ownerHpkePublicKey, owner.publicKey);
    assert.deepEqual(verified.selloLogs, [logUrl]);
    assert.deepEqual(verified.authorizationTokenBytes, new TextEncoder().encode(token));
  });

  it("rejects non-compact tokens", () => {
    const issuer = generateEd25519KeyPair();

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: "not.compact",
          issuerPublicKey: issuer.publicKey,
        }),
      /compact JWS/,
    );
  });

  it("rejects unsupported algorithms", () => {
    const issuer = generateEd25519KeyPair();
    const owner = generateHpkeKeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      protectedHeader: { alg: "HS256" },
      payload: {
        owner_hpke_pk: base64urlEncode(owner.publicKey),
        sello_logs: [logUrl],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /alg must be EdDSA/,
    );
  });

  it("rejects JWS crit headers", () => {
    const issuer = generateEd25519KeyPair();
    const owner = generateHpkeKeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      protectedHeader: { crit: ["exp"] },
      payload: {
        owner_hpke_pk: base64urlEncode(owner.publicKey),
        sello_logs: [logUrl],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /crit is not supported/,
    );
  });

  it("rejects bad signatures before reading malformed claims", () => {
    const issuer = generateEd25519KeyPair();
    const otherIssuer = generateEd25519KeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: otherIssuer.privateKey,
      payload: {
        owner_hpke_pk: "not-a-key",
        sello_logs: ["https://Rekor.example.com/api"],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /signature verification failed/,
    );
  });

  it("rejects malformed owner_hpke_pk after signature verification", () => {
    const issuer = generateEd25519KeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      payload: {
        owner_hpke_pk: "not-a-key",
        sello_logs: [logUrl],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /owner_hpke_pk must encode/,
    );
  });

  it("rejects impossible base64url lengths after signature verification", () => {
    const issuer = generateEd25519KeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      payload: {
        owner_hpke_pk: "A",
        sello_logs: [logUrl],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /owner_hpke_pk must encode/,
    );
  });

  it("rejects malformed sello_logs after signature verification", () => {
    const issuer = generateEd25519KeyPair();
    const owner = generateHpkeKeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      payload: {
        owner_hpke_pk: base64urlEncode(owner.publicKey),
        sello_logs: ["https://Rekor.example.com/api"],
      },
    });

    assert.throws(
      () =>
        verifySelloJwsToken({
          authorizationToken: token,
          issuerPublicKey: issuer.publicKey,
        }),
      /host must be lowercase/,
    );
  });

  it("allows absent sello_logs for local policy fallback", () => {
    const issuer = generateEd25519KeyPair();
    const owner = generateHpkeKeyPair();
    const token = signSelloJwsToken({
      issuerPrivateKey: issuer.privateKey,
      payload: {
        owner_hpke_pk: base64urlEncode(owner.publicKey),
      },
    });

    const verified = verifySelloJwsToken({
      authorizationToken: token,
      issuerPublicKey: issuer.publicKey,
    });

    assert.equal(verified.selloLogs, undefined);
  });
});
