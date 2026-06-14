import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { generateEd25519KeyPair } from "../../src/cose/sign1.ts";
import { toHex } from "../../src/crypto/identifiers.ts";
import {
  assertKeyNotRevoked,
  loadSignedRegistry,
  resolveServiceKey,
  signRegistryJson,
} from "../../src/registry/json-registry.ts";

const textEncoder = new TextEncoder();

describe("signed JSON identity registry", () => {
  it("loads a valid signed registry and resolves a service key", () => {
    const trustRoot = generateEd25519KeyPair();
    const service = generateEd25519KeyPair();
    const kid = textEncoder.encode("svc-key-1");
    const registryBytes = registryJson({
      [toHex(kid)]: registryEntry("github.com/mcp/v1", service.publicKey),
    });
    const signatureBase64Url = signRegistryJson(registryBytes, trustRoot.privateKey);

    const registry = loadSignedRegistry({
      registryBytes,
      signatureBase64Url,
      trustRootPublicKey: trustRoot.publicKey,
    });
    const entry = resolveServiceKey(registry, kid);

    assert.equal(entry.serviceIdentifier, "github.com/mcp/v1");
    assert.deepEqual(entry.publicKeyEd25519, service.publicKey);
  });

  it("rejects a bad registry signature", () => {
    const trustRoot = generateEd25519KeyPair();
    const otherTrustRoot = generateEd25519KeyPair();
    const service = generateEd25519KeyPair();
    const kid = textEncoder.encode("svc-key-1");
    const registryBytes = registryJson({
      [toHex(kid)]: registryEntry("github.com/mcp/v1", service.publicKey),
    });
    const signatureBase64Url = signRegistryJson(registryBytes, otherTrustRoot.privateKey);

    assert.throws(
      () =>
        loadSignedRegistry({
          registryBytes,
          signatureBase64Url,
          trustRootPublicKey: trustRoot.publicKey,
        }),
      /registry signature verification failed/,
    );
  });

  it("rejects unknown kids", () => {
    const trustRoot = generateEd25519KeyPair();
    const registryBytes = registryJson({});
    const signatureBase64Url = signRegistryJson(registryBytes, trustRoot.privateKey);
    const registry = loadSignedRegistry({
      registryBytes,
      signatureBase64Url,
      trustRootPublicKey: trustRoot.publicKey,
    });

    assert.throws(
      () => resolveServiceKey(registry, textEncoder.encode("missing")),
      /unknown kid/,
    );
  });

  it("accepts revoked keys before revoked_at", () => {
    const { registry, kid } = revokedRegistry("2026-05-28T10:00:00Z");

    assert.doesNotThrow(() =>
      assertKeyNotRevoked(registry, kid, "2026-05-28T09:59:59Z"),
    );
  });

  it("rejects revoked keys at or after revoked_at", () => {
    const { registry, kid } = revokedRegistry("2026-05-28T10:00:00Z");

    assert.throws(
      () => assertKeyNotRevoked(registry, kid, "2026-05-28T10:00:00Z"),
      /was revoked at/,
    );
    assert.throws(
      () => assertKeyNotRevoked(registry, kid, "2026-05-28T10:00:01Z"),
      /was revoked at/,
    );
  });

  it("fails closed for revoked keys without integrated time", () => {
    const { registry, kid } = revokedRegistry("2026-05-28T10:00:00Z");

    assert.throws(
      () => assertKeyNotRevoked(registry, kid),
      /requires verifiable integrated time/,
    );
  });

  it("rejects malformed registry entries", () => {
    const trustRoot = generateEd25519KeyPair();
    const registryBytes = registryJson({
      "ABC123": {
        service_identifier: "github.com/mcp/v1",
        public_key_ed25519: "not-base64url",
      },
    });
    const signatureBase64Url = signRegistryJson(registryBytes, trustRoot.privateKey);

    assert.throws(
      () =>
        loadSignedRegistry({
          registryBytes,
          signatureBase64Url,
          trustRootPublicKey: trustRoot.publicKey,
        }),
      /registry kid must be lowercase even-length hex/,
    );
  });

  it("rejects impossible base64url signature lengths", () => {
    const trustRoot = generateEd25519KeyPair();
    const registryBytes = registryJson({});

    assert.throws(
      () =>
        loadSignedRegistry({
          registryBytes,
          signatureBase64Url: "A",
          trustRootPublicKey: trustRoot.publicKey,
        }),
      /registry signature must be unpadded base64url/,
    );
  });
});

function revokedRegistry(revokedAt: string) {
  const trustRoot = generateEd25519KeyPair();
  const service = generateEd25519KeyPair();
  const kid = textEncoder.encode("svc-key-1");
  const kidHex = toHex(kid);
  const registryBytes = registryJson({
    [kidHex]: registryEntry("github.com/mcp/v1", service.publicKey),
    revoked: {
      [kidHex]: {
        revoked_at: revokedAt,
      },
    },
  });
  const signatureBase64Url = signRegistryJson(registryBytes, trustRoot.privateKey);
  const registry = loadSignedRegistry({
    registryBytes,
    signatureBase64Url,
    trustRootPublicKey: trustRoot.publicKey,
  });

  return { registry, kid };
}

function registryEntry(serviceIdentifier: string, publicKey: Uint8Array) {
  return {
    service_identifier: serviceIdentifier,
    public_key_ed25519: Buffer.from(publicKey).toString("base64url"),
  };
}

function registryJson(value: unknown): Uint8Array {
  return textEncoder.encode(JSON.stringify(value));
}
