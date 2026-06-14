import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  generateEd25519KeyPair,
  generateHpkeKeyPair,
  loadSignedRegistry,
  signRegistryJson,
  signSelloJwsToken,
  base64urlEncode,
  toHex,
  verifyReceipts,
  sello,
} from "../../src/index.ts";
import { encodeServiceKey } from "../../src/sdk/keys.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { type TransparencyLogEntry } from "../../src/log/types.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;

type ToolRequest = {
  authorizationToken: string;
  params: Record<string, unknown>;
};

type ToolResponse = {
  ok: boolean;
  id?: string;
};

describe("Stripe-style Sello SDK service wrapper", () => {
  it("wraps a tool and emits a verifiable success receipt", async () => {
    const fixture = makeFixture();
    const events: unknown[] = [];
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "await" },
      onReceipt: (event) => events.push(event),
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async (request) => ({ ok: true, id: String(request.params.title) }),
    );

    const response = await wrapped(fixture.request());
    const verified = verifyReceipts(fixture.ownerInput());

    assert.deepEqual(response, { ok: true, id: "launch" });
    assert.equal(events.length, 1);
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].receipt["action-type"], "calendar.create_event");
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("emits an error receipt and rethrows handler failures", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "await" },
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async () => {
        throw new Error("calendar exploded");
      },
    );

    await assert.rejects(() => wrapped(fixture.request()), /calendar exploded/);
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].receipt["result-status"], "error");
  });

  it("emits a denied receipt without running the handler", async () => {
    const fixture = makeFixture();
    let called = false;
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "await" },
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async () => {
        called = true;
        return { ok: true };
      },
      {
        isDenied: () => true,
        deniedResponse: () => ({ ok: false }),
      },
    );

    const response = await wrapped(fixture.request());
    const verified = verifyReceipts(fixture.ownerInput());

    assert.deepEqual(response, { ok: false });
    assert.equal(called, false);
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts[0].receipt["result-status"], "denied");
  });

  it("verifies the token before running the handler", async () => {
    const fixture = makeFixture();
    const otherIssuer = generateEd25519KeyPair();
    const badToken = signSelloJwsToken({
      issuerPrivateKey: otherIssuer.privateKey,
      payload: {
        owner_hpke_pk: base64urlEncode(fixture.owner.publicKey),
        sello_logs: [logUrl],
      },
    });
    let called = false;
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "await" },
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async () => {
        called = true;
        return { ok: true };
      },
    );

    await assert.rejects(
      () => wrapped({ ...fixture.request(), authorizationToken: badToken }),
      /signature verification failed/,
    );

    assert.equal(called, false);
    assert.equal(fixture.log.queryByTokenRef(new Uint8Array(32)).entries.length, 0);
  });

  it("supports custom token extraction and canonicalizers", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "await" },
    });
    const wrapped = receipts.tool<{ token: string; input: string }, ToolResponse>(
      "custom.action",
      async () => ({ ok: true }),
      {
        authorizationToken: (request) => request.token,
        canonicalizeInput: (request) => textEncoder.encode(request.input),
        canonicalizeOutput: (response) => textEncoder.encode(String(response.ok)),
      },
    );

    await wrapped({ token: fixture.authorizationToken, input: "stable input" });
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts[0].receipt["action-type"], "custom.action");
  });

  it("background submission returns before a slow append completes", async () => {
    const fixture = makeFixture();
    let resolveAppend: (() => void) | undefined;
    let appended = false;
    const slowLog = {
      logUrl,
      append: async (
        envelope: Uint8Array,
        integratedTime?: string,
      ): Promise<TransparencyLogEntry> => {
        await new Promise<void>((resolve) => {
          resolveAppend = resolve;
        });
        appended = true;
        return fixture.log.append(envelope, integratedTime);
      },
    };
    const receipts = sello.service({
      ...fixture.serviceConfig({ log: slowLog }),
      submit: { mode: "background" },
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async () => ({ ok: true }),
    );

    const response = await wrapped(fixture.request());

    assert.deepEqual(response, { ok: true });
    assert.equal(appended, false);

    resolveAppend?.();
    await receipts.flush();

    assert.equal(appended, true);
    assert.equal(verifyReceipts(fixture.ownerInput()).receipts.length, 1);
  });

  it("drops background submissions when the queue is full", async () => {
    const fixture = makeFixture();
    const drops: unknown[] = [];
    const receipts = sello.service({
      ...fixture.serviceConfig(),
      submit: { mode: "background", maxPending: 0 },
      onDrop: (event) => drops.push(event),
    });
    const wrapped = receipts.tool<ToolRequest, ToolResponse>(
      "calendar.create_event",
      async () => ({ ok: true }),
    );

    await wrapped(fixture.request());
    await receipts.flush();

    assert.equal(drops.length, 1);
    assert.equal(verifyReceipts(fixture.ownerInput()).receipts.length, 0);
  });

  it("loads service config from env without requiring owner keys", () => {
    const fixture = makeFixture();
    const previous = snapshotEnv();
    try {
      process.env.SELLO_SERVICE_ID = fixture.serviceIdentifier;
      process.env.SELLO_SERVICE_KEY = encodeServiceKey(
        fixture.serviceKid,
        fixture.service.privateKey,
      );
      process.env.SELLO_TOKEN_ISSUER_PUBLIC_KEY = base64urlEncode(
        fixture.tokenIssuer.publicKey,
      );
      process.env.SELLO_LOG_URL = logUrl;
      delete process.env.SELLO_OWNER_KEY;

      const receipts = sello.service();

      assert.equal(typeof receipts.tool, "function");
      assert.equal(typeof receipts.flush, "function");
    } finally {
      restoreEnv(previous);
    }
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("svc-key-1");
  const serviceIdentifier = "calendar.example.com/mcp/v1";
  const log = new MockTransparencyLog(logUrl);
  const authorizationToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      owner_hpke_pk: base64urlEncode(owner.publicKey),
      sello_logs: [logUrl],
    },
  });
  const registryBytes = textEncoder.encode(
    JSON.stringify({
      [toHex(serviceKid)]: {
        service_identifier: serviceIdentifier,
        public_key_ed25519: base64urlEncode(service.publicKey),
      },
    }),
  );
  const registry = loadSignedRegistry({
    registryBytes,
    signatureBase64Url: signRegistryJson(registryBytes, trustRoot.privateKey),
    trustRootPublicKey: trustRoot.publicKey,
  });

  return {
    owner,
    service,
    tokenIssuer,
    serviceKid,
    serviceIdentifier,
    log,
    authorizationToken,
    request: (): ToolRequest => ({
      authorizationToken,
      params: { title: "launch" },
    }),
    serviceConfig: (
      overrides: Partial<Parameters<typeof sello.service>[0] & { log: unknown }> = {},
    ) => ({
      service: serviceIdentifier,
      serviceKey: {
        kid: serviceKid,
        privateKey: service.privateKey,
      },
      tokenIssuer: tokenIssuer.publicKey,
      log,
      now: () => "2026-06-04T10:12:03Z",
      ...overrides,
    }),
    ownerInput: () => ({
      authorizationTokenBytes: textEncoder.encode(authorizationToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}

function snapshotEnv(): Record<string, string | undefined> {
  return {
    SELLO_SERVICE_ID: process.env.SELLO_SERVICE_ID,
    SELLO_SERVICE_KEY: process.env.SELLO_SERVICE_KEY,
    SELLO_TOKEN_ISSUER_PUBLIC_KEY: process.env.SELLO_TOKEN_ISSUER_PUBLIC_KEY,
    SELLO_LOG_URL: process.env.SELLO_LOG_URL,
    SELLO_OWNER_KEY: process.env.SELLO_OWNER_KEY,
  };
}

function restoreEnv(snapshot: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(snapshot)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}
