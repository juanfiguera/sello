import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { generateEd25519KeyPair } from "../../src/cose/sign1.ts";
import { toHex } from "../../src/crypto/identifiers.ts";
import { generateHpkeKeyPair } from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";
import {
  canonicalJsonBytes,
  createSelloMcpMiddleware,
  type SelloMcpReceiptEvent,
} from "../../src/mcp/middleware.ts";
import { verifyReceipts } from "../../src/owner/verify.ts";
import { ZERO_SHA256_DIGEST } from "../../src/receipt/body.ts";
import {
  loadSignedRegistry,
  signRegistryJson,
} from "../../src/registry/json-registry.ts";
import {
  base64urlEncode,
  signSelloJwsToken,
} from "../../src/token/jws-profile.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;

type ToolRequest = {
  authorization: string;
  params: {
    name: string;
    arguments: Record<string, unknown>;
  };
};

type ToolResponse = {
  content?: readonly { type: "text"; text: string }[];
  error?: { code: number; message: string };
};

describe("Sello MCP middleware", () => {
  it("emits a success receipt around a tool handler", async () => {
    const fixture = makeFixture();
    const receipts: SelloMcpReceiptEvent<ToolResponse>[] = [];
    const handler = createSelloMcpMiddleware<ToolRequest, ToolResponse>({
      ...fixture.middlewareInput(receipts),
      handler: async (request) => ({
        content: [{ type: "text", text: `created ${request.params.arguments.title}` }],
      }),
    });

    const response = await handler(fixture.request());
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(response.content?.[0].text, "created launch notes");
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].resultStatus, "success");
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].receipt["action-type"], "tools/call");
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("emits an error receipt and rethrows handler failures", async () => {
    const fixture = makeFixture();
    const receipts: SelloMcpReceiptEvent<ToolResponse>[] = [];
    const handler = createSelloMcpMiddleware<ToolRequest, ToolResponse>({
      ...fixture.middlewareInput(receipts),
      handler: async () => {
        throw new Error("tool exploded");
      },
    });

    await assert.rejects(() => handler(fixture.request()), /tool exploded/);
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].resultStatus, "error");
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts[0].receipt["result-status"], "error");
  });

  it("emits a denied receipt without running the handler", async () => {
    const fixture = makeFixture();
    const receipts: SelloMcpReceiptEvent<ToolResponse>[] = [];
    let handlerCalled = false;
    const handler = createSelloMcpMiddleware<ToolRequest, ToolResponse>({
      ...fixture.middlewareInput(receipts),
      handler: async () => {
        handlerCalled = true;
        return { content: [{ type: "text", text: "should not run" }] };
      },
      isDenied: async () => true,
      deniedResponse: async () => ({
        error: { code: -32000, message: "denied" },
      }),
    });

    const response = await handler(fixture.request());
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(handlerCalled, false);
    assert.equal(response.error?.message, "denied");
    assert.equal(receipts[0].resultStatus, "denied");
    assert.equal(verified.receipts[0].receipt["result-status"], "denied");
    assert.deepEqual(
      verified.receipts[0].receipt["action-output-hash"],
      ZERO_SHA256_DIGEST,
    );
  });

  it("verifies the token before running the handler", async () => {
    const fixture = makeFixture();
    const otherIssuer = generateEd25519KeyPair();
    const badToken = signSelloJwsToken({
      issuerPrivateKey: otherIssuer.privateKey,
      payload: {
        owner_hpke_pk: "not-a-key",
        sello_logs: ["https://Rekor.example.com/api"],
      },
    });
    let handlerCalled = false;
    const handler = createSelloMcpMiddleware<ToolRequest, ToolResponse>({
      ...fixture.middlewareInput([]),
      authorizationToken: () => badToken,
      handler: async () => {
        handlerCalled = true;
        return { content: [{ type: "text", text: "should not run" }] };
      },
    });

    await assert.rejects(() => handler(fixture.request()), /signature verification failed/);

    assert.equal(handlerCalled, false);
    assert.equal(fixture.log.queryByTokenRef(new Uint8Array(32)).entries.length, 0);
  });

  it("canonicalizes JSON input with sorted object keys", () => {
    assert.equal(
      new TextDecoder().decode(canonicalJsonBytes({ b: 2, a: { d: 4, c: 3 } })),
      '{"a":{"c":3,"d":4},"b":2}',
    );
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("svc-key-1");
  const log = new MockTransparencyLog(logUrl);
  const serviceIdentifier = "github.com/mcp/v1";
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
        public_key_ed25519: Buffer.from(service.publicKey).toString("base64url"),
      },
    }),
  );
  const registry = loadSignedRegistry({
    registryBytes,
    signatureBase64Url: signRegistryJson(registryBytes, trustRoot.privateKey),
    trustRootPublicKey: trustRoot.publicKey,
  });

  return {
    log,
    request: (): ToolRequest => ({
      authorization: authorizationToken,
      params: {
        name: "create_issue",
        arguments: { title: "launch notes" },
      },
    }),
    middlewareInput: (receipts: SelloMcpReceiptEvent<ToolResponse>[]) => ({
      authorizationToken: (request: ToolRequest) => request.authorization,
      tokenIssuerPublicKey: tokenIssuer.publicKey,
      serviceKid,
      servicePrivateKey: service.privateKey,
      serviceIdentifier,
      log,
      canonicalizeInput: (request: ToolRequest) => canonicalJsonBytes(request.params),
      now: () => "2026-05-28T10:00:00Z",
      onReceipt: (event: SelloMcpReceiptEvent<ToolResponse>) => {
        receipts.push(event);
      },
    }),
    ownerInput: (
      overrides: Partial<Parameters<typeof verifyReceipts>[0]> = {},
    ) => ({
      authorizationTokenBytes: textEncoder.encode(authorizationToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
      ...overrides,
    }),
  };
}
