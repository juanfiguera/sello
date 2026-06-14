import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  base64urlEncode,
  encodeServiceKey,
  generateEd25519KeyPair,
  generateHpkeKeyPair,
  loadSignedRegistry,
  sello,
  signRegistryJson,
  signSelloJwsToken,
  toHex,
  verifyReceipts,
  type CanonicalLogUrl,
} from "../../src/index.ts";
import {
  createCalendarMcpServer,
  type MinimalMcpRequest,
} from "../../examples/mcp-minimal-server.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://localhost:8787/api" as CanonicalLogUrl;

describe("minimal MCP integration example", () => {
  it("wraps a tools/call handler and emits a verifiable receipt", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      service: fixture.serviceIdentifier,
      serviceKey: fixture.serviceKey,
      tokenIssuer: fixture.tokenIssuerPublicKey,
      log: fixture.log,
      submit: { mode: "await" },
      now: () => "2026-06-07T10:12:03Z",
    });
    const server = createCalendarMcpServer(receipts);

    const response = await server.handle(fixture.request({
      name: "calendar.create_event",
      arguments: {
        calendarId: "demo-calendar",
        title: "Ship the minimal example",
      },
    }));
    await server.flush();

    const verified = verifyReceipts(fixture.ownerInput());
    assert.deepEqual(response, {
      jsonrpc: "2.0",
      id: "demo-call-1",
      result: {
        content: [
          {
            type: "text",
            text: "created Ship the minimal example",
          },
        ],
      },
    });
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].serviceIdentifier, fixture.serviceIdentifier);
    assert.equal(
      verified.receipts[0].receipt["action-type"],
      "mcp.tools/call.calendar.create_event",
    );
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("does not emit a receipt for unknown tools", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      service: fixture.serviceIdentifier,
      serviceKey: fixture.serviceKey,
      tokenIssuer: fixture.tokenIssuerPublicKey,
      log: fixture.log,
      submit: { mode: "await" },
    });
    const server = createCalendarMcpServer(receipts);

    const response = await server.handle(fixture.request({
      name: "unknown.tool",
      arguments: {},
    }));
    await server.flush();

    assert.deepEqual(response, {
      jsonrpc: "2.0",
      id: "demo-call-1",
      error: {
        code: -32601,
        message: "tool not found",
      },
    });
    assert.equal(verifyReceipts(fixture.ownerInput()).receipts.length, 0);
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("minimal-mcp-service-key");
  const serviceIdentifier = "calendar.example.com/mcp/v1";
  const log = sello.logs.memory(logUrl);
  const agentToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "minimal-mcp-agent",
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
    serviceIdentifier,
    serviceKey: encodeServiceKey(serviceKid, service.privateKey),
    tokenIssuerPublicKey: base64urlEncode(tokenIssuer.publicKey),
    log,
    request: (
      params: MinimalMcpRequest["body"]["params"],
    ): MinimalMcpRequest => ({
      headers: {
        authorization: `Bearer ${agentToken}`,
      },
      body: {
        jsonrpc: "2.0",
        id: "demo-call-1",
        method: "tools/call",
        params,
      },
    }),
    ownerInput: () => ({
      authorizationTokenBytes: textEncoder.encode(agentToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}
