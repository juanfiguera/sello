import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
  createSelloMcpToolServer,
  runMcpToolServerExample,
  type McpHttpToolCall,
} from "../../examples/mcp-tool-server.ts";
import { type QuickstartDevState } from "../../examples/quickstart-tool.ts";

const textEncoder = new TextEncoder();
const examplePath = fileURLToPath(
  new URL("../../examples/mcp-tool-server.ts", import.meta.url),
);
const logUrl = "https://localhost:8787/api" as CanonicalLogUrl;

describe("MCP tool server example", () => {
  it("handles tools/call and emits a verifiable receipt", async () => {
    const fixture = makeFixture();

    const result = await runMcpToolServerExample({
      state: fixture.state,
      log: fixture.log,
      now: () => "2026-06-05T10:12:03Z",
      toolArguments: {
        title: "Ship the MCP example",
      },
    });
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(result.response.status, 200);
    assert.deepEqual(result.response.body, {
      jsonrpc: "2.0",
      id: "demo-call-1",
      result: {
        content: [
          {
            type: "text",
            text: "created Ship the MCP example",
          },
        ],
      },
    });
    assert.equal(result.actionsUrl, "http://localhost:8787/actions");
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].serviceIdentifier, fixture.serviceIdentifier);
    assert.equal(
      verified.receipts[0].receipt["action-type"],
      "mcp.tools/call.calendar.create_event",
    );
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("returns a JSON-RPC error without emitting a receipt for unknown tools", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      service: fixture.serviceIdentifier,
      serviceKey: fixture.state.serviceKey,
      tokenIssuer: fixture.state.tokenIssuerPublicKey,
      log: fixture.log,
      submit: { mode: "await" },
      now: () => "2026-06-05T10:12:03Z",
    });
    const server = createSelloMcpToolServer(receipts);
    const response = await server.handle(fixture.request({
      name: "unknown.tool",
      arguments: {},
    }));
    await receipts.flush();

    assert.deepEqual(response.body, {
      jsonrpc: "2.0",
      id: "demo-call-1",
      error: {
        code: -32601,
        message: "tool not found",
      },
    });
    assert.equal(verifyReceipts(fixture.ownerInput()).receipts.length, 0);
  });

  it("prints a friendly setup error when local dev state is missing", () => {
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", examplePath],
      {
        cwd: mkdtempSync(join(tmpdir(), "sello-mcp-example-test-")),
        encoding: "utf8",
      },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /node --run dev/);
    assert.match(result.stderr, /node --run example:mcp/);
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("mcp-example-service-key");
  const serviceIdentifier = "calendar.example.com/mcp/v1";
  const log = sello.logs.memory(logUrl);
  const agentToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "mcp-example-agent",
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
  const state: QuickstartDevState = {
    serviceId: serviceIdentifier,
    serviceKey: encodeServiceKey(serviceKid, service.privateKey),
    tokenIssuerPublicKey: base64urlEncode(tokenIssuer.publicKey),
    agentToken,
    logUrl,
    logEndpoint: "http://localhost:8787/api",
  };

  return {
    serviceIdentifier,
    state,
    log,
    request: (
      params: McpHttpToolCall["body"]["params"],
    ): McpHttpToolCall => ({
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
