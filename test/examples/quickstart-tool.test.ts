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
  loadQuickstartDevState,
  runQuickstartTool,
  type QuickstartDevState,
} from "../../examples/quickstart-tool.ts";

const textEncoder = new TextEncoder();
const examplePath = fileURLToPath(
  new URL("../../examples/quickstart-tool.ts", import.meta.url),
);
const logUrl = "https://localhost:8787/api" as CanonicalLogUrl;

describe("quickstart tool example", () => {
  it("runs a wrapped tool and emits a verifiable receipt", async () => {
    const fixture = makeFixture();

    const result = await runQuickstartTool({
      state: fixture.state,
      log: fixture.log,
      now: () => "2026-06-05T10:12:03Z",
      request: {
        title: "Ship the example",
        attendees: ["reader@example.com"],
      },
    });
    const verified = verifyReceipts(fixture.ownerInput());

    assert.equal(result.response.status, "created");
    assert.equal(result.response.id, "evt_ship_the_example");
    assert.equal(result.actionsUrl, "http://localhost:8787/actions");
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].serviceIdentifier, fixture.serviceIdentifier);
    assert.equal(verified.receipts[0].receipt["action-type"], "calendar.create_event");
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("prints a friendly setup error when local dev state is missing", () => {
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", examplePath],
      {
        cwd: mkdtempSync(join(tmpdir(), "sello-example-test-")),
        encoding: "utf8",
      },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /node --run dev/);
    assert.match(result.stderr, /npx sello dev/);
    assert.match(result.stderr, /node --run example:tool/);
  });

  it("validates local dev state shape", () => {
    assert.throws(
      () => loadQuickstartDevState(join(makeTempCwd(), ".sello", "dev.json")),
      /missing local Sello dev state/,
    );
  });
});

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("quickstart-service-key");
  const serviceIdentifier = "calendar.example.com/mcp/v1";
  const log = sello.logs.memory(logUrl);
  const agentToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "quickstart-agent",
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
    ownerInput: () => ({
      authorizationTokenBytes: textEncoder.encode(agentToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}

function makeTempCwd(): string {
  return mkdtempSync(join(tmpdir(), "sello-example-test-"));
}
