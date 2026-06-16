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
  createCalendarA2aAgent,
  type MinimalA2aRequest,
} from "../../examples/a2a-minimal-server.ts";

const textEncoder = new TextEncoder();
const logUrl = "https://localhost:8787/api" as CanonicalLogUrl;

describe("minimal A2A integration example", () => {
  it("wraps a message/send handler and emits a verifiable receipt", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      service: fixture.serviceIdentifier,
      serviceKey: fixture.serviceKey,
      tokenIssuer: fixture.tokenIssuerPublicKey,
      log: fixture.log,
      submit: { mode: "await" },
      now: () => "2026-06-16T10:12:03Z",
    });
    const agent = createCalendarA2aAgent(receipts);

    const response = await agent.handle(fixture.request("message/send"));
    await agent.flush();

    const verified = verifyReceipts(fixture.ownerInput());
    assert.deepEqual(response, {
      jsonrpc: "2.0",
      id: "a2a-call-1",
      result: {
        kind: "message",
        messageId: "calendar-reply-1",
        role: "agent",
        parts: [
          {
            kind: "text",
            text: "created Ship the A2A example",
          },
        ],
      },
    });
    assert.equal(verified.rejected.length, 0);
    assert.equal(verified.receipts.length, 1);
    assert.equal(verified.receipts[0].serviceIdentifier, fixture.serviceIdentifier);
    assert.equal(verified.receipts[0].receipt["action-type"], "a2a.message/send");
    assert.equal(verified.receipts[0].receipt["result-status"], "success");
  });

  it("does not emit a receipt for unknown A2A methods", async () => {
    const fixture = makeFixture();
    const receipts = sello.service({
      service: fixture.serviceIdentifier,
      serviceKey: fixture.serviceKey,
      tokenIssuer: fixture.tokenIssuerPublicKey,
      log: fixture.log,
      submit: { mode: "await" },
    });
    const agent = createCalendarA2aAgent(receipts);

    const response = await agent.handle(fixture.request("tasks/get"));
    await agent.flush();

    assert.deepEqual(response, {
      jsonrpc: "2.0",
      id: "a2a-call-1",
      error: {
        code: -32601,
        message: "method not found",
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
  const serviceKid = textEncoder.encode("minimal-a2a-service-key");
  const serviceIdentifier = "calendar.example.com/a2a/v1";
  const log = sello.logs.memory(logUrl);
  const agentToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "minimal-a2a-agent",
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
    request: (method: string): MinimalA2aRequest => ({
      headers: {
        authorization: `Bearer ${agentToken}`,
      },
      body: {
        jsonrpc: "2.0",
        id: "a2a-call-1",
        method,
        params: {
          message: {
            role: "user",
            parts: [{ kind: "text", text: "Ship the A2A example" }],
          },
        },
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
