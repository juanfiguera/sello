import assert from "node:assert/strict";
import { it } from "node:test";

import {
  buildReceiptHpkeInfo,
  loadSignedRegistry,
  generateEd25519KeyPair,
  MockTransparencyLog,
  RekorDiscoveryLog,
  createSelloMcpMiddleware,
  buildReceipt,
  createReceiptFromJwsToken,
  createReceipt,
  decodeProtectedHeader,
  deriveTokenIdentifiers,
  encodeProtectedHeader,
  generateHpkeKeyPair,
  isCanonicalLogUrl,
  openReceiptBody,
  signReceiptEnvelope,
  signRegistryJson,
  verifySelloJwsToken,
  sealReceiptBody,
  sello,
  verifyReceipts,
  verifyReceiptEnvelope,
} from "../src/index.ts";

it("exports the initial public API from the package root", () => {
  const identifiers = deriveTokenIdentifiers(new TextEncoder().encode("token"));

  assert.equal(identifiers.sello_token_ref.byteLength, 32);
  assert.match(identifiers.agent_identifier, /^[0-9a-f]{32}$/);
});

it("exports canonical log URL helpers from the package root", () => {
  assert.equal(isCanonicalLogUrl("https://rekor.example.com/api"), true);
});

it("exports protected header helpers from the package root", () => {
  assert.equal(typeof encodeProtectedHeader, "function");
  assert.equal(typeof decodeProtectedHeader, "function");
});

it("exports receipt HPKE helpers from the package root", () => {
  assert.equal(typeof generateHpkeKeyPair, "function");
  assert.equal(typeof buildReceiptHpkeInfo, "function");
  assert.equal(typeof sealReceiptBody, "function");
  assert.equal(typeof openReceiptBody, "function");
});

it("exports COSE signing helpers from the package root", () => {
  assert.equal(typeof generateEd25519KeyPair, "function");
  assert.equal(typeof signReceiptEnvelope, "function");
  assert.equal(typeof verifyReceiptEnvelope, "function");
});

it("exports registry helpers from the package root", () => {
  assert.equal(typeof signRegistryJson, "function");
  assert.equal(typeof loadSignedRegistry, "function");
});

it("exports mock log helpers from the package root", () => {
  assert.equal(typeof MockTransparencyLog, "function");
});

it("exports Rekor discovery helpers from the package root", () => {
  assert.equal(typeof RekorDiscoveryLog, "function");
});

it("exports owner verification helpers from the package root", () => {
  assert.equal(typeof verifyReceipts, "function");
});

it("exports MCP middleware helpers from the package root", () => {
  assert.equal(typeof createSelloMcpMiddleware, "function");
});

it("exports service receipt creation helpers from the package root", () => {
  assert.equal(typeof buildReceipt, "function");
  assert.equal(typeof createReceipt, "function");
  assert.equal(typeof createReceiptFromJwsToken, "function");
});

it("exports JWS token profile helpers from the package root", () => {
  assert.equal(typeof verifySelloJwsToken, "function");
});

it("exports the Stripe-style SDK facade from the package root", () => {
  const service = generateEd25519KeyPair();
  const receipts = sello.service({
    service: "calendar.example.com/test",
    serviceKey: {
      kid: new TextEncoder().encode("export-test-key"),
      privateKey: service.privateKey,
    },
    tokenIssuer: service.publicKey,
    log: sello.logs.memory("https://rekor.example.com/api"),
  });

  assert.equal(typeof sello.service, "function");
  assert.equal(typeof sello.logs.memory, "function");
  assert.equal(typeof sello.logs.http, "function");
  assert.equal(typeof receipts.a2aMessage, "function");
  assert.equal(typeof receipts.mcpTool, "function");
});
