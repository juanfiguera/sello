import assert from "node:assert/strict";
import { it } from "node:test";

import {
  buildReceiptHpkeInfo,
  loadSignedRegistry,
  generateEd25519KeyPair,
  MockTransparencyLog,
  createReceipt,
  decodeProtectedHeader,
  deriveTokenIdentifiers,
  encodeProtectedHeader,
  generateHpkeKeyPair,
  isCanonicalLogUrl,
  openReceiptBody,
  signReceiptEnvelope,
  signRegistryJson,
  sealReceiptBody,
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

it("exports owner verification helpers from the package root", () => {
  assert.equal(typeof verifyReceipts, "function");
});

it("exports service receipt creation helpers from the package root", () => {
  assert.equal(typeof createReceipt, "function");
});
