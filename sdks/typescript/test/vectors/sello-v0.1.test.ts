import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { decodeProtectedHeader } from "../../src/cose/protected-header.ts";
import {
  decodeReceiptEnvelope,
  verifyReceiptEnvelope,
} from "../../src/cose/sign1.ts";
import { deriveTokenIdentifiers, toHex } from "../../src/crypto/identifiers.ts";
import { openReceiptBody } from "../../src/hpke/receipt.ts";
import { type CanonicalLogUrl } from "../../src/log/canonical-url.ts";
import { MockTransparencyLog } from "../../src/log/mock-log.ts";
import { verifyReceipts } from "../../src/owner/verify.ts";
import { decodeReceiptBody } from "../../src/receipt/body.ts";
import {
  loadSignedRegistry,
  resolveServiceKey,
} from "../../src/registry/json-registry.ts";
import { verifySelloJwsToken } from "../../src/token/jws-profile.ts";

type VectorFile = {
  common: {
    service_identifier: string;
    log_url: string;
    kid_hex: string;
    keys: Record<string, string>;
    registry_json: string;
    registry_signature_base64url: string;
  };
  vectors: VectorCase[];
};

type VectorCase = {
  name: string;
  integrated_time: string;
  authorization_token: string;
  sello_token_ref: string;
  agent_identifier: string;
  receipt_body: Record<string, string>;
  receipt_body_cbor_hex: string;
  protected_header_hex: string;
  hpke_payload_hex: string;
  cose_sign1_envelope_hex: string;
  mock_log_proof: {
    logUrl: string;
    index: number;
    integratedTime: string;
    envelopeHash: string;
    proofHash: string;
  };
};

const textEncoder = new TextEncoder();
const vectors = JSON.parse(
  readFileSync(new URL("../../fixtures/vectors/sello-v0.1.json", import.meta.url), "utf8"),
) as VectorFile;

describe("Sello v0.1 published vectors", () => {
  for (const vector of vectors.vectors) {
    it(`verifies ${vector.name} vector from committed bytes`, () => {
      const registryBytes = textEncoder.encode(vectors.common.registry_json);
      const registry = loadSignedRegistry({
        registryBytes,
        signatureBase64Url: vectors.common.registry_signature_base64url,
        trustRootPublicKey: fromHex(vectors.common.keys.trust_root_public_key_ed25519),
      });
      const verifiedToken = verifySelloJwsToken({
        authorizationToken: vector.authorization_token,
        issuerPublicKey: fromHex(vectors.common.keys.issuer_public_key_ed25519),
      });

      assert.equal(
        toHex(verifiedToken.ownerHpkePublicKey),
        vectors.common.keys.owner_public_key_x25519,
      );

      const identifiers = deriveTokenIdentifiers(verifiedToken.authorizationTokenBytes);
      assert.equal(toHex(identifiers.sello_token_ref), vector.sello_token_ref);
      assert.equal(identifiers.agent_identifier, vector.agent_identifier);

      const envelopeBytes = fromHex(vector.cose_sign1_envelope_hex);
      const envelope = decodeReceiptEnvelope(envelopeBytes);
      assert.equal(toHex(envelope.protectedBytes), vector.protected_header_hex);
      assert.equal(toHex(envelope.payload), vector.hpke_payload_hex);

      const protectedHeader = decodeProtectedHeader(envelope.protectedBytes);
      assert.equal(toHex(protectedHeader.kid), vectors.common.kid_hex);
      assert.equal(toHex(protectedHeader.sello_token_ref), vector.sello_token_ref);
      assert.equal(protectedHeader.sello_log_url, vectors.common.log_url);

      const service = resolveServiceKey(registry, protectedHeader.kid);
      assert.equal(service.serviceIdentifier, vectors.common.service_identifier);
      verifyReceiptEnvelope({
        envelope: envelopeBytes,
        servicePublicKey: service.publicKeyEd25519,
      });

      const plaintext = openReceiptBody({
        payload: envelope.payload,
        ownerPrivateKey: fromHex(vectors.common.keys.owner_private_key_x25519),
        protectedHeaderBytes: envelope.protectedBytes,
        serviceIdentifier: service.serviceIdentifier,
        selloTokenRef: protectedHeader.sello_token_ref,
      });
      assert.equal(toHex(plaintext), vector.receipt_body_cbor_hex);

      const receiptBody = decodeReceiptBody(plaintext);
      assert.equal(receiptBody["agent-identifier"], vector.receipt_body["agent-identifier"]);
      assert.equal(receiptBody["action-type"], vector.receipt_body["action-type"]);
      assert.equal(toHex(receiptBody["action-input-hash"]), vector.receipt_body["action-input-hash"]);
      assert.equal(toHex(receiptBody["action-output-hash"]), vector.receipt_body["action-output-hash"]);
      assert.equal(receiptBody["result-status"], vector.receipt_body["result-status"]);
      assert.equal(receiptBody.timestamp, vector.receipt_body.timestamp);

      const log = new MockTransparencyLog(vectors.common.log_url as CanonicalLogUrl);
      const logEntry = log.append(envelopeBytes, vector.integrated_time);
      assert.deepEqual(logEntry.proof, vector.mock_log_proof);

      const result = verifyReceipts({
        authorizationTokenBytes: verifiedToken.authorizationTokenBytes,
        trustedLogs: [log],
        registry,
        ownerPrivateKey: fromHex(vectors.common.keys.owner_private_key_x25519),
      });
      assert.equal(result.rejected.length, 0);
      assert.equal(result.receipts.length, 1);
      assert.equal(result.receipts[0].receipt["result-status"], vector.receipt_body["result-status"]);
    });
  }

  it("fails when a published envelope byte changes", () => {
    const vector = vectors.vectors[0];
    const envelopeBytes = fromHex(vector.cose_sign1_envelope_hex);
    envelopeBytes[envelopeBytes.byteLength - 1] ^= 0xff;

    assert.throws(
      () =>
        verifyReceiptEnvelope({
          envelope: envelopeBytes,
          servicePublicKey: fromHex(vectors.common.keys.service_public_key_ed25519),
        }),
      /signature verification failed/,
    );
  });
});

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}
