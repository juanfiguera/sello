import { encodeCbor } from "../cbor.ts";
import { decodeReceiptEnvelope, generateEd25519KeyPair } from "../cose/sign1.ts";
import { toHex } from "../crypto/identifiers.ts";
import { generateHpkeKeyPair } from "../hpke/receipt.ts";
import { type CanonicalLogUrl } from "../log/canonical-url.ts";
import { MockTransparencyLog } from "../log/mock-log.ts";
import { verifyReceipts } from "../owner/verify.ts";
import {
  loadSignedRegistry,
  signRegistryJson,
} from "../registry/json-registry.ts";
import { createReceipt } from "../service/create-receipt.ts";

const textEncoder = new TextEncoder();
const tokenBytes = textEncoder.encode("demo.compact.jws.token");
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const serviceIdentifier = "github.com/mcp/v1";

const owner = generateHpkeKeyPair();
const service = generateEd25519KeyPair();
const trustRoot = generateEd25519KeyPair();
const serviceKid = textEncoder.encode("github-mcp-v1-2026-q2");
const log = new MockTransparencyLog(logUrl);
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

const created = [
  createDemoReceipt("success", "2026-05-28T10:00:00Z", "issue created"),
  createDemoReceipt("error", "2026-05-28T10:00:01Z", "service error"),
  createDemoReceipt("denied", "2026-05-28T10:00:02Z", "ignored"),
];

if (process.argv.includes("--tamper")) {
  const decoded = decodeReceiptEnvelope(created[0].envelope);
  log.append(
    encodeCbor([
      decoded.protectedBytes,
      new Map(),
      textEncoder.encode("tampered payload"),
      decoded.signature,
    ]),
    "2026-05-28T10:00:03Z",
  );
}

const result = verifyReceipts({
  authorizationTokenBytes: tokenBytes,
  trustedLogs: [log],
  registry,
  ownerPrivateKey: owner.privateKey,
});

console.log(
  JSON.stringify(
    {
      receipts: result.receipts.map((record) => ({
        service: record.serviceIdentifier,
        "action-type": record.receipt["action-type"],
        "result-status": record.receipt["result-status"],
        timestamp: record.receipt.timestamp,
        verified: record.status === "valid",
        status: record.status,
      })),
      rejected: result.rejected.map((record) => ({
        code: record.code,
        message: record.message,
      })),
    },
    null,
    2,
  ),
);

function createDemoReceipt(
  resultStatus: "success" | "error" | "denied",
  timestamp: string,
  outputText: string,
) {
  return createReceipt({
    authorizationTokenBytes: tokenBytes,
    ownerHpkePublicKey: owner.publicKey,
    selloLogs: [logUrl],
    serviceKid,
    servicePrivateKey: service.privateKey,
    serviceIdentifier,
    log,
    actionType: "tools/call",
    actionInputBytes: textEncoder.encode(`demo ${resultStatus} input`),
    actionOutputBytes: textEncoder.encode(outputText),
    resultStatus,
    timestamp,
  });
}
