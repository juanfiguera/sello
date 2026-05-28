import { encodeProtectedHeader } from "../cose/protected-header.ts";
import { signReceiptEnvelope } from "../cose/sign1.ts";
import { deriveTokenIdentifiers, sha256 } from "../crypto/identifiers.ts";
import { sealReceiptBody } from "../hpke/receipt.ts";
import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
  logUrlsEqual,
} from "../log/canonical-url.ts";
import { type MockLogEntry, MockTransparencyLog } from "../log/mock-log.ts";
import {
  ZERO_SHA256_DIGEST,
  encodeReceiptBody,
  type ReceiptBody,
  type ResultStatus,
} from "../receipt/body.ts";

export type CreateReceiptInput = {
  authorizationTokenBytes: Uint8Array;
  ownerHpkePublicKey: Uint8Array;
  selloLogs: readonly string[];
  serviceKid: Uint8Array;
  servicePrivateKey: Uint8Array;
  serviceIdentifier: string;
  log: MockTransparencyLog;
  actionType: string;
  actionInputBytes: Uint8Array;
  actionOutputBytes?: Uint8Array;
  resultStatus: ResultStatus;
  timestamp: string;
};

export type CreatedReceipt = {
  receiptBody: ReceiptBody;
  protectedHeaderBytes: Uint8Array;
  envelope: Uint8Array;
  logEntry: MockLogEntry;
};

export function createReceipt(input: CreateReceiptInput): CreatedReceipt {
  assertBytes(input.authorizationTokenBytes, "authorizationTokenBytes");
  assertByteLength(input.ownerHpkePublicKey, 32, "ownerHpkePublicKey");
  assertBytes(input.serviceKid, "serviceKid");
  assertBytes(input.servicePrivateKey, "servicePrivateKey");
  assertBytes(input.actionInputBytes, "actionInputBytes");

  if (typeof input.serviceIdentifier !== "string" || input.serviceIdentifier.length === 0) {
    throw new TypeError("serviceIdentifier must be a non-empty string");
  }

  if (typeof input.actionType !== "string" || input.actionType.length === 0) {
    throw new TypeError("actionType must be a non-empty string");
  }

  const selectedLogUrl = selectOwnerTrustedLog(input.selloLogs, input.log.logUrl);
  const identifiers = deriveTokenIdentifiers(input.authorizationTokenBytes);
  const receiptBody: ReceiptBody = {
    "agent-identifier": identifiers.agent_identifier,
    "action-type": input.actionType,
    "action-input-hash": sha256(input.actionInputBytes),
    "action-output-hash":
      input.resultStatus === "denied"
        ? ZERO_SHA256_DIGEST
        : sha256(input.actionOutputBytes ?? new Uint8Array()),
    "result-status": input.resultStatus,
    timestamp: input.timestamp,
  };
  const protectedHeaderBytes = encodeProtectedHeader({
    kid: input.serviceKid,
    sello_token_ref: identifiers.sello_token_ref,
    sello_log_url: selectedLogUrl,
  });
  const payload = sealReceiptBody({
    plaintext: encodeReceiptBody(receiptBody),
    ownerPublicKey: input.ownerHpkePublicKey,
    protectedHeaderBytes,
    serviceIdentifier: input.serviceIdentifier,
    selloTokenRef: identifiers.sello_token_ref,
  });
  const envelope = signReceiptEnvelope({
    protectedHeaderBytes,
    payload,
    servicePrivateKey: input.servicePrivateKey,
  });
  const logEntry = input.log.append(envelope, input.timestamp);

  return {
    receiptBody,
    protectedHeaderBytes,
    envelope,
    logEntry,
  };
}

function selectOwnerTrustedLog(
  selloLogs: readonly string[],
  candidateLogUrl: CanonicalLogUrl,
): CanonicalLogUrl {
  if (!Array.isArray(selloLogs) || selloLogs.length === 0) {
    throw new TypeError("selloLogs must contain at least one owner-trusted log");
  }

  const canonicalLogs = selloLogs.map((logUrl) => {
    assertCanonicalLogUrl(logUrl, "selloLogs entry");
    return logUrl;
  });

  const match = canonicalLogs.find((logUrl) => logUrlsEqual(logUrl, candidateLogUrl));
  if (!match) {
    throw new TypeError("service log must be listed in selloLogs");
  }

  return match;
}

function assertByteLength(
  value: unknown,
  length: number,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new TypeError(`${name} must be a ${length}-byte Uint8Array`);
  }
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}
