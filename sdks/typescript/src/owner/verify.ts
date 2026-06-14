import { decodeProtectedHeader } from "../cose/protected-header.ts";
import { decodeReceiptEnvelope, verifyReceiptEnvelope } from "../cose/sign1.ts";
import { deriveTokenIdentifiers, toHex } from "../crypto/identifiers.ts";
import { openReceiptBody } from "../hpke/receipt.ts";
import {
  type CanonicalLogUrl,
  logUrlsEqual,
} from "../log/canonical-url.ts";
import {
  type LogCompleteness,
  type TransparencyLogEntry,
  type VerificationLog,
} from "../log/types.ts";
import { decodeReceiptBody, type ReceiptBody } from "../receipt/body.ts";
import {
  type JsonIdentityRegistry,
  assertKeyNotRevoked,
  resolveServiceKey,
} from "../registry/json-registry.ts";

export type VerificationRejectionCode =
  | "log_url_mismatch"
  | "untrusted_log"
  | "inclusion_proof_failed"
  | "token_ref_mismatch"
  | "unknown_kid"
  | "revoked_key"
  | "cose_signature_failed"
  | "hpke_open_failed"
  | "invalid_receipt_body";

export type VerifyReceiptsInput = {
  authorizationTokenBytes: Uint8Array;
  trustedLogs: readonly VerificationLog[];
  registry: JsonIdentityRegistry;
  ownerPrivateKey: Uint8Array;
};

export type VerifiedReceipt = {
  status: "valid" | "duplicate";
  receipt: ReceiptBody;
  serviceIdentifier: string;
  kidHex: string;
  tokenRefHex: string;
  logUrl: CanonicalLogUrl;
  logCompleteness: LogCompleteness;
  integratedTime: string;
  duplicateOf?: number;
  sameSecondActivity: boolean;
};

export type RejectedReceipt = {
  status: "rejected";
  code: VerificationRejectionCode;
  message: string;
  logUrl?: CanonicalLogUrl;
  integratedTime?: string;
};

export type VerifyReceiptsResult = {
  receipts: VerifiedReceipt[];
  rejected: RejectedReceipt[];
};

export function verifyReceipts(input: VerifyReceiptsInput): VerifyReceiptsResult {
  const identifiers = deriveTokenIdentifiers(input.authorizationTokenBytes);
  const trustedLogUrls = input.trustedLogs.map((log) => log.logUrl);
  const receipts: VerifiedReceipt[] = [];
  const rejected: RejectedReceipt[] = [];
  const exactDedup = new Map<string, number>();
  const sameSecond = new Map<string, number>();

  for (const log of input.trustedLogs) {
    const result = log.queryByTokenRef(identifiers.sello_token_ref);

    for (const entry of result.entries) {
      const verified = verifyOneEntry({
        entry,
        log,
        logCompleteness: result.completeness,
        trustedLogUrls,
        tokenRef: identifiers.sello_token_ref,
        registry: input.registry,
        ownerPrivateKey: input.ownerPrivateKey,
      });

      if (verified.status === "rejected") {
        rejected.push(verified);
        continue;
      }

      const exactKey = buildExactDedupKey(verified);
      const existingIndex = exactDedup.get(exactKey);

      if (existingIndex !== undefined) {
        receipts.push({
          ...verified,
          status: "duplicate",
          duplicateOf: existingIndex,
        });
        continue;
      }

      const sameSecondKey = buildSameSecondKey(verified);
      const sameSecondIndex = sameSecond.get(sameSecondKey);

      if (sameSecondIndex !== undefined) {
        receipts[sameSecondIndex] = {
          ...receipts[sameSecondIndex],
          sameSecondActivity: true,
        };
        verified.sameSecondActivity = true;
      } else {
        sameSecond.set(sameSecondKey, receipts.length);
      }

      exactDedup.set(exactKey, receipts.length);
      receipts.push(verified);
    }
  }

  return { receipts, rejected };
}

type VerifyOneEntryInput = {
  entry: TransparencyLogEntry;
  log: VerificationLog;
  logCompleteness: LogCompleteness;
  trustedLogUrls: readonly CanonicalLogUrl[];
  tokenRef: Uint8Array;
  registry: JsonIdentityRegistry;
  ownerPrivateKey: Uint8Array;
};

function verifyOneEntry(input: VerifyOneEntryInput): VerifiedReceipt | RejectedReceipt {
  let protectedHeaderBytes: Uint8Array;
  let payload: Uint8Array;
  let protectedHeader: ReturnType<typeof decodeProtectedHeader>;

  try {
    const envelope = decodeReceiptEnvelope(input.entry.envelope);
    protectedHeaderBytes = envelope.protectedBytes;
    payload = envelope.payload;
    protectedHeader = decodeProtectedHeader(protectedHeaderBytes);
  } catch (error) {
    return reject("invalid_receipt_body", error, input.entry);
  }

  if (!logUrlsEqual(protectedHeader.sello_log_url, input.log.logUrl)) {
    return reject(
      "log_url_mismatch",
      "receipt log URL does not match returning log",
      input.entry,
    );
  }

  if (!input.trustedLogUrls.some((logUrl) => logUrlsEqual(logUrl, input.log.logUrl))) {
    return reject("untrusted_log", "returning log is not trusted", input.entry);
  }

  if (!bytesEqual(protectedHeader.sello_token_ref, input.tokenRef)) {
    return reject(
      "token_ref_mismatch",
      "receipt token ref does not match requested token",
      input.entry,
    );
  }

  if (!input.log.verifyInclusionProof(input.entry)) {
    return reject("inclusion_proof_failed", "inclusion proof failed", input.entry);
  }

  let service;
  try {
    service = resolveServiceKey(input.registry, protectedHeader.kid);
  } catch (error) {
    return reject("unknown_kid", error, input.entry);
  }

  try {
    assertKeyNotRevoked(
      input.registry,
      protectedHeader.kid,
      input.entry.integratedTime,
    );
  } catch (error) {
    return reject("revoked_key", error, input.entry);
  }

  try {
    verifyReceiptEnvelope({
      envelope: input.entry.envelope,
      servicePublicKey: service.publicKeyEd25519,
    });
  } catch (error) {
    return reject("cose_signature_failed", error, input.entry);
  }

  let plaintext;
  try {
    plaintext = openReceiptBody({
      payload,
      ownerPrivateKey: input.ownerPrivateKey,
      protectedHeaderBytes,
      serviceIdentifier: service.serviceIdentifier,
      selloTokenRef: protectedHeader.sello_token_ref,
    });
  } catch (error) {
    return reject("hpke_open_failed", error, input.entry);
  }

  try {
    return {
      status: "valid",
      receipt: decodeReceiptBody(plaintext),
      serviceIdentifier: service.serviceIdentifier,
      kidHex: toHex(protectedHeader.kid),
      tokenRefHex: toHex(protectedHeader.sello_token_ref),
      logUrl: input.log.logUrl,
      logCompleteness: input.logCompleteness,
      integratedTime: input.entry.integratedTime,
      sameSecondActivity: false,
    };
  } catch (error) {
    return reject("invalid_receipt_body", error, input.entry);
  }
}

function buildExactDedupKey(record: VerifiedReceipt): string {
  return [
    buildSameSecondKey(record),
    record.receipt["action-type"],
    toHex(record.receipt["action-input-hash"]),
    toHex(record.receipt["action-output-hash"]),
  ].join("|");
}

function buildSameSecondKey(record: VerifiedReceipt): string {
  return [
    record.kidHex,
    record.tokenRefHex,
    truncateTimestampToSecond(record.receipt.timestamp),
  ].join("|");
}

function truncateTimestampToSecond(timestamp: string): string {
  return timestamp.replace(/\.\d+Z$/, "Z");
}

function reject(
  code: VerificationRejectionCode,
  error: unknown,
  entry: TransparencyLogEntry,
): RejectedReceipt {
  return {
    status: "rejected",
    code,
    message: error instanceof Error ? error.message : String(error),
    logUrl: entry.logUrl,
    integratedTime: entry.integratedTime,
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let index = 0; index < a.byteLength; index += 1) {
    if (a[index] !== b[index]) {
      return false;
    }
  }

  return true;
}
