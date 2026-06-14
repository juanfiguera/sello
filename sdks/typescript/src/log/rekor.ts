import { decodeProtectedHeader } from "../cose/protected-header.ts";
import { decodeReceiptEnvelope } from "../cose/sign1.ts";
import { assertTokenRef, toHex } from "../crypto/identifiers.ts";
import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
  logUrlsEqual,
} from "./canonical-url.ts";
import {
  type TransparencyLogEntry,
  type TransparencyLogQueryResult,
} from "./types.ts";

export type RekorProofVerifier = (entry: TransparencyLogEntry) => boolean;

export type RekorDiscoveredEntryInput = {
  tokenRef?: Uint8Array;
  logUrl?: CanonicalLogUrl;
  index: number;
  integratedTime: string;
  envelope: Uint8Array;
  proof: unknown;
};

export type RekorDiscoveryLogInput = {
  logUrl: CanonicalLogUrl;
  entries?: readonly RekorDiscoveredEntryInput[];
  verifyInclusionProof?: RekorProofVerifier;
};

type IndexedEntry = {
  tokenRefHex: string;
  entry: TransparencyLogEntry;
};

export class RekorDiscoveryLog {
  readonly logUrl: CanonicalLogUrl;
  #entries: IndexedEntry[] = [];
  #verifyInclusionProof: RekorProofVerifier;

  constructor(input: RekorDiscoveryLogInput) {
    assertCanonicalLogUrl(input.logUrl, "logUrl");
    this.logUrl = input.logUrl;
    this.#verifyInclusionProof = input.verifyInclusionProof ?? (() => false);

    for (const entry of input.entries ?? []) {
      this.addDiscoveredEntry(entry);
    }
  }

  addDiscoveredEntry(input: RekorDiscoveredEntryInput): TransparencyLogEntry {
    const entryLogUrl = input.logUrl ?? this.logUrl;
    assertCanonicalLogUrl(entryLogUrl, "entry.logUrl");
    assertUtcTimestamp(input.integratedTime, "integratedTime");
    assertSafeIndex(input.index);
    assertBytes(input.envelope, "envelope");

    const tokenRefHex = input.tokenRef
      ? tokenRefToHex(input.tokenRef)
      : tokenRefFromEnvelope(input.envelope);

    const entry = cloneEntry({
      logUrl: entryLogUrl,
      index: input.index,
      integratedTime: input.integratedTime,
      envelope: input.envelope,
      proof: input.proof,
    });

    this.#entries.push({ tokenRefHex, entry });
    return cloneEntry(entry);
  }

  queryByTokenRef(tokenRef: Uint8Array): TransparencyLogQueryResult {
    const tokenRefHex = tokenRefToHex(tokenRef);

    return {
      completeness: "discovery-only",
      entries: this.#entries
        .filter((indexed) => indexed.tokenRefHex === tokenRefHex)
        .map((indexed) => cloneEntry(indexed.entry)),
    };
  }

  verifyInclusionProof(entry: TransparencyLogEntry): boolean {
    try {
      assertCanonicalLogUrl(entry.logUrl, "entry.logUrl");
      if (!logUrlsEqual(entry.logUrl, this.logUrl)) {
        return false;
      }

      return this.#verifyInclusionProof(entry);
    } catch {
      return false;
    }
  }
}

function tokenRefFromEnvelope(envelope: Uint8Array): string {
  const decodedEnvelope = decodeReceiptEnvelope(envelope);
  const protectedHeader = decodeProtectedHeader(decodedEnvelope.protectedBytes);
  return tokenRefToHex(protectedHeader.sello_token_ref);
}

function tokenRefToHex(tokenRef: Uint8Array): string {
  assertTokenRef(tokenRef, "tokenRef");
  return toHex(tokenRef);
}

function cloneEntry(entry: TransparencyLogEntry): TransparencyLogEntry {
  return {
    logUrl: entry.logUrl,
    index: entry.index,
    integratedTime: entry.integratedTime,
    envelope: new Uint8Array(entry.envelope),
    proof: cloneProof(entry.proof),
  };
}

function cloneProof(proof: unknown): unknown {
  if (proof === null || typeof proof !== "object") {
    return proof;
  }

  return globalThis.structuredClone(proof);
}

function assertUtcTimestamp(value: string, name: string): void {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new TypeError(`${name} must be an RFC 3339 UTC timestamp`);
  }
}

function assertSafeIndex(index: number): void {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new TypeError("index must be a non-negative safe integer");
  }
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}
