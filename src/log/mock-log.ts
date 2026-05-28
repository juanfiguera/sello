import { sha256, assertTokenRef, toHex } from "../crypto/identifiers.ts";
import { decodeProtectedHeader } from "../cose/protected-header.ts";
import { decodeReceiptEnvelope } from "../cose/sign1.ts";
import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
  logUrlsEqual,
} from "./canonical-url.ts";
import { type TransparencyLogQueryResult } from "./types.ts";

export type MockInclusionProof = {
  logUrl: CanonicalLogUrl;
  index: number;
  integratedTime: string;
  envelopeHash: string;
  proofHash: string;
};

export type MockLogEntry = {
  logUrl: CanonicalLogUrl;
  index: number;
  integratedTime: string;
  envelope: Uint8Array;
  proof: MockInclusionProof;
};

export type MockLogQueryResult = TransparencyLogQueryResult & {
  completeness: "complete";
  entries: MockLogEntry[];
};

export class MockTransparencyLog {
  readonly logUrl: CanonicalLogUrl;
  #entries: MockLogEntry[] = [];
  #tokenIndex = new Map<string, number[]>();

  constructor(logUrl: CanonicalLogUrl) {
    assertCanonicalLogUrl(logUrl, "logUrl");
    this.logUrl = logUrl;
  }

  append(envelope: Uint8Array, integratedTime = nowUtcSeconds()): MockLogEntry {
    assertBytes(envelope, "envelope");
    assertUtcTimestamp(integratedTime, "integratedTime");

    const decodedEnvelope = decodeReceiptEnvelope(envelope);
    const protectedHeader = decodeProtectedHeader(decodedEnvelope.protectedBytes);
    if (!logUrlsEqual(protectedHeader.sello_log_url, this.logUrl)) {
      throw new TypeError("envelope sello_log_url must match mock log URL");
    }

    const index = this.#entries.length;
    const proof = buildProof(this.logUrl, index, integratedTime, envelope);
    const entry = freezeEntry({
      logUrl: this.logUrl,
      index,
      integratedTime,
      envelope,
      proof,
    });

    this.#entries.push(entry);

    const tokenRefHex = toHex(protectedHeader.sello_token_ref);
    const indexes = this.#tokenIndex.get(tokenRefHex) ?? [];
    indexes.push(index);
    this.#tokenIndex.set(tokenRefHex, indexes);

    return cloneEntry(entry);
  }

  queryByTokenRef(tokenRef: Uint8Array): MockLogQueryResult {
    assertTokenRef(tokenRef, "tokenRef");
    const indexes = this.#tokenIndex.get(toHex(tokenRef)) ?? [];

    return {
      completeness: "complete",
      entries: indexes.map((index) => cloneEntry(this.#entries[index])),
    };
  }

  verifyInclusionProof(entry: MockLogEntry): boolean {
    try {
      assertCanonicalLogUrl(entry.logUrl, "entry.logUrl");
      if (!logUrlsEqual(entry.logUrl, this.logUrl)) {
        return false;
      }

      const expected = buildProof(
        this.logUrl,
        entry.index,
        entry.integratedTime,
        entry.envelope,
      );

      return (
        entry.proof.logUrl === expected.logUrl &&
        entry.proof.index === expected.index &&
        entry.proof.integratedTime === expected.integratedTime &&
        entry.proof.envelopeHash === expected.envelopeHash &&
        entry.proof.proofHash === expected.proofHash
      );
    } catch {
      return false;
    }
  }
}

function buildProof(
  logUrl: CanonicalLogUrl,
  index: number,
  integratedTime: string,
  envelope: Uint8Array,
): MockInclusionProof {
  const envelopeHash = toHex(sha256(envelope));
  const proofHash = toHex(
    sha256(
      new TextEncoder().encode(
        `${logUrl}\n${index}\n${integratedTime}\n${envelopeHash}`,
      ),
    ),
  );

  return {
    logUrl,
    index,
    integratedTime,
    envelopeHash,
    proofHash,
  };
}

function freezeEntry(entry: MockLogEntry): MockLogEntry {
  return {
    logUrl: entry.logUrl,
    index: entry.index,
    integratedTime: entry.integratedTime,
    envelope: new Uint8Array(entry.envelope),
    proof: { ...entry.proof },
  };
}

function cloneEntry(entry: MockLogEntry): MockLogEntry {
  return {
    logUrl: entry.logUrl,
    index: entry.index,
    integratedTime: entry.integratedTime,
    envelope: new Uint8Array(entry.envelope),
    proof: { ...entry.proof },
  };
}

function nowUtcSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function assertUtcTimestamp(value: string, name: string): void {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new TypeError(`${name} must be an RFC 3339 UTC timestamp`);
  }
}

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}
