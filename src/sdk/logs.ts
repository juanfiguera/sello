import { toHex } from "../crypto/identifiers.ts";
import {
  type CanonicalLogUrl,
  assertCanonicalLogUrl,
} from "../log/canonical-url.ts";
import { MockTransparencyLog } from "../log/mock-log.ts";
import {
  type TransparencyLogEntry,
  type TransparencyLogQueryResult,
} from "../log/types.ts";
import { base64urlEncode, decodeBase64url } from "./keys.ts";

export type MaybePromise<T> = T | Promise<T>;

export type SdkSubmissionLog = {
  logUrl: CanonicalLogUrl;
  append(
    envelope: Uint8Array,
    integratedTime?: string,
  ): MaybePromise<TransparencyLogEntry>;
};

export type SelloHttpLogOptions = {
  endpoint?: string;
  logUrl?: string;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
};

export type SerializedTransparencyLogEntry = {
  logUrl: string;
  index: number;
  integratedTime: string;
  envelope: string;
  proof: unknown;
};

export function memory(url: string): MockTransparencyLog {
  return new MockTransparencyLog(toCanonicalLogUrl(url));
}

export function http(url: string, options: SelloHttpLogOptions = {}): HttpSelloLog {
  return new HttpSelloLog(url, options);
}

export async function queryHttpLogByTokenRef(
  input: {
    endpoint: string;
    tokenRef: Uint8Array;
    headers?: Record<string, string>;
    fetch?: typeof fetch;
  },
): Promise<TransparencyLogQueryResult> {
  const fetcher = input.fetch ?? fetch;
  const url = buildUrl(input.endpoint, `/entries?sello_token_ref=${toHex(input.tokenRef)}`);
  const response = await fetcher(url, {
    method: "GET",
    headers: input.headers,
  });

  if (!response.ok) {
    throw new TypeError(`Sello log query failed with HTTP ${response.status}`);
  }

  const decoded = await response.json();
  if (!isRecord(decoded) || !Array.isArray(decoded.entries)) {
    throw new TypeError("Sello log query response must contain entries");
  }

  const completeness =
    decoded.completeness === "complete" ? "complete" : "discovery-only";

  return {
    completeness,
    entries: decoded.entries.map(deserializeEntry),
  };
}

export class HttpSelloLog {
  readonly logUrl: CanonicalLogUrl;
  readonly endpoint: string;
  readonly #headers?: Record<string, string>;
  readonly #fetch: typeof fetch;

  constructor(url: string, options: SelloHttpLogOptions = {}) {
    this.logUrl = toCanonicalLogUrl(options.logUrl ?? url);
    this.endpoint = normalizeEndpoint(options.endpoint ?? url);
    this.#headers = options.headers;
    this.#fetch = options.fetch ?? fetch;
  }

  async append(
    envelope: Uint8Array,
    integratedTime?: string,
  ): Promise<TransparencyLogEntry> {
    const response = await this.#fetch(buildUrl(this.endpoint, "/entries"), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...this.#headers,
      },
      body: JSON.stringify({
        logUrl: this.logUrl,
        envelope: base64urlEncode(envelope),
        ...(integratedTime === undefined ? {} : { integratedTime }),
      }),
    });

    if (!response.ok) {
      throw new TypeError(`Sello log append failed with HTTP ${response.status}`);
    }

    return deserializeEntry(await response.json());
  }
}

export function serializeEntry(
  entry: TransparencyLogEntry,
): SerializedTransparencyLogEntry {
  return {
    logUrl: entry.logUrl,
    index: entry.index,
    integratedTime: entry.integratedTime,
    envelope: base64urlEncode(entry.envelope),
    proof: cloneJson(entry.proof),
  };
}

export function deserializeEntry(input: unknown): TransparencyLogEntry {
  if (!isRecord(input)) {
    throw new TypeError("Sello log entry must be an object");
  }

  const { logUrl, index, integratedTime, envelope, proof } = input;
  assertCanonicalLogUrl(logUrl, "entry.logUrl");

  if (!Number.isSafeInteger(index) || index < 0) {
    throw new TypeError("entry.index must be a non-negative safe integer");
  }

  if (
    typeof integratedTime !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(integratedTime)
  ) {
    throw new TypeError("entry.integratedTime must be an RFC 3339 UTC timestamp");
  }

  if (typeof envelope !== "string") {
    throw new TypeError("entry.envelope must be base64url");
  }

  return {
    logUrl,
    index,
    integratedTime,
    envelope: decodeBase64url(envelope, "entry.envelope"),
    proof: cloneJson(proof),
  };
}

export function toCanonicalLogUrl(url: string): CanonicalLogUrl {
  if (typeof url !== "string" || url.length === 0) {
    throw new TypeError("log URL must be a non-empty string");
  }

  const parsed = new URL(url);
  const path = parsed.pathname === "/" ? "/api" : parsed.pathname;
  const protocol =
    parsed.protocol === "http:" && isLocalHost(parsed.hostname) ? "https:" : parsed.protocol;
  const canonical = `${protocol}//${parsed.host}${path}`;

  assertCanonicalLogUrl(canonical, "logUrl");
  return canonical;
}

function normalizeEndpoint(url: string): string {
  const parsed = new URL(url);
  const path = parsed.pathname === "/" ? "/api" : parsed.pathname.replace(/\/$/, "");
  return `${parsed.protocol}//${parsed.host}${path}`;
}

function buildUrl(endpoint: string, path: string): string {
  return `${endpoint.replace(/\/$/, "")}${path}`;
}

function isLocalHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cloneJson(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }

  return globalThis.structuredClone(value);
}
