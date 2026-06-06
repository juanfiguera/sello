#!/usr/bin/env -S node --experimental-strip-types

import { performance } from "node:perf_hooks";

import { encodeReceiptBody } from "../receipt/body.ts";
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
import {
  createReceiptFromJwsToken,
  type CreatedReceipt,
} from "../service/create-receipt.ts";
import { base64urlEncode, signSelloJwsToken } from "../token/jws-profile.ts";

type Distribution = {
  count: number;
  mean: number;
  median: number;
  p95: number;
  p99: number;
  stddev: number;
};

type BenchResult = {
  iterations: number;
  warmup_iterations: number;
  node: string;
  sizes: {
    receipt_body_cbor_bytes: number;
    protected_header_bytes: number;
    hpke_payload_bytes: number;
    cose_sign1_envelope_bytes: number;
    mock_log_proof_json_bytes: number;
  };
  timings_ms: {
    create_receipt_avg: number;
    verify_one_receipt_avg: number;
    verify_batch_total: number;
    verify_batch_per_receipt: number;
  };
  distributions: {
    create_receipt: Distribution;
    verify_one_receipt: Distribution;
    verify_batch_total: { count: 1; value: number };
    verify_batch_per_receipt: { count: 1; value: number };
  };
};

const DEFAULT_WARMUP_ITERATIONS = 500;

const textEncoder = new TextEncoder();
const logUrl = "https://rekor.example.com/api" as CanonicalLogUrl;
const serviceIdentifier = "github.com/mcp/v1";

const options = parseArgs(process.argv.slice(2));
const result = runBenchmark(options.iterations, options.warmupIterations);

if (options.json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  printText(result);
}

function runBenchmark(iterations: number, warmupIterations: number): BenchResult {
  const sampleFixture = makeFixture();
  const sampleReceipt = createBenchReceipt(sampleFixture, 0);
  const sampleEnvelope = decodeReceiptEnvelope(sampleReceipt.envelope);
  const sizes = {
    receipt_body_cbor_bytes: encodeReceiptBody(sampleReceipt.receiptBody).byteLength,
    protected_header_bytes: sampleReceipt.protectedHeaderBytes.byteLength,
    hpke_payload_bytes: sampleEnvelope.payload.byteLength,
    cose_sign1_envelope_bytes: sampleReceipt.envelope.byteLength,
    mock_log_proof_json_bytes: textEncoder.encode(
      JSON.stringify(sampleReceipt.logEntry.proof),
    ).byteLength,
  };

  // When --expose-gc is set, force a baseline GC before warmup so the steady-state
  // sample isn't contaminated by collection of size-sample allocations. Silently
  // skipped if the flag isn't present.
  if (typeof globalThis.gc === "function") {
    globalThis.gc();
  }

  warmup(warmupIterations);

  const createFixture = makeFixture();
  const createDurations = new Array<number>(iterations);
  for (let index = 0; index < iterations; index += 1) {
    const t0 = performance.now();
    createBenchReceipt(createFixture, index);
    createDurations[index] = performance.now() - t0;
  }

  const verifyOneFixture = makeFixture();
  createBenchReceipt(verifyOneFixture, 0);
  const verifyOneDurations = new Array<number>(iterations);
  for (let index = 0; index < iterations; index += 1) {
    const t0 = performance.now();
    const result = verifyReceipts(verifyOneFixture.ownerInput());
    verifyOneDurations[index] = performance.now() - t0;
    assertVerifiedCount(result.receipts.length, 1);
  }

  const batchFixture = makeFixture();
  for (let index = 0; index < iterations; index += 1) {
    createBenchReceipt(batchFixture, index);
  }
  const verifyBatchTiming = time(() => {
    const result = verifyReceipts(batchFixture.ownerInput());
    assertVerifiedCount(result.receipts.length, iterations);
  });

  const createTotal = sum(createDurations);
  const verifyOneTotal = sum(verifyOneDurations);

  return {
    iterations,
    warmup_iterations: warmupIterations,
    node: process.version,
    sizes,
    timings_ms: {
      create_receipt_avg: roundMs(createTotal / iterations),
      verify_one_receipt_avg: roundMs(verifyOneTotal / iterations),
      verify_batch_total: roundMs(verifyBatchTiming),
      verify_batch_per_receipt: roundMs(verifyBatchTiming / iterations),
    },
    distributions: {
      create_receipt: summarize(createDurations),
      verify_one_receipt: summarize(verifyOneDurations),
      verify_batch_total: { count: 1, value: roundMs(verifyBatchTiming) },
      verify_batch_per_receipt: {
        count: 1,
        value: roundMs(verifyBatchTiming / iterations),
      },
    },
  };
}

function warmup(count: number): void {
  const fixture = makeFixture();
  for (let index = 0; index < count; index += 1) {
    createBenchReceipt(fixture, index);
  }
  const verifyFixture = makeFixture();
  createBenchReceipt(verifyFixture, 0);
  for (let index = 0; index < count; index += 1) {
    const result = verifyReceipts(verifyFixture.ownerInput());
    assertVerifiedCount(result.receipts.length, 1);
  }
}

function summarize(durations: number[]): Distribution {
  if (durations.length === 0) {
    throw new Error("cannot summarize empty distribution");
  }
  const sorted = durations.slice().sort((a, b) => a - b);
  const count = sorted.length;
  const total = sum(sorted);
  const mean = total / count;
  const variance =
    sorted.reduce((acc, value) => acc + (value - mean) ** 2, 0) / count;
  return {
    count,
    mean: roundMs(mean),
    median: roundMs(percentile(sorted, 0.5)),
    p95: roundMs(percentile(sorted, 0.95)),
    p99: roundMs(percentile(sorted, 0.99)),
    stddev: roundMs(Math.sqrt(variance)),
  };
}

function percentile(sortedAscending: number[], quantile: number): number {
  if (sortedAscending.length === 1) {
    return sortedAscending[0];
  }
  const rank = quantile * (sortedAscending.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  if (lower === upper) {
    return sortedAscending[lower];
  }
  const fraction = rank - lower;
  return sortedAscending[lower] * (1 - fraction) + sortedAscending[upper] * fraction;
}

function sum(values: number[]): number {
  let total = 0;
  for (const value of values) {
    total += value;
  }
  return total;
}

function makeFixture() {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const serviceKid = textEncoder.encode("github-mcp-v1-2026-q2");
  const log = new MockTransparencyLog(logUrl);
  const authorizationToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "bench-agent",
      owner_hpke_pk: base64urlEncode(owner.publicKey),
      sello_logs: [logUrl],
    },
  });
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

  return {
    authorizationToken,
    tokenIssuerPublicKey: tokenIssuer.publicKey,
    serviceKid,
    servicePrivateKey: service.privateKey,
    serviceIdentifier,
    log,
    ownerInput: () => ({
      authorizationTokenBytes: textEncoder.encode(authorizationToken),
      trustedLogs: [log],
      registry,
      ownerPrivateKey: owner.privateKey,
    }),
  };
}

function createBenchReceipt(
  fixture: ReturnType<typeof makeFixture>,
  index: number,
): CreatedReceipt {
  return createReceiptFromJwsToken({
    authorizationToken: fixture.authorizationToken,
    tokenIssuerPublicKey: fixture.tokenIssuerPublicKey,
    serviceKid: fixture.serviceKid,
    servicePrivateKey: fixture.servicePrivateKey,
    serviceIdentifier: fixture.serviceIdentifier,
    log: fixture.log,
    actionType: "tools/call",
    actionInputBytes: textEncoder.encode(`bench input ${index}`),
    actionOutputBytes: textEncoder.encode(`bench output ${index}`),
    resultStatus: "success",
    timestamp: timestampForIndex(index),
  });
}

function timestampForIndex(index: number): string {
  const base = Date.parse("2026-05-28T10:00:00Z");
  return new Date(base + index * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function time(callback: () => void): number {
  const start = performance.now();
  callback();
  return performance.now() - start;
}

function parseArgs(args: string[]): {
  iterations: number;
  warmupIterations: number;
  json: boolean;
} {
  let iterations = 100;
  let warmupIterations = DEFAULT_WARMUP_ITERATIONS;
  let json = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--json") {
      json = true;
      continue;
    }

    if (arg === "--iterations") {
      const raw = args[index + 1];
      index += 1;
      iterations = parseIterations(raw);
      continue;
    }

    if (arg.startsWith("--iterations=")) {
      iterations = parseIterations(arg.slice("--iterations=".length));
      continue;
    }

    if (arg === "--warmup") {
      const raw = args[index + 1];
      index += 1;
      warmupIterations = parseWarmupIterations(raw);
      continue;
    }

    if (arg.startsWith("--warmup=")) {
      warmupIterations = parseWarmupIterations(arg.slice("--warmup=".length));
      continue;
    }

    if (arg === "--help") {
      printHelp();
      process.exit(0);
    }

    throw new TypeError(`unknown argument: ${arg}`);
  }

  return { iterations, warmupIterations, json };
}

function parseIterations(value: string | undefined): number {
  const iterations = Number(value);

  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new TypeError("--iterations must be a positive integer");
  }

  return iterations;
}

function parseWarmupIterations(value: string | undefined): number {
  const iterations = Number(value);

  if (!Number.isSafeInteger(iterations) || iterations < 0) {
    throw new TypeError("--warmup must be a non-negative integer");
  }

  return iterations;
}

function assertVerifiedCount(actual: number, expected: number): void {
  if (actual !== expected) {
    throw new Error(`expected ${expected} verified receipts, got ${actual}`);
  }
}

function roundMs(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function printText(result: BenchResult): void {
  console.log(
    `Sello benchmark (${result.iterations} iterations, ${result.warmup_iterations} warmup, ${result.node})`,
  );
  console.log("");
  console.log("Receipt sizes:");
  for (const [name, value] of Object.entries(result.sizes)) {
    console.log(`  ${name}: ${value} bytes`);
  }
  console.log("");
  console.log("Timings:");
  for (const [name, value] of Object.entries(result.timings_ms)) {
    console.log(`  ${name}: ${value} ms`);
  }
  console.log("");
  console.log("Distributions:");
  printDistribution("create_receipt", result.distributions.create_receipt);
  printDistribution("verify_one_receipt", result.distributions.verify_one_receipt);
}

function printHelp(): void {
  console.log(`Usage: sello-bench [--iterations N] [--warmup N] [--json]

Runs a local benchmark over the mock-log Sello receipt flow.
Results are useful for rough regression tracking, not formal crypto benchmarks.`);
}

function printDistribution(name: string, distribution: Distribution): void {
  console.log(
    `  ${name}: mean ${distribution.mean} ms, median ${distribution.median} ms, p95 ${distribution.p95} ms, p99 ${distribution.p99} ms, stddev ${distribution.stddev} ms`,
  );
}
