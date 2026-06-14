import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

describe("benchmark CLI", () => {
  it("prints machine-readable receipt sizes and timings", () => {
    const result = runBench(["--iterations", "3", "--warmup", "2", "--json"]);

    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);

    assert.equal(parsed.iterations, 3);
    assert.equal(parsed.warmup_iterations, 2);
    assert.match(parsed.node, /^v\d+\./);
    assert.equal(typeof parsed.sizes.receipt_body_cbor_bytes, "number");
    assert.equal(typeof parsed.sizes.protected_header_bytes, "number");
    assert.equal(typeof parsed.sizes.hpke_payload_bytes, "number");
    assert.equal(typeof parsed.sizes.cose_sign1_envelope_bytes, "number");
    assert.equal(typeof parsed.sizes.mock_log_proof_json_bytes, "number");
    assert.equal(typeof parsed.timings_ms.create_receipt_avg, "number");
    assert.equal(typeof parsed.timings_ms.verify_one_receipt_avg, "number");
    assert.equal(typeof parsed.timings_ms.verify_batch_total, "number");
    assert.equal(typeof parsed.timings_ms.verify_batch_per_receipt, "number");
    assertDistribution(parsed.distributions.create_receipt, 3);
    assertDistribution(parsed.distributions.verify_one_receipt, 3);
    assert.deepEqual(Object.keys(parsed.distributions.verify_batch_total), ["count", "value"]);
    assert.deepEqual(Object.keys(parsed.distributions.verify_batch_per_receipt), ["count", "value"]);
  });

  it("prints human-readable distribution summaries", () => {
    const result = runBench(["--iterations", "2", "--warmup", "0"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /2 iterations, 0 warmup/);
    assert.match(result.stdout, /Distributions:/);
    assert.match(result.stdout, /create_receipt: mean .* median .* p95 .* p99 .* stddev/);
    assert.match(result.stdout, /verify_one_receipt: mean .* median .* p95 .* p99 .* stddev/);
  });

  it("rejects invalid iteration counts", () => {
    const result = runBench(["--iterations", "0", "--json"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /positive integer/);
  });

  it("rejects invalid warmup counts", () => {
    const result = runBench(["--warmup", "-1", "--json"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /non-negative integer/);
  });
});

function runBench(args: string[] = []) {
  return spawnSync(
    process.execPath,
    ["--experimental-strip-types", "src/cli/bench.ts", ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
}

function assertDistribution(
  value: unknown,
  expectedCount: number,
): asserts value is Record<string, number> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  const distribution = value as Record<string, number>;
  assert.equal(distribution.count, expectedCount);
  assert.equal(typeof distribution.mean, "number");
  assert.equal(typeof distribution.median, "number");
  assert.equal(typeof distribution.p95, "number");
  assert.equal(typeof distribution.p99, "number");
  assert.equal(typeof distribution.stddev, "number");
}
