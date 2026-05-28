import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

describe("benchmark CLI", () => {
  it("prints machine-readable receipt sizes and timings", () => {
    const result = runBench(["--iterations", "3", "--json"]);

    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);

    assert.equal(parsed.iterations, 3);
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
  });

  it("rejects invalid iteration counts", () => {
    const result = runBench(["--iterations", "0", "--json"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /positive integer/);
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
