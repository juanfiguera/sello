import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

describe("demo CLI", () => {
  it("prints three verified receipts", () => {
    const result = runDemo();

    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(
      parsed.receipts.map((receipt: { "result-status": string }) => receipt["result-status"]),
      ["success", "error", "denied"],
    );
    assert.equal(parsed.receipts.every((receipt: { verified: boolean }) => receipt.verified), true);
    assert.deepEqual(parsed.rejected, []);
  });

  it("prints a clear rejected entry in tamper mode", () => {
    const result = runDemo(["--tamper"]);

    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.receipts.length, 3);
    assert.equal(parsed.rejected.length, 1);
    assert.equal(parsed.rejected[0].code, "cose_signature_failed");
  });
});

function runDemo(args: string[] = []) {
  return spawnSync(
    process.execPath,
    ["--experimental-strip-types", "src/cli/demo.ts", ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
}
