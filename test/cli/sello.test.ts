import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const selloCli = fileURLToPath(new URL("../../src/cli/sello.ts", import.meta.url));

const SELLO_ENV_KEYS = [
  "SELLO_ACTION_TOKEN",
  "SELLO_LOG_ENDPOINT",
  "SELLO_LOG_URL",
  "SELLO_OWNER_KEY",
  "SELLO_REGISTRY_PATH",
  "SELLO_REGISTRY_SIGNATURE",
  "SELLO_REGISTRY_TRUST_ROOT_PUBLIC_KEY",
  "SELLO_REGISTRY_URL",
  "SELLO_SECRET_KEY",
  "SELLO_SERVICE_ID",
  "SELLO_SERVICE_KEY",
  "SELLO_SUBMIT_MODE",
  "SELLO_TOKEN_ISSUER_JWKS",
  "SELLO_TOKEN_ISSUER_PUBLIC_KEY",
] as const;

describe("sello CLI", () => {
  it("prints help for the main commands", () => {
    const result = runSello(["--help"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /sello dev/);
    assert.match(result.stdout, /sello actions/);
    assert.match(result.stdout, /sello keys service/);
  });

  it("generates service key environment variables", () => {
    const result = runSello(["keys", "service"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^SELLO_SERVICE_KEY=sello_dev_/m);
    assert.match(result.stdout, /^SELLO_SERVICE_PUBLIC_KEY=/m);
    assert.match(result.stdout, /^SELLO_SERVICE_KID=svc-/m);
  });

  it("redacts sensitive values when inspecting env", () => {
    const result = runSello(["inspect-env"], {
      env: {
        SELLO_SECRET_KEY: "sello_live_supersecretvalue",
        SELLO_OWNER_KEY: "sello_owner_dev_privatevalue",
        SELLO_LOG_URL: "https://logs.example.com/api",
      },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /SELLO_SECRET_KEY=sello_...alue/);
    assert.match(result.stdout, /SELLO_OWNER_KEY=sello_...alue/);
    assert.match(result.stdout, /SELLO_LOG_URL=https:\/\/logs\.example\.com\/api/);
    assert.doesNotMatch(result.stdout, /supersecretvalue/);
    assert.doesNotMatch(result.stdout, /privatevalue/);
  });

  it("writes local dev state in dry-run mode without starting a server", () => {
    const cwd = makeTempCwd();
    const result = runSello([
      "dev",
      "--port",
      "8787",
      "--service",
      "todo.example.com/mcp/v1",
      "--dry-run",
    ], { cwd });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Sello dev log running at http:\/\/localhost:8787\/actions/);
    assert.match(result.stdout, /SELLO_SERVICE_ID=todo\.example\.com\/mcp\/v1/);
    assert.match(result.stdout, /^SELLO_SERVICE_KEY=sello_dev_/m);
    assert.match(result.stdout, /^SELLO_OWNER_KEY=sello_owner_dev_/m);
    assert.match(result.stdout, /^SELLO_ACTION_TOKEN=/m);
    assert.match(result.stdout, /Dry run: dev state written, server not started\./);

    const statePath = join(cwd, ".sello", "dev.json");
    assert.equal(existsSync(statePath), true);

    const state = JSON.parse(readFileSync(statePath, "utf8"));
    assert.equal(state.serviceId, "todo.example.com/mcp/v1");
    assert.equal(state.logUrl, "https://localhost:8787/api");
    assert.equal(state.logEndpoint, "http://localhost:8787/api");
    assert.match(state.serviceKey, /^sello_dev_/);
    assert.match(state.ownerKey, /^sello_owner_dev_/);
    assert.equal(typeof state.agentToken, "string");
  });

  it("rejects invalid dev ports", () => {
    const result = runSello(["dev", "--port", "0", "--dry-run"], {
      cwd: makeTempCwd(),
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /port must be between 1 and 65535/);
  });

  it("reports missing token before viewing actions", () => {
    const result = runSello(["actions"], { cwd: makeTempCwd() });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /missing token/);
  });

  it("reports missing owner key when a token is present", () => {
    const result = runSello(["actions", "--token", "example-token"], {
      cwd: makeTempCwd(),
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /missing SELLO_OWNER_KEY/);
  });
});

function runSello(
  args: string[] = [],
  options: { cwd?: string; env?: Record<string, string> } = {},
) {
  return spawnSync(
    process.execPath,
    ["--experimental-strip-types", selloCli, ...args],
    {
      cwd: options.cwd ?? process.cwd(),
      encoding: "utf8",
      env: cleanEnv(options.env),
    },
  );
}

function cleanEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const key of SELLO_ENV_KEYS) {
    delete env[key];
  }
  return { ...env, ...overrides };
}

function makeTempCwd(): string {
  return mkdtempSync(join(tmpdir(), "sello-cli-test-"));
}
