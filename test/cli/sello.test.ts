import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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
    assert.match(result.stdout, /sello emit-demo/);
    assert.match(result.stdout, /sello init-demo/);
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

  it("scaffolds a demo receipt emitter", () => {
    const cwd = makeTempCwd();
    const result = runSello(["init-demo"], { cwd });
    const outputPath = join(cwd, "emit-receipt.mjs");

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Created emit-receipt\.mjs/);
    assert.equal(existsSync(outputPath), true);

    const source = readFileSync(outputPath, "utf8");
    assert.match(source, /import \{ canonicalJsonBytes, sello \} from "sello"/);
    assert.match(source, /calendar\.create_event/);
    assert.match(source, /authorizationToken: state\.agentToken/);
  });

  it("does not overwrite the demo emitter without --force", () => {
    const cwd = makeTempCwd();

    assert.equal(runSello(["init-demo"], { cwd }).status, 0);

    const result = runSello(["init-demo"], { cwd });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /emit-receipt\.mjs already exists/);
  });

  it("reports missing dev state before emitting a demo receipt", () => {
    const result = runSello(["emit-demo"], { cwd: makeTempCwd() });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Run `sello dev` first/);
  });

  it("emits a demo receipt to the local dev log", async (context) => {
    const cwd = makeTempCwd();
    const port = await freePort();
    if (port === undefined) {
      context.skip("localhost listeners are unavailable in this sandbox");
      return;
    }

    const stateResult = runSello([
      "dev",
      "--port",
      String(port),
      "--dry-run",
    ], { cwd });
    let appendBody: Record<string, unknown> | undefined;
    const server = createServer(async (request, response) => {
      if (request.method !== "POST" || request.url !== "/api/entries") {
        response.writeHead(404);
        response.end();
        return;
      }

      appendBody = await readRequestJson(request);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        logUrl: appendBody.logUrl,
        index: 0,
        integratedTime: appendBody.integratedTime,
        envelope: appendBody.envelope,
        proof: {},
      }));
    });

    assert.equal(stateResult.status, 0, stateResult.stderr);
    const statePath = join(cwd, ".sello", "dev.json");
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    state.logEndpoint = `http://127.0.0.1:${port}/api`;
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);

    try {
      await listen(server, port);
    } catch (error) {
      if (isListenUnavailable(error)) {
        context.skip("localhost listeners are unavailable in this sandbox");
        return;
      }

      throw error;
    }

    try {
      const result = await runSelloAsync([
        "emit-demo",
        "--title",
        "CLI emitted receipt",
      ], { cwd });

      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /Emitted demo Sello receipt/);
      assert.match(result.stdout, /evt_cli_emitted_receipt/);
      assert.match(result.stdout, /sello actions/);
      assert.equal(appendBody?.logUrl, `https://localhost:${port}/api`);
      assert.equal(typeof appendBody?.envelope, "string");
    } finally {
      await close(server);
    }
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

function runSelloAsync(
  args: string[] = [],
  options: { cwd?: string; env?: Record<string, string> } = {},
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", selloCli, ...args],
      {
        cwd: options.cwd ?? process.cwd(),
        env: cleanEnv(options.env),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({
        status,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
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

function freePort(): Promise<number | undefined> {
  const server = createServer();
  return new Promise((resolve, reject) => {
    server.on("error", (error) => {
      if (isListenUnavailable(error)) {
        resolve(undefined);
        return;
      }

      reject(error);
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to allocate test port"));
        return;
      }

      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve(port);
        }
      });
    });
  });
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

async function readRequestJson(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function isListenUnavailable(error: unknown): boolean {
  return isRecord(error) && error.code === "EPERM" && error.syscall === "listen";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
