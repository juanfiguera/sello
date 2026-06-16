#!/usr/bin/env node
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const tmp = mkdtempSync(join(tmpdir(), "sello-a2a-package-test-"));
const packDir = join(tmp, "pack");
const projectDir = join(tmp, "consumer");
const npmCache = join(tmp, "npm-cache");
const npmCommand = resolveNodeTool("npm");

let failed = false;
let last = { stdout: "" };

try {
  mkdirSync(packDir, { recursive: true });
  mkdirSync(projectDir, { recursive: true });

  const packageSpec = process.env.SELLO_PACKAGE_SPEC ?? packLocalPackage();

  writeFileSync(join(projectDir, "package.json"), JSON.stringify({
    private: true,
    type: "module",
  }, null, 2));
  writeFileSync(join(projectDir, "a2a-smoke.mjs"), a2aSmokeSource());

  run(npmCommand, ["install", "--ignore-scripts", packageSpec], { cwd: projectDir });
  run(process.execPath, ["a2a-smoke.mjs"], { cwd: projectDir });

  console.log(`A2A package smoke test passed for ${packageSpec}.`);
} catch (error) {
  failed = true;
  console.error(`A2A package smoke test temp directory: ${tmp}`);
  throw error;
} finally {
  if (!failed) {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function packLocalPackage() {
  run(npmCommand, ["pack", "--silent", "--pack-destination", packDir], { cwd: root });
  const tarballName = lastTarballName(last.stdout);
  const tarballPath = join(packDir, tarballName);
  if (!existsSync(tarballPath)) {
    throw new Error(`npm pack did not create ${tarballPath}`);
  }

  return tarballPath;
}

function run(command, args, options) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      npm_config_audit: "false",
      npm_config_cache: npmCache,
      npm_config_fund: "false",
    },
  });

  last = result;

  if (result.error || result.status !== 0) {
    if (result.stdout) {
      process.stderr.write(result.stdout);
    }
    if (result.stderr) {
      process.stderr.write(result.stderr);
    }
    const reason = result.error?.message ?? `exit code ${result.status}`;
    throw new Error(`${command} ${args.join(" ")} failed with ${reason}`);
  }

  return result;
}

function lastTarballName(stdout) {
  const tarballName = stdout
    .trim()
    .split(/\r?\n/)
    .reverse()
    .find((line) => line.endsWith(".tgz"));

  if (!tarballName) {
    throw new Error(`could not find tarball name in npm pack output:\n${stdout}`);
  }

  return tarballName;
}

function resolveNodeTool(name) {
  const suffix = process.platform === "win32" ? ".cmd" : "";
  const candidates = [
    join(dirname(process.execPath), `${name}${suffix}`),
    `/usr/local/bin/${name}`,
    `/opt/homebrew/bin/${name}`,
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? name;
}

function a2aSmokeSource() {
  return `import assert from "node:assert/strict";
import {
  base64urlEncode,
  generateEd25519KeyPair,
  generateHpkeKeyPair,
  loadSignedRegistry,
  sello,
  signRegistryJson,
  signSelloJwsToken,
  toHex,
  verifyReceipts,
} from "sello";

const textEncoder = new TextEncoder();
const owner = generateHpkeKeyPair();
const service = generateEd25519KeyPair();
const tokenIssuer = generateEd25519KeyPair();
const trustRoot = generateEd25519KeyPair();
const serviceKid = textEncoder.encode("a2a-smoke-service-key");
const serviceIdentifier = "calendar.example.com/a2a/v1";
const log = sello.logs.memory("https://localhost:8787/api");
const authorizationToken = signSelloJwsToken({
  issuerPrivateKey: tokenIssuer.privateKey,
  payload: {
    owner_hpke_pk: base64urlEncode(owner.publicKey),
    sello_logs: [log.logUrl],
  },
});
const registryBytes = textEncoder.encode(JSON.stringify({
  [toHex(serviceKid)]: {
    service_identifier: serviceIdentifier,
    public_key_ed25519: base64urlEncode(service.publicKey),
  },
}));
const registry = loadSignedRegistry({
  registryBytes,
  signatureBase64Url: signRegistryJson(registryBytes, trustRoot.privateKey),
  trustRootPublicKey: trustRoot.publicKey,
});
const receipts = sello.service({
  service: serviceIdentifier,
  serviceKey: {
    kid: serviceKid,
    privateKey: service.privateKey,
  },
  tokenIssuer: tokenIssuer.publicKey,
  log,
  submit: { mode: "await" },
  now: () => "2026-06-16T10:00:00Z",
});
const sendMessage = receipts.a2aMessage(async (request) => ({
  jsonrpc: "2.0",
  id: request.id,
  result: {
    kind: "message",
    messageId: "reply-1",
    role: "agent",
    parts: [{ kind: "text", text: "created launch checklist" }],
  },
}));
const response = await sendMessage(
  {
    jsonrpc: "2.0",
    id: "a2a-smoke-1",
    method: "message/send",
    params: {
      message: {
        role: "user",
        parts: [{ kind: "text", text: "Create launch checklist" }],
      },
    },
  },
  {
    headers: new Headers({
      authorization: "Bearer " + authorizationToken,
    }),
  },
);
await receipts.flush();

assert.equal(response.result.messageId, "reply-1");

const result = verifyReceipts({
  authorizationTokenBytes: textEncoder.encode(authorizationToken),
  trustedLogs: [log],
  registry,
  ownerPrivateKey: owner.privateKey,
});

assert.equal(result.rejected.length, 0);
assert.equal(result.receipts.length, 1);
assert.equal(result.receipts[0].receipt["action-type"], "a2a.message/send");
assert.equal(result.receipts[0].receipt["result-status"], "success");
`;
}
