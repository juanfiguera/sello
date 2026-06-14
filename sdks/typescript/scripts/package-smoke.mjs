#!/usr/bin/env node
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const tmp = mkdtempSync(join(tmpdir(), "sello-package-test-"));
const packDir = join(tmp, "pack");
const projectDir = join(tmp, "consumer");
const npmCache = join(tmp, "npm-cache");
const npmCommand = resolveNodeTool("npm");
const npxCommand = resolveNodeTool("npx");

let failed = false;
let last = { stdout: "" };

try {
  mkdirSync(packDir, { recursive: true });
  mkdirSync(projectDir, { recursive: true });

  run(npmCommand, ["pack", "--silent", "--pack-destination", packDir], { cwd: root });
  const tarballName = lastTarballName(last.stdout);
  const tarballPath = join(packDir, tarballName);
  if (!existsSync(tarballPath)) {
    throw new Error(`npm pack did not create ${tarballPath}`);
  }

  writeFileSync(join(projectDir, "package.json"), JSON.stringify({
    private: true,
    type: "module",
  }, null, 2));

  run(npmCommand, ["install", "--ignore-scripts", tarballPath], { cwd: projectDir });
  run(process.execPath, [
    "-e",
    "import('sello').then(({ sello }) => { if (typeof sello.service !== 'function') throw new Error('missing sello.service'); })",
  ], { cwd: projectDir });
  run(npxCommand, ["--no-install", "sello", "--help"], { cwd: projectDir });
  run(npxCommand, ["--no-install", "sello", "init-demo"], { cwd: projectDir });
  if (!existsSync(join(projectDir, "emit-receipt.mjs"))) {
    throw new Error("sello init-demo did not create emit-receipt.mjs");
  }
  run(npxCommand, ["--no-install", "sello", "init-http-demo"], { cwd: projectDir });
  if (!existsSync(join(projectDir, "sello-http-route.mjs"))) {
    throw new Error("sello init-http-demo did not create sello-http-route.mjs");
  }
  run(npxCommand, ["--no-install", "sello", "dev", "--dry-run"], { cwd: projectDir });

  console.log("Package smoke test passed.");
} catch (error) {
  failed = true;
  console.error(`Package smoke test temp directory: ${tmp}`);
  throw error;
} finally {
  if (!failed) {
    rmSync(tmp, { recursive: true, force: true });
  }
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
