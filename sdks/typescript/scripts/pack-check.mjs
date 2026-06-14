#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const npmCommand = resolveNodeTool("npm");
const cacheDir = mkdtempSync(join(tmpdir(), "sello-npm-cache-"));
const result = spawnSync(npmCommand, ["pack", "--dry-run"], {
  cwd: join(import.meta.dirname, "../../.."),
  encoding: "utf8",
  env: {
    ...process.env,
    npm_config_audit: "false",
    npm_config_cache: cacheDir,
    npm_config_fund: "false",
  },
  stdio: "inherit",
});

rmSync(cacheDir, { recursive: true, force: true });

if (result.error) {
  throw result.error;
}

process.exitCode = result.status ?? 1;

function resolveNodeTool(name) {
  const suffix = process.platform === "win32" ? ".cmd" : "";
  const candidates = [
    join(dirname(process.execPath), `${name}${suffix}`),
    `/usr/local/bin/${name}`,
    `/opt/homebrew/bin/${name}`,
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? name;
}
