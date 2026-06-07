#!/usr/bin/env node
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = join(root, "src");
const distRoot = join(root, "dist");
const cliEntrypoints = new Set([
  "cli/bench.js",
  "cli/demo.js",
  "cli/sello.js",
]);

rmSync(distRoot, { recursive: true, force: true });

let built = 0;
for (const sourcePath of walk(srcRoot)) {
  if (!sourcePath.endsWith(".ts")) {
    continue;
  }

  const relativeSource = relative(srcRoot, sourcePath);
  const relativeOutput = relativeSource.replace(/\.ts$/, ".js");
  const outputPath = join(distRoot, relativeOutput);
  const source = readFileSync(sourcePath, "utf8");
  const output = toJavaScript(source);

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, output);

  if (cliEntrypoints.has(relativeOutput)) {
    chmodSync(outputPath, 0o755);
  }

  built += 1;
}

console.log(`Built ${built} JavaScript files into dist/.`);

function* walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* walk(path);
    } else if (entry.isFile()) {
      yield path;
    }
  }
}

function toJavaScript(source) {
  return stripTypeScriptTypes(source, { mode: "strip" })
    .replace(/^#!\/usr\/bin\/env -S node --experimental-strip-types$/m, "#!/usr/bin/env node")
    .replace(/(\bfrom\s+["'][^"']+)\.ts(["'])/g, "$1.js$2")
    .replace(/(\bimport\s+["'][^"']+)\.ts(["'])/g, "$1.js$2")
    .replace(/(\bimport\s*\(\s*["'][^"']+)\.ts(["'])/g, "$1.js$2")
    .replace(/^\s*import\s*\{\s*\}\s*from\s*["'][^"']+["'];\s*\n?/gm, "");
}
