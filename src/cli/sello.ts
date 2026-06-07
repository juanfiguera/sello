#!/usr/bin/env -S node --experimental-strip-types

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { generateEd25519KeyPair } from "../cose/sign1.ts";
import { deriveTokenIdentifiers, sha256, toHex } from "../crypto/identifiers.ts";
import { generateHpkeKeyPair } from "../hpke/receipt.ts";
import { type CanonicalLogUrl } from "../log/canonical-url.ts";
import { MockTransparencyLog } from "../log/mock-log.ts";
import { canonicalJsonBytes } from "../mcp/middleware.ts";
import { verifyReceipts } from "../owner/verify.ts";
import {
  loadSignedRegistry,
  parseRegistry,
  signRegistryJson,
} from "../registry/json-registry.ts";
import { base64urlEncode as tokenBase64urlEncode, signSelloJwsToken } from "../token/jws-profile.ts";
import {
  base64urlEncode,
  decodeBase64url,
  encodeOwnerKey,
  encodeServiceKey,
  normalizeEd25519PublicKey,
  normalizeHpkePrivateKey,
} from "../sdk/keys.ts";
import {
  deserializeEntry,
  http as httpLog,
  queryHttpLogByTokenRef,
  serializeEntry,
  toCanonicalLogUrl,
} from "../sdk/logs.ts";
import { createSelloService } from "../sdk/service.ts";

type DevState = {
  serviceId: string;
  serviceKey: string;
  servicePublicKey: string;
  ownerKey: string;
  ownerPublicKey: string;
  tokenIssuerPublicKey: string;
  agentToken: string;
  logUrl: string;
  logEndpoint: string;
  registryJson: string;
};

type ActionsViewModel = {
  receipts: {
    integratedTime: string;
    serviceIdentifier: string;
    actionType: string;
    resultStatus: string;
    status: string;
    logUrl: string;
    logCompleteness: string;
    sameSecondActivity: boolean;
  }[];
  rejected: {
    code: string;
    message: string;
    logUrl?: string;
    integratedTime?: string;
  }[];
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const command = process.argv[2] ?? "help";

try {
  enforceNodeVersion();
  switch (command) {
    case "actions":
      await actionsCommand(process.argv.slice(3));
      break;
    case "dev":
      await devCommand(process.argv.slice(3));
      break;
    case "emit-demo":
      await emitDemoCommand(process.argv.slice(3));
      break;
    case "init-demo":
      initDemoCommand(process.argv.slice(3));
      break;
    case "keys":
      keysCommand(process.argv.slice(3));
      break;
    case "inspect-env":
      inspectEnvCommand();
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      throw new TypeError(`unknown command ${command}`);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`sello: ${message}`);
  process.exitCode = 1;
}

async function actionsCommand(args: string[]): Promise<void> {
  const devState = loadDevStateIfPresent();
  const token = readFlag(args, "--token") ?? process.env.SELLO_ACTION_TOKEN ?? devState?.agentToken;
  if (!token) {
    throw new TypeError("missing token. Pass --token <agent-token> or run sello dev first.");
  }

  const ownerKeyInput = process.env.SELLO_OWNER_KEY ?? devState?.ownerKey;
  if (!ownerKeyInput) {
    throw new TypeError("missing SELLO_OWNER_KEY. Viewing actions requires the owner private key.");
  }

  const logUrl = process.env.SELLO_LOG_URL ?? devState?.logUrl;
  const endpoint = process.env.SELLO_LOG_ENDPOINT ?? devState?.logEndpoint ?? logUrl;
  if (!logUrl || !endpoint) {
    throw new TypeError("missing SELLO_LOG_URL. Configure a trusted log before viewing actions.");
  }

  const registry = await loadViewerRegistry(devState);
  const tokenBytes = textEncoder.encode(token);
  const identifiers = deriveTokenIdentifiers(tokenBytes);
  const query = await queryHttpLogByTokenRef({
    endpoint,
    tokenRef: identifiers.sello_token_ref,
  });
  const log = {
    logUrl: toCanonicalLogUrl(logUrl),
    queryByTokenRef: () => query,
    verifyInclusionProof: verifyHttpProof,
  };
  const result = verifyReceipts({
    authorizationTokenBytes: tokenBytes,
    trustedLogs: [log],
    registry,
    ownerPrivateKey: normalizeHpkePrivateKey(ownerKeyInput, "SELLO_OWNER_KEY"),
  });

  printActions(result);
}

async function devCommand(args: string[]): Promise<void> {
  const port = Number(readFlag(args, "--port") ?? process.env.PORT ?? "8787");
  const dryRun = args.includes("--dry-run");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new TypeError("port must be between 1 and 65535");
  }

  const serviceId =
    readFlag(args, "--service") ??
    process.env.SELLO_SERVICE_ID ??
    "calendar.example.com/mcp/v1";
  const logEndpoint = `http://localhost:${port}/api`;
  const logUrl = toCanonicalLogUrl(`http://localhost:${port}/api`);
  const state = createDevState({ serviceId, logUrl, logEndpoint });
  saveDevState(state);

  if (dryRun) {
    printDevConfig(port, state);
    console.log("");
    console.log("Dry run: dev state written, server not started.");
    return;
  }

  const log = new MockTransparencyLog(logUrl);
  const registry = parseRegistry(textEncoder.encode(state.registryJson));
  const server = createServer(async (request, response) => {
    try {
      await handleDevRequest({ request, response, log, state, registry });
    } catch (error) {
      sendJson(response, 500, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  server.listen(port, () => {
    printDevConfig(port, state);
  });
}

async function emitDemoCommand(args: string[]): Promise<void> {
  const state = loadDevStateOrThrow(
    "missing local Sello dev state. Run `sello dev` first, then run `sello emit-demo` in another terminal from the same directory.",
  );
  const title = readFlag(args, "--title") ?? "Test Sello receipt";
  const receipts = createSelloService({
    service: state.serviceId,
    serviceKey: state.serviceKey,
    tokenIssuer: state.tokenIssuerPublicKey,
    log: httpLog(state.logUrl, { endpoint: state.logEndpoint }),
    submit: { mode: "await" },
  });
  const createEvent = receipts.tool<DemoEventRequest, DemoEventResponse>(
    "calendar.create_event",
    async (request) => ({
      id: `evt_${slug(request.title)}`,
      calendarId: request.calendarId,
      title: request.title,
      status: "created",
      createdAt: new Date().toISOString(),
    }),
    {
      canonicalizeInput: (request) => canonicalJsonBytes({
        calendarId: request.calendarId,
        title: request.title,
        start: request.start,
        attendees: request.attendees,
      }),
    },
  );
  const response = await createEvent({
    authorizationToken: state.agentToken,
    calendarId: "demo-calendar",
    title,
    start: "2026-06-05T17:00:00Z",
    attendees: ["ada@example.com", "grace@example.com"],
  });

  await receipts.flush();

  console.log("Emitted demo Sello receipt.");
  console.log(JSON.stringify(response, null, 2));
  console.log("");
  console.log("View verified actions with:");
  console.log("  sello actions");
  console.log("");
  console.log("Or open:");
  console.log(`  ${actionViewerUrl(state)}`);
}

function initDemoCommand(args: string[]): void {
  const output = readFlag(args, "--output") ?? "emit-receipt.mjs";
  const force = args.includes("--force");

  if (existsSync(output) && !force) {
    throw new TypeError(`${output} already exists. Pass --force to overwrite it.`);
  }

  writeFileSync(output, demoEmitterSource(), { mode: 0o644 });

  console.log(`Created ${output}`);
  console.log("");
  console.log("Run:");
  console.log("  npm install sello");
  console.log("  npx sello dev");
  console.log(`  node ${output}`);
  console.log("  npx sello actions");
}

function keysCommand(args: string[]): void {
  const subcommand = args[0] ?? "service";
  if (subcommand !== "service") {
    throw new TypeError("only `sello keys service` is supported");
  }

  const key = generateEd25519KeyPair();
  const kid = textEncoder.encode(`svc-${Date.now().toString(36)}`);
  console.log(`SELLO_SERVICE_KEY=${encodeServiceKey(kid, key.privateKey)}`);
  console.log(`SELLO_SERVICE_PUBLIC_KEY=${base64urlEncode(key.publicKey)}`);
  console.log(`SELLO_SERVICE_KID=${textDecoder.decode(kid)}`);
}

function inspectEnvCommand(): void {
  const keys = [
    "SELLO_SERVICE_ID",
    "SELLO_SERVICE_KEY",
    "SELLO_TOKEN_ISSUER_PUBLIC_KEY",
    "SELLO_TOKEN_ISSUER_JWKS",
    "SELLO_LOG_URL",
    "SELLO_LOG_ENDPOINT",
    "SELLO_SUBMIT_MODE",
    "SELLO_SECRET_KEY",
    "SELLO_OWNER_KEY",
    "SELLO_REGISTRY_URL",
    "SELLO_REGISTRY_PATH",
  ];

  for (const key of keys) {
    const value = process.env[key];
    if (!value) {
      console.log(`${key}=<unset>`);
      continue;
    }

    const sensitive = /KEY|SECRET/.test(key);
    console.log(`${key}=${sensitive ? redact(value) : value}`);
  }
}

async function handleDevRequest(input: {
  request: IncomingMessage;
  response: ServerResponse;
  log: MockTransparencyLog;
  state: DevState;
  registry: ReturnType<typeof parseRegistry>;
}): Promise<void> {
  const { request, response, log, state, registry } = input;
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/actions")) {
    const result = verifyDevActions({ log, state, registry });
    sendHtml(response, renderActionsHtml(result));
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/actions") {
    const result = verifyDevActions({ log, state, registry });
    sendJson(response, 200, actionsViewModel(result));
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/entries") {
    const body = await readJson(request);
    if (!isRecord(body) || typeof body.envelope !== "string") {
      throw new TypeError("append body must contain envelope");
    }

    const entry = log.append(
      decodeBase64url(body.envelope, "envelope"),
      typeof body.integratedTime === "string" ? body.integratedTime : undefined,
    );
    sendJson(response, 200, serializeEntry(entry));
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/entries") {
    const tokenRefHex = url.searchParams.get("sello_token_ref");
    if (!tokenRefHex || !/^[0-9a-f]{64}$/.test(tokenRefHex)) {
      throw new TypeError("sello_token_ref query must be 64 lowercase hex characters");
    }

    const query = log.queryByTokenRef(Uint8Array.from(Buffer.from(tokenRefHex, "hex")));
    sendJson(response, 200, {
      completeness: query.completeness,
      entries: query.entries.map(serializeEntry),
    });
    return;
  }

  sendJson(response, 404, { error: "not found" });
}

function verifyDevActions(input: {
  log: MockTransparencyLog;
  state: DevState;
  registry: ReturnType<typeof parseRegistry>;
}): ReturnType<typeof verifyReceipts> {
  return verifyReceipts({
    authorizationTokenBytes: textEncoder.encode(input.state.agentToken),
    trustedLogs: [input.log],
    registry: input.registry,
    ownerPrivateKey: normalizeHpkePrivateKey(input.state.ownerKey),
  });
}

async function loadViewerRegistry(devState: DevState | undefined) {
  if (process.env.SELLO_REGISTRY_PATH) {
    return parseRegistry(readFileBytes(process.env.SELLO_REGISTRY_PATH));
  }

  if (process.env.SELLO_REGISTRY_URL) {
    const response = await fetch(process.env.SELLO_REGISTRY_URL);
    if (!response.ok) {
      throw new TypeError(`registry fetch failed with HTTP ${response.status}`);
    }
    const registryBytes = new Uint8Array(await response.arrayBuffer());
    const signature = process.env.SELLO_REGISTRY_SIGNATURE;
    const trustRoot = process.env.SELLO_REGISTRY_TRUST_ROOT_PUBLIC_KEY;
    if (!signature || !trustRoot) {
      throw new TypeError(
        "SELLO_REGISTRY_URL requires SELLO_REGISTRY_SIGNATURE and SELLO_REGISTRY_TRUST_ROOT_PUBLIC_KEY",
      );
    }

    return loadSignedRegistry({
      registryBytes,
      signatureBase64Url: signature,
      trustRootPublicKey: normalizeEd25519PublicKey(trustRoot, "SELLO_REGISTRY_TRUST_ROOT_PUBLIC_KEY"),
    });
  }

  if (devState) {
    return parseRegistry(textEncoder.encode(devState.registryJson));
  }

  throw new TypeError(
    "missing registry. Set SELLO_REGISTRY_PATH or SELLO_REGISTRY_URL.",
  );
}

function createDevState(input: {
  serviceId: string;
  logUrl: CanonicalLogUrl;
  logEndpoint: string;
}): DevState {
  const owner = generateHpkeKeyPair();
  const service = generateEd25519KeyPair();
  const tokenIssuer = generateEd25519KeyPair();
  const trustRoot = generateEd25519KeyPair();
  const kid = textEncoder.encode("dev-service-key");
  const agentToken = signSelloJwsToken({
    issuerPrivateKey: tokenIssuer.privateKey,
    payload: {
      sub: "sello-dev-agent",
      owner_hpke_pk: tokenBase64urlEncode(owner.publicKey),
      sello_logs: [input.logUrl],
    },
  });
  const registryJson = JSON.stringify({
    [toHex(kid)]: {
      service_identifier: input.serviceId,
      public_key_ed25519: base64urlEncode(service.publicKey),
    },
  });

  signRegistryJson(textEncoder.encode(registryJson), trustRoot.privateKey);

  return {
    serviceId: input.serviceId,
    serviceKey: encodeServiceKey(kid, service.privateKey),
    servicePublicKey: base64urlEncode(service.publicKey),
    ownerKey: encodeOwnerKey(owner.privateKey),
    ownerPublicKey: base64urlEncode(owner.publicKey),
    tokenIssuerPublicKey: base64urlEncode(tokenIssuer.publicKey),
    agentToken,
    logUrl: input.logUrl,
    logEndpoint: input.logEndpoint,
    registryJson,
  };
}

function saveDevState(state: DevState): void {
  const path = devStatePath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

function loadDevStateIfPresent(): DevState | undefined {
  try {
    return JSON.parse(textDecoder.decode(readFileBytes(devStatePath()))) as DevState;
  } catch {
    return undefined;
  }
}

function loadDevStateOrThrow(message: string): DevState {
  const state = loadDevStateIfPresent();
  if (!state) {
    throw new TypeError(message);
  }
  return state;
}

function devStatePath(): string {
  return join(process.cwd(), ".sello", "dev.json");
}

function readFileBytes(path: string): Uint8Array {
  return new Uint8Array(readFileSync(path));
}

function printActions(result: ReturnType<typeof verifyReceipts>): void {
  console.log("Verified agent actions");
  console.log("");

  if (result.receipts.length === 0) {
    console.log("No verified actions found.");
  }

  for (const record of result.receipts) {
    console.log(
      [
        record.integratedTime.padEnd(21),
        record.serviceIdentifier.padEnd(30),
        record.receipt["action-type"].padEnd(28),
        record.receipt["result-status"],
        record.status === "duplicate" ? "(duplicate)" : "",
      ].filter(Boolean).join("  "),
    );
  }

  if (result.rejected.length > 0) {
    console.log("");
    console.log("Rejected receipts");
    for (const rejected of result.rejected) {
      console.log(`${rejected.code}: ${rejected.message}`);
    }
  }
}

function actionsViewModel(result: ReturnType<typeof verifyReceipts>): ActionsViewModel {
  return {
    receipts: result.receipts.map((record) => ({
      integratedTime: record.integratedTime,
      serviceIdentifier: record.serviceIdentifier,
      actionType: record.receipt["action-type"],
      resultStatus: record.receipt["result-status"],
      status: record.status,
      logUrl: record.logUrl,
      logCompleteness: record.logCompleteness,
      sameSecondActivity: record.sameSecondActivity,
    })),
    rejected: result.rejected.map((record) => ({
      code: record.code,
      message: record.message,
      ...(record.logUrl === undefined ? {} : { logUrl: record.logUrl }),
      ...(record.integratedTime === undefined ? {} : { integratedTime: record.integratedTime }),
    })),
  };
}

function renderActionsHtml(result: ReturnType<typeof verifyReceipts>): string {
  const view = actionsViewModel(result);
  const rows = view.receipts.map((record) => `
    <tr>
      <td>${escapeHtml(record.integratedTime)}</td>
      <td>${escapeHtml(record.serviceIdentifier)}</td>
      <td>${escapeHtml(record.actionType)}</td>
      <td>${escapeHtml(record.resultStatus)}</td>
      <td>${escapeHtml(record.status)}</td>
    </tr>`).join("");
  const rejected = view.rejected.map((record) => `
    <li><strong>${escapeHtml(record.code)}</strong>: ${escapeHtml(record.message)}</li>`).join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sello Actions</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 40px; color: #17201d; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border-bottom: 1px solid #d8dfdc; padding: 10px 8px; text-align: left; }
    th { color: #52615b; font-weight: 600; }
    .empty { color: #52615b; margin-top: 16px; }
  </style>
</head>
<body>
  <h1>Sello Actions</h1>
  ${rows ? `<table><thead><tr><th>Integrated time</th><th>Service</th><th>Action</th><th>Result</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="empty">No verified actions found yet.</p>`}
  ${rejected ? `<h2>Rejected receipts</h2><ul>${rejected}</ul>` : ""}
</body>
</html>`;
}

function verifyHttpProof(entry: ReturnType<typeof deserializeEntry>): boolean {
  if (!isRecord(entry.proof)) {
    return false;
  }

  const envelopeHash = toHex(sha256(entry.envelope));
  const proofHash = toHex(
    sha256(
      textEncoder.encode(
        `${entry.logUrl}\n${entry.index}\n${entry.integratedTime}\n${envelopeHash}`,
      ),
    ),
  );

  return (
    entry.proof.logUrl === entry.logUrl &&
    entry.proof.index === entry.index &&
    entry.proof.integratedTime === entry.integratedTime &&
    entry.proof.envelopeHash === envelopeHash &&
    entry.proof.proofHash === proofHash
  );
}

function readFlag(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(typeof chunk === "string" ? textEncoder.encode(chunk) : chunk);
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body)}\n`);
}

function sendHtml(response: ServerResponse, body: string): void {
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(body);
}

function redact(value: string): string {
  return value.length <= 8 ? "<set>" : `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  }[char] as string));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function printHelp(): void {
  console.log(`Usage:
  sello dev [--port 8787] [--service service-id] [--dry-run]
  sello emit-demo [--title title]
  sello init-demo [--output emit-receipt.mjs] [--force]
  sello actions [--token agent-token]
  sello keys service
  sello inspect-env
`);
}

function printDevConfig(port: number, state: DevState): void {
  console.log(`Sello dev log running at http://localhost:${port}/actions`);
  console.log("");
  console.log("Service env:");
  console.log(`SELLO_SERVICE_ID=${state.serviceId}`);
  console.log(`SELLO_SERVICE_KEY=${state.serviceKey}`);
  console.log(`SELLO_TOKEN_ISSUER_PUBLIC_KEY=${state.tokenIssuerPublicKey}`);
  console.log(`SELLO_LOG_URL=${state.logUrl}`);
  console.log(`SELLO_LOG_ENDPOINT=${state.logEndpoint}`);
  console.log("SELLO_SUBMIT_MODE=background");
  console.log("");
  console.log("Viewer env:");
  console.log(`SELLO_OWNER_KEY=${state.ownerKey}`);
  console.log(`SELLO_LOG_URL=${state.logUrl}`);
  console.log(`SELLO_LOG_ENDPOINT=${state.logEndpoint}`);
  console.log("");
  console.log("Dev token:");
  console.log(`SELLO_ACTION_TOKEN=${state.agentToken}`);
}

function enforceNodeVersion(): void {
  const [major = 0, minor = 0] = process.versions.node
    .split(".")
    .map((part) => Number(part));
  if (major < 22 || (major === 22 && minor < 7)) {
    throw new TypeError(
      `Sello requires Node >=22.7.0; current Node is ${process.versions.node}`,
    );
  }
}

type DemoEventRequest = {
  authorizationToken: string;
  calendarId: string;
  title: string;
  start: string;
  attendees: string[];
};

type DemoEventResponse = {
  id: string;
  calendarId: string;
  title: string;
  status: "created";
  createdAt: string;
};

function actionViewerUrl(state: DevState): string {
  const endpoint = new URL(state.logEndpoint);
  return `${endpoint.origin}/actions`;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
}

function demoEmitterSource(): string {
  return `import { readFileSync } from "node:fs";
import { canonicalJsonBytes, sello } from "sello";

const state = JSON.parse(readFileSync(".sello/dev.json", "utf8"));

const receipts = sello.service({
  service: state.serviceId,
  serviceKey: state.serviceKey,
  tokenIssuer: state.tokenIssuerPublicKey,
  log: sello.logs.http(state.logUrl, { endpoint: state.logEndpoint }),
  submit: { mode: "await" },
});

const createEvent = receipts.tool(
  "calendar.create_event",
  async (request) => ({
    id: "evt_test_sello_receipt",
    calendarId: request.calendarId,
    title: request.title,
    status: "created",
    createdAt: new Date().toISOString(),
  }),
  {
    canonicalizeInput: (request) =>
      canonicalJsonBytes({
        calendarId: request.calendarId,
        title: request.title,
        start: request.start,
        attendees: request.attendees,
      }),
  },
);

const result = await createEvent({
  authorizationToken: state.agentToken,
  calendarId: "demo-calendar",
  title: "Test Sello receipt",
  start: "2026-06-05T17:00:00Z",
  attendees: ["ada@example.com", "grace@example.com"],
});

await receipts.flush();
console.log(result);
`;
}
