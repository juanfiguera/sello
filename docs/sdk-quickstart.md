# Sello SDK Quickstart

Sello's SDK is designed to make the first receipt easy: wrap a tool handler, run it, and inspect verified actions.

The local demo CLI and action viewer require Node.js 22.7 or newer. The Python SDK requires Python 3.9 or newer.

## Install

TypeScript:

```bash
npm install sello
```

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
```

Python:

```bash
pip install sello
```

```py
import sello

receipts = sello.service()

@receipts.tool("calendar.create_event")
def create_event(request):
    return calendar.events.create(request)
```

The service process emits receipts. It does not need the owner private key.

## Local Development

From a new project, the shortest loop is:

```bash
# Terminal 1
npx --yes sello dev

# Terminal 2
npx --yes sello emit-demo
npx --yes sello actions
```

To write the tiny emitter file into your project:

```bash
npx --yes sello init-demo
```

To write a dependency-free HTTP route example into your project:

```bash
npx --yes sello init-http-demo
```

The route example imports `sello`, reads the local dev config, verifies a bearer token, runs one `POST /calendar/events` handler, and emits a receipt. With `npx sello dev` and the generated route running, call it with:

```bash
npx --yes sello call-http-demo
npx --yes sello actions
```

## What Just Happened?

`sello dev` created local development keys, a demo authorization token, a service registry, and a local transparency log. The wrapped tool or route verified the token before running your handler. After the handler returned, Sello signed an encrypted receipt for the observed action and submitted it to the local log. The log stored encrypted receipt data, not plaintext action details. `sello actions` used the owner key from local dev state to fetch, verify, decrypt, and print the action.

Local dev state lives under `.sello/`. The encrypted dev log is stored in `.sello/dev-log.jsonl`, so receipts survive restarting `sello dev` without being committed to git.

## Troubleshooting

- **Port already in use:** run `npx sello dev --port 8791`.
- **No actions found:** make sure `sello dev` is running from the same project folder where you emitted the receipt.
- **Missing token:** run `npx sello dev` first so `.sello/dev.json` exists.

Inside this repo, start the local log and action viewer:

```bash
node --run dev
```

In another terminal, run the repo's wrapped tool example:

```bash
node --run example:tool
node --run actions
```

For an MCP tool, wrap the callback you already register:

```ts
import { sello } from "sello";

const receipts = sello.service();

server.registerTool(
  "calendar.create_event",
  { inputSchema: createEventInputSchema },
  receipts.mcpTool("calendar.create_event", async (args) => {
    const event = await calendar.events.create(args);
    return {
      content: [{ type: "text", text: event.id }],
    };
  }),
);
```

Some MCP SDK versions call this method `tool` instead of `registerTool`; use the same callback slot either way.

`receipts.mcpTool(...)` uses action type `mcp.tools/call.<tool-name>` and hashes only the MCP method name, tool name, and arguments. It tries common MCP context/header locations for the bearer token. If your transport puts the token somewhere else, pass an extractor:

```ts
receipts.mcpTool("calendar.create_event", handler, {
  authorizationToken: ({ context }) => context.session.token,
});
```

For the complete MCP placement notes, see [MCP Integration](mcp.md).

For an A2A agent, wrap the message handler you already expose:

```ts
import { sello } from "sello";

const receipts = sello.service();

export const sendMessage = receipts.a2aMessage(async (request, context) => {
  return agent.handleMessage(request, context);
});
```

`receipts.a2aMessage(...)` uses action type `a2a.<method>`, for example `a2a.message/send`, and hashes only the A2A JSON-RPC method and params. It excludes request ids, headers, bearer tokens, and runtime context. If your transport stores the token somewhere else, pass an extractor:

```ts
receipts.a2aMessage(handler, {
  authorizationToken: ({ context }) => context.session.token,
});
```

For the complete A2A placement notes, see [A2A Integration](a2a.md).

Or run the matching Python example:

```bash
python -m pip install ./sdks/python
python sdks/python/examples/quickstart_tool.py
npx --yes sello actions
```

For an MCP-shaped `tools/call` boundary, run:

```bash
node --run example:mcp
node --run actions
```

or open:

```text
http://localhost:8787/actions
```

Both examples read `.sello/dev.json`, wrap a mock calendar handler, submit one encrypted receipt, and let the owner verify it locally.

For the smallest production-shaped MCP boundary, see [`sdks/typescript/examples/mcp-minimal-server.ts`](../sdks/typescript/examples/mcp-minimal-server.ts). It wraps one `tools/call` handler with `sello.service()` and leaves unknown tools unreceipted.

For your own tool server, copy the printed service env:

```bash
SELLO_SERVICE_ID=calendar.example.com/mcp/v1
SELLO_SERVICE_KEY=sello_dev_...
SELLO_TOKEN_ISSUER_PUBLIC_KEY=...
SELLO_LOG_URL=https://localhost:8787/api
SELLO_LOG_ENDPOINT=http://localhost:8787/api
SELLO_SUBMIT_MODE=background
```

Call your wrapped tool with the printed dev token. Then view actions:

```bash
npx sello actions
```

In local dev, `sello dev` prints and saves the token:

```bash
SELLO_ACTION_TOKEN=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

`npx sello actions` reads that token from `.sello/dev.json`. Pass `--token` only when you want to inspect receipts for a specific agent authorization token.

## Self-Hosted Production

Use your own Sello-compatible log server:

```bash
SELLO_SERVICE_ID=calendar.example.com/mcp/v1
SELLO_SERVICE_KEY=sello_live_local_...
SELLO_TOKEN_ISSUER_JWKS=https://auth.example.com/.well-known/jwks.json
SELLO_LOG_URL=https://logs.example.com/api
SELLO_SUBMIT_MODE=background
```

View actions from an owner-controlled environment:

```bash
SELLO_OWNER_KEY=sello_owner_live_...
SELLO_REGISTRY_URL=https://registry.example.com/sello.json
SELLO_REGISTRY_SIGNATURE=...
SELLO_REGISTRY_TRUST_ROOT_PUBLIC_KEY=...
SELLO_LOG_URL=https://logs.example.com/api
npx sello actions --token <agent-token>
```

## Hosted Sello

Hosted mode keeps the application code the same:

```bash
SELLO_SECRET_KEY=sello_test_...
```

The secret is server-side only. Hosted mode is optional; Sello does not require `sello.build`.

## Advanced Explicit Config

You can bypass env config entirely:

```ts
const receipts = sello.service({
  service: "calendar.example.com/mcp/v1",
  serviceKey: { kid, privateKey },
  tokenIssuer: tokenIssuerPublicKey,
  log: sello.logs.memory("https://localhost:8787/api"),
  submit: { mode: "await" },
});
```

Use explicit config for tests, embedded runtimes, or custom self-hosted deployments.

## Privacy

Public logs store encrypted receipts. Viewing action details requires the owner private key or an explicitly delegated viewer key. The CLI decrypts locally; hosted dashboards must use client-side decryption or delegated viewer keys.
