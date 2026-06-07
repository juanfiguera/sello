# Sello SDK Quickstart

Sello's SDK is designed to make the first receipt easy: wrap a tool handler, run it, and inspect verified actions.

Requires Node.js 22.7 or newer.

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
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

Inside this repo, start the local log and action viewer:

```bash
node --run dev
```

In another terminal, run the repo's wrapped tool example:

```bash
node --run example:tool
node --run actions
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

Both examples read `.sello/dev.json`, wrap a fake calendar handler, submit one encrypted receipt, and let the owner verify it locally.

For the smallest production-shaped MCP boundary, see [`examples/mcp-minimal-server.ts`](../examples/mcp-minimal-server.ts). It wraps one `tools/call` handler with `sello.service()` and leaves unknown tools unreceipted.

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
