# Sello SDK Quickstart

Sello's SDK is designed to make the first receipt easy: wrap a tool handler, run it, and inspect verified actions.

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
```

The service process emits receipts. It does not need the owner private key.

## Local Development

Start the local log and action viewer:

```bash
npx sello dev
```

Copy the printed service env into your tool server:

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

or open:

```text
http://localhost:8787/actions
```

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
