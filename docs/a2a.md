# Add Sello to an A2A Agent

Sello belongs around the handler that receives an A2A message: after your server has accepted the request and before your agent logic runs.

```ts
import { sello } from "sello";

const receipts = sello.service();

export const sendMessage = receipts.a2aMessage(async (request, context) => {
  return agent.handleMessage(request, context);
});
```

## What It Does

`receipts.a2aMessage(...)` returns a normal A2A message handler. When another agent sends a message, Sello:

1. Reads the agent authorization token from the A2A context.
2. Verifies the token before your handler runs.
3. Runs your handler unchanged.
4. Emits a `success`, `error`, or `denied` receipt.
5. Preserves the handler return value and rethrows handler errors.

For JSON-RPC requests, the default receipt action type is:

```text
a2a.<method>
```

For `message/send`, the action type is:

```text
a2a.message/send
```

## Token Source

By default, Sello looks for `Authorization: Bearer ...` in common context or request shapes, including:

```ts
context.headers.authorization
context.requestInfo.headers.authorization
context.request.headers.authorization
request.headers.authorization
```

Fetch-style `Headers` objects are supported too.

If your A2A runtime stores the token somewhere else, pass an extractor:

```ts
receipts.a2aMessage(handler, {
  authorizationToken: ({ context }) => context.session.token,
});
```

The token should be the same authorization token the calling agent used for the A2A request. Sello hashes the exact token bytes into `sello_token_ref`; do not parse and reserialize it first.

## What Gets Hashed

For JSON-RPC-shaped A2A requests, the default input hash covers only the stable method boundary:

```json
{
  "method": "message/send",
  "params": {}
}
```

Sello does not hash:

- The bearer token.
- Transport headers.
- JSON-RPC request ids.
- Connection/session objects.
- Other context that may vary across runtimes.

That keeps receipts stable without leaking secrets or transport details.

If you need a different hash boundary, pass `canonicalizeInput`.

## Unknown Methods

Only wrap A2A methods you actually execute. If a request names an unknown method, return your normal JSON-RPC method-not-found error without emitting a Sello receipt.

The minimal example does this:

```ts
if (request.body.method !== "message/send") {
  return {
    jsonrpc: "2.0",
    id: request.body.id,
    error: { code: -32601, message: "method not found" },
  };
}
```

## View Actions

In local development:

```bash
npx sello dev
```

Run your A2A message call, then view verified actions:

```bash
npx sello actions
```

Or open:

```text
http://localhost:8787/actions
```

For a specific agent token:

```bash
npx sello actions --token <agent-token>
```

## Example

See [`sdks/typescript/examples/a2a-minimal-server.ts`](../sdks/typescript/examples/a2a-minimal-server.ts) for a dependency-free A2A-shaped example. It wraps one `message/send` handler and leaves unknown methods unreceipted.
