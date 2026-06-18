# Add Sello to an MCP Server

Sello belongs around the tool callback: after your MCP server has identified the tool, before your business logic runs.

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

Some MCP SDK versions call this registration method `tool` instead of `registerTool`. Use the same callback slot either way.

## What It Does

`receipts.mcpTool(...)` returns a normal MCP tool callback. When the agent calls the tool, Sello:

1. Reads the agent authorization token from the MCP context.
2. Verifies the token before your callback runs.
3. Runs your callback unchanged.
4. Emits a `success`, `error`, or `denied` receipt.
5. Preserves the callback return value and rethrows callback errors.

The default receipt action type is:

```text
mcp.tools/call.<tool-name>
```

For `calendar.create_event`, the action type is:

```text
mcp.tools/call.calendar.create_event
```

## Token Source

By default, Sello looks for `Authorization: Bearer ...` in common MCP context shapes, including:

```ts
context.headers.authorization
context.requestInfo.headers.authorization
context.request.headers.authorization
```

Fetch-style `Headers` objects are supported too.

If your transport stores the token somewhere else, pass an extractor:

```ts
receipts.mcpTool("calendar.create_event", handler, {
  authorizationToken: ({ context }) => context.session.token,
});
```

The token should be the same authorization token the agent used for the tool call. Sello hashes the exact token bytes into `sello_token_ref`; do not parse and reserialize it first.

## What Gets Hashed

The default MCP input hash covers only the stable MCP action shape:

```json
{
  "method": "tools/call",
  "params": {
    "name": "calendar.create_event",
    "arguments": {}
  }
}
```

Sello does not hash:

- The bearer token.
- Transport headers.
- Connection/session objects.
- Other context that may vary across runtimes.

That keeps receipts stable without leaking secrets or transport details.

If you need a different hash boundary, pass `canonicalizeInput`.

## Unknown Tools

Only wrap tools you actually execute. If a request names an unknown tool, return your normal MCP `method not found` or `tool not found` error without emitting a Sello receipt.

The minimal example does this:

```ts
if (request.body.params.name !== "calendar.create_event") {
  return {
    jsonrpc: "2.0",
    id: request.body.id,
    error: { code: -32601, message: "tool not found" },
  };
}
```

## View Actions

In local development:

```bash
npx sello dev
```

Run your MCP tool call, then view verified actions:

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

## Runnable Demo

To generate a tiny MCP-shaped demo in your project:

```bash
npx --yes sello init-mcp-demo
node sello-mcp-demo.mjs
npx --yes sello actions
```

Keep `npx sello dev` running in another terminal while you run the generated file.

## Example

See [`sdks/typescript/examples/mcp-minimal-server.ts`](../sdks/typescript/examples/mcp-minimal-server.ts) for a dependency-free MCP-shaped example. It wraps one `tools/call` handler and leaves unknown tools unreceipted.
