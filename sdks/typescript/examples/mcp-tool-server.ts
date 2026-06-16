#!/usr/bin/env -S node --experimental-strip-types

import { pathToFileURL } from "node:url";

import {
  sello,
  type SdkSubmissionLog,
  type SelloReceipts,
} from "../src/index.ts";
import {
  loadQuickstartDevState,
  type QuickstartDevState,
} from "./quickstart-tool.ts";

export type JsonRpcId = string | number | null;

export type McpToolCallBody = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: "tools/call";
  params: {
    name: string;
    arguments: Record<string, unknown>;
  };
};

export type McpHttpToolCall = {
  headers: {
    authorization: string;
  };
  body: McpToolCallBody;
};

export type McpToolResult = {
  content: readonly {
    type: "text";
    text: string;
  }[];
};

export type McpHttpToolResponse = {
  status: number;
  body:
    | {
        jsonrpc: "2.0";
        id: JsonRpcId;
        result: McpToolResult;
      }
    | {
        jsonrpc: "2.0";
        id: JsonRpcId;
        error: {
          code: number;
          message: string;
        };
      };
};

export type SelloMcpToolServer = {
  tool(
    name: string,
    handler: (args: Record<string, unknown>) => McpToolResult | Promise<McpToolResult>,
  ): void;
  handle(request: McpHttpToolCall): Promise<McpHttpToolResponse>;
};

export type McpToolServerExampleOptions = {
  state?: QuickstartDevState;
  statePath?: string;
  log?: SdkSubmissionLog;
  now?: () => string;
  toolArguments?: Record<string, unknown>;
};

export function createSelloMcpToolServer(receipts: SelloReceipts): SelloMcpToolServer {
  const tools = new Map<
    string,
    (
      args: Record<string, unknown>,
      request: McpHttpToolCall,
    ) => Promise<McpHttpToolResponse>
  >();

  return {
    tool(name, handler) {
      if (typeof name !== "string" || name.length === 0) {
        throw new TypeError("MCP tool name must be a non-empty string");
      }
      if (tools.has(name)) {
        throw new TypeError(`MCP tool ${name} is already registered`);
      }

      const wrapped = receipts.mcpTool<
        Record<string, unknown>,
        McpHttpToolResponse,
        McpHttpToolCall
      >(
        name,
        async (args, request) => ({
          status: 200,
          body: {
            jsonrpc: "2.0",
            id: request.body.id,
            result: await handler(args),
          },
        }),
      );

      tools.set(name, wrapped);
    },

    async handle(request) {
      if (request.body.method !== "tools/call") {
        return jsonRpcError(request.body.id, -32601, "method not found");
      }

      const tool = tools.get(request.body.params.name);
      if (!tool) {
        return jsonRpcError(request.body.id, -32601, "tool not found");
      }

      return await tool(request.body.params.arguments, request);
    },
  };
}

export async function runMcpToolServerExample(
  options: McpToolServerExampleOptions = {},
): Promise<{
  request: McpHttpToolCall;
  response: McpHttpToolResponse;
  actionsUrl: string;
}> {
  const state = options.state ?? loadMcpDevState(options.statePath);
  const receipts = sello.service({
    service: state.serviceId,
    serviceKey: state.serviceKey,
    tokenIssuer: state.tokenIssuerPublicKey,
    log: options.log ?? sello.logs.http(state.logUrl, {
      endpoint: state.logEndpoint,
    }),
    submit: { mode: "await" },
    now: options.now,
  });
  const server = createSelloMcpToolServer(receipts);

  server.tool("calendar.create_event", async (args) => {
    const title = readString(args.title, "title");
    return {
      content: [
        {
          type: "text",
          text: `created ${title}`,
        },
      ],
    };
  });

  const request = {
    headers: {
      authorization: `Bearer ${state.agentToken}`,
    },
    body: {
      jsonrpc: "2.0",
      id: "demo-call-1",
      method: "tools/call",
      params: {
        name: "calendar.create_event",
        arguments: {
          calendarId: "demo-calendar",
          title: "Review launch plan",
          start: "2026-06-05T17:00:00Z",
          ...(options.toolArguments ?? {}),
        },
      },
    },
  } satisfies McpHttpToolCall;

  const response = await server.handle(request);
  await receipts.flush();

  return { request, response, actionsUrl: actionViewerUrl(state) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { response, actionsUrl } = await runMcpToolServerExample();
    console.log("Handled MCP tools/call and emitted a Sello receipt.");
    console.log(JSON.stringify(response.body, null, 2));
    console.log("");
    console.log("View verified actions with:");
    console.log("  node --run actions");
    console.log("");
    console.log("Or open:");
    console.log(`  ${actionsUrl}`);
  } catch (error) {
    console.error(`sello mcp example: ${error instanceof Error ? error.message : String(error)}`);
    if (
      error instanceof Error &&
      (error.message.includes("fetch failed") ||
        error.message.includes("Sello log append failed"))
    ) {
      console.error("Is the local dev log running? Start it with `node --run dev`.");
    }
    process.exitCode = 1;
  }
}

function jsonRpcError(
  id: JsonRpcId,
  code: number,
  message: string,
): McpHttpToolResponse {
  return {
    status: 200,
    body: {
      jsonrpc: "2.0",
      id,
      error: { code, message },
    },
  };
}

function actionViewerUrl(state: QuickstartDevState): string {
  const endpoint = new URL(state.logEndpoint);
  return `${endpoint.origin}/actions`;
}

function loadMcpDevState(statePath?: string): QuickstartDevState {
  try {
    return loadQuickstartDevState(statePath);
  } catch (error) {
    if (error instanceof Error) {
      throw new TypeError(
        error.message.replace("node --run example:tool", "node --run example:mcp"),
      );
    }

    throw error;
  }
}

function readString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }

  return value;
}
