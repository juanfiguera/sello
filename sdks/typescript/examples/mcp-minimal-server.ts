import { sello, type SelloReceipts } from "../src/index.ts";

export type MinimalMcpRequest = {
  headers: {
    authorization?: string;
    Authorization?: string;
  };
  body: {
    jsonrpc: "2.0";
    id: string | number | null;
    method: "tools/call";
    params: {
      name: string;
      arguments: Record<string, unknown>;
    };
  };
};

export type MinimalMcpResponse = {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: {
    content: { type: "text"; text: string }[];
  };
  error?: {
    code: number;
    message: string;
  };
};

export function createCalendarMcpServer(
  receipts: SelloReceipts = sello.service(),
) {
  const createEvent = receipts.mcpTool<
    MinimalMcpRequest["body"]["params"]["arguments"],
    MinimalMcpResponse,
    MinimalMcpRequest
  >(
    "calendar.create_event",
    async (args, request) => {
      const title = readString(args.title, "title");

      return {
        jsonrpc: "2.0",
        id: request.body.id,
        result: {
          content: [
            {
              type: "text",
              text: `created ${title}`,
            },
          ],
        },
      };
    },
  );

  return {
    async handle(request: MinimalMcpRequest): Promise<MinimalMcpResponse> {
      if (
        request.body.method !== "tools/call" ||
        request.body.params.name !== "calendar.create_event"
      ) {
        return {
          jsonrpc: "2.0",
          id: request.body.id,
          error: {
            code: -32601,
            message: "tool not found",
          },
        };
      }

      return await createEvent(request.body.params.arguments, request);
    },

    flush: () => receipts.flush(),
  };
}

function readString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }

  return value;
}
