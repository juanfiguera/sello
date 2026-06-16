import { sello, type SelloReceipts } from "../src/index.ts";

export type MinimalA2aRequest = {
  headers: {
    authorization?: string;
    Authorization?: string;
  };
  body: {
    jsonrpc: "2.0";
    id: string | number | null;
    method: string;
    params: {
      message: {
        role: "user" | "agent";
        parts: { kind: "text"; text: string }[];
      };
    };
  };
};

export type MinimalA2aResponse = {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: {
    kind: "message";
    messageId: string;
    role: "agent";
    parts: { kind: "text"; text: string }[];
  };
  error?: {
    code: number;
    message: string;
  };
};

export function createCalendarA2aAgent(
  receipts: SelloReceipts = sello.service(),
) {
  const sendMessage = receipts.a2aMessage<
    MinimalA2aRequest["body"],
    MinimalA2aResponse,
    MinimalA2aRequest
  >(async (body) => {
    const text = body.params.message.parts
      .filter((part) => part.kind === "text")
      .map((part) => part.text)
      .join(" ");
    const title = text || "untitled";

    return {
      jsonrpc: "2.0",
      id: body.id,
      result: {
        kind: "message",
        messageId: "calendar-reply-1",
        role: "agent",
        parts: [
          {
            kind: "text",
            text: `created ${title}`,
          },
        ],
      },
    };
  });

  return {
    async handle(request: MinimalA2aRequest): Promise<MinimalA2aResponse> {
      if (request.body.method !== "message/send") {
        return {
          jsonrpc: "2.0",
          id: request.body.id,
          error: {
            code: -32601,
            message: "method not found",
          },
        };
      }

      return await sendMessage(request.body, request);
    },

    flush: () => receipts.flush(),
  };
}
