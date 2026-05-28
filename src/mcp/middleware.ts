import { createReceipt, type CreatedReceipt } from "../service/create-receipt.ts";
import { verifySelloJwsToken } from "../token/jws-profile.ts";
import { type ReceiptSubmissionLog } from "../log/types.ts";

export type SelloMcpHandler<Request, Response> = (
  request: Request,
) => Response | Promise<Response>;

export type SelloMcpValueOrGetter<Request, Value> =
  | Value
  | ((request: Request) => Value);

export type SelloMcpReceiptEvent<Response = unknown> = {
  resultStatus: "success" | "error" | "denied";
  receipt: CreatedReceipt;
  response?: Response;
  error?: unknown;
};

export type SelloMcpMiddlewareInput<Request, Response> = {
  handler: SelloMcpHandler<Request, Response>;
  authorizationToken: SelloMcpValueOrGetter<Request, string | Uint8Array>;
  tokenIssuerPublicKey: Uint8Array;
  fallbackSelloLogs?: readonly string[];
  serviceKid: Uint8Array;
  servicePrivateKey: Uint8Array;
  serviceIdentifier: string;
  log: ReceiptSubmissionLog;
  actionType?: string | ((request: Request) => string);
  canonicalizeInput?: (request: Request) => Uint8Array;
  canonicalizeOutput?: (response: Response) => Uint8Array;
  canonicalizeError?: (error: unknown) => Uint8Array;
  isDenied?: (request: Request) => boolean | Promise<boolean>;
  deniedResponse?: (request: Request) => Response | Promise<Response>;
  now?: () => string;
  onReceipt?: (event: SelloMcpReceiptEvent<Response>) => void;
};

export class SelloMcpDeniedError extends Error {
  readonly receipt: CreatedReceipt;

  constructor(receipt: CreatedReceipt) {
    super("MCP request denied by Sello middleware");
    this.name = "SelloMcpDeniedError";
    this.receipt = receipt;
  }
}

export function createSelloMcpMiddleware<Request, Response>(
  input: SelloMcpMiddlewareInput<Request, Response>,
): SelloMcpHandler<Request, Response> {
  return async (request: Request): Promise<Response> => {
    const authorizationToken = resolveValue(input.authorizationToken, request);
    const verifiedToken = verifySelloJwsToken({
      authorizationToken,
      issuerPublicKey: input.tokenIssuerPublicKey,
    });
    const baseReceiptInput = {
      authorizationTokenBytes: verifiedToken.authorizationTokenBytes,
      ownerHpkePublicKey: verifiedToken.ownerHpkePublicKey,
      selloLogs: verifiedToken.selloLogs ?? input.fallbackSelloLogs ?? [],
      serviceKid: input.serviceKid,
      servicePrivateKey: input.servicePrivateKey,
      serviceIdentifier: input.serviceIdentifier,
      log: input.log,
      actionType: resolveActionType(input.actionType, request),
      actionInputBytes: (input.canonicalizeInput ?? canonicalJsonBytes)(request),
      timestamp: (input.now ?? nowUtcSeconds)(),
    };

    if (input.isDenied && (await input.isDenied(request))) {
      const response = input.deniedResponse
        ? await input.deniedResponse(request)
        : undefined;
      const receipt = createReceipt({
        ...baseReceiptInput,
        actionOutputBytes: new Uint8Array(),
        resultStatus: "denied",
      });
      input.onReceipt?.({ resultStatus: "denied", receipt, response });

      if (input.deniedResponse) {
        return response as Response;
      }

      throw new SelloMcpDeniedError(receipt);
    }

    let response: Response;
    try {
      response = await input.handler(request);
    } catch (error) {
      const receipt = createReceipt({
        ...baseReceiptInput,
        actionOutputBytes: (input.canonicalizeError ?? canonicalErrorBytes)(
          error,
        ),
        resultStatus: "error",
      });
      input.onReceipt?.({ resultStatus: "error", receipt, error });
      throw error;
    }

    const receipt = createReceipt({
      ...baseReceiptInput,
      actionOutputBytes: (input.canonicalizeOutput ?? canonicalJsonBytes)(
        response,
      ),
      resultStatus: "success",
    });
    input.onReceipt?.({ resultStatus: "success", receipt, response });
    return response;
  };
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

function canonicalJson(value: unknown): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
    case "number":
    case "string":
      return primitiveJson(value);
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map(canonicalJson).join(",")}]`;
      }

      return objectJson(value as Record<string, unknown>);
    default:
      throw new TypeError("value must be JSON-serializable");
  }
}

function primitiveJson(value: boolean | number | string): string {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("number must be finite");
  }

  return JSON.stringify(value);
}

function objectJson(value: Record<string, unknown>): string {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("object must be a plain JSON object");
  }

  const entries = Object.entries(value);
  entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));

  return `{${entries
    .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
    .join(",")}}`;
}

function canonicalErrorBytes(error: unknown): Uint8Array {
  if (error instanceof Error) {
    return canonicalJsonBytes({
      name: error.name,
      message: error.message,
    });
  }

  return canonicalJsonBytes({ error: String(error) });
}

function resolveValue<Request, Value>(
  value: SelloMcpValueOrGetter<Request, Value>,
  request: Request,
): Value {
  if (typeof value === "function") {
    return (value as (request: Request) => Value)(request);
  }

  return value;
}

function resolveActionType<Request>(
  actionType: SelloMcpMiddlewareInput<Request, unknown>["actionType"],
  request: Request,
): string {
  if (typeof actionType === "function") {
    return actionType(request);
  }

  return actionType ?? "tools/call";
}

function nowUtcSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
