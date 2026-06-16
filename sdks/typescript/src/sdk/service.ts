import { type BuiltReceipt, buildReceipt } from "../service/create-receipt.ts";
import { verifySelloJwsToken } from "../token/jws-profile.ts";
import { type CanonicalLogUrl, assertCanonicalLogUrl, logUrlsEqual } from "../log/canonical-url.ts";
import { type ResultStatus } from "../receipt/body.ts";
import { canonicalJsonBytes } from "../mcp/middleware.ts";
import {
  type KeyInput,
  type ServiceKeyInput,
  decodeBase64url,
  normalizeEd25519PublicKey,
  normalizeServiceKey,
} from "./keys.ts";
import { type SdkSubmissionLog, http } from "./logs.ts";
import {
  BackgroundReceiptPublisher,
  type DropEvent,
  type SelloSubmitOptions,
  type SubmitMode,
} from "./publisher.ts";

export type SelloToolHandler<Request, Response> = (
  request: Request,
) => Response | Promise<Response>;

export type SelloValueOrGetter<Request, Value> =
  | Value
  | ((request: Request) => Value);

export type SelloReceiptEvent<Response = unknown> = {
  resultStatus: ResultStatus;
  receipt: BuiltReceipt;
  response?: Response;
  error?: unknown;
};

export type SelloToolOptions<Request, Response> = {
  authorizationToken?: SelloValueOrGetter<Request, string | Uint8Array>;
  canonicalizeInput?: (request: Request) => Uint8Array;
  canonicalizeOutput?: (response: Response) => Uint8Array;
  canonicalizeError?: (error: unknown) => Uint8Array;
  isDenied?: (request: Request) => boolean | Promise<boolean>;
  deniedResponse?: (request: Request) => Response | Promise<Response>;
};

export type SelloMcpToolInvocation<Args, Context = unknown> = {
  name: string;
  arguments: Args;
  context: Context;
};

export type SelloMcpToolHandler<Args, Response, Context = unknown> = (
  args: Args,
  context: Context,
) => Response | Promise<Response>;

export type SelloMcpToolOptions<Args, Response, Context = unknown> = {
  actionType?: string;
  authorizationToken?: SelloValueOrGetter<
    SelloMcpToolInvocation<Args, Context>,
    string | Uint8Array
  >;
  canonicalizeInput?: (
    invocation: SelloMcpToolInvocation<Args, Context>,
  ) => Uint8Array;
  canonicalizeOutput?: (response: Response) => Uint8Array;
  canonicalizeError?: (error: unknown) => Uint8Array;
  isDenied?: (
    invocation: SelloMcpToolInvocation<Args, Context>,
  ) => boolean | Promise<boolean>;
  deniedResponse?: (
    invocation: SelloMcpToolInvocation<Args, Context>,
  ) => Response | Promise<Response>;
};

export type SelloServiceConfig = {
  service?: string;
  serviceKey?: ServiceKeyInput;
  serviceKid?: KeyInput;
  tokenIssuer?: KeyInput | { publicKey?: KeyInput; jwksUrl?: string };
  tokenIssuerPublicKey?: KeyInput;
  tokenIssuerJwks?: string;
  log?: SdkSubmissionLog;
  fallbackSelloLogs?: readonly string[];
  submit?: SubmitMode | SelloSubmitOptions;
  now?: () => string;
  onReceipt?: (event: SelloReceiptEvent) => void;
  onSubmitError?: (error: unknown) => void;
  onDrop?: (event: DropEvent) => void;
};

export type SelloServiceInput = string | SelloServiceConfig;

export type SelloReceipts = {
  tool<Request, Response>(
    actionType: string,
    handler: SelloToolHandler<Request, Response>,
    options?: SelloToolOptions<Request, Response>,
  ): SelloToolHandler<Request, Response>;
  mcpTool<Args, Response, Context = unknown>(
    name: string,
    handler: SelloMcpToolHandler<Args, Response, Context>,
    options?: SelloMcpToolOptions<Args, Response, Context>,
  ): SelloMcpToolHandler<Args, Response, Context>;
  flush(): Promise<void>;
};

type Environment = Record<string, string | undefined>;

type TokenIssuerConfig =
  | { type: "public-key"; publicKey: Uint8Array }
  | { type: "jwks"; jwksUrl: string; publicKey?: Uint8Array };

type ResolvedServiceConfig = {
  service: string;
  serviceKid: Uint8Array;
  servicePrivateKey: Uint8Array;
  tokenIssuer: TokenIssuerConfig;
  log: SdkSubmissionLog;
  fallbackSelloLogs?: readonly string[];
  now: () => string;
  onReceipt?: (event: SelloReceiptEvent) => void;
};

type DeferredConfig =
  | { type: "resolved"; config: ResolvedServiceConfig }
  | {
      type: "hosted";
      secretKey: string;
      configUrl: string;
      now: () => string;
      onReceipt?: (event: SelloReceiptEvent) => void;
    };

export function createSelloService(input?: SelloServiceInput): SelloReceipts {
  const deferred = resolveDeferredConfig(input, process.env);
  const publisherOptions = resolvePublisherOptions(input, process.env);
  let loaded: Promise<ResolvedServiceConfig> | undefined;
  let publisher: BackgroundReceiptPublisher | undefined;

  async function config(): Promise<ResolvedServiceConfig> {
    loaded ??= loadDeferredConfig(deferred);
    return await loaded;
  }

  function publisherFor(resolved: ResolvedServiceConfig): BackgroundReceiptPublisher {
    publisher ??= new BackgroundReceiptPublisher({
      log: resolved.log,
      ...publisherOptions,
    });
    return publisher;
  }

  function wrapTool<Request, Response>(
    actionType: string,
    handler: SelloToolHandler<Request, Response>,
    options: SelloToolOptions<Request, Response> = {},
  ): SelloToolHandler<Request, Response> {
    if (typeof actionType !== "string" || actionType.length === 0) {
      throw new TypeError("Sello action type must be a non-empty string");
    }

    return async (request: Request): Promise<Response> => {
      const resolved = await config();
      const authorizationToken = resolveValue(
        options.authorizationToken ?? defaultAuthorizationToken,
        request,
      );
      const tokenIssuerPublicKey = await resolveTokenIssuerPublicKey(resolved.tokenIssuer);
      const verifiedToken = verifySelloJwsToken({
        authorizationToken,
        issuerPublicKey: tokenIssuerPublicKey,
      });
      const selloLogs = selectSelloLogs(
        verifiedToken.selloLogs,
        resolved.fallbackSelloLogs,
        resolved.log.logUrl,
      );
      const base = {
        authorizationTokenBytes: verifiedToken.authorizationTokenBytes,
        ownerHpkePublicKey: verifiedToken.ownerHpkePublicKey,
        selloLogs,
        serviceKid: resolved.serviceKid,
        servicePrivateKey: resolved.servicePrivateKey,
        serviceIdentifier: resolved.service,
        logUrl: resolved.log.logUrl,
        actionType,
        actionInputBytes: (options.canonicalizeInput ?? canonicalJsonBytes)(request),
        timestamp: resolved.now(),
      };

      if (options.isDenied && (await options.isDenied(request))) {
        const response = options.deniedResponse
          ? await options.deniedResponse(request)
          : undefined;
        const receipt = emitReceipt({
          ...base,
          actionOutputBytes: new Uint8Array(),
          resultStatus: "denied",
        });
        resolved.onReceipt?.({ resultStatus: "denied", receipt, response });
        await submit(resolved, receipt, base.timestamp);

        if (options.deniedResponse) {
          return response as Response;
        }

        throw new SelloDeniedError(receipt);
      }

      let response: Response;
      try {
        response = await handler(request);
      } catch (error) {
        const receipt = emitReceipt({
          ...base,
          actionOutputBytes: (options.canonicalizeError ?? canonicalErrorBytes)(
            error,
          ),
          resultStatus: "error",
        });
        resolved.onReceipt?.({ resultStatus: "error", receipt, error });
        await submit(resolved, receipt, base.timestamp);
        throw error;
      }

      const receipt = emitReceipt({
        ...base,
        actionOutputBytes: (options.canonicalizeOutput ?? canonicalJsonBytes)(
          response,
        ),
        resultStatus: "success",
      });
      resolved.onReceipt?.({ resultStatus: "success", receipt, response });
      await submit(resolved, receipt, base.timestamp);
      return response;
    };
  }

  return {
    tool<Request, Response>(
      actionType: string,
      handler: SelloToolHandler<Request, Response>,
      options: SelloToolOptions<Request, Response> = {},
    ): SelloToolHandler<Request, Response> {
      return wrapTool(actionType, handler, options);
    },
    mcpTool<Args, Response, Context = unknown>(
      name: string,
      handler: SelloMcpToolHandler<Args, Response, Context>,
      options: SelloMcpToolOptions<Args, Response, Context> = {},
    ): SelloMcpToolHandler<Args, Response, Context> {
      if (typeof name !== "string" || name.length === 0) {
        throw new TypeError("MCP tool name must be a non-empty string");
      }

      const wrapped = wrapTool<SelloMcpToolInvocation<Args, Context>, Response>(
        options.actionType ?? `mcp.tools/call.${name}`,
        async (invocation) => handler(invocation.arguments, invocation.context),
        {
          authorizationToken:
            options.authorizationToken ?? defaultMcpAuthorizationToken,
          canonicalizeInput:
            options.canonicalizeInput ?? defaultMcpCanonicalizeInput,
          canonicalizeOutput: options.canonicalizeOutput,
          canonicalizeError: options.canonicalizeError,
          isDenied: options.isDenied,
          deniedResponse: options.deniedResponse,
        },
      );

      return async (args: Args, context: Context): Promise<Response> => {
        return await wrapped({ name, arguments: args, context });
      };
    },
    async flush(): Promise<void> {
      await publisher?.flush();
    },
  };

  async function submit(
    resolved: ResolvedServiceConfig,
    receipt: BuiltReceipt,
    integratedTime: string,
  ): Promise<void> {
    const currentPublisher = publisherFor(resolved);
    if (currentPublisher.mode === "await") {
      await currentPublisher.publish({
        envelope: receipt.envelope,
        integratedTime,
      });
      return;
    }

    currentPublisher.publishBackground({
      envelope: receipt.envelope,
      integratedTime,
    });
  }
}

export class SelloDeniedError extends Error {
  readonly receipt: BuiltReceipt;

  constructor(receipt: BuiltReceipt) {
    super("Sello request denied");
    this.name = "SelloDeniedError";
    this.receipt = receipt;
  }
}

function emitReceipt(input: Parameters<typeof buildReceipt>[0]): BuiltReceipt {
  return buildReceipt(input);
}

function resolveDeferredConfig(
  input: SelloServiceInput | undefined,
  env: Environment,
): DeferredConfig {
  const objectInput =
    typeof input === "object" && input !== null ? input : {};
  const serviceOverride = typeof input === "string" ? input : objectInput.service;
  const hostedSecret = env.SELLO_SECRET_KEY;

  if (
    hostedSecret &&
    objectInput.serviceKey === undefined &&
    env.SELLO_SERVICE_KEY === undefined
  ) {
    return {
      type: "hosted",
      secretKey: hostedSecret,
      configUrl:
        env.SELLO_HOSTED_CONFIG_URL ?? "https://sello.build/api/sdk/config",
      now: objectInput.now ?? nowUtcSeconds,
      onReceipt: objectInput.onReceipt,
    };
  }

  return {
    type: "resolved",
    config: resolveSelfHostedConfig(objectInput, serviceOverride, env),
  };
}

function resolvePublisherOptions(
  input: SelloServiceInput | undefined,
  env: Environment,
): Omit<ConstructorParameters<typeof BackgroundReceiptPublisher>[0], "log"> {
  const objectInput =
    typeof input === "object" && input !== null ? input : {};

  return {
    submit: objectInput.submit ?? envSubmitMode(env),
    onSubmitError: objectInput.onSubmitError,
    onDrop: objectInput.onDrop,
  };
}

function resolveSelfHostedConfig(
  input: SelloServiceConfig,
  serviceOverride: string | undefined,
  env: Environment,
): ResolvedServiceConfig {
  const service = serviceOverride ?? env.SELLO_SERVICE_ID;
  if (!service) {
    throw new TypeError(
      "Sello setup missing SELLO_SERVICE_ID. Set SELLO_SERVICE_ID or call sello.service(\"service-id\").",
    );
  }

  const serviceKey = normalizeServiceKey(
    input.serviceKey ?? env.SELLO_SERVICE_KEY,
    input.serviceKid ?? env.SELLO_SERVICE_KID,
  );
  const log =
    input.log ??
    (env.SELLO_LOG_URL
      ? http(env.SELLO_LOG_URL, { endpoint: env.SELLO_LOG_ENDPOINT })
      : undefined);

  if (!log) {
    throw new TypeError(
      "Sello setup missing SELLO_LOG_URL. Set SELLO_LOG_URL or pass log explicitly.",
    );
  }

  return {
    service,
    serviceKid: serviceKey.kid,
    servicePrivateKey: serviceKey.privateKey,
    tokenIssuer: normalizeTokenIssuer(input, env),
    log,
    fallbackSelloLogs: input.fallbackSelloLogs ?? [log.logUrl],
    now: input.now ?? nowUtcSeconds,
    onReceipt: input.onReceipt,
  };
}

async function loadDeferredConfig(
  deferred: DeferredConfig,
): Promise<ResolvedServiceConfig> {
  if (deferred.type === "resolved") {
    return deferred.config;
  }

  const response = await fetch(deferred.configUrl, {
    method: "GET",
    headers: {
      authorization: `Bearer ${deferred.secretKey}`,
    },
  });

  if (!response.ok) {
    throw new TypeError(`sello.build config fetch failed with HTTP ${response.status}`);
  }

  const config = await response.json();
  if (!isRecord(config)) {
    throw new TypeError("sello.build config response must be an object");
  }

  const service = readString(config.service, "hosted service");
  const logUrl = readString(config.logUrl, "hosted logUrl");
  const hostedServiceKey = normalizeServiceKey(
    readString(config.serviceKey, "hosted serviceKey"),
  );

  return {
    service,
    serviceKid: hostedServiceKey.kid,
    servicePrivateKey: hostedServiceKey.privateKey,
    tokenIssuer: {
      type: "public-key",
      publicKey: normalizeEd25519PublicKey(
        readString(config.tokenIssuerPublicKey, "hosted tokenIssuerPublicKey"),
        "hosted tokenIssuerPublicKey",
      ),
    },
    log: http(logUrl, {
      endpoint:
        typeof config.logEndpoint === "string" ? config.logEndpoint : undefined,
    }),
    fallbackSelloLogs: [http(logUrl).logUrl],
    now: deferred.now,
    onReceipt: deferred.onReceipt,
  };
}

function normalizeTokenIssuer(
  input: SelloServiceConfig,
  env: Environment,
): TokenIssuerConfig {
  const tokenIssuer = input.tokenIssuer;

  if (tokenIssuer instanceof Uint8Array || typeof tokenIssuer === "string") {
    return {
      type: "public-key",
      publicKey: normalizeEd25519PublicKey(tokenIssuer, "tokenIssuer"),
    };
  }

  if (tokenIssuer && typeof tokenIssuer === "object") {
    if (tokenIssuer.publicKey) {
      return {
        type: "public-key",
        publicKey: normalizeEd25519PublicKey(
          tokenIssuer.publicKey,
          "tokenIssuer.publicKey",
        ),
      };
    }

    if (tokenIssuer.jwksUrl) {
      return { type: "jwks", jwksUrl: tokenIssuer.jwksUrl };
    }
  }

  if (input.tokenIssuerPublicKey || env.SELLO_TOKEN_ISSUER_PUBLIC_KEY) {
    return {
      type: "public-key",
      publicKey: normalizeEd25519PublicKey(
        input.tokenIssuerPublicKey ?? env.SELLO_TOKEN_ISSUER_PUBLIC_KEY as string,
        "SELLO_TOKEN_ISSUER_PUBLIC_KEY",
      ),
    };
  }

  const jwksUrl = input.tokenIssuerJwks ?? env.SELLO_TOKEN_ISSUER_JWKS;
  if (jwksUrl) {
    return { type: "jwks", jwksUrl };
  }

  throw new TypeError(
    "Sello setup missing token issuer. Set SELLO_TOKEN_ISSUER_PUBLIC_KEY, SELLO_TOKEN_ISSUER_JWKS, or pass tokenIssuer.",
  );
}

async function resolveTokenIssuerPublicKey(
  issuer: TokenIssuerConfig,
): Promise<Uint8Array> {
  if (issuer.type === "public-key") {
    return issuer.publicKey;
  }

  issuer.publicKey ??= await fetchEd25519JwksKey(issuer.jwksUrl);
  return issuer.publicKey;
}

async function fetchEd25519JwksKey(jwksUrl: string): Promise<Uint8Array> {
  const response = await fetch(jwksUrl);
  if (!response.ok) {
    throw new TypeError(`token issuer JWKS fetch failed with HTTP ${response.status}`);
  }

  const jwks = await response.json();
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    throw new TypeError("token issuer JWKS must contain keys");
  }

  const key = jwks.keys.find(
    (candidate) =>
      isRecord(candidate) &&
      candidate.kty === "OKP" &&
      candidate.crv === "Ed25519" &&
      typeof candidate.x === "string",
  );

  if (!key || !isRecord(key) || typeof key.x !== "string") {
    throw new TypeError("token issuer JWKS must contain an Ed25519 OKP key");
  }

  return normalizeEd25519PublicKey(decodeBase64url(key.x, "JWKS x"), "JWKS x");
}

function selectSelloLogs(
  tokenLogs: readonly string[] | undefined,
  fallbackLogs: readonly string[] | undefined,
  logUrl: CanonicalLogUrl,
): readonly string[] {
  const selloLogs = tokenLogs ?? fallbackLogs ?? [];
  if (selloLogs.length === 0) {
    throw new TypeError("Sello token did not provide owner-trusted logs");
  }

  for (const entry of selloLogs) {
    assertCanonicalLogUrl(entry, "sello_logs entry");
    if (logUrlsEqual(entry, logUrl)) {
      return selloLogs;
    }
  }

  throw new TypeError("Sello log must be listed in the token's sello_logs");
}

function defaultAuthorizationToken(request: unknown): string | Uint8Array {
  const token = authorizationTokenFromUnknown(request);
  if (token) {
    return token;
  }

  throw new TypeError(
    "Sello authorization token not found. Pass authorizationToken or include request.authorizationToken.",
  );
}

function defaultMcpAuthorizationToken(
  invocation: SelloMcpToolInvocation<unknown, unknown>,
): string | Uint8Array {
  const fromContext = authorizationTokenFromUnknown(invocation.context);
  if (fromContext) {
    return fromContext;
  }

  throw new TypeError(
    "Sello MCP authorization token not found. Pass authorizationToken or include an Authorization header in the MCP context.",
  );
}

function defaultMcpCanonicalizeInput(
  invocation: SelloMcpToolInvocation<unknown, unknown>,
): Uint8Array {
  return canonicalJsonBytes({
    method: "tools/call",
    params: {
      name: invocation.name,
      arguments: invocation.arguments,
    },
  });
}

function authorizationTokenFromUnknown(value: unknown): string | Uint8Array | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const direct = value.authorizationToken ?? value.authorization;
  if (typeof direct === "string" || direct instanceof Uint8Array) {
    return stripBearer(direct);
  }

  const headers = value.headers;
  const fromHeaders = authorizationTokenFromHeaders(headers);
  if (fromHeaders) {
    return fromHeaders;
  }

  const requestInfo = value.requestInfo;
  if (isRecord(requestInfo)) {
    const fromRequestInfo = authorizationTokenFromHeaders(requestInfo.headers);
    if (fromRequestInfo) {
      return fromRequestInfo;
    }
  }

  const request = value.request;
  if (isRecord(request)) {
    const fromRequest = authorizationTokenFromHeaders(request.headers);
    if (fromRequest) {
      return fromRequest;
    }
  }

  const authInfo = value.authInfo;
  if (isRecord(authInfo)) {
    const token = authInfo.token ?? authInfo.accessToken ?? authInfo.access_token;
    if (typeof token === "string" || token instanceof Uint8Array) {
      return stripBearer(token);
    }
  }

  return undefined;
}

function authorizationTokenFromHeaders(
  headers: unknown,
): string | Uint8Array | undefined {
  if (isHeadersLike(headers)) {
    const header = headers.get("authorization") ?? headers.get("Authorization");
    if (typeof header === "string") {
      return stripBearer(header);
    }
  }

  if (!isRecord(headers)) {
    return undefined;
  }

  const header = headers.authorization ?? headers.Authorization;
  if (typeof header === "string" || header instanceof Uint8Array) {
    return stripBearer(header);
  }

  return undefined;
}

function isHeadersLike(
  value: unknown,
): value is { get(name: string): string | null } {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { get?: unknown }).get === "function"
  );
}

function stripBearer(value: string | Uint8Array): string | Uint8Array {
  if (typeof value !== "string") {
    return value;
  }

  return value.startsWith("Bearer ") ? value.slice("Bearer ".length) : value;
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
  value: SelloValueOrGetter<Request, Value>,
  request: Request,
): Value {
  if (typeof value === "function") {
    return (value as (request: Request) => Value)(request);
  }

  return value;
}

function envSubmitMode(env: Environment): SubmitMode | SelloSubmitOptions | undefined {
  const mode = env.SELLO_SUBMIT_MODE;
  if (mode === undefined) {
    return undefined;
  }

  if (mode !== "background" && mode !== "await") {
    throw new TypeError("SELLO_SUBMIT_MODE must be background or await");
  }

  return mode;
}

function nowUtcSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }

  return value;
}
