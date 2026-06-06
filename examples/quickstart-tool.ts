#!/usr/bin/env -S node --experimental-strip-types

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  canonicalJsonBytes,
  sello,
  type SdkSubmissionLog,
} from "../src/index.ts";

export type QuickstartDevState = {
  serviceId: string;
  serviceKey: string;
  tokenIssuerPublicKey: string;
  agentToken: string;
  logUrl: string;
  logEndpoint: string;
};

export type QuickstartEventRequest = {
  authorizationToken: string;
  calendarId: string;
  title: string;
  start: string;
  attendees: string[];
};

export type QuickstartEventResponse = {
  id: string;
  calendarId: string;
  title: string;
  status: "created";
  createdAt: string;
};

export type QuickstartToolOptions = {
  state?: QuickstartDevState;
  statePath?: string;
  log?: SdkSubmissionLog;
  now?: () => string;
  request?: Partial<Omit<QuickstartEventRequest, "authorizationToken">>;
};

const defaultRequest = {
  calendarId: "demo-calendar",
  title: "Review launch plan",
  start: "2026-06-05T17:00:00Z",
  attendees: ["ada@example.com", "grace@example.com"],
};

export async function runQuickstartTool(
  options: QuickstartToolOptions = {},
): Promise<{
  request: QuickstartEventRequest;
  response: QuickstartEventResponse;
  actionsUrl: string;
}> {
  const state = options.state ?? loadQuickstartDevState(options.statePath);
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

  const createEvent = receipts.tool<QuickstartEventRequest, QuickstartEventResponse>(
    "calendar.create_event",
    async (request) => ({
      id: `evt_${slug(request.title)}`,
      calendarId: request.calendarId,
      title: request.title,
      status: "created",
      createdAt: new Date().toISOString(),
    }),
    {
      canonicalizeInput: (request) => canonicalJsonBytes({
        calendarId: request.calendarId,
        title: request.title,
        start: request.start,
        attendees: request.attendees,
      }),
    },
  );

  const request = {
    ...defaultRequest,
    ...options.request,
    authorizationToken: state.agentToken,
  };
  const response = await createEvent(request);
  await receipts.flush();

  return { request, response, actionsUrl: actionViewerUrl(state) };
}

export function loadQuickstartDevState(
  statePath = join(process.cwd(), ".sello", "dev.json"),
): QuickstartDevState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(statePath, "utf8"));
  } catch {
    throw new TypeError(
      "missing local Sello dev state. Start the local log with `node --run dev` from this repo, or `npx sello dev` after install, then run `node --run example:tool` in another terminal.",
    );
  }

  if (!isRecord(parsed)) {
    throw new TypeError("local Sello dev state must be a JSON object");
  }

  return {
    serviceId: readString(parsed.serviceId, "dev state serviceId"),
    serviceKey: readString(parsed.serviceKey, "dev state serviceKey"),
    tokenIssuerPublicKey: readString(
      parsed.tokenIssuerPublicKey,
      "dev state tokenIssuerPublicKey",
    ),
    agentToken: readString(parsed.agentToken, "dev state agentToken"),
    logUrl: readString(parsed.logUrl, "dev state logUrl"),
    logEndpoint: readString(parsed.logEndpoint, "dev state logEndpoint"),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { response, actionsUrl } = await runQuickstartTool();
    console.log("Created example event and emitted a Sello receipt.");
    console.log(JSON.stringify(response, null, 2));
    console.log("");
    console.log("View verified actions with:");
    console.log("  node --run actions");
    console.log("");
    console.log("Or open:");
    console.log(`  ${actionsUrl}`);
  } catch (error) {
    console.error(`sello quickstart: ${error instanceof Error ? error.message : String(error)}`);
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

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
}

function actionViewerUrl(state: QuickstartDevState): string {
  const endpoint = new URL(state.logEndpoint);
  return `${endpoint.origin}/actions`;
}

function readString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }

  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
