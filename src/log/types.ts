import { type CanonicalLogUrl } from "./canonical-url.ts";

export type LogCompleteness = "complete" | "discovery-only";

export type TransparencyLogEntry = {
  logUrl: CanonicalLogUrl;
  index: number;
  integratedTime: string;
  envelope: Uint8Array;
  proof: unknown;
};

export type TransparencyLogQueryResult = {
  completeness: LogCompleteness;
  entries: TransparencyLogEntry[];
};

export type VerificationLog = {
  logUrl: CanonicalLogUrl;
  queryByTokenRef(tokenRef: Uint8Array): TransparencyLogQueryResult;
  verifyInclusionProof(entry: TransparencyLogEntry): boolean;
};
