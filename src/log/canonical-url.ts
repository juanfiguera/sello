export type CanonicalLogUrl = string & { readonly __canonicalLogUrl: unique symbol };

const UNRESERVED = /^[A-Za-z0-9._~-]$/;

export function isCanonicalLogUrl(value: unknown): value is CanonicalLogUrl {
  try {
    assertCanonicalLogUrl(value);
    return true;
  } catch {
    return false;
  }
}

export function assertCanonicalLogUrl(
  value: unknown,
  name = "logUrl",
): asserts value is CanonicalLogUrl {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }

  if (!value.startsWith("https://")) {
    throw new TypeError(`${name} must use lowercase https scheme`);
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${name} must be a valid URL`);
  }

  if (parsed.protocol !== "https:") {
    throw new TypeError(`${name} must use https`);
  }

  if (parsed.username !== "" || parsed.password !== "") {
    throw new TypeError(`${name} must not contain userinfo`);
  }

  if (parsed.search !== "") {
    throw new TypeError(`${name} must not contain a query string`);
  }

  if (parsed.hash !== "") {
    throw new TypeError(`${name} must not contain a fragment`);
  }

  const authority = getAuthority(value);
  if (authority.includes("@")) {
    throw new TypeError(`${name} must not contain userinfo`);
  }

  const { rawHost, rawPort } = splitAuthority(authority);
  if (rawHost === "") {
    throw new TypeError(`${name} must contain a host`);
  }

  if (/[A-Z]/.test(rawHost)) {
    throw new TypeError(`${name} host must be lowercase`);
  }

  if (rawPort === "443") {
    throw new TypeError(`${name} must omit default port :443`);
  }

  if (rawPort !== undefined && !/^[0-9]+$/.test(rawPort)) {
    throw new TypeError(`${name} port must be numeric`);
  }

  const rawPath = getRawPath(value);
  if (rawPath === "") {
    throw new TypeError(`${name} must include a path prefix`);
  }

  if (!rawPath.startsWith("/")) {
    throw new TypeError(`${name} path must start with /`);
  }

  if (rawPath.length > 1 && rawPath.endsWith("/")) {
    throw new TypeError(`${name} must not have a trailing slash`);
  }

  assertPercentEncoding(rawPath, name);
  assertNoDotSegments(rawPath, name);
}

export function logUrlsEqual(a: CanonicalLogUrl, b: CanonicalLogUrl): boolean {
  assertCanonicalLogUrl(a, "a");
  assertCanonicalLogUrl(b, "b");
  return a === b;
}

function getAuthority(value: string): string {
  const withoutScheme = value.slice("https://".length);
  const end = withoutScheme.search(/[/?#]/);
  return end === -1 ? withoutScheme : withoutScheme.slice(0, end);
}

function getRawPath(value: string): string {
  const withoutScheme = value.slice("https://".length);
  const pathStart = withoutScheme.search(/[/?#]/);
  if (pathStart === -1 || withoutScheme[pathStart] !== "/") {
    return "";
  }

  const pathAndSuffix = withoutScheme.slice(pathStart);
  const end = pathAndSuffix.search(/[?#]/);
  return end === -1 ? pathAndSuffix : pathAndSuffix.slice(0, end);
}

function splitAuthority(authority: string): { rawHost: string; rawPort?: string } {
  if (authority.startsWith("[")) {
    const closing = authority.indexOf("]");
    if (closing === -1) {
      return { rawHost: authority };
    }
    const rawHost = authority.slice(0, closing + 1);
    const rest = authority.slice(closing + 1);
    return rest.startsWith(":")
      ? { rawHost, rawPort: rest.slice(1) }
      : { rawHost };
  }

  const colon = authority.lastIndexOf(":");
  if (colon === -1) {
    return { rawHost: authority };
  }

  return {
    rawHost: authority.slice(0, colon),
    rawPort: authority.slice(colon + 1),
  };
}

function assertPercentEncoding(rawPath: string, name: string): void {
  for (let index = 0; index < rawPath.length; index += 1) {
    if (rawPath[index] !== "%") {
      continue;
    }

    const hex = rawPath.slice(index + 1, index + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
      throw new TypeError(`${name} contains invalid percent-encoding`);
    }

    if (hex !== hex.toUpperCase()) {
      throw new TypeError(`${name} percent-encoding hex digits must be uppercase`);
    }

    const decoded = String.fromCharCode(Number.parseInt(hex, 16));
    if (UNRESERVED.test(decoded)) {
      throw new TypeError(`${name} must not percent-encode unreserved characters`);
    }

    index += 2;
  }
}

function assertNoDotSegments(rawPath: string, name: string): void {
  const segments = rawPath.split("/");

  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw new TypeError(`${name} must not contain dot segments`);
    }
  }
}
