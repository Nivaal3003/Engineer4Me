export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000 as const;
export const DEFAULT_MAXIMUM_RESPONSE_BYTES = 2_000_000 as const;

export interface ApiTransportConfiguration {
  readonly applicationOrigin: string;
  readonly apiOrigin: string;
  readonly requestTimeoutMs: number;
  readonly maximumResponseBytes: number;
}

function originUrl(label: string, value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute URL origin.`);
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(`${label} must be a credential-free HTTP(S) origin.`);
  }
  return parsed;
}

function boundedInteger(label: string, value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

export function createApiTransportConfiguration(input: {
  readonly applicationOrigin: string;
  readonly apiOrigin?: string;
  readonly requestTimeoutMs?: number;
  readonly maximumResponseBytes?: number;
}): ApiTransportConfiguration {
  const application = originUrl("applicationOrigin", input.applicationOrigin);
  const api = originUrl("apiOrigin", input.apiOrigin ?? input.applicationOrigin);
  if (application.origin !== api.origin) {
    throw new Error("Engineer4Me API transport is restricted to the application origin.");
  }
  return Object.freeze({
    applicationOrigin: application.origin,
    apiOrigin: api.origin,
    requestTimeoutMs: boundedInteger(
      "requestTimeoutMs",
      input.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      1,
      120_000,
    ),
    maximumResponseBytes: boundedInteger(
      "maximumResponseBytes",
      input.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES,
      1,
      20_000_000,
    ),
  });
}

export function resolveSameOriginApiUrl(
  configuration: ApiTransportConfiguration,
  path: string,
): URL {
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#")
  ) {
    throw new Error("API operation path must be an absolute same-origin path without query or fragment.");
  }
  const resolved = new URL(path, configuration.apiOrigin);
  if (resolved.origin !== configuration.applicationOrigin) {
    throw new Error("Resolved API URL crossed the application origin boundary.");
  }
  return resolved;
}
