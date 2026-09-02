const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;

export interface AuthenticationRedirectPolicyInput {
  readonly applicationOrigin: string;
  readonly redirectPath?: string;
  readonly postLogoutPath?: string;
  readonly allowedReturnPaths: readonly string[];
}

export interface AuthenticationRedirectPolicy {
  readonly applicationOrigin: string;
  readonly redirectUri: string;
  readonly postLogoutRedirectUri: string;
  readonly allowedReturnPaths: readonly string[];
}

function parseApplicationOrigin(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Authentication application origin must be an absolute URL.");
  }
  const loopbackHttp =
    parsed.protocol === "http:" &&
    (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "[::1]");
  if (
    (parsed.protocol !== "https:" && !loopbackHttp) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error("Authentication application origin must be credential-free HTTPS or an explicit loopback HTTP origin.");
  }
  return parsed;
}

function normalizePathOnly(value: string, label: string): string {
  const candidate = value.trim();
  if (
    candidate.length === 0 ||
    candidate.length > 512 ||
    CONTROL_PATTERN.test(candidate) ||
    !candidate.startsWith("/") ||
    candidate.startsWith("//") ||
    candidate.includes("\\") ||
    candidate.includes("?") ||
    candidate.includes("#")
  ) {
    throw new Error(`${label} must be a bounded same-origin path without query or fragment.`);
  }
  const normalized = candidate.length > 1 ? candidate.replace(/\/+$/u, "") : candidate;
  return normalized || "/";
}

export function createAuthenticationRedirectPolicy(
  input: AuthenticationRedirectPolicyInput,
): AuthenticationRedirectPolicy {
  const origin = parseApplicationOrigin(input.applicationOrigin);
  if (input.allowedReturnPaths.length === 0 || input.allowedReturnPaths.length > 64) {
    throw new Error("Authentication return-path allowlist must contain between 1 and 64 entries.");
  }
  const allowed = Object.freeze(
    [...new Set(input.allowedReturnPaths.map((path) => normalizePathOnly(path, "Allowed return path")))].sort(),
  );
  const redirectPath = normalizePathOnly(input.redirectPath ?? "/", "Redirect path");
  const postLogoutPath = normalizePathOnly(input.postLogoutPath ?? "/", "Post-logout path");
  if (!allowed.includes(redirectPath) || !allowed.includes(postLogoutPath)) {
    throw new Error("Redirect and post-logout paths must be present in the reviewed return-path allowlist.");
  }
  return Object.freeze({
    applicationOrigin: origin.origin,
    redirectUri: new URL(redirectPath, origin).href,
    postLogoutRedirectUri: new URL(postLogoutPath, origin).href,
    allowedReturnPaths: allowed,
  });
}

export function resolveAuthenticationReturnPath(
  policy: AuthenticationRedirectPolicy,
  value: string,
): string {
  const path = normalizePathOnly(value, "Authentication return path");
  if (!policy.allowedReturnPaths.includes(path)) {
    throw new Error("Authentication return path is not in the reviewed same-origin allowlist.");
  }
  return new URL(path, policy.applicationOrigin).href;
}
