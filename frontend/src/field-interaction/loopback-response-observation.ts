import {
  DEFAULT_DENY_PERMISSIONS_POLICY_VALUE,
  parseDeploymentPermissionsPolicyValue,
} from "./deployment-permissions-policy";
import { validateFieldInteractionIdentifier } from "./models";

export const CONTROLLED_LOOPBACK_HOST = "127.0.0.1" as const;
export const CONTROLLED_LOOPBACK_PATH = "/phase10-readiness" as const;
export const CONTROLLED_LOOPBACK_CONTENT_TYPE =
  "text/html; charset=utf-8" as const;

export type ControlledLoopbackObservationSource =
  | "controlled_verification_probe"
  | "scripted_test_fixture";

export interface ControlledResponseHeaderEntry {
  readonly name: string;
  readonly value: string;
}

export interface ControlledLoopbackResponseObservation {
  readonly observationId: string;
  readonly source: ControlledLoopbackObservationSource;
  readonly state: "accepted" | "invalid";
  readonly requestMethod: "GET";
  readonly requestUrl: string;
  readonly statusCode: number;
  readonly permissionsPolicyValue: string | null;
  readonly exactDefaultDenyHeaderObserved: boolean;
  readonly contentTypeValue: string | null;
  readonly cacheControlValue: string | null;
  readonly headerCount: number;
  readonly blockingReasons: readonly string[];
  readonly loopbackRequestPerformed: boolean;
  readonly externalNetworkRequestPerformed: false;
  readonly liveDeploymentHeaderRead: false;
  readonly browserExecuted: false;
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly authenticationPerformed: false;
  readonly bearerTokenAttached: false;
  readonly protectedContentAccessed: false;
  readonly backendTransportActivated: false;
}

const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

function normalizeHeaders(
  entries: readonly ControlledResponseHeaderEntry[],
): ReadonlyMap<string, readonly string[]> {
  if (entries.length > 32) {
    throw new Error("Controlled loopback response has too many header entries.");
  }
  const headers = new Map<string, string[]>();
  for (const entry of entries) {
    const name = entry.name.trim().toLowerCase();
    const value = entry.value.trim();
    if (!HEADER_NAME_PATTERN.test(name)) {
      throw new Error("Controlled loopback response contains an invalid header name.");
    }
    if (CONTROL_CHARACTER_PATTERN.test(value)) {
      throw new Error("Controlled loopback response contains a control character.");
    }
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return headers;
}

function singleHeader(
  headers: ReadonlyMap<string, readonly string[]>,
  name: string,
  reasons: string[],
): string | null {
  const values = headers.get(name) ?? [];
  if (values.length !== 1) {
    reasons.push(
      values.length === 0
        ? `Required ${name} response header is absent.`
        : `Duplicate ${name} response headers are not accepted.`,
    );
    return null;
  }
  return values[0]!;
}

function validateLoopbackUrl(value: string, reasons: string[]): string {
  const supplied = value.trim();
  try {
    const parsed = new URL(supplied);
    if (parsed.protocol !== "http:") {
      reasons.push("Controlled observation requires an HTTP loopback URL.");
    }
    if (parsed.hostname !== CONTROLLED_LOOPBACK_HOST) {
      reasons.push("Controlled observation is restricted to the IPv4 loopback host.");
    }
    if (!/^\d{1,5}$/.test(parsed.port)) {
      reasons.push("Controlled observation requires an explicit loopback port.");
    } else {
      const port = Number(parsed.port);
      if (port < 1 || port > 65535) {
        reasons.push("Controlled observation loopback port is outside the valid range.");
      }
    }
    if (parsed.pathname !== CONTROLLED_LOOPBACK_PATH) {
      reasons.push("Controlled observation request path differs.");
    }
    if (parsed.search || parsed.hash || parsed.username || parsed.password) {
      reasons.push("Controlled observation URL contains unsupported components.");
    }
    return parsed.toString();
  } catch {
    reasons.push("Controlled observation request URL is invalid.");
    return supplied;
  }
}

export function createControlledLoopbackResponseObservation(input: {
  readonly observationId: string;
  readonly source: ControlledLoopbackObservationSource;
  readonly requestMethod: "GET";
  readonly requestUrl: string;
  readonly statusCode: number;
  readonly headers: readonly ControlledResponseHeaderEntry[];
}): ControlledLoopbackResponseObservation {
  const reasons: string[] = [];
  const requestUrl = validateLoopbackUrl(input.requestUrl, reasons);
  if (input.requestMethod !== "GET") {
    reasons.push("Controlled observation request method must be GET.");
  }
  if (input.statusCode !== 200) {
    reasons.push("Controlled observation response status must be 200.");
  }

  let headers: ReadonlyMap<string, readonly string[]>;
  try {
    headers = normalizeHeaders(input.headers);
  } catch (error) {
    reasons.push(error instanceof Error ? error.message : "Header normalization failed.");
    headers = new Map();
  }

  const permissionsPolicyValue = singleHeader(
    headers,
    "permissions-policy",
    reasons,
  );
  const contentTypeValue = singleHeader(headers, "content-type", reasons);
  const cacheControlValue = singleHeader(headers, "cache-control", reasons);

  if (contentTypeValue !== null && contentTypeValue.toLowerCase() !== CONTROLLED_LOOPBACK_CONTENT_TYPE) {
    reasons.push("Controlled observation Content-Type differs.");
  }
  if (cacheControlValue !== null && cacheControlValue.toLowerCase() !== "no-store") {
    reasons.push("Controlled observation Cache-Control must be no-store.");
  }
  for (const prohibited of [
    "location",
    "set-cookie",
    "www-authenticate",
    "proxy-authenticate",
    "access-control-allow-origin",
  ]) {
    if ((headers.get(prohibited) ?? []).length > 0) {
      reasons.push(`Prohibited ${prohibited} response header is present.`);
    }
  }

  const parsedPolicy = parseDeploymentPermissionsPolicyValue(
    permissionsPolicyValue,
  );
  const exactDefaultDenyHeaderObserved =
    parsedPolicy.state === "accepted"
    && permissionsPolicyValue === DEFAULT_DENY_PERMISSIONS_POLICY_VALUE
    && parsedPolicy.canonicalValue === DEFAULT_DENY_PERMISSIONS_POLICY_VALUE;
  if (!exactDefaultDenyHeaderObserved) {
    reasons.push(
      "Controlled observation must prove the exact canonical default-deny Permissions-Policy value.",
    );
  }

  return Object.freeze({
    observationId: validateFieldInteractionIdentifier(
      input.observationId,
      "Loopback observation identifier",
    ),
    source: input.source,
    state: reasons.length === 0 ? "accepted" : "invalid",
    requestMethod: "GET",
    requestUrl,
    statusCode: input.statusCode,
    permissionsPolicyValue,
    exactDefaultDenyHeaderObserved,
    contentTypeValue,
    cacheControlValue,
    headerCount: input.headers.length,
    blockingReasons: Object.freeze(reasons),
    loopbackRequestPerformed: input.source === "controlled_verification_probe",
    externalNetworkRequestPerformed: false,
    liveDeploymentHeaderRead: false,
    browserExecuted: false,
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    authenticationPerformed: false,
    bearerTokenAttached: false,
    protectedContentAccessed: false,
    backendTransportActivated: false,
  });
}
