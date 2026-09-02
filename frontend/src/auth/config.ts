import {
  BrowserCacheLocation,
  PublicClientApplication,
  type Configuration,
} from "@azure/msal-browser";

export const REQUIRED_PUBLIC_AUTHENTICATION_SETTINGS = [
  "VITE_ENTRA_CLIENT_ID",
  "VITE_ENTRA_AUTHORITY",
  "VITE_ENTRA_API_SCOPE",
] as const;

export type RequiredPublicAuthenticationSetting =
  (typeof REQUIRED_PUBLIC_AUTHENTICATION_SETTINGS)[number];

export type AuthenticationConfigurationIssueCode =
  | "missing"
  | "invalid_client_id"
  | "invalid_authority"
  | "invalid_api_scope";

export interface AuthenticationConfigurationIssue {
  readonly setting: RequiredPublicAuthenticationSetting;
  readonly code: AuthenticationConfigurationIssueCode;
}

export interface AuthenticationConfigurationInput {
  readonly VITE_ENTRA_CLIENT_ID?: string | undefined;
  readonly VITE_ENTRA_AUTHORITY?: string | undefined;
  readonly VITE_ENTRA_API_SCOPE?: string | undefined;
}

export type AuthenticationConfigurationReadiness =
  | {
      readonly ready: false;
      readonly missing: readonly RequiredPublicAuthenticationSetting[];
      readonly issues: readonly AuthenticationConfigurationIssue[];
    }
  | {
      readonly ready: true;
      readonly missing: readonly [];
      readonly issues: readonly [];
      readonly clientId: string;
      readonly authority: string;
      readonly apiScope: string;
    };

const CLIENT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const CONTROL_OR_SPACE_PATTERN = /[\u0000-\u0020\u007f]/u;

function normalizeSetting(value: string | undefined): string {
  return (value ?? "").trim();
}

function validAuthority(value: string): boolean {
  try {
    const authority = new URL(value);
    return (
      authority.protocol === "https:" &&
      authority.hostname.length > 0 &&
      authority.username.length === 0 &&
      authority.password.length === 0 &&
      authority.search.length === 0 &&
      authority.hash.length === 0 &&
      authority.hostname !== "localhost" &&
      !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(authority.hostname)
    );
  } catch {
    return false;
  }
}

function validApiScope(value: string): boolean {
  if (value.length > 512 || CONTROL_OR_SPACE_PATTERN.test(value)) {
    return false;
  }
  try {
    const scope = new URL(value);
    return (
      (scope.protocol === "api:" || scope.protocol === "https:") &&
      scope.hostname.length > 0 &&
      scope.pathname.length > 1 &&
      scope.username.length === 0 &&
      scope.password.length === 0 &&
      scope.search.length === 0 &&
      scope.hash.length === 0
    );
  } catch {
    return false;
  }
}

export function evaluateAuthenticationConfiguration(
  input: AuthenticationConfigurationInput,
): AuthenticationConfigurationReadiness {
  const values = {
    VITE_ENTRA_CLIENT_ID: normalizeSetting(input.VITE_ENTRA_CLIENT_ID),
    VITE_ENTRA_AUTHORITY: normalizeSetting(input.VITE_ENTRA_AUTHORITY),
    VITE_ENTRA_API_SCOPE: normalizeSetting(input.VITE_ENTRA_API_SCOPE),
  } satisfies Record<RequiredPublicAuthenticationSetting, string>;

  const issues: AuthenticationConfigurationIssue[] = [];
  for (const setting of REQUIRED_PUBLIC_AUTHENTICATION_SETTINGS) {
    if (values[setting].length === 0) {
      issues.push({ setting, code: "missing" });
    }
  }

  if (
    values.VITE_ENTRA_CLIENT_ID.length > 0 &&
    !CLIENT_ID_PATTERN.test(values.VITE_ENTRA_CLIENT_ID)
  ) {
    issues.push({ setting: "VITE_ENTRA_CLIENT_ID", code: "invalid_client_id" });
  }
  if (
    values.VITE_ENTRA_AUTHORITY.length > 0 &&
    !validAuthority(values.VITE_ENTRA_AUTHORITY)
  ) {
    issues.push({ setting: "VITE_ENTRA_AUTHORITY", code: "invalid_authority" });
  }
  if (
    values.VITE_ENTRA_API_SCOPE.length > 0 &&
    !validApiScope(values.VITE_ENTRA_API_SCOPE)
  ) {
    issues.push({ setting: "VITE_ENTRA_API_SCOPE", code: "invalid_api_scope" });
  }

  if (issues.length > 0) {
    const missing = REQUIRED_PUBLIC_AUTHENTICATION_SETTINGS.filter((setting) =>
      issues.some((issue) => issue.setting === setting && issue.code === "missing"),
    );
    return Object.freeze({
      ready: false,
      missing: Object.freeze(missing),
      issues: Object.freeze(issues),
    });
  }

  return Object.freeze({
    ready: true,
    missing: Object.freeze([]) as readonly [],
    issues: Object.freeze([]) as readonly [],
    clientId: values.VITE_ENTRA_CLIENT_ID.toLowerCase(),
    authority: values.VITE_ENTRA_AUTHORITY,
    apiScope: values.VITE_ENTRA_API_SCOPE,
  });
}

export function readAuthenticationConfiguration(): AuthenticationConfigurationReadiness {
  return evaluateAuthenticationConfiguration({
    VITE_ENTRA_CLIENT_ID: import.meta.env.VITE_ENTRA_CLIENT_ID,
    VITE_ENTRA_AUTHORITY: import.meta.env.VITE_ENTRA_AUTHORITY,
    VITE_ENTRA_API_SCOPE: import.meta.env.VITE_ENTRA_API_SCOPE,
  });
}

/**
 * Constructs an MSAL client without initializing it or starting an identity-provider operation.
 * The running application does not call this function in Batch 329-344.
 * Redirect-result handling options remain deferred to a later activation gate.
 */
export function createInactiveMsalClient(
  readiness: Extract<AuthenticationConfigurationReadiness, { ready: true }>,
): PublicClientApplication {
  const configuration: Configuration = {
    auth: {
      clientId: readiness.clientId,
      authority: readiness.authority,
      redirectUri: window.location.origin,
      postLogoutRedirectUri: window.location.origin,
    },
    cache: {
      cacheLocation: BrowserCacheLocation.SessionStorage,
    },
  };
  return new PublicClientApplication(configuration);
}
