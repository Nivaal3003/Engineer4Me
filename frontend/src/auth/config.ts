import {
  BrowserCacheLocation,
  PublicClientApplication,
  type Configuration,
} from "@azure/msal-browser";

const REQUIRED_PUBLIC_SETTINGS = [
  "VITE_ENTRA_CLIENT_ID",
  "VITE_ENTRA_AUTHORITY",
  "VITE_ENTRA_API_SCOPE",
] as const;

type RequiredPublicSetting = (typeof REQUIRED_PUBLIC_SETTINGS)[number];

export type AuthenticationConfigurationReadiness =
  | {
      ready: false;
      missing: RequiredPublicSetting[];
    }
  | {
      ready: true;
      missing: [];
      clientId: string;
      authority: string;
      apiScope: string;
    };

function readSetting(name: RequiredPublicSetting): string {
  return (import.meta.env[name] ?? "").trim();
}

export function readAuthenticationConfiguration(): AuthenticationConfigurationReadiness {
  const values = new Map<RequiredPublicSetting, string>(
    REQUIRED_PUBLIC_SETTINGS.map((name) => [name, readSetting(name)]),
  );

  const missing = REQUIRED_PUBLIC_SETTINGS.filter(
    (name) => (values.get(name) ?? "").length === 0,
  );

  if (missing.length > 0) {
    return { ready: false, missing };
  }

  return {
    ready: true,
    missing: [],
    clientId: values.get("VITE_ENTRA_CLIENT_ID")!,
    authority: values.get("VITE_ENTRA_AUTHORITY")!,
    apiScope: values.get("VITE_ENTRA_API_SCOPE")!,
  };
}

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
