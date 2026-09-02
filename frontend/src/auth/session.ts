import type { AuthenticationConfigurationReadiness } from "./config";
import type { BackendAuthorizationProfile } from "./authorization";
import type { IdentityPrincipal } from "./identity";
import {
  selectOrganisationContext,
  type ActiveOrganisationContext,
} from "./organisation";

export type AuthenticationPhase =
  | "not_configured"
  | "configured_inactive"
  | "initializing"
  | "authenticated"
  | "blocked"
  | "error";

export interface AuthenticationSnapshot {
  readonly phase: AuthenticationPhase;
  readonly configurationReady: boolean;
  readonly principal: IdentityPrincipal | null;
  readonly authorizationProfile: BackendAuthorizationProfile | null;
  readonly activeOrganisation: ActiveOrganisationContext | null;
  readonly tokenAttachment: "inactive";
  readonly safeMessage: string;
}

function snapshot(value: AuthenticationSnapshot): AuthenticationSnapshot {
  return Object.freeze(value);
}

export function createInitialAuthenticationSnapshot(
  readiness: AuthenticationConfigurationReadiness,
): AuthenticationSnapshot {
  return snapshot({
    phase: readiness.ready ? "configured_inactive" : "not_configured",
    configurationReady: readiness.ready,
    principal: null,
    authorizationProfile: null,
    activeOrganisation: null,
    tokenAttachment: "inactive",
    safeMessage: readiness.ready
      ? "Authentication configuration is valid, but identity-provider execution is inactive."
      : "Authentication configuration is incomplete or invalid.",
  });
}

export function beginAuthenticationInitialization(
  current: AuthenticationSnapshot,
): AuthenticationSnapshot {
  if (!current.configurationReady || current.phase !== "configured_inactive") {
    throw new Error("Authentication initialization is not permitted from the current state.");
  }
  return snapshot({ ...current, phase: "initializing", safeMessage: "Authentication initialization is in progress." });
}

export function establishAuthenticatedIdentity(
  current: AuthenticationSnapshot,
  principal: IdentityPrincipal,
): AuthenticationSnapshot {
  if (current.phase !== "initializing") {
    throw new Error("Authenticated identity cannot be established from the current state.");
  }
  return snapshot({
    ...current,
    phase: "authenticated",
    principal,
    authorizationProfile: null,
    activeOrganisation: null,
    safeMessage: "Identity is established; backend authorization profile is still required.",
  });
}

export function applyBackendAuthorizationProfile(
  current: AuthenticationSnapshot,
  profile: BackendAuthorizationProfile,
): AuthenticationSnapshot {
  if (current.phase !== "authenticated" || !current.principal) {
    throw new Error("Authorization profile requires an authenticated identity.");
  }
  if (profile.principalKey !== current.principal.principalKey) {
    throw new Error("Authorization profile does not belong to the active principal.");
  }
  return snapshot({
    ...current,
    authorizationProfile: profile,
    activeOrganisation: null,
    safeMessage: "Identity and backend authorization profile are established; organisation selection remains explicit.",
  });
}

export function selectAuthenticationOrganisation(
  current: AuthenticationSnapshot,
  organisationId: string,
): AuthenticationSnapshot {
  if (!current.authorizationProfile) {
    throw new Error("Organisation selection requires a backend authorization profile.");
  }
  return snapshot({
    ...current,
    activeOrganisation: selectOrganisationContext(
      current.authorizationProfile.organisations,
      organisationId,
    ),
    safeMessage: "An approved organisation context has been explicitly selected.",
  });
}

export function blockAuthenticationSnapshot(
  current: AuthenticationSnapshot,
  safeMessage: string,
): AuthenticationSnapshot {
  const message = safeMessage.trim();
  if (message.length === 0 || message.length > 240 || /[\u0000-\u001f\u007f]/u.test(message)) {
    throw new Error("Authentication error message is not safe for presentation.");
  }
  return snapshot({
    ...current,
    phase: "blocked",
    principal: null,
    authorizationProfile: null,
    activeOrganisation: null,
    tokenAttachment: "inactive",
    safeMessage: message,
  });
}

export function isBackendAuthorizedSession(
  current: AuthenticationSnapshot,
): current is AuthenticationSnapshot & {
  readonly principal: IdentityPrincipal;
  readonly authorizationProfile: BackendAuthorizationProfile;
} {
  return current.phase === "authenticated" && current.principal !== null && current.authorizationProfile !== null;
}

export function authenticationPhaseLabel(phase: AuthenticationPhase): string {
  const labels: Record<AuthenticationPhase, string> = {
    not_configured: "Configuration blocked",
    configured_inactive: "Configured, inactive",
    initializing: "Initializing",
    authenticated: "Authenticated",
    blocked: "Blocked",
    error: "Error",
  };
  return labels[phase];
}
