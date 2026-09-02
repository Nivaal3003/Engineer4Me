import type { AuthenticationSnapshot } from "../auth/session";
import type { BackendAuthorizationProfileSourceReadiness } from "../auth/profile-source";
import { evaluateRouteAccess, type AppRouteDefinition, type RouteAccessContext } from "../routing";

export type ProtectedWorkspaceState =
  | "authentication_inactive"
  | "authorization_profile_unavailable"
  | "organisation_required"
  | "entitlement_denied"
  | "transport_inactive"
  | "request_ready";

export interface ProtectedWorkspaceModel {
  readonly state: ProtectedWorkspaceState;
  readonly title: string;
  readonly detail: string;
  readonly guidance: readonly string[];
  readonly protectedContentAvailable: false;
}

export function createProtectedWorkspaceModel(input: {
  readonly route: AppRouteDefinition;
  readonly accessContext: RouteAccessContext;
  readonly authentication: AuthenticationSnapshot;
  readonly profileSource: BackendAuthorizationProfileSourceReadiness;
  readonly apiTransportActive: boolean;
}): ProtectedWorkspaceModel {
  const access = evaluateRouteAccess(input.route, input.accessContext);
  const commonGuidance = Object.freeze([
    "No engineering result, organisational record, or protected data has been disclosed.",
    "Client-side state is presentation control only; backend authorization remains authoritative.",
    "Final engineering approval and operational authorization remain user or authorized-organisation responsibilities.",
  ]);
  if (input.authentication.principal === null) {
    return Object.freeze({
      state: "authentication_inactive",
      title: `${input.route.label} is not available`,
      detail: "Authentication execution has not been activated.",
      guidance: commonGuidance,
      protectedContentAvailable: false,
    });
  }
  if (input.profileSource.state === "unavailable" || input.authentication.authorizationProfile === null) {
    return Object.freeze({
      state: "authorization_profile_unavailable",
      title: `${input.route.label} is not available`,
      detail: "A backend-authoritative access profile is not available through an accepted API operation.",
      guidance: commonGuidance,
      protectedContentAvailable: false,
    });
  }
  if (input.authentication.activeOrganisation === null) {
    return Object.freeze({
      state: "organisation_required",
      title: `${input.route.label} requires an organisation`,
      detail: "An approved organisation membership must be selected explicitly.",
      guidance: commonGuidance,
      protectedContentAvailable: false,
    });
  }
  if (!access.allowed) {
    return Object.freeze({
      state: "entitlement_denied",
      title: `${input.route.label} access is denied`,
      detail: access.requiredEntitlement
        ? `The required entitlement ${access.requiredEntitlement} is not present.`
        : access.reason,
      guidance: commonGuidance,
      protectedContentAvailable: false,
    });
  }
  if (!input.apiTransportActive) {
    return Object.freeze({
      state: "transport_inactive",
      title: `${input.route.label} is not connected`,
      detail: "The controlled API transport has not been activated in the running application.",
      guidance: commonGuidance,
      protectedContentAvailable: false,
    });
  }
  return Object.freeze({
    state: "request_ready",
    title: `${input.route.label} is ready for a controlled request`,
    detail: "Access gates are satisfied, but no protected request or result has been loaded.",
    guidance: commonGuidance,
    protectedContentAvailable: false,
  });
}
