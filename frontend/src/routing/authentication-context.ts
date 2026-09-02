import { isBackendAuthorizedSession, type AuthenticationSnapshot } from "../auth/session";
import type { RouteAccessContext } from "./access";

export function createRouteAccessContext(
  snapshot: AuthenticationSnapshot,
): RouteAccessContext {
  if (!isBackendAuthorizedSession(snapshot)) {
    return Object.freeze({
      authentication: "inactive",
      entitlements: new Set<string>(),
      controlledAdministration: false,
    });
  }

  const entitlements = new Set(snapshot.authorizationProfile.entitlements);
  for (const entitlement of snapshot.activeOrganisation?.entitlements ?? []) {
    entitlements.add(entitlement);
  }

  return Object.freeze({
    authentication: "authenticated",
    entitlements,
    controlledAdministration: snapshot.authorizationProfile.controlledAdministration,
  });
}
