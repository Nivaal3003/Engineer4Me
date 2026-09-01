import type { AppRouteDefinition } from "./routes";

export type AuthenticationState = "inactive" | "authenticated";

export interface RouteAccessContext {
  readonly authentication: AuthenticationState;
  readonly entitlements: ReadonlySet<string>;
  readonly controlledAdministration: boolean;
}

export type RouteAccessDecisionState = "allowed" | "inactive" | "denied";

export interface RouteAccessDecision {
  readonly state: RouteAccessDecisionState;
  readonly allowed: boolean;
  readonly reason: string;
  readonly requiredEntitlement: string | null;
}

export const INACTIVE_ROUTE_ACCESS_CONTEXT: RouteAccessContext = Object.freeze({
  authentication: "inactive",
  entitlements: new Set<string>(),
  controlledAdministration: false,
});

export function evaluateRouteAccess(
  route: AppRouteDefinition,
  context: RouteAccessContext,
): RouteAccessDecision {
  if (route.accessRequirement === "public") {
    return {
      state: "allowed",
      allowed: true,
      reason: "This route is part of the public product shell.",
      requiredEntitlement: null,
    };
  }

  if (context.authentication !== "authenticated") {
    return {
      state: "inactive",
      allowed: false,
      reason:
        "Authentication is not active. The route remains visible for controlled product orientation, but protected content is fail closed.",
      requiredEntitlement: route.requiredEntitlement,
    };
  }

  if (route.accessRequirement === "authenticated") {
    return {
      state: "allowed",
      allowed: true,
      reason: "An authenticated session satisfies this route ownership boundary.",
      requiredEntitlement: null,
    };
  }

  if (route.accessRequirement === "entitled") {
    const entitlement = route.requiredEntitlement;
    if (entitlement && context.entitlements.has(entitlement)) {
      return {
        state: "allowed",
        allowed: true,
        reason: "The required entitlement is present.",
        requiredEntitlement: entitlement,
      };
    }
    return {
      state: "denied",
      allowed: false,
      reason: "The required entitlement is absent. No capability content is disclosed.",
      requiredEntitlement: entitlement,
    };
  }

  if (!context.controlledAdministration) {
    return {
      state: "denied",
      allowed: false,
      reason: "Controlled-administration access has not been established.",
      requiredEntitlement: route.requiredEntitlement,
    };
  }

  const entitlement = route.requiredEntitlement;
  if (entitlement && !context.entitlements.has(entitlement)) {
    return {
      state: "denied",
      allowed: false,
      reason: "The controlled-administration entitlement is absent.",
      requiredEntitlement: entitlement,
    };
  }

  return {
    state: "allowed",
    allowed: true,
    reason: "Controlled-administration access and entitlement have been explicitly established.",
    requiredEntitlement: entitlement,
  };
}
