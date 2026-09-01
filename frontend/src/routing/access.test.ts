import { evaluateRouteAccess, INACTIVE_ROUTE_ACCESS_CONTEXT } from "./access";
import { routeById } from "./routes";

describe("Engineer4Me protected-route ownership", () => {
  it("allows only the public shell while authentication is inactive", () => {
    expect(evaluateRouteAccess(routeById("home"), INACTIVE_ROUTE_ACCESS_CONTEXT)).toMatchObject({
      state: "allowed",
      allowed: true,
    });
    expect(
      evaluateRouteAccess(routeById("selection"), INACTIVE_ROUTE_ACCESS_CONTEXT),
    ).toMatchObject({ state: "inactive", allowed: false });
  });

  it("requires explicit entitlements for entitled engineering routes", () => {
    const authenticated = {
      authentication: "authenticated" as const,
      entitlements: new Set<string>(),
      controlledAdministration: false,
    };
    expect(evaluateRouteAccess(routeById("designs"), authenticated)).toMatchObject({
      state: "denied",
      allowed: false,
      requiredEntitlement: "engineering.designs.read",
    });

    const entitled = {
      ...authenticated,
      entitlements: new Set(["engineering.designs.read"]),
    };
    expect(evaluateRouteAccess(routeById("designs"), entitled)).toMatchObject({
      state: "allowed",
      allowed: true,
    });
  });

  it("keeps controlled administration separate from ordinary authentication", () => {
    const authenticated = {
      authentication: "authenticated" as const,
      entitlements: new Set(["security.audit.read"]),
      controlledAdministration: false,
    };
    expect(evaluateRouteAccess(routeById("security"), authenticated)).toMatchObject({
      state: "denied",
      allowed: false,
    });
    expect(
      evaluateRouteAccess(routeById("security"), {
        authentication: "authenticated",
        entitlements: new Set<string>(),
        controlledAdministration: true,
      }),
    ).toMatchObject({ state: "denied", allowed: false });
    expect(
      evaluateRouteAccess(routeById("security"), {
        ...authenticated,
        controlledAdministration: true,
      }),
    ).toMatchObject({ state: "allowed", allowed: true });
  });
});
