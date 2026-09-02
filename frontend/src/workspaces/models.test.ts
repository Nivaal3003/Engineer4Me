import { evaluateAuthenticationConfiguration } from "../auth/config";
import { createInitialAuthenticationSnapshot } from "../auth/session";
import { INACTIVE_ROUTE_ACCESS_CONTEXT, routeById } from "../routing";
import { createProtectedWorkspaceModel } from "./models";

const AUTHENTICATION = createInitialAuthenticationSnapshot(evaluateAuthenticationConfiguration({}));
const PROFILE_SOURCE = {
  state: "unavailable",
  reason: "no_accepted_backend_authorization_profile_operation",
  operation: null,
} as const;

describe("protected workspace model", () => {
  it("fails closed before identity, profile, organisation, entitlement, and transport gates", () => {
    const model = createProtectedWorkspaceModel({
      route: routeById("selection"),
      accessContext: INACTIVE_ROUTE_ACCESS_CONTEXT,
      authentication: AUTHENTICATION,
      profileSource: PROFILE_SOURCE,
      apiTransportActive: false,
    });
    expect(model).toMatchObject({ state: "authentication_inactive", protectedContentAvailable: false });
  });
});
