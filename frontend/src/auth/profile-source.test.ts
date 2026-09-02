import type { BackendOperationDefinition } from "../api/operation-registry";
import type { ControlledApiTransport } from "../api/transport";
import { normalizeIdentityAccount } from "./identity";
import {
  createTransportBackedAuthorizationProfileSource,
  evaluateBackendAuthorizationProfileSource,
} from "./profile-source";

const PRINCIPAL = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
const SYNTHETIC_PROFILE_OPERATION: BackendOperationDefinition = {
  key: "get_authorization_profile",
  operationId: "getAuthorizationProfile",
  method: "GET",
  pathTemplate: "/synthetic/profile",
  pathParameters: [],
  source: "synthetic-test-only",
  sourceLine: 1,
  responseModel: "AuthorizationProfileResponse",
  frontendAccessPolicy: "authenticated",
  inventorySecurityDependencySignal: true,
};

describe("backend authorization profile source", () => {
  it("reports unavailable because the accepted Step 281 registry contains no profile operation", () => {
    expect(evaluateBackendAuthorizationProfileSource()).toEqual({
      state: "unavailable",
      reason: "no_accepted_backend_authorization_profile_operation",
      operation: null,
    });
  });

  it("decodes a profile only through an explicitly supplied accepted-operation descriptor", async () => {
    const readiness = evaluateBackendAuthorizationProfileSource([SYNTHETIC_PROFILE_OPERATION]);
    if (readiness.state !== "ready") throw new Error("Expected synthetic test readiness.");
    const execute = vi.fn(async () => ({
      status: 200,
      correlationId: "correlation-1",
      data: {
        authority: "backend",
        principalKey: PRINCIPAL.principalKey,
        revision: "profile-1",
        roles: [],
        entitlements: [],
        controlledAdministration: false,
        organisations: [],
      },
    }));
    const transport: ControlledApiTransport = {
      execute: execute as ControlledApiTransport["execute"],
    };
    const source = createTransportBackedAuthorizationProfileSource({ readiness, transport });
    await expect(source.loadProfile({ principal: PRINCIPAL, correlationId: "correlation-1" }))
      .resolves.toMatchObject({ authority: "backend", revision: "profile-1" });
  });
});
