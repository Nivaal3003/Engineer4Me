import {
  applyBackendAuthorizationProfile,
  beginAuthenticationInitialization,
  createBackendAuthorizationProfile,
  createInitialAuthenticationSnapshot,
  establishAuthenticatedIdentity,
  normalizeIdentityAccount,
  selectAuthenticationOrganisation,
} from "../auth";
import { getBackendOperation } from "../api/operation-registry";
import type { BackendAuthorizationProfileSourceReadiness } from "../auth/profile-source";
import { evaluateAuthenticationConfiguration } from "../auth/config";
import { createRouteAccessContext, INACTIVE_ROUTE_ACCESS_CONTEXT, routeById } from "../routing";
import { createProtectedWorkspaceModel } from "./models";

const AUTHENTICATION = createInitialAuthenticationSnapshot(evaluateAuthenticationConfiguration({}));
const PROFILE_SOURCE: BackendAuthorizationProfileSourceReadiness = {
  state: "unavailable",
  reason: "no_accepted_backend_authorization_profile_operation",
  operation: null,
};

const TEST_READY_PROFILE_SOURCE: BackendAuthorizationProfileSourceReadiness = {
  state: "ready",
  reason: "accepted_backend_authorization_profile_operation_present",
  operation: getBackendOperation("get_api_v1_manufacturers"),
};

function authorizedAuthentication() {
  const readiness = evaluateAuthenticationConfiguration({
    VITE_ENTRA_CLIENT_ID: "11111111-2222-3333-4444-555555555555",
    VITE_ENTRA_AUTHORITY: "https://engineer4me.ciamlogin.com/",
    VITE_ENTRA_API_SCOPE: "api://11111111-2222-3333-4444-555555555555/access_as_user",
  });
  const principal = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
  const initialized = beginAuthenticationInitialization(createInitialAuthenticationSnapshot(readiness));
  const authenticated = establishAuthenticatedIdentity(initialized, principal);
  const profile = createBackendAuthorizationProfile({
    authority: "backend",
    principalKey: principal.principalKey,
    roles: ["engineer"],
    entitlements: ["engineering.designs.read", "engineering.projects.read", "security.audit.read"],
    controlledAdministration: true,
    organisations: [{
      organisationId: "organisation-1",
      organisationName: "Controlled test organisation",
      entitlements: ["engineering.designs.read", "engineering.projects.read", "security.audit.read"],
    }],
    revision: "fixture-1",
  }, principal);
  return selectAuthenticationOrganisation(
    applyBackendAuthorizationProfile(authenticated, profile),
    "organisation-1",
  );
}

describe("protected workspace model", () => {
  it("fails closed before identity, profile, organisation, entitlement, and transport gates", () => {
    const model = createProtectedWorkspaceModel({
      route: routeById("selection"),
      accessContext: INACTIVE_ROUTE_ACCESS_CONTEXT,
      authentication: AUTHENTICATION,
      profileSource: PROFILE_SOURCE,
      apiTransportActive: false,
    });
    expect(model).toMatchObject({
      state: "authentication_inactive",
      capabilityAdapterState: "prepared_in_memory_contract_only",
      allocatedOperationCount: 22,
      queryOperationCount: 9,
      commandOperationCount: 13,
      verticalSliceAvailability: "evidence_led_in_memory_ready",
      liveTransportActive: false,
      protectedContentAvailable: false,
    });
  });

  it("keeps routes without accepted operations unavailable after access gates", () => {
    const authentication = authorizedAuthentication();
    const model = createProtectedWorkspaceModel({
      route: routeById("troubleshooting"),
      accessContext: createRouteAccessContext(authentication),
      authentication,
      profileSource: TEST_READY_PROFILE_SOURCE,
      apiTransportActive: true,
    });
    expect(model).toMatchObject({
      state: "capability_adapter_unavailable",
      capabilityAdapterState: "no_accepted_backend_operation",
      allocatedOperationCount: 0,
      queryOperationCount: 0,
      commandOperationCount: 0,
      verticalSliceAvailability: "no_accepted_backend_operation",
      liveTransportActive: false,
      protectedContentAvailable: false,
    });
  });

  it("prepares an allocated route without loading protected content", () => {
    const authentication = authorizedAuthentication();
    const model = createProtectedWorkspaceModel({
      route: routeById("selection"),
      accessContext: createRouteAccessContext(authentication),
      authentication,
      profileSource: TEST_READY_PROFILE_SOURCE,
      apiTransportActive: true,
    });
    expect(model).toMatchObject({
      state: "request_ready",
      capabilityAdapterState: "prepared_in_memory_contract_only",
      allocatedOperationCount: 22,
      queryOperationCount: 9,
      commandOperationCount: 13,
      verticalSliceAvailability: "evidence_led_in_memory_ready",
      liveTransportActive: false,
      protectedContentAvailable: false,
    });
  });
});
