import type { AuthenticationSnapshot } from "../auth/session";
import type { BackendAuthorizationProfileSourceReadiness } from "../auth/profile-source";
import {
  getProtectedCapabilityAdapterDefinition,
  type CapabilityAdapterReadinessState,
} from "../capabilities";
import { getCapabilityVerticalSlice } from "../capability-workspace";
import { evaluateRouteAccess, type AppRouteDefinition, type RouteAccessContext } from "../routing";

export type ProtectedWorkspaceState =
  | "authentication_inactive"
  | "authorization_profile_unavailable"
  | "organisation_required"
  | "entitlement_denied"
  | "capability_adapter_unavailable"
  | "transport_inactive"
  | "request_ready";

export interface ProtectedWorkspaceModel {
  readonly state: ProtectedWorkspaceState;
  readonly title: string;
  readonly detail: string;
  readonly guidance: readonly string[];
  readonly capabilityAdapterState: CapabilityAdapterReadinessState;
  readonly allocatedOperationCount: number;
  readonly queryOperationCount: number;
  readonly commandOperationCount: number;
  readonly verticalSliceAvailability:
    | "evidence_led_in_memory_ready"
    | "no_accepted_backend_operation";
  readonly liveTransportActive: false;
  readonly protectedContentAvailable: false;
}

export function createProtectedWorkspaceModel(input: {
  readonly route: AppRouteDefinition;
  readonly accessContext: RouteAccessContext;
  readonly authentication: AuthenticationSnapshot;
  readonly profileSource: BackendAuthorizationProfileSourceReadiness;
  readonly apiTransportActive: boolean;
}): ProtectedWorkspaceModel {
  if (input.route.id === "home") {
    throw new Error("The public home route does not have a protected capability adapter.");
  }
  const adapter = getProtectedCapabilityAdapterDefinition(input.route.id);
  const verticalSlice = getCapabilityVerticalSlice(input.route.id);
  const access = evaluateRouteAccess(input.route, input.accessContext);
  const adapterGuidance = adapter.state === "prepared_in_memory_contract_only"
    ? `${adapter.operationCount} accepted backend operations are allocated for in-memory contract verification only; no request has been made.`
    : "No accepted backend operation is allocated to this protected capability route.";
  const commonGuidance = Object.freeze([
    adapterGuidance,
    "No engineering result, organisational record, or protected data has been disclosed.",
    "Client-side state is presentation control only; backend authorization remains authoritative.",
    "Final engineering approval and operational authorization remain user or authorized-organisation responsibilities.",
  ]);
  const model = (
    state: ProtectedWorkspaceState,
    title: string,
    detail: string,
  ): ProtectedWorkspaceModel => Object.freeze({
    state,
    title,
    detail,
    guidance: commonGuidance,
    capabilityAdapterState: adapter.state,
    allocatedOperationCount: adapter.operationCount,
    queryOperationCount: adapter.queryOperationCount,
    commandOperationCount: adapter.commandOperationCount,
    verticalSliceAvailability: verticalSlice.availability,
    liveTransportActive: false,
    protectedContentAvailable: false,
  });

  if (input.authentication.principal === null) {
    return model(
      "authentication_inactive",
      `${input.route.label} is not available`,
      "Authentication execution has not been activated.",
    );
  }
  if (input.profileSource.state === "unavailable" || input.authentication.authorizationProfile === null) {
    return model(
      "authorization_profile_unavailable",
      `${input.route.label} is not available`,
      "A backend-authoritative access profile is not available through an accepted API operation.",
    );
  }
  if (input.authentication.activeOrganisation === null) {
    return model(
      "organisation_required",
      `${input.route.label} requires an organisation`,
      "An approved organisation membership must be selected explicitly.",
    );
  }
  if (!access.allowed) {
    return model(
      "entitlement_denied",
      `${input.route.label} access is denied`,
      access.requiredEntitlement
        ? `The required entitlement ${access.requiredEntitlement} is not present.`
        : access.reason,
    );
  }
  if (adapter.state === "no_accepted_backend_operation") {
    return model(
      "capability_adapter_unavailable",
      `${input.route.label} is not connected`,
      "No accepted backend operation is available for this capability, so no adapter request can be prepared.",
    );
  }
  if (!input.apiTransportActive) {
    return model(
      "transport_inactive",
      `${input.route.label} is not connected`,
      "The capability contract is prepared, but controlled API transport has not been activated in the running application.",
    );
  }
  return model(
    "request_ready",
    `${input.route.label} is ready for a controlled request`,
    "Access and adapter gates are satisfied, but no protected request or result has been loaded.",
  );
}
