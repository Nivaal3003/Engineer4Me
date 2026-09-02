import type { ControlledApiTransport } from "../api/transport";
import { BACKEND_OPERATIONS, type BackendOperationDefinition } from "../api/operation-registry";
import type { BackendAuthorizationProfile } from "./authorization";
import type { IdentityPrincipal } from "./identity";
import { decodeBackendAuthorizationProfile } from "./profile-decoder";

export type BackendAuthorizationProfileSourceReadiness =
  | {
      readonly state: "unavailable";
      readonly reason: "no_accepted_backend_authorization_profile_operation";
      readonly operation: null;
    }
  | {
      readonly state: "ready";
      readonly reason: "accepted_backend_authorization_profile_operation_present";
      readonly operation: BackendOperationDefinition;
    };

export interface BackendAuthorizationProfileSourcePort {
  loadProfile(input: {
    readonly principal: IdentityPrincipal;
    readonly correlationId: string;
  }): Promise<BackendAuthorizationProfile>;
}

function isProfileOperation(operation: BackendOperationDefinition): boolean {
  const searchable = `${operation.key} ${operation.operationId ?? ""} ${operation.responseModel ?? ""}`.toLowerCase();
  return (
    operation.method === "GET" &&
    operation.frontendAccessPolicy === "authenticated" &&
    operation.pathParameters.length === 0 &&
    searchable.includes("authorization") &&
    searchable.includes("profile")
  );
}

export function evaluateBackendAuthorizationProfileSource(
  operations: readonly BackendOperationDefinition[] = BACKEND_OPERATIONS,
): BackendAuthorizationProfileSourceReadiness {
  const matches = operations.filter(isProfileOperation);
  if (matches.length === 0) {
    return Object.freeze({
      state: "unavailable",
      reason: "no_accepted_backend_authorization_profile_operation",
      operation: null,
    });
  }
  if (matches.length !== 1) throw new Error("Backend authorization profile operation ownership is ambiguous.");
  return Object.freeze({
    state: "ready",
    reason: "accepted_backend_authorization_profile_operation_present",
    operation: matches[0]!,
  });
}

export function createTransportBackedAuthorizationProfileSource(input: {
  readonly readiness: Extract<BackendAuthorizationProfileSourceReadiness, { state: "ready" }>;
  readonly transport: ControlledApiTransport;
}): BackendAuthorizationProfileSourcePort {
  return Object.freeze({
    loadProfile: async ({ principal, correlationId }: { readonly principal: IdentityPrincipal; readonly correlationId: string }) => {
      const response = await input.transport.execute({
        operationKey: input.readiness.operation.key,
        correlationId,
      });
      return decodeBackendAuthorizationProfile(response.data, principal);
    },
  });
}
