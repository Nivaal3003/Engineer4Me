import type { IdentityPrincipal } from "./identity";
import {
  normalizeOrganisationMemberships,
  type OrganisationMembership,
  type OrganisationMembershipInput,
} from "./organisation";
import { normalizeAccessValues } from "./values";

export interface BackendAuthorizationProfileInput {
  readonly authority: "backend";
  readonly principalKey: unknown;
  readonly roles?: readonly unknown[];
  readonly entitlements?: readonly unknown[];
  readonly controlledAdministration?: boolean;
  readonly organisations?: readonly OrganisationMembershipInput[];
  readonly revision: unknown;
}

export interface BackendAuthorizationProfile {
  readonly authority: "backend";
  readonly principalKey: string;
  readonly roles: readonly string[];
  readonly entitlements: readonly string[];
  readonly controlledAdministration: boolean;
  readonly organisations: readonly OrganisationMembership[];
  readonly revision: string;
}

export function createBackendAuthorizationProfile(
  input: BackendAuthorizationProfileInput,
  principal: IdentityPrincipal,
): BackendAuthorizationProfile {
  if (input.authority !== "backend") {
    throw new Error("Authorization profile authority must be the backend.");
  }
  if (input.principalKey !== principal.principalKey) {
    throw new Error("Authorization profile principal ownership differs.");
  }
  if (typeof input.revision !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(input.revision)) {
    throw new Error("Authorization profile revision is invalid.");
  }
  return Object.freeze({
    authority: "backend",
    principalKey: principal.principalKey,
    roles: normalizeAccessValues(input.roles ?? [], "role", 128),
    entitlements: normalizeAccessValues(input.entitlements ?? [], "entitlement", 256),
    controlledAdministration: input.controlledAdministration === true,
    organisations: normalizeOrganisationMemberships(input.organisations ?? []),
    revision: input.revision,
  });
}
