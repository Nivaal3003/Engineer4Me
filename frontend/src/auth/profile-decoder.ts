import { createBackendAuthorizationProfile, type BackendAuthorizationProfile } from "./authorization";
import type { IdentityPrincipal } from "./identity";
import type { OrganisationMembershipInput } from "./organisation";

const TOP_LEVEL_KEYS = new Set([
  "authority",
  "principalKey",
  "roles",
  "entitlements",
  "controlledAdministration",
  "organisations",
  "revision",
]);
const ORGANISATION_KEYS = new Set(["organisationId", "organisationName", "roles", "entitlements"]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>, label: string): void {
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length > 0) throw new Error(`${label} contains an unexpected field.`);
}

function unknownArray(value: unknown, label: string, maximum: number): readonly unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`${label} is not a bounded array.`);
  return value;
}

export function decodeBackendAuthorizationProfile(
  value: unknown,
  principal: IdentityPrincipal,
): BackendAuthorizationProfile {
  const input = record(value, "Backend authorization profile");
  exactKeys(input, TOP_LEVEL_KEYS, "Backend authorization profile");
  const organisations = unknownArray(input.organisations, "Organisation memberships", 50).map((item) => {
    const membership = record(item, "Organisation membership");
    exactKeys(membership, ORGANISATION_KEYS, "Organisation membership");
    return {
      organisationId: membership.organisationId,
      organisationName: membership.organisationName,
      roles: unknownArray(membership.roles, "Organisation roles", 128),
      entitlements: unknownArray(membership.entitlements, "Organisation entitlements", 256),
    } satisfies OrganisationMembershipInput;
  });
  return createBackendAuthorizationProfile({
    authority: input.authority as "backend",
    principalKey: input.principalKey,
    roles: unknownArray(input.roles, "Roles", 128),
    entitlements: unknownArray(input.entitlements, "Entitlements", 256),
    controlledAdministration: input.controlledAdministration === true,
    organisations,
    revision: input.revision,
  }, principal);
}
