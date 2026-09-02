import { normalizeAccessValues, normalizeBoundedText, normalizeOpaqueIdentifier } from "./values";

export interface OrganisationMembershipInput {
  readonly organisationId: unknown;
  readonly organisationName: unknown;
  readonly roles?: readonly unknown[];
  readonly entitlements?: readonly unknown[];
}

export interface OrganisationMembership {
  readonly organisationId: string;
  readonly organisationName: string;
  readonly roles: readonly string[];
  readonly entitlements: readonly string[];
}

export interface ActiveOrganisationContext extends OrganisationMembership {
  readonly selectedExplicitly: true;
}

export function normalizeOrganisationMemberships(
  values: readonly OrganisationMembershipInput[],
): readonly OrganisationMembership[] {
  if (values.length > 50) throw new Error("Too many organisation memberships.");
  const identifiers = new Set<string>();
  const result = values.map((value): OrganisationMembership => {
    const organisationId = normalizeOpaqueIdentifier(value.organisationId, "Organisation identifier");
    if (identifiers.has(organisationId)) throw new Error("Duplicate organisation membership.");
    identifiers.add(organisationId);
    const organisationName = normalizeBoundedText(value.organisationName, "Organisation name", 160);
    if (!organisationName) throw new Error("Organisation name is required.");
    return Object.freeze({
      organisationId,
      organisationName,
      roles: normalizeAccessValues(value.roles ?? [], "role", 64),
      entitlements: normalizeAccessValues(value.entitlements ?? [], "entitlement", 128),
    });
  });
  return Object.freeze(result.sort((left, right) =>
    left.organisationName.localeCompare(right.organisationName),
  ));
}

export function selectOrganisationContext(
  memberships: readonly OrganisationMembership[],
  organisationId: string,
): ActiveOrganisationContext {
  const selected = memberships.find((membership) => membership.organisationId === organisationId);
  if (!selected) throw new Error("Selected organisation is not an approved membership.");
  return Object.freeze({ ...selected, selectedExplicitly: true });
}
