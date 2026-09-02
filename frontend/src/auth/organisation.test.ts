import { normalizeOrganisationMemberships, selectOrganisationContext } from "./organisation";

describe("organisation membership context", () => {
  it("normalizes backend-provided memberships and requires explicit selection", () => {
    const memberships = normalizeOrganisationMemberships([
      { organisationId: "org-2", organisationName: "Zulu Plant", roles: ["Engineer"] },
      { organisationId: "org-1", organisationName: "Alpha Plant", entitlements: ["engineering.designs.read"] },
    ]);
    expect(memberships.map((item) => item.organisationId)).toEqual(["org-1", "org-2"]);
    expect(selectOrganisationContext(memberships, "org-1")).toMatchObject({
      organisationName: "Alpha Plant",
      selectedExplicitly: true,
    });
  });

  it("rejects duplicate memberships and unapproved selections", () => {
    expect(() => normalizeOrganisationMemberships([
      { organisationId: "org-1", organisationName: "One" },
      { organisationId: "org-1", organisationName: "Duplicate" },
    ])).toThrow(/Duplicate/u);
    expect(() => selectOrganisationContext([], "org-1")).toThrow(/not an approved membership/u);
  });
});
