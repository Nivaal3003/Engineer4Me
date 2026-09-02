import { createBackendAuthorizationProfile } from "./authorization";
import { normalizeIdentityAccount } from "./identity";

const PRINCIPAL = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });

describe("backend-authoritative authorization profile", () => {
  it("normalizes roles, entitlements, organisations, and explicit administration state", () => {
    expect(createBackendAuthorizationProfile({
      authority: "backend",
      principalKey: PRINCIPAL.principalKey,
      roles: ["Engineer", "engineer"],
      entitlements: ["Engineering.Designs.Read"],
      controlledAdministration: true,
      organisations: [{ organisationId: "org-1", organisationName: "Plant One" }],
      revision: "profile-7",
    }, PRINCIPAL)).toMatchObject({
      authority: "backend",
      roles: ["engineer"],
      entitlements: ["engineering.designs.read"],
      controlledAdministration: true,
      revision: "profile-7",
    });
  });

  it("rejects a profile not owned by the authenticated principal", () => {
    expect(() => createBackendAuthorizationProfile({
      authority: "backend",
      principalKey: "tenant-1:other",
      revision: "profile-1",
    }, PRINCIPAL)).toThrow(/ownership differs/u);
  });
});
