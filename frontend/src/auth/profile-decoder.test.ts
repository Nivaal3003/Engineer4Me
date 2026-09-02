import { normalizeIdentityAccount } from "./identity";
import { decodeBackendAuthorizationProfile } from "./profile-decoder";

const PRINCIPAL = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });

describe("backend authorization profile decoder", () => {
  it("accepts only an exact backend-owned profile for the active principal", () => {
    expect(decodeBackendAuthorizationProfile({
      authority: "backend",
      principalKey: PRINCIPAL.principalKey,
      revision: "profile-1",
      roles: ["engineer"],
      entitlements: ["engineering.designs.read"],
      controlledAdministration: false,
      organisations: [{ organisationId: "org-1", organisationName: "Plant One" }],
    }, PRINCIPAL)).toMatchObject({ authority: "backend", principalKey: PRINCIPAL.principalKey, revision: "profile-1" });
  });

  it("rejects unexpected fields, foreign principal ownership, and malformed memberships", () => {
    expect(() => decodeBackendAuthorizationProfile({
      authority: "backend",
      principalKey: PRINCIPAL.principalKey,
      revision: "profile-1",
      accessToken: "secret",
    }, PRINCIPAL)).toThrow(/unexpected/u);
    expect(() => decodeBackendAuthorizationProfile({
      authority: "backend",
      principalKey: "foreign",
      revision: "profile-1",
    }, PRINCIPAL)).toThrow(/ownership/u);
  });
});
