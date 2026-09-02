import { createBackendAuthorizationProfile } from "./authorization";
import { normalizeIdentityAccount } from "./identity";
import {
  applyBackendAuthorizationProfile,
  beginAuthenticationInitialization,
  createInitialAuthenticationSnapshot,
  establishAuthenticatedIdentity,
  isBackendAuthorizedSession,
  selectAuthenticationOrganisation,
} from "./session";

describe("fail-closed authentication lifecycle", () => {
  it("keeps a valid configuration inactive until an explicit provider operation", () => {
    expect(createInitialAuthenticationSnapshot({
      ready: true,
      missing: [],
      issues: [],
      clientId: "11111111-2222-3333-4444-555555555555",
      authority: "https://example.test/",
      apiScope: "api://example.test/access",
    })).toMatchObject({ phase: "configured_inactive", tokenAttachment: "inactive" });
  });

  it("requires identity, backend authorization, and explicit organisation selection in order", () => {
    const initial = createInitialAuthenticationSnapshot({
      ready: true,
      missing: [],
      issues: [],
      clientId: "11111111-2222-3333-4444-555555555555",
      authority: "https://example.test/",
      apiScope: "api://example.test/access",
    });
    const principal = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
    const identified = establishAuthenticatedIdentity(beginAuthenticationInitialization(initial), principal);
    expect(isBackendAuthorizedSession(identified)).toBe(false);
    const profile = createBackendAuthorizationProfile({
      authority: "backend",
      principalKey: principal.principalKey,
      entitlements: ["engineering.designs.read"],
      organisations: [{ organisationId: "org-1", organisationName: "Plant One" }],
      revision: "profile-1",
    }, principal);
    const authorized = applyBackendAuthorizationProfile(identified, profile);
    expect(isBackendAuthorizedSession(authorized)).toBe(true);
    expect(selectAuthenticationOrganisation(authorized, "org-1").activeOrganisation)
      .toMatchObject({ organisationId: "org-1", selectedExplicitly: true });
  });
});
