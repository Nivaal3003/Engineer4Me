import {
  applyBackendAuthorizationProfile,
  beginAuthenticationInitialization,
  createBackendAuthorizationProfile,
  createInitialAuthenticationSnapshot,
  establishAuthenticatedIdentity,
  normalizeIdentityAccount,
  selectAuthenticationOrganisation,
} from "../auth";
import { createRouteAccessContext } from "./authentication-context";

const READINESS = {
  ready: true,
  missing: [],
  issues: [],
  clientId: "11111111-2222-3333-4444-555555555555",
  authority: "https://example.test/",
  apiScope: "api://example.test/access",
} as const;

describe("authentication-to-route access projection", () => {
  it("projects inactive access before backend authorization is established", () => {
    expect(createRouteAccessContext(createInitialAuthenticationSnapshot(READINESS)))
      .toMatchObject({ authentication: "inactive", controlledAdministration: false });
  });

  it("combines backend and explicitly selected organisation entitlements", () => {
    const principal = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
    const identified = establishAuthenticatedIdentity(
      beginAuthenticationInitialization(createInitialAuthenticationSnapshot(READINESS)),
      principal,
    );
    const profile = createBackendAuthorizationProfile({
      authority: "backend",
      principalKey: principal.principalKey,
      entitlements: ["engineering.designs.read"],
      organisations: [{
        organisationId: "org-1",
        organisationName: "Plant One",
        entitlements: ["engineering.projects.read"],
      }],
      controlledAdministration: false,
      revision: "profile-1",
    }, principal);
    const selected = selectAuthenticationOrganisation(
      applyBackendAuthorizationProfile(identified, profile),
      "org-1",
    );
    const context = createRouteAccessContext(selected);
    expect(context.authentication).toBe("authenticated");
    expect([...context.entitlements]).toEqual([
      "engineering.designs.read",
      "engineering.projects.read",
    ]);
  });
});
