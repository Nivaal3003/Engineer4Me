import { evaluateAuthenticationConfiguration } from "./config";

const VALID_CONFIGURATION = {
  VITE_ENTRA_CLIENT_ID: "11111111-2222-3333-4444-555555555555",
  VITE_ENTRA_AUTHORITY: "https://engineer4me.ciamlogin.com/",
  VITE_ENTRA_API_SCOPE: "api://11111111-2222-3333-4444-555555555555/access_as_user",
} as const;

describe("controlled authentication configuration", () => {
  it("reports only setting names and safe issue codes when values are absent", () => {
    const readiness = evaluateAuthenticationConfiguration({});
    expect(readiness).toMatchObject({ ready: false });
    if (readiness.ready) throw new Error("Expected blocked readiness.");
    expect(readiness.missing).toEqual([
      "VITE_ENTRA_CLIENT_ID",
      "VITE_ENTRA_AUTHORITY",
      "VITE_ENTRA_API_SCOPE",
    ]);
    expect(JSON.stringify(readiness)).not.toContain("undefined");
  });

  it("rejects malformed identifiers, non-HTTPS authorities, and unsafe scopes", () => {
    const readiness = evaluateAuthenticationConfiguration({
      VITE_ENTRA_CLIENT_ID: "not-a-client-id",
      VITE_ENTRA_AUTHORITY: "http://localhost/tenant",
      VITE_ENTRA_API_SCOPE: "api://example.test/scope with space",
    });
    expect(readiness).toMatchObject({ ready: false });
    if (readiness.ready) throw new Error("Expected invalid readiness.");
    expect(readiness.issues.map((issue) => issue.code)).toEqual([
      "invalid_client_id",
      "invalid_authority",
      "invalid_api_scope",
    ]);
  });

  it("normalizes an exact valid public configuration without activating MSAL", () => {
    expect(evaluateAuthenticationConfiguration(VALID_CONFIGURATION)).toEqual({
      ready: true,
      missing: [],
      issues: [],
      clientId: VALID_CONFIGURATION.VITE_ENTRA_CLIENT_ID,
      authority: VALID_CONFIGURATION.VITE_ENTRA_AUTHORITY,
      apiScope: VALID_CONFIGURATION.VITE_ENTRA_API_SCOPE,
    });
  });
});
