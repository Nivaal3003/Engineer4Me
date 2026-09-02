import { evaluateAuthenticationConfiguration } from "./config";
import {
  evaluateAuthenticationActivationReadiness,
  NO_AUTHENTICATION_ACTIVATION_EVIDENCE,
} from "./activation-readiness";
import { createAuthenticationRedirectPolicy } from "./redirect-policy";

const CONFIGURATION = evaluateAuthenticationConfiguration({
  VITE_ENTRA_CLIENT_ID: "11111111-2222-3333-4444-555555555555",
  VITE_ENTRA_AUTHORITY: "https://engineer4me.ciamlogin.com/",
  VITE_ENTRA_API_SCOPE: "api://11111111-2222-3333-4444-555555555555/access_as_user",
});
const POLICY = createAuthenticationRedirectPolicy({
  applicationOrigin: "https://engineer4me.example/",
  allowedReturnPaths: ["/", "/selection"],
});

describe("authentication activation readiness", () => {
  it("keeps execution blocked without external registration, consent, and deployment evidence", () => {
    const readiness = evaluateAuthenticationActivationReadiness({
      configuration: CONFIGURATION,
      redirectPolicy: POLICY,
      evidence: NO_AUTHENTICATION_ACTIVATION_EVIDENCE,
    });
    expect(readiness.sourceReady).toBe(true);
    expect(readiness.interactiveExecutionReady).toBe(false);
    expect(readiness.missingGates).toContain("delegated_api_permission_consent_proven");
    expect(JSON.stringify(readiness)).not.toContain("11111111-2222-3333-4444-555555555555");
  });

  it("requires every reviewed gate before reporting execution readiness", () => {
    const readiness = evaluateAuthenticationActivationReadiness({
      configuration: CONFIGURATION,
      redirectPolicy: POLICY,
      evidence: {
        applicationRegistrationReviewed: true,
        redirectUriRegistrationProven: true,
        delegatedApiPermissionConsentProven: true,
        callingClientAssociationProven: true,
        externalIdUserFlowAssociationProven: true,
        historyFallbackProven: true,
        supportedDeploymentEnvironmentProven: true,
      },
    });
    expect(readiness).toMatchObject({ interactiveExecutionReady: true, missingGates: [] });
  });
});
