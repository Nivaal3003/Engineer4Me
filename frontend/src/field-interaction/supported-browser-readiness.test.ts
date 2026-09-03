import {
  createNoDeploymentPermissionsPolicyHeaderEvidence,
  createReviewedDeploymentPermissionsPolicyHeaderEvidence,
} from "./deployment-header-evidence";
import { detectReadOnlyPermissionCapabilities } from "./permission-capabilities";
import { evaluateSupportedBrowserPermissionReadiness } from "./supported-browser-readiness";

function capableEnvironment() {
  const windowObject = {};
  return {
    window: windowObject,
    self: windowObject,
    top: windowObject,
    isSecureContext: true,
    navigator: { mediaDevices: { getUserMedia: () => undefined } },
  };
}

function reviewed(value: string) {
  return createReviewedDeploymentPermissionsPolicyHeaderEvidence({
    evidenceId: "supported-browser-header-fixture",
    source: "scripted_test_fixture",
    artifactSha256: "b".repeat(64),
    headerName: "Permissions-Policy",
    value,
    reviewCompleted: true,
  });
}

describe("supported-browser permission readiness", () => {
  it("requires deployment header evidence even when capability prerequisites pass", () => {
    expect(evaluateSupportedBrowserPermissionReadiness({
      permission: "microphone",
      capabilities: detectReadOnlyPermissionCapabilities(capableEnvironment()),
      headerEvidence: createNoDeploymentPermissionsPolicyHeaderEvidence(),
    })).toMatchObject({
      state: "deployment_header_evidence_required",
      capabilityRequirementsSatisfied: true,
      candidateForControlledActivationGate: false,
      userAgentRead: false,
      permissionPromptShown: false,
    });
  });

  it("keeps the default-deny deployment profile blocked", () => {
    expect(evaluateSupportedBrowserPermissionReadiness({
      permission: "camera",
      capabilities: detectReadOnlyPermissionCapabilities(capableEnvironment()),
      headerEvidence: reviewed("microphone=(), camera=()"),
    })).toMatchObject({
      state: "deployment_policy_denied",
      deploymentDirective: "deny",
      permissionPromptAuthorized: false,
    });
  });

  it("reaches only an intervention-required candidate with reviewed self-only evidence", () => {
    expect(evaluateSupportedBrowserPermissionReadiness({
      permission: "microphone",
      capabilities: detectReadOnlyPermissionCapabilities(capableEnvironment()),
      headerEvidence: reviewed("microphone=(self), camera=(self)"),
    })).toMatchObject({
      state: "intervention_required",
      reviewedDeploymentHeaderAccepted: true,
      deploymentDirective: "allow_self",
      candidateForControlledActivationGate: true,
      permissionRequestPrepared: false,
      permissionPromptAuthorized: false,
      captureStarted: false,
      networkRequestPerformed: false,
    });
  });

  it("does not bypass secure-context evidence", () => {
    const environment = { ...capableEnvironment(), isSecureContext: false };
    expect(evaluateSupportedBrowserPermissionReadiness({
      permission: "microphone",
      capabilities: detectReadOnlyPermissionCapabilities(environment),
      headerEvidence: reviewed("microphone=(self), camera=(self)"),
    })).toMatchObject({
      state: "secure_context_required",
      candidateForControlledActivationGate: false,
    });
  });
});
