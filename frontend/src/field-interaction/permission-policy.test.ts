import { detectReadOnlyPermissionCapabilities } from "./permission-capabilities";
import {
  createNoPermissionPolicyEvidence,
  createReviewedPermissionPolicyEvidence,
  evaluatePermissionPrerequisites,
} from "./permission-policy";

function capableEnvironment() {
  const windowObject = {};
  return {
    window: windowObject,
    self: windowObject,
    top: windowObject,
    isSecureContext: true,
    navigator: {
      mediaDevices: { getUserMedia: () => undefined },
      permissions: { query: () => undefined },
    },
  };
}

describe("permission prerequisite policy", () => {
  it("requires reviewed deployment evidence without querying permission status", () => {
    const evaluation = evaluatePermissionPrerequisites({
      permission: "microphone",
      capabilities: detectReadOnlyPermissionCapabilities(capableEnvironment()),
      policyEvidence: createNoPermissionPolicyEvidence(),
    });
    expect(evaluation).toMatchObject({
      state: "permission_policy_evidence_required",
      policyEvidenceAccepted: false,
      eligibleForInterventionGate: false,
      browserPermissionApiCalled: false,
      permissionStatusQueried: false,
      permissionPromptAuthorized: false,
    });
  });

  it("reaches only the intervention gate after all prerequisites are reviewed", () => {
    const evaluation = evaluatePermissionPrerequisites({
      permission: "camera",
      capabilities: detectReadOnlyPermissionCapabilities(capableEnvironment()),
      policyEvidence: createReviewedPermissionPolicyEvidence({
        evidenceId: "scripted-policy-evidence",
        source: "scripted_test_fixture",
        microphoneDirective: "allow_self",
        cameraDirective: "allow_self",
        reviewCompleted: true,
      }),
    });
    expect(evaluation).toMatchObject({
      state: "intervention_required",
      eligibleForInterventionGate: true,
      permissionPromptAuthorized: false,
      permissionPromptShown: false,
    });
  });
});
