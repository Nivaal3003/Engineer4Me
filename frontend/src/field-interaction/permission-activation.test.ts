import { createPermissionActivationProposal } from "./permission-activation";
import { detectReadOnlyPermissionCapabilities } from "./permission-capabilities";
import {
  createReviewedPermissionPolicyEvidence,
  evaluatePermissionPrerequisites,
} from "./permission-policy";
import {
  createUserGestureEvidence,
  evaluateUserGestureEvidence,
} from "./user-gesture";

function acceptedPrerequisites() {
  const windowObject = {};
  return evaluatePermissionPrerequisites({
    permission: "microphone",
    capabilities: detectReadOnlyPermissionCapabilities({
      window: windowObject,
      self: windowObject,
      top: windowObject,
      isSecureContext: true,
      navigator: { mediaDevices: { getUserMedia: () => undefined } },
    }),
    policyEvidence: createReviewedPermissionPolicyEvidence({
      evidenceId: "accepted-policy-fixture",
      source: "scripted_test_fixture",
      microphoneDirective: "allow_self",
      cameraDirective: "allow_self",
      reviewCompleted: true,
    }),
  });
}

describe("permission activation proposal", () => {
  it("remains non-executable even when readiness and gesture evidence pass", () => {
    const gesture = evaluateUserGestureEvidence({
      evidence: createUserGestureEvidence({
        evidenceId: "accepted-gesture-fixture",
        targetId: "microphone-permission-control",
        gestureKind: "button_click",
        occurredAtEpochMs: 10_000,
        trustedEvent: true,
      }),
      expectedTargetId: "microphone-permission-control",
      referenceEpochMs: 11_000,
    });
    expect(createPermissionActivationProposal({
      proposalId: "microphone-activation-proposal",
      permission: "microphone",
      prerequisites: acceptedPrerequisites(),
      gesture,
    })).toMatchObject({
      state: "intervention_required",
      eligibleForControlledPromptAfterGate: true,
      permissionRequestPrepared: false,
      activationAuthorized: false,
      browserPermissionApiCalled: false,
      permissionPromptShown: false,
      rawMediaCaptured: false,
      automaticRetryEnabled: false,
    });
  });

  it("blocks preparation without trusted gesture evidence", () => {
    const gesture = evaluateUserGestureEvidence({
      evidence: null,
      expectedTargetId: "microphone-permission-control",
      referenceEpochMs: 0,
    });
    expect(createPermissionActivationProposal({
      proposalId: "blocked-microphone-proposal",
      permission: "microphone",
      prerequisites: acceptedPrerequisites(),
      gesture,
    })).toMatchObject({
      state: "trusted_user_gesture_required",
      eligibleForControlledPromptAfterGate: false,
      activationAuthorized: false,
    });
  });
});
