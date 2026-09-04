import { createAcceptedMicrophonePermissionActivationEvidence } from "./microphone-permission-activation-evidence";
import { createUnrecordedMicrophonePermissionConsent } from "./permission-consent-evidence";
import { evaluateMicrophonePermissionConsent } from "./permission-consent-policy";
import { createMicrophonePermissionPromptExecutionPlan } from "./permission-prompt-execution-plan";
import { createMicrophonePermissionPromptProposal } from "./permission-prompt-proposal";
import { evaluateUserGestureEvidence } from "./user-gesture";

describe("microphone permission prompt execution plan", () => {
  it("describes a future one-prompt gate without exposing an operation", () => {
    const proposal = createMicrophonePermissionPromptProposal({
      proposalId: "microphone-prompt-proposal-003",
      capabilityEvidence: createAcceptedMicrophonePermissionActivationEvidence(),
      consent: evaluateMicrophonePermissionConsent({
        evidence: createUnrecordedMicrophonePermissionConsent(),
        referenceEpochMs: 10_000,
      }),
      gesture: evaluateUserGestureEvidence({
        evidence: null,
        expectedTargetId: "microphone-permission-control",
        referenceEpochMs: 10_000,
      }),
    });
    const plan = createMicrophonePermissionPromptExecutionPlan(proposal);
    expect(plan.state).toBe("evidence_incomplete");
    expect(plan.exactPromptCountMaximum).toBe(1);
    expect(plan.promptExecutionOperationAvailable).toBe(false);
    expect(plan.executionAuthorized).toBe(false);
    expect(plan.cameraPermissionIncluded).toBe(false);
    expect(plan.captureIncluded).toBe(false);
    expect(plan.automaticRetryAllowed).toBe(false);
  });
});
