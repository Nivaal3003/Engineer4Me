import { createAcceptedMicrophonePermissionActivationEvidence } from "./microphone-permission-activation-evidence";
import {
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
  MICROPHONE_PERMISSION_PURPOSE,
  createImportedMicrophonePermissionConsent,
  createUnrecordedMicrophonePermissionConsent,
} from "./permission-consent-evidence";
import { evaluateMicrophonePermissionConsent } from "./permission-consent-policy";
import { createMicrophonePermissionPromptProposal } from "./permission-prompt-proposal";
import { createUserGestureEvidence, evaluateUserGestureEvidence } from "./user-gesture";

describe("microphone permission prompt proposal", () => {
  it("requires consent before it can reach the intervention state", () => {
    const proposal = createMicrophonePermissionPromptProposal({
      proposalId: "microphone-prompt-proposal-001",
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
    expect(proposal.state).toBe("consent_required");
    expect(proposal.permissionPromptAuthorized).toBe(false);
    expect(proposal.permissionPromptShown).toBe(false);
  });

  it("retains a separate intervention gate after consent and gesture evidence", () => {
    const consent = createImportedMicrophonePermissionConsent({
      evidenceId: "consent-evidence-004",
      disclosureVersion: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
      disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
      purpose: MICROPHONE_PERMISSION_PURPOSE,
      decision: "affirmative",
      occurredAtEpochMs: 9_000,
      explicit: true,
      userInitiated: true,
    });
    const gesture = createUserGestureEvidence({
      evidenceId: "gesture-evidence-001",
      targetId: "microphone-permission-control",
      gestureKind: "button_click",
      occurredAtEpochMs: 9_900,
      trustedEvent: true,
    });
    const proposal = createMicrophonePermissionPromptProposal({
      proposalId: "microphone-prompt-proposal-002",
      capabilityEvidence: createAcceptedMicrophonePermissionActivationEvidence(),
      consent: evaluateMicrophonePermissionConsent({ evidence: consent, referenceEpochMs: 10_000 }),
      gesture: evaluateUserGestureEvidence({
        evidence: gesture,
        expectedTargetId: "microphone-permission-control",
        referenceEpochMs: 10_000,
      }),
    });
    expect(proposal.state).toBe("intervention_required");
    expect(proposal.eligibleForPromptExecutionIntervention).toBe(true);
    expect(proposal.permissionRequestPrepared).toBe(false);
    expect(proposal.permissionPromptAuthorized).toBe(false);
  });
});
