import { validateFieldInteractionIdentifier } from "./models";
import type { MicrophonePermissionActivationEvidence } from "./microphone-permission-activation-evidence";
import type { PermissionConsentEvaluation } from "./permission-consent-policy";
import type { UserGestureEvaluation } from "./user-gesture";

export type MicrophonePermissionPromptProposalState =
  | "capability_evidence_blocked"
  | "consent_required"
  | "trusted_user_gesture_required"
  | "intervention_required";

export interface MicrophonePermissionPromptProposal {
  readonly proposalId: string;
  readonly permission: "microphone";
  readonly state: MicrophonePermissionPromptProposalState;
  readonly acceptedCapabilityEvidenceBound: boolean;
  readonly consentEvidenceAccepted: boolean;
  readonly trustedUserGestureEvidenceAccepted: boolean;
  readonly eligibleForPromptExecutionIntervention: boolean;
  readonly explicitConsentRequired: true;
  readonly singleUseGestureRequired: true;
  readonly promptExecutionInterventionRequired: true;
  readonly permissionRequestPrepared: false;
  readonly permissionPromptAuthorized: false;
  readonly browserPermissionApiCalled: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly automaticRetryEnabled: false;
  readonly blockingReasons: readonly string[];
}

function acceptedCapabilityEvidence(
  evidence: MicrophonePermissionActivationEvidence,
): boolean {
  return evidence.observationAccepted
    && evidence.secureContextObserved
    && evidence.topLevelContextObserved
    && evidence.mediaDevicesObjectPresent
    && evidence.getUserMediaPropertyPresent
    && evidence.permissionsPolicySurfacePresent
    && evidence.propertyPresenceEvidenceOnly
    && !evidence.permissionStateKnown
    && !evidence.permissionStatusQueried
    && !evidence.permissionsPolicyMethodCalled
    && !evidence.browserPermissionApiCalled
    && !evidence.permissionPromptShown
    && !evidence.mediaDeviceEnumerationPerformed
    && !evidence.captureStarted;
}

export function createMicrophonePermissionPromptProposal(input: {
  readonly proposalId: string;
  readonly capabilityEvidence: MicrophonePermissionActivationEvidence;
  readonly consent: PermissionConsentEvaluation;
  readonly gesture: UserGestureEvaluation;
}): MicrophonePermissionPromptProposal {
  const capabilityEvidenceBound = acceptedCapabilityEvidence(input.capabilityEvidence);
  const consentEvidenceAccepted = input.consent.acceptedForFuturePromptGate;
  const trustedUserGestureEvidenceAccepted = input.gesture.acceptedForFuturePromptPreparation;
  const blockingReasons: string[] = [];
  let state: MicrophonePermissionPromptProposalState;

  if (!capabilityEvidenceBound) {
    state = "capability_evidence_blocked";
    blockingReasons.push("Accepted read-only browser capability evidence is absent or inconsistent.");
  } else if (!consentEvidenceAccepted) {
    state = "consent_required";
    blockingReasons.push(...input.consent.blockingReasons);
  } else if (!trustedUserGestureEvidenceAccepted) {
    state = "trusted_user_gesture_required";
    blockingReasons.push(...input.gesture.blockingReasons);
  } else {
    state = "intervention_required";
    blockingReasons.push("A separate user-run gate is required before one browser permission prompt may be executed.");
  }

  return Object.freeze({
    proposalId: validateFieldInteractionIdentifier(
      input.proposalId,
      "Microphone permission prompt proposal identifier",
    ),
    permission: "microphone",
    state,
    acceptedCapabilityEvidenceBound: capabilityEvidenceBound,
    consentEvidenceAccepted,
    trustedUserGestureEvidenceAccepted,
    eligibleForPromptExecutionIntervention:
      capabilityEvidenceBound
      && consentEvidenceAccepted
      && trustedUserGestureEvidenceAccepted,
    explicitConsentRequired: true,
    singleUseGestureRequired: true,
    promptExecutionInterventionRequired: true,
    permissionRequestPrepared: false,
    permissionPromptAuthorized: false,
    browserPermissionApiCalled: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    automaticRetryEnabled: false,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
