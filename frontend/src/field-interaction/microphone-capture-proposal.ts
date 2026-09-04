import type { ImportedControlledMicrophonePermissionOutcome } from "./controlled-microphone-permission-import";
import type {
  MicrophoneCaptureConsentEvaluation,
  MicrophoneCaptureConsentEvidence,
} from "./microphone-capture-consent";
import { evaluateMicrophoneCaptureConsent } from "./microphone-capture-consent";
import type { MicrophoneCapturePolicy } from "./microphone-capture-policy";

export type MicrophoneCaptureProposalState =
  | "parent_outcome_unaccepted"
  | "capture_specific_consent_required"
  | "trusted_start_gesture_required"
  | "intervention_required";

export interface MicrophoneCaptureStartGestureEvidence {
  readonly trusted: boolean;
  readonly singleUse: boolean;
  readonly target: "start_bounded_microphone_source_session";
  readonly recordedAtUnixMs: number | null;
  readonly maximumAgeMilliseconds: 5_000;
}

export interface MicrophoneCaptureProposal {
  readonly proposalType: "bounded_no_persistence_microphone_source_session";
  readonly state: MicrophoneCaptureProposalState;
  readonly importedPermissionOutcomeAccepted: boolean;
  readonly currentPermissionStateInferred: false;
  readonly captureAuthorizationDerivedFromPermissionOutcome: false;
  readonly captureSpecificConsent: MicrophoneCaptureConsentEvaluation;
  readonly trustedStartGestureAccepted: boolean;
  readonly sourceSessionMaximumMilliseconds: 3000;
  readonly executionInterventionRequired: true;
  readonly executionAuthorized: false;
  readonly applicationOperationAvailable: false;
  readonly blockingReasons: readonly string[];
}

function evaluateTrustedStartGesture(
  evidence: MicrophoneCaptureStartGestureEvidence | null,
  nowUnixMs: number,
): boolean {
  return (
    evidence !== null &&
    evidence.trusted &&
    evidence.singleUse &&
    evidence.target === "start_bounded_microphone_source_session" &&
    evidence.maximumAgeMilliseconds === 5_000 &&
    evidence.recordedAtUnixMs !== null &&
    Number.isSafeInteger(evidence.recordedAtUnixMs) &&
    evidence.recordedAtUnixMs >= 0 &&
    nowUnixMs >= evidence.recordedAtUnixMs &&
    nowUnixMs - evidence.recordedAtUnixMs <= evidence.maximumAgeMilliseconds
  );
}

export function createMicrophoneCaptureProposal(input: {
  readonly importedOutcome: ImportedControlledMicrophonePermissionOutcome;
  readonly consent: MicrophoneCaptureConsentEvidence;
  readonly trustedStartGesture: MicrophoneCaptureStartGestureEvidence | null;
  readonly policy: MicrophoneCapturePolicy;
  readonly nowUnixMs: number;
}): MicrophoneCaptureProposal {
  const importedPermissionOutcomeAccepted =
    input.importedOutcome.outcome === "granted_tracks_stopped" &&
    input.importedOutcome.exactGetUserMediaCallCount === 1 &&
    input.importedOutcome.immediateTrackTerminationAccepted &&
    !input.importedOutcome.captureAuthorizationDerived &&
    input.importedOutcome.furtherCaptureGateRequired;
  const captureSpecificConsent = evaluateMicrophoneCaptureConsent(
    input.consent,
    input.nowUnixMs,
  );
  const trustedStartGestureAccepted = evaluateTrustedStartGesture(
    input.trustedStartGesture,
    input.nowUnixMs,
  );
  const blockingReasons: string[] = [];

  if (!importedPermissionOutcomeAccepted) {
    blockingReasons.push("Accepted granted-and-stopped parent evidence is required.");
  }
  blockingReasons.push(...captureSpecificConsent.blockingReasons);
  if (!trustedStartGestureAccepted) {
    blockingReasons.push("A fresh trusted single-use capture-start gesture is required.");
  }
  if (input.policy.maximumSourceSessionMilliseconds !== 3_000) {
    blockingReasons.push("The microphone source-session ceiling differs.");
  }
  if (input.policy.applicationOperationAvailable) {
    blockingReasons.push("The application capture operation must remain unavailable.");
  }
  if (input.policy.captureExecutionAuthorized) {
    blockingReasons.push("Capture execution must remain unauthorized in this proposal batch.");
  }

  let state: MicrophoneCaptureProposalState;
  if (!importedPermissionOutcomeAccepted) {
    state = "parent_outcome_unaccepted";
  } else if (!captureSpecificConsent.accepted) {
    state = "capture_specific_consent_required";
  } else if (!trustedStartGestureAccepted) {
    state = "trusted_start_gesture_required";
  } else {
    state = "intervention_required";
  }

  return Object.freeze({
    proposalType: "bounded_no_persistence_microphone_source_session",
    state,
    importedPermissionOutcomeAccepted,
    currentPermissionStateInferred: false,
    captureAuthorizationDerivedFromPermissionOutcome: false,
    captureSpecificConsent,
    trustedStartGestureAccepted,
    sourceSessionMaximumMilliseconds: 3000,
    executionInterventionRequired: true,
    executionAuthorized: false,
    applicationOperationAvailable: false,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
