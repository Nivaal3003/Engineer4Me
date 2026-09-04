import { validateFieldInteractionIdentifier } from "./models";
import { evaluateImmediateTrackTermination } from "./immediate-track-termination-evidence";

export const CONTROLLED_MICROPHONE_PERMISSION_OUTCOMES = [
  "granted_tracks_stopped",
  "not_allowed_or_dismissed",
  "no_matching_source",
  "source_unreadable",
  "request_aborted",
  "security_or_api_unavailable",
  "constraints_rejected",
] as const;

export type ControlledMicrophonePermissionOutcome =
  (typeof CONTROLLED_MICROPHONE_PERMISSION_OUTCOMES)[number];

export interface ControlledMicrophonePermissionOutcomeEvidence {
  readonly evidenceId: string;
  readonly source: "user_run_loopback_verifier";
  readonly permission: "microphone";
  readonly outcome: ControlledMicrophonePermissionOutcome;
  readonly getUserMediaCallCount: 1;
  readonly explicitConsentRecorded: true;
  readonly trustedClickRecorded: true;
  readonly mediaStreamReturned: boolean;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
  readonly immediateTrackTerminationAccepted: boolean;
  readonly browserMayHaveBrieflyActivatedMicrophone: boolean;
  readonly permissionPromptDisplayState: "not_observable";
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly deviceIdentifierReadPerformed: false;
  readonly audioElementAttachmentPerformed: false;
  readonly audioContextCreated: false;
  readonly mediaRecorderCreated: false;
  readonly audioSampleReadPerformed: false;
  readonly rawMediaPersisted: false;
  readonly mediaTransmitted: false;
  readonly automaticRetryPerformed: false;
  readonly captureAuthorizationDerived: false;
  readonly furtherCaptureGateRequired: true;
}

export function createControlledMicrophonePermissionOutcomeEvidence(input: {
  readonly evidenceId: string;
  readonly outcome: ControlledMicrophonePermissionOutcome;
  readonly getUserMediaCallCount: number;
  readonly explicitConsentRecorded: boolean;
  readonly trustedClickRecorded: boolean;
  readonly mediaStreamReturned: boolean;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
}): ControlledMicrophonePermissionOutcomeEvidence {
  if (input.getUserMediaCallCount !== 1) {
    throw new Error("Controlled microphone permission evidence must represent exactly one request call.");
  }
  if (!input.explicitConsentRecorded || !input.trustedClickRecorded) {
    throw new Error("Controlled microphone permission evidence requires explicit consent and a trusted click.");
  }
  const termination = evaluateImmediateTrackTermination({
    mediaStreamReturned: input.mediaStreamReturned,
    returnedTrackCount: input.returnedTrackCount,
    trackStopCallCount: input.trackStopCallCount,
    allReturnedTracksEnded: input.allReturnedTracksEnded,
  });
  const granted = input.outcome === "granted_tracks_stopped";
  if (granted !== input.mediaStreamReturned) {
    throw new Error("Permission outcome and stream-return evidence differ.");
  }
  if (!termination.immediateTerminationAccepted) {
    throw new Error(termination.blockingReasons.join(" "));
  }
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Controlled microphone permission outcome evidence identifier",
    ),
    source: "user_run_loopback_verifier",
    permission: "microphone",
    outcome: input.outcome,
    getUserMediaCallCount: 1,
    explicitConsentRecorded: true,
    trustedClickRecorded: true,
    mediaStreamReturned: input.mediaStreamReturned,
    returnedTrackCount: input.returnedTrackCount,
    trackStopCallCount: input.trackStopCallCount,
    allReturnedTracksEnded: input.allReturnedTracksEnded,
    immediateTrackTerminationAccepted: true,
    browserMayHaveBrieflyActivatedMicrophone: granted,
    permissionPromptDisplayState: "not_observable",
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    mediaDeviceEnumerationPerformed: false,
    deviceIdentifierReadPerformed: false,
    audioElementAttachmentPerformed: false,
    audioContextCreated: false,
    mediaRecorderCreated: false,
    audioSampleReadPerformed: false,
    rawMediaPersisted: false,
    mediaTransmitted: false,
    automaticRetryPerformed: false,
    captureAuthorizationDerived: false,
    furtherCaptureGateRequired: true,
  });
}
