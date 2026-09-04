import type { ControlledMicrophonePermissionPolicy } from "./controlled-microphone-permission-policy";
import type { ControlledMicrophonePermissionOutcomeEvidence } from "./controlled-microphone-permission-outcome";

export interface ControlledMicrophonePermissionReceipt {
  readonly receiptType: "controlled_microphone_permission_request";
  readonly state: "accepted";
  readonly permission: "microphone";
  readonly outcome: ControlledMicrophonePermissionOutcomeEvidence["outcome"];
  readonly exactRequestCallCount: 1;
  readonly consentAndTrustedGestureAccepted: true;
  readonly temporarySelfOnlyPermissionsPolicyAccepted: true;
  readonly immediateTrackTerminationAccepted: true;
  readonly noPermissionStatusQueryAccepted: true;
  readonly noDeviceEnumerationAccepted: true;
  readonly noAudioUseAccepted: true;
  readonly noPersistenceOrTransmissionAccepted: true;
  readonly captureAuthorized: false;
  readonly furtherCaptureGateRequired: true;
  readonly blockingReasons: readonly string[];
}

export function createControlledMicrophonePermissionReceipt(input: {
  readonly policy: ControlledMicrophonePermissionPolicy;
  readonly outcome: ControlledMicrophonePermissionOutcomeEvidence;
}): ControlledMicrophonePermissionReceipt {
  if (input.policy.applicationOperationAvailable) {
    throw new Error("The application permission-request operation must remain unavailable.");
  }
  if (input.policy.exactGetUserMediaCallMaximum !== 1) {
    throw new Error("The controlled request-call maximum differs.");
  }
  if (input.policy.temporaryPermissionsPolicy !== "microphone=(self), camera=()") {
    throw new Error("The temporary Permissions-Policy value differs.");
  }
  if (!input.outcome.immediateTrackTerminationAccepted) {
    throw new Error("Immediate track-termination evidence is not accepted.");
  }
  return Object.freeze({
    receiptType: "controlled_microphone_permission_request",
    state: "accepted",
    permission: "microphone",
    outcome: input.outcome.outcome,
    exactRequestCallCount: 1,
    consentAndTrustedGestureAccepted: true,
    temporarySelfOnlyPermissionsPolicyAccepted: true,
    immediateTrackTerminationAccepted: true,
    noPermissionStatusQueryAccepted: true,
    noDeviceEnumerationAccepted: true,
    noAudioUseAccepted: true,
    noPersistenceOrTransmissionAccepted: true,
    captureAuthorized: false,
    furtherCaptureGateRequired: true,
    blockingReasons: Object.freeze([]),
  });
}
