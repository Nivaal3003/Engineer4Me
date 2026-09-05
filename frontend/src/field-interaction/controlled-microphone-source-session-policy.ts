export const CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_VERSION =
  "phase10-controlled-microphone-source-session-consent-v2";
export const CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE =
  "Engineer4Me will start one microphone-only source session only after you select the consent checkbox and activate the reviewed control. If browser access is available, the microphone may remain active for no more than three seconds; a user stop control will be available, an automatic safety stop is scheduled before the three-second ceiling, and an independent verifier watchdog will close the temporary browser if completion is not observed within the bounded source-session interval. Every returned track will be stopped during normal completion. Engineer4Me will not attach the stream to an audio element, create an AudioContext, MediaRecorder, or AudioWorklet, read, play, analyze, or record audio samples, persist raw media, transmit media, call a backend, access protected content, or invoke external AI. Camera access, permission-status queries, device enumeration, automatic retry, authentication, native packaging, header deployment, and production deployment remain disabled. The outcome does not authorize later audio-sample access or voice processing.";
export const CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_SHA256 =
  "a0285cd4ead3193bc69570cfc205fef2cc5d946a0ec1232a2e803428c6ef6bcc";
export const CONTROLLED_MICROPHONE_SOURCE_SESSION_MAXIMUM_MS = 3_000;
export const CONTROLLED_MICROPHONE_SOURCE_SESSION_SAFETY_STOP_MS = 2_000;
export const CONTROLLED_MICROPHONE_SOURCE_SESSION_HARD_CEILING_WATCHDOG_MS = 2_500;

export interface ControlledMicrophoneSourceSessionPolicy {
  readonly operationScope: "user_run_loopback_verifier";
  readonly mediaScope: "microphone_only";
  readonly exactGetUserMediaCallMaximum: 1;
  readonly maximumSourceSessionMilliseconds: 3000;
  readonly automaticSafetyStopMilliseconds: 2000;
  readonly hardCeilingWatchdogMilliseconds: 2500;
  readonly sourceSessionStartedReceiptRequired: true;
  readonly independentProcessWatchdogRequired: true;
  readonly hardCeilingWatchdogClosesBrowser: true;
  readonly userEarlyStopControlRequired: true;
  readonly everyReturnedTrackStopRequired: true;
  readonly explicitCaptureSpecificConsentRequired: true;
  readonly trustedSingleUseStartGestureRequired: true;
  readonly temporaryPermissionsPolicy: "microphone=(self), camera=()";
  readonly permissionPromptDisplayState: "not_observable";
  readonly automaticRetryAllowed: false;
  readonly permissionStatusQueryAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly deviceIdentifierReadAllowed: false;
  readonly cameraRequestAllowed: false;
  readonly audioElementAttachmentAllowed: false;
  readonly audioContextCreationAllowed: false;
  readonly mediaRecorderCreationAllowed: false;
  readonly audioWorkletCreationAllowed: false;
  readonly audioSampleReadAllowed: false;
  readonly audioPlaybackAllowed: false;
  readonly audioAnalysisAllowed: false;
  readonly recordingCreationAllowed: false;
  readonly rawMediaPersistenceAllowed: false;
  readonly mediaTransmissionAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly externalAiAllowed: false;
  readonly applicationOperationAvailable: false;
  readonly furtherAudioSampleGateRequired: true;
}

export function createControlledMicrophoneSourceSessionPolicy(): ControlledMicrophoneSourceSessionPolicy {
  return Object.freeze({
    operationScope: "user_run_loopback_verifier",
    mediaScope: "microphone_only",
    exactGetUserMediaCallMaximum: 1,
    maximumSourceSessionMilliseconds: 3000,
    automaticSafetyStopMilliseconds: 2000,
    hardCeilingWatchdogMilliseconds: 2500,
    sourceSessionStartedReceiptRequired: true,
    independentProcessWatchdogRequired: true,
    hardCeilingWatchdogClosesBrowser: true,
    userEarlyStopControlRequired: true,
    everyReturnedTrackStopRequired: true,
    explicitCaptureSpecificConsentRequired: true,
    trustedSingleUseStartGestureRequired: true,
    temporaryPermissionsPolicy: "microphone=(self), camera=()",
    permissionPromptDisplayState: "not_observable",
    automaticRetryAllowed: false,
    permissionStatusQueryAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    deviceIdentifierReadAllowed: false,
    cameraRequestAllowed: false,
    audioElementAttachmentAllowed: false,
    audioContextCreationAllowed: false,
    mediaRecorderCreationAllowed: false,
    audioWorkletCreationAllowed: false,
    audioSampleReadAllowed: false,
    audioPlaybackAllowed: false,
    audioAnalysisAllowed: false,
    recordingCreationAllowed: false,
    rawMediaPersistenceAllowed: false,
    mediaTransmissionAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    externalAiAllowed: false,
    applicationOperationAvailable: false,
    furtherAudioSampleGateRequired: true,
  });
}
