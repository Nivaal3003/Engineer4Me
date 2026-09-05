export const CONTROLLED_MICROPHONE_SOURCE_SESSION_OUTCOMES = [
  "source_session_completed_automatic_stop",
  "source_session_completed_user_stop",
  "not_allowed_or_dismissed",
  "no_matching_source",
  "source_unreadable",
  "request_aborted",
  "security_or_api_unavailable",
  "constraints_rejected",
] as const;

export type ControlledMicrophoneSourceSessionOutcome =
  (typeof CONTROLLED_MICROPHONE_SOURCE_SESSION_OUTCOMES)[number];
export type ControlledMicrophoneSourceSessionStopReason =
  | "automatic_safety_stop"
  | "user_stop"
  | "not_started";

export interface ControlledMicrophoneSourceSessionOutcomeEvidence {
  readonly source: "user_run_loopback_verifier";
  readonly outcome: ControlledMicrophoneSourceSessionOutcome;
  readonly getUserMediaCallCount: 1;
  readonly mediaStreamReturned: boolean;
  readonly sourceSessionStarted: boolean;
  readonly sourceSessionStopReason: ControlledMicrophoneSourceSessionStopReason;
  readonly maximumSourceSessionMilliseconds: 3000;
  readonly automaticSafetyStopMilliseconds: 2000;
  readonly observedSourceSessionMilliseconds: number | null;
  readonly returnedTrackCount: number;
  readonly returnedAudioTrackCount: number;
  readonly returnedVideoTrackCount: number;
  readonly audioTrackKindsOnly: boolean;
  readonly allReturnedTracksLiveBeforeStop: boolean;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
  readonly userEarlyStopControlAvailable: boolean;
  readonly userEarlyStopRequested: boolean;
  readonly automaticStopTriggered: boolean;
  readonly permissionPromptDisplayState: "not_observable";
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly deviceIdentifierReadPerformed: false;
  readonly audioElementAttachmentPerformed: false;
  readonly audioContextCreated: false;
  readonly mediaRecorderCreated: false;
  readonly audioWorkletCreated: false;
  readonly audioSampleReadPerformed: false;
  readonly audioSamplesAccessed: false;
  readonly audioPlaybackStarted: false;
  readonly audioAnalysisPerformed: false;
  readonly audioRecordingCreated: false;
  readonly rawMediaPersisted: false;
  readonly mediaTransmitted: false;
  readonly automaticRetryPerformed: false;
  readonly cameraRequested: false;
  readonly currentPermissionStateInferred: false;
  readonly audioSampleAuthorizationDerived: false;
  readonly furtherAudioSampleGateRequired: true;
}

export function createControlledMicrophoneSourceSessionOutcomeEvidence(input: {
  readonly outcome: ControlledMicrophoneSourceSessionOutcome;
  readonly getUserMediaCallCount: number;
  readonly mediaStreamReturned: boolean;
  readonly sourceSessionStarted: boolean;
  readonly sourceSessionStopReason: ControlledMicrophoneSourceSessionStopReason;
  readonly observedSourceSessionMilliseconds: number | null;
  readonly returnedTrackCount: number;
  readonly returnedAudioTrackCount: number;
  readonly returnedVideoTrackCount: number;
  readonly audioTrackKindsOnly: boolean;
  readonly allReturnedTracksLiveBeforeStop: boolean;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
  readonly userEarlyStopControlAvailable: boolean;
  readonly userEarlyStopRequested: boolean;
  readonly automaticStopTriggered: boolean;
}): ControlledMicrophoneSourceSessionOutcomeEvidence {
  if (input.getUserMediaCallCount !== 1) {
    throw new Error("Controlled source-session evidence must represent exactly one getUserMedia call.");
  }
  for (const value of [input.returnedTrackCount, input.returnedAudioTrackCount,
    input.returnedVideoTrackCount, input.trackStopCallCount]) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 16) {
      throw new Error("Controlled source-session count is outside the accepted bound.");
    }
  }
  const completed = input.outcome === "source_session_completed_automatic_stop" ||
    input.outcome === "source_session_completed_user_stop";
  if (completed) {
    if (!input.mediaStreamReturned || !input.sourceSessionStarted || input.returnedTrackCount < 1) {
      throw new Error("Completed source-session evidence requires a returned stream and at least one track.");
    }
    if (input.returnedVideoTrackCount !== 0 || !input.audioTrackKindsOnly ||
        input.returnedAudioTrackCount !== input.returnedTrackCount) {
      throw new Error("Completed source-session evidence is not microphone-only.");
    }
    if (!input.allReturnedTracksLiveBeforeStop ||
        input.trackStopCallCount !== input.returnedTrackCount ||
        !input.allReturnedTracksEnded) {
      throw new Error("Completed source-session track lifecycle evidence differs.");
    }
    if (input.observedSourceSessionMilliseconds === null ||
        !Number.isSafeInteger(input.observedSourceSessionMilliseconds) ||
        input.observedSourceSessionMilliseconds < 0 ||
        input.observedSourceSessionMilliseconds > 3_000) {
      throw new Error("Observed source-session duration exceeds the accepted three-second ceiling.");
    }
    if (!input.userEarlyStopControlAvailable) {
      throw new Error("Completed source-session evidence requires an available user stop control.");
    }
    if (input.outcome === "source_session_completed_automatic_stop") {
      if (input.sourceSessionStopReason !== "automatic_safety_stop" ||
          !input.automaticStopTriggered || input.userEarlyStopRequested ||
          input.observedSourceSessionMilliseconds < 1_000) {
        throw new Error("Automatic source-session stop evidence differs.");
      }
    } else if (input.sourceSessionStopReason !== "user_stop" ||
               !input.userEarlyStopRequested || input.automaticStopTriggered) {
      throw new Error("User source-session stop evidence differs.");
    }
  } else {
    if (input.mediaStreamReturned || input.sourceSessionStarted ||
        input.sourceSessionStopReason !== "not_started" ||
        input.observedSourceSessionMilliseconds !== null ||
        input.returnedTrackCount !== 0 || input.returnedAudioTrackCount !== 0 ||
        input.returnedVideoTrackCount !== 0 || input.trackStopCallCount !== 0 ||
        input.allReturnedTracksLiveBeforeStop || input.allReturnedTracksEnded ||
        input.userEarlyStopControlAvailable || input.userEarlyStopRequested ||
        input.automaticStopTriggered) {
      throw new Error("Non-started source-session evidence contains active-session values.");
    }
  }
  return Object.freeze({
    source: "user_run_loopback_verifier",
    outcome: input.outcome,
    getUserMediaCallCount: 1,
    mediaStreamReturned: input.mediaStreamReturned,
    sourceSessionStarted: input.sourceSessionStarted,
    sourceSessionStopReason: input.sourceSessionStopReason,
    maximumSourceSessionMilliseconds: 3000,
    automaticSafetyStopMilliseconds: 2000,
    observedSourceSessionMilliseconds: input.observedSourceSessionMilliseconds,
    returnedTrackCount: input.returnedTrackCount,
    returnedAudioTrackCount: input.returnedAudioTrackCount,
    returnedVideoTrackCount: input.returnedVideoTrackCount,
    audioTrackKindsOnly: input.audioTrackKindsOnly,
    allReturnedTracksLiveBeforeStop: input.allReturnedTracksLiveBeforeStop,
    trackStopCallCount: input.trackStopCallCount,
    allReturnedTracksEnded: input.allReturnedTracksEnded,
    userEarlyStopControlAvailable: input.userEarlyStopControlAvailable,
    userEarlyStopRequested: input.userEarlyStopRequested,
    automaticStopTriggered: input.automaticStopTriggered,
    permissionPromptDisplayState: "not_observable",
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    mediaDeviceEnumerationPerformed: false,
    deviceIdentifierReadPerformed: false,
    audioElementAttachmentPerformed: false,
    audioContextCreated: false,
    mediaRecorderCreated: false,
    audioWorkletCreated: false,
    audioSampleReadPerformed: false,
    audioSamplesAccessed: false,
    audioPlaybackStarted: false,
    audioAnalysisPerformed: false,
    audioRecordingCreated: false,
    rawMediaPersisted: false,
    mediaTransmitted: false,
    automaticRetryPerformed: false,
    cameraRequested: false,
    currentPermissionStateInferred: false,
    audioSampleAuthorizationDerived: false,
    furtherAudioSampleGateRequired: true,
  });
}
