export const AUDIO_SAMPLE_MAXIMUM_FRAME_LENGTH = 2_048;
export const AUDIO_SAMPLE_MAXIMUM_RAW_BYTES = 8_192;
export const AUDIO_SAMPLE_MAXIMUM_SOURCE_SESSION_MS = 1_000;
export const AUDIO_SAMPLE_EXACT_READ_CALL_MAXIMUM = 1;
export const AUDIO_SIGNAL_PRESENCE_ABSOLUTE_PEAK_THRESHOLD = 0.001;

export interface AudioSampleAcquisitionPolicy {
  readonly operationScope: "future_controlled_loopback_verifier";
  readonly mediaScope: "microphone_only";
  readonly sampleFormat: "float32_mono";
  readonly exactGetUserMediaCallMaximum: 1;
  readonly exactSampleReadCallMaximum: 1;
  readonly maximumFrameLength: 2048;
  readonly maximumRawBytes: 8192;
  readonly maximumSourceSessionMilliseconds: 1000;
  readonly signalPresenceThreshold: 0.001;
  readonly signalPresenceClassificationOnly: true;
  readonly numericAmplitudeRetentionAllowed: false;
  readonly waveformRetentionAllowed: false;
  readonly rawBufferZeroizationRequired: true;
  readonly audioContextClosureRequired: true;
  readonly everyReturnedTrackStopRequired: true;
  readonly explicitSampleSpecificConsentRequired: true;
  readonly trustedSingleUseStartGestureRequired: true;
  readonly permissionStatusQueryAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly deviceIdentifierReadAllowed: false;
  readonly cameraRequestAllowed: false;
  readonly audioPlaybackAllowed: false;
  readonly mediaRecorderCreationAllowed: false;
  readonly audioWorkletCreationAllowed: false;
  readonly recordingCreationAllowed: false;
  readonly rawMediaPersistenceAllowed: false;
  readonly mediaTransmissionAllowed: false;
  readonly speechToTextAllowed: false;
  readonly voiceCommandInterpretationAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly externalOrLocalAiAllowed: false;
  readonly applicationOperationAvailable: false;
  readonly executionAuthorized: false;
  readonly executionInterventionRequired: true;
}

export function createAudioSampleAcquisitionPolicy(): AudioSampleAcquisitionPolicy {
  return Object.freeze({
    operationScope: "future_controlled_loopback_verifier",
    mediaScope: "microphone_only",
    sampleFormat: "float32_mono",
    exactGetUserMediaCallMaximum: 1,
    exactSampleReadCallMaximum: 1,
    maximumFrameLength: 2048,
    maximumRawBytes: 8192,
    maximumSourceSessionMilliseconds: 1000,
    signalPresenceThreshold: 0.001,
    signalPresenceClassificationOnly: true,
    numericAmplitudeRetentionAllowed: false,
    waveformRetentionAllowed: false,
    rawBufferZeroizationRequired: true,
    audioContextClosureRequired: true,
    everyReturnedTrackStopRequired: true,
    explicitSampleSpecificConsentRequired: true,
    trustedSingleUseStartGestureRequired: true,
    permissionStatusQueryAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    deviceIdentifierReadAllowed: false,
    cameraRequestAllowed: false,
    audioPlaybackAllowed: false,
    mediaRecorderCreationAllowed: false,
    audioWorkletCreationAllowed: false,
    recordingCreationAllowed: false,
    rawMediaPersistenceAllowed: false,
    mediaTransmissionAllowed: false,
    speechToTextAllowed: false,
    voiceCommandInterpretationAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    externalOrLocalAiAllowed: false,
    applicationOperationAvailable: false,
    executionAuthorized: false,
    executionInterventionRequired: true,
  });
}
