export const MICROPHONE_CAPTURE_MAXIMUM_SOURCE_SESSION_MS = 3_000;
export const MICROPHONE_CAPTURE_EXACT_GET_USER_MEDIA_CALL_MAXIMUM = 1;

export interface MicrophoneCapturePolicy {
  readonly scope: "microphone_only";
  readonly exactGetUserMediaCallMaximum: 1;
  readonly maximumSourceSessionMilliseconds: 3000;
  readonly userEarlyStopRequired: true;
  readonly automaticStopAtCeilingRequired: true;
  readonly everyReturnedTrackStopRequired: true;
  readonly applicationOperationAvailable: false;
  readonly captureExecutionAuthorized: false;
  readonly audioElementAttachmentAllowed: false;
  readonly audioContextCreationAllowed: false;
  readonly mediaRecorderCreationAllowed: false;
  readonly audioWorkletCreationAllowed: false;
  readonly audioSampleReadAllowed: false;
  readonly audioAnalysisAllowed: false;
  readonly recordingCreationAllowed: false;
  readonly rawMediaPersistenceAllowed: false;
  readonly mediaTransmissionAllowed: false;
  readonly permissionStatusQueryAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly deviceIdentifierReadAllowed: false;
  readonly cameraRequestAllowed: false;
  readonly automaticRetryAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly externalAiAllowed: false;
  readonly serviceWorkerAllowed: false;
  readonly persistentCacheAllowed: false;
  readonly nativePackagingAllowed: false;
  readonly productionDeploymentAllowed: false;
  readonly executionInterventionRequired: true;
}

export function createMicrophoneCapturePolicy(): MicrophoneCapturePolicy {
  return Object.freeze({
    scope: "microphone_only",
    exactGetUserMediaCallMaximum: MICROPHONE_CAPTURE_EXACT_GET_USER_MEDIA_CALL_MAXIMUM,
    maximumSourceSessionMilliseconds: MICROPHONE_CAPTURE_MAXIMUM_SOURCE_SESSION_MS,
    userEarlyStopRequired: true,
    automaticStopAtCeilingRequired: true,
    everyReturnedTrackStopRequired: true,
    applicationOperationAvailable: false,
    captureExecutionAuthorized: false,
    audioElementAttachmentAllowed: false,
    audioContextCreationAllowed: false,
    mediaRecorderCreationAllowed: false,
    audioWorkletCreationAllowed: false,
    audioSampleReadAllowed: false,
    audioAnalysisAllowed: false,
    recordingCreationAllowed: false,
    rawMediaPersistenceAllowed: false,
    mediaTransmissionAllowed: false,
    permissionStatusQueryAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    deviceIdentifierReadAllowed: false,
    cameraRequestAllowed: false,
    automaticRetryAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    externalAiAllowed: false,
    serviceWorkerAllowed: false,
    persistentCacheAllowed: false,
    nativePackagingAllowed: false,
    productionDeploymentAllowed: false,
    executionInterventionRequired: true,
  });
}
