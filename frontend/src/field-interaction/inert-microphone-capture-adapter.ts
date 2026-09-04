export interface InertMicrophoneCaptureAdapter {
  readonly captureStartOperationAvailable: false;
  readonly captureStopOperationAvailable: false;
  readonly consentRecordingOperationAvailable: false;
  readonly trustedGestureRecordingOperationAvailable: false;
  readonly permissionStatusQueryOperationAvailable: false;
  readonly deviceEnumerationOperationAvailable: false;
  readonly sampleReadOperationAvailable: false;
  readonly recordingOperationAvailable: false;
  readonly persistenceOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly externalAiOperationAvailable: false;
  readonly counters: {
    readonly sourceSessionStarts: 0;
    readonly getUserMediaCalls: 0;
    readonly trackStopCalls: 0;
    readonly audioSamplesRead: 0;
    readonly recordingsCreated: 0;
    readonly persistedMediaBytes: 0;
    readonly transmittedMediaBytes: 0;
    readonly backendRequests: 0;
    readonly externalAiRequests: 0;
  };
}

export function createInertMicrophoneCaptureAdapter():
  InertMicrophoneCaptureAdapter {
  return Object.freeze({
    captureStartOperationAvailable: false,
    captureStopOperationAvailable: false,
    consentRecordingOperationAvailable: false,
    trustedGestureRecordingOperationAvailable: false,
    permissionStatusQueryOperationAvailable: false,
    deviceEnumerationOperationAvailable: false,
    sampleReadOperationAvailable: false,
    recordingOperationAvailable: false,
    persistenceOperationAvailable: false,
    backendTransportOperationAvailable: false,
    externalAiOperationAvailable: false,
    counters: Object.freeze({
      sourceSessionStarts: 0,
      getUserMediaCalls: 0,
      trackStopCalls: 0,
      audioSamplesRead: 0,
      recordingsCreated: 0,
      persistedMediaBytes: 0,
      transmittedMediaBytes: 0,
      backendRequests: 0,
      externalAiRequests: 0,
    }),
  });
}
