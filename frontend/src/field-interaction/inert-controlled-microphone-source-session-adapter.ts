export interface InertControlledMicrophoneSourceSessionAdapter {
  readonly adapterType: "inert_controlled_microphone_source_session";
  readonly browserLaunchOperationAvailable: false;
  readonly navigationOperationAvailable: false;
  readonly getUserMediaOperationAvailable: false;
  readonly sourceSessionStartOperationAvailable: false;
  readonly sourceSessionStopOperationAvailable: false;
  readonly permissionStatusQueryOperationAvailable: false;
  readonly mediaDeviceEnumerationOperationAvailable: false;
  readonly audioSampleReadOperationAvailable: false;
  readonly recordingOperationAvailable: false;
  readonly persistenceOperationAvailable: false;
  readonly transmissionOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly externalAiOperationAvailable: false;
  readonly browserLaunchCount: 0;
  readonly getUserMediaCallCount: 0;
  readonly sourceSessionStartCount: 0;
  readonly audioSampleReadCount: 0;
  readonly recordingCount: 0;
  readonly persistenceCount: 0;
  readonly transmissionCount: 0;
}

export function createInertControlledMicrophoneSourceSessionAdapter(): InertControlledMicrophoneSourceSessionAdapter {
  return Object.freeze({
    adapterType: "inert_controlled_microphone_source_session",
    browserLaunchOperationAvailable: false,
    navigationOperationAvailable: false,
    getUserMediaOperationAvailable: false,
    sourceSessionStartOperationAvailable: false,
    sourceSessionStopOperationAvailable: false,
    permissionStatusQueryOperationAvailable: false,
    mediaDeviceEnumerationOperationAvailable: false,
    audioSampleReadOperationAvailable: false,
    recordingOperationAvailable: false,
    persistenceOperationAvailable: false,
    transmissionOperationAvailable: false,
    backendTransportOperationAvailable: false,
    externalAiOperationAvailable: false,
    browserLaunchCount: 0,
    getUserMediaCallCount: 0,
    sourceSessionStartCount: 0,
    audioSampleReadCount: 0,
    recordingCount: 0,
    persistenceCount: 0,
    transmissionCount: 0,
  });
}
