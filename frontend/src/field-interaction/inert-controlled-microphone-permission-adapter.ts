export interface InertControlledMicrophonePermissionAdapter {
  readonly permissionRequestOperationAvailable: false;
  readonly consentRecordingOperationAvailable: false;
  readonly trustedGestureRecordingOperationAvailable: false;
  readonly permissionStatusQueryOperationAvailable: false;
  readonly deviceEnumerationOperationAvailable: false;
  readonly captureOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly externalAiOperationAvailable: false;
  readonly counters: {
    readonly permissionRequests: 0;
    readonly permissionStatusQueries: 0;
    readonly deviceEnumerations: 0;
    readonly trackConsumers: 0;
    readonly recordings: 0;
    readonly persistedMedia: 0;
    readonly transmittedMedia: 0;
  };
}

export function createInertControlledMicrophonePermissionAdapter():
  InertControlledMicrophonePermissionAdapter {
  return Object.freeze({
    permissionRequestOperationAvailable: false,
    consentRecordingOperationAvailable: false,
    trustedGestureRecordingOperationAvailable: false,
    permissionStatusQueryOperationAvailable: false,
    deviceEnumerationOperationAvailable: false,
    captureOperationAvailable: false,
    backendTransportOperationAvailable: false,
    externalAiOperationAvailable: false,
    counters: Object.freeze({
      permissionRequests: 0,
      permissionStatusQueries: 0,
      deviceEnumerations: 0,
      trackConsumers: 0,
      recordings: 0,
      persistedMedia: 0,
      transmittedMedia: 0,
    }),
  });
}
