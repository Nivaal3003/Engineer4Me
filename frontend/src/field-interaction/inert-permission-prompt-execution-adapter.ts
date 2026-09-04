export interface InertPermissionPromptExecutionAdapter {
  readonly adapterType: "inert_permission_prompt_execution_adapter";
  readonly evidenceSource: "accepted_archives_and_caller_supplied_records_only";
  readonly consentRecordingOperationAvailable: false;
  readonly trustedGestureRecordingOperationAvailable: false;
  readonly permissionPromptExecutionOperationAvailable: false;
  readonly permissionStatusQueryOperationAvailable: false;
  readonly deviceEnumerationOperationAvailable: false;
  readonly captureOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly externalAiOperationAvailable: false;
  readonly counters: {
    readonly consentDecisionsRecorded: 0;
    readonly trustedGesturesRecorded: 0;
    readonly permissionPromptsExecuted: 0;
    readonly permissionStatusQueries: 0;
    readonly deviceEnumerations: 0;
    readonly captures: 0;
    readonly backendRequests: 0;
    readonly externalAiRequests: 0;
  };
}

export function createInertPermissionPromptExecutionAdapter():
  InertPermissionPromptExecutionAdapter {
  return Object.freeze({
    adapterType: "inert_permission_prompt_execution_adapter",
    evidenceSource: "accepted_archives_and_caller_supplied_records_only",
    consentRecordingOperationAvailable: false,
    trustedGestureRecordingOperationAvailable: false,
    permissionPromptExecutionOperationAvailable: false,
    permissionStatusQueryOperationAvailable: false,
    deviceEnumerationOperationAvailable: false,
    captureOperationAvailable: false,
    backendTransportOperationAvailable: false,
    externalAiOperationAvailable: false,
    counters: Object.freeze({
      consentDecisionsRecorded: 0,
      trustedGesturesRecorded: 0,
      permissionPromptsExecuted: 0,
      permissionStatusQueries: 0,
      deviceEnumerations: 0,
      captures: 0,
      backendRequests: 0,
      externalAiRequests: 0,
    }),
  });
}
