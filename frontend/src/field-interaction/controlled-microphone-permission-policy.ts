export const CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_VERSION =
  "phase10-controlled-microphone-permission-consent-v2" as const;
export const CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE =
  "Engineer4Me will make one browser request for microphone access only after you select the consent checkbox and activate the reviewed control. If access is granted, the browser may briefly activate the microphone to create a media stream. Engineer4Me will immediately stop every returned track and will not read, play, analyze, record, store, or transmit audio. Camera access, permission-status queries, device enumeration, automatic retry, authentication, backend transport, protected-content access, and external AI remain disabled." as const;
export const CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_SHA256 =
  "cb33ff95e71d70379f755e20267e13b60d62f25278e777096d66e21c4992f8ed" as const;

export interface ControlledMicrophonePermissionPolicy {
  readonly executionSurface: "user_run_loopback_verifier";
  readonly permission: "microphone";
  readonly audioConstraint: true;
  readonly videoConstraint: false;
  readonly exactGetUserMediaCallMaximum: 1;
  readonly explicitConsentRequired: true;
  readonly trustedClickRequired: true;
  readonly singleUseRequestRequired: true;
  readonly freshEphemeralBrowserProfileRequired: true;
  readonly temporaryPermissionsPolicy: "microphone=(self), camera=()";
  readonly permissionStatusQueryAllowed: false;
  readonly permissionsPolicyMethodCallAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly deviceIdentifierReadAllowed: false;
  readonly streamConsumerAttachmentAllowed: false;
  readonly audioContextCreationAllowed: false;
  readonly mediaRecorderCreationAllowed: false;
  readonly audioSampleReadAllowed: false;
  readonly rawMediaPersistenceAllowed: false;
  readonly externalMediaTransmissionAllowed: false;
  readonly automaticRetryAllowed: false;
  readonly applicationOperationAvailable: false;
  readonly permissionPromptDisplayState: "not_observable";
  readonly browserMayBrieflyActivateMicrophoneOnGrant: true;
  readonly immediateTrackStopRequiredOnGrant: true;
  readonly furtherCaptureGateRequired: true;
}

export function createControlledMicrophonePermissionPolicy():
  ControlledMicrophonePermissionPolicy {
  return Object.freeze({
    executionSurface: "user_run_loopback_verifier",
    permission: "microphone",
    audioConstraint: true,
    videoConstraint: false,
    exactGetUserMediaCallMaximum: 1,
    explicitConsentRequired: true,
    trustedClickRequired: true,
    singleUseRequestRequired: true,
    freshEphemeralBrowserProfileRequired: true,
    temporaryPermissionsPolicy: "microphone=(self), camera=()",
    permissionStatusQueryAllowed: false,
    permissionsPolicyMethodCallAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    deviceIdentifierReadAllowed: false,
    streamConsumerAttachmentAllowed: false,
    audioContextCreationAllowed: false,
    mediaRecorderCreationAllowed: false,
    audioSampleReadAllowed: false,
    rawMediaPersistenceAllowed: false,
    externalMediaTransmissionAllowed: false,
    automaticRetryAllowed: false,
    applicationOperationAvailable: false,
    permissionPromptDisplayState: "not_observable",
    browserMayBrieflyActivateMicrophoneOnGrant: true,
    immediateTrackStopRequiredOnGrant: true,
    furtherCaptureGateRequired: true,
  });
}
