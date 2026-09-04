export const ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_COMMIT =
  "01f602eb3b8da288788e1991abc12c178e4b3518" as const;
export const ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_TREE =
  "7e7f12ce5b3085c5799c58e3b83880e9d1a452cd" as const;
export const ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_CONTRACT_ID =
  "5f6e0e8f9fd4933c88a119c2123ea7a93d42db6d779b06a945d8e5ea409ed2fd" as const;
export const ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_RECOVERY_ID =
  "fcf6e8fdcceb33a4e33053c38ca41ce2600717d5f8c3f94bba6c9bd6840a8902" as const;
export const ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_ARCHIVE_SHA256 =
  "0e54214d47fc0f1c0705b74e072da3c6baf7f1e8a691dedc73533066faacc020" as const;

export interface MicrophonePermissionActivationEvidence {
  readonly evidenceType: "accepted_browser_capability_observation_reference";
  readonly permission: "microphone";
  readonly acceptedCommit: typeof ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_COMMIT;
  readonly acceptedTree: typeof ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_TREE;
  readonly acceptedContractId:
    typeof ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_CONTRACT_ID;
  readonly acceptedRecoveryId:
    typeof ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_RECOVERY_ID;
  readonly acceptanceArchiveSha256:
    typeof ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_ARCHIVE_SHA256;
  readonly observationAccepted: true;
  readonly secureContextObserved: true;
  readonly topLevelContextObserved: true;
  readonly mediaDevicesObjectPresent: true;
  readonly getUserMediaPropertyPresent: true;
  readonly permissionsObjectPresent: true;
  readonly permissionsQueryPropertyPresent: true;
  readonly permissionsPolicySurfacePresent: true;
  readonly propertyPresenceEvidenceOnly: true;
  readonly permissionStateKnown: false;
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly browserPermissionApiCalled: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly deviceIdentifierReadPerformed: false;
  readonly captureStarted: false;
  readonly rawMediaPersisted: false;
}

export function createAcceptedMicrophonePermissionActivationEvidence():
  MicrophonePermissionActivationEvidence {
  return Object.freeze({
    evidenceType: "accepted_browser_capability_observation_reference",
    permission: "microphone",
    acceptedCommit: ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_COMMIT,
    acceptedTree: ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_TREE,
    acceptedContractId: ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_CONTRACT_ID,
    acceptedRecoveryId: ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_RECOVERY_ID,
    acceptanceArchiveSha256: ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_ARCHIVE_SHA256,
    observationAccepted: true,
    secureContextObserved: true,
    topLevelContextObserved: true,
    mediaDevicesObjectPresent: true,
    getUserMediaPropertyPresent: true,
    permissionsObjectPresent: true,
    permissionsQueryPropertyPresent: true,
    permissionsPolicySurfacePresent: true,
    propertyPresenceEvidenceOnly: true,
    permissionStateKnown: false,
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    browserPermissionApiCalled: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    deviceIdentifierReadPerformed: false,
    captureStarted: false,
    rawMediaPersisted: false,
  });
}
