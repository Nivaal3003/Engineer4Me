export const CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT =
  "http://127.0.0.1:<ephemeral>/phase10-capability-readiness" as const;
export const CONTROLLED_BROWSER_CAPABILITY_MARKER =
  "phase10-controlled-browser-capability-observation" as const;

export const READ_ONLY_BROWSER_CAPABILITY_PROPERTIES = Object.freeze([
  "secure_context_state",
  "top_level_context_state",
  "media_devices_object_presence",
  "get_user_media_property_presence",
  "enumerate_devices_property_presence",
  "permissions_object_presence",
  "permissions_query_property_presence",
  "permissions_policy_object_presence",
  "permissions_policy_allows_feature_property_presence",
  "legacy_feature_policy_object_presence",
  "legacy_feature_policy_allows_feature_property_presence",
] as const);

export interface BrowserCapabilityObservationPolicy {
  readonly profile: "single_read_only_loopback_capability_observation";
  readonly redactedEndpoint: typeof CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT;
  readonly observationMarker: typeof CONTROLLED_BROWSER_CAPABILITY_MARKER;
  readonly allowedPropertyEvidence: typeof READ_ONLY_BROWSER_CAPABILITY_PROPERTIES;
  readonly secureContextRequired: true;
  readonly topLevelContextRequired: true;
  readonly onePolicySurfaceRequired: true;
  readonly exactNavigationCount: 1;
  readonly exactMainDocumentRequestCount: 1;
  readonly reviewedSignedExecutableRequired: true;
  readonly headlessRequired: true;
  readonly freshEphemeralProfileRequired: true;
  readonly profileDeletionRequired: true;
  readonly permissionStatusQueryAllowed: false;
  readonly permissionsPolicyMethodInvocationAllowed: false;
  readonly getUserMediaInvocationAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly permissionPromptAllowed: false;
  readonly permissionOverrideAllowed: false;
  readonly userAgentReadAllowed: false;
  readonly clientHintsReadAllowed: false;
  readonly deviceIdentifierReadAllowed: false;
  readonly captureAllowed: false;
  readonly externalNetworkAllowed: false;
  readonly authenticationAllowed: false;
  readonly bearerTokenAttachmentAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly externalAiAllowed: false;
  readonly serviceWorkerAllowed: false;
  readonly persistentCacheAllowed: false;
  readonly nativePackagingAllowed: false;
  readonly productionDeploymentAllowed: false;
}

export function createBrowserCapabilityObservationPolicy():
  BrowserCapabilityObservationPolicy {
  return Object.freeze({
    profile: "single_read_only_loopback_capability_observation",
    redactedEndpoint: CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
    observationMarker: CONTROLLED_BROWSER_CAPABILITY_MARKER,
    allowedPropertyEvidence: READ_ONLY_BROWSER_CAPABILITY_PROPERTIES,
    secureContextRequired: true,
    topLevelContextRequired: true,
    onePolicySurfaceRequired: true,
    exactNavigationCount: 1,
    exactMainDocumentRequestCount: 1,
    reviewedSignedExecutableRequired: true,
    headlessRequired: true,
    freshEphemeralProfileRequired: true,
    profileDeletionRequired: true,
    permissionStatusQueryAllowed: false,
    permissionsPolicyMethodInvocationAllowed: false,
    getUserMediaInvocationAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    permissionPromptAllowed: false,
    permissionOverrideAllowed: false,
    userAgentReadAllowed: false,
    clientHintsReadAllowed: false,
    deviceIdentifierReadAllowed: false,
    captureAllowed: false,
    externalNetworkAllowed: false,
    authenticationAllowed: false,
    bearerTokenAttachmentAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    externalAiAllowed: false,
    serviceWorkerAllowed: false,
    persistentCacheAllowed: false,
    nativePackagingAllowed: false,
    productionDeploymentAllowed: false,
  });
}
