import {
  CONTROLLED_LOOPBACK_HOST,
  CONTROLLED_LOOPBACK_PATH,
} from "./loopback-response-observation";

export interface ControlledBrowserNavigationPolicy {
  readonly profile: "single_headless_loopback_navigation";
  readonly allowedHost: typeof CONTROLLED_LOOPBACK_HOST;
  readonly allowedPath: typeof CONTROLLED_LOOPBACK_PATH;
  readonly allowedMethod: "GET";
  readonly controlledVerifierBrowserLaunchAuthorized: true;
  readonly applicationBrowserLaunchOperationAvailable: false;
  readonly reviewedExecutableEvidenceRequired: true;
  readonly headlessRequired: true;
  readonly freshEphemeralProfileRequired: true;
  readonly profileDeletionRequired: true;
  readonly maximumNavigationCount: 1;
  readonly maximumMainDocumentRequestCount: 1;
  readonly exactDefaultDenyHeaderRequired: true;
  readonly staticScriptFreeFixtureRequired: true;
  readonly externalOriginNavigationAllowed: false;
  readonly externalNetworkAllowed: false;
  readonly redirectsAllowed: false;
  readonly credentialsAllowed: false;
  readonly downloadsAllowed: false;
  readonly popupsAllowed: false;
  readonly extensionsAllowed: false;
  readonly serviceWorkersAllowed: false;
  readonly persistentStorageAllowed: false;
  readonly permissionOverridesAllowed: false;
  readonly permissionQueriesAllowed: false;
  readonly microphonePermissionAllowed: false;
  readonly cameraPermissionAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly captureAllowed: false;
  readonly browserIdentityCollectionAllowed: false;
  readonly userAgentCollectionAllowed: false;
  readonly authenticationAllowed: false;
  readonly bearerTokenAttachmentAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly externalAiAllowed: false;
  readonly productionDeploymentAllowed: false;
}

export function createControlledBrowserNavigationPolicy():
  ControlledBrowserNavigationPolicy {
  return Object.freeze({
    profile: "single_headless_loopback_navigation",
    allowedHost: CONTROLLED_LOOPBACK_HOST,
    allowedPath: CONTROLLED_LOOPBACK_PATH,
    allowedMethod: "GET",
    controlledVerifierBrowserLaunchAuthorized: true,
    applicationBrowserLaunchOperationAvailable: false,
    reviewedExecutableEvidenceRequired: true,
    headlessRequired: true,
    freshEphemeralProfileRequired: true,
    profileDeletionRequired: true,
    maximumNavigationCount: 1,
    maximumMainDocumentRequestCount: 1,
    exactDefaultDenyHeaderRequired: true,
    staticScriptFreeFixtureRequired: true,
    externalOriginNavigationAllowed: false,
    externalNetworkAllowed: false,
    redirectsAllowed: false,
    credentialsAllowed: false,
    downloadsAllowed: false,
    popupsAllowed: false,
    extensionsAllowed: false,
    serviceWorkersAllowed: false,
    persistentStorageAllowed: false,
    permissionOverridesAllowed: false,
    permissionQueriesAllowed: false,
    microphonePermissionAllowed: false,
    cameraPermissionAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    captureAllowed: false,
    browserIdentityCollectionAllowed: false,
    userAgentCollectionAllowed: false,
    authenticationAllowed: false,
    bearerTokenAttachmentAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    externalAiAllowed: false,
    productionDeploymentAllowed: false,
  });
}
