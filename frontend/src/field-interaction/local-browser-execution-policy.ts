import {
  CONTROLLED_LOOPBACK_HOST,
  CONTROLLED_LOOPBACK_PATH,
} from "./loopback-response-observation";

export interface ControlledLocalBrowserExecutionPolicy {
  readonly profile: "isolated_headless_loopback_readiness";
  readonly allowedHost: typeof CONTROLLED_LOOPBACK_HOST;
  readonly allowedPath: typeof CONTROLLED_LOOPBACK_PATH;
  readonly headlessRequired: true;
  readonly isolatedUserDataDirectoryRequired: true;
  readonly ephemeralProfileDeletionRequired: true;
  readonly freshBrowserContextRequired: true;
  readonly loopbackNavigationOnly: true;
  readonly externalOriginNavigationAllowed: false;
  readonly externalNetworkAllowed: false;
  readonly credentialStoreUseAllowed: false;
  readonly extensionLoadingAllowed: false;
  readonly serviceWorkersAllowed: false;
  readonly persistentStorageAllowed: false;
  readonly downloadsAllowed: false;
  readonly popupsAllowed: false;
  readonly permissionOverridesAllowed: false;
  readonly microphonePermissionAllowed: false;
  readonly cameraPermissionAllowed: false;
  readonly mediaDeviceEnumerationAllowed: false;
  readonly browserIdentityCollectionAllowed: false;
  readonly userAgentCollectionAllowed: false;
  readonly liveDeploymentHeaderReadAllowed: false;
  readonly authenticationAllowed: false;
  readonly bearerTokenAttachmentAllowed: false;
  readonly backendTransportAllowed: false;
  readonly protectedContentAccessAllowed: false;
  readonly browserLaunchAuthorized: false;
  readonly interventionRequired: true;
}

export function createControlledLocalBrowserExecutionPolicy():
  ControlledLocalBrowserExecutionPolicy {
  return Object.freeze({
    profile: "isolated_headless_loopback_readiness",
    allowedHost: CONTROLLED_LOOPBACK_HOST,
    allowedPath: CONTROLLED_LOOPBACK_PATH,
    headlessRequired: true,
    isolatedUserDataDirectoryRequired: true,
    ephemeralProfileDeletionRequired: true,
    freshBrowserContextRequired: true,
    loopbackNavigationOnly: true,
    externalOriginNavigationAllowed: false,
    externalNetworkAllowed: false,
    credentialStoreUseAllowed: false,
    extensionLoadingAllowed: false,
    serviceWorkersAllowed: false,
    persistentStorageAllowed: false,
    downloadsAllowed: false,
    popupsAllowed: false,
    permissionOverridesAllowed: false,
    microphonePermissionAllowed: false,
    cameraPermissionAllowed: false,
    mediaDeviceEnumerationAllowed: false,
    browserIdentityCollectionAllowed: false,
    userAgentCollectionAllowed: false,
    liveDeploymentHeaderReadAllowed: false,
    authenticationAllowed: false,
    bearerTokenAttachmentAllowed: false,
    backendTransportAllowed: false,
    protectedContentAccessAllowed: false,
    browserLaunchAuthorized: false,
    interventionRequired: true,
  });
}
