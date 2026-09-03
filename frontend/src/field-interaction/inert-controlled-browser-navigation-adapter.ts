export interface InertControlledBrowserNavigationAdapter {
  readonly evidenceSource: "acceptance_archive_only";
  readonly applicationBrowserLaunchOperationAvailable: false;
  readonly navigationOperationAvailable: false;
  readonly executablePathReadOperationAvailable: false;
  readonly liveDeploymentHeaderReadOperationAvailable: false;
  readonly permissionQueryOperationAvailable: false;
  readonly permissionRequestOperationAvailable: false;
  readonly deviceEnumerationOperationAvailable: false;
  readonly captureOperationAvailable: false;
  readonly externalNetworkOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly counters: {
    readonly browserLaunches: 0;
    readonly navigations: 0;
    readonly executablePathReads: 0;
    readonly permissionQueries: 0;
    readonly permissionRequests: 0;
    readonly deviceEnumerations: 0;
    readonly captures: 0;
    readonly externalNetworkRequests: 0;
    readonly backendRequests: 0;
  };
}

export function createInertControlledBrowserNavigationAdapter():
  InertControlledBrowserNavigationAdapter {
  return Object.freeze({
    evidenceSource: "acceptance_archive_only",
    applicationBrowserLaunchOperationAvailable: false,
    navigationOperationAvailable: false,
    executablePathReadOperationAvailable: false,
    liveDeploymentHeaderReadOperationAvailable: false,
    permissionQueryOperationAvailable: false,
    permissionRequestOperationAvailable: false,
    deviceEnumerationOperationAvailable: false,
    captureOperationAvailable: false,
    externalNetworkOperationAvailable: false,
    backendTransportOperationAvailable: false,
    counters: Object.freeze({
      browserLaunches: 0,
      navigations: 0,
      executablePathReads: 0,
      permissionQueries: 0,
      permissionRequests: 0,
      deviceEnumerations: 0,
      captures: 0,
      externalNetworkRequests: 0,
      backendRequests: 0,
    }),
  });
}
