export interface InertBrowserCapabilityObservationAdapter {
  readonly evidenceSource: "acceptance_archive_only";
  readonly observationOperationAvailable: false;
  readonly browserLaunchOperationAvailable: false;
  readonly navigationOperationAvailable: false;
  readonly permissionStatusQueryOperationAvailable: false;
  readonly permissionsPolicyMethodOperationAvailable: false;
  readonly permissionRequestOperationAvailable: false;
  readonly getUserMediaOperationAvailable: false;
  readonly deviceEnumerationOperationAvailable: false;
  readonly captureOperationAvailable: false;
  readonly externalNetworkOperationAvailable: false;
  readonly backendTransportOperationAvailable: false;
  readonly counters: {
    readonly observations: 0;
    readonly browserLaunches: 0;
    readonly navigations: 0;
    readonly permissionQueries: 0;
    readonly permissionsPolicyMethodCalls: 0;
    readonly permissionRequests: 0;
    readonly getUserMediaCalls: 0;
    readonly deviceEnumerations: 0;
    readonly captures: 0;
    readonly externalNetworkRequests: 0;
    readonly backendRequests: 0;
  };
}

export function createInertBrowserCapabilityObservationAdapter():
  InertBrowserCapabilityObservationAdapter {
  return Object.freeze({
    evidenceSource: "acceptance_archive_only",
    observationOperationAvailable: false,
    browserLaunchOperationAvailable: false,
    navigationOperationAvailable: false,
    permissionStatusQueryOperationAvailable: false,
    permissionsPolicyMethodOperationAvailable: false,
    permissionRequestOperationAvailable: false,
    getUserMediaOperationAvailable: false,
    deviceEnumerationOperationAvailable: false,
    captureOperationAvailable: false,
    externalNetworkOperationAvailable: false,
    backendTransportOperationAvailable: false,
    counters: Object.freeze({
      observations: 0,
      browserLaunches: 0,
      navigations: 0,
      permissionQueries: 0,
      permissionsPolicyMethodCalls: 0,
      permissionRequests: 0,
      getUserMediaCalls: 0,
      deviceEnumerations: 0,
      captures: 0,
      externalNetworkRequests: 0,
      backendRequests: 0,
    }),
  });
}
