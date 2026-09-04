import { createInertBrowserCapabilityObservationAdapter } from "./inert-browser-capability-observation-adapter";

describe("inert browser capability observation adapter", () => {
  it("exposes evidence metadata but no executable browser or permission operation", () => {
    const adapter = createInertBrowserCapabilityObservationAdapter();
    expect(adapter.evidenceSource).toBe("acceptance_archive_only");
    expect(adapter.observationOperationAvailable).toBe(false);
    expect(adapter.browserLaunchOperationAvailable).toBe(false);
    expect(adapter.navigationOperationAvailable).toBe(false);
    expect(adapter.permissionStatusQueryOperationAvailable).toBe(false);
    expect(adapter.permissionsPolicyMethodOperationAvailable).toBe(false);
    expect(adapter.permissionRequestOperationAvailable).toBe(false);
    expect(adapter.getUserMediaOperationAvailable).toBe(false);
    expect(adapter.deviceEnumerationOperationAvailable).toBe(false);
    expect(adapter.captureOperationAvailable).toBe(false);
    expect(adapter.externalNetworkOperationAvailable).toBe(false);
    expect(adapter.backendTransportOperationAvailable).toBe(false);
    expect(adapter.counters).toEqual({
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
    });
  });
});
