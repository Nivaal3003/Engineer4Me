import { createInertLocalBrowserExecutionAdapter } from "./inert-local-browser-execution-adapter";

describe("inert local browser execution adapter", () => {
  it("offers evaluation only and cannot launch, navigate, read live deployment headers, or request permission", () => {
    const adapter = createInertLocalBrowserExecutionAdapter();
    expect(adapter).toMatchObject({
      browserLaunchOperationAvailable: false,
      navigationOperationAvailable: false,
      liveDeploymentHeaderReadOperationAvailable: false,
      permissionOverrideOperationAvailable: false,
      permissionRequestOperationAvailable: false,
      sideEffects: {
        browserLaunches: 0,
        navigations: 0,
        liveDeploymentHeaderReads: 0,
        externalNetworkRequests: 0,
        userAgentReads: 0,
        permissionQueries: 0,
        permissionPrompts: 0,
        permissionOverrides: 0,
        deviceEnumerations: 0,
        captureRequests: 0,
        authenticationRequests: 0,
        bearerAttachments: 0,
        backendRequests: 0,
        protectedContentReads: 0,
      },
    });
    expect("launchBrowser" in adapter).toBe(false);
    expect("navigate" in adapter).toBe(false);
    expect("readLiveDeploymentHeader" in adapter).toBe(false);
    expect("requestPermission" in adapter).toBe(false);
    expect(adapter.evaluate()).toMatchObject({
      state: "loopback_observation_required",
      browserLaunchAuthorized: false,
      browserExecuted: false,
    });
  });
});
