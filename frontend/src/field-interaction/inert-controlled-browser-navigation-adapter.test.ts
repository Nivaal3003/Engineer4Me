import { createInertControlledBrowserNavigationAdapter } from "./inert-controlled-browser-navigation-adapter";

describe("inert controlled browser navigation adapter", () => {
  it("exposes acceptance evidence only and no executable, launch, navigation, permission, capture, or transport operation", () => {
    const adapter = createInertControlledBrowserNavigationAdapter();
    expect(adapter).toMatchObject({
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
      counters: {
        browserLaunches: 0,
        navigations: 0,
        executablePathReads: 0,
        permissionQueries: 0,
        permissionRequests: 0,
        deviceEnumerations: 0,
        captures: 0,
        externalNetworkRequests: 0,
        backendRequests: 0,
      },
    });
    expect("launch" in adapter).toBe(false);
    expect("navigate" in adapter).toBe(false);
    expect("readExecutablePath" in adapter).toBe(false);
    expect("requestPermission" in adapter).toBe(false);
  });
});
