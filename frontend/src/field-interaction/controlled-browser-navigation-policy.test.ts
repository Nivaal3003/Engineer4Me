import { createControlledBrowserNavigationPolicy } from "./controlled-browser-navigation-policy";

describe("controlled browser navigation policy", () => {
  it("authorizes one verifier-only headless loopback navigation and nothing broader", () => {
    const policy = createControlledBrowserNavigationPolicy();
    expect(policy).toMatchObject({
      profile: "single_headless_loopback_navigation",
      allowedHost: "127.0.0.1",
      allowedPath: "/phase10-readiness",
      allowedMethod: "GET",
      controlledVerifierBrowserLaunchAuthorized: true,
      applicationBrowserLaunchOperationAvailable: false,
      maximumNavigationCount: 1,
      maximumMainDocumentRequestCount: 1,
      externalNetworkAllowed: false,
      permissionOverridesAllowed: false,
      permissionQueriesAllowed: false,
      microphonePermissionAllowed: false,
      cameraPermissionAllowed: false,
      mediaDeviceEnumerationAllowed: false,
      captureAllowed: false,
      serviceWorkersAllowed: false,
      productionDeploymentAllowed: false,
    });
  });
});
