import { createControlledLocalBrowserExecutionPolicy } from "./local-browser-execution-policy";

describe("controlled local browser execution policy", () => {
  it("is headless, isolated, loopback-only, and still requires intervention", () => {
    expect(createControlledLocalBrowserExecutionPolicy()).toMatchObject({
      profile: "isolated_headless_loopback_readiness",
      allowedHost: "127.0.0.1",
      allowedPath: "/phase10-readiness",
      headlessRequired: true,
      isolatedUserDataDirectoryRequired: true,
      loopbackNavigationOnly: true,
      externalNetworkAllowed: false,
      browserLaunchAuthorized: false,
      interventionRequired: true,
    });
  });

  it("does not permit identity, credentials, permissions, storage, or protected transport", () => {
    expect(createControlledLocalBrowserExecutionPolicy()).toMatchObject({
      browserIdentityCollectionAllowed: false,
      userAgentCollectionAllowed: false,
      credentialStoreUseAllowed: false,
      serviceWorkersAllowed: false,
      persistentStorageAllowed: false,
      permissionOverridesAllowed: false,
      microphonePermissionAllowed: false,
      cameraPermissionAllowed: false,
      mediaDeviceEnumerationAllowed: false,
      authenticationAllowed: false,
      bearerTokenAttachmentAllowed: false,
      backendTransportAllowed: false,
      protectedContentAccessAllowed: false,
    });
  });
});
