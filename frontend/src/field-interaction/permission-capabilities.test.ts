import { detectReadOnlyPermissionCapabilities } from "./permission-capabilities";

describe("read-only permission capability detection", () => {
  it("detects property presence without invoking protected browser functions", () => {
    let captureCalls = 0;
    let queryCalls = 0;
    let policyCalls = 0;
    const windowObject = {};
    const environment = {
      window: windowObject,
      self: windowObject,
      top: windowObject,
      isSecureContext: true,
      navigator: {
        mediaDevices: {
          getUserMedia: () => {
            captureCalls += 1;
            throw new Error("must not execute");
          },
        },
        permissions: {
          query: () => {
            queryCalls += 1;
            throw new Error("must not execute");
          },
        },
      },
      document: {
        permissionsPolicy: {
          allowsFeature: () => {
            policyCalls += 1;
            throw new Error("must not execute");
          },
        },
      },
    };

    expect(detectReadOnlyPermissionCapabilities(environment)).toMatchObject({
      detectionMode: "read_only_property_presence",
      secureContext: true,
      embeddingContext: "top_level",
      mediaDevicesObjectPresent: true,
      getUserMediaFunctionPresent: true,
      permissionsObjectPresent: true,
      permissionsQueryFunctionPresent: true,
      permissionsPolicyObjectPresent: true,
      permissionsPolicyAllowsFeatureFunctionPresent: true,
      browserPermissionApiCalled: false,
      permissionStatusQueried: false,
      permissionPromptShown: false,
      mediaDeviceEnumerationPerformed: false,
      liveCaptureStarted: false,
    });
    expect({ captureCalls, queryCalls, policyCalls }).toEqual({
      captureCalls: 0,
      queryCalls: 0,
      policyCalls: 0,
    });
  });

  it("fails closed when browser surfaces are unavailable", () => {
    expect(detectReadOnlyPermissionCapabilities({})).toMatchObject({
      secureContext: null,
      embeddingContext: "not_available",
      navigatorPresent: false,
      mediaDevicesObjectPresent: false,
      getUserMediaFunctionPresent: false,
    });
  });
});
