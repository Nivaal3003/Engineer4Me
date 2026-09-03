import { createInertPermissionCapabilityAdapter } from "./inert-permission-adapter";

function guardedEnvironment(calls: { capture: number; query: number; enumerate: number }) {
  const windowObject = {};
  return {
    window: windowObject,
    self: windowObject,
    top: windowObject,
    isSecureContext: true,
    navigator: {
      mediaDevices: {
        getUserMedia: () => { calls.capture += 1; },
        enumerateDevices: () => { calls.enumerate += 1; },
      },
      permissions: {
        query: () => { calls.query += 1; },
      },
    },
  };
}

describe("inert permission adapter", () => {
  it("has no permission request operation and causes no protected side effects", () => {
    const calls = { capture: 0, query: 0, enumerate: 0 };
    const adapter = createInertPermissionCapabilityAdapter(guardedEnvironment(calls));
    expect(adapter.inspectCapabilities()).toMatchObject({
      getUserMediaFunctionPresent: true,
      permissionsQueryFunctionPresent: true,
      browserPermissionApiCalled: false,
      mediaDeviceEnumerationPerformed: false,
    });
    expect(adapter).toMatchObject({
      mode: "read_only_capability_detection_only",
      permissionRequestOperationAvailable: false,
      sideEffects: {
        permissionQueries: 0,
        permissionPrompts: 0,
        captureRequests: 0,
        deviceEnumerations: 0,
        mediaTracksCreated: 0,
        networkRequests: 0,
      },
    });
    expect("requestPermission" in adapter).toBe(false);
    expect(calls).toEqual({ capture: 0, query: 0, enumerate: 0 });
  });
});
