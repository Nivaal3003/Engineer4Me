import { createNoDeploymentPermissionsPolicyHeaderEvidence } from "./deployment-header-evidence";
import { createInertBrowserReadinessAdapter } from "./inert-browser-readiness-adapter";

describe("inert supported-browser readiness adapter", () => {
  it("does not read identity, invoke protected APIs, or expose activation operations", () => {
    const calls = {
      userAgent: 0,
      capture: 0,
      query: 0,
      enumerate: 0,
      policy: 0,
    };
    const windowObject = {};
    const navigatorObject = {
      get userAgent() {
        calls.userAgent += 1;
        return "forbidden-fixture";
      },
      mediaDevices: {
        getUserMedia: () => { calls.capture += 1; },
        enumerateDevices: () => { calls.enumerate += 1; },
      },
      permissions: { query: () => { calls.query += 1; } },
    };
    const adapter = createInertBrowserReadinessAdapter({
      window: windowObject,
      self: windowObject,
      top: windowObject,
      isSecureContext: true,
      navigator: navigatorObject,
      document: {
        permissionsPolicy: { allowsFeature: () => { calls.policy += 1; } },
      },
    });
    expect(adapter.evaluate({
      permission: "microphone",
      headerEvidence: createNoDeploymentPermissionsPolicyHeaderEvidence(),
    })).toMatchObject({
      state: "deployment_header_evidence_required",
      userAgentRead: false,
      liveResponseHeaderRead: false,
      permissionStatusQueried: false,
      permissionsPolicyMethodCalled: false,
      permissionPromptShown: false,
    });
    expect(adapter).toMatchObject({
      mode: "capability_based_read_only_and_caller_supplied_header_evidence",
      userAgentReadOperationAvailable: false,
      liveHeaderReadOperationAvailable: false,
      permissionRequestOperationAvailable: false,
      sideEffects: {
        userAgentReads: 0,
        liveHeaderReads: 0,
        permissionQueries: 0,
        policyMethodCalls: 0,
        permissionPrompts: 0,
        captureRequests: 0,
        deviceEnumerations: 0,
        networkRequests: 0,
      },
    });
    expect("requestPermission" in adapter).toBe(false);
    expect("readLiveHeader" in adapter).toBe(false);
    expect(calls).toEqual({ userAgent: 0, capture: 0, query: 0, enumerate: 0, policy: 0 });
  });
});
