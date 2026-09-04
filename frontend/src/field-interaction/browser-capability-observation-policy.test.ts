import {
  CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
  READ_ONLY_BROWSER_CAPABILITY_PROPERTIES,
  createBrowserCapabilityObservationPolicy,
} from "./browser-capability-observation-policy";

describe("controlled browser capability observation policy", () => {
  it("permits property evidence while keeping all callable operations closed", () => {
    const policy = createBrowserCapabilityObservationPolicy();
    expect(policy.redactedEndpoint).toBe(CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT);
    expect(policy.allowedPropertyEvidence).toBe(READ_ONLY_BROWSER_CAPABILITY_PROPERTIES);
    expect(policy.exactNavigationCount).toBe(1);
    expect(policy.exactMainDocumentRequestCount).toBe(1);
    expect(policy.permissionStatusQueryAllowed).toBe(false);
    expect(policy.permissionsPolicyMethodInvocationAllowed).toBe(false);
    expect(policy.getUserMediaInvocationAllowed).toBe(false);
    expect(policy.mediaDeviceEnumerationAllowed).toBe(false);
    expect(policy.permissionPromptAllowed).toBe(false);
    expect(policy.externalNetworkAllowed).toBe(false);
    expect(policy.backendTransportAllowed).toBe(false);
    expect(policy.productionDeploymentAllowed).toBe(false);
  });
});
