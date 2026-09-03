import {
  DEFAULT_DENY_PERMISSIONS_POLICY_VALUE,
  FUTURE_CONTROLLED_SELF_PERMISSIONS_POLICY_VALUE,
  parseDeploymentPermissionsPolicyValue,
} from "./deployment-permissions-policy";

describe("deployment Permissions-Policy parser", () => {
  it("accepts and canonicalizes the exact controlled default-deny profile", () => {
    expect(parseDeploymentPermissionsPolicyValue(
      "camera=(), microphone=()",
    )).toMatchObject({
      state: "accepted",
      canonicalValue: DEFAULT_DENY_PERMISSIONS_POLICY_VALUE,
      microphoneDirective: "deny",
      cameraDirective: "deny",
      liveResponseHeaderRead: false,
      networkRequestPerformed: false,
    });
  });

  it("accepts the self-only candidate as evidence without authorizing activation", () => {
    expect(parseDeploymentPermissionsPolicyValue(
      FUTURE_CONTROLLED_SELF_PERMISSIONS_POLICY_VALUE,
    )).toMatchObject({
      state: "accepted",
      microphoneDirective: "allow_self",
      cameraDirective: "allow_self",
      permissionPromptShown: false,
      permissionStatusQueried: false,
    });
  });

  it.each([
    "microphone=(self)",
    "microphone=(self), microphone=(), camera=(self)",
    "microphone=(*), camera=(self)",
    "microphone=(self), camera=(self), geolocation=()",
  ])("fails closed for ambiguous or unsupported input: %s", (value) => {
    expect(parseDeploymentPermissionsPolicyValue(value)).toMatchObject({
      state: "invalid",
      exactControlledDirectiveSet: false,
      canonicalValue: null,
    });
  });

  it("treats absent evidence as absent rather than inferring a live header", () => {
    expect(parseDeploymentPermissionsPolicyValue(null)).toMatchObject({
      state: "absent",
      suppliedValue: null,
      liveResponseHeaderRead: false,
    });
  });
});
