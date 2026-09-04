import {
  CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE,
  CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_SHA256,
  CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_VERSION,
  createControlledMicrophonePermissionPolicy,
} from "./controlled-microphone-permission-policy";

describe("controlled microphone permission policy", () => {
  it("binds one microphone-only request and retains every media-use denial", () => {
    const policy = createControlledMicrophonePermissionPolicy();
    expect(CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_VERSION).toBe(
      "phase10-controlled-microphone-permission-consent-v2",
    );
    expect(CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_SHA256).toBe(
      "cb33ff95e71d70379f755e20267e13b60d62f25278e777096d66e21c4992f8ed",
    );
    expect(CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE).toContain(
      "may briefly activate the microphone",
    );
    expect(policy.exactGetUserMediaCallMaximum).toBe(1);
    expect(policy.audioConstraint).toBe(true);
    expect(policy.videoConstraint).toBe(false);
    expect(policy.temporaryPermissionsPolicy).toBe(
      "microphone=(self), camera=()",
    );
    expect(policy.audioSampleReadAllowed).toBe(false);
    expect(policy.applicationOperationAvailable).toBe(false);
    expect(policy.furtherCaptureGateRequired).toBe(true);
  });
});
