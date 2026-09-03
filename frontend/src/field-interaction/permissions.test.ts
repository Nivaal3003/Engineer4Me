import {
  createFieldInteractionPermissionSnapshot,
  createInactivePermissionReadiness,
} from "./permissions";

describe("field-interaction permission readiness", () => {
  it("keeps microphone and camera permissions inactive and intervention-gated", () => {
    expect(createInactivePermissionReadiness("microphone")).toEqual({
      permission: "microphone",
      state: "inactive_not_requested",
      interventionRequired: true,
      browserPermissionApiCalled: false,
      permissionPromptShown: false,
      userGestureRecorded: false,
      controlledEvidenceAccepted: false,
      activationAuthorized: false,
    });
    expect(createFieldInteractionPermissionSnapshot()).toMatchObject({
      liveCaptureActive: false,
      rawMediaCaptured: false,
      microphone: { activationAuthorized: false },
      camera: { activationAuthorized: false },
    });
  });
});
