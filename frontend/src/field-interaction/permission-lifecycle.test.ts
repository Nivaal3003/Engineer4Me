import {
  createInactivePermissionLifecycle,
  PERMISSION_LIFECYCLE_STATES,
  transitionPermissionLifecycle,
} from "./permission-lifecycle";

describe("permission lifecycle outcome model", () => {
  it("contains no granted or capturing state", () => {
    expect(PERMISSION_LIFECYCLE_STATES).not.toContain("granted");
    expect(PERMISSION_LIFECYCLE_STATES).not.toContain("capturing");
  });

  it("models readiness and accepted imported denial outcomes without runtime activation", () => {
    const ready = transitionPermissionLifecycle(
      createInactivePermissionLifecycle("camera"),
      { type: "reach_intervention_gate" },
    );
    expect(ready).toMatchObject({
      state: "intervention_required",
      permissionPromptPerformedByThisRuntime: false,
      activationAuthorized: false,
    });
    const denied = transitionPermissionLifecycle(ready, {
      type: "record_imported_outcome",
      outcome: "denied",
      evidenceAccepted: true,
    });
    expect(denied).toMatchObject({
      state: "denied",
      importedOutcomeEvidenceAccepted: true,
      permissionPromptPerformedByThisRuntime: false,
      browserPermissionApiCalledByThisRuntime: false,
      rawMediaAvailable: false,
    });
  });

  it("rejects unaccepted imported outcomes", () => {
    expect(() => transitionPermissionLifecycle(
      createInactivePermissionLifecycle("microphone"),
      {
        type: "record_imported_outcome",
        outcome: "dismissed",
        evidenceAccepted: false,
      },
    )).toThrow(/accepted evidence/);
  });
});
