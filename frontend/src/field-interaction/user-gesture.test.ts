import {
  createUserGestureEvidence,
  evaluateUserGestureEvidence,
} from "./user-gesture";

describe("explicit user-gesture evidence", () => {
  it("accepts a fresh trusted target-bound gesture only for a future gate", () => {
    const evidence = createUserGestureEvidence({
      evidenceId: "microphone-gesture-evidence",
      targetId: "microphone-permission-control",
      gestureKind: "button_click",
      occurredAtEpochMs: 10_000,
      trustedEvent: true,
    });
    expect(evaluateUserGestureEvidence({
      evidence,
      expectedTargetId: "microphone-permission-control",
      referenceEpochMs: 12_000,
    })).toMatchObject({
      trustedEventSatisfied: true,
      targetBindingSatisfied: true,
      freshnessSatisfied: true,
      singleUseSatisfied: true,
      acceptedForFuturePromptPreparation: true,
      interventionRequired: true,
      activationAuthorized: false,
      permissionPromptShown: false,
    });
  });

  it("rejects absent, untrusted, stale, or misbound evidence", () => {
    expect(evaluateUserGestureEvidence({
      evidence: null,
      expectedTargetId: "camera-permission-control",
      referenceEpochMs: 20_000,
    }).acceptedForFuturePromptPreparation).toBe(false);

    const evidence = createUserGestureEvidence({
      evidenceId: "unsafe-gesture-evidence",
      targetId: "other-control",
      gestureKind: "keyboard_activation",
      occurredAtEpochMs: 1_000,
      trustedEvent: false,
      repeatedActivation: true,
    });
    expect(evaluateUserGestureEvidence({
      evidence,
      expectedTargetId: "camera-permission-control",
      referenceEpochMs: 20_000,
    })).toMatchObject({
      trustedEventSatisfied: false,
      targetBindingSatisfied: false,
      freshnessSatisfied: false,
      acceptedForFuturePromptPreparation: false,
    });
  });
});
