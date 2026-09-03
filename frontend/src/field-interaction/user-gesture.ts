import { validateFieldInteractionIdentifier } from "./models";

export const USER_GESTURE_KINDS = [
  "button_click",
  "keyboard_activation",
  "pointer_release",
] as const;

export type UserGestureKind = (typeof USER_GESTURE_KINDS)[number];

export interface UserGestureEvidence {
  readonly evidenceId: string;
  readonly targetId: string;
  readonly gestureKind: UserGestureKind;
  readonly occurredAtEpochMs: number;
  readonly trustedEvent: boolean;
  readonly defaultPrevented: boolean;
  readonly repeatedActivation: boolean;
  readonly evidenceConsumed: false;
  readonly permissionRequestPerformed: false;
}

export interface UserGestureEvaluation {
  readonly evidencePresent: boolean;
  readonly trustedEventSatisfied: boolean;
  readonly targetBindingSatisfied: boolean;
  readonly freshnessSatisfied: boolean;
  readonly singleUseSatisfied: boolean;
  readonly acceptedForFuturePromptPreparation: boolean;
  readonly maximumAgeMs: number;
  readonly ageMs: number | null;
  readonly blockingReasons: readonly string[];
  readonly interventionRequired: true;
  readonly activationAuthorized: false;
  readonly permissionPromptShown: false;
}

function safeEpochMs(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
  return value;
}

export function createUserGestureEvidence(input: {
  readonly evidenceId: string;
  readonly targetId: string;
  readonly gestureKind: UserGestureKind;
  readonly occurredAtEpochMs: number;
  readonly trustedEvent: boolean;
  readonly defaultPrevented?: boolean;
  readonly repeatedActivation?: boolean;
}): UserGestureEvidence {
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "User-gesture evidence identifier",
    ),
    targetId: validateFieldInteractionIdentifier(
      input.targetId,
      "User-gesture target identifier",
    ),
    gestureKind: input.gestureKind,
    occurredAtEpochMs: safeEpochMs(input.occurredAtEpochMs, "Gesture timestamp"),
    trustedEvent: input.trustedEvent,
    defaultPrevented: input.defaultPrevented ?? false,
    repeatedActivation: input.repeatedActivation ?? false,
    evidenceConsumed: false,
    permissionRequestPerformed: false,
  });
}

export function evaluateUserGestureEvidence(input: {
  readonly evidence: UserGestureEvidence | null;
  readonly expectedTargetId: string;
  readonly referenceEpochMs: number;
  readonly maximumAgeMs?: number;
}): UserGestureEvaluation {
  const expectedTargetId = validateFieldInteractionIdentifier(
    input.expectedTargetId,
    "Expected user-gesture target identifier",
  );
  const referenceEpochMs = safeEpochMs(input.referenceEpochMs, "Gesture reference timestamp");
  const maximumAgeMs = input.maximumAgeMs ?? 5_000;
  if (!Number.isSafeInteger(maximumAgeMs) || maximumAgeMs <= 0 || maximumAgeMs > 30_000) {
    throw new Error("User-gesture maximum age must be between 1 and 30000 milliseconds.");
  }

  const reasons: string[] = [];
  const evidence = input.evidence;
  const evidencePresent = evidence !== null;
  const trustedEventSatisfied = evidence?.trustedEvent === true
    && evidence.defaultPrevented === false
    && evidence.repeatedActivation === false;
  const targetBindingSatisfied = evidence?.targetId === expectedTargetId;
  const ageMs = evidence === null ? null : referenceEpochMs - evidence.occurredAtEpochMs;
  const freshnessSatisfied = ageMs !== null && ageMs >= 0 && ageMs <= maximumAgeMs;
  const singleUseSatisfied = evidence?.evidenceConsumed === false;

  if (!evidencePresent) reasons.push("A trusted user gesture has not been recorded.");
  if (evidencePresent && !trustedEventSatisfied) {
    reasons.push("The gesture is not an accepted trusted, non-repeated activation event.");
  }
  if (evidencePresent && !targetBindingSatisfied) {
    reasons.push("The gesture is not bound to the intended permission control.");
  }
  if (evidencePresent && !freshnessSatisfied) {
    reasons.push("The gesture is stale or has a timestamp later than the evaluation reference.");
  }
  if (evidencePresent && !singleUseSatisfied) {
    reasons.push("The gesture evidence has already been consumed.");
  }

  const acceptedForFuturePromptPreparation =
    evidencePresent
    && trustedEventSatisfied
    && targetBindingSatisfied
    && freshnessSatisfied
    && singleUseSatisfied;

  if (acceptedForFuturePromptPreparation) {
    reasons.push("Gesture evidence is eligible for a future controlled prompt gate only.");
  }

  return Object.freeze({
    evidencePresent,
    trustedEventSatisfied,
    targetBindingSatisfied,
    freshnessSatisfied,
    singleUseSatisfied,
    acceptedForFuturePromptPreparation,
    maximumAgeMs,
    ageMs,
    blockingReasons: Object.freeze(reasons),
    interventionRequired: true,
    activationAuthorized: false,
    permissionPromptShown: false,
  });
}
