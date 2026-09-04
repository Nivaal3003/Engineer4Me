import {
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
  MICROPHONE_PERMISSION_PURPOSE,
  type PermissionConsentEvidence,
} from "./permission-consent-evidence";

export const MICROPHONE_PERMISSION_CONSENT_MAXIMUM_AGE_MS = 300_000 as const;

export interface PermissionConsentEvaluation {
  readonly evidencePresent: boolean;
  readonly exactDisclosureSatisfied: boolean;
  readonly purposeLimitationSatisfied: boolean;
  readonly affirmativeDecisionSatisfied: boolean;
  readonly explicitUserInitiatedDecisionSatisfied: boolean;
  readonly freshnessSatisfied: boolean;
  readonly singleUseSatisfied: boolean;
  readonly acceptedForFuturePromptGate: boolean;
  readonly ageMs: number | null;
  readonly maximumAgeMs: typeof MICROPHONE_PERMISSION_CONSENT_MAXIMUM_AGE_MS;
  readonly consentRequired: true;
  readonly cameraConsentAccepted: false;
  readonly permissionPromptAuthorized: false;
  readonly captureAuthorized: false;
  readonly interventionRequired: true;
  readonly blockingReasons: readonly string[];
}

function safeReferenceEpochMs(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Consent reference timestamp must be a non-negative safe integer.");
  }
  return value;
}

export function evaluateMicrophonePermissionConsent(input: {
  readonly evidence: PermissionConsentEvidence | null;
  readonly referenceEpochMs: number;
}): PermissionConsentEvaluation {
  const referenceEpochMs = safeReferenceEpochMs(input.referenceEpochMs);
  const evidence = input.evidence;
  const evidencePresent = evidence !== null && evidence.decision !== "not_recorded";
  const exactDisclosureSatisfied = evidence !== null
    && evidence.disclosureVersion === MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION
    && evidence.disclosureSha256 === MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256;
  const purposeLimitationSatisfied = evidence?.purpose === MICROPHONE_PERMISSION_PURPOSE;
  const affirmativeDecisionSatisfied = evidence?.decision === "affirmative";
  const explicitUserInitiatedDecisionSatisfied = evidence?.explicit === true
    && evidence.userInitiated === true;
  const ageMs = evidence?.occurredAtEpochMs === null || evidence?.occurredAtEpochMs === undefined
    ? null
    : referenceEpochMs - evidence.occurredAtEpochMs;
  const freshnessSatisfied = ageMs !== null
    && ageMs >= 0
    && ageMs <= MICROPHONE_PERMISSION_CONSENT_MAXIMUM_AGE_MS;
  const singleUseSatisfied = evidence?.evidenceConsumed === false;
  const blockingReasons: string[] = [];

  if (!evidencePresent) blockingReasons.push("Explicit microphone permission consent has not been recorded.");
  if (evidencePresent && !exactDisclosureSatisfied) blockingReasons.push("The consent disclosure identity differs.");
  if (evidencePresent && !purposeLimitationSatisfied) blockingReasons.push("The consent purpose limitation differs.");
  if (evidencePresent && !affirmativeDecisionSatisfied) blockingReasons.push("Affirmative consent is absent or has been withdrawn.");
  if (evidencePresent && !explicitUserInitiatedDecisionSatisfied) blockingReasons.push("Consent is not an explicit user-initiated decision.");
  if (evidencePresent && !freshnessSatisfied) blockingReasons.push("Consent is stale or has a future timestamp.");
  if (evidencePresent && !singleUseSatisfied) blockingReasons.push("Consent evidence has already been consumed.");

  const acceptedForFuturePromptGate = evidencePresent
    && exactDisclosureSatisfied
    && purposeLimitationSatisfied
    && affirmativeDecisionSatisfied
    && explicitUserInitiatedDecisionSatisfied
    && freshnessSatisfied
    && singleUseSatisfied;

  if (acceptedForFuturePromptGate) {
    blockingReasons.push("Consent evidence is eligible for a separate future prompt-execution gate only.");
  }

  return Object.freeze({
    evidencePresent,
    exactDisclosureSatisfied,
    purposeLimitationSatisfied,
    affirmativeDecisionSatisfied,
    explicitUserInitiatedDecisionSatisfied,
    freshnessSatisfied,
    singleUseSatisfied,
    acceptedForFuturePromptGate,
    ageMs,
    maximumAgeMs: MICROPHONE_PERMISSION_CONSENT_MAXIMUM_AGE_MS,
    consentRequired: true,
    cameraConsentAccepted: false,
    permissionPromptAuthorized: false,
    captureAuthorized: false,
    interventionRequired: true,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
