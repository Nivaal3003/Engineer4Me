/** Planning evidence only: no provider selection or transcription operation. */
export const TRANSCRIPT_PROCESSING_GATE_KEYS = Object.freeze([
  "providerSelection", "licenseReview", "privacyReview", "dataLocationReview",
  "retentionAndDeletionReview", "languageAndQualityReview", "cancellationReview",
  "securityReview", "freshProcessingConsent", "explicitExecutionApproval",
] as const);
export type TranscriptProcessingGate = (typeof TRANSCRIPT_PROCESSING_GATE_KEYS)[number];
export function evaluateTranscriptProcessingReadiness(input: unknown) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("Processing gate evidence must be an object.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).sort().join("|") !== [...TRANSCRIPT_PROCESSING_GATE_KEYS].sort().join("|")) {
    throw new Error("Processing gate evidence inventory differs.");
  }
  for (const key of TRANSCRIPT_PROCESSING_GATE_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "boolean") {
      throw new Error("Processing gates require own boolean data fields.");
    }
  }
  const missing = TRANSCRIPT_PROCESSING_GATE_KEYS.filter((key) => value[key] !== true);
  return Object.freeze({
    state: missing.length > 0 ? "evidence_required" as const : "intervention_required" as const,
    missingGates: Object.freeze(missing), evidenceIsCallerSupplied: true as const,
    permissionStateInferred: false as const, providerSelectedByApplication: false as const,
    runtimeImplementationPresent: false as const, executionAuthorized: false as const,
    consentRecordedByApplication: false as const, speechToTextPerformed: false as const,
    localAiCalled: false as const, externalAiCalled: false as const,
    newCaptureAuthorized: false as const, automaticRetryAuthorized: false as const,
  });
}
export function createUnconfiguredTranscriptProcessingReadiness() {
  return evaluateTranscriptProcessingReadiness(Object.fromEntries(TRANSCRIPT_PROCESSING_GATE_KEYS.map((key) => [key, false])));
}
