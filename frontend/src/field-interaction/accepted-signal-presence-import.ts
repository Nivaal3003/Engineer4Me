/** Historical, minimized evidence only; a signal result contains no transcript. */
export const ACCEPTED_SIGNAL_EVIDENCE = Object.freeze({
  commit: "8d3f7ffc7b6f426070dac9b1e39bcadab363c06e",
  tree: "5550068bfbbece59b31a9a6794575972efb20e7c",
  acceptanceSha256: "9e2af99af8126708d15f12ecf2e506086f3f4202995c065772414fe3b6233b82",
  receiptSha256: "cca6df5e65dbee851aa207cb989baed0366b275d3da096a792a56880de053d88",
  outcome: "signal_absent",
} as const);

export function importAcceptedSignalPresence(input: unknown) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Historical signal evidence must be an object.");
  }
  const value = input as Record<string, unknown>;
  const expected = ACCEPTED_SIGNAL_EVIDENCE;
  if (Object.keys(value).sort().join("|") !== Object.keys(expected).sort().join("|")) {
    throw new Error("Historical signal evidence field inventory differs.");
  }
  for (const key of Object.keys(expected) as (keyof typeof expected)[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.value !== expected[key]) {
      throw new Error("Historical signal evidence identity differs.");
    }
  }
  return Object.freeze({
    ...expected,
    provenance: "pinned_historical_verifier_identity" as const,
    bindingScope: "metadata_identity_only" as const,
    archiveBytesVerifiedByThisFunction: false as const,
    receiptBytesVerifiedByThisFunction: false as const,
    currentPermissionState: "unknown" as const,
    interpretation: "one_frame_did_not_cross_the_reviewed_threshold" as const,
    microphoneFailureEstablished: false as const,
    speechAbsenceEstablished: false as const,
    transcriptAvailableFromSignalResult: false as const,
    transcriptionAuthorized: false as const,
    newCaptureAuthorized: false as const,
    automaticRetryAuthorized: false as const,
    operationExecutionAuthorized: false as const,
  });
}
