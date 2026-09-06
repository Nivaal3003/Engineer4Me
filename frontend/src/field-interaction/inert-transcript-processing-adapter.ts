import { createUnconfiguredTranscriptProcessingReadiness } from "./transcript-processing-readiness";
export function createInertTranscriptProcessingAdapter() {
  return Object.freeze({
    kind: "inert_transcript_processing" as const,
    readiness: createUnconfiguredTranscriptProcessingReadiness(),
    operations: Object.freeze([] as readonly never[]),
    counters: Object.freeze({ microphoneRequests: 0, sampleReads: 0, transcriptServiceRequests: 0,
      localAiRequests: 0, externalAiRequests: 0, backendRequests: 0, executionRequests: 0 }),
    historicalSignalDoesNotContainWords: true as const,
    automaticRetryEnabled: false as const,
    manualOrScriptedReviewContractsAvailable: true as const,
    activeApplicationReviewUi: false as const,
    liveTranscriptionAvailable: false as const,
    protectedContentAccessed: false as const,
    operationExecutionAuthorized: false as const,
  });
}
