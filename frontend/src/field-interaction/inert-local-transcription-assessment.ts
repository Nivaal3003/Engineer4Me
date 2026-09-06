import { LOCAL_FIRST_TRANSCRIPTION_DECISION } from "./local-first-transcription-decision";
/** No callbacks, executable paths or network endpoints are exposed. */
export function localTranscriptionAssessmentStatus() {
  return Object.freeze({
    direction: LOCAL_FIRST_TRANSCRIPTION_DECISION.assessmentRoute,
    firstCandidate: LOCAL_FIRST_TRANSCRIPTION_DECISION.firstAssessmentCandidate,
    ownerDirectionRecorded: true,
    directionApprovalIsExecutionApproval: false,
    implementationScope: "artifact_declarations_and_measurement_review_only",
    unresolvedGates: Object.freeze(["exact_artifact_bytes_and_provenance", "prerelease_and_security_review",
      "license_and_dependency_review", "host_and_mobile_capability_review", "runtime_isolation_and_cancellation",
      "rights_cleared_evaluation_inputs", "explicit_acquisition_approval", "fresh_speech_execution_approval"] as const),
    downloadOperationAvailable: false, processLaunchOperationAvailable: false,
    sampleReadOperationAvailable: false, speechOperationAvailable: false,
    automaticCloudFallbackAvailable: false, manualTextAlternativeRetained: true,
  } as const);
}
