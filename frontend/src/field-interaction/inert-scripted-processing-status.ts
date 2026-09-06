import { createUnconfiguredTranscriptProcessingReadiness } from "./transcript-processing-readiness";
import { SCRIPTED_PROCESSING_LIMITS } from "./scripted-processing-policy";
/** Presentation metadata only; this object exposes no controller or execution operation. */
export function createInertScriptedProcessingStatus() {
  return Object.freeze({ mode: "scripted_fixture_simulation_only" as const,
    limits: SCRIPTED_PROCESSING_LIMITS, readiness: createUnconfiguredTranscriptProcessingReadiness(),
    timersInstalled: false as const, applicationControlsActive: false as const,
    providerSelected: false as const, providerOperationAvailable: false as const,
    backgroundProcessingAvailable: false as const, liveTranscriptAccepted: false as const,
    authenticatedApprovalEstablished: false as const, executionAuthorized: false as const,
    retainedTranscriptContent: null, furtherTranscriptionInterventionGateRequired: true as const });
}
