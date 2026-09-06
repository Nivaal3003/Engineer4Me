import { assertIssuedProcessingDossierController } from "./scoped-processing-dossier";
import type { ProcessingDossierController, ProcessingDossierHandle } from "./scoped-processing-dossier";
/** Completeness is not verified evidence, consent, provider selection or execution approval. */
export function evaluateProcessingEvidenceReadiness(controller: ProcessingDossierController, handle: ProcessingDossierHandle, tick: number) {
  assertIssuedProcessingDossierController(controller);
  const snapshot = controller.inspect(handle, tick);
  return Object.freeze({
    dossierId: snapshot.dossierId, revision: snapshot.revision, generation: snapshot.generation,
    planningDeclarationsComplete: snapshot.state === "declarations_complete_intervention_required",
    acceptedDeclarationCount: snapshot.acceptedDeclarationCount,
    missingCategories: snapshot.missingCategories, rejectedCategories: snapshot.rejectedCategories,
    expiredCategories: snapshot.expiredCategories, needsReviewCategories: snapshot.needsReviewCategories,
    state: snapshot.state, evidenceContentVerified: false as const, reviewerAuthenticated: false as const,
    providerSelectedByApplication: false as const, legalApprovalEstablished: false as const,
    consentRecorded: false as const, executionApprovalEstablished: false as const,
    liveTranscriptionRuntimePresent: false as const, executionAuthorized: false as const,
    blockersNotSatisfiedByDeclarations: Object.freeze(["independent_evidence_validation", "processing_approach_selection", "fresh_processing_consent", "explicit_execution_approval", "reviewed_runtime_implementation"] as const),
    furtherInterventionRequired: true as const, simulationTicksOnly: true as const,
  });
}
