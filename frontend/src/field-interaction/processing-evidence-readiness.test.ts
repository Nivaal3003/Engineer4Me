import { describe, expect, it } from "vitest";
import { createProcessingCandidateScope } from "./processing-candidate-scope";
import { createProcessingReviewDeclaration, PROCESSING_REVIEW_CATEGORIES } from "./processing-review-declaration";
import { createProcessingDossierController } from "./scoped-processing-dossier";
import { evaluateProcessingEvidenceReadiness } from "./processing-evidence-readiness";
const setup = () => {
  const scope = createProcessingCandidateScope({ dossierId: "readiness-one", revision: 1, mode: "local_only_candidate", processingRef: "engine", processingRevision: "v1", processingRevisionSha256: "a".repeat(64), deploymentRef: "local", dataLocationRef: "device", retentionPolicySha256: "b".repeat(64), languageTag: "en", purpose: "transcription_evaluation_only" });
  const controller = createProcessingDossierController(), handle = controller.open(scope, 0);
  return { scope, controller, handle };
};
describe("declared processing evidence readiness", () => {
  it("keeps independent verification, consent, selection and execution gates after all declarations", () => {
    const { scope, controller, handle } = setup();
    for (const category of PROCESSING_REVIEW_CATEGORIES) controller.declareReview(handle, createProcessingReviewDeclaration(scope, { category, referenceId: category, referenceRevision: "r1", declaredSha256: "c".repeat(64), decision: "accepted_for_planning", validForSimulationTicks: 2 }), 0);
    const value = evaluateProcessingEvidenceReadiness(controller, handle, 0);
    expect(value.planningDeclarationsComplete).toBe(true); expect(value.blockersNotSatisfiedByDeclarations).toHaveLength(5);
    for (const key of ["evidenceContentVerified", "reviewerAuthenticated", "providerSelectedByApplication", "legalApprovalEstablished", "consentRecorded", "executionApprovalEstablished", "liveTranscriptionRuntimePresent", "executionAuthorized"] as const) expect(value[key]).toBe(false);
    expect(value.furtherInterventionRequired).toBe(true); expect(value.simulationTicksOnly).toBe(true);
    expect(evaluateProcessingEvidenceReadiness(controller, handle, 2).planningDeclarationsComplete).toBe(false);
  });
  it("does not accept a copied or caller-implemented controller", () => {
    const { controller, handle } = setup(); expect(() => evaluateProcessingEvidenceReadiness({ ...controller }, handle, 0)).toThrow(/unissued/);
  });
  it("retains exact missing categories and immutable output", () => {
    const { controller, handle } = setup(); const value = evaluateProcessingEvidenceReadiness(controller, handle, 0);
    expect(value.missingCategories).toEqual(PROCESSING_REVIEW_CATEGORIES); expect(Object.isFrozen(value)).toBe(true); expect(Object.isFrozen(value.missingCategories)).toBe(true);
  });
});
