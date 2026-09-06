import { describe, expect, it } from "vitest";
import { createProcessingCandidateScope } from "./processing-candidate-scope";
import type { ProcessingCandidateScope } from "./processing-candidate-scope";
import { createProcessingReviewDeclaration, PROCESSING_REVIEW_CATEGORIES } from "./processing-review-declaration";
import type { ProcessingReviewCategory } from "./processing-review-declaration";
import { createProcessingDossierController } from "./scoped-processing-dossier";
import type { ProcessingDossierController, ProcessingDossierHandle } from "./scoped-processing-dossier";
const input = (dossierId = "dossier-one", revision = 1) => ({ dossierId, revision, mode: "local_only_candidate", processingRef: "engine", processingRevision: "v1", processingRevisionSha256: "a".repeat(64), deploymentRef: "local", dataLocationRef: "device", retentionPolicySha256: "b".repeat(64), languageTag: "en", purpose: "transcription_evaluation_only" });
const declaration = (scope: ProcessingCandidateScope, category: ProcessingReviewCategory = "license", decision = "accepted_for_planning", ticks = 100) => createProcessingReviewDeclaration(scope, { category, referenceId: category + "-reference", referenceRevision: "r1", declaredSha256: "c".repeat(64), decision, validForSimulationTicks: ticks });
function complete(controller: ProcessingDossierController, handle: ProcessingDossierHandle, scope: ProcessingCandidateScope) {
  for (const category of PROCESSING_REVIEW_CATEGORIES) controller.declareReview(handle, declaration(scope, category), 0);
  return controller.issuePlanningTicket(handle, 0);
}
describe("revocable scope-bound processing dossiers", () => {
  it("starts missing and never authorizes execution after all declarations", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0);
    expect(controller.inspect(handle, 0).missingCategories).toHaveLength(8);
    expect(() => controller.issuePlanningTicket(handle, 0)).toThrow(/incomplete/);
    const ticket = complete(controller, handle, scope); expect(controller.issuePlanningTicket(handle, 1)).toBe(ticket);
    const ready = controller.inspect(handle, 1); expect(ready.state).toBe("declarations_complete_intervention_required");
    expect(ready.acceptedDeclarationCount).toBe(8); expect(ready.executionAuthorized).toBe(false); expect(ticket.executionAuthorized).toBe(false);
    expect(ready.referencesVerified).toBe(false); expect(ready.authenticatedReviewEstablished).toBe(false); expect(ready.freshProcessingConsentRecorded).toBe(false);
  });
  it("rejects duplicate active identifiers and the ninth active dossier", () => {
    const controller = createProcessingDossierController(), handles: ProcessingDossierHandle[] = [];
    for (let index = 0; index < 8; index += 1) handles.push(controller.open(createProcessingCandidateScope(input("dossier-" + index)), 0));
    expect(() => controller.open(createProcessingCandidateScope(input("dossier-0")), 0)).toThrow(/already active/);
    expect(() => controller.open(createProcessingCandidateScope(input("dossier-8")), 0)).toThrow(/eight/);
    controller.discard(handles[0]!, 0); expect(() => controller.open(createProcessingCandidateScope(input("dossier-8")), 0)).not.toThrow();
  });
  it("rejects copied or cross-controller handles and planning tickets", () => {
    const one = createProcessingDossierController(), two = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = one.open(scope, 0), ticket = complete(one, handle, scope);
    expect(() => one.inspect({ ...handle }, 0)).toThrow(/unissued/);
    expect(() => two.inspect(handle, 0)).toThrow(/unissued/);
    expect(() => one.assertCurrentPlanningTicket(handle, { ...ticket }, 0)).toThrow(/unissued/);
    const second = two.open(scope, 0); complete(two, second, scope);
    expect(() => two.assertCurrentPlanningTicket(second, ticket, 0)).toThrow(/unissued/);
  });
  it("invalidates an issued ticket when a review is replaced, including same reference", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), ticket = complete(controller, handle, scope);
    controller.declareReview(handle, declaration(scope), 1);
    expect(() => controller.assertCurrentPlanningTicket(handle, ticket, 1)).toThrow(/stale/);
    const next = controller.issuePlanningTicket(handle, 1); expect(next).not.toBe(ticket); expect(next.executionAuthorized).toBe(false);
  });
  it("does not allow the same declaration object to refresh its simulated expiry", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), review = declaration(scope);
    controller.declareReview(handle, review, 0);
    expect(() => controller.declareReview(handle, review, 50)).toThrow(/reused/);
    expect(controller.inspect(handle, 100).expiredCategories).toEqual(["license"]);
  });
  it("revocation blocks tickets even after a replacement declaration", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), ticket = complete(controller, handle, scope);
    controller.revokeReview(handle, "license", 1);
    expect(() => controller.assertCurrentPlanningTicket(handle, ticket, 1)).toThrow(/revoked/);
    controller.declareReview(handle, declaration(scope), 1);
    expect(() => controller.assertCurrentPlanningTicket(handle, ticket, 1)).toThrow(/stale/);
    expect(() => controller.assertCurrentPlanningTicket(handle, controller.issuePlanningTicket(handle, 1), 1)).not.toThrow();
  });
  it("expires at the inclusive simulated deadline, not one tick later", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), ticket = complete(controller, handle, scope);
    expect(() => controller.assertCurrentPlanningTicket(handle, ticket, 99)).not.toThrow();
    expect(() => controller.assertCurrentPlanningTicket(handle, ticket, 100)).toThrow(/expired/);
    expect(controller.inspect(handle, 100).expiredCategories).toHaveLength(8);
  });
  it("reports rejected and needs-review declarations separately", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0);
    controller.declareReview(handle, declaration(scope, "license", "rejected"), 0);
    controller.declareReview(handle, declaration(scope, "privacy", "needs_review"), 0);
    const state = controller.inspect(handle, 0); expect(state.rejectedCategories).toEqual(["license"]); expect(state.needsReviewCategories).toEqual(["privacy"]); expect(state.missingCategories).toHaveLength(6);
    expect(() => controller.issuePlanningTicket(handle, 0)).toThrow(/incomplete/);
  });
  it("rejects backwards, fractional and out-of-range simulation time", () => {
    const controller = createProcessingDossierController(), handle = controller.open(createProcessingCandidateScope(input()), 10);
    for (const tick of [9, -1, 10.5, NaN, Infinity, 1000000001]) expect(() => controller.inspect(handle, tick)).toThrow();
    expect(controller.inspect(handle, 10).simulationTicksOnly).toBe(true);
  });
  it("requires an exact next revision and the original dossier identifier", () => {
    const controller = createProcessingDossierController(), handle = controller.open(createProcessingCandidateScope(input()), 0);
    for (const raw of [input(), input("dossier-one", 3), input("changed-id", 2)]) expect(() => controller.revise(handle, createProcessingCandidateScope(raw), 0)).toThrow(/exactly once/);
    expect(controller.inspect(handle, 0).revision).toBe(1);
  });
  it("discard invalidates tickets; reopening a name does not restore them", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), ticket = complete(controller, handle, scope);
    controller.discard(handle, 0); expect(() => controller.inspect(handle, 0)).toThrow(/discarded/);
    const next = controller.open(scope, 0); complete(controller, next, scope);
    expect(() => controller.assertCurrentPlanningTicket(next, ticket, 0)).toThrow(/unissued/);
  });
  it("rejects unknown revocation categories and declarations bound to another scope", () => {
    const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0);
    expect(() => controller.revokeReview(handle, "execution" as ProcessingReviewCategory, 0)).toThrow(/category/);
    expect(() => controller.revokeReview(handle, "license", 0)).toThrow(/No declared/);
    expect(() => controller.declareReview(handle, declaration(createProcessingCandidateScope(input())), 0)).toThrow(/not issued/);
  });
  for (const [field, value] of [["mode", "external_service_candidate"], ["processingRef", "other-engine"], ["processingRevision", "v2"], ["processingRevisionSha256", "d".repeat(64)], ["deploymentRef", "other-deployment"], ["dataLocationRef", "other-location"], ["retentionPolicySha256", "e".repeat(64)], ["languageTag", "fr"]] as const) {
    it("invalidates every review and ticket after a " + field + " revision", () => {
      const controller = createProcessingDossierController(), scope = createProcessingCandidateScope(input()), handle = controller.open(scope, 0), ticket = complete(controller, handle, scope);
      const oldReview = declaration(scope), nextScope = createProcessingCandidateScope({ ...input("dossier-one", 2), [field]: value });
      const next = controller.revise(handle, nextScope, 1);
      expect(controller.inspect(next, 1).missingCategories).toHaveLength(8);
      expect(() => controller.inspect(handle, 1)).toThrow(/superseded/);
      expect(() => controller.assertCurrentPlanningTicket(next, ticket, 1)).toThrow(/stale|unissued/);
      expect(() => controller.declareReview(next, oldReview, 1)).toThrow(/not issued/);
    });
  }
});
