import { describe, expect, it } from "vitest";
import { createProcessingCandidateScope } from "./processing-candidate-scope";
import { assertIssuedProcessingReviewDeclaration, createProcessingReviewDeclaration, PROCESSING_REVIEW_CATEGORIES } from "./processing-review-declaration";
const scope = () => createProcessingCandidateScope({ dossierId: "dossier-review", revision: 1, mode: "local_only_candidate", processingRef: "engine", processingRevision: "v1", processingRevisionSha256: "a".repeat(64), deploymentRef: "local", dataLocationRef: "device", retentionPolicySha256: "b".repeat(64), languageTag: "en", purpose: "transcription_evaluation_only" });
const input = () => ({ category: "license", referenceId: "license-review", referenceRevision: "v1", declaredSha256: "c".repeat(64), decision: "accepted_for_planning", validForSimulationTicks: 100 });
describe("scope-bound processing review declarations", () => {
  it("supports exactly eight review categories", () => {
    expect(PROCESSING_REVIEW_CATEGORIES).toHaveLength(8); const target = scope();
    for (const category of PROCESSING_REVIEW_CATEGORIES) expect(createProcessingReviewDeclaration(target, { ...input(), category }).category).toBe(category);
  });
  it("never establishes content validation or reviewer authority", () => {
    const target = scope(), value = createProcessingReviewDeclaration(target, input());
    expect(value.dossierId).toBe(target.dossierId); expect(value.scopeRevision).toBe(1); expect(Object.isFrozen(value)).toBe(true);
    expect(value.referenceContentRead).toBe(false); expect(value.referenceContentVerified).toBe(false); expect(value.reviewerAuthenticated).toBe(false); expect(value.legalOrSecurityApprovalEstablished).toBe(false);
    expect(() => assertIssuedProcessingReviewDeclaration(value, target)).not.toThrow();
  });
  it("rejects a copied declaration and a different issued scope", () => {
    const target = scope(), value = createProcessingReviewDeclaration(target, input());
    expect(() => assertIssuedProcessingReviewDeclaration({ ...value }, target)).toThrow(/not issued/);
    expect(() => assertIssuedProcessingReviewDeclaration(value, scope())).toThrow(/not issued/);
  });
  it("rejects unknown categories, acceptance coercion and invalid validity bounds", () => {
    const target = scope();
    for (const change of [{ category: "execution" }, { decision: true }, { decision: "approved_to_execute" }, { validForSimulationTicks: 0 }, { validForSimulationTicks: 60001 }, { validForSimulationTicks: Infinity }, { declaredSha256: "z".repeat(64) }]) {
      expect(() => createProcessingReviewDeclaration(target, { ...input(), ...change })).toThrow();
    }
  });
  it("rejects accessors and additional consent fields without invoking accessors", () => {
    const target = scope(), raw = input(); let calls = 0;
    Object.defineProperty(raw, "decision", { enumerable: true, get() { calls += 1; return "accepted_for_planning"; } });
    expect(() => createProcessingReviewDeclaration(target, raw)).toThrow(/data fields/); expect(calls).toBe(0);
    expect(() => createProcessingReviewDeclaration(target, { ...input(), consent: true })).toThrow(/inventory/);
  });
});
