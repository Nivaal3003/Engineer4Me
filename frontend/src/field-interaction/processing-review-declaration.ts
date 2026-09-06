import { assertIssuedProcessingCandidateScope, processingEvidenceDataRecord, processingEvidenceDigest, processingEvidenceIdentifier, processingEvidenceInteger } from "./processing-candidate-scope";
import type { ProcessingCandidateScope } from "./processing-candidate-scope";
export const PROCESSING_REVIEW_CATEGORIES = Object.freeze([
  "provider_identity", "license", "privacy", "data_location", "retention_deletion", "language_quality", "cancellation", "security",
] as const);
export type ProcessingReviewCategory = (typeof PROCESSING_REVIEW_CATEGORIES)[number];
export type ProcessingPlanningDecision = "accepted_for_planning" | "needs_review" | "rejected";
export interface ProcessingReviewDeclaration {
  readonly dossierId: string;
  readonly scopeRevision: number;
  readonly category: ProcessingReviewCategory;
  readonly referenceId: string;
  readonly referenceRevision: string;
  readonly declaredSha256: string;
  readonly decision: ProcessingPlanningDecision;
  readonly validForSimulationTicks: number;
  readonly referenceContentRead: false;
  readonly referenceContentVerified: false;
  readonly reviewerAuthenticated: false;
  readonly legalOrSecurityApprovalEstablished: false;
}
const issued = new WeakMap<object, ProcessingCandidateScope>();
export function assertProcessingReviewCategory(value: unknown): asserts value is ProcessingReviewCategory {
  if (typeof value !== "string" || !(PROCESSING_REVIEW_CATEGORIES as readonly string[]).includes(value)) throw new Error("Processing review category differs.");
}
export function createProcessingReviewDeclaration(scope: ProcessingCandidateScope, input: unknown): ProcessingReviewDeclaration {
  assertIssuedProcessingCandidateScope(scope);
  const value = processingEvidenceDataRecord(input, ["category", "referenceId", "referenceRevision", "declaredSha256", "decision", "validForSimulationTicks"]);
  assertProcessingReviewCategory(value.category);
  if (value.decision !== "accepted_for_planning" && value.decision !== "needs_review" && value.decision !== "rejected") throw new Error("Processing planning decision differs.");
  const result: ProcessingReviewDeclaration = Object.freeze({ dossierId: scope.dossierId, scopeRevision: scope.revision, category: value.category, referenceId: processingEvidenceIdentifier(value.referenceId),
    referenceRevision: processingEvidenceIdentifier(value.referenceRevision), declaredSha256: processingEvidenceDigest(value.declaredSha256),
    decision: value.decision, validForSimulationTicks: processingEvidenceInteger(value.validForSimulationTicks, 1, 60000),
    referenceContentRead: false, referenceContentVerified: false, reviewerAuthenticated: false, legalOrSecurityApprovalEstablished: false });
  issued.set(result, scope);
  return result;
}
export function assertIssuedProcessingReviewDeclaration(value: ProcessingReviewDeclaration, scope: ProcessingCandidateScope): void {
  if (issued.get(value) !== scope) throw new Error("Processing review declaration was not issued in this memory-only session.");
}
