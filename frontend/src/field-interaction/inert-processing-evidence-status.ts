import { PROCESSING_REVIEW_CATEGORIES } from "./processing-review-declaration";
export function createInertProcessingEvidenceStatus() {
  return Object.freeze({ state: "not_configured" as const, requiredReviewCategories: PROCESSING_REVIEW_CATEGORIES,
    activeDossierCount: 0 as const, providerSelected: false as const, evidenceContentVerified: false as const,
    reviewerAuthenticated: false as const, consentRecorded: false as const, executionAuthorized: false as const,
    dossierInputOperationAvailable: false as const, transcriptionOperationAvailable: false as const,
    networkOperationAvailable: false as const, applicationControlsActive: false as const,
    historicalMicrophoneCheckRepeated: false as const, furtherInterventionRequired: true as const });
}
