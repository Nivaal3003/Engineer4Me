/** Evidence and approval contracts retained across Engineer4Me UI boundaries. */
export type ConfidenceLevel = "unknown" | "low" | "medium" | "high";

export type EvidenceVerificationStatus =
  | "unverified"
  | "partially_verified"
  | "verified";

export type EngineeringApprovalStatus =
  | "not_requested"
  | "draft"
  | "under_review"
  | "approved"
  | "rejected"
  | "superseded";

export interface EvidenceReferenceViewModel {
  readonly referenceId: string;
  readonly title: string;
  readonly sourceType: string;
  readonly verificationStatus: EvidenceVerificationStatus;
  readonly revision?: string;
  readonly locator?: string;
}

export interface ConfidenceViewModel {
  readonly level: ConfidenceLevel;
  readonly scorePercent?: number;
  readonly basis: readonly string[];
}

export interface RevisionViewModel {
  readonly revision: string;
  readonly status: EngineeringApprovalStatus;
  readonly owner: string;
  readonly changedAt?: string;
}

export interface EngineeringEvidenceViewModel {
  readonly evidence: readonly EvidenceReferenceViewModel[];
  readonly confidence: ConfidenceViewModel;
  readonly assumptions: readonly string[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
  readonly revision: RevisionViewModel;
  readonly standardsConformityClaim: "not_claimed";
  readonly finalEngineeringApprovalOwner: "user_or_authorized_organisation";
}
