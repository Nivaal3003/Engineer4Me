export type ConfidenceLevel = "not_assessed" | "low" | "medium" | "high";
export type ApprovalStatus = "unreviewed" | "review_required" | "approved" | "rejected";

export interface EvidenceReference {
  readonly sourceId: string;
  readonly title: string;
  readonly revision: string | null;
  readonly locator: string | null;
}

export interface ApprovalRecord {
  readonly status: ApprovalStatus;
  readonly owner: string;
  readonly approvedAt: string | null;
}

export interface EvidenceEnvelope<T> {
  readonly value: T;
  readonly evidence: readonly EvidenceReference[];
  readonly assumptions: readonly string[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
  readonly confidence: ConfidenceLevel;
  readonly revision: string;
  readonly approval: ApprovalRecord;
}

function nonBlank(label: string, value: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${label} must not be blank.`);
  }
  return normalized;
}

export function createUnreviewedEvidenceEnvelope<T>(input: {
  readonly value: T;
  readonly revision: string;
  readonly approvalOwner: string;
  readonly evidence?: readonly EvidenceReference[];
  readonly assumptions?: readonly string[];
  readonly limitations?: readonly string[];
  readonly warnings?: readonly string[];
  readonly confidence?: ConfidenceLevel;
}): EvidenceEnvelope<T> {
  return Object.freeze({
    value: input.value,
    evidence: Object.freeze([...(input.evidence ?? [])]),
    assumptions: Object.freeze([...(input.assumptions ?? [])]),
    limitations: Object.freeze([...(input.limitations ?? [])]),
    warnings: Object.freeze([...(input.warnings ?? [])]),
    confidence: input.confidence ?? "not_assessed",
    revision: nonBlank("revision", input.revision),
    approval: Object.freeze({
      status: "unreviewed" as const,
      owner: nonBlank("approval owner", input.approvalOwner),
      approvedAt: null,
    }),
  });
}
