import type {
  CapabilityWorkspaceResult,
  ProtectedCapabilityId,
} from "../capabilities";
import type { ConfidenceLevel } from "../contracts";

export type CapabilityWorkspacePresentationState =
  | "ready"
  | "empty"
  | "degraded";

export interface CapabilityEvidenceItemViewModel {
  readonly sourceId: string;
  readonly title: string;
  readonly revisionLabel: string;
  readonly locatorLabel: string;
}

export interface CapabilityResultViewModel {
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly state: CapabilityWorkspacePresentationState;
  readonly title: string;
  readonly summary: string;
  readonly itemCount: number;
  readonly itemCountLabel: string;
  readonly confidence: ConfidenceLevel;
  readonly confidenceLabel: string;
  readonly revision: string;
  readonly approvalStatusLabel: string;
  readonly approvalOwner: string;
  readonly evidence: readonly CapabilityEvidenceItemViewModel[];
  readonly assumptions: readonly string[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
  readonly vendorNeutralityLabel: string;
  readonly standardsBoundaryLabel: string;
  readonly proprietaryBoundaryLabel: string;
  readonly engineeringApprovalLabel: string;
  readonly operationalAuthorizationLabel: string;
  readonly sourceMode: "in_memory_contract_only";
  readonly liveTransportActive: false;
  readonly protectedContentSource: "scripted_in_memory_fixture";
}

function sentenceCase(value: string): string {
  return value.replaceAll("_", " ");
}

export function createCapabilityResultViewModel(
  result: CapabilityWorkspaceResult,
): CapabilityResultViewModel {
  return Object.freeze({
    capabilityId: result.capabilityId,
    operationKey: result.operationKey,
    state: result.state,
    title: result.value.title,
    summary: result.value.summary,
    itemCount: result.value.itemCount,
    itemCountLabel: result.value.itemCount === 1
      ? "1 item"
      : `${result.value.itemCount} items`,
    confidence: result.confidence,
    confidenceLabel: sentenceCase(result.confidence),
    revision: result.revision,
    approvalStatusLabel: sentenceCase(result.approval.status),
    approvalOwner: result.approval.owner,
    evidence: Object.freeze(result.evidence.map((item) => Object.freeze({
      sourceId: item.sourceId,
      title: item.title,
      revisionLabel: item.revision ?? "Not supplied",
      locatorLabel: item.locator ?? "Not supplied",
    }))),
    assumptions: Object.freeze([...result.assumptions]),
    limitations: Object.freeze([...result.limitations]),
    warnings: Object.freeze([...result.warnings]),
    vendorNeutralityLabel: "Vendor neutrality required",
    standardsBoundaryLabel: "No standards conformity claim",
    proprietaryBoundaryLabel: "Proprietary and trademark identification required",
    engineeringApprovalLabel: "Final engineering approval remains with the user or authorized organisation",
    operationalAuthorizationLabel: "Operational authorization remains with the user or authorized organisation",
    sourceMode: "in_memory_contract_only",
    liveTransportActive: false,
    protectedContentSource: "scripted_in_memory_fixture",
  });
}
