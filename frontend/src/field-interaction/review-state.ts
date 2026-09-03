import type { ControlledIntentProposal } from "./intent-proposal";

export const FIELD_INTERACTION_REVIEW_STATES = [
  "draft",
  "review_required",
  "approved_for_local_preview",
  "rejected",
  "execution_gated",
] as const;

export type FieldInteractionReviewState =
  (typeof FIELD_INTERACTION_REVIEW_STATES)[number];

export type FieldInteractionReviewEvent =
  | "submit_for_review"
  | "approve_local_preview"
  | "reject"
  | "request_execution";

export interface FieldInteractionReviewSnapshot {
  readonly proposalId: string;
  readonly state: FieldInteractionReviewState;
  readonly userReviewCompleted: boolean;
  readonly localPreviewAuthorized: boolean;
  readonly executionAuthorized: false;
  readonly finalEngineeringApprovalGranted: false;
  readonly operationalAuthorizationGranted: false;
}

function snapshot(
  proposalId: string,
  state: FieldInteractionReviewState,
  userReviewCompleted: boolean,
  localPreviewAuthorized: boolean,
): FieldInteractionReviewSnapshot {
  return Object.freeze({
    proposalId,
    state,
    userReviewCompleted,
    localPreviewAuthorized,
    executionAuthorized: false,
    finalEngineeringApprovalGranted: false,
    operationalAuthorizationGranted: false,
  });
}

export function createInitialFieldInteractionReview(
  proposal: ControlledIntentProposal,
): FieldInteractionReviewSnapshot {
  return snapshot(proposal.proposalId, "draft", false, false);
}

export function transitionFieldInteractionReview(
  current: FieldInteractionReviewSnapshot,
  event: FieldInteractionReviewEvent,
): FieldInteractionReviewSnapshot {
  if (current.state === "draft" && event === "submit_for_review") {
    return snapshot(current.proposalId, "review_required", false, false);
  }
  if (
    current.state === "review_required" &&
    event === "approve_local_preview"
  ) {
    return snapshot(
      current.proposalId,
      "approved_for_local_preview",
      true,
      true,
    );
  }
  if (
    (current.state === "draft" || current.state === "review_required") &&
    event === "reject"
  ) {
    return snapshot(current.proposalId, "rejected", true, false);
  }
  if (
    current.state === "approved_for_local_preview" &&
    event === "request_execution"
  ) {
    return snapshot(current.proposalId, "execution_gated", true, true);
  }
  throw new Error(
    `Review transition is not authorized: ${current.state} -> ${event}.`,
  );
}
