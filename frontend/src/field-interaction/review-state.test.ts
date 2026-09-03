import { createControlledIntentProposal } from "./intent-proposal";
import {
  createInitialFieldInteractionReview,
  transitionFieldInteractionReview,
} from "./review-state";

function proposal() {
  return createControlledIntentProposal({
    proposalId: "review-proposal",
    capabilityId: "knowledge",
    intentKind: "query",
    prompt: "Review evidence.",
  });
}

describe("field-interaction review state machine", () => {
  it("permits local preview review while keeping execution gated", () => {
    const draft = createInitialFieldInteractionReview(proposal());
    const reviewRequired = transitionFieldInteractionReview(
      draft,
      "submit_for_review",
    );
    const approved = transitionFieldInteractionReview(
      reviewRequired,
      "approve_local_preview",
    );
    const gated = transitionFieldInteractionReview(
      approved,
      "request_execution",
    );
    expect(gated).toMatchObject({
      state: "execution_gated",
      userReviewCompleted: true,
      localPreviewAuthorized: true,
      executionAuthorized: false,
      finalEngineeringApprovalGranted: false,
      operationalAuthorizationGranted: false,
    });
  });

  it("rejects transitions that bypass review", () => {
    expect(() => transitionFieldInteractionReview(
      createInitialFieldInteractionReview(proposal()),
      "request_execution",
    )).toThrow(/not authorized/);
  });
});
