import { createControlledIntentProposal } from "./intent-proposal";

describe("controlled field-interaction intent proposals", () => {
  it("creates a review-only query without choosing an operation", () => {
    expect(createControlledIntentProposal({
      proposalId: "selection-query-proposal",
      capabilityId: "selection",
      intentKind: "query",
      prompt: "  Show   accepted evidence. ",
    })).toMatchObject({
      normalizedPrompt: "Show accepted evidence.",
      candidateOperationKey: null,
      authorizationBoundary: "review_required_before_query_preparation",
      requiresUserReview: true,
      executionAuthorized: false,
      backendRequestPrepared: false,
      bearerTokenAttached: false,
      protectedContentLoaded: false,
      automaticBestBrandSelection: false,
      standardsConformityClaimed: false,
    });
  });

  it("keeps a command proposal behind explicit authorization", () => {
    expect(createControlledIntentProposal({
      proposalId: "design-command-proposal",
      capabilityId: "designs",
      intentKind: "command",
      prompt: "Prepare a revision proposal.",
    })).toMatchObject({
      authorizationBoundary: "explicit_command_authorization_required",
      executionAuthorized: false,
      backendRequestPrepared: false,
    });
  });
});
