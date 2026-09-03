import { evaluateFieldInteractionPrivacy } from "./privacy";

describe("field-interaction privacy boundary", () => {
  it("fails closed for unknown content and external processing", () => {
    const evaluation = evaluateFieldInteractionPrivacy({
      classification: "unknown",
      externalProcessingRequested: true,
    });
    expect(evaluation).toMatchObject({
      retentionMode: "memory_only",
      externalProcessingAllowed: false,
      persistenceAllowed: false,
      rawMediaRetentionAllowed: false,
      requiresExplicitUserConfirmation: true,
      requiresDataOwnerReview: true,
    });
    expect(evaluation.blockingReasons).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/classification is unknown/),
        expect.stringMatching(/External processing was requested/),
      ]),
    );
  });

  it("does not silently allow external processing even for public content", () => {
    expect(evaluateFieldInteractionPrivacy({
      classification: "public",
      externalProcessingRequested: false,
    })).toMatchObject({
      externalProcessingAllowed: false,
      persistenceAllowed: false,
      requiresDataOwnerReview: false,
    });
  });
});
