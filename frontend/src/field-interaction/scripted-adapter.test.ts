import { createScriptedFieldInteractionPreview } from "./scripted-adapter";

describe("scripted in-memory field-interaction adapter", () => {
  it("demonstrates voice and multimodal contracts without capture or transport", () => {
    const preview = createScriptedFieldInteractionPreview("selection");
    expect(preview.mode).toBe("scripted_in_memory_only");
    expect(preview.sources).toHaveLength(3);
    expect(preview.sources.every((source) => !source.rawContentAvailable)).toBe(true);
    expect(preview.provenance).toHaveLength(3);
    expect(preview.transcript.languageTag).toBe("en-ZA");
    expect(preview.proposal.candidateOperationKey).toBeNull();
    expect(preview.review.state).toBe("review_required");
    expect(preview.permissions.liveCaptureActive).toBe(false);
    expect(preview).toMatchObject({
      networkRequestsMade: 0,
      permissionRequestsMade: 0,
      externalAiRequestsMade: 0,
      backendRequestsMade: 0,
      protectedContentItemsLoaded: 0,
    });
  });
});
