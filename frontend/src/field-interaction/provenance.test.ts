import { createFieldInteractionSourceDescriptor } from "./models";
import { createFieldInteractionProvenance } from "./provenance";

describe("field-interaction provenance contract", () => {
  it("records scripted metadata provenance without claiming capture or external evidence", () => {
    const source = createFieldInteractionSourceDescriptor({
      sourceId: "scripted-image-1",
      kind: "scripted_image_descriptor",
      label: "Scripted image descriptor",
      mediaType: "image/jpeg",
      declaredByteLength: 2048,
      declaredSha256: "a".repeat(64),
      captureMode: "scripted",
    });
    expect(createFieldInteractionProvenance({
      provenanceId: "scripted-image-1-provenance",
      source,
      origin: "scripted_fixture",
    })).toEqual({
      provenanceId: "scripted-image-1-provenance",
      sourceId: "scripted-image-1",
      origin: "scripted_fixture",
      declaredSha256: "a".repeat(64),
      generatedFromLiveCapture: false,
      captureEvidenceAccepted: false,
      externalServiceEvidenceAccepted: false,
      userReviewCompleted: false,
      retentionMode: "memory_only",
    });
  });
});
