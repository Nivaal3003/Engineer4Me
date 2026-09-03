import {
  createControlledTranscript,
  createFieldInteractionSourceDescriptor,
} from "./models";

describe("field-interaction source contracts", () => {
  it("creates metadata-only descriptors and transcripts with inactive execution flags", () => {
    const source = createFieldInteractionSourceDescriptor({
      sourceId: "scripted-selection-image",
      kind: "scripted_image_descriptor",
      label: "  Scripted image descriptor  ",
      mediaType: "IMAGE/JPEG",
      declaredByteLength: 2048,
      declaredSha256: "a".repeat(64),
      captureMode: "scripted",
    });
    expect(source).toMatchObject({
      sourceId: "scripted-selection-image",
      label: "Scripted image descriptor",
      mediaType: "image/jpeg",
      declaredByteLength: 2048,
      rawContentAvailable: false,
      permissionRequested: false,
      externalProcessingUsed: false,
    });
    const transcript = createControlledTranscript({
      transcriptId: "selection-transcript",
      sourceId: "selection-source",
      sourceKind: "scripted_voice_transcript",
      languageTag: "en-ZA",
      text: "  Review   accepted evidence. ",
    });
    expect(transcript).toMatchObject({
      text: "Review accepted evidence.",
      confidence: null,
      rawAudioAvailable: false,
      microphonePermissionRequested: false,
      externalAiUsed: false,
    });
  });

  it("rejects unsafe identifiers, hashes, and empty transcript content", () => {
    expect(() => createFieldInteractionSourceDescriptor({
      sourceId: "../unsafe",
      kind: "manual_text",
      label: "Unsafe",
      captureMode: "manual",
    })).toThrow(/controlled identifier format/);
    expect(() => createFieldInteractionSourceDescriptor({
      sourceId: "safe-id",
      kind: "manual_text",
      label: "Unsafe hash",
      declaredSha256: "ABC",
      captureMode: "manual",
    })).toThrow(/Declared SHA-256/);
    expect(() => createControlledTranscript({
      transcriptId: "empty-transcript",
      sourceId: "safe-source",
      sourceKind: "manual_text",
      languageTag: "en-ZA",
      text: " ",
    })).toThrow(/Transcript text is required/);
  });
});
