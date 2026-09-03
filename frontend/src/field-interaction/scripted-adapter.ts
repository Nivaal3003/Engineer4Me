import type { ProtectedCapabilityId } from "../capabilities";
import {
  createControlledIntentProposal,
  type ControlledIntentProposal,
} from "./intent-proposal";
import {
  createControlledTranscript,
  createFieldInteractionSourceDescriptor,
  type ControlledTranscript,
  type FieldInteractionSourceDescriptor,
} from "./models";
import {
  createFieldInteractionPermissionSnapshot,
  type FieldInteractionPermissionSnapshot,
} from "./permissions";
import {
  evaluateFieldInteractionPrivacy,
  type FieldInteractionPrivacyEvaluation,
} from "./privacy";
import {
  createFieldInteractionProvenance,
  type FieldInteractionProvenanceRecord,
} from "./provenance";
import {
  createInitialFieldInteractionReview,
  transitionFieldInteractionReview,
  type FieldInteractionReviewSnapshot,
} from "./review-state";

const CAPABILITY_LABELS = Object.freeze({
  selection: "selection and sizing",
  troubleshooting: "troubleshooting",
  knowledge: "knowledge and evidence",
  ingestion: "document ingestion",
  calculations: "engineering calculations",
  designs: "design cases",
  projects: "multidisciplinary projects",
  security: "access and audit",
} satisfies Readonly<Record<ProtectedCapabilityId, string>>);

export interface ScriptedFieldInteractionPreview {
  readonly mode: "scripted_in_memory_only";
  readonly capabilityId: ProtectedCapabilityId;
  readonly sources: readonly FieldInteractionSourceDescriptor[];
  readonly transcript: ControlledTranscript;
  readonly provenance: readonly FieldInteractionProvenanceRecord[];
  readonly privacy: FieldInteractionPrivacyEvaluation;
  readonly proposal: ControlledIntentProposal;
  readonly review: FieldInteractionReviewSnapshot;
  readonly permissions: FieldInteractionPermissionSnapshot;
  readonly networkRequestsMade: 0;
  readonly permissionRequestsMade: 0;
  readonly externalAiRequestsMade: 0;
  readonly backendRequestsMade: 0;
  readonly protectedContentItemsLoaded: 0;
}

export function createScriptedFieldInteractionPreview(
  capabilityId: ProtectedCapabilityId,
): ScriptedFieldInteractionPreview {
  const transcriptSource = createFieldInteractionSourceDescriptor({
    sourceId: `scripted-${capabilityId}-transcript`,
    kind: "scripted_voice_transcript",
    label: "Scripted voice transcript fixture",
    mediaType: "text/plain",
    captureMode: "scripted",
  });
  const imageSource = createFieldInteractionSourceDescriptor({
    sourceId: `scripted-${capabilityId}-image`,
    kind: "scripted_image_descriptor",
    label: "Scripted image metadata descriptor",
    mediaType: "image/jpeg",
    captureMode: "scripted",
  });
  const documentSource = createFieldInteractionSourceDescriptor({
    sourceId: `scripted-${capabilityId}-document`,
    kind: "scripted_document_descriptor",
    label: "Scripted document metadata descriptor",
    mediaType: "application/pdf",
    captureMode: "scripted",
  });
  const sources = Object.freeze([
    transcriptSource,
    imageSource,
    documentSource,
  ]);
  const transcript = createControlledTranscript({
    transcriptId: `scripted-${capabilityId}-transcript-text`,
    sourceId: transcriptSource.sourceId,
    sourceKind: "scripted_voice_transcript",
    languageTag: "en-ZA",
    text: `Review the accepted evidence and available operations for ${CAPABILITY_LABELS[capabilityId]}.`,
  });
  const provenance = Object.freeze(
    sources.map((source) =>
      createFieldInteractionProvenance({
        provenanceId: `${source.sourceId}-provenance`,
        source,
        origin: "scripted_fixture",
      }),
    ),
  );
  const privacy = evaluateFieldInteractionPrivacy({
    classification: "unknown",
    externalProcessingRequested: false,
  });
  const proposal = createControlledIntentProposal({
    proposalId: `scripted-${capabilityId}-proposal`,
    capabilityId,
    intentKind: "query",
    prompt: transcript.text,
  });
  const review = transitionFieldInteractionReview(
    createInitialFieldInteractionReview(proposal),
    "submit_for_review",
  );
  return Object.freeze({
    mode: "scripted_in_memory_only",
    capabilityId,
    sources,
    transcript,
    provenance,
    privacy,
    proposal,
    review,
    permissions: createFieldInteractionPermissionSnapshot(),
    networkRequestsMade: 0,
    permissionRequestsMade: 0,
    externalAiRequestsMade: 0,
    backendRequestsMade: 0,
    protectedContentItemsLoaded: 0,
  });
}
