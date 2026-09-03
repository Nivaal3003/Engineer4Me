import type { FieldInteractionSourceDescriptor } from "./models";
import { validateFieldInteractionIdentifier } from "./models";

export type FieldInteractionProvenanceOrigin =
  | "manual_user_input"
  | "scripted_fixture";

export interface FieldInteractionProvenanceRecord {
  readonly provenanceId: string;
  readonly sourceId: string;
  readonly origin: FieldInteractionProvenanceOrigin;
  readonly declaredSha256: string | null;
  readonly generatedFromLiveCapture: false;
  readonly captureEvidenceAccepted: false;
  readonly externalServiceEvidenceAccepted: false;
  readonly userReviewCompleted: false;
  readonly retentionMode: "memory_only";
}

export function createFieldInteractionProvenance(input: {
  readonly provenanceId: string;
  readonly source: FieldInteractionSourceDescriptor;
  readonly origin: FieldInteractionProvenanceOrigin;
}): FieldInteractionProvenanceRecord {
  if (input.source.rawContentAvailable) {
    throw new Error("Raw content cannot enter the source-only provenance contract.");
  }
  return Object.freeze({
    provenanceId: validateFieldInteractionIdentifier(
      input.provenanceId,
      "Provenance identifier",
    ),
    sourceId: input.source.sourceId,
    origin: input.origin,
    declaredSha256: input.source.declaredSha256,
    generatedFromLiveCapture: false,
    captureEvidenceAccepted: false,
    externalServiceEvidenceAccepted: false,
    userReviewCompleted: false,
    retentionMode: "memory_only",
  });
}
