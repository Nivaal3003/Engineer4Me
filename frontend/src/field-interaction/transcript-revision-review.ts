import { assertIssuedTranscriptEnvelope, createTranscriptReviewEnvelope } from "./transcript-review-envelope";
import type { TranscriptReviewEnvelope, ReviewAttachmentReference } from "./transcript-review-envelope";
export type TranscriptLocalReviewState = "draft" | "review_required" | "approved_for_local_preview" | "rejected";
export interface TranscriptRevisionReview {
  readonly envelope: TranscriptReviewEnvelope;
  readonly state: TranscriptLocalReviewState;
  readonly revisionBinding: number;
  readonly localPreviewAuthorized: boolean;
  readonly authenticatedApprovalEstablished: false;
  readonly engineeringApprovalGranted: false;
  readonly operationExecutionAuthorized: false;
}
const issuedReviews = new WeakSet<object>();
const issuedPreviews = new WeakMap<object, TranscriptRevisionReview>();
const currentByTranscript = new Map<string, TranscriptRevisionReview>();
function snapshot(envelope: TranscriptReviewEnvelope, state: TranscriptLocalReviewState): TranscriptRevisionReview {
  const result: TranscriptRevisionReview = Object.freeze({
    envelope, state, revisionBinding: envelope.revision,
    localPreviewAuthorized: state === "approved_for_local_preview",
    authenticatedApprovalEstablished: false, engineeringApprovalGranted: false,
    operationExecutionAuthorized: false,
  });
  issuedReviews.add(result); currentByTranscript.set(envelope.transcriptId, result);
  return result;
}
function current(review: TranscriptRevisionReview): void {
  if (!issuedReviews.has(review) || currentByTranscript.get(review.envelope.transcriptId) !== review) {
    throw new Error("The review is unissued, superseded, or discarded.");
  }
  assertIssuedTranscriptEnvelope(review.envelope);
}
export function beginTranscriptRevisionReview(envelope: TranscriptReviewEnvelope): TranscriptRevisionReview {
  assertIssuedTranscriptEnvelope(envelope);
  if (currentByTranscript.has(envelope.transcriptId)) throw new Error("A review for this transcript is already active.");
  if (currentByTranscript.size >= 16) throw new Error("The memory-only review limit is sixteen active transcripts.");
  return snapshot(envelope, "draft");
}
export function transitionTranscriptRevisionReview(review: TranscriptRevisionReview, event: "submit" | "approve_local_preview" | "reject"): TranscriptRevisionReview {
  current(review);
  if (event === "submit" && review.state === "draft") return snapshot(review.envelope, "review_required");
  if (event === "approve_local_preview" && review.state === "review_required") return snapshot(review.envelope, "approved_for_local_preview");
  if (event === "reject" && (review.state === "draft" || review.state === "review_required")) return snapshot(review.envelope, "rejected");
  throw new Error("Transcript review transition is not authorized.");
}
export function reviseTranscriptReview(review: TranscriptRevisionReview, text: string, attachments: readonly ReviewAttachmentReference[]): TranscriptRevisionReview {
  current(review);
  const old = review.envelope;
  const envelope = createTranscriptReviewEnvelope({ transcriptId: old.transcriptId, sourceId: old.sourceId,
    origin: old.origin, languageTag: old.languageTag, text, revision: old.revision + 1, attachments });
  return snapshot(envelope, "draft");
}
export function createRevisionBoundIntentPreview(review: TranscriptRevisionReview, chosenIntent: "query" | "command" | "undetermined") {
  current(review);
  if (!review.localPreviewAuthorized || review.state !== "approved_for_local_preview") throw new Error("Local preview requires review of the current revision.");
  if (!["query", "command", "undetermined"].includes(chosenIntent)) throw new Error("Intent must be supplied explicitly, not inferred.");
  const preview = Object.freeze({ transcriptId: review.envelope.transcriptId, revision: review.revisionBinding,
    text: review.envelope.text, attachments: review.envelope.attachments,
    intentKind: chosenIntent, intentOrigin: "explicit_caller_selection" as const,
    candidateOperationKey: null, speechToTextPerformed: false as const,
    voiceCommandInterpretationPerformed: false as const, backendRequestPrepared: false as const,
    operationExecutionAuthorized: false as const, furtherExecutionGateRequired: true as const,
    retentionMode: "memory_only" as const,
  });
  issuedPreviews.set(preview, review);
  return preview;
}
export function assertCurrentRevisionBoundIntentPreview(preview: object): void {
  const review = issuedPreviews.get(preview);
  if (!review) throw new Error("The preview was not issued in this memory-only session.");
  current(review);
}
export function discardTranscriptRevisionReview(review: TranscriptRevisionReview): void {
  current(review); currentByTranscript.delete(review.envelope.transcriptId);
}
