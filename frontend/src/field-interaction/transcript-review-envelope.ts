/** Strict manual/scripted text input; never accepts an audio-derived transcript. */
export type ReviewTextOrigin = "manual_text" | "scripted_voice_transcript";
export interface ReviewAttachmentReference {
  readonly sourceId: string;
  readonly revision: string;
  readonly declaredSha256: string;
}
export interface TranscriptReviewEnvelope {
  readonly transcriptId: string;
  readonly sourceId: string;
  readonly origin: ReviewTextOrigin;
  readonly languageTag: string;
  readonly text: string;
  readonly revision: number;
  readonly attachments: readonly ReviewAttachmentReference[];
  readonly attachmentContentVerified: false;
  readonly liveAudioProcessedByThisModule: false;
  readonly originDeclarationOnly: true;
  readonly originVerified: false;
  readonly confidence: null;
  readonly retentionMode: "memory_only";
}
const issuedEnvelopes = new WeakSet<object>();
const identifier = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const forbiddenText = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Transcript metadata must be an object.");
  }
  if (Object.keys(value).sort().join("|") !== [...fields].sort().join("|")) {
    throw new Error("Transcript metadata field inventory differs.");
  }
  for (const field of fields) {
    const d = Object.getOwnPropertyDescriptor(value, field);
    if (!d || !("value" in d)) throw new Error("Transcript metadata must contain own data fields.");
  }
  return value as Record<string, unknown>;
}
function id(value: unknown): string {
  if (typeof value !== "string" || value.trim() !== value || !identifier.test(value)) throw new Error("Invalid transcript identifier.");
  return value;
}
export function createTranscriptReviewEnvelope(input: unknown): TranscriptReviewEnvelope {
  const value = record(input, ["transcriptId", "sourceId", "origin", "languageTag", "text", "revision", "attachments"]);
  if (value.origin !== "manual_text" && value.origin !== "scripted_voice_transcript") {
    throw new Error("Only manual or scripted text is permitted; live transcription remains gated.");
  }
  if (typeof value.languageTag !== "string" || value.languageTag.trim() !== value.languageTag || !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(value.languageTag)) {
    throw new Error("Invalid review language tag.");
  }
  if (typeof value.text !== "string" || value.text.trim().length === 0 || value.text.length > 4096 || forbiddenText.test(value.text)) {
    throw new Error("Review text must be nonempty, bounded to 4096 code units, and free of disallowed controls.");
  }
  if (typeof value.revision !== "number" || !Number.isSafeInteger(value.revision) || value.revision < 1 || value.revision > 1000000) {
    throw new Error("Review revision must be an integer between 1 and 1000000.");
  }
  if (!Array.isArray(value.attachments) || value.attachments.length > 8) throw new Error("At most eight metadata references are permitted.");
  const seen = new Set<string>();
  const attachments = value.attachments.map((raw: unknown) => {
    const item = record(raw, ["sourceId", "revision", "declaredSha256"]);
    const sourceId = id(item.sourceId);
    if (seen.has(sourceId)) throw new Error("Duplicate attachment source identifier.");
    seen.add(sourceId);
    if (typeof item.revision !== "string" || item.revision.trim() !== item.revision || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(item.revision)) {
      throw new Error("Invalid declared attachment revision.");
    }
    if (typeof item.declaredSha256 !== "string" || item.declaredSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(item.declaredSha256)) {
      throw new Error("Invalid declared attachment digest.");
    }
    return Object.freeze({ sourceId, revision: item.revision, declaredSha256: item.declaredSha256 });
  });
  const envelope: TranscriptReviewEnvelope = Object.freeze({
    transcriptId: id(value.transcriptId), sourceId: id(value.sourceId), origin: value.origin,
    languageTag: value.languageTag, text: value.text, revision: value.revision,
    attachments: Object.freeze(attachments), attachmentContentVerified: false,
    liveAudioProcessedByThisModule: false, originDeclarationOnly: true, originVerified: false, confidence: null, retentionMode: "memory_only",
  });
  issuedEnvelopes.add(envelope);
  return envelope;
}
export function assertIssuedTranscriptEnvelope(value: TranscriptReviewEnvelope): void {
  if (!issuedEnvelopes.has(value)) throw new Error("Review requires an envelope issued in this memory-only session.");
}
