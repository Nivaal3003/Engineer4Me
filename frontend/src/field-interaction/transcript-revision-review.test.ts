import { describe, expect, it } from "vitest";
import { createTranscriptReviewEnvelope } from "./transcript-review-envelope";
import { beginTranscriptRevisionReview, transitionTranscriptRevisionReview, reviseTranscriptReview,
  createRevisionBoundIntentPreview, assertCurrentRevisionBoundIntentPreview, discardTranscriptRevisionReview } from "./transcript-revision-review";
function draft(id: string) {
  return beginTranscriptRevisionReview(createTranscriptReviewEnvelope({ transcriptId: id, sourceId: "manual.1",
    origin: "manual_text", languageTag: "en", text: "Do not start the pump.", revision: 1, attachments: [] }));
}
describe("revision-bound in-memory review", () => {
  it("requires submitted review and never converts preview approval into execution", () => {
    const d = draft("review.first"); expect(() => createRevisionBoundIntentPreview(d, "command")).toThrow(/requires review/i);
    expect(() => transitionTranscriptRevisionReview(d, "approve_local_preview")).toThrow();
    const r = transitionTranscriptRevisionReview(d, "submit");
    const a = transitionTranscriptRevisionReview(r, "approve_local_preview");
    const p = createRevisionBoundIntentPreview(a, "command");
    expect(p.text).toBe("Do not start the pump."); expect(p.operationExecutionAuthorized).toBe(false);
    expect(p.candidateOperationKey).toBe(null); expect(p.voiceCommandInterpretationPerformed).toBe(false);
    expect(a.authenticatedApprovalEstablished).toBe(false);
    expect(() => createRevisionBoundIntentPreview({ ...a }, "query")).toThrow(/unissued/i);
    assertCurrentRevisionBoundIntentPreview(p);
    discardTranscriptRevisionReview(a);
    expect(() => assertCurrentRevisionBoundIntentPreview(p)).toThrow(/discarded/i);
    expect(() => createRevisionBoundIntentPreview(a, "command")).toThrow(/discarded/i);
  });
  it("invalidates an approved revision after text or attachment revision changes", () => {
    const a = transitionTranscriptRevisionReview(transitionTranscriptRevisionReview(draft("review.edit"), "submit"), "approve_local_preview");
    const revised = reviseTranscriptReview(a, "Inspect the pump only.", [{ sourceId: "drawing.1", revision: "R2", declaredSha256: "b".repeat(64) }]);
    expect(revised.revisionBinding).toBe(2); expect(revised.localPreviewAuthorized).toBe(false);
    expect(() => createRevisionBoundIntentPreview(a, "query")).toThrow(/superseded/i);
    expect(() => createRevisionBoundIntentPreview(revised, "query")).toThrow(/review/i);
    discardTranscriptRevisionReview(revised);
  });
  it("keeps rejection closed and permits correction only through a new revision", () => {
    const r = transitionTranscriptRevisionReview(draft("review.reject"), "reject");
    expect(() => transitionTranscriptRevisionReview(r, "approve_local_preview")).toThrow();
    const n = reviseTranscriptReview(r, "Inspect equipment.", []); expect(n.state).toBe("draft");
    discardTranscriptRevisionReview(n);
  });
  it("bounds the active registry and releases discarded reviews", () => {
    const reviews = Array.from({ length: 16 }, (_, i) => draft(`review.limit.${i}`));
    expect(() => draft("review.limit.excess")).toThrow(/sixteen/i);
    for (const r of reviews) discardTranscriptRevisionReview(r);
    const next = draft("review.limit.excess"); discardTranscriptRevisionReview(next);
  });
});
