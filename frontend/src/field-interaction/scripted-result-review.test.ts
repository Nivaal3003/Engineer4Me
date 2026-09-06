import { afterEach, describe, expect, it } from "vitest";
import { createTranscriptReviewEnvelope } from "./transcript-review-envelope";
import { beginTranscriptRevisionReview, transitionTranscriptRevisionReview, createRevisionBoundIntentPreview,
  discardTranscriptRevisionReview, reviseTranscriptReview } from "./transcript-revision-review";
import type { TranscriptRevisionReview } from "./transcript-revision-review";
import { createScriptedTranscriptFixture } from "./scripted-transcript-fixture";
import { createScriptedProcessingController } from "./scripted-processing-controller";

const reviews: TranscriptRevisionReview[] = [];
let counter = 0;
function makeContext(text = "Do NOT change 4.5 bar.") {
  counter += 1;
  let review = beginTranscriptRevisionReview(createTranscriptReviewEnvelope({
    transcriptId: `test535-${counter}`, sourceId: "manual535", origin: "manual_text", languageTag: "en-ZA", text,
    revision: 1, attachments: [{ sourceId: "doc535", revision: "A", declaredSha256: "a".repeat(64) }],
  }));
  review = transitionTranscriptRevisionReview(review, "submit");
  review = transitionTranscriptRevisionReview(review, "approve_local_preview");
  reviews.push(review);
  return { review, preview: createRevisionBoundIntentPreview(review, "query") };
}
function fixture() { return createScriptedTranscriptFixture({ fixtureId: "script535", text: "Scripted result only.", languageTag: "en-ZA" }); }
afterEach(() => {
  for (const review of reviews) { try { discardTranscriptRevisionReview(review); } catch { /* superseded snapshots have no current authority */ } }
  reviews.length = 0;
});

import { admitScriptedResultForFreshReview } from "./scripted-result-review";
describe("scripted result fresh review admission", () => {
  it("requires a fresh draft and retains exact fixture text and declared attachments", () => {
    const c = createScriptedProcessingController(); const x = makeContext();
    const f = createScriptedTranscriptFixture({ fixtureId: "script535", languageTag: "en-ZA", text: "Do NOT open V-7.\n2.5 bar" });
    const job = c.queue(x.preview, f, 0); c.start(job, 1); const result = c.deliver(job, 2);
    const review = admitScriptedResultForFreshReview(c, result, "new-result535", 3); reviews.push(review);
    expect(review.state).toBe("draft"); expect(review.localPreviewAuthorized).toBe(false);
    expect(review.envelope.text).toBe(f.text); expect(review.envelope.origin).toBe("scripted_voice_transcript");
    expect(review.envelope.attachments).toEqual(x.preview.attachments); expect(review.envelope.attachmentContentVerified).toBe(false);
    expect(review.authenticatedApprovalEstablished).toBe(false); expect(review.operationExecutionAuthorized).toBe(false);
    expect(() => createRevisionBoundIntentPreview(review, "command")).toThrow(/review/i);
    expect(c.inspect(job, 3).resultTextRetainedByController).toBe(false);
    expect(() => admitScriptedResultForFreshReview(c, result, "second-result535", 4)).toThrow();
  });
  it("blocks a forged controller, cloned result and same transcript identifier", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const job = c.queue(x.preview, fixture(), 0); c.start(job, 1);
    const r = c.deliver(job, 2);
    expect(() => admitScriptedResultForFreshReview({ ...c }, r, "new535", 3)).toThrow(/issued/i);
    expect(() => admitScriptedResultForFreshReview(c, { ...r }, "new535", 3)).toThrow(/unissued/i);
    expect(() => admitScriptedResultForFreshReview(c, r, x.preview.transcriptId, 3)).toThrow(/distinct/i); c.discardAll();
  });
  it("does not admit a stale result after context replacement", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const job = c.queue(x.preview, fixture(), 0); c.start(job, 1);
    const r = c.deliver(job, 2); reviews.push(reviseTranscriptReview(x.review, x.review.envelope.text, []));
    expect(() => admitScriptedResultForFreshReview(c, r, "new535", 3)).toThrow(/superseded/i);
  });
  it("does not resend when the separate review registry rejects admission", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const other = makeContext();
    const job = c.queue(x.preview, fixture(), 0); c.start(job, 1); const r = c.deliver(job, 2);
    expect(() => admitScriptedResultForFreshReview(c, r, other.preview.transcriptId, 3)).toThrow(/already active/i);
    expect(c.inspect(job, 3).state).toBe("consumed_for_fresh_review");
    expect(() => c.deliver(job, 4)).toThrow();
  });
});
