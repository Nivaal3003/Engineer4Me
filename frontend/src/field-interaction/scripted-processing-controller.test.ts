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

describe("scripted processing controller", () => {
  it("quarantines exactly one final result; queueing and start do not call a provider", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const job = c.queue(x.preview, fixture(), 0);
    expect(c.inspect(job, 0).state).toBe("queued"); expect(() => c.deliver(job, 1)).toThrow();
    c.start(job, 2); const result = c.deliver(job, 3);
    expect(result.resultQuarantined).toBe(true); expect(result.executionAuthorized).toBe(false);
    expect(Object.keys(result)).toEqual(["jobSerial", "resultQuarantined", "executionAuthorized"]);
    expect(c.inspect(job, 3).providerInvoked).toBe(false); expect(() => c.deliver(job, 4)).toThrow(); c.discardAll();
  });
  it("rejects forged and cross-controller handles", () => {
    const a = createScriptedProcessingController(); const b = createScriptedProcessingController();
    const job = a.queue(makeContext().preview, fixture(), 0);
    expect(() => a.start({ ...job }, 1)).toThrow(/unissued/i); expect(() => b.start(job, 1)).toThrow(/cross-controller/i); a.discardAll();
  });
  it("requires a current issued preview and fixture", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const f = fixture();
    expect(() => c.queue({ ...x.preview }, f, 0)).toThrow();
    expect(() => c.queue(x.preview, { ...f }, 0)).toThrow();
    const job = c.queue(x.preview, f, 1);
    expect(() => c.queue(x.preview, f, 1)).toThrow(/already active/i); c.cancel(job, 2);
  });
  it("blocks cancelled jobs at queued, running and result stages", () => {
    for (const stage of ["queued", "running", "result"] as const) {
      const c = createScriptedProcessingController(); const job = c.queue(makeContext().preview, fixture(), 0);
      if (stage !== "queued") c.start(job, 1);
      const result = stage === "result" ? c.deliver(job, 2) : null;
      c.cancel(job, 3);
      expect(() => c.deliver(job, 4)).toThrow(/cancelled/i);
      if (result) expect(() => c.takeForFreshReview(result, "never-admit", 4)).toThrow(/cancelled/i);
      expect(c.inspect(job, 4).resultTextRetainedByController).toBe(false);
    }
  });
  it("expires at the exact injected deadline with no timer claim", () => {
    const c = createScriptedProcessingController(); const job = c.queue(makeContext().preview, fixture(), 10); c.start(job, 11);
    expect(c.inspect(job, 60009).state).toBe("running");
    expect(() => c.deliver(job, 60010)).toThrow(/expired/i);
    expect(c.inspect(job, 60010).realTimeEnforcementPresent).toBe(false); expect(c.inspect(job, 60010).activeJobCount).toBe(0);
  });
  it("rejects nonmonotonic ticks", () => {
    const c = createScriptedProcessingController(); const job = c.queue(makeContext().preview, fixture(), 5);
    expect(() => c.start(job, 4)).toThrow(/backwards/i); c.discardAll();
  });
  it("invalidates a delivered result when text changes", () => {
    const c = createScriptedProcessingController(); const x = makeContext(); const job = c.queue(x.preview, fixture(), 0); c.start(job, 1);
    const result = c.deliver(job, 2); reviews.push(reviseTranscriptReview(x.review, "Changed 5 bar.", x.review.envelope.attachments));
    expect(() => c.takeForFreshReview(result, "late535", 3)).toThrow(/superseded/i);
    expect(c.inspect(job, 3).resultTextRetainedByController).toBe(false);
  });
  it("invalidates jobs on attachment-only changes and source discard", () => {
    for (const action of ["attachment", "discard"] as const) {
      const c = createScriptedProcessingController(); const x = makeContext(); const job = c.queue(x.preview, fixture(), 0); c.start(job, 1);
      if (action === "attachment") reviews.push(reviseTranscriptReview(x.review, x.review.envelope.text, []));
      else discardTranscriptRevisionReview(x.review);
      expect(() => c.deliver(job, 2)).toThrow(/superseded/i);
    }
  });
  it("bounds and releases the active registry", () => {
    const c = createScriptedProcessingController(); const jobs = [];
    for (let i = 0; i < 16; i += 1) jobs.push(c.queue(makeContext().preview, fixture(), 0));
    const first = jobs[0]; if (!first) throw new Error("Missing test job.");
    const firstReview = reviews[0]; if (!firstReview) throw new Error("Missing test review.");
    expect(() => c.queue(createRevisionBoundIntentPreview(firstReview, "query"), fixture(), 0)).toThrow(/sixteen/i);
    expect(c.inspect(first, 0).activeJobCount).toBe(16); c.discardAll();
    expect(c.inspect(first, 0).activeJobCount).toBe(0); expect(c.inspect(first, 0).state).toBe("cancelled");
  });
});
