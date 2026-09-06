import { describe, expect, it } from "vitest";
import { createInertTranscriptProcessingAdapter } from "./inert-transcript-processing-adapter";
describe("inert transcript processing adapter", () => {
  it("exposes no processing operation and starts every external-operation counter at zero", () => {
    const a = createInertTranscriptProcessingAdapter();
    expect(a.operations).toHaveLength(0); expect(Object.values(a.counters).every((n) => n === 0)).toBe(true);
    expect(a.liveTranscriptionAvailable).toBe(false); expect(a.activeApplicationReviewUi).toBe(false);
    expect(a.automaticRetryEnabled).toBe(false); expect(Object.isFrozen(a)).toBe(true);
  });
});
