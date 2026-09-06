import { describe, expect, it } from "vitest";
import { TRANSCRIPT_PROCESSING_GATE_KEYS, createUnconfiguredTranscriptProcessingReadiness, evaluateTranscriptProcessingReadiness } from "./transcript-processing-readiness";
describe("provider-neutral processing readiness", () => {
  it("begins with all evidence missing and no automatically selected provider", () => {
    const r = createUnconfiguredTranscriptProcessingReadiness();
    expect(r.missingGates).toHaveLength(10); expect(r.providerSelectedByApplication).toBe(false);
    expect(r.executionAuthorized).toBe(false);
  });
  it("retains intervention even when all caller-supplied gate flags are true", () => {
    const raw = Object.fromEntries(TRANSCRIPT_PROCESSING_GATE_KEYS.map((k) => [k, true]));
    const r = evaluateTranscriptProcessingReadiness(raw);
    expect(r.state).toBe("intervention_required"); expect(r.executionAuthorized).toBe(false);
    expect(r.runtimeImplementationPresent).toBe(false); expect(r.consentRecordedByApplication).toBe(false);
    expect(() => evaluateTranscriptProcessingReadiness({ ...raw, localModel: "unapproved" })).toThrow(/inventory/i);
    expect(() => evaluateTranscriptProcessingReadiness({ ...raw, securityReview: "true" })).toThrow(/boolean/i);
  });
});
