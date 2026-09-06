import { describe, expect, it } from "vitest";
import { SCRIPTED_PROCESSING_LIMITS, assertScriptedProcessingTick } from "./scripted-processing-policy";
describe("scripted processing policy", () => {
  it("uses bounded frozen simulation limits", () => {
    expect(Object.isFrozen(SCRIPTED_PROCESSING_LIMITS)).toBe(true);
    expect(SCRIPTED_PROCESSING_LIMITS.maximumActiveJobs).toBe(16);
    expect(SCRIPTED_PROCESSING_LIMITS.maximumFinalResultsPerJob).toBe(1);
    expect(SCRIPTED_PROCESSING_LIMITS.maximumTextCodeUnits).toBe(4096);
  });
  it("accepts valid injected ticks without reading a clock", () => {
    expect(() => assertScriptedProcessingTick(0)).not.toThrow();
    expect(() => assertScriptedProcessingTick(Number.MAX_SAFE_INTEGER - 60000)).not.toThrow();
  });
  it("rejects invalid or overflowing ticks", () => {
    for (const value of [NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER]) expect(() => assertScriptedProcessingTick(value)).toThrow();
  });
});
