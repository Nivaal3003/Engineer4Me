import { describe, expect, it } from "vitest";
import { createInertScriptedProcessingStatus } from "./inert-scripted-processing-status";
describe("inert scripted processing status", () => {
  it("exposes no provider or background operation", () => {
    const s = createInertScriptedProcessingStatus();
    expect(s.mode).toBe("scripted_fixture_simulation_only"); expect(s.applicationControlsActive).toBe(false);
    expect(s.providerSelected).toBe(false); expect(s.providerOperationAvailable).toBe(false);
    expect(s.backgroundProcessingAvailable).toBe(false); expect(s.timersInstalled).toBe(false);
    expect(s.liveTranscriptAccepted).toBe(false); expect(s.executionAuthorized).toBe(false);
    expect(s.readiness.missingGates).toHaveLength(10); expect(s.retainedTranscriptContent).toBeNull();
    expect(Object.values(s).some((v) => typeof v === "function")).toBe(false);
  });
});
