import { describe, expect, it } from "vitest";
import { createInertProcessingEvidenceStatus } from "./inert-processing-evidence-status";
describe("inert processing evidence status", () => {
  it("has no application input, provider or execution operation", () => {
    const value = createInertProcessingEvidenceStatus(); expect(value.state).toBe("not_configured"); expect(value.activeDossierCount).toBe(0); expect(value.requiredReviewCategories).toHaveLength(8);
    expect(Object.values(value).some(item => typeof item === "function")).toBe(false);
    expect(value.providerSelected).toBe(false); expect(value.executionAuthorized).toBe(false); expect(value.applicationControlsActive).toBe(false); expect(value.furtherInterventionRequired).toBe(true);
  });
  it("does not repeat the historical microphone check or authenticate review declarations", () => {
    const value = createInertProcessingEvidenceStatus(); expect(value.historicalMicrophoneCheckRepeated).toBe(false); expect(value.reviewerAuthenticated).toBe(false); expect(value.evidenceContentVerified).toBe(false); expect(value.consentRecorded).toBe(false); expect(Object.isFrozen(value)).toBe(true);
  });
});
