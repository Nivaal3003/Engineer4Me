import { createImportedMicrophonePermissionPromptOutcomeEvidence } from "./permission-outcome-evidence";

describe("imported microphone permission prompt outcome evidence", () => {
  it("records an imported outcome without deriving capture authorization", () => {
    const evidence = createImportedMicrophonePermissionPromptOutcomeEvidence({
      evidenceId: "prompt-outcome-evidence-001",
      outcome: "granted",
      promptCount: 1,
      occurredAtEpochMs: 12_000,
    });
    expect(evidence.outcome).toBe("granted");
    expect(evidence.captureAuthorizationDerived).toBe(false);
    expect(evidence.mediaDeviceEnumerationPerformed).toBe(false);
    expect(evidence.captureStarted).toBe(false);
    expect(evidence.furtherInterventionRequired).toBe(true);
    expect(() => createImportedMicrophonePermissionPromptOutcomeEvidence({
      evidenceId: "prompt-outcome-evidence-002",
      outcome: "denied",
      promptCount: 2,
      occurredAtEpochMs: 12_000,
    })).toThrow(/exactly one prompt/);
  });
});
