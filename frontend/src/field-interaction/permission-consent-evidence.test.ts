import {
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
  MICROPHONE_PERMISSION_PURPOSE,
  createImportedMicrophonePermissionConsent,
  createUnrecordedMicrophonePermissionConsent,
} from "./permission-consent-evidence";

describe("microphone permission consent evidence", () => {
  it("starts unrecorded and exposes no prompt or capture side effect", () => {
    const evidence = createUnrecordedMicrophonePermissionConsent();
    expect(evidence.decision).toBe("not_recorded");
    expect(evidence.explicit).toBe(false);
    expect(evidence.userInitiated).toBe(false);
    expect(evidence.permissionPromptShownByThisRuntime).toBe(false);
    expect(evidence.captureStartedByThisRuntime).toBe(false);
  });

  it("accepts only an exact reviewed disclosure and purpose", () => {
    const evidence = createImportedMicrophonePermissionConsent({
      evidenceId: "consent-evidence-001",
      disclosureVersion: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
      disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
      purpose: MICROPHONE_PERMISSION_PURPOSE,
      decision: "affirmative",
      occurredAtEpochMs: 10_000,
      explicit: true,
      userInitiated: true,
    });
    expect(evidence.decision).toBe("affirmative");
    expect(evidence.importedFromControlledEvidence).toBe(true);
    expect(() => createImportedMicrophonePermissionConsent({
      evidenceId: "consent-evidence-002",
      disclosureVersion: "unreviewed",
      disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
      purpose: MICROPHONE_PERMISSION_PURPOSE,
      decision: "affirmative",
      occurredAtEpochMs: 10_000,
      explicit: true,
      userInitiated: true,
    })).toThrow(/version differs/);
  });
});
