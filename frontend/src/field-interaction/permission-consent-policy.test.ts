import {
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
  MICROPHONE_PERMISSION_PURPOSE,
  createImportedMicrophonePermissionConsent,
  createUnrecordedMicrophonePermissionConsent,
} from "./permission-consent-evidence";
import { evaluateMicrophonePermissionConsent } from "./permission-consent-policy";

describe("microphone permission consent policy", () => {
  it("fails closed while consent is unrecorded", () => {
    const result = evaluateMicrophonePermissionConsent({
      evidence: createUnrecordedMicrophonePermissionConsent(),
      referenceEpochMs: 10_000,
    });
    expect(result.acceptedForFuturePromptGate).toBe(false);
    expect(result.permissionPromptAuthorized).toBe(false);
    expect(result.captureAuthorized).toBe(false);
  });

  it("accepts fresh explicit evidence for a future gate without authorizing a prompt", () => {
    const evidence = createImportedMicrophonePermissionConsent({
      evidenceId: "consent-evidence-003",
      disclosureVersion: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
      disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
      purpose: MICROPHONE_PERMISSION_PURPOSE,
      decision: "affirmative",
      occurredAtEpochMs: 9_000,
      explicit: true,
      userInitiated: true,
    });
    const result = evaluateMicrophonePermissionConsent({
      evidence,
      referenceEpochMs: 10_000,
    });
    expect(result.acceptedForFuturePromptGate).toBe(true);
    expect(result.permissionPromptAuthorized).toBe(false);
    expect(result.interventionRequired).toBe(true);
  });
});
