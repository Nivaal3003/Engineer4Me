import { describe, expect, it } from "vitest";
import {
  MICROPHONE_CAPTURE_CONSENT_MAXIMUM_AGE_MS,
  MICROPHONE_CAPTURE_DISCLOSURE_SHA256,
  MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
  createUnrecordedMicrophoneCaptureConsent,
  evaluateMicrophoneCaptureConsent,
} from "./microphone-capture-consent";

describe("microphone capture consent", () => {
  it("keeps the proposal closed when capture-specific consent is not recorded", () => {
    const evaluation = evaluateMicrophoneCaptureConsent(
      createUnrecordedMicrophoneCaptureConsent(),
      10_000,
    );

    expect(evaluation.accepted).toBe(false);
    expect(evaluation.blockingReasons).toContain(
      "Fresh affirmative capture-specific consent is required.",
    );
  });

  it("accepts only fresh affirmative purpose-bound single-use consent", () => {
    const recordedAtUnixMs = 50_000;
    const evaluation = evaluateMicrophoneCaptureConsent(
      {
        decision: "affirmative",
        disclosureVersion: MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
        disclosureSha256: MICROPHONE_CAPTURE_DISCLOSURE_SHA256,
        purpose: "bounded_no_persistence_microphone_source_session",
        userInitiated: true,
        singleUse: true,
        recordedAtUnixMs,
      },
      recordedAtUnixMs + MICROPHONE_CAPTURE_CONSENT_MAXIMUM_AGE_MS,
    );

    expect(evaluation).toMatchObject({
      accepted: true,
      fresh: true,
      disclosureIdentityAccepted: true,
      purposeAccepted: true,
      userInitiationAccepted: true,
      singleUseAccepted: true,
    });
  });
});
