import { describe, expect, it } from "vitest";
import { createAcceptedControlledMicrophonePermissionImport } from "./controlled-microphone-permission-import";
import {
  MICROPHONE_CAPTURE_DISCLOSURE_SHA256,
  MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
  createUnrecordedMicrophoneCaptureConsent,
} from "./microphone-capture-consent";
import { createMicrophoneCapturePolicy } from "./microphone-capture-policy";
import { createMicrophoneCaptureProposal } from "./microphone-capture-proposal";

describe("bounded microphone capture proposal", () => {
  it("requires distinct capture consent after importing the permission outcome", () => {
    const proposal = createMicrophoneCaptureProposal({
      importedOutcome: createAcceptedControlledMicrophonePermissionImport(),
      consent: createUnrecordedMicrophoneCaptureConsent(),
      trustedStartGesture: null,
      policy: createMicrophoneCapturePolicy(),
      nowUnixMs: 10_000,
    });

    expect(proposal).toMatchObject({
      state: "capture_specific_consent_required",
      importedPermissionOutcomeAccepted: true,
      currentPermissionStateInferred: false,
      captureAuthorizationDerivedFromPermissionOutcome: false,
      executionInterventionRequired: true,
      executionAuthorized: false,
      applicationOperationAvailable: false,
    });
  });

  it("retains the intervention gate even after fresh consent and gesture evidence", () => {
    const nowUnixMs = 20_000;
    const proposal = createMicrophoneCaptureProposal({
      importedOutcome: createAcceptedControlledMicrophonePermissionImport(),
      consent: {
        decision: "affirmative",
        disclosureVersion: MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
        disclosureSha256: MICROPHONE_CAPTURE_DISCLOSURE_SHA256,
        purpose: "bounded_no_persistence_microphone_source_session",
        userInitiated: true,
        singleUse: true,
        recordedAtUnixMs: nowUnixMs,
      },
      trustedStartGesture: {
        trusted: true,
        singleUse: true,
        target: "start_bounded_microphone_source_session",
        recordedAtUnixMs: nowUnixMs,
        maximumAgeMilliseconds: 5_000,
      },
      policy: createMicrophoneCapturePolicy(),
      nowUnixMs,
    });

    expect(proposal).toMatchObject({
      state: "intervention_required",
      importedPermissionOutcomeAccepted: true,
      trustedStartGestureAccepted: true,
      executionInterventionRequired: true,
      executionAuthorized: false,
      sourceSessionMaximumMilliseconds: 3000,
    });
  });
});
