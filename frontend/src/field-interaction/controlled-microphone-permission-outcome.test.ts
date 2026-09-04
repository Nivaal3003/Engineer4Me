import { createControlledMicrophonePermissionOutcomeEvidence } from "./controlled-microphone-permission-outcome";

describe("controlled microphone permission outcome evidence", () => {
  it("accepts a granted outcome only after immediate track termination", () => {
    const evidence = createControlledMicrophonePermissionOutcomeEvidence({
      evidenceId: "controlled-microphone-outcome-001",
      outcome: "granted_tracks_stopped",
      getUserMediaCallCount: 1,
      explicitConsentRecorded: true,
      trustedClickRecorded: true,
      mediaStreamReturned: true,
      returnedTrackCount: 1,
      trackStopCallCount: 1,
      allReturnedTracksEnded: true,
    });
    expect(evidence.immediateTrackTerminationAccepted).toBe(true);
    expect(evidence.browserMayHaveBrieflyActivatedMicrophone).toBe(true);
    expect(evidence.captureAuthorizationDerived).toBe(false);
    expect(evidence.audioSampleReadPerformed).toBe(false);
  });

  it("accepts a non-grant without inventing track evidence", () => {
    const evidence = createControlledMicrophonePermissionOutcomeEvidence({
      evidenceId: "controlled-microphone-outcome-002",
      outcome: "not_allowed_or_dismissed",
      getUserMediaCallCount: 1,
      explicitConsentRecorded: true,
      trustedClickRecorded: true,
      mediaStreamReturned: false,
      returnedTrackCount: 0,
      trackStopCallCount: 0,
      allReturnedTracksEnded: false,
    });
    expect(evidence.mediaStreamReturned).toBe(false);
    expect(evidence.browserMayHaveBrieflyActivatedMicrophone).toBe(false);
    expect(evidence.furtherCaptureGateRequired).toBe(true);
  });
});
