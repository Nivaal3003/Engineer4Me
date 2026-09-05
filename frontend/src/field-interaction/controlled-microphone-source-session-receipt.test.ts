import { describe, expect, it } from "vitest";
import { createControlledMicrophoneSourceSessionOutcomeEvidence } from "./controlled-microphone-source-session-outcome";
import { createControlledMicrophoneSourceSessionReceipt } from "./controlled-microphone-source-session-receipt";

describe("controlled microphone source-session receipt", () => {
  it("accepts completed source evidence while retaining all audio-use gates", () => {
    const outcome = createControlledMicrophoneSourceSessionOutcomeEvidence({
      outcome: "source_session_completed_user_stop",
      getUserMediaCallCount: 1,
      mediaStreamReturned: true,
      sourceSessionStarted: true,
      sourceSessionStopReason: "user_stop",
      observedSourceSessionMilliseconds: 500,
      returnedTrackCount: 1,
      returnedAudioTrackCount: 1,
      returnedVideoTrackCount: 0,
      audioTrackKindsOnly: true,
      allReturnedTracksLiveBeforeStop: true,
      trackStopCallCount: 1,
      allReturnedTracksEnded: true,
      userEarlyStopControlAvailable: true,
      userEarlyStopRequested: true,
      automaticStopTriggered: false,
    });
    expect(createControlledMicrophoneSourceSessionReceipt({
      outcome,
      cleanup: {
        browserProcessClosed: true,
        ephemeralProfileDeleted: true,
        externalNetworkConnectionEstablished: false,
        automaticRetryPerformed: false,
      },
    })).toMatchObject({
      sourceSessionExecutionAccepted: true,
      applicationAudioSampleAccessAuthorized: false,
      furtherAudioSampleGateRequired: true,
    });
  });

  it("rejects incomplete cleanup", () => {
    const outcome = createControlledMicrophoneSourceSessionOutcomeEvidence({
      outcome: "not_allowed_or_dismissed",
      getUserMediaCallCount: 1,
      mediaStreamReturned: false,
      sourceSessionStarted: false,
      sourceSessionStopReason: "not_started",
      observedSourceSessionMilliseconds: null,
      returnedTrackCount: 0,
      returnedAudioTrackCount: 0,
      returnedVideoTrackCount: 0,
      audioTrackKindsOnly: true,
      allReturnedTracksLiveBeforeStop: false,
      trackStopCallCount: 0,
      allReturnedTracksEnded: false,
      userEarlyStopControlAvailable: false,
      userEarlyStopRequested: false,
      automaticStopTriggered: false,
    });
    expect(() => createControlledMicrophoneSourceSessionReceipt({
      outcome,
      cleanup: {
        browserProcessClosed: true,
        ephemeralProfileDeleted: false as true,
        externalNetworkConnectionEstablished: false,
        automaticRetryPerformed: false,
      },
    })).toThrow(/cleanup evidence/i);
  });
});
