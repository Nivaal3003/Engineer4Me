import { describe, expect, it } from "vitest";
import { createControlledMicrophoneSourceSessionOutcomeEvidence } from "./controlled-microphone-source-session-outcome";

const automatic = () => createControlledMicrophoneSourceSessionOutcomeEvidence({
  outcome: "source_session_completed_automatic_stop",
  getUserMediaCallCount: 1,
  mediaStreamReturned: true,
  sourceSessionStarted: true,
  sourceSessionStopReason: "automatic_safety_stop",
  observedSourceSessionMilliseconds: 2000,
  returnedTrackCount: 1,
  returnedAudioTrackCount: 1,
  returnedVideoTrackCount: 0,
  audioTrackKindsOnly: true,
  allReturnedTracksLiveBeforeStop: true,
  trackStopCallCount: 1,
  allReturnedTracksEnded: true,
  userEarlyStopControlAvailable: true,
  userEarlyStopRequested: false,
  automaticStopTriggered: true,
});

describe("controlled microphone source-session outcome", () => {
  it("accepts an automatic stop within the three-second ceiling", () => {
    expect(automatic()).toMatchObject({
      outcome: "source_session_completed_automatic_stop",
      observedSourceSessionMilliseconds: 2000,
      audioSampleReadPerformed: false,
      furtherAudioSampleGateRequired: true,
    });
  });

  it("accepts a trusted user early stop", () => {
    expect(createControlledMicrophoneSourceSessionOutcomeEvidence({
      ...automatic(),
      outcome: "source_session_completed_user_stop",
      sourceSessionStopReason: "user_stop",
      observedSourceSessionMilliseconds: 400,
      userEarlyStopRequested: true,
      automaticStopTriggered: false,
    })).toMatchObject({ outcome: "source_session_completed_user_stop" });
  });

  it("accepts a denied request without active-session claims", () => {
    expect(createControlledMicrophoneSourceSessionOutcomeEvidence({
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
    })).toMatchObject({ sourceSessionStarted: false });
  });

  it("rejects a session beyond the maximum", () => {
    expect(() => createControlledMicrophoneSourceSessionOutcomeEvidence({
      ...automatic(),
      observedSourceSessionMilliseconds: 3001,
    })).toThrow(/three-second ceiling/i);
  });
});
