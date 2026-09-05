import { describe, expect, it } from "vitest";
import { validateControlledSignalPresenceOutcome } from "./controlled-audio-signal-presence-outcome";

const accepted = {
  outcome: "signal_present",
  sampleReadCallCount: 1,
  frameLength: 2048,
  rawBytes: 8192,
  sourceIntervalMilliseconds: 120,
  signalPresenceDetected: true,
  sampleBufferZeroized: true,
  processingContextClosed: true,
  returnedTrackCount: 1,
  trackStopCallCount: 1,
  allReturnedTracksEnded: true,
  numericAmplitudeRetained: false,
  waveformRetained: false,
  rawSampleBufferRetained: false,
  audioPlaybackStarted: false,
  audioRecordingCreated: false,
  mediaTransmitted: false,
} as const;

describe("controlled audio signal-presence outcome", () => {
  it("retains only the boolean classification and teardown evidence", () => {
    expect(validateControlledSignalPresenceOutcome(accepted)).toEqual({
      outcome: "signal_present",
      signalPresenceDetected: true,
      sampleReadCallCount: 1,
      sampleBufferZeroized: true,
      processingContextClosed: true,
      everyReturnedTrackStopped: true,
      numericAmplitudeRetained: false,
      waveformRetained: false,
      rawSampleBufferRetained: false,
    });
  });

  it("rejects numeric amplitude retention", () => {
    expect(() => validateControlledSignalPresenceOutcome({
      ...accepted,
      numericAmplitudeRetained: true,
    })).toThrow(/prohibited side effect/i);
  });
});
