import { describe, expect, it } from "vitest";
import { createControlledSignalPresenceReceipt } from "./controlled-audio-signal-presence-receipt";

describe("controlled audio signal-presence receipt", () => {
  it("retains the next intervention boundary", () => {
    const receipt = createControlledSignalPresenceReceipt({
      contractId: "a".repeat(64),
      parentCommit: "b".repeat(40),
      outcome: {
        outcome: "signal_absent",
        signalPresenceDetected: false,
        sampleReadCallCount: 1,
        sampleBufferZeroized: true,
        processingContextClosed: true,
        everyReturnedTrackStopped: true,
        numericAmplitudeRetained: false,
        waveformRetained: false,
        rawSampleBufferRetained: false,
      },
    });
    expect(receipt.applicationAudioSampleOperationAvailable).toBe(false);
    expect(receipt.furtherVoiceInterpretationGateRequired).toBe(true);
  });
});
