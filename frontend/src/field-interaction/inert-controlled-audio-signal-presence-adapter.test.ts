import { describe, expect, it } from "vitest";
import { createInertControlledSignalPresenceAdapter } from "./inert-controlled-audio-signal-presence-adapter";

describe("inert controlled signal-presence adapter", () => {
  it("exposes no application operation and zero side-effect counters", () => {
    expect(createInertControlledSignalPresenceAdapter()).toEqual({
      kind: "inert_controlled_signal_presence_adapter",
      operationAvailable: false,
      counters: {
        microphoneRequestCount: 0,
        sampleReadCount: 0,
        playbackCount: 0,
        recordingCount: 0,
        persistenceCount: 0,
        transmissionCount: 0,
        backendRequestCount: 0,
        externalAiRequestCount: 0,
      },
    });
  });
});
