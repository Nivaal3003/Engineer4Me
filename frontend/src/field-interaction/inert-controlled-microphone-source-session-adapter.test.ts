import { describe, expect, it } from "vitest";
import { createInertControlledMicrophoneSourceSessionAdapter } from "./inert-controlled-microphone-source-session-adapter";

describe("inert controlled microphone source-session adapter", () => {
  it("exposes no browser, microphone, sample, recording, persistence, or transport operation", () => {
    expect(createInertControlledMicrophoneSourceSessionAdapter()).toEqual({
      adapterType: "inert_controlled_microphone_source_session",
      browserLaunchOperationAvailable: false,
      navigationOperationAvailable: false,
      getUserMediaOperationAvailable: false,
      sourceSessionStartOperationAvailable: false,
      sourceSessionStopOperationAvailable: false,
      permissionStatusQueryOperationAvailable: false,
      mediaDeviceEnumerationOperationAvailable: false,
      audioSampleReadOperationAvailable: false,
      recordingOperationAvailable: false,
      persistenceOperationAvailable: false,
      transmissionOperationAvailable: false,
      backendTransportOperationAvailable: false,
      externalAiOperationAvailable: false,
      browserLaunchCount: 0,
      getUserMediaCallCount: 0,
      sourceSessionStartCount: 0,
      audioSampleReadCount: 0,
      recordingCount: 0,
      persistenceCount: 0,
      transmissionCount: 0,
    });
  });
});
