import { describe, expect, it } from "vitest";
import { createInertMicrophoneCaptureAdapter } from "./inert-microphone-capture-adapter";

describe("inert microphone capture adapter", () => {
  it("exposes no capture or downstream media operation", () => {
    expect(createInertMicrophoneCaptureAdapter()).toEqual({
      captureStartOperationAvailable: false,
      captureStopOperationAvailable: false,
      consentRecordingOperationAvailable: false,
      trustedGestureRecordingOperationAvailable: false,
      permissionStatusQueryOperationAvailable: false,
      deviceEnumerationOperationAvailable: false,
      sampleReadOperationAvailable: false,
      recordingOperationAvailable: false,
      persistenceOperationAvailable: false,
      backendTransportOperationAvailable: false,
      externalAiOperationAvailable: false,
      counters: {
        sourceSessionStarts: 0,
        getUserMediaCalls: 0,
        trackStopCalls: 0,
        audioSamplesRead: 0,
        recordingsCreated: 0,
        persistedMediaBytes: 0,
        transmittedMediaBytes: 0,
        backendRequests: 0,
        externalAiRequests: 0,
      },
    });
  });
});
