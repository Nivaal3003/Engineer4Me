import { describe, expect, it } from "vitest";
import {
  MICROPHONE_CAPTURE_EXACT_GET_USER_MEDIA_CALL_MAXIMUM,
  MICROPHONE_CAPTURE_MAXIMUM_SOURCE_SESSION_MS,
  createMicrophoneCapturePolicy,
} from "./microphone-capture-policy";

describe("bounded microphone capture policy", () => {
  it("retains an exact one-call, three-second, no-sample boundary", () => {
    const policy = createMicrophoneCapturePolicy();

    expect(policy).toMatchObject({
      scope: "microphone_only",
      exactGetUserMediaCallMaximum:
        MICROPHONE_CAPTURE_EXACT_GET_USER_MEDIA_CALL_MAXIMUM,
      maximumSourceSessionMilliseconds:
        MICROPHONE_CAPTURE_MAXIMUM_SOURCE_SESSION_MS,
      userEarlyStopRequired: true,
      automaticStopAtCeilingRequired: true,
      everyReturnedTrackStopRequired: true,
      applicationOperationAvailable: false,
      captureExecutionAuthorized: false,
      audioElementAttachmentAllowed: false,
      audioContextCreationAllowed: false,
      mediaRecorderCreationAllowed: false,
      audioWorkletCreationAllowed: false,
      audioSampleReadAllowed: false,
      audioAnalysisAllowed: false,
      recordingCreationAllowed: false,
      rawMediaPersistenceAllowed: false,
      mediaTransmissionAllowed: false,
      automaticRetryAllowed: false,
      executionInterventionRequired: true,
    });
  });
});
