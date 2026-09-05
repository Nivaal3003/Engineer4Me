import { describe, expect, it } from "vitest";
import {
  CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE,
  CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_SHA256,
  createControlledMicrophoneSourceSessionPolicy,
} from "./controlled-microphone-source-session-policy";

describe("controlled microphone source-session policy", () => {
  it("retains one microphone-only session under the three-second ceiling", () => {
    expect(createControlledMicrophoneSourceSessionPolicy()).toMatchObject({
      exactGetUserMediaCallMaximum: 1,
      maximumSourceSessionMilliseconds: 3000,
      automaticSafetyStopMilliseconds: 2000,
      hardCeilingWatchdogMilliseconds: 2500,
      sourceSessionStartedReceiptRequired: true,
      independentProcessWatchdogRequired: true,
      hardCeilingWatchdogClosesBrowser: true,
      userEarlyStopControlRequired: true,
      audioSampleReadAllowed: false,
      applicationOperationAvailable: false,
      furtherAudioSampleGateRequired: true,
    });
  });

  it("binds an accurate no-sample-use disclosure", () => {
    expect(CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE).toMatch(/no more than three seconds/i);
    expect(CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });
});
