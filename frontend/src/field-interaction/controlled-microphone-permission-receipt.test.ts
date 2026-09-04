import { createControlledMicrophonePermissionOutcomeEvidence } from "./controlled-microphone-permission-outcome";
import { createControlledMicrophonePermissionPolicy } from "./controlled-microphone-permission-policy";
import { createControlledMicrophonePermissionReceipt } from "./controlled-microphone-permission-receipt";

describe("controlled microphone permission receipt", () => {
  it("retains the capture gate after a safe request outcome", () => {
    const receipt = createControlledMicrophonePermissionReceipt({
      policy: createControlledMicrophonePermissionPolicy(),
      outcome: createControlledMicrophonePermissionOutcomeEvidence({
        evidenceId: "controlled-microphone-outcome-003",
        outcome: "not_allowed_or_dismissed",
        getUserMediaCallCount: 1,
        explicitConsentRecorded: true,
        trustedClickRecorded: true,
        mediaStreamReturned: false,
        returnedTrackCount: 0,
        trackStopCallCount: 0,
        allReturnedTracksEnded: false,
      }),
    });
    expect(receipt.state).toBe("accepted");
    expect(receipt.exactRequestCallCount).toBe(1);
    expect(receipt.captureAuthorized).toBe(false);
    expect(receipt.furtherCaptureGateRequired).toBe(true);
  });
});
