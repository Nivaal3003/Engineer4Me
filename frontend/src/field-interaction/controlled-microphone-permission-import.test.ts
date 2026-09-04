import { describe, expect, it } from "vitest";
import {
  ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256,
  ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID,
  ACCEPTED_CONTROLLED_MICROPHONE_COMMIT,
  ACCEPTED_CONTROLLED_MICROPHONE_TREE,
  createAcceptedControlledMicrophonePermissionImport,
  importAcceptedControlledMicrophonePermissionOutcome,
} from "./controlled-microphone-permission-import";

describe("accepted controlled microphone outcome import", () => {
  it("imports the granted-and-stopped evidence without deriving capture authorization", () => {
    const imported = createAcceptedControlledMicrophonePermissionImport();

    expect(imported).toMatchObject({
      outcome: "granted_tracks_stopped",
      exactGetUserMediaCallCount: 1,
      returnedTrackCount: 1,
      trackStopCallCount: 1,
      allReturnedTracksEnded: true,
      immediateTrackTerminationAccepted: true,
      captureAuthorizationDerived: false,
      currentPermissionStateInferred: false,
      permissionStateKnown: false,
      furtherCaptureGateRequired: true,
    });
  });

  it("fails closed when the acceptance identity differs", () => {
    expect(() =>
      importAcceptedControlledMicrophonePermissionOutcome({
        batchContractId: ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID,
        commit: ACCEPTED_CONTROLLED_MICROPHONE_COMMIT,
        tree: ACCEPTED_CONTROLLED_MICROPHONE_TREE,
        acceptanceArchiveSha256: `${ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256.slice(0, -1)}0`,
        outcome: "granted_tracks_stopped",
        getUserMediaCallCount: 1,
        returnedTrackCount: 1,
        trackStopCallCount: 1,
        allReturnedTracksEnded: true,
      }),
    ).toThrow(/archive identity differs/i);
  });
});
