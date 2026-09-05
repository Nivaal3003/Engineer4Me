import {
  ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256,
  ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID,
  ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT,
  ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE,
  createAcceptedMicrophoneSourceSessionImport,
  importAcceptedMicrophoneSourceSession,
} from "./accepted-microphone-source-session-import";

const acceptedInput = {
  batchContractId: ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID,
  commit: ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT,
  tree: ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE,
  acceptanceArchiveSha256: ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256,
  outcome: "source_session_completed_automatic_stop",
  stopReason: "automatic_safety_stop",
  observedMilliseconds: 2_013,
  getUserMediaCallCount: 1,
  returnedTrackCount: 1,
  trackStopCallCount: 1,
  allReturnedTracksEnded: true,
  hardCeilingWatchdogTriggered: false,
  audioSampleReadPerformed: false,
  audioPlaybackStarted: false,
  audioAnalysisPerformed: false,
  audioRecordingCreated: false,
  rawMediaPersisted: false,
  mediaTransmitted: false,
  externalNetworkConnectionEstablished: false,
} as const;

describe("accepted microphone source-session import", () => {
  it("imports the accepted automatic-stop outcome without deriving sample authorization", () => {
    const evidence = createAcceptedMicrophoneSourceSessionImport();
    expect(evidence.outcome).toBe("source_session_completed_automatic_stop");
    expect(evidence.observedMilliseconds).toBe(2_013);
    expect(evidence.allReturnedTracksEnded).toBe(true);
    expect(evidence.audioSampleReadPerformed).toBe(false);
    expect(evidence.audioSampleAuthorizationDerived).toBe(false);
  });

  it("fails closed when the accepted archive identity differs", () => {
    const mismatchedArchiveSha256 = `${
      ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256.slice(0, -1)
    }${
      ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256.endsWith("0") ? "1" : "0"
    }`;
    expect(mismatchedArchiveSha256).not.toBe(ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256);
    expect(() => importAcceptedMicrophoneSourceSession({
      ...acceptedInput,
      acceptanceArchiveSha256: mismatchedArchiveSha256,
    })).toThrow(/archive identity differs/i);
  });
});
