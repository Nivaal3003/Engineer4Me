export const ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID =
  "93c75f6d75e988e729688bf89941c3c310cc33bb4364df7a1d6629fd79acadaa";
export const ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT =
  "85640f707dd4742d8eca64a9892320dbb4c25448";
export const ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE =
  "2b1172f7df1db0ad7ca71c3f128add4543309bba";
export const ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256 =
  "3c479948ff3ba232676d516fb75e1cfd9cfa5738dc90e55422de3c6923e35b40";

export interface AcceptedMicrophoneSourceSessionImport {
  readonly source: "accepted_batch487_498_source_session";
  readonly batchContractId: typeof ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID;
  readonly commit: typeof ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT;
  readonly tree: typeof ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE;
  readonly acceptanceArchiveSha256: typeof ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256;
  readonly outcome: "source_session_completed_automatic_stop";
  readonly stopReason: "automatic_safety_stop";
  readonly observedMilliseconds: 2013;
  readonly getUserMediaCallCount: 1;
  readonly returnedTrackCount: 1;
  readonly trackStopCallCount: 1;
  readonly allReturnedTracksEnded: true;
  readonly hardCeilingWatchdogTriggered: false;
  readonly audioSampleReadPerformed: false;
  readonly audioPlaybackStarted: false;
  readonly audioAnalysisPerformed: false;
  readonly audioRecordingCreated: false;
  readonly rawMediaPersisted: false;
  readonly mediaTransmitted: false;
  readonly externalNetworkConnectionEstablished: false;
  readonly audioSampleAuthorizationDerived: false;
}

export function importAcceptedMicrophoneSourceSession(input: {
  readonly batchContractId: string;
  readonly commit: string;
  readonly tree: string;
  readonly acceptanceArchiveSha256: string;
  readonly outcome: string;
  readonly stopReason: string;
  readonly observedMilliseconds: number;
  readonly getUserMediaCallCount: number;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
  readonly hardCeilingWatchdogTriggered: boolean;
  readonly audioSampleReadPerformed: boolean;
  readonly audioPlaybackStarted: boolean;
  readonly audioAnalysisPerformed: boolean;
  readonly audioRecordingCreated: boolean;
  readonly rawMediaPersisted: boolean;
  readonly mediaTransmitted: boolean;
  readonly externalNetworkConnectionEstablished: boolean;
}): AcceptedMicrophoneSourceSessionImport {
  if (input.batchContractId !== ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID) {
    throw new Error("Accepted microphone source-session contract identity differs.");
  }
  if (input.commit !== ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT) {
    throw new Error("Accepted microphone source-session commit differs.");
  }
  if (input.tree !== ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE) {
    throw new Error("Accepted microphone source-session tree differs.");
  }
  if (input.acceptanceArchiveSha256 !== ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256) {
    throw new Error("Accepted microphone source-session archive identity differs.");
  }
  if (input.outcome !== "source_session_completed_automatic_stop" ||
      input.stopReason !== "automatic_safety_stop") {
    throw new Error("Accepted microphone source-session outcome differs.");
  }
  if (input.observedMilliseconds !== 2_013 ||
      input.observedMilliseconds > 3_000 ||
      input.hardCeilingWatchdogTriggered) {
    throw new Error("Accepted microphone source-session duration evidence differs.");
  }
  if (input.getUserMediaCallCount !== 1 ||
      input.returnedTrackCount !== 1 ||
      input.trackStopCallCount !== input.returnedTrackCount ||
      !input.allReturnedTracksEnded) {
    throw new Error("Accepted microphone source-session track evidence differs.");
  }
  if (input.audioSampleReadPerformed ||
      input.audioPlaybackStarted ||
      input.audioAnalysisPerformed ||
      input.audioRecordingCreated ||
      input.rawMediaPersisted ||
      input.mediaTransmitted ||
      input.externalNetworkConnectionEstablished) {
    throw new Error("Accepted microphone source-session side-effect boundary differs.");
  }
  return Object.freeze({
    source: "accepted_batch487_498_source_session",
    batchContractId: ACCEPTED_MICROPHONE_SOURCE_SESSION_BATCH_CONTRACT_ID,
    commit: ACCEPTED_MICROPHONE_SOURCE_SESSION_COMMIT,
    tree: ACCEPTED_MICROPHONE_SOURCE_SESSION_TREE,
    acceptanceArchiveSha256: ACCEPTED_MICROPHONE_SOURCE_SESSION_ARCHIVE_SHA256,
    outcome: "source_session_completed_automatic_stop",
    stopReason: "automatic_safety_stop",
    observedMilliseconds: 2013,
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
    audioSampleAuthorizationDerived: false,
  });
}

export function createAcceptedMicrophoneSourceSessionImport(): AcceptedMicrophoneSourceSessionImport {
  return importAcceptedMicrophoneSourceSession({
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
  });
}
