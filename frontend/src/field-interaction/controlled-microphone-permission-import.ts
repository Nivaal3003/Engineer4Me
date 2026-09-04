import { createControlledMicrophonePermissionOutcomeEvidence } from "./controlled-microphone-permission-outcome";

export const ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID =
  "ea51b4f927f27f3ece38f6b6d45eebee61ade1565fe9783423a141200fee5494";
export const ACCEPTED_CONTROLLED_MICROPHONE_COMMIT =
  "2a48c6188feb41f99b7da4c3130f89e9e5b2bcc1";
export const ACCEPTED_CONTROLLED_MICROPHONE_TREE =
  "b1cc6a13e8751f18626ca12da2189f6798c66574";
export const ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256 =
  "cfbcfd0de25fbc19ab97bced26a7b77875a1f4f1b3aea08b3bd9fc99abf2e7a9";

export interface ImportedControlledMicrophonePermissionOutcome {
  readonly source: "accepted_batch463_474_evidence";
  readonly batchContractId: typeof ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID;
  readonly commit: typeof ACCEPTED_CONTROLLED_MICROPHONE_COMMIT;
  readonly tree: typeof ACCEPTED_CONTROLLED_MICROPHONE_TREE;
  readonly acceptanceArchiveSha256: typeof ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256;
  readonly outcome: "granted_tracks_stopped";
  readonly exactGetUserMediaCallCount: 1;
  readonly returnedTrackCount: 1;
  readonly trackStopCallCount: 1;
  readonly allReturnedTracksEnded: true;
  readonly immediateTrackTerminationAccepted: true;
  readonly captureAuthorizationDerived: false;
  readonly currentPermissionStateInferred: false;
  readonly permissionStateKnown: false;
  readonly importedEvidenceOnly: true;
  readonly furtherCaptureGateRequired: true;
}

export function importAcceptedControlledMicrophonePermissionOutcome(input: {
  readonly batchContractId: string;
  readonly commit: string;
  readonly tree: string;
  readonly acceptanceArchiveSha256: string;
  readonly outcome: string;
  readonly getUserMediaCallCount: number;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
}): ImportedControlledMicrophonePermissionOutcome {
  if (input.batchContractId !== ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID) {
    throw new Error("Controlled microphone parent contract identity differs.");
  }
  if (input.commit !== ACCEPTED_CONTROLLED_MICROPHONE_COMMIT) {
    throw new Error("Controlled microphone parent commit differs.");
  }
  if (input.tree !== ACCEPTED_CONTROLLED_MICROPHONE_TREE) {
    throw new Error("Controlled microphone parent tree differs.");
  }
  if (input.acceptanceArchiveSha256 !== ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256) {
    throw new Error("Controlled microphone parent archive identity differs.");
  }
  if (input.outcome !== "granted_tracks_stopped") {
    throw new Error("The accepted parent outcome is not granted_tracks_stopped.");
  }

  const accepted = createControlledMicrophonePermissionOutcomeEvidence({
    evidenceId: "phase10-batch463-474-granted-tracks-stopped",
    outcome: "granted_tracks_stopped",
    getUserMediaCallCount: input.getUserMediaCallCount,
    explicitConsentRecorded: true,
    trustedClickRecorded: true,
    mediaStreamReturned: true,
    returnedTrackCount: input.returnedTrackCount,
    trackStopCallCount: input.trackStopCallCount,
    allReturnedTracksEnded: input.allReturnedTracksEnded,
  });

  if (!accepted.immediateTrackTerminationAccepted) {
    throw new Error("Accepted parent immediate-track termination evidence differs.");
  }
  if (accepted.returnedTrackCount !== 1 || accepted.trackStopCallCount !== 1) {
    throw new Error("Accepted parent track-count evidence differs.");
  }

  return Object.freeze({
    source: "accepted_batch463_474_evidence",
    batchContractId: ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID,
    commit: ACCEPTED_CONTROLLED_MICROPHONE_COMMIT,
    tree: ACCEPTED_CONTROLLED_MICROPHONE_TREE,
    acceptanceArchiveSha256: ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256,
    outcome: "granted_tracks_stopped",
    exactGetUserMediaCallCount: 1,
    returnedTrackCount: 1,
    trackStopCallCount: 1,
    allReturnedTracksEnded: true,
    immediateTrackTerminationAccepted: true,
    captureAuthorizationDerived: false,
    currentPermissionStateInferred: false,
    permissionStateKnown: false,
    importedEvidenceOnly: true,
    furtherCaptureGateRequired: true,
  });
}

export function createAcceptedControlledMicrophonePermissionImport():
  ImportedControlledMicrophonePermissionOutcome {
  return importAcceptedControlledMicrophonePermissionOutcome({
    batchContractId: ACCEPTED_CONTROLLED_MICROPHONE_BATCH_CONTRACT_ID,
    commit: ACCEPTED_CONTROLLED_MICROPHONE_COMMIT,
    tree: ACCEPTED_CONTROLLED_MICROPHONE_TREE,
    acceptanceArchiveSha256: ACCEPTED_CONTROLLED_MICROPHONE_ARCHIVE_SHA256,
    outcome: "granted_tracks_stopped",
    getUserMediaCallCount: 1,
    returnedTrackCount: 1,
    trackStopCallCount: 1,
    allReturnedTracksEnded: true,
  });
}
