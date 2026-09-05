export const ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID =
  "51cb36e1cdc3c256ef540ea7400727bb9aa49d4381553c87d73601ca5ba840cf";
export const ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT =
  "837d619d5f0d57bcf7fcd934a66da1ddf3869014";
export const ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE =
  "1f01c0adf9268d73f43e7b183de9a41e04f3ec7b";
export const ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256 =
  "a7f46fbadf72353286b0904a88953a3fcd7b400b021744f1ef6515562bb47690";

export interface AcceptedMicrophoneCaptureProposalImport {
  readonly source: "accepted_batch475_486_capture_proposal";
  readonly batchContractId: typeof ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID;
  readonly commit: typeof ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT;
  readonly tree: typeof ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE;
  readonly acceptanceArchiveSha256: typeof ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256;
  readonly sourceSessionMaximumMilliseconds: 3000;
  readonly exactGetUserMediaCallMaximum: 1;
  readonly captureSpecificConsentRequired: true;
  readonly trustedSingleUseStartGestureRequired: true;
  readonly userEarlyStopRequired: true;
  readonly automaticStopAtCeilingRequired: true;
  readonly everyReturnedTrackStopRequired: true;
  readonly currentPermissionStateInferred: false;
  readonly captureExecutionAuthorizedByParent: false;
  readonly audioSampleAccessAuthorized: false;
  readonly recordingAuthorized: false;
  readonly persistenceAuthorized: false;
  readonly transmissionAuthorized: false;
}

export function importAcceptedMicrophoneCaptureProposal(input: {
  readonly batchContractId: string;
  readonly commit: string;
  readonly tree: string;
  readonly acceptanceArchiveSha256: string;
  readonly sourceSessionMaximumMilliseconds: number;
  readonly exactGetUserMediaCallMaximum: number;
  readonly captureSpecificConsentRequired: boolean;
  readonly trustedSingleUseStartGestureRequired: boolean;
  readonly userEarlyStopRequired: boolean;
  readonly automaticStopAtCeilingRequired: boolean;
  readonly everyReturnedTrackStopRequired: boolean;
  readonly currentPermissionStateInferred: boolean;
  readonly captureExecutionAuthorized: boolean;
}): AcceptedMicrophoneCaptureProposalImport {
  if (input.batchContractId !== ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID) {
    throw new Error("Accepted microphone capture proposal contract identity differs.");
  }
  if (input.commit !== ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT) {
    throw new Error("Accepted microphone capture proposal commit differs.");
  }
  if (input.tree !== ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE) {
    throw new Error("Accepted microphone capture proposal tree differs.");
  }
  if (input.acceptanceArchiveSha256 !== ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256) {
    throw new Error("Accepted microphone capture proposal archive identity differs.");
  }
  if (input.sourceSessionMaximumMilliseconds !== 3_000) {
    throw new Error("Accepted source-session ceiling differs.");
  }
  if (input.exactGetUserMediaCallMaximum !== 1) {
    throw new Error("Accepted source-session call maximum differs.");
  }
  if (!input.captureSpecificConsentRequired || !input.trustedSingleUseStartGestureRequired ||
      !input.userEarlyStopRequired || !input.automaticStopAtCeilingRequired ||
      !input.everyReturnedTrackStopRequired) {
    throw new Error("Accepted source-session control requirements differ.");
  }
  if (input.currentPermissionStateInferred || input.captureExecutionAuthorized) {
    throw new Error("Accepted proposal must retain permission inference and execution authorization closed.");
  }
  return Object.freeze({
    source: "accepted_batch475_486_capture_proposal",
    batchContractId: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID,
    commit: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT,
    tree: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE,
    acceptanceArchiveSha256: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256,
    sourceSessionMaximumMilliseconds: 3000,
    exactGetUserMediaCallMaximum: 1,
    captureSpecificConsentRequired: true,
    trustedSingleUseStartGestureRequired: true,
    userEarlyStopRequired: true,
    automaticStopAtCeilingRequired: true,
    everyReturnedTrackStopRequired: true,
    currentPermissionStateInferred: false,
    captureExecutionAuthorizedByParent: false,
    audioSampleAccessAuthorized: false,
    recordingAuthorized: false,
    persistenceAuthorized: false,
    transmissionAuthorized: false,
  });
}

export function createAcceptedMicrophoneCaptureProposalImport(): AcceptedMicrophoneCaptureProposalImport {
  return importAcceptedMicrophoneCaptureProposal({
    batchContractId: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID,
    commit: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT,
    tree: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE,
    acceptanceArchiveSha256: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256,
    sourceSessionMaximumMilliseconds: 3_000,
    exactGetUserMediaCallMaximum: 1,
    captureSpecificConsentRequired: true,
    trustedSingleUseStartGestureRequired: true,
    userEarlyStopRequired: true,
    automaticStopAtCeilingRequired: true,
    everyReturnedTrackStopRequired: true,
    currentPermissionStateInferred: false,
    captureExecutionAuthorized: false,
  });
}
