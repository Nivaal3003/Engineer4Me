export const ACCEPTED_AUDIO_SAMPLE_PROPOSAL_COMMIT =
  "b4daf7eb37f4b3d5a71339bb348139353ba09509" as const;
export const ACCEPTED_AUDIO_SAMPLE_PROPOSAL_TREE =
  "5848c9646e45b09a4006b9840457f34347e15acb" as const;
export const ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256 =
  "3a3760350ca6319a642b83a292f912e46b9f1bd96ab24ca58ca8ab1b5453d378" as const;

export interface AcceptedAudioSampleProposalEvidence {
  readonly commit: string;
  readonly tree: string;
  readonly acceptanceArchiveSha256: string;
  readonly boundedProposalImplemented: boolean;
  readonly maximumFrameLength: number;
  readonly maximumRawBytes: number;
  readonly maximumSourceIntervalMilliseconds: number;
  readonly exactSampleReadCallMaximum: number;
  readonly currentPermissionStateInferred: boolean;
  readonly audioSampleExecutionAuthorized: boolean;
}

export interface ImportedAudioSampleProposalEvidence {
  readonly accepted: true;
  readonly maximumFrameLength: 2048;
  readonly maximumRawBytes: 8192;
  readonly maximumSourceIntervalMilliseconds: 1000;
  readonly exactSampleReadCallMaximum: 1;
  readonly currentPermissionStateInferred: false;
  readonly audioSampleExecutionAuthorized: false;
}

export function importAcceptedAudioSampleProposalEvidence(
  evidence: AcceptedAudioSampleProposalEvidence,
): ImportedAudioSampleProposalEvidence {
  if (
    evidence.commit !== ACCEPTED_AUDIO_SAMPLE_PROPOSAL_COMMIT ||
    evidence.tree !== ACCEPTED_AUDIO_SAMPLE_PROPOSAL_TREE ||
    evidence.acceptanceArchiveSha256 !==
      ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256
  ) {
    throw new Error("Accepted audio-sample proposal archive identity differs");
  }
  if (
    !evidence.boundedProposalImplemented ||
    evidence.maximumFrameLength !== 2048 ||
    evidence.maximumRawBytes !== 8192 ||
    evidence.maximumSourceIntervalMilliseconds !== 1000 ||
    evidence.exactSampleReadCallMaximum !== 1 ||
    evidence.currentPermissionStateInferred ||
    evidence.audioSampleExecutionAuthorized
  ) {
    throw new Error("Accepted audio-sample proposal boundaries differ");
  }
  return Object.freeze({
    accepted: true,
    maximumFrameLength: 2048,
    maximumRawBytes: 8192,
    maximumSourceIntervalMilliseconds: 1000,
    exactSampleReadCallMaximum: 1,
    currentPermissionStateInferred: false,
    audioSampleExecutionAuthorized: false,
  });
}
