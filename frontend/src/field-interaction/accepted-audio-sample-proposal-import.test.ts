import { describe, expect, it } from "vitest";
import {
  ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256,
  ACCEPTED_AUDIO_SAMPLE_PROPOSAL_COMMIT,
  ACCEPTED_AUDIO_SAMPLE_PROPOSAL_TREE,
  importAcceptedAudioSampleProposalEvidence,
} from "./accepted-audio-sample-proposal-import";

const acceptedEvidence = {
  commit: ACCEPTED_AUDIO_SAMPLE_PROPOSAL_COMMIT,
  tree: ACCEPTED_AUDIO_SAMPLE_PROPOSAL_TREE,
  acceptanceArchiveSha256: ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256,
  boundedProposalImplemented: true,
  maximumFrameLength: 2048,
  maximumRawBytes: 8192,
  maximumSourceIntervalMilliseconds: 1000,
  exactSampleReadCallMaximum: 1,
  currentPermissionStateInferred: false,
  audioSampleExecutionAuthorized: false,
} as const;

describe("accepted audio-sample proposal import", () => {
  it("imports the exact proposal without deriving execution authorization", () => {
    expect(importAcceptedAudioSampleProposalEvidence(acceptedEvidence)).toEqual({
      accepted: true,
      maximumFrameLength: 2048,
      maximumRawBytes: 8192,
      maximumSourceIntervalMilliseconds: 1000,
      exactSampleReadCallMaximum: 1,
      currentPermissionStateInferred: false,
      audioSampleExecutionAuthorized: false,
    });
  });

  it("fails closed when the accepted archive identity differs", () => {
    const finalCharacter = ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256.endsWith("0")
      ? "1"
      : "0";
    const mismatch = `${ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256.slice(0, -1)}${finalCharacter}`;
    expect(mismatch).not.toBe(ACCEPTED_AUDIO_SAMPLE_PROPOSAL_ARCHIVE_SHA256);
    expect(() =>
      importAcceptedAudioSampleProposalEvidence({
        ...acceptedEvidence,
        acceptanceArchiveSha256: mismatch,
      }),
    ).toThrow(/archive identity differs/i);
  });
});
