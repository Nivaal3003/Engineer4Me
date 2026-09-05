import { describe, expect, it } from "vitest";
import {
  ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256,
  ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID,
  ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT,
  ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE,
  createAcceptedMicrophoneCaptureProposalImport,
  importAcceptedMicrophoneCaptureProposal,
} from "./accepted-microphone-capture-proposal-import";

describe("accepted microphone capture proposal import", () => {
  it("imports the three-second proposal without inferring permission or authorization", () => {
    expect(createAcceptedMicrophoneCaptureProposalImport()).toMatchObject({
      sourceSessionMaximumMilliseconds: 3000,
      exactGetUserMediaCallMaximum: 1,
      currentPermissionStateInferred: false,
      captureExecutionAuthorizedByParent: false,
      audioSampleAccessAuthorized: false,
    });
  });

  it("fails closed when the accepted archive identity differs", () => {
    const mismatchedArchiveSha256 = `${
      ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256.slice(0, -1)
    }${ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256.endsWith("0") ? "1" : "0"}`;

    expect(mismatchedArchiveSha256).not.toBe(
      ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_ARCHIVE_SHA256,
    );
    expect(() => importAcceptedMicrophoneCaptureProposal({
      batchContractId: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_BATCH_CONTRACT_ID,
      commit: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_COMMIT,
      tree: ACCEPTED_MICROPHONE_CAPTURE_PROPOSAL_TREE,
      acceptanceArchiveSha256: mismatchedArchiveSha256,
      sourceSessionMaximumMilliseconds: 3000,
      exactGetUserMediaCallMaximum: 1,
      captureSpecificConsentRequired: true,
      trustedSingleUseStartGestureRequired: true,
      userEarlyStopRequired: true,
      automaticStopAtCeilingRequired: true,
      everyReturnedTrackStopRequired: true,
      currentPermissionStateInferred: false,
      captureExecutionAuthorized: false,
    })).toThrow(/archive identity differs/i);
  });
});
