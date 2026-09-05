import { createAudioSignalPresenceProposal } from "./audio-signal-presence-proposal";

describe("audio signal-presence proposal", () => {
  it("binds the completed source session while retaining sample access closed", () => {
    const proposal = createAudioSignalPresenceProposal();
    expect(proposal.acceptedSourceSessionBound).toBe(true);
    expect(proposal.acceptedSourceSessionCompletedWithinCeiling).toBe(true);
    expect(proposal.currentPermissionStateInferred).toBe(false);
    expect(proposal.sampleAuthorizationDerivedFromSourceSession).toBe(false);
    expect(proposal.state).toBe("intervention_required");
    expect(proposal.executionAuthorized).toBe(false);
    expect(proposal.applicationOperationAvailable).toBe(false);
  });
});
