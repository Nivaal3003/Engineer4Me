import {
  ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_ARCHIVE_SHA256,
  ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_COMMIT,
  createAcceptedMicrophonePermissionActivationEvidence,
} from "./microphone-permission-activation-evidence";

describe("accepted microphone permission activation evidence", () => {
  it("binds the accepted read-only capability proof without inferring permission", () => {
    const evidence = createAcceptedMicrophonePermissionActivationEvidence();
    expect(evidence.acceptedCommit).toBe(ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_COMMIT);
    expect(evidence.acceptanceArchiveSha256).toBe(
      ACCEPTED_BROWSER_CAPABILITY_OBSERVATION_ARCHIVE_SHA256,
    );
    expect(evidence.permission).toBe("microphone");
    expect(evidence.observationAccepted).toBe(true);
    expect(evidence.propertyPresenceEvidenceOnly).toBe(true);
    expect(evidence.permissionStateKnown).toBe(false);
    expect(evidence.permissionStatusQueried).toBe(false);
    expect(evidence.browserPermissionApiCalled).toBe(false);
    expect(evidence.permissionPromptShown).toBe(false);
    expect(evidence.captureStarted).toBe(false);
  });
});
