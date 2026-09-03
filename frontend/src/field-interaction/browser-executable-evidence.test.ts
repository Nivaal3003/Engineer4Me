import { createControlledBrowserExecutableEvidence } from "./browser-executable-evidence";

const SHA256 = "1".repeat(64);

describe("controlled browser executable evidence", () => {
  it("accepts only reviewed ordinary signed-file evidence without persisting identity", () => {
    const evidence = createControlledBrowserExecutableEvidence({
      evidenceId: "controlled-browser-executable-fixture",
      source: "scripted_test_fixture",
      executableFilePresent: true,
      executableRegularFile: true,
      executableReparsePointDetected: false,
      executableBytes: 1024,
      executableSha256: SHA256,
      signatureStatus: "valid",
      signerPolicyAccepted: true,
      reviewCompleted: true,
    });
    expect(evidence).toMatchObject({
      state: "accepted",
      executablePathPersisted: false,
      signerIdentityPersisted: false,
      browserNameCollected: false,
      browserVersionCollected: false,
      userAgentRead: false,
      clientHintsRead: false,
      executableInstalledOrDownloaded: false,
    });
  });

  it("fails closed for a reparse point, invalid signature, or incomplete review", () => {
    const evidence = createControlledBrowserExecutableEvidence({
      evidenceId: "controlled-browser-executable-invalid",
      source: "scripted_test_fixture",
      executableFilePresent: true,
      executableRegularFile: true,
      executableReparsePointDetected: true,
      executableBytes: 1024,
      executableSha256: SHA256,
      signatureStatus: "invalid",
      signerPolicyAccepted: false,
      reviewCompleted: false,
    });
    expect(evidence.state).toBe("invalid");
    expect(evidence.blockingReasons).toHaveLength(4);
  });
});
