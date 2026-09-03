import { validateFieldInteractionIdentifier } from "./models";

export type ControlledBrowserExecutableEvidenceSource =
  | "bounded_standard_path_review"
  | "explicit_operator_path_review"
  | "scripted_test_fixture";

export type ControlledBrowserExecutableSignatureStatus =
  | "valid"
  | "invalid"
  | "unavailable";

export interface ControlledBrowserExecutableEvidence {
  readonly evidenceId: string;
  readonly source: ControlledBrowserExecutableEvidenceSource;
  readonly state: "accepted" | "invalid";
  readonly executableFilePresent: boolean;
  readonly executableRegularFile: boolean;
  readonly executableReparsePointDetected: boolean;
  readonly executableBytes: number;
  readonly executableSha256: string;
  readonly signatureStatus: ControlledBrowserExecutableSignatureStatus;
  readonly signerPolicyAccepted: boolean;
  readonly reviewCompleted: boolean;
  readonly blockingReasons: readonly string[];
  readonly executablePathPersisted: false;
  readonly signerIdentityPersisted: false;
  readonly browserNameCollected: false;
  readonly browserVersionCollected: false;
  readonly userAgentRead: false;
  readonly clientHintsRead: false;
  readonly executableInstalledOrDownloaded: false;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function createControlledBrowserExecutableEvidence(input: {
  readonly evidenceId: string;
  readonly source: ControlledBrowserExecutableEvidenceSource;
  readonly executableFilePresent: boolean;
  readonly executableRegularFile: boolean;
  readonly executableReparsePointDetected: boolean;
  readonly executableBytes: number;
  readonly executableSha256: string;
  readonly signatureStatus: ControlledBrowserExecutableSignatureStatus;
  readonly signerPolicyAccepted: boolean;
  readonly reviewCompleted: boolean;
}): ControlledBrowserExecutableEvidence {
  const executableSha256 = input.executableSha256.trim().toLowerCase();
  if (!SHA256_PATTERN.test(executableSha256)) {
    throw new Error(
      "Controlled browser executable SHA-256 must be exactly 64 lowercase hexadecimal characters.",
    );
  }
  if (!Number.isSafeInteger(input.executableBytes) || input.executableBytes <= 0) {
    throw new Error("Controlled browser executable byte count must be a positive safe integer.");
  }

  const blockingReasons: string[] = [];
  if (!input.executableFilePresent) {
    blockingReasons.push("The reviewed browser executable file is absent.");
  }
  if (!input.executableRegularFile) {
    blockingReasons.push("The reviewed browser executable is not an ordinary file.");
  }
  if (input.executableReparsePointDetected) {
    blockingReasons.push("A symbolic link, junction, or other reparse point is not accepted.");
  }
  if (input.signatureStatus !== "valid") {
    blockingReasons.push("The browser executable Authenticode signature is not valid.");
  }
  if (!input.signerPolicyAccepted) {
    blockingReasons.push("The browser executable signer is outside the accepted bounded policy.");
  }
  if (!input.reviewCompleted) {
    blockingReasons.push("The controlled browser executable review is incomplete.");
  }

  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Controlled browser executable evidence identifier",
    ),
    source: input.source,
    state: blockingReasons.length === 0 ? "accepted" : "invalid",
    executableFilePresent: input.executableFilePresent,
    executableRegularFile: input.executableRegularFile,
    executableReparsePointDetected: input.executableReparsePointDetected,
    executableBytes: input.executableBytes,
    executableSha256,
    signatureStatus: input.signatureStatus,
    signerPolicyAccepted: input.signerPolicyAccepted,
    reviewCompleted: input.reviewCompleted,
    blockingReasons: Object.freeze(blockingReasons),
    executablePathPersisted: false,
    signerIdentityPersisted: false,
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    clientHintsRead: false,
    executableInstalledOrDownloaded: false,
  });
}
