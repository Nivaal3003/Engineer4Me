import type { ControlledLocalBrowserExecutionPolicy } from "./local-browser-execution-policy";
import type { ControlledLoopbackResponseObservation } from "./loopback-response-observation";
import { validateFieldInteractionIdentifier } from "./models";

export type LocalBrowserExecutableEvidenceSource =
  | "none"
  | "reviewed_host_inventory"
  | "scripted_test_fixture";

export interface LocalBrowserExecutableEvidence {
  readonly evidenceId: string | null;
  readonly source: LocalBrowserExecutableEvidenceSource;
  readonly executableFilePresent: boolean;
  readonly executableSha256: string | null;
  readonly reviewCompleted: boolean;
  readonly browserNameCollected: false;
  readonly browserVersionCollected: false;
  readonly userAgentRead: false;
  readonly executableLaunched: false;
}

export type LocalBrowserExecutionReadinessState =
  | "loopback_observation_required"
  | "loopback_observation_invalid"
  | "browser_executable_evidence_required"
  | "browser_executable_evidence_invalid"
  | "execution_policy_invalid"
  | "intervention_required";

export interface LocalBrowserExecutionReadiness {
  readonly state: LocalBrowserExecutionReadinessState;
  readonly loopbackObservationAccepted: boolean;
  readonly exactDefaultDenyHeaderObserved: boolean;
  readonly executableEvidenceAccepted: boolean;
  readonly executionPolicyAccepted: boolean;
  readonly candidateForControlledBrowserExecutionGate: boolean;
  readonly interventionRequired: true;
  readonly blockingReasons: readonly string[];
  readonly browserLaunchAuthorized: false;
  readonly browserExecuted: false;
  readonly browserNameCollected: false;
  readonly browserVersionCollected: false;
  readonly userAgentRead: false;
  readonly externalNetworkRequestPerformed: false;
  readonly liveDeploymentHeaderRead: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly authenticationPerformed: false;
  readonly bearerTokenAttached: false;
  readonly backendTransportActivated: false;
  readonly protectedContentAccessed: false;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function createNoLocalBrowserExecutableEvidence():
  LocalBrowserExecutableEvidence {
  return Object.freeze({
    evidenceId: null,
    source: "none",
    executableFilePresent: false,
    executableSha256: null,
    reviewCompleted: false,
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    executableLaunched: false,
  });
}

export function createReviewedLocalBrowserExecutableEvidence(input: {
  readonly evidenceId: string;
  readonly source: Exclude<LocalBrowserExecutableEvidenceSource, "none">;
  readonly executableFilePresent: boolean;
  readonly executableSha256: string;
  readonly reviewCompleted: boolean;
}): LocalBrowserExecutableEvidence {
  const executableSha256 = input.executableSha256.trim().toLowerCase();
  if (!SHA256_PATTERN.test(executableSha256)) {
    throw new Error(
      "Local browser executable evidence SHA-256 must be exactly 64 lowercase hexadecimal characters.",
    );
  }
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Local browser executable evidence identifier",
    ),
    source: input.source,
    executableFilePresent: input.executableFilePresent,
    executableSha256,
    reviewCompleted: input.reviewCompleted,
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    executableLaunched: false,
  });
}

function policyAccepted(policy: ControlledLocalBrowserExecutionPolicy): boolean {
  return policy.headlessRequired
    && policy.isolatedUserDataDirectoryRequired
    && policy.ephemeralProfileDeletionRequired
    && policy.freshBrowserContextRequired
    && policy.loopbackNavigationOnly
    && !policy.externalOriginNavigationAllowed
    && !policy.externalNetworkAllowed
    && !policy.credentialStoreUseAllowed
    && !policy.extensionLoadingAllowed
    && !policy.serviceWorkersAllowed
    && !policy.persistentStorageAllowed
    && !policy.downloadsAllowed
    && !policy.popupsAllowed
    && !policy.permissionOverridesAllowed
    && !policy.microphonePermissionAllowed
    && !policy.cameraPermissionAllowed
    && !policy.mediaDeviceEnumerationAllowed
    && !policy.browserIdentityCollectionAllowed
    && !policy.userAgentCollectionAllowed
    && !policy.liveDeploymentHeaderReadAllowed
    && !policy.authenticationAllowed
    && !policy.bearerTokenAttachmentAllowed
    && !policy.backendTransportAllowed
    && !policy.protectedContentAccessAllowed
    && !policy.browserLaunchAuthorized
    && policy.interventionRequired;
}

export function evaluateLocalBrowserExecutionReadiness(input: {
  readonly observation: ControlledLoopbackResponseObservation | null;
  readonly executableEvidence: LocalBrowserExecutableEvidence;
  readonly policy: ControlledLocalBrowserExecutionPolicy;
}): LocalBrowserExecutionReadiness {
  const loopbackObservationAccepted = input.observation?.state === "accepted";
  const exactDefaultDenyHeaderObserved =
    input.observation?.exactDefaultDenyHeaderObserved === true;
  const executableEvidenceAccepted =
    input.executableEvidence.source !== "none"
    && input.executableEvidence.executableFilePresent
    && input.executableEvidence.reviewCompleted
    && input.executableEvidence.executableSha256 !== null;
  const executionPolicyAccepted = policyAccepted(input.policy);
  const reasons: string[] = [];
  let state: LocalBrowserExecutionReadinessState = "intervention_required";

  if (input.observation === null) {
    state = "loopback_observation_required";
    reasons.push("Controlled loopback response-header observation evidence is required.");
  } else if (!loopbackObservationAccepted || !exactDefaultDenyHeaderObserved) {
    state = "loopback_observation_invalid";
    reasons.push(...input.observation.blockingReasons);
  } else if (input.executableEvidence.source === "none") {
    state = "browser_executable_evidence_required";
    reasons.push("Reviewed local browser executable evidence is required.");
  } else if (!executableEvidenceAccepted) {
    state = "browser_executable_evidence_invalid";
    reasons.push("Local browser executable evidence is incomplete or unreviewed.");
  } else if (!executionPolicyAccepted) {
    state = "execution_policy_invalid";
    reasons.push("The controlled local browser execution policy is not fail closed.");
  } else {
    reasons.push(
      "Loopback, executable, and isolation prerequisites are accepted, but browser launch requires a separate intervention gate.",
    );
  }

  return Object.freeze({
    state,
    loopbackObservationAccepted,
    exactDefaultDenyHeaderObserved,
    executableEvidenceAccepted,
    executionPolicyAccepted,
    candidateForControlledBrowserExecutionGate: state === "intervention_required",
    interventionRequired: true,
    blockingReasons: Object.freeze(reasons),
    browserLaunchAuthorized: false,
    browserExecuted: false,
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    externalNetworkRequestPerformed: false,
    liveDeploymentHeaderRead: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    authenticationPerformed: false,
    bearerTokenAttached: false,
    backendTransportActivated: false,
    protectedContentAccessed: false,
  });
}
