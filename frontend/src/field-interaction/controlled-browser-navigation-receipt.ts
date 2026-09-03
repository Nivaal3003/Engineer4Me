import type { ControlledBrowserExecutableEvidence } from "./browser-executable-evidence";
import type { ControlledBrowserNavigationObservation } from "./controlled-browser-navigation-observation";
import type { ControlledBrowserNavigationPolicy } from "./controlled-browser-navigation-policy";

export interface ControlledBrowserNavigationReceipt {
  readonly state: "accepted" | "invalid";
  readonly executableEvidenceAccepted: boolean;
  readonly navigationObservationAccepted: boolean;
  readonly policyAccepted: boolean;
  readonly acceptanceArchiveEvidenceRequired: true;
  readonly applicationBrowserLaunchOperationAvailable: false;
  readonly furtherActivationInterventionRequired: true;
  readonly blockingReasons: readonly string[];
  readonly controlledBrowserExecuted: boolean;
  readonly permissionActivationAuthorized: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly externalNetworkConnectionEstablished: false;
  readonly backendTransportActivated: false;
  readonly protectedContentAccessed: false;
}

function policyAccepted(policy: ControlledBrowserNavigationPolicy): boolean {
  return policy.controlledVerifierBrowserLaunchAuthorized
    && !policy.applicationBrowserLaunchOperationAvailable
    && policy.reviewedExecutableEvidenceRequired
    && policy.headlessRequired
    && policy.freshEphemeralProfileRequired
    && policy.profileDeletionRequired
    && policy.maximumNavigationCount === 1
    && policy.maximumMainDocumentRequestCount === 1
    && policy.exactDefaultDenyHeaderRequired
    && policy.staticScriptFreeFixtureRequired
    && !policy.externalOriginNavigationAllowed
    && !policy.externalNetworkAllowed
    && !policy.redirectsAllowed
    && !policy.credentialsAllowed
    && !policy.downloadsAllowed
    && !policy.popupsAllowed
    && !policy.extensionsAllowed
    && !policy.serviceWorkersAllowed
    && !policy.persistentStorageAllowed
    && !policy.permissionOverridesAllowed
    && !policy.permissionQueriesAllowed
    && !policy.microphonePermissionAllowed
    && !policy.cameraPermissionAllowed
    && !policy.mediaDeviceEnumerationAllowed
    && !policy.captureAllowed
    && !policy.browserIdentityCollectionAllowed
    && !policy.userAgentCollectionAllowed
    && !policy.authenticationAllowed
    && !policy.bearerTokenAttachmentAllowed
    && !policy.backendTransportAllowed
    && !policy.protectedContentAccessAllowed
    && !policy.externalAiAllowed
    && !policy.productionDeploymentAllowed;
}

export function createControlledBrowserNavigationReceipt(input: {
  readonly executableEvidence: ControlledBrowserExecutableEvidence;
  readonly observation: ControlledBrowserNavigationObservation;
  readonly policy: ControlledBrowserNavigationPolicy;
}): ControlledBrowserNavigationReceipt {
  const executableEvidenceAccepted = input.executableEvidence.state === "accepted";
  const navigationObservationAccepted = input.observation.state === "accepted";
  const acceptedPolicy = policyAccepted(input.policy);
  const blockingReasons: string[] = [];
  if (!executableEvidenceAccepted) {
    blockingReasons.push(...input.executableEvidence.blockingReasons);
  }
  if (!navigationObservationAccepted) {
    blockingReasons.push(...input.observation.blockingReasons);
  }
  if (!acceptedPolicy) {
    blockingReasons.push("The controlled browser navigation policy differs from the accepted fail-closed profile.");
  }
  return Object.freeze({
    state: blockingReasons.length === 0 ? "accepted" : "invalid",
    executableEvidenceAccepted,
    navigationObservationAccepted,
    policyAccepted: acceptedPolicy,
    acceptanceArchiveEvidenceRequired: true,
    applicationBrowserLaunchOperationAvailable: false,
    furtherActivationInterventionRequired: true,
    blockingReasons: Object.freeze(blockingReasons),
    controlledBrowserExecuted: input.observation.browserExecuted,
    permissionActivationAuthorized: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    externalNetworkConnectionEstablished: false,
    backendTransportActivated: false,
    protectedContentAccessed: false,
  });
}
