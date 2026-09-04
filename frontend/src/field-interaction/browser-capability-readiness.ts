import type { BrowserCapabilityObservation } from "./browser-capability-observation";
import type { BrowserCapabilityObservationPolicy } from "./browser-capability-observation-policy";

export interface BrowserCapabilityReadiness {
  readonly state: "evidence_accepted_activation_closed" | "unavailable";
  readonly observationAccepted: boolean;
  readonly secureTopLevelContextObserved: boolean;
  readonly mediaCapabilityPropertiesObserved: boolean;
  readonly permissionCapabilityPropertiesObserved: boolean;
  readonly policyCapabilityPropertiesObserved: boolean;
  readonly propertyPresenceEvidenceOnly: true;
  readonly permissionStateKnown: false;
  readonly applicationObservationOperationAvailable: false;
  readonly permissionActivationAuthorized: false;
  readonly interventionRequired: true;
  readonly blockingReasons: readonly string[];
}

function policyIsFailClosed(policy: BrowserCapabilityObservationPolicy): boolean {
  return policy.secureContextRequired
    && policy.topLevelContextRequired
    && policy.onePolicySurfaceRequired
    && policy.exactNavigationCount === 1
    && policy.exactMainDocumentRequestCount === 1
    && policy.reviewedSignedExecutableRequired
    && policy.headlessRequired
    && policy.freshEphemeralProfileRequired
    && policy.profileDeletionRequired
    && !policy.permissionStatusQueryAllowed
    && !policy.permissionsPolicyMethodInvocationAllowed
    && !policy.getUserMediaInvocationAllowed
    && !policy.mediaDeviceEnumerationAllowed
    && !policy.permissionPromptAllowed
    && !policy.permissionOverrideAllowed
    && !policy.userAgentReadAllowed
    && !policy.clientHintsReadAllowed
    && !policy.deviceIdentifierReadAllowed
    && !policy.captureAllowed
    && !policy.externalNetworkAllowed
    && !policy.authenticationAllowed
    && !policy.bearerTokenAttachmentAllowed
    && !policy.backendTransportAllowed
    && !policy.protectedContentAccessAllowed
    && !policy.externalAiAllowed
    && !policy.serviceWorkerAllowed
    && !policy.persistentCacheAllowed
    && !policy.nativePackagingAllowed
    && !policy.productionDeploymentAllowed;
}

export function evaluateBrowserCapabilityReadiness(input: {
  readonly observation: BrowserCapabilityObservation;
  readonly policy: BrowserCapabilityObservationPolicy;
}): BrowserCapabilityReadiness {
  const observationAccepted = input.observation.state === "accepted";
  const secureTopLevelContextObserved =
    input.observation.snapshot.secureContext
    && input.observation.snapshot.topLevelContext;
  const mediaCapabilityPropertiesObserved =
    input.observation.snapshot.mediaDevicesObjectPresent
    && input.observation.snapshot.getUserMediaPropertyPresent
    && input.observation.snapshot.enumerateDevicesPropertyPresent;
  const permissionCapabilityPropertiesObserved =
    input.observation.snapshot.permissionsObjectPresent
    && input.observation.snapshot.permissionsQueryPropertyPresent;
  const policyCapabilityPropertiesObserved = input.observation.onePolicySurfacePresent;
  const blockingReasons: string[] = [];

  if (!observationAccepted) {
    blockingReasons.push(...input.observation.blockingReasons);
  }
  if (!policyIsFailClosed(input.policy)) {
    blockingReasons.push("The browser capability observation policy differs from the accepted fail-closed profile.");
  }

  return Object.freeze({
    state: blockingReasons.length === 0
      ? "evidence_accepted_activation_closed"
      : "unavailable",
    observationAccepted,
    secureTopLevelContextObserved,
    mediaCapabilityPropertiesObserved,
    permissionCapabilityPropertiesObserved,
    policyCapabilityPropertiesObserved,
    propertyPresenceEvidenceOnly: true,
    permissionStateKnown: false,
    applicationObservationOperationAvailable: false,
    permissionActivationAuthorized: false,
    interventionRequired: true,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
