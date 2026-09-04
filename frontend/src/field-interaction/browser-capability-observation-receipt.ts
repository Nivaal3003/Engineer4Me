import type { BrowserCapabilityObservation } from "./browser-capability-observation";
import type { BrowserCapabilityReadiness } from "./browser-capability-readiness";

export interface BrowserCapabilityObservationReceipt {
  readonly state: "accepted" | "invalid";
  readonly observationId: string;
  readonly observationAccepted: boolean;
  readonly readinessEvidenceAccepted: boolean;
  readonly propertyPresenceEvidenceOnly: true;
  readonly acceptanceArchiveEvidenceRequired: true;
  readonly applicationObservationOperationAvailable: false;
  readonly permissionActivationAuthorized: false;
  readonly interventionRequired: true;
  readonly blockingReasons: readonly string[];
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly getUserMediaCalled: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly externalNetworkConnectionEstablished: false;
}

export function createBrowserCapabilityObservationReceipt(input: {
  readonly observation: BrowserCapabilityObservation;
  readonly readiness: BrowserCapabilityReadiness;
}): BrowserCapabilityObservationReceipt {
  const observationAccepted = input.observation.state === "accepted";
  const readinessEvidenceAccepted =
    input.readiness.state === "evidence_accepted_activation_closed";
  const blockingReasons = [
    ...input.observation.blockingReasons,
    ...input.readiness.blockingReasons,
  ];

  return Object.freeze({
    state: observationAccepted && readinessEvidenceAccepted
      ? "accepted"
      : "invalid",
    observationId: input.observation.observationId,
    observationAccepted,
    readinessEvidenceAccepted,
    propertyPresenceEvidenceOnly: true,
    acceptanceArchiveEvidenceRequired: true,
    applicationObservationOperationAvailable: false,
    permissionActivationAuthorized: false,
    interventionRequired: true,
    blockingReasons: Object.freeze(blockingReasons),
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    getUserMediaCalled: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    externalNetworkConnectionEstablished: false,
  });
}
