import type { ControlledBrowserNavigationObservation } from "./controlled-browser-navigation-observation";
import {
  CONTROLLED_BROWSER_CAPABILITY_MARKER,
  CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
} from "./browser-capability-observation-policy";
import { validateFieldInteractionIdentifier } from "./models";

export interface ReadOnlyBrowserCapabilitySnapshot {
  readonly secureContext: boolean;
  readonly topLevelContext: boolean;
  readonly mediaDevicesObjectPresent: boolean;
  readonly getUserMediaPropertyPresent: boolean;
  readonly enumerateDevicesPropertyPresent: boolean;
  readonly permissionsObjectPresent: boolean;
  readonly permissionsQueryPropertyPresent: boolean;
  readonly permissionsPolicyObjectPresent: boolean;
  readonly permissionsPolicyAllowsFeaturePropertyPresent: boolean;
  readonly legacyFeaturePolicyObjectPresent: boolean;
  readonly legacyFeaturePolicyAllowsFeaturePropertyPresent: boolean;
}

export type BrowserCapabilityObservationSource =
  | "controlled_acceptance_probe"
  | "scripted_test_fixture";

export interface BrowserCapabilityObservation {
  readonly observationId: string;
  readonly source: BrowserCapabilityObservationSource;
  readonly state: "accepted" | "invalid";
  readonly navigationObservationId: string;
  readonly requestEndpoint: typeof CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT;
  readonly documentMarker: typeof CONTROLLED_BROWSER_CAPABILITY_MARKER;
  readonly snapshot: ReadOnlyBrowserCapabilitySnapshot;
  readonly modernPermissionsPolicySurfacePresent: boolean;
  readonly legacyFeaturePolicySurfacePresent: boolean;
  readonly onePolicySurfacePresent: boolean;
  readonly blockingReasons: readonly string[];
  readonly browserExecuted: boolean;
  readonly capabilityDetectionReadOnly: true;
  readonly userAgentRead: false;
  readonly clientHintsRead: false;
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly getUserMediaCalled: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly deviceIdentifiersLoaded: false;
  readonly permissionPromptShown: false;
  readonly permissionOverridePerformed: false;
  readonly captureStarted: false;
  readonly rawMediaPersisted: false;
  readonly externalNetworkConnectionEstablished: false;
  readonly authenticationPerformed: false;
  readonly bearerTokenAttached: false;
  readonly backendTransportActivated: false;
  readonly protectedContentAccessed: false;
  readonly externalAiServiceCalled: false;
  readonly serviceWorkerEnabled: false;
  readonly persistentCacheEnabled: false;
  readonly productionDeploymentPerformed: false;
}

export function createBrowserCapabilityObservation(input: {
  readonly observationId: string;
  readonly source: BrowserCapabilityObservationSource;
  readonly navigationObservation: ControlledBrowserNavigationObservation;
  readonly requestEndpoint: string;
  readonly documentMarker: string;
  readonly snapshot: ReadOnlyBrowserCapabilitySnapshot;
}): BrowserCapabilityObservation {
  const modernPermissionsPolicySurfacePresent =
    input.snapshot.permissionsPolicyObjectPresent
    && input.snapshot.permissionsPolicyAllowsFeaturePropertyPresent;
  const legacyFeaturePolicySurfacePresent =
    input.snapshot.legacyFeaturePolicyObjectPresent
    && input.snapshot.legacyFeaturePolicyAllowsFeaturePropertyPresent;
  const onePolicySurfacePresent =
    modernPermissionsPolicySurfacePresent || legacyFeaturePolicySurfacePresent;
  const blockingReasons: string[] = [];

  if (input.navigationObservation.state !== "accepted") {
    blockingReasons.push("The controlled browser navigation evidence is not accepted.");
  }
  if (input.requestEndpoint !== CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT) {
    blockingReasons.push("The capability observation endpoint is not the redacted approved loopback endpoint.");
  }
  if (input.documentMarker !== CONTROLLED_BROWSER_CAPABILITY_MARKER) {
    blockingReasons.push("The controlled capability document marker differs.");
  }
  if (!input.snapshot.secureContext) {
    blockingReasons.push("The controlled capability document is not a secure context.");
  }
  if (!input.snapshot.topLevelContext) {
    blockingReasons.push("The controlled capability document is not a top-level context.");
  }
  if (!input.snapshot.mediaDevicesObjectPresent) {
    blockingReasons.push("The media-devices object is unavailable.");
  }
  if (!input.snapshot.getUserMediaPropertyPresent) {
    blockingReasons.push("The media-capture property is unavailable.");
  }
  if (!input.snapshot.enumerateDevicesPropertyPresent) {
    blockingReasons.push("The media-device enumeration property is unavailable.");
  }
  if (!input.snapshot.permissionsObjectPresent) {
    blockingReasons.push("The permissions object is unavailable.");
  }
  if (!input.snapshot.permissionsQueryPropertyPresent) {
    blockingReasons.push("The permissions query property is unavailable.");
  }
  if (!onePolicySurfacePresent) {
    blockingReasons.push("No supported permissions-policy property surface was observed.");
  }

  return Object.freeze({
    observationId: validateFieldInteractionIdentifier(
      input.observationId,
      "Browser capability observation identifier",
    ),
    source: input.source,
    state: blockingReasons.length === 0 ? "accepted" : "invalid",
    navigationObservationId: input.navigationObservation.observationId,
    requestEndpoint: CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
    documentMarker: CONTROLLED_BROWSER_CAPABILITY_MARKER,
    snapshot: Object.freeze({ ...input.snapshot }),
    modernPermissionsPolicySurfacePresent,
    legacyFeaturePolicySurfacePresent,
    onePolicySurfacePresent,
    blockingReasons: Object.freeze(blockingReasons),
    browserExecuted: input.source === "controlled_acceptance_probe",
    capabilityDetectionReadOnly: true,
    userAgentRead: false,
    clientHintsRead: false,
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    getUserMediaCalled: false,
    mediaDeviceEnumerationPerformed: false,
    deviceIdentifiersLoaded: false,
    permissionPromptShown: false,
    permissionOverridePerformed: false,
    captureStarted: false,
    rawMediaPersisted: false,
    externalNetworkConnectionEstablished: false,
    authenticationPerformed: false,
    bearerTokenAttached: false,
    backendTransportActivated: false,
    protectedContentAccessed: false,
    externalAiServiceCalled: false,
    serviceWorkerEnabled: false,
    persistentCacheEnabled: false,
    productionDeploymentPerformed: false,
  });
}
