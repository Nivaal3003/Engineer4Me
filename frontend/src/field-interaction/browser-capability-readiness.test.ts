import { createControlledBrowserExecutableEvidence } from "./browser-executable-evidence";
import {
  CONTROLLED_BROWSER_EXPECTED_HEADING,
  CONTROLLED_BROWSER_EXPECTED_MARKER,
  CONTROLLED_BROWSER_EXPECTED_TITLE,
  CONTROLLED_BROWSER_REDACTED_ENDPOINT,
  createControlledBrowserNavigationObservation,
} from "./controlled-browser-navigation-observation";

function acceptedNavigationObservation() {
  const executableEvidence = createControlledBrowserExecutableEvidence({
    evidenceId: "browser-executable-evidence-439",
    source: "scripted_test_fixture",
    executableFilePresent: true,
    executableRegularFile: true,
    executableReparsePointDetected: false,
    executableBytes: 4096,
    executableSha256: "a".repeat(64),
    signatureStatus: "valid",
    signerPolicyAccepted: true,
    reviewCompleted: true,
  });
  return createControlledBrowserNavigationObservation({
    observationId: "browser-navigation-observation-439",
    source: "scripted_test_fixture",
    executableEvidence,
    requestEndpoint: CONTROLLED_BROWSER_REDACTED_ENDPOINT,
    navigationCount: 1,
    mainDocumentRequestCount: 1,
    allowedRequestCount: 1,
    blockedRequestCount: 0,
    responseStatus: 200,
    permissionsPolicyValue: "microphone=(), camera=()",
    cacheControlNoStoreServedToBrowser: true,
    contentTypeServedToBrowser: true,
    documentTitle: CONTROLLED_BROWSER_EXPECTED_TITLE,
    documentHeading: CONTROLLED_BROWSER_EXPECTED_HEADING,
    documentMarker: CONTROLLED_BROWSER_EXPECTED_MARKER,
    responseBodySha256: "b".repeat(64),
    browserProcessStarted: true,
    browserProcessClosed: true,
    ephemeralProfileCreated: true,
    ephemeralProfileDeleted: true,
    externalNetworkConnectionEstablished: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    serviceWorkerEnabled: false,
    downloadStarted: false,
    popupOpened: false,
  });
}

import {
  CONTROLLED_BROWSER_CAPABILITY_MARKER,
  CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
  createBrowserCapabilityObservationPolicy,
} from "./browser-capability-observation-policy";
import { createBrowserCapabilityObservation } from "./browser-capability-observation";
import { evaluateBrowserCapabilityReadiness } from "./browser-capability-readiness";

describe("browser capability readiness", () => {
  it("accepts evidence while retaining the activation intervention gate", () => {
    const observation = createBrowserCapabilityObservation({
      observationId: "browser-capability-readiness-observation-439",
      source: "scripted_test_fixture",
      navigationObservation: acceptedNavigationObservation(),
      requestEndpoint: CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
      documentMarker: CONTROLLED_BROWSER_CAPABILITY_MARKER,
      snapshot: {
        secureContext: true,
        topLevelContext: true,
        mediaDevicesObjectPresent: true,
        getUserMediaPropertyPresent: true,
        enumerateDevicesPropertyPresent: true,
        permissionsObjectPresent: true,
        permissionsQueryPropertyPresent: true,
        permissionsPolicyObjectPresent: true,
        permissionsPolicyAllowsFeaturePropertyPresent: true,
        legacyFeaturePolicyObjectPresent: false,
        legacyFeaturePolicyAllowsFeaturePropertyPresent: false,
      },
    });
    const readiness = evaluateBrowserCapabilityReadiness({
      observation,
      policy: createBrowserCapabilityObservationPolicy(),
    });
    expect(readiness.state).toBe("evidence_accepted_activation_closed");
    expect(readiness.propertyPresenceEvidenceOnly).toBe(true);
    expect(readiness.permissionStateKnown).toBe(false);
    expect(readiness.applicationObservationOperationAvailable).toBe(false);
    expect(readiness.permissionActivationAuthorized).toBe(false);
    expect(readiness.interventionRequired).toBe(true);
  });
});
