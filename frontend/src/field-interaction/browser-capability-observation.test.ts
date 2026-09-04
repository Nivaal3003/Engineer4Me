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
} from "./browser-capability-observation-policy";
import { createBrowserCapabilityObservation } from "./browser-capability-observation";

const acceptedSnapshot = {
  secureContext: true,
  topLevelContext: true,
  mediaDevicesObjectPresent: true,
  getUserMediaPropertyPresent: true,
  enumerateDevicesPropertyPresent: true,
  permissionsObjectPresent: true,
  permissionsQueryPropertyPresent: true,
  permissionsPolicyObjectPresent: false,
  permissionsPolicyAllowsFeaturePropertyPresent: false,
  legacyFeaturePolicyObjectPresent: true,
  legacyFeaturePolicyAllowsFeaturePropertyPresent: true,
} as const;

describe("controlled read-only browser capability observation", () => {
  it("accepts a supported property surface without inferring permission state", () => {
    const observation = createBrowserCapabilityObservation({
      observationId: "browser-capability-observation-439",
      source: "scripted_test_fixture",
      navigationObservation: acceptedNavigationObservation(),
      requestEndpoint: CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
      documentMarker: CONTROLLED_BROWSER_CAPABILITY_MARKER,
      snapshot: acceptedSnapshot,
    });
    expect(observation.state).toBe("accepted");
    expect(observation.onePolicySurfacePresent).toBe(true);
    expect(observation.capabilityDetectionReadOnly).toBe(true);
    expect(observation.permissionStatusQueried).toBe(false);
    expect(observation.permissionsPolicyMethodCalled).toBe(false);
    expect(observation.getUserMediaCalled).toBe(false);
    expect(observation.mediaDeviceEnumerationPerformed).toBe(false);
    expect(observation.deviceIdentifiersLoaded).toBe(false);
    expect(observation.permissionPromptShown).toBe(false);
  });

  it("fails closed when the controlled context or policy surface is absent", () => {
    const observation = createBrowserCapabilityObservation({
      observationId: "browser-capability-observation-440",
      source: "scripted_test_fixture",
      navigationObservation: acceptedNavigationObservation(),
      requestEndpoint: CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
      documentMarker: CONTROLLED_BROWSER_CAPABILITY_MARKER,
      snapshot: {
        ...acceptedSnapshot,
        secureContext: false,
        legacyFeaturePolicyObjectPresent: false,
        legacyFeaturePolicyAllowsFeaturePropertyPresent: false,
      },
    });
    expect(observation.state).toBe("invalid");
    expect(observation.blockingReasons).toContain(
      "The controlled capability document is not a secure context.",
    );
    expect(observation.blockingReasons).toContain(
      "No supported permissions-policy property surface was observed.",
    );
  });
});
