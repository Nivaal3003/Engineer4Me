import { createControlledBrowserExecutableEvidence } from "./browser-executable-evidence";
import {
  CONTROLLED_BROWSER_EXPECTED_HEADING,
  CONTROLLED_BROWSER_EXPECTED_MARKER,
  CONTROLLED_BROWSER_EXPECTED_TITLE,
  CONTROLLED_BROWSER_REDACTED_ENDPOINT,
  createControlledBrowserNavigationObservation,
} from "./controlled-browser-navigation-observation";
import { createControlledBrowserNavigationPolicy } from "./controlled-browser-navigation-policy";
import { createControlledBrowserNavigationReceipt } from "./controlled-browser-navigation-receipt";

function fixture() {
  const executableEvidence = createControlledBrowserExecutableEvidence({
    evidenceId: "browser-receipt-executable",
    source: "scripted_test_fixture",
    executableFilePresent: true,
    executableRegularFile: true,
    executableReparsePointDetected: false,
    executableBytes: 4096,
    executableSha256: "4".repeat(64),
    signatureStatus: "valid",
    signerPolicyAccepted: true,
    reviewCompleted: true,
  });
  const observation = createControlledBrowserNavigationObservation({
    observationId: "browser-receipt-observation",
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
    responseBodySha256: "5".repeat(64),
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
  return { executableEvidence, observation };
}

describe("controlled browser navigation receipt", () => {
  it("accepts verified evidence while retaining all application and permission gates", () => {
    const values = fixture();
    const receipt = createControlledBrowserNavigationReceipt({
      ...values,
      policy: createControlledBrowserNavigationPolicy(),
    });
    expect(receipt).toMatchObject({
      state: "accepted",
      applicationBrowserLaunchOperationAvailable: false,
      furtherActivationInterventionRequired: true,
      controlledBrowserExecuted: false,
      permissionActivationAuthorized: false,
      permissionPromptShown: false,
      mediaDeviceEnumerationPerformed: false,
      captureStarted: false,
      externalNetworkConnectionEstablished: false,
      backendTransportActivated: false,
      protectedContentAccessed: false,
    });
  });
});
