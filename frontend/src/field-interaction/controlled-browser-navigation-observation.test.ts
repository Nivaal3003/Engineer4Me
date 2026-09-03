import { createControlledBrowserExecutableEvidence } from "./browser-executable-evidence";
import {
  CONTROLLED_BROWSER_EXPECTED_HEADING,
  CONTROLLED_BROWSER_EXPECTED_MARKER,
  CONTROLLED_BROWSER_EXPECTED_TITLE,
  CONTROLLED_BROWSER_REDACTED_ENDPOINT,
  createControlledBrowserNavigationObservation,
} from "./controlled-browser-navigation-observation";

const evidence = createControlledBrowserExecutableEvidence({
  evidenceId: "controlled-browser-executable-fixture",
  source: "scripted_test_fixture",
  executableFilePresent: true,
  executableRegularFile: true,
  executableReparsePointDetected: false,
  executableBytes: 2048,
  executableSha256: "2".repeat(64),
  signatureStatus: "valid",
  signerPolicyAccepted: true,
  reviewCompleted: true,
});

function observe(overrides: Partial<Parameters<
  typeof createControlledBrowserNavigationObservation
>[0]> = {}) {
  return createControlledBrowserNavigationObservation({
    observationId: "controlled-browser-navigation-fixture",
    source: "scripted_test_fixture",
    executableEvidence: evidence,
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
    responseBodySha256: "3".repeat(64),
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
    ...overrides,
  });
}

describe("controlled browser navigation observation", () => {
  it("accepts one exact scripted loopback navigation without broadening runtime authority", () => {
    const observation = observe();
    expect(observation).toMatchObject({
      state: "accepted",
      requestEndpoint: CONTROLLED_BROWSER_REDACTED_ENDPOINT,
      exactDefaultDenyHeaderServedToBrowser: true,
      browserExecuted: false,
      browserExecutablePathPersisted: false,
      browserNameCollected: false,
      browserVersionCollected: false,
      userAgentRead: false,
      externalNetworkConnectionEstablished: false,
      permissionPromptShown: false,
      mediaDeviceEnumerationPerformed: false,
      captureStarted: false,
    });
  });

  it("fails closed for extra requests or incomplete process and profile closure", () => {
    const observation = observe({
      blockedRequestCount: 65,
      browserProcessClosed: false,
      ephemeralProfileDeleted: false,
    });
    expect(observation.state).toBe("invalid");
    expect(observation.blockingReasons.length).toBeGreaterThanOrEqual(3);
  });
});
