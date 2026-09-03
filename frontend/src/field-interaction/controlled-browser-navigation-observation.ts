import type { ControlledBrowserExecutableEvidence } from "./browser-executable-evidence";
import { DEFAULT_DENY_PERMISSIONS_POLICY_VALUE } from "./deployment-permissions-policy";
import { validateFieldInteractionIdentifier } from "./models";

export const CONTROLLED_BROWSER_REDACTED_ENDPOINT =
  "http://127.0.0.1:<ephemeral>/phase10-readiness" as const;
export const CONTROLLED_BROWSER_EXPECTED_TITLE =
  "Engineer4Me controlled headless loopback readiness" as const;
export const CONTROLLED_BROWSER_EXPECTED_HEADING =
  "Controlled headless loopback readiness" as const;
export const CONTROLLED_BROWSER_EXPECTED_MARKER =
  "phase10-controlled-browser-navigation" as const;

export type ControlledBrowserNavigationObservationSource =
  | "controlled_acceptance_probe"
  | "scripted_test_fixture";

export interface ControlledBrowserNavigationObservation {
  readonly observationId: string;
  readonly source: ControlledBrowserNavigationObservationSource;
  readonly state: "accepted" | "invalid";
  readonly executableEvidenceId: string;
  readonly requestEndpoint: typeof CONTROLLED_BROWSER_REDACTED_ENDPOINT;
  readonly navigationCount: number;
  readonly mainDocumentRequestCount: number;
  readonly allowedRequestCount: number;
  readonly blockedRequestCount: number;
  readonly responseStatus: number;
  readonly permissionsPolicyValue: string;
  readonly exactDefaultDenyHeaderServedToBrowser: boolean;
  readonly cacheControlNoStoreServedToBrowser: boolean;
  readonly contentTypeServedToBrowser: boolean;
  readonly documentTitle: string;
  readonly documentHeading: string;
  readonly documentMarker: string;
  readonly responseBodySha256: string;
  readonly browserProcessStarted: boolean;
  readonly browserProcessClosed: boolean;
  readonly ephemeralProfileCreated: boolean;
  readonly ephemeralProfileDeleted: boolean;
  readonly blockingReasons: readonly string[];
  readonly browserExecuted: boolean;
  readonly browserExecutablePathPersisted: false;
  readonly browserNameCollected: false;
  readonly browserVersionCollected: false;
  readonly userAgentRead: false;
  readonly clientHintsRead: false;
  readonly externalNetworkConnectionEstablished: false;
  readonly liveDeploymentResponseHeaderRead: false;
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly permissionPromptShown: false;
  readonly permissionOverridePerformed: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly authenticationPerformed: false;
  readonly bearerTokenAttached: false;
  readonly backendTransportActivated: false;
  readonly protectedContentAccessed: false;
  readonly externalAiServiceCalled: false;
  readonly serviceWorkerEnabled: false;
  readonly downloadStarted: false;
  readonly popupOpened: false;
  readonly productionDeploymentPerformed: false;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function createControlledBrowserNavigationObservation(input: {
  readonly observationId: string;
  readonly source: ControlledBrowserNavigationObservationSource;
  readonly executableEvidence: ControlledBrowserExecutableEvidence;
  readonly requestEndpoint: string;
  readonly navigationCount: number;
  readonly mainDocumentRequestCount: number;
  readonly allowedRequestCount: number;
  readonly blockedRequestCount: number;
  readonly responseStatus: number;
  readonly permissionsPolicyValue: string;
  readonly cacheControlNoStoreServedToBrowser: boolean;
  readonly contentTypeServedToBrowser: boolean;
  readonly documentTitle: string;
  readonly documentHeading: string;
  readonly documentMarker: string;
  readonly responseBodySha256: string;
  readonly browserProcessStarted: boolean;
  readonly browserProcessClosed: boolean;
  readonly ephemeralProfileCreated: boolean;
  readonly ephemeralProfileDeleted: boolean;
  readonly externalNetworkConnectionEstablished: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly serviceWorkerEnabled: false;
  readonly downloadStarted: false;
  readonly popupOpened: false;
}): ControlledBrowserNavigationObservation {
  const blockingReasons: string[] = [];
  const responseBodySha256 = input.responseBodySha256.trim().toLowerCase();
  if (!SHA256_PATTERN.test(responseBodySha256)) {
    throw new Error("Controlled browser response-body SHA-256 differs in format.");
  }
  if (input.executableEvidence.state !== "accepted") {
    blockingReasons.push("Controlled browser executable evidence is not accepted.");
  }
  if (input.requestEndpoint !== CONTROLLED_BROWSER_REDACTED_ENDPOINT) {
    blockingReasons.push("The persisted browser navigation endpoint is not the redacted loopback endpoint.");
  }
  if (input.navigationCount !== 1) {
    blockingReasons.push("Exactly one browser navigation is required.");
  }
  if (input.mainDocumentRequestCount !== 1 || input.allowedRequestCount !== 1) {
    blockingReasons.push("Exactly one allowed main-document request is required.");
  }
  if (
    !Number.isSafeInteger(input.blockedRequestCount)
    || input.blockedRequestCount < 0
    || input.blockedRequestCount > 64
  ) {
    blockingReasons.push("The bounded denied-request count is outside the accepted range.");
  }
  if (input.responseStatus !== 200) {
    blockingReasons.push("The controlled browser response status is not 200.");
  }
  const exactDefaultDenyHeaderServedToBrowser =
    input.permissionsPolicyValue === DEFAULT_DENY_PERMISSIONS_POLICY_VALUE;
  if (!exactDefaultDenyHeaderServedToBrowser) {
    blockingReasons.push("The exact default-deny Permissions-Policy value was not served to the browser.");
  }
  if (!input.cacheControlNoStoreServedToBrowser) {
    blockingReasons.push("Cache-Control: no-store was not served to the browser.");
  }
  if (!input.contentTypeServedToBrowser) {
    blockingReasons.push("The accepted HTML content type was not served to the browser.");
  }
  if (input.documentTitle !== CONTROLLED_BROWSER_EXPECTED_TITLE) {
    blockingReasons.push("The controlled document title differs.");
  }
  if (input.documentHeading !== CONTROLLED_BROWSER_EXPECTED_HEADING) {
    blockingReasons.push("The controlled document heading differs.");
  }
  if (input.documentMarker !== CONTROLLED_BROWSER_EXPECTED_MARKER) {
    blockingReasons.push("The controlled document marker differs.");
  }
  if (!input.browserProcessStarted || !input.browserProcessClosed) {
    blockingReasons.push("The controlled browser process lifecycle is incomplete.");
  }
  if (!input.ephemeralProfileCreated || !input.ephemeralProfileDeleted) {
    blockingReasons.push("The controlled ephemeral profile lifecycle is incomplete.");
  }
  if (
    input.externalNetworkConnectionEstablished
    || input.permissionPromptShown
    || input.mediaDeviceEnumerationPerformed
    || input.captureStarted
    || input.serviceWorkerEnabled
    || input.downloadStarted
    || input.popupOpened
  ) {
    blockingReasons.push("A prohibited controlled-browser side effect was observed.");
  }

  return Object.freeze({
    observationId: validateFieldInteractionIdentifier(
      input.observationId,
      "Controlled browser navigation observation identifier",
    ),
    source: input.source,
    state: blockingReasons.length === 0 ? "accepted" : "invalid",
    executableEvidenceId: input.executableEvidence.evidenceId,
    requestEndpoint: CONTROLLED_BROWSER_REDACTED_ENDPOINT,
    navigationCount: input.navigationCount,
    mainDocumentRequestCount: input.mainDocumentRequestCount,
    allowedRequestCount: input.allowedRequestCount,
    blockedRequestCount: input.blockedRequestCount,
    responseStatus: input.responseStatus,
    permissionsPolicyValue: input.permissionsPolicyValue,
    exactDefaultDenyHeaderServedToBrowser,
    cacheControlNoStoreServedToBrowser: input.cacheControlNoStoreServedToBrowser,
    contentTypeServedToBrowser: input.contentTypeServedToBrowser,
    documentTitle: input.documentTitle,
    documentHeading: input.documentHeading,
    documentMarker: input.documentMarker,
    responseBodySha256,
    browserProcessStarted: input.browserProcessStarted,
    browserProcessClosed: input.browserProcessClosed,
    ephemeralProfileCreated: input.ephemeralProfileCreated,
    ephemeralProfileDeleted: input.ephemeralProfileDeleted,
    blockingReasons: Object.freeze(blockingReasons),
    browserExecuted: input.source === "controlled_acceptance_probe",
    browserExecutablePathPersisted: false,
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    clientHintsRead: false,
    externalNetworkConnectionEstablished: false,
    liveDeploymentResponseHeaderRead: false,
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    permissionPromptShown: false,
    permissionOverridePerformed: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    authenticationPerformed: false,
    bearerTokenAttached: false,
    backendTransportActivated: false,
    protectedContentAccessed: false,
    externalAiServiceCalled: false,
    serviceWorkerEnabled: false,
    downloadStarted: false,
    popupOpened: false,
    productionDeploymentPerformed: false,
  });
}
