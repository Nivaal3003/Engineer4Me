import type { DeploymentPermissionsPolicyHeaderEvidence } from "./deployment-header-evidence";
import {
  detectReadOnlyPermissionCapabilities,
  type ReadOnlyPermissionCapabilitySnapshot,
} from "./permission-capabilities";
import type { FieldInteractionPermissionKind } from "./permissions";
import {
  evaluateSupportedBrowserPermissionReadiness,
  type SupportedBrowserPermissionReadiness,
} from "./supported-browser-readiness";

export interface BrowserReadinessAdapterSideEffects {
  readonly userAgentReads: 0;
  readonly clientHintReads: 0;
  readonly liveHeaderReads: 0;
  readonly permissionQueries: 0;
  readonly policyMethodCalls: 0;
  readonly permissionPrompts: 0;
  readonly captureRequests: 0;
  readonly deviceEnumerations: 0;
  readonly networkRequests: 0;
}

export interface InertBrowserReadinessAdapter {
  readonly mode: "capability_based_read_only_and_caller_supplied_header_evidence";
  readonly userAgentReadOperationAvailable: false;
  readonly liveHeaderReadOperationAvailable: false;
  readonly permissionRequestOperationAvailable: false;
  readonly sideEffects: BrowserReadinessAdapterSideEffects;
  readonly inspectCapabilities: () => ReadOnlyPermissionCapabilitySnapshot;
  readonly evaluate: (input: {
    readonly permission: FieldInteractionPermissionKind;
    readonly headerEvidence: DeploymentPermissionsPolicyHeaderEvidence;
  }) => SupportedBrowserPermissionReadiness;
}

const NO_BROWSER_READINESS_SIDE_EFFECTS: BrowserReadinessAdapterSideEffects =
  Object.freeze({
    userAgentReads: 0,
    clientHintReads: 0,
    liveHeaderReads: 0,
    permissionQueries: 0,
    policyMethodCalls: 0,
    permissionPrompts: 0,
    captureRequests: 0,
    deviceEnumerations: 0,
    networkRequests: 0,
  });

export function createInertBrowserReadinessAdapter(
  environment: unknown = globalThis,
): InertBrowserReadinessAdapter {
  const inspectCapabilities = () => detectReadOnlyPermissionCapabilities(environment);
  return Object.freeze({
    mode: "capability_based_read_only_and_caller_supplied_header_evidence",
    userAgentReadOperationAvailable: false,
    liveHeaderReadOperationAvailable: false,
    permissionRequestOperationAvailable: false,
    sideEffects: NO_BROWSER_READINESS_SIDE_EFFECTS,
    inspectCapabilities,
    evaluate: (input: {
      readonly permission: FieldInteractionPermissionKind;
      readonly headerEvidence: DeploymentPermissionsPolicyHeaderEvidence;
    }) =>
      evaluateSupportedBrowserPermissionReadiness({
        permission: input.permission,
        capabilities: inspectCapabilities(),
        headerEvidence: input.headerEvidence,
      }),
  });
}
