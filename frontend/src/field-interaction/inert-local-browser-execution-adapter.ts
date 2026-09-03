import { createControlledLocalBrowserExecutionPolicy } from "./local-browser-execution-policy";
import {
  createNoLocalBrowserExecutableEvidence,
  evaluateLocalBrowserExecutionReadiness,
  type LocalBrowserExecutableEvidence,
  type LocalBrowserExecutionReadiness,
} from "./local-browser-execution-readiness";
import type { ControlledLoopbackResponseObservation } from "./loopback-response-observation";

export interface LocalBrowserExecutionAdapterSideEffects {
  readonly browserLaunches: 0;
  readonly navigations: 0;
  readonly liveDeploymentHeaderReads: 0;
  readonly externalNetworkRequests: 0;
  readonly userAgentReads: 0;
  readonly permissionQueries: 0;
  readonly permissionPrompts: 0;
  readonly permissionOverrides: 0;
  readonly deviceEnumerations: 0;
  readonly captureRequests: 0;
  readonly authenticationRequests: 0;
  readonly bearerAttachments: 0;
  readonly backendRequests: 0;
  readonly protectedContentReads: 0;
}

export interface LocalBrowserExecutionEvidenceInput {
  readonly observation?: ControlledLoopbackResponseObservation | null;
  readonly executableEvidence?: LocalBrowserExecutableEvidence;
}

export interface InertLocalBrowserExecutionAdapter {
  readonly mode: "caller_supplied_loopback_and_executable_evidence_only";
  readonly browserLaunchOperationAvailable: false;
  readonly navigationOperationAvailable: false;
  readonly liveDeploymentHeaderReadOperationAvailable: false;
  readonly permissionOverrideOperationAvailable: false;
  readonly permissionRequestOperationAvailable: false;
  readonly sideEffects: LocalBrowserExecutionAdapterSideEffects;
  readonly evaluate: (input?: LocalBrowserExecutionEvidenceInput) => LocalBrowserExecutionReadiness;
}

const NO_LOCAL_BROWSER_SIDE_EFFECTS: LocalBrowserExecutionAdapterSideEffects =
  Object.freeze({
    browserLaunches: 0,
    navigations: 0,
    liveDeploymentHeaderReads: 0,
    externalNetworkRequests: 0,
    userAgentReads: 0,
    permissionQueries: 0,
    permissionPrompts: 0,
    permissionOverrides: 0,
    deviceEnumerations: 0,
    captureRequests: 0,
    authenticationRequests: 0,
    bearerAttachments: 0,
    backendRequests: 0,
    protectedContentReads: 0,
  });

export function createInertLocalBrowserExecutionAdapter():
  InertLocalBrowserExecutionAdapter {
  const policy = createControlledLocalBrowserExecutionPolicy();
  return Object.freeze({
    mode: "caller_supplied_loopback_and_executable_evidence_only",
    browserLaunchOperationAvailable: false,
    navigationOperationAvailable: false,
    liveDeploymentHeaderReadOperationAvailable: false,
    permissionOverrideOperationAvailable: false,
    permissionRequestOperationAvailable: false,
    sideEffects: NO_LOCAL_BROWSER_SIDE_EFFECTS,
    evaluate: (input: LocalBrowserExecutionEvidenceInput = {}) =>
      evaluateLocalBrowserExecutionReadiness({
      observation: input.observation ?? null,
      executableEvidence:
        input.executableEvidence ?? createNoLocalBrowserExecutableEvidence(),
        policy,
      }),
  });
}
