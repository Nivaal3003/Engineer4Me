import {
  deploymentDirectiveFor,
  type DeploymentPermissionDirective,
} from "./deployment-permissions-policy";
import type { DeploymentPermissionsPolicyHeaderEvidence } from "./deployment-header-evidence";
import type { ReadOnlyPermissionCapabilitySnapshot } from "./permission-capabilities";
import type { FieldInteractionPermissionKind } from "./permissions";

export type SupportedBrowserReadinessState =
  | "global_surface_unavailable"
  | "capture_api_surface_unavailable"
  | "secure_context_required"
  | "top_level_context_required"
  | "deployment_header_evidence_required"
  | "deployment_header_invalid"
  | "deployment_policy_denied"
  | "intervention_required";

export interface SupportedBrowserPermissionReadiness {
  readonly permission: FieldInteractionPermissionKind;
  readonly state: SupportedBrowserReadinessState;
  readonly capabilityRequirementsSatisfied: boolean;
  readonly reviewedDeploymentHeaderAccepted: boolean;
  readonly deploymentDirective: DeploymentPermissionDirective | null;
  readonly candidateForControlledActivationGate: boolean;
  readonly interventionRequired: true;
  readonly supportDeterminationMode: "capability_based_read_only";
  readonly browserNameCollected: false;
  readonly browserVersionCollected: false;
  readonly userAgentRead: false;
  readonly userAgentClientHintsRead: false;
  readonly liveResponseHeaderRead: false;
  readonly permissionStatusQueried: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly permissionRequestPrepared: false;
  readonly permissionPromptAuthorized: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly captureStarted: false;
  readonly networkRequestPerformed: false;
  readonly blockingReasons: readonly string[];
}

export function evaluateSupportedBrowserPermissionReadiness(input: {
  readonly permission: FieldInteractionPermissionKind;
  readonly capabilities: ReadOnlyPermissionCapabilitySnapshot;
  readonly headerEvidence: DeploymentPermissionsPolicyHeaderEvidence;
}): SupportedBrowserPermissionReadiness {
  const reasons: string[] = [];
  const captureApiSurfacePresent =
    input.capabilities.mediaDevicesObjectPresent
    && input.capabilities.getUserMediaFunctionPresent;
  const capabilityRequirementsSatisfied =
    input.capabilities.globalObjectPresent
    && input.capabilities.secureContext === true
    && input.capabilities.embeddingContext === "top_level"
    && captureApiSurfacePresent;
  const directive = deploymentDirectiveFor(
    input.permission,
    input.headerEvidence.parsed,
  );
  const reviewedDeploymentHeaderAccepted =
    input.headerEvidence.reviewCompleted
    && input.headerEvidence.source !== "none"
    && input.headerEvidence.parsed.state === "accepted"
    && input.headerEvidence.parsed.exactControlledDirectiveSet;

  let state: SupportedBrowserReadinessState = "intervention_required";
  if (!input.capabilities.globalObjectPresent) {
    state = "global_surface_unavailable";
    reasons.push("A browser global surface was not available for read-only inspection.");
  } else if (!captureApiSurfacePresent) {
    state = "capture_api_surface_unavailable";
    reasons.push("The browser media-capture API surface is unavailable.");
  } else if (input.capabilities.secureContext !== true) {
    state = "secure_context_required";
    reasons.push("A verified secure context is required.");
  } else if (input.capabilities.embeddingContext !== "top_level") {
    state = "top_level_context_required";
    reasons.push("A verified top-level context is required.");
  } else if (input.headerEvidence.source === "none" || !input.headerEvidence.reviewCompleted) {
    state = "deployment_header_evidence_required";
    reasons.push("Reviewed deployment Permissions-Policy header evidence is required.");
  } else if (input.headerEvidence.parsed.state !== "accepted") {
    state = "deployment_header_invalid";
    reasons.push(...input.headerEvidence.parsed.blockingReasons);
  } else if (directive !== "allow_self") {
    state = "deployment_policy_denied";
    reasons.push(`Deployment Permissions-Policy denies ${input.permission} access.`);
  } else {
    reasons.push(
      "Capability and reviewed deployment-header prerequisites are satisfied, but a separate intervention gate remains required.",
    );
  }

  return Object.freeze({
    permission: input.permission,
    state,
    capabilityRequirementsSatisfied,
    reviewedDeploymentHeaderAccepted,
    deploymentDirective: directive,
    candidateForControlledActivationGate: state === "intervention_required",
    interventionRequired: true,
    supportDeterminationMode: "capability_based_read_only",
    browserNameCollected: false,
    browserVersionCollected: false,
    userAgentRead: false,
    userAgentClientHintsRead: false,
    liveResponseHeaderRead: false,
    permissionStatusQueried: false,
    permissionsPolicyMethodCalled: false,
    permissionRequestPrepared: false,
    permissionPromptAuthorized: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    captureStarted: false,
    networkRequestPerformed: false,
    blockingReasons: Object.freeze(reasons),
  });
}
