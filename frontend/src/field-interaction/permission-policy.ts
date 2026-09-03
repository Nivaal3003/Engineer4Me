import { validateFieldInteractionIdentifier } from "./models";
import type { FieldInteractionPermissionKind } from "./permissions";
import type { ReadOnlyPermissionCapabilitySnapshot } from "./permission-capabilities";

export const PERMISSION_POLICY_DIRECTIVES = [
  "allow_self",
  "deny",
  "unknown",
] as const;

export type PermissionPolicyDirective =
  (typeof PERMISSION_POLICY_DIRECTIVES)[number];

export type PermissionPolicyEvidenceSource =
  | "none"
  | "deployment_header_review"
  | "scripted_test_fixture";

export interface PermissionPolicyEvidence {
  readonly evidenceId: string | null;
  readonly source: PermissionPolicyEvidenceSource;
  readonly microphoneDirective: PermissionPolicyDirective;
  readonly cameraDirective: PermissionPolicyDirective;
  readonly reviewCompleted: boolean;
  readonly livePolicyApiCalled: false;
  readonly permissionPromptShown: false;
}

export type PermissionPrerequisiteState =
  | "capture_api_surface_unavailable"
  | "secure_context_required"
  | "top_level_context_required"
  | "permission_policy_denied"
  | "permission_policy_evidence_required"
  | "intervention_required";

export interface PermissionPrerequisiteEvaluation {
  readonly permission: FieldInteractionPermissionKind;
  readonly state: PermissionPrerequisiteState;
  readonly secureContextSatisfied: boolean;
  readonly topLevelContextSatisfied: boolean;
  readonly captureApiSurfacePresent: boolean;
  readonly policyEvidenceAccepted: boolean;
  readonly eligibleForInterventionGate: boolean;
  readonly blockingReasons: readonly string[];
  readonly browserPermissionApiCalled: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptAuthorized: false;
  readonly permissionPromptShown: false;
}

export function createNoPermissionPolicyEvidence(): PermissionPolicyEvidence {
  return Object.freeze({
    evidenceId: null,
    source: "none",
    microphoneDirective: "unknown",
    cameraDirective: "unknown",
    reviewCompleted: false,
    livePolicyApiCalled: false,
    permissionPromptShown: false,
  });
}

export function createReviewedPermissionPolicyEvidence(input: {
  readonly evidenceId: string;
  readonly source: Exclude<PermissionPolicyEvidenceSource, "none">;
  readonly microphoneDirective: PermissionPolicyDirective;
  readonly cameraDirective: PermissionPolicyDirective;
  readonly reviewCompleted: boolean;
}): PermissionPolicyEvidence {
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Permission-policy evidence identifier",
    ),
    source: input.source,
    microphoneDirective: input.microphoneDirective,
    cameraDirective: input.cameraDirective,
    reviewCompleted: input.reviewCompleted,
    livePolicyApiCalled: false,
    permissionPromptShown: false,
  });
}

function directiveFor(
  permission: FieldInteractionPermissionKind,
  evidence: PermissionPolicyEvidence,
): PermissionPolicyDirective {
  return permission === "microphone"
    ? evidence.microphoneDirective
    : evidence.cameraDirective;
}

export function evaluatePermissionPrerequisites(input: {
  readonly permission: FieldInteractionPermissionKind;
  readonly capabilities: ReadOnlyPermissionCapabilitySnapshot;
  readonly policyEvidence: PermissionPolicyEvidence;
}): PermissionPrerequisiteEvaluation {
  const reasons: string[] = [];
  const captureApiSurfacePresent =
    input.capabilities.mediaDevicesObjectPresent
    && input.capabilities.getUserMediaFunctionPresent;
  const secureContextSatisfied = input.capabilities.secureContext === true;
  const topLevelContextSatisfied = input.capabilities.embeddingContext === "top_level";
  const directive = directiveFor(input.permission, input.policyEvidence);
  const policyEvidenceAccepted =
    input.policyEvidence.reviewCompleted
    && input.policyEvidence.source !== "none"
    && directive === "allow_self";

  let state: PermissionPrerequisiteState = "intervention_required";
  if (!captureApiSurfacePresent) {
    state = "capture_api_surface_unavailable";
    reasons.push("The browser media-capture API surface is unavailable.");
  } else if (!secureContextSatisfied) {
    state = "secure_context_required";
    reasons.push("A verified secure context is required before permission activation.");
  } else if (!topLevelContextSatisfied) {
    state = "top_level_context_required";
    reasons.push("Top-level context evidence is required; embedded delegation is not accepted.");
  } else if (directive === "deny") {
    state = "permission_policy_denied";
    reasons.push(`Deployment policy explicitly denies ${input.permission} access.`);
  } else if (!policyEvidenceAccepted) {
    state = "permission_policy_evidence_required";
    reasons.push("Reviewed deployment permission-policy evidence is required.");
  }

  if (state === "intervention_required") {
    reasons.push("All readiness prerequisites are satisfied, but the activation gate remains closed.");
  }

  return Object.freeze({
    permission: input.permission,
    state,
    secureContextSatisfied,
    topLevelContextSatisfied,
    captureApiSurfacePresent,
    policyEvidenceAccepted,
    eligibleForInterventionGate: state === "intervention_required",
    blockingReasons: Object.freeze(reasons),
    browserPermissionApiCalled: false,
    permissionStatusQueried: false,
    permissionPromptAuthorized: false,
    permissionPromptShown: false,
  });
}
