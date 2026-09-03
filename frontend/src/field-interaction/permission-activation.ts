import { validateFieldInteractionIdentifier } from "./models";
import type { FieldInteractionPermissionKind } from "./permissions";
import type { PermissionPrerequisiteEvaluation } from "./permission-policy";
import type { UserGestureEvaluation } from "./user-gesture";

export type PermissionActivationProposalState =
  | "capability_or_context_blocked"
  | "policy_evidence_blocked"
  | "trusted_user_gesture_required"
  | "intervention_required";

export interface PermissionActivationProposal {
  readonly proposalId: string;
  readonly permission: FieldInteractionPermissionKind;
  readonly state: PermissionActivationProposalState;
  readonly eligibleForControlledPromptAfterGate: boolean;
  readonly interventionRequired: true;
  readonly singleUseGestureRequired: true;
  readonly explicitUserGestureRequired: true;
  readonly permissionRequestPrepared: false;
  readonly activationAuthorized: false;
  readonly browserPermissionApiCalled: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly rawMediaCaptured: false;
  readonly deviceIdentifiersLoaded: false;
  readonly automaticRetryEnabled: false;
  readonly blockingReasons: readonly string[];
}

export function createPermissionActivationProposal(input: {
  readonly proposalId: string;
  readonly permission: FieldInteractionPermissionKind;
  readonly prerequisites: PermissionPrerequisiteEvaluation;
  readonly gesture: UserGestureEvaluation;
}): PermissionActivationProposal {
  if (input.prerequisites.permission !== input.permission) {
    throw new Error("Permission prerequisite evaluation targets a different permission.");
  }
  const reasons = [
    ...input.prerequisites.blockingReasons,
    ...input.gesture.blockingReasons,
  ];

  let state: PermissionActivationProposalState;
  if (
    input.prerequisites.state === "capture_api_surface_unavailable"
    || input.prerequisites.state === "secure_context_required"
    || input.prerequisites.state === "top_level_context_required"
  ) {
    state = "capability_or_context_blocked";
  } else if (input.prerequisites.state !== "intervention_required") {
    state = "policy_evidence_blocked";
  } else if (!input.gesture.acceptedForFuturePromptPreparation) {
    state = "trusted_user_gesture_required";
  } else {
    state = "intervention_required";
    reasons.push("A separate accepted intervention is required before any permission prompt.");
  }

  return Object.freeze({
    proposalId: validateFieldInteractionIdentifier(
      input.proposalId,
      "Permission activation proposal identifier",
    ),
    permission: input.permission,
    state,
    eligibleForControlledPromptAfterGate: state === "intervention_required",
    interventionRequired: true,
    singleUseGestureRequired: true,
    explicitUserGestureRequired: true,
    permissionRequestPrepared: false,
    activationAuthorized: false,
    browserPermissionApiCalled: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    rawMediaCaptured: false,
    deviceIdentifiersLoaded: false,
    automaticRetryEnabled: false,
    blockingReasons: Object.freeze(reasons),
  });
}
