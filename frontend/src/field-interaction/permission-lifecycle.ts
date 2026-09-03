import type { FieldInteractionPermissionKind } from "./permissions";

export const PERMISSION_LIFECYCLE_STATES = [
  "inactive_not_requested",
  "capability_unavailable",
  "policy_blocked",
  "trusted_gesture_required",
  "intervention_required",
  "denied",
  "dismissed",
  "revoked",
] as const;

export type PermissionLifecycleState =
  (typeof PERMISSION_LIFECYCLE_STATES)[number];

export type ImportedPermissionOutcome = "denied" | "dismissed" | "revoked";

export interface PermissionLifecycleSnapshot {
  readonly permission: FieldInteractionPermissionKind;
  readonly state: PermissionLifecycleState;
  readonly importedOutcome: ImportedPermissionOutcome | null;
  readonly importedOutcomeEvidenceAccepted: boolean;
  readonly permissionPromptPerformedByThisRuntime: false;
  readonly browserPermissionApiCalledByThisRuntime: false;
  readonly activationAuthorized: false;
  readonly rawMediaAvailable: false;
  readonly automaticRetryEnabled: false;
}

export type PermissionLifecycleEvent =
  | { readonly type: "report_capability_unavailable" }
  | { readonly type: "report_policy_blocked" }
  | { readonly type: "require_trusted_gesture" }
  | { readonly type: "reach_intervention_gate" }
  | {
      readonly type: "record_imported_outcome";
      readonly outcome: ImportedPermissionOutcome;
      readonly evidenceAccepted: boolean;
    }
  | { readonly type: "reset_to_inactive" };

export function createInactivePermissionLifecycle(
  permission: FieldInteractionPermissionKind,
): PermissionLifecycleSnapshot {
  return Object.freeze({
    permission,
    state: "inactive_not_requested",
    importedOutcome: null,
    importedOutcomeEvidenceAccepted: false,
    permissionPromptPerformedByThisRuntime: false,
    browserPermissionApiCalledByThisRuntime: false,
    activationAuthorized: false,
    rawMediaAvailable: false,
    automaticRetryEnabled: false,
  });
}

export function transitionPermissionLifecycle(
  current: PermissionLifecycleSnapshot,
  event: PermissionLifecycleEvent,
): PermissionLifecycleSnapshot {
  if (event.type === "reset_to_inactive") {
    return createInactivePermissionLifecycle(current.permission);
  }
  if (event.type === "record_imported_outcome") {
    if (!event.evidenceAccepted) {
      throw new Error("Imported permission outcomes require accepted evidence.");
    }
    return Object.freeze({
      ...current,
      state: event.outcome,
      importedOutcome: event.outcome,
      importedOutcomeEvidenceAccepted: true,
      permissionPromptPerformedByThisRuntime: false,
      browserPermissionApiCalledByThisRuntime: false,
      activationAuthorized: false,
      rawMediaAvailable: false,
      automaticRetryEnabled: false,
    });
  }
  const stateByEvent = {
    report_capability_unavailable: "capability_unavailable",
    report_policy_blocked: "policy_blocked",
    require_trusted_gesture: "trusted_gesture_required",
    reach_intervention_gate: "intervention_required",
  } as const;
  return Object.freeze({
    ...current,
    state: stateByEvent[event.type],
    importedOutcome: null,
    importedOutcomeEvidenceAccepted: false,
    permissionPromptPerformedByThisRuntime: false,
    browserPermissionApiCalledByThisRuntime: false,
    activationAuthorized: false,
    rawMediaAvailable: false,
    automaticRetryEnabled: false,
  });
}
