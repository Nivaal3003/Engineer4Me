/** Source-only microphone and camera permission readiness; no browser API is called. */
export const FIELD_INTERACTION_PERMISSION_KINDS = [
  "microphone",
  "camera",
] as const;

export type FieldInteractionPermissionKind =
  (typeof FIELD_INTERACTION_PERMISSION_KINDS)[number];

export interface FieldInteractionPermissionReadiness {
  readonly permission: FieldInteractionPermissionKind;
  readonly state: "inactive_not_requested";
  readonly interventionRequired: true;
  readonly browserPermissionApiCalled: false;
  readonly permissionPromptShown: false;
  readonly userGestureRecorded: false;
  readonly controlledEvidenceAccepted: false;
  readonly activationAuthorized: false;
}

export interface FieldInteractionPermissionSnapshot {
  readonly microphone: FieldInteractionPermissionReadiness;
  readonly camera: FieldInteractionPermissionReadiness;
  readonly liveCaptureActive: false;
  readonly rawMediaCaptured: false;
}

export function createInactivePermissionReadiness(
  permission: FieldInteractionPermissionKind,
): FieldInteractionPermissionReadiness {
  return Object.freeze({
    permission,
    state: "inactive_not_requested",
    interventionRequired: true,
    browserPermissionApiCalled: false,
    permissionPromptShown: false,
    userGestureRecorded: false,
    controlledEvidenceAccepted: false,
    activationAuthorized: false,
  });
}

export function createFieldInteractionPermissionSnapshot():
  FieldInteractionPermissionSnapshot {
  return Object.freeze({
    microphone: createInactivePermissionReadiness("microphone"),
    camera: createInactivePermissionReadiness("camera"),
    liveCaptureActive: false,
    rawMediaCaptured: false,
  });
}
