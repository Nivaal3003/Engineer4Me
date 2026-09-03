import {
  createPermissionActivationProposal,
  type PermissionActivationProposal,
} from "./permission-activation";
import {
  detectReadOnlyPermissionCapabilities,
  type ReadOnlyPermissionCapabilitySnapshot,
} from "./permission-capabilities";
import type { PermissionPrerequisiteEvaluation } from "./permission-policy";
import type { FieldInteractionPermissionKind } from "./permissions";
import type { UserGestureEvaluation } from "./user-gesture";

export interface PermissionAdapterSideEffects {
  readonly permissionQueries: 0;
  readonly permissionPrompts: 0;
  readonly captureRequests: 0;
  readonly deviceEnumerations: 0;
  readonly mediaTracksCreated: 0;
  readonly networkRequests: 0;
}

export interface InertPermissionCapabilityAdapter {
  readonly mode: "read_only_capability_detection_only";
  readonly permissionRequestOperationAvailable: false;
  readonly sideEffects: PermissionAdapterSideEffects;
  readonly inspectCapabilities: () => ReadOnlyPermissionCapabilitySnapshot;
  readonly prepareActivationProposal: (input: {
    readonly proposalId: string;
    readonly permission: FieldInteractionPermissionKind;
    readonly prerequisites: PermissionPrerequisiteEvaluation;
    readonly gesture: UserGestureEvaluation;
  }) => PermissionActivationProposal;
}

const NO_PERMISSION_SIDE_EFFECTS: PermissionAdapterSideEffects = Object.freeze({
  permissionQueries: 0,
  permissionPrompts: 0,
  captureRequests: 0,
  deviceEnumerations: 0,
  mediaTracksCreated: 0,
  networkRequests: 0,
});

export function createInertPermissionCapabilityAdapter(
  environment: unknown = globalThis,
): InertPermissionCapabilityAdapter {
  return Object.freeze({
    mode: "read_only_capability_detection_only",
    permissionRequestOperationAvailable: false,
    sideEffects: NO_PERMISSION_SIDE_EFFECTS,
    inspectCapabilities: () => detectReadOnlyPermissionCapabilities(environment),
    prepareActivationProposal: createPermissionActivationProposal,
  });
}
