export const CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_FRAME_LENGTH = 2048 as const;
export const CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_RAW_BYTES = 8192 as const;
export const CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_SOURCE_INTERVAL_MILLISECONDS =
  1000 as const;
export const CONTROLLED_SIGNAL_PRESENCE_EXACT_SAMPLE_READ_CALL_MAXIMUM = 1 as const;
export const CONTROLLED_SIGNAL_PRESENCE_ABSOLUTE_THRESHOLD = 0.001 as const;

export type ControlledSignalPresenceReadinessState =
  | "sample_specific_consent_required"
  | "trusted_gesture_required"
  | "intervention_required";

export interface ControlledSignalPresenceReadinessInput {
  readonly acceptedProposalBound: boolean;
  readonly sampleSpecificConsentRecorded: boolean;
  readonly trustedSingleUseGestureRecorded: boolean;
  readonly currentPermissionStateInferred: boolean;
  readonly applicationOperationAvailable: boolean;
}

export interface ControlledSignalPresenceReadiness {
  readonly state: ControlledSignalPresenceReadinessState;
  readonly executionInterventionRequired: true;
  readonly executionAuthorized: false;
  readonly applicationOperationAvailable: false;
  readonly currentPermissionStateInferred: false;
}

export function evaluateControlledSignalPresenceReadiness(
  input: ControlledSignalPresenceReadinessInput,
): ControlledSignalPresenceReadiness {
  if (input.currentPermissionStateInferred || input.applicationOperationAvailable) {
    throw new Error("Controlled signal-presence activation boundary differs");
  }
  const state: ControlledSignalPresenceReadinessState = !input.acceptedProposalBound ||
    !input.sampleSpecificConsentRecorded
    ? "sample_specific_consent_required"
    : !input.trustedSingleUseGestureRecorded
      ? "trusted_gesture_required"
      : "intervention_required";
  return Object.freeze({
    state,
    executionInterventionRequired: true,
    executionAuthorized: false,
    applicationOperationAvailable: false,
    currentPermissionStateInferred: false,
  });
}
