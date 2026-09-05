import type { AcceptedControlledSignalPresenceOutcome } from "./controlled-audio-signal-presence-outcome";

export interface ControlledSignalPresenceReceipt {
  readonly schemaVersion: 1;
  readonly contractId: string;
  readonly parentCommit: string;
  readonly outcome: AcceptedControlledSignalPresenceOutcome;
  readonly applicationAudioSampleOperationAvailable: false;
  readonly furtherVoiceInterpretationGateRequired: true;
}

export function createControlledSignalPresenceReceipt(input: {
  readonly contractId: string;
  readonly parentCommit: string;
  readonly outcome: AcceptedControlledSignalPresenceOutcome;
}): ControlledSignalPresenceReceipt {
  if (!/^[a-f0-9]{64}$/.test(input.contractId)) {
    throw new Error("Controlled signal-presence contract identity differs");
  }
  if (!/^[a-f0-9]{40}$/.test(input.parentCommit)) {
    throw new Error("Controlled signal-presence parent identity differs");
  }
  return Object.freeze({
    schemaVersion: 1,
    contractId: input.contractId,
    parentCommit: input.parentCommit,
    outcome: input.outcome,
    applicationAudioSampleOperationAvailable: false,
    furtherVoiceInterpretationGateRequired: true,
  });
}
