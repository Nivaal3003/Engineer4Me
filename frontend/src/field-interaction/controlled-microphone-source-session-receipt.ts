import type { ControlledMicrophoneSourceSessionOutcomeEvidence } from "./controlled-microphone-source-session-outcome";

export interface ControlledMicrophoneSourceSessionCleanupEvidence {
  readonly browserProcessClosed: true;
  readonly ephemeralProfileDeleted: true;
  readonly externalNetworkConnectionEstablished: false;
  readonly automaticRetryPerformed: false;
}

export interface ControlledMicrophoneSourceSessionReceipt {
  readonly receiptType: "phase10_controlled_microphone_source_session";
  readonly acceptedParentBatch: "475_486";
  readonly outcome: ControlledMicrophoneSourceSessionOutcomeEvidence;
  readonly cleanup: ControlledMicrophoneSourceSessionCleanupEvidence;
  readonly outcomeRecorded: true;
  readonly sourceSessionExecutionAccepted: boolean;
  readonly applicationAudioSampleAccessAuthorized: false;
  readonly applicationRecordingAuthorized: false;
  readonly applicationPersistenceAuthorized: false;
  readonly applicationTransmissionAuthorized: false;
  readonly furtherAudioSampleGateRequired: true;
}

export function createControlledMicrophoneSourceSessionReceipt(input: {
  readonly outcome: ControlledMicrophoneSourceSessionOutcomeEvidence;
  readonly cleanup: ControlledMicrophoneSourceSessionCleanupEvidence;
}): ControlledMicrophoneSourceSessionReceipt {
  if (!input.cleanup.browserProcessClosed || !input.cleanup.ephemeralProfileDeleted ||
      input.cleanup.externalNetworkConnectionEstablished || input.cleanup.automaticRetryPerformed) {
    throw new Error("Controlled source-session cleanup evidence is not accepted.");
  }
  const sourceSessionExecutionAccepted =
    input.outcome.outcome === "source_session_completed_automatic_stop" ||
    input.outcome.outcome === "source_session_completed_user_stop";
  return Object.freeze({
    receiptType: "phase10_controlled_microphone_source_session",
    acceptedParentBatch: "475_486",
    outcome: input.outcome,
    cleanup: input.cleanup,
    outcomeRecorded: true,
    sourceSessionExecutionAccepted,
    applicationAudioSampleAccessAuthorized: false,
    applicationRecordingAuthorized: false,
    applicationPersistenceAuthorized: false,
    applicationTransmissionAuthorized: false,
    furtherAudioSampleGateRequired: true,
  });
}
