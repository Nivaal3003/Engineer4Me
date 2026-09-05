import {
  CONTROLLED_SIGNAL_PRESENCE_EXACT_SAMPLE_READ_CALL_MAXIMUM,
  CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_FRAME_LENGTH,
  CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_RAW_BYTES,
  CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_SOURCE_INTERVAL_MILLISECONDS,
} from "./controlled-audio-signal-presence-policy";

export type ControlledSignalPresenceOutcome =
  | "signal_present"
  | "signal_absent"
  | "microphone_access_not_available"
  | "sample_api_not_available";

export interface ControlledSignalPresenceOutcomeEvidence {
  readonly outcome: ControlledSignalPresenceOutcome;
  readonly sampleReadCallCount: number;
  readonly frameLength: number;
  readonly rawBytes: number;
  readonly sourceIntervalMilliseconds: number;
  readonly signalPresenceDetected: boolean | null;
  readonly sampleBufferZeroized: boolean;
  readonly processingContextClosed: boolean;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
  readonly numericAmplitudeRetained: boolean;
  readonly waveformRetained: boolean;
  readonly rawSampleBufferRetained: boolean;
  readonly audioPlaybackStarted: boolean;
  readonly audioRecordingCreated: boolean;
  readonly mediaTransmitted: boolean;
}

export interface AcceptedControlledSignalPresenceOutcome {
  readonly outcome: ControlledSignalPresenceOutcome;
  readonly signalPresenceDetected: boolean | null;
  readonly sampleReadCallCount: 0 | 1;
  readonly sampleBufferZeroized: boolean;
  readonly processingContextClosed: boolean;
  readonly everyReturnedTrackStopped: boolean;
  readonly numericAmplitudeRetained: false;
  readonly waveformRetained: false;
  readonly rawSampleBufferRetained: false;
}

export function validateControlledSignalPresenceOutcome(
  evidence: ControlledSignalPresenceOutcomeEvidence,
): AcceptedControlledSignalPresenceOutcome {
  if (
    evidence.numericAmplitudeRetained ||
    evidence.waveformRetained ||
    evidence.rawSampleBufferRetained ||
    evidence.audioPlaybackStarted ||
    evidence.audioRecordingCreated ||
    evidence.mediaTransmitted
  ) {
    throw new Error("Controlled signal-presence prohibited side effect observed");
  }
  const completed = evidence.outcome === "signal_present" || evidence.outcome === "signal_absent";
  if (completed) {
    if (
      evidence.sampleReadCallCount !== CONTROLLED_SIGNAL_PRESENCE_EXACT_SAMPLE_READ_CALL_MAXIMUM ||
      evidence.frameLength < 1 ||
      evidence.frameLength > CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_FRAME_LENGTH ||
      evidence.rawBytes !== evidence.frameLength * 4 ||
      evidence.rawBytes > CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_RAW_BYTES ||
      evidence.sourceIntervalMilliseconds < 0 ||
      evidence.sourceIntervalMilliseconds >
        CONTROLLED_SIGNAL_PRESENCE_MAXIMUM_SOURCE_INTERVAL_MILLISECONDS ||
      evidence.signalPresenceDetected !== (evidence.outcome === "signal_present") ||
      !evidence.sampleBufferZeroized ||
      !evidence.processingContextClosed ||
      evidence.returnedTrackCount < 1 ||
      evidence.trackStopCallCount !== evidence.returnedTrackCount ||
      !evidence.allReturnedTracksEnded
    ) {
      throw new Error("Controlled signal-presence completed evidence differs");
    }
  } else if (
    evidence.sampleReadCallCount !== 0 ||
    evidence.frameLength !== 0 ||
    evidence.rawBytes !== 0 ||
    evidence.signalPresenceDetected !== null
  ) {
    throw new Error("Controlled signal-presence unavailable evidence differs");
  }
  return Object.freeze({
    outcome: evidence.outcome,
    signalPresenceDetected: evidence.signalPresenceDetected,
    sampleReadCallCount: evidence.sampleReadCallCount === 1 ? 1 : 0,
    sampleBufferZeroized: evidence.sampleBufferZeroized,
    processingContextClosed: evidence.processingContextClosed,
    everyReturnedTrackStopped:
      evidence.returnedTrackCount === evidence.trackStopCallCount &&
      evidence.allReturnedTracksEnded,
    numericAmplitudeRetained: false,
    waveformRetained: false,
    rawSampleBufferRetained: false,
  });
}
