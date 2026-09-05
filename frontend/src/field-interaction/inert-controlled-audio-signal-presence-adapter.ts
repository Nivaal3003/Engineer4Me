export interface InertControlledSignalPresenceCounters {
  readonly microphoneRequestCount: 0;
  readonly sampleReadCount: 0;
  readonly playbackCount: 0;
  readonly recordingCount: 0;
  readonly persistenceCount: 0;
  readonly transmissionCount: 0;
  readonly backendRequestCount: 0;
  readonly externalAiRequestCount: 0;
}

export interface InertControlledSignalPresenceAdapter {
  readonly kind: "inert_controlled_signal_presence_adapter";
  readonly operationAvailable: false;
  readonly counters: InertControlledSignalPresenceCounters;
}

export function createInertControlledSignalPresenceAdapter(): InertControlledSignalPresenceAdapter {
  return Object.freeze({
    kind: "inert_controlled_signal_presence_adapter",
    operationAvailable: false,
    counters: Object.freeze({
      microphoneRequestCount: 0,
      sampleReadCount: 0,
      playbackCount: 0,
      recordingCount: 0,
      persistenceCount: 0,
      transmissionCount: 0,
      backendRequestCount: 0,
      externalAiRequestCount: 0,
    }),
  });
}
