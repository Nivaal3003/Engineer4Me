export interface ImmediateTrackTerminationInput {
  readonly mediaStreamReturned: boolean;
  readonly returnedTrackCount: number;
  readonly trackStopCallCount: number;
  readonly allReturnedTracksEnded: boolean;
}

export interface ImmediateTrackTerminationEvaluation {
  readonly stopRequired: boolean;
  readonly returnedTrackCountAccepted: boolean;
  readonly everyTrackStopCalled: boolean;
  readonly allReturnedTracksEnded: boolean;
  readonly immediateTerminationAccepted: boolean;
  readonly audioElementAttachmentPerformed: false;
  readonly audioContextCreated: false;
  readonly mediaRecorderCreated: false;
  readonly audioSampleReadPerformed: false;
  readonly rawMediaPersisted: false;
  readonly mediaTransmitted: false;
  readonly blockingReasons: readonly string[];
}

function boundedCount(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 16) {
    throw new Error(`${label} must be a safe integer from zero through sixteen.`);
  }
  return value;
}

export function evaluateImmediateTrackTermination(
  input: ImmediateTrackTerminationInput,
): ImmediateTrackTerminationEvaluation {
  const returnedTrackCount = boundedCount(
    input.returnedTrackCount,
    "Returned track count",
  );
  const trackStopCallCount = boundedCount(
    input.trackStopCallCount,
    "Track stop-call count",
  );
  const stopRequired = input.mediaStreamReturned;
  const returnedTrackCountAccepted = stopRequired
    ? returnedTrackCount >= 1
    : returnedTrackCount === 0;
  const everyTrackStopCalled = stopRequired
    ? trackStopCallCount === returnedTrackCount
    : trackStopCallCount === 0;
  const endedStateAccepted = stopRequired
    ? input.allReturnedTracksEnded
    : !input.allReturnedTracksEnded;
  const blockingReasons: string[] = [];

  if (!returnedTrackCountAccepted) {
    blockingReasons.push("Returned-track count is inconsistent with the stream outcome.");
  }
  if (!everyTrackStopCalled) {
    blockingReasons.push("Every returned track was not stopped exactly once.");
  }
  if (!endedStateAccepted) {
    blockingReasons.push("Returned tracks were not all ended after immediate stop.");
  }

  return Object.freeze({
    stopRequired,
    returnedTrackCountAccepted,
    everyTrackStopCalled,
    allReturnedTracksEnded: input.allReturnedTracksEnded,
    immediateTerminationAccepted:
      returnedTrackCountAccepted && everyTrackStopCalled && endedStateAccepted,
    audioElementAttachmentPerformed: false,
    audioContextCreated: false,
    mediaRecorderCreated: false,
    audioSampleReadPerformed: false,
    rawMediaPersisted: false,
    mediaTransmitted: false,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
