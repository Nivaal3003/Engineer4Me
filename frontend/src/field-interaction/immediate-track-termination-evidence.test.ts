import { evaluateImmediateTrackTermination } from "./immediate-track-termination-evidence";

describe("immediate track termination evidence", () => {
  it("accepts a granted stream only when every returned track is ended", () => {
    const evaluation = evaluateImmediateTrackTermination({
      mediaStreamReturned: true,
      returnedTrackCount: 1,
      trackStopCallCount: 1,
      allReturnedTracksEnded: true,
    });
    expect(evaluation.immediateTerminationAccepted).toBe(true);
    expect(evaluation.audioSampleReadPerformed).toBe(false);
    expect(evaluation.rawMediaPersisted).toBe(false);
    expect(evaluation.mediaTransmitted).toBe(false);
  });

  it("rejects an incomplete stop record", () => {
    const evaluation = evaluateImmediateTrackTermination({
      mediaStreamReturned: true,
      returnedTrackCount: 2,
      trackStopCallCount: 1,
      allReturnedTracksEnded: false,
    });
    expect(evaluation.immediateTerminationAccepted).toBe(false);
    expect(evaluation.blockingReasons).toHaveLength(2);
  });
});
