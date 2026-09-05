import {
  AUDIO_SAMPLE_EXACT_READ_CALL_MAXIMUM,
  AUDIO_SAMPLE_MAXIMUM_FRAME_LENGTH,
  AUDIO_SAMPLE_MAXIMUM_RAW_BYTES,
  AUDIO_SAMPLE_MAXIMUM_SOURCE_SESSION_MS,
  AUDIO_SIGNAL_PRESENCE_ABSOLUTE_PEAK_THRESHOLD,
  createAudioSampleAcquisitionPolicy,
} from "./audio-sample-acquisition-policy";

describe("bounded audio sample acquisition policy", () => {
  it("retains one small local signal-presence read behind intervention", () => {
    const policy = createAudioSampleAcquisitionPolicy();
    expect(policy.exactSampleReadCallMaximum).toBe(AUDIO_SAMPLE_EXACT_READ_CALL_MAXIMUM);
    expect(policy.maximumFrameLength).toBe(AUDIO_SAMPLE_MAXIMUM_FRAME_LENGTH);
    expect(policy.maximumRawBytes).toBe(AUDIO_SAMPLE_MAXIMUM_RAW_BYTES);
    expect(policy.maximumSourceSessionMilliseconds).toBe(AUDIO_SAMPLE_MAXIMUM_SOURCE_SESSION_MS);
    expect(policy.signalPresenceThreshold).toBe(AUDIO_SIGNAL_PRESENCE_ABSOLUTE_PEAK_THRESHOLD);
    expect(policy.rawBufferZeroizationRequired).toBe(true);
    expect(policy.signalPresenceClassificationOnly).toBe(true);
    expect(policy.executionAuthorized).toBe(false);
    expect(policy.applicationOperationAvailable).toBe(false);
  });
});
