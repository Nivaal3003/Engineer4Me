import { createInertAudioSampleAcquisitionAdapter } from "./inert-audio-sample-acquisition-adapter";

describe("inert audio sample acquisition adapter", () => {
  it("exposes no operation and preserves all counters at zero", () => {
    const adapter = createInertAudioSampleAcquisitionAdapter();
    expect(adapter.sampleAcquisitionOperationAvailable).toBe(false);
    for (const value of Object.values(adapter)) {
      if (typeof value === "number") {
        expect(value).toBe(0);
      }
    }
  });
});
