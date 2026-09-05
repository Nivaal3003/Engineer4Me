import {
  AUDIO_SAMPLE_ACCESS_DISCLOSURE_SHA256,
  AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION,
  createAudioSampleAccessConsentPolicy,
} from "./audio-sample-access-consent";

describe("audio sample access consent policy", () => {
  it("requires distinct fresh consent and a trusted single-use gesture", () => {
    const policy = createAudioSampleAccessConsentPolicy();
    expect(policy.purpose).toBe("local_signal_presence_only");
    expect(policy.disclosureVersion).toBe(AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION);
    expect(policy.disclosureSha256).toBe(AUDIO_SAMPLE_ACCESS_DISCLOSURE_SHA256);
    expect(policy.permissionConsentReusable).toBe(false);
    expect(policy.sourceSessionConsentReusable).toBe(false);
    expect(policy.consentRecorded).toBe(false);
    expect(policy.trustedGestureRecorded).toBe(false);
  });
});
