export const AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION =
  "phase10-bounded-audio-sample-signal-presence-consent-v1";
export const AUDIO_SAMPLE_ACCESS_DISCLOSURE =
  "Engineer4Me proposes one future microphone-only, local in-memory signal-presence check after a separate reviewed disclosure, fresh sample-specific consent, and a trusted single-use Start click. The future verifier may read at most one mono Float32 frame containing no more than 2,048 samples during a source session of no more than one second. It may classify only whether a bounded signal is present using the reviewed absolute-peak threshold. It must not retain a numeric amplitude, waveform, device label, device identifier, transcript, or voice command. The sample buffer must be zeroized immediately, the audio processing context must close, and every returned media track must stop. No playback, recording, raw-media persistence, transmission, backend transport, protected-content access, external or local AI, speech-to-text processing, service worker, persistent cache, native packaging, deployment-header application, or production deployment is authorized. This proposal does not infer current permission state and does not authorize execution.";
export const AUDIO_SAMPLE_ACCESS_DISCLOSURE_SHA256 =
  "84e02f06e6cf646da0796e88b46c25e36b0f635533930be56649218f34e2b5d7";

export interface AudioSampleAccessConsentPolicy {
  readonly purpose: "local_signal_presence_only";
  readonly disclosureVersion: typeof AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION;
  readonly disclosureSha256: typeof AUDIO_SAMPLE_ACCESS_DISCLOSURE_SHA256;
  readonly explicitAffirmativeConsentRequired: true;
  readonly freshConsentRequired: true;
  readonly withdrawalBeforeExecutionSupported: true;
  readonly trustedSingleUseStartGestureRequired: true;
  readonly permissionConsentReusable: false;
  readonly sourceSessionConsentReusable: false;
  readonly consentRecorded: false;
  readonly trustedGestureRecorded: false;
}

export function createAudioSampleAccessConsentPolicy(): AudioSampleAccessConsentPolicy {
  return Object.freeze({
    purpose: "local_signal_presence_only",
    disclosureVersion: AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION,
    disclosureSha256: AUDIO_SAMPLE_ACCESS_DISCLOSURE_SHA256,
    explicitAffirmativeConsentRequired: true,
    freshConsentRequired: true,
    withdrawalBeforeExecutionSupported: true,
    trustedSingleUseStartGestureRequired: true,
    permissionConsentReusable: false,
    sourceSessionConsentReusable: false,
    consentRecorded: false,
    trustedGestureRecorded: false,
  });
}
