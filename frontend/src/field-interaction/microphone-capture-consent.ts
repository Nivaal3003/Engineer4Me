export const MICROPHONE_CAPTURE_DISCLOSURE_VERSION =
  "phase10-bounded-microphone-source-session-consent-v1";
export const MICROPHONE_CAPTURE_DISCLOSURE =
  "Engineer4Me proposes one microphone-only source session lasting no more than three seconds. If a later controlled gate is authorized, the browser may activate the microphone during that bounded session. Every returned track must be stopped on user request or automatically at the three-second ceiling. Engineer4Me will not attach the stream to an audio element, create an AudioContext, MediaRecorder, or AudioWorklet, read or analyze audio samples, create a recording, persist raw media, transmit media, call a backend, or invoke external AI. This proposal does not authorize capture; fresh capture-specific consent, a trusted single-use start gesture, and a separate intervention gate remain required.";
export const MICROPHONE_CAPTURE_DISCLOSURE_SHA256 =
  "8386ce2ca1b9538fde4c9844fbfcb3078ca88715364b9eb3fcc5ae0b4e8badd5";

export type MicrophoneCaptureConsentDecision =
  | "not_recorded"
  | "affirmative"
  | "declined"
  | "withdrawn";

export interface MicrophoneCaptureConsentEvidence {
  readonly decision: MicrophoneCaptureConsentDecision;
  readonly disclosureVersion: string;
  readonly disclosureSha256: string;
  readonly purpose: "bounded_no_persistence_microphone_source_session";
  readonly userInitiated: boolean;
  readonly singleUse: boolean;
  readonly recordedAtUnixMs: number | null;
}

export interface MicrophoneCaptureConsentEvaluation {
  readonly accepted: boolean;
  readonly fresh: boolean;
  readonly disclosureIdentityAccepted: boolean;
  readonly purposeAccepted: boolean;
  readonly userInitiationAccepted: boolean;
  readonly singleUseAccepted: boolean;
  readonly blockingReasons: readonly string[];
}

export const MICROPHONE_CAPTURE_CONSENT_MAXIMUM_AGE_MS = 5_000;

export function createUnrecordedMicrophoneCaptureConsent():
  MicrophoneCaptureConsentEvidence {
  return Object.freeze({
    decision: "not_recorded",
    disclosureVersion: MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
    disclosureSha256: MICROPHONE_CAPTURE_DISCLOSURE_SHA256,
    purpose: "bounded_no_persistence_microphone_source_session",
    userInitiated: false,
    singleUse: true,
    recordedAtUnixMs: null,
  });
}

export function evaluateMicrophoneCaptureConsent(
  evidence: MicrophoneCaptureConsentEvidence,
  nowUnixMs: number,
): MicrophoneCaptureConsentEvaluation {
  if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) {
    throw new Error("Consent evaluation time must be a non-negative safe integer.");
  }
  const disclosureIdentityAccepted =
    evidence.disclosureVersion === MICROPHONE_CAPTURE_DISCLOSURE_VERSION &&
    evidence.disclosureSha256 === MICROPHONE_CAPTURE_DISCLOSURE_SHA256;
  const purposeAccepted =
    evidence.purpose === "bounded_no_persistence_microphone_source_session";
  const userInitiationAccepted = evidence.userInitiated;
  const singleUseAccepted = evidence.singleUse;
  const fresh =
    evidence.recordedAtUnixMs !== null &&
    Number.isSafeInteger(evidence.recordedAtUnixMs) &&
    evidence.recordedAtUnixMs >= 0 &&
    nowUnixMs >= evidence.recordedAtUnixMs &&
    nowUnixMs - evidence.recordedAtUnixMs <=
      MICROPHONE_CAPTURE_CONSENT_MAXIMUM_AGE_MS;
  const blockingReasons: string[] = [];

  if (evidence.decision !== "affirmative") {
    blockingReasons.push("Fresh affirmative capture-specific consent is required.");
  }
  if (!disclosureIdentityAccepted) {
    blockingReasons.push("Capture disclosure identity is not accepted.");
  }
  if (!purposeAccepted) {
    blockingReasons.push("Capture consent purpose differs.");
  }
  if (!userInitiationAccepted) {
    blockingReasons.push("Capture consent was not user initiated.");
  }
  if (!singleUseAccepted) {
    blockingReasons.push("Capture consent is not single use.");
  }
  if (!fresh) {
    blockingReasons.push("Capture consent is absent or stale.");
  }

  return Object.freeze({
    accepted:
      evidence.decision === "affirmative" &&
      disclosureIdentityAccepted &&
      purposeAccepted &&
      userInitiationAccepted &&
      singleUseAccepted &&
      fresh,
    fresh,
    disclosureIdentityAccepted,
    purposeAccepted,
    userInitiationAccepted,
    singleUseAccepted,
    blockingReasons: Object.freeze(blockingReasons),
  });
}
