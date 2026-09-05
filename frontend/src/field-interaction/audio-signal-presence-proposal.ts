import { createAcceptedMicrophoneSourceSessionImport } from "./accepted-microphone-source-session-import";
import { createAudioSampleAccessConsentPolicy } from "./audio-sample-access-consent";
import { createAudioSampleAcquisitionPolicy } from "./audio-sample-acquisition-policy";

export interface AudioSignalPresenceProposal {
  readonly state: "intervention_required";
  readonly acceptedSourceSessionBound: true;
  readonly acceptedSourceSessionCompletedWithinCeiling: true;
  readonly currentPermissionStateInferred: false;
  readonly sampleAuthorizationDerivedFromSourceSession: false;
  readonly localSignalPresenceOnly: true;
  readonly sampleSpecificConsentRecorded: false;
  readonly trustedSampleStartGestureRecorded: false;
  readonly executionInterventionRequired: true;
  readonly executionAuthorized: false;
  readonly applicationOperationAvailable: false;
  readonly nextAction: "separate_controlled_audio_sample_intervention";
}

export function createAudioSignalPresenceProposal(): AudioSignalPresenceProposal {
  const sourceSession = createAcceptedMicrophoneSourceSessionImport();
  const consent = createAudioSampleAccessConsentPolicy();
  const acquisition = createAudioSampleAcquisitionPolicy();
  if (sourceSession.observedMilliseconds > 3_000 ||
      sourceSession.audioSampleReadPerformed ||
      !sourceSession.allReturnedTracksEnded) {
    throw new Error("Accepted source-session evidence cannot support the sample proposal.");
  }
  if (consent.consentRecorded || consent.trustedGestureRecorded ||
      acquisition.executionAuthorized || acquisition.applicationOperationAvailable) {
    throw new Error("Audio sample proposal activation boundary differs.");
  }
  return Object.freeze({
    state: "intervention_required",
    acceptedSourceSessionBound: true,
    acceptedSourceSessionCompletedWithinCeiling: true,
    currentPermissionStateInferred: false,
    sampleAuthorizationDerivedFromSourceSession: false,
    localSignalPresenceOnly: true,
    sampleSpecificConsentRecorded: false,
    trustedSampleStartGestureRecorded: false,
    executionInterventionRequired: true,
    executionAuthorized: false,
    applicationOperationAvailable: false,
    nextAction: "separate_controlled_audio_sample_intervention",
  });
}
