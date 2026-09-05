import { SectionHeading, StatusBadge } from "../design-system";
import { createAcceptedMicrophoneSourceSessionImport } from "./accepted-microphone-source-session-import";
import {
  AUDIO_SAMPLE_ACCESS_DISCLOSURE,
  AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION,
  createAudioSampleAccessConsentPolicy,
} from "./audio-sample-access-consent";
import { createAudioSampleAcquisitionPolicy } from "./audio-sample-acquisition-policy";
import { createAudioSignalPresenceProposal } from "./audio-signal-presence-proposal";
import { createInertAudioSampleAcquisitionAdapter } from "./inert-audio-sample-acquisition-adapter";

export function ControlledAudioSampleAcquisitionProposalPanel() {
  const parent = createAcceptedMicrophoneSourceSessionImport();
  const consent = createAudioSampleAccessConsentPolicy();
  const policy = createAudioSampleAcquisitionPolicy();
  const proposal = createAudioSignalPresenceProposal();
  const adapter = createInertAudioSampleAcquisitionAdapter();
  const headingId = "controlled-audio-sample-acquisition-proposal-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-audio-sample-proposal"
      data-audio-sample-acquisition-available="false"
      data-signal-presence-operation-available="false"
    >
      <SectionHeading
        eyebrow="Separate sample-access intervention"
        headingId={headingId}
        title="Bounded audio sample and signal-presence proposal"
        description="The accepted source session completed within its ceiling, but it grants no sample-access authority. A future local-only signal-presence check remains behind fresh consent, one trusted gesture, and another controlled intervention gate."
      />
      <div
        aria-label="Audio sample proposal statuses"
        className="controlled-audio-sample-proposal__status"
      >
        <StatusBadge tone="positive">Source session accepted</StatusBadge>
        <StatusBadge tone="information">One 2,048-sample frame maximum</StatusBadge>
        <StatusBadge tone="warning">Sample access gate closed</StatusBadge>
        <StatusBadge tone="warning">Application operation unavailable</StatusBadge>
      </div>
      <dl
        aria-label="Audio sample proposal boundary"
        className="controlled-audio-sample-proposal__summary"
      >
        <div><dt>Accepted source outcome</dt><dd>{parent.outcome}</dd></div>
        <div><dt>Observed source duration</dt><dd>{parent.observedMilliseconds} ms</dd></div>
        <div><dt>Future sample format</dt><dd>{policy.sampleFormat}</dd></div>
        <div><dt>Maximum frame</dt><dd>{policy.maximumFrameLength} samples</dd></div>
        <div><dt>Maximum raw buffer</dt><dd>{policy.maximumRawBytes} bytes</dd></div>
        <div><dt>Maximum source interval</dt><dd>{policy.maximumSourceSessionMilliseconds} ms</dd></div>
        <div><dt>Output</dt><dd>Signal present or absent only</dd></div>
        <div><dt>Buffer retention</dt><dd>Immediate zeroization required</dd></div>
        <div><dt>Consent status</dt><dd>{consent.consentRecorded ? "Recorded" : "Not recorded"}</dd></div>
        <div><dt>Proposal state</dt><dd>{proposal.state}</dd></div>
        <div><dt>Application operation</dt><dd>{adapter.sampleAcquisitionOperationAvailable ? "Available" : "Unavailable"}</dd></div>
      </dl>
      <div className="controlled-audio-sample-proposal__disclosure">
        <h3>{AUDIO_SAMPLE_ACCESS_DISCLOSURE_VERSION}</h3>
        <p>{AUDIO_SAMPLE_ACCESS_DISCLOSURE}</p>
      </div>
      <ul className="controlled-audio-sample-proposal__boundaries">
        <li>No current permission state is inferred, and the completed source session does not derive sample acquisition authorization.</li>
        <li>No sample reader, AudioContext, playback, MediaRecorder, AudioWorklet, recording, persistence, media transmission, backend, protected-content, speech-to-text, voice-command, or AI operation is available in the application.</li>
        <li>A future verifier must zeroize the bounded sample buffer, close its local processing context, stop every returned track, and retain no amplitude or waveform.</li>
      </ul>
    </section>
  );
}
