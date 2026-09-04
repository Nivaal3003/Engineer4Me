import { SectionHeading, StatusBadge } from "../design-system";
import { createAcceptedControlledMicrophonePermissionImport } from "./controlled-microphone-permission-import";
import {
  MICROPHONE_CAPTURE_DISCLOSURE,
  MICROPHONE_CAPTURE_DISCLOSURE_VERSION,
  createUnrecordedMicrophoneCaptureConsent,
} from "./microphone-capture-consent";
import { createMicrophoneCapturePolicy } from "./microphone-capture-policy";
import { createMicrophoneCaptureProposal } from "./microphone-capture-proposal";
import { createInertMicrophoneCaptureAdapter } from "./inert-microphone-capture-adapter";

export function ControlledMicrophoneCaptureProposalPanel() {
  const importedOutcome = createAcceptedControlledMicrophonePermissionImport();
  const policy = createMicrophoneCapturePolicy();
  const proposal = createMicrophoneCaptureProposal({
    importedOutcome,
    consent: createUnrecordedMicrophoneCaptureConsent(),
    trustedStartGesture: null,
    policy,
    nowUnixMs: 0,
  });
  const adapter = createInertMicrophoneCaptureAdapter();
  const headingId = "controlled-microphone-capture-proposal-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-microphone-capture-proposal"
      data-capture-execution-available="false"
      data-audio-sample-access-available="false"
      data-media-persistence-available="false"
    >
      <SectionHeading
        eyebrow="Separate capture intervention plan"
        headingId={headingId}
        title="Bounded microphone source-session proposal"
        description="The accepted granted-and-stopped permission outcome is imported as evidence only. A separate capture-specific consent, trusted start gesture, and controlled intervention gate remain required."
      />
      <div
        aria-label="Bounded microphone source-session statuses"
        className="controlled-microphone-capture-proposal__status"
      >
        <StatusBadge tone="information">Permission outcome imported</StatusBadge>
        <StatusBadge tone="warning">Capture consent not recorded</StatusBadge>
        <StatusBadge tone="information">Three-second ceiling</StatusBadge>
        <StatusBadge tone="warning">Execution gate closed</StatusBadge>
      </div>
      <dl
        aria-label="Bounded microphone source-session boundary"
        className="controlled-microphone-capture-proposal__summary"
      >
        <div>
          <dt>Accepted parent outcome</dt>
          <dd>{importedOutcome.outcome}</dd>
        </div>
        <div>
          <dt>Current permission state</dt>
          <dd>Not inferred</dd>
        </div>
        <div>
          <dt>Source scope</dt>
          <dd>Microphone only</dd>
        </div>
        <div>
          <dt>Maximum source session</dt>
          <dd>{policy.maximumSourceSessionMilliseconds / 1_000} seconds</dd>
        </div>
        <div>
          <dt>Audio sample access</dt>
          <dd>Prohibited</dd>
        </div>
        <div>
          <dt>Recording</dt>
          <dd>Prohibited</dd>
        </div>
        <div>
          <dt>Persistence or transmission</dt>
          <dd>Prohibited</dd>
        </div>
        <div>
          <dt>Application operation</dt>
          <dd>{adapter.captureStartOperationAvailable ? "Available" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Proposal state</dt>
          <dd>{proposal.state}</dd>
        </div>
      </dl>
      <div className="controlled-microphone-capture-proposal__disclosure">
        <h3>{MICROPHONE_CAPTURE_DISCLOSURE_VERSION}</h3>
        <p>{MICROPHONE_CAPTURE_DISCLOSURE}</p>
      </div>
      <ul className="controlled-microphone-capture-proposal__boundaries">
        <li>The accepted permission result proves only that one prior stream returned and its single track was stopped. It does not prove the current permission state and does not authorize capture.</li>
        <li>A future controlled gate must require fresh capture-specific consent and a trusted single-use start gesture. User stop and automatic stop at the three-second ceiling are mandatory.</li>
        <li>No audio element, AudioContext, MediaRecorder, AudioWorklet, sample reader, analysis, recording, raw-media persistence, transmission, backend request, protected-content access, or external AI operation is available.</li>
        <li>No permission-status query, device enumeration, device identifier read, camera request, automatic retry, service worker, persistent cache, native packaging, deployment header, or production deployment is authorized.</li>
      </ul>
    </section>
  );
}
