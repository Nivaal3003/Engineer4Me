import { SectionHeading, StatusBadge } from "../design-system";
import { createAcceptedMicrophoneCaptureProposalImport } from "./accepted-microphone-capture-proposal-import";
import {
  CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE,
  CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_VERSION,
  createControlledMicrophoneSourceSessionPolicy,
} from "./controlled-microphone-source-session-policy";
import { createInertControlledMicrophoneSourceSessionAdapter } from "./inert-controlled-microphone-source-session-adapter";

export function ControlledMicrophoneSourceSessionEvidencePanel() {
  const parent = createAcceptedMicrophoneCaptureProposalImport();
  const policy = createControlledMicrophoneSourceSessionPolicy();
  const adapter = createInertControlledMicrophoneSourceSessionAdapter();
  const headingId = "controlled-microphone-source-session-evidence-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-microphone-source-session-evidence"
      data-application-source-session-available="false"
      data-audio-sample-access-available="false"
    >
      <SectionHeading
        eyebrow="Verifier-only bounded source gate"
        headingId={headingId}
        title="Controlled microphone source-session evidence"
        description="A separate user-run verifier may hold one microphone source for no more than three seconds after fresh capture-specific consent and a trusted click. The application exposes no microphone or audio-use operation."
      />
      <div
        aria-label="Controlled microphone source-session statuses"
        className="controlled-microphone-source-session-evidence__status"
      >
        <StatusBadge tone="information">One source session maximum</StatusBadge>
        <StatusBadge tone="information">Three-second source ceiling</StatusBadge>
        <StatusBadge tone="warning">Audio samples remain inaccessible</StatusBadge>
        <StatusBadge tone="warning">Application source-session control unavailable</StatusBadge>
      </div>
      <dl
        aria-label="Controlled microphone source-session boundary"
        className="controlled-microphone-source-session-evidence__summary"
      >
        <div><dt>Accepted proposal</dt><dd>{parent.source}</dd></div>
        <div><dt>Source scope</dt><dd>Microphone only</dd></div>
        <div><dt>Maximum source session</dt><dd>{policy.maximumSourceSessionMilliseconds / 1000} seconds</dd></div>
        <div><dt>Automatic safety stop</dt><dd>{policy.automaticSafetyStopMilliseconds / 1000} seconds</dd></div>
        <div><dt>User early stop</dt><dd>Required control</dd></div>
        <div><dt>Temporary policy</dt><dd>{policy.temporaryPermissionsPolicy}</dd></div>
        <div><dt>Audio sample access</dt><dd>Prohibited</dd></div>
        <div><dt>Application operation</dt><dd>{adapter.sourceSessionStartOperationAvailable ? "Available" : "Unavailable"}</dd></div>
        <div><dt>Next gate</dt><dd>Separate audio-sample intervention</dd></div>
      </dl>
      <div className="controlled-microphone-source-session-evidence__disclosure">
        <h3>{CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE_VERSION}</h3>
        <p>{CONTROLLED_MICROPHONE_SOURCE_SESSION_DISCLOSURE}</p>
      </div>
      <ul className="controlled-microphone-source-session-evidence__boundaries">
        <li>The source-session outcome is recorded by a separate loopback verifier and does not expose a browser, microphone, start, or stop operation to the application.</li>
        <li>No audio element, AudioContext, MediaRecorder, AudioWorklet, sample reader, playback, analysis, recording, raw-media persistence, media transmission, backend request, protected-content access, or external AI operation is available.</li>
        <li>No permission-status query, device enumeration, device identifier read, camera request, automatic retry, service worker, persistent cache, native packaging, deployment header, or production deployment is authorized.</li>
      </ul>
    </section>
  );
}
