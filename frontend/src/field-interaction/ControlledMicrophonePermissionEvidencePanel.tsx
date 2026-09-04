import { SectionHeading, StatusBadge } from "../design-system";
import {
  CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE,
  CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_VERSION,
  createControlledMicrophonePermissionPolicy,
} from "./controlled-microphone-permission-policy";
import { createInertControlledMicrophonePermissionAdapter } from "./inert-controlled-microphone-permission-adapter";

export function ControlledMicrophonePermissionEvidencePanel() {
  const policy = createControlledMicrophonePermissionPolicy();
  const adapter = createInertControlledMicrophonePermissionAdapter();
  const headingId = "controlled-microphone-permission-evidence-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-microphone-permission-evidence"
      data-application-permission-request-available="false"
      data-capture-authorized="false"
    >
      <SectionHeading
        eyebrow="Verifier-only controlled gate"
        headingId={headingId}
        title="Controlled microphone permission request evidence"
        description="A separate user-run verifier may make one microphone-only browser request after explicit consent and a trusted click. The application exposes no permission-request or capture operation."
      />
      <div
        aria-label="Controlled microphone permission request statuses"
        className="controlled-microphone-permission-evidence__status"
      >
        <StatusBadge tone="information">One request maximum</StatusBadge>
        <StatusBadge tone="warning">Brief microphone activation disclosed</StatusBadge>
        <StatusBadge tone="information">Immediate track stop required</StatusBadge>
        <StatusBadge tone="warning">Application request control unavailable</StatusBadge>
      </div>
      <dl
        aria-label="Controlled microphone permission request boundary"
        className="controlled-microphone-permission-evidence__summary"
      >
        <div>
          <dt>Permission scope</dt>
          <dd>Microphone only</dd>
        </div>
        <div>
          <dt>Request-call maximum</dt>
          <dd>{policy.exactGetUserMediaCallMaximum}</dd>
        </div>
        <div>
          <dt>Temporary policy</dt>
          <dd>{policy.temporaryPermissionsPolicy}</dd>
        </div>
        <div>
          <dt>Prompt display</dt>
          <dd>Not observable by application code</dd>
        </div>
        <div>
          <dt>Audio sample access</dt>
          <dd>Prohibited</dd>
        </div>
        <div>
          <dt>Application operation</dt>
          <dd>{adapter.permissionRequestOperationAvailable ? "Available" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Capture authorization</dt>
          <dd>No</dd>
        </div>
      </dl>
      <div className="controlled-microphone-permission-evidence__disclosure">
        <h3>{CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE_VERSION}</h3>
        <p>{CONTROLLED_MICROPHONE_PERMISSION_DISCLOSURE}</p>
      </div>
      <ul className="controlled-microphone-permission-evidence__boundaries">
        <li>The verifier requires the reviewed disclosure, an affirmative checkbox, and a trusted single-use button click before its only request call.</li>
        <li>On grant, every returned track must be stopped immediately before outcome reporting; no audio element, AudioContext, MediaRecorder, sample reader, persistence, or media transmission is allowed.</li>
        <li>Denied, dismissed, unavailable, and granted outcomes do not authorize capture. A separate controlled capture gate remains required.</li>
        <li>No permission-status query, Permissions Policy method call, camera request, device enumeration, identifier read, authentication, bearer attachment, backend transport, protected-content access, external AI, service worker, persistent cache, native packaging, deployment header, or production deployment is available.</li>
      </ul>
    </section>
  );
}
