import { SectionHeading, StatusBadge } from "../design-system";
import {
  CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT,
  createBrowserCapabilityObservationPolicy,
} from "./browser-capability-observation-policy";
import { DEFAULT_DENY_PERMISSIONS_POLICY_VALUE } from "./deployment-permissions-policy";
import { createInertBrowserCapabilityObservationAdapter } from "./inert-browser-capability-observation-adapter";

export function ControlledBrowserCapabilityObservationPanel() {
  const adapter = createInertBrowserCapabilityObservationAdapter();
  const policy = createBrowserCapabilityObservationPolicy();
  const headingId = "controlled-browser-capability-observation-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-browser-capability-observation"
      data-application-observation-operation="false"
      data-permission-activation-authorized="false"
    >
      <SectionHeading
        eyebrow="Controlled acceptance evidence"
        headingId={headingId}
        title="Controlled browser capability observation"
        description="One isolated headless IPv4-loopback page may report secure-context, top-level-context, and property-presence evidence. No permission state, device identity, captured media, browser identity, protected content, or external service is accessed."
      />
      <div
        aria-label="Controlled browser capability observation statuses"
        className="controlled-browser-capability-observation__status"
      >
        <StatusBadge tone="information">Read-only capability evidence</StatusBadge>
        <StatusBadge tone="warning">Permission methods not invoked</StatusBadge>
        <StatusBadge tone="warning">Activation gate closed</StatusBadge>
      </div>
      <dl
        aria-label="Controlled browser capability observation summary"
        className="controlled-browser-capability-observation__summary"
      >
        <div>
          <dt>Evidence source</dt>
          <dd>{adapter.evidenceSource}</dd>
        </div>
        <div>
          <dt>Observation endpoint</dt>
          <dd>{CONTROLLED_BROWSER_CAPABILITY_REDACTED_ENDPOINT}</dd>
        </div>
        <div>
          <dt>Evidence mode</dt>
          <dd>Property presence only</dd>
        </div>
        <div>
          <dt>Required context</dt>
          <dd>Secure and top-level</dd>
        </div>
        <div>
          <dt>Response policy</dt>
          <dd>{DEFAULT_DENY_PERMISSIONS_POLICY_VALUE}</dd>
        </div>
        <div>
          <dt>Allowed evidence properties</dt>
          <dd>{policy.allowedPropertyEvidence.length}</dd>
        </div>
        <div>
          <dt>Application operation</dt>
          <dd>Unavailable</dd>
        </div>
      </dl>
      <ul className="controlled-browser-capability-observation__boundaries">
        <li>The acceptance verifier may inspect only the approved read-only property-presence list during one bounded loopback navigation.</li>
        <li>The permissions query, Permissions Policy methods, media capture, and device enumeration are present only as names whose availability may be reported; none is invoked.</li>
        <li>No permission status, prompt, override, device identifier, user-agent, client hint, browser name, browser version, audio, image, video, document byte, credential, token, or protected content is collected.</li>
        <li>Application runtime exposes no observation, launch, navigation, permission, capture, external-network, backend-transport, external-AI, service-worker, caching, native-packaging, or deployment operation.</li>
      </ul>
    </section>
  );
}
