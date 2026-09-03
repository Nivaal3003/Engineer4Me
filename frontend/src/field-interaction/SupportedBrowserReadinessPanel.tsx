import { SectionHeading, StatusBadge } from "../design-system";
import { createNoDeploymentPermissionsPolicyHeaderEvidence } from "./deployment-header-evidence";
import {
  DEFAULT_DENY_PERMISSIONS_POLICY_VALUE,
  FUTURE_CONTROLLED_SELF_PERMISSIONS_POLICY_VALUE,
} from "./deployment-permissions-policy";
import { createInertBrowserReadinessAdapter } from "./inert-browser-readiness-adapter";

function contextLabel(value: boolean | null): string {
  if (value === null) return "Unknown";
  return value ? "Verified" : "Not verified";
}

export function SupportedBrowserReadinessPanel() {
  const adapter = createInertBrowserReadinessAdapter();
  const capabilities = adapter.inspectCapabilities();
  const headerEvidence = createNoDeploymentPermissionsPolicyHeaderEvidence();
  const microphone = adapter.evaluate({
    permission: "microphone",
    headerEvidence,
  });
  const camera = adapter.evaluate({
    permission: "camera",
    headerEvidence,
  });
  const headingId = "supported-browser-readiness-heading";
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel supported-browser-readiness"
      data-permission-prompt-authorized="false"
      data-support-determination-mode="capability_based_read_only"
    >
      <SectionHeading
        eyebrow="Browser and deployment evidence"
        headingId={headingId}
        title="Supported-browser readiness evidence"
        description="Readiness is capability-based and version-independent. Browser identity, user-agent data, live response headers, permission status, and media devices are not read."
      />
      <div
        aria-label="Supported-browser readiness statuses"
        className="supported-browser-readiness__status"
      >
        <StatusBadge tone="information">Capability-based inspection</StatusBadge>
        <StatusBadge tone="warning">Deployment header unverified</StatusBadge>
        <StatusBadge tone="warning">Permission prompts closed</StatusBadge>
      </div>
      <dl
        aria-label="Browser and deployment-header readiness evidence"
        className="supported-browser-readiness__summary"
      >
        <div>
          <dt>Browser identity</dt>
          <dd>Not collected</dd>
        </div>
        <div>
          <dt>Secure context</dt>
          <dd>{contextLabel(capabilities.secureContext)}</dd>
        </div>
        <div>
          <dt>Embedding context</dt>
          <dd>{capabilities.embeddingContext}</dd>
        </div>
        <div>
          <dt>Microphone readiness</dt>
          <dd>{microphone.state}</dd>
        </div>
        <div>
          <dt>Camera readiness</dt>
          <dd>{camera.state}</dd>
        </div>
        <div>
          <dt>Live response header</dt>
          <dd>Not read</dd>
        </div>
      </dl>
      <div className="supported-browser-readiness__profiles">
        <div>
          <h3>Repository default-deny profile</h3>
          <code>{DEFAULT_DENY_PERMISSIONS_POLICY_VALUE}</code>
          <p>Desired-state evidence only; this batch does not deploy or verify a live header.</p>
        </div>
        <div>
          <h3>Future controlled self-only candidate</h3>
          <code>{FUTURE_CONTROLLED_SELF_PERMISSIONS_POLICY_VALUE}</code>
          <p>Not authorized for deployment and does not authorize a permission prompt.</p>
        </div>
      </div>
      <ul className="supported-browser-readiness__boundaries">
        <li>No browser name, version, user-agent string, or client hint was collected.</li>
        <li>No live response header or deployment platform was queried.</li>
        <li>No permission-status query or Permissions Policy browser method was called.</li>
        <li>No microphone, camera, device enumeration, capture, transport, or external processing operation is available here.</li>
      </ul>
    </section>
  );
}
