import { SectionHeading, StatusBadge } from "../design-system";
import { createInertPermissionCapabilityAdapter } from "./inert-permission-adapter";

function yesNoUnknown(value: boolean | null): string {
  if (value === null) return "Unknown";
  return value ? "Present" : "Not present";
}

export function PermissionCapabilityPanel() {
  const capabilities = createInertPermissionCapabilityAdapter().inspectCapabilities();
  const headingId = "permission-capability-evidence-heading";
  const captureSurfacePresent =
    capabilities.mediaDevicesObjectPresent
    && capabilities.getUserMediaFunctionPresent;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel permission-capability-panel"
      data-detection-mode={capabilities.detectionMode}
      data-permission-prompt="not-requested"
    >
      <SectionHeading
        eyebrow="Phase 10 permission readiness"
        headingId={headingId}
        title="Permission capability evidence"
        description="The browser surface is inspected by property presence only. No permission status query, prompt, device enumeration, or capture call is made."
      />
      <div
        aria-label="Permission capability statuses"
        className="permission-capability-panel__status"
      >
        <StatusBadge tone="information">Read-only detection</StatusBadge>
        <StatusBadge tone={captureSurfacePresent ? "information" : "warning"}>
          Capture API surface {captureSurfacePresent ? "present" : "unavailable"}
        </StatusBadge>
        <StatusBadge tone="warning">No permission prompt</StatusBadge>
      </div>
      <dl
        aria-label="Read-only browser capability evidence"
        className="permission-capability-panel__summary"
      >
        <div>
          <dt>Secure context</dt>
          <dd>{yesNoUnknown(capabilities.secureContext)}</dd>
        </div>
        <div>
          <dt>Embedding context</dt>
          <dd>{capabilities.embeddingContext}</dd>
        </div>
        <div>
          <dt>Media capture surface</dt>
          <dd>{captureSurfacePresent ? "Function present" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Permission-status surface</dt>
          <dd>{capabilities.permissionsQueryFunctionPresent ? "Function present" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Permissions Policy surface</dt>
          <dd>{capabilities.permissionsPolicyAllowsFeatureFunctionPresent ? "Function present" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Device identifiers</dt>
          <dd>Not enumerated</dd>
        </div>
      </dl>
      <ul className="permission-capability-panel__boundaries">
        <li>No permission-status query or Permissions Policy method was invoked.</li>
        <li>No microphone or camera permission prompt was requested.</li>
        <li>No media device was enumerated and no label or device identifier was loaded.</li>
        <li>Capability presence does not grant permission or authorize capture.</li>
      </ul>
    </section>
  );
}
