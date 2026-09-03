import { SectionHeading, StatusBadge } from "../design-system";
import { createInertControlledBrowserNavigationAdapter } from "./inert-controlled-browser-navigation-adapter";
import {
  CONTROLLED_BROWSER_REDACTED_ENDPOINT,
} from "./controlled-browser-navigation-observation";
import { createControlledBrowserNavigationPolicy } from "./controlled-browser-navigation-policy";
import { DEFAULT_DENY_PERMISSIONS_POLICY_VALUE } from "./deployment-permissions-policy";

export function ControlledBrowserNavigationEvidencePanel() {
  const adapter = createInertControlledBrowserNavigationAdapter();
  const policy = createControlledBrowserNavigationPolicy();
  const headingId = "controlled-browser-navigation-evidence-heading";
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel controlled-browser-navigation-evidence"
      data-application-browser-launch-operation="false"
      data-permission-activation-authorized="false"
    >
      <SectionHeading
        eyebrow="Controlled acceptance evidence"
        headingId={headingId}
        title="Controlled headless browser navigation evidence"
        description="The controlled batch verifier may execute exactly one headless navigation to the static IPv4-loopback fixture. Application runtime remains inert and receives no browser-launch, permission, capture, network, or transport operation."
      />
      <div
        aria-label="Controlled browser navigation evidence statuses"
        className="controlled-browser-navigation-evidence__status"
      >
        <StatusBadge tone="information">One loopback navigation controlled</StatusBadge>
        <StatusBadge tone="warning">Application browser launch closed</StatusBadge>
        <StatusBadge tone="warning">Permission prompts closed</StatusBadge>
      </div>
      <dl
        aria-label="Controlled browser navigation evidence summary"
        className="controlled-browser-navigation-evidence__summary"
      >
        <div>
          <dt>Evidence source</dt>
          <dd>{adapter.evidenceSource}</dd>
        </div>
        <div>
          <dt>Allowed endpoint</dt>
          <dd>{CONTROLLED_BROWSER_REDACTED_ENDPOINT}</dd>
        </div>
        <div>
          <dt>Maximum navigations</dt>
          <dd>{policy.maximumNavigationCount}</dd>
        </div>
        <div>
          <dt>Required response policy</dt>
          <dd>{DEFAULT_DENY_PERMISSIONS_POLICY_VALUE}</dd>
        </div>
        <div>
          <dt>Browser identity</dt>
          <dd>Not collected</dd>
        </div>
        <div>
          <dt>Executable path</dt>
          <dd>Not persisted</dd>
        </div>
      </dl>
      <ul className="controlled-browser-navigation-evidence__boundaries">
        <li>The verifier uses a reviewed ordinary signed executable and deletes its fresh ephemeral profile after closure.</li>
        <li>No browser executable is installed, downloaded, recursively inventoried, named, or versioned.</li>
        <li>No user-agent, client hint, permission status, policy method, prompt, device identifier, media byte, credential, token, protected content, or production setting is read.</li>
        <li>External destinations remain denied locally; no external connection, service worker, persistent cache, download, popup, backend transport, external AI, PWA, native package, or deployment is authorized.</li>
      </ul>
    </section>
  );
}
