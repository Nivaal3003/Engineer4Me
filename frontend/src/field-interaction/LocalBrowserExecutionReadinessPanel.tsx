import { SectionHeading, StatusBadge } from "../design-system";
import { createInertLocalBrowserExecutionAdapter } from "./inert-local-browser-execution-adapter";
import { createControlledLocalBrowserExecutionPolicy } from "./local-browser-execution-policy";
import {
  CONTROLLED_LOOPBACK_HOST,
  CONTROLLED_LOOPBACK_PATH,
} from "./loopback-response-observation";
import { DEFAULT_DENY_PERMISSIONS_POLICY_VALUE } from "./deployment-permissions-policy";

export function LocalBrowserExecutionReadinessPanel() {
  const adapter = createInertLocalBrowserExecutionAdapter();
  const readiness = adapter.evaluate();
  const policy = createControlledLocalBrowserExecutionPolicy();
  const headingId = "local-browser-execution-readiness-heading";
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel local-browser-execution-readiness"
      data-browser-launch-authorized="false"
      data-external-network-allowed="false"
    >
      <SectionHeading
        eyebrow="Controlled local verification"
        headingId={headingId}
        title="Local browser execution readiness"
        description="A deterministic loopback response-header proof and reviewed executable evidence must be accepted before any separate browser-launch gate. This application panel cannot launch a browser."
      />
      <div
        aria-label="Local browser execution readiness statuses"
        className="local-browser-execution-readiness__status"
      >
        <StatusBadge tone="information">Loopback proof controlled</StatusBadge>
        <StatusBadge tone="warning">Browser launch closed</StatusBadge>
        <StatusBadge tone="warning">Permission prompts closed</StatusBadge>
      </div>
      <dl
        aria-label="Local browser execution readiness evidence"
        className="local-browser-execution-readiness__summary"
      >
        <div>
          <dt>Readiness state</dt>
          <dd>{readiness.state}</dd>
        </div>
        <div>
          <dt>Loopback observation evidence</dt>
          <dd>Acceptance archive only</dd>
        </div>
        <div>
          <dt>Allowed origin</dt>
          <dd>{`http://${CONTROLLED_LOOPBACK_HOST}:<ephemeral>`}</dd>
        </div>
        <div>
          <dt>Allowed path</dt>
          <dd>{CONTROLLED_LOOPBACK_PATH}</dd>
        </div>
        <div>
          <dt>Browser identity</dt>
          <dd>Not collected</dd>
        </div>
        <div>
          <dt>Next gate</dt>
          <dd>Intervention required</dd>
        </div>
      </dl>
      <div className="local-browser-execution-readiness__profile">
        <h3>Required isolated profile</h3>
        <p>
          Headless, fresh, ephemeral, loopback-only, and default deny. External
          navigation, credentials, extensions, service workers, persistent storage,
          downloads, popups, permission overrides, capture, authentication, backend
          transport, and protected-content access remain prohibited.
        </p>
        <code>{DEFAULT_DENY_PERMISSIONS_POLICY_VALUE}</code>
        <p>
          Policy profile: {policy.profile}. The controlled verification probe may
          observe this exact header on loopback; application runtime does not read a
          live deployment response.
        </p>
      </div>
      <ul className="local-browser-execution-readiness__boundaries">
        <li>No browser launch or navigation operation is exposed.</li>
        <li>No browser name, version, user-agent string, or client hint is collected.</li>
        <li>No permission-status query, policy-method call, permission prompt, device enumeration, or capture is allowed.</li>
        <li>No external network, identity-provider, bearer-token, backend, protected-content, service-worker, PWA, native, or production-deployment operation is authorized.</li>
      </ul>
    </section>
  );
}
