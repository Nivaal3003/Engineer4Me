import { SectionHeading, StatusBadge } from "../design-system";
import { createInertPermissionPromptExecutionAdapter } from "./inert-permission-prompt-execution-adapter";
import { createAcceptedMicrophonePermissionActivationEvidence } from "./microphone-permission-activation-evidence";
import {
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE,
  MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
  createUnrecordedMicrophonePermissionConsent,
} from "./permission-consent-evidence";
import { evaluateMicrophonePermissionConsent } from "./permission-consent-policy";
import { createMicrophonePermissionPromptExecutionPlan } from "./permission-prompt-execution-plan";
import { createMicrophonePermissionPromptProposal } from "./permission-prompt-proposal";
import { evaluateUserGestureEvidence } from "./user-gesture";

export function MicrophonePermissionActivationProposalPanel() {
  const capabilityEvidence = createAcceptedMicrophonePermissionActivationEvidence();
  const consent = evaluateMicrophonePermissionConsent({
    evidence: createUnrecordedMicrophonePermissionConsent(),
    referenceEpochMs: 0,
  });
  const gesture = evaluateUserGestureEvidence({
    evidence: null,
    expectedTargetId: "microphone-permission-control",
    referenceEpochMs: 0,
  });
  const proposal = createMicrophonePermissionPromptProposal({
    proposalId: "microphone-permission-prompt-proposal",
    capabilityEvidence,
    consent,
    gesture,
  });
  const plan = createMicrophonePermissionPromptExecutionPlan(proposal);
  const adapter = createInertPermissionPromptExecutionAdapter();
  const headingId = "microphone-permission-activation-proposal-heading";

  return (
    <section
      aria-labelledby={headingId}
      className="content-panel microphone-permission-activation-proposal"
      data-permission-prompt-authorized="false"
      data-capture-authorized="false"
    >
      <SectionHeading
        eyebrow="Controlled activation proposal"
        headingId={headingId}
        title="Microphone permission activation proposal"
        description="Accepted browser capability evidence is bound, but explicit consent, a fresh trusted gesture, and a separate user-run prompt-execution gate remain required. This panel cannot display a permission prompt or start capture."
      />
      <div
        aria-label="Microphone permission activation proposal statuses"
        className="microphone-permission-activation-proposal__status"
      >
        <StatusBadge tone="information">Capability evidence accepted</StatusBadge>
        <StatusBadge tone="warning">Consent not recorded</StatusBadge>
        <StatusBadge tone="warning">Trusted gesture not recorded</StatusBadge>
        <StatusBadge tone="warning">Prompt execution gate closed</StatusBadge>
      </div>
      <dl
        aria-label="Microphone permission activation proposal summary"
        className="microphone-permission-activation-proposal__summary"
      >
        <div>
          <dt>Permission scope</dt>
          <dd>Microphone only</dd>
        </div>
        <div>
          <dt>Capability evidence</dt>
          <dd>Accepted Batch 439-450</dd>
        </div>
        <div>
          <dt>Proposal state</dt>
          <dd>{proposal.state}</dd>
        </div>
        <div>
          <dt>Consent disclosure</dt>
          <dd>{MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION}</dd>
        </div>
        <div>
          <dt>Future prompt maximum</dt>
          <dd>{plan.exactPromptCountMaximum}</dd>
        </div>
        <div>
          <dt>Prompt operation</dt>
          <dd>{adapter.permissionPromptExecutionOperationAvailable ? "Available" : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Capture authorized</dt>
          <dd>No</dd>
        </div>
      </dl>
      <div className="microphone-permission-activation-proposal__disclosure">
        <h3>Reviewed pre-prompt disclosure</h3>
        <p>{MICROPHONE_PERMISSION_CONSENT_DISCLOSURE}</p>
      </div>
      <ul className="microphone-permission-activation-proposal__boundaries">
        <li>No live consent decision or trusted user gesture is recorded by this source-only batch.</li>
        <li>No permission-status query, browser permission request, prompt, override, automatic retry, camera request, device enumeration, identifier read, or media capture is available.</li>
        <li>A future granted prompt outcome would not itself authorize capture; a further controlled capture gate would still be required.</li>
        <li>No authentication, bearer-token attachment, backend transport, protected-content access, external AI, service worker, persistent cache, native packaging, header application, or production deployment is performed.</li>
      </ul>
    </section>
  );
}
