import type { ProtectedCapabilityId } from "../capabilities";
import { SectionHeading, StatusBadge } from "../design-system";
import { createPermissionActivationProposal } from "./permission-activation";
import { createInertPermissionCapabilityAdapter } from "./inert-permission-adapter";
import {
  createNoPermissionPolicyEvidence,
  evaluatePermissionPrerequisites,
} from "./permission-policy";
import { evaluateUserGestureEvidence } from "./user-gesture";

function proposalFor(
  capabilityId: ProtectedCapabilityId,
  permission: "microphone" | "camera",
) {
  const capabilities = createInertPermissionCapabilityAdapter().inspectCapabilities();
  const prerequisites = evaluatePermissionPrerequisites({
    permission,
    capabilities,
    policyEvidence: createNoPermissionPolicyEvidence(),
  });
  const targetId = `${capabilityId}-${permission}-permission-control`;
  const gesture = evaluateUserGestureEvidence({
    evidence: null,
    expectedTargetId: targetId,
    referenceEpochMs: 0,
  });
  return createPermissionActivationProposal({
    proposalId: `${capabilityId}-${permission}-activation-proposal`,
    permission,
    prerequisites,
    gesture,
  });
}

export function PermissionGesturePolicyPanel({
  capabilityId,
}: {
  readonly capabilityId: ProtectedCapabilityId;
}) {
  const microphone = proposalFor(capabilityId, "microphone");
  const camera = proposalFor(capabilityId, "camera");
  const headingId = `permission-${capabilityId}-gesture-policy-heading`;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel permission-gesture-policy"
      data-activation-authorized="false"
    >
      <SectionHeading
        eyebrow="Controlled activation policy"
        headingId={headingId}
        title="User-gesture activation policy"
        description="A future permission request must be tied to a fresh, trusted, target-bound, single-use user gesture and a separately accepted intervention gate."
      />
      <div
        aria-label="User gesture policy states"
        className="permission-gesture-policy__status"
      >
        <StatusBadge tone="warning">Trusted gesture required</StatusBadge>
        <StatusBadge tone="warning">Policy evidence required</StatusBadge>
        <StatusBadge tone="warning">Intervention gate closed</StatusBadge>
      </div>
      <dl
        aria-label="Permission activation proposal states"
        className="permission-gesture-policy__summary"
      >
        <div>
          <dt>Microphone proposal</dt>
          <dd>{microphone.state}</dd>
        </div>
        <div>
          <dt>Camera proposal</dt>
          <dd>{camera.state}</dd>
        </div>
        <div>
          <dt>Gesture freshness</dt>
          <dd>Maximum 5 seconds</dd>
        </div>
        <div>
          <dt>Gesture reuse</dt>
          <dd>Single use only</dd>
        </div>
        <div>
          <dt>Prompt prepared</dt>
          <dd>No</dd>
        </div>
        <div>
          <dt>Activation authorized</dt>
          <dd>No</dd>
        </div>
      </dl>
      <div className="permission-gesture-policy__boundary">
        <p>
          This panel records policy requirements only. It has no permission-request
          operation, does not attach event listeners for capture, and cannot start a
          microphone, camera, device enumeration, retry, backend request, or external
          processing operation.
        </p>
      </div>
    </section>
  );
}
