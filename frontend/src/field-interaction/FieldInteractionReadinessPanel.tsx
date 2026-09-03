import type { ProtectedCapabilityId } from "../capabilities";
import { SectionHeading, StatusBadge } from "../design-system";
import { createFieldInteractionPermissionSnapshot } from "./permissions";

export function FieldInteractionReadinessPanel({
  capabilityId,
}: {
  readonly capabilityId: ProtectedCapabilityId;
}) {
  const permissions = createFieldInteractionPermissionSnapshot();
  const headingId = `field-interaction-${capabilityId}-readiness-heading`;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel field-interaction-readiness"
      data-activation-state="inactive"
    >
      <SectionHeading
        eyebrow="Phase 10 field interaction"
        headingId={headingId}
        title="Voice and multimodal readiness"
        description="Source contracts are available for controlled review, while live capture and external processing remain inactive."
      />
      <div
        aria-label="Field interaction activation states"
        className="field-interaction-readiness__status"
      >
        <StatusBadge tone="information">Source contracts ready</StatusBadge>
        <StatusBadge tone="warning">Microphone inactive</StatusBadge>
        <StatusBadge tone="warning">Camera inactive</StatusBadge>
        <StatusBadge tone="warning">External AI inactive</StatusBadge>
      </div>
      <dl
        aria-label="Permission readiness"
        className="field-interaction-readiness__summary"
      >
        <div>
          <dt>Microphone</dt>
          <dd>{permissions.microphone.state}</dd>
        </div>
        <div>
          <dt>Camera</dt>
          <dd>{permissions.camera.state}</dd>
        </div>
        <div>
          <dt>Live capture</dt>
          <dd>Not active</dd>
        </div>
        <div>
          <dt>Retention</dt>
          <dd>Memory only</dd>
        </div>
      </dl>
      <ul className="field-interaction-readiness__boundaries">
        <li>No browser permission API or permission prompt has been invoked.</li>
        <li>No audio, image, document bytes, or protected content have been loaded.</li>
        <li>No external speech, vision, OCR, or AI service has been contacted.</li>
        <li>Every proposed query or command remains subject to explicit user review.</li>
      </ul>
    </section>
  );
}
