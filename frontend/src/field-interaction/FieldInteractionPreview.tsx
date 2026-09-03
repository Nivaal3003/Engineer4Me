import type { ProtectedCapabilityId } from "../capabilities";
import { SectionHeading, StatusBadge } from "../design-system";
import { createScriptedFieldInteractionPreview } from "./scripted-adapter";

function readableIntent(value: string): string {
  return value.replaceAll("_", " ");
}

export function FieldInteractionPreview({
  capabilityId,
}: {
  readonly capabilityId: ProtectedCapabilityId;
}) {
  const preview = createScriptedFieldInteractionPreview(capabilityId);
  const headingId = `field-interaction-${capabilityId}-preview-heading`;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel field-interaction-preview"
      data-source-mode={preview.mode}
    >
      <SectionHeading
        eyebrow="Scripted in-memory demonstration"
        headingId={headingId}
        title="Field interaction review preview"
        description="A deterministic fixture demonstrates transcript, multimodal metadata, privacy, provenance, and review contracts without live capture."
      />
      <div
        aria-label="Field interaction preview state"
        className="field-interaction-preview__summary"
      >
        <div>
          <span className="data-label">Source mode</span>
          <strong>Scripted in memory</strong>
        </div>
        <div>
          <span className="data-label">Intent</span>
          <strong>{readableIntent(preview.proposal.intentKind)}</strong>
        </div>
        <div>
          <span className="data-label">Review</span>
          <StatusBadge tone="warning">Review required</StatusBadge>
        </div>
        <div>
          <span className="data-label">Operation</span>
          <strong>No operation selected</strong>
        </div>
      </div>
      <blockquote className="field-interaction-preview__transcript">
        <p>{preview.transcript.text}</p>
        <cite>Scripted transcript; no audio captured</cite>
      </blockquote>
      <div className="field-interaction-preview__grid">
        <div>
          <h3>Metadata-only multimodal descriptors</h3>
          <ul>
            {preview.sources.slice(1).map((source) => (
              <li key={source.sourceId}>
                <strong>{source.label}</strong>
                <span>{source.mediaType}</span>
                <span>Raw content unavailable</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h3>Privacy and provenance</h3>
          <ul>
            <li>Classification: {preview.privacy.classification}</li>
            <li>Retention: {preview.privacy.retentionMode}</li>
            <li>External processing allowed: no</li>
            <li>Provenance records: {preview.provenance.length}</li>
          </ul>
        </div>
      </div>
      <div className="field-interaction-preview__boundary">
        <p>
          No backend request, bearer-token attachment, protected-content read,
          engineering approval, operational authorization, or command execution
          has occurred.
        </p>
      </div>
    </section>
  );
}
