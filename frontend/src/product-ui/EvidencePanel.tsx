import type { EngineeringEvidenceViewModel } from "../foundation";
import { SectionHeading, StatusBadge } from "../design-system";

export interface EvidencePanelProps {
  readonly model: EngineeringEvidenceViewModel;
}

function TextList({ label, values }: { readonly label: string; readonly values: readonly string[] }) {
  return (
    <div className="evidence-panel__list">
      <h3>{label}</h3>
      {values.length > 0 ? (
        <ul>
          {values.map((value) => (
            <li key={value}>{value}</li>
          ))}
        </ul>
      ) : (
        <p>None recorded for this inactive shell state.</p>
      )}
    </div>
  );
}

export function EvidencePanel({ model }: EvidencePanelProps) {
  return (
    <section className="content-panel evidence-panel" aria-labelledby="evidence-heading">
      <SectionHeading
        eyebrow="Evidence control"
        headingId="evidence-heading"
        title="Evidence remains visible at the decision boundary"
        description="This shell does not invent evidence or imply an approved engineering result."
      />
      <div className="evidence-panel__summary">
        <div>
          <span className="data-label">Confidence</span>
          <StatusBadge tone="information">{model.confidence.level}</StatusBadge>
        </div>
        <div>
          <span className="data-label">Revision</span>
          <strong>{model.revision.revision}</strong>
        </div>
        <div>
          <span className="data-label">Approval status</span>
          <strong>{model.revision.status.replaceAll("_", " ")}</strong>
        </div>
      </div>
      <div className="evidence-panel__grid">
        <TextList label="Evidence references" values={model.evidence.map((item) => item.title)} />
        <TextList label="Assumptions" values={model.assumptions} />
        <TextList label="Limitations" values={model.limitations} />
        <TextList label="Warnings" values={model.warnings} />
      </div>
      <div className="evidence-panel__ownership">
        <p><strong>No standards conformity claim</strong> is made by this interface.</p>
        <p>Final engineering approval remains with the user or authorized organisation.</p>
      </div>
    </section>
  );
}
