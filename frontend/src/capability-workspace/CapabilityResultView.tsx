import { SectionHeading, StatusBadge } from "../design-system";
import type { CapabilityWorkspaceResult } from "../capabilities";
import { createCapabilityResultViewModel } from "./models";

function ControlledList({
  title,
  values,
  emptyLabel,
}: {
  readonly title: string;
  readonly values: readonly string[];
  readonly emptyLabel: string;
}) {
  return (
    <div className="capability-result-view__list">
      <h3>{title}</h3>
      {values.length > 0 ? (
        <ul>{values.map((value) => <li key={value}>{value}</li>)}</ul>
      ) : (
        <p>{emptyLabel}</p>
      )}
    </div>
  );
}

export function CapabilityResultView({
  result,
}: {
  readonly result: CapabilityWorkspaceResult;
}) {
  const model = createCapabilityResultViewModel(result);
  const headingId = `capability-result-${model.capabilityId}-heading`;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel capability-result-view"
      data-source-mode={model.sourceMode}
    >
      <SectionHeading
        eyebrow="In-memory contract demonstration"
        headingId={headingId}
        title={model.title}
        description={model.summary}
      />
      <div className="capability-result-view__summary">
        <div><span className="data-label">State</span><StatusBadge tone={model.state === "degraded" ? "warning" : "information"}>{model.state}</StatusBadge></div>
        <div><span className="data-label">Items</span><strong>{model.itemCountLabel}</strong></div>
        <div><span className="data-label">Confidence</span><strong>{model.confidenceLabel}</strong></div>
        <div><span className="data-label">Revision</span><strong>{model.revision}</strong></div>
        <div><span className="data-label">Approval</span><strong>{model.approvalStatusLabel}</strong></div>
      </div>
      <div className="capability-result-view__evidence">
        <h3>Evidence references</h3>
        <ol>
          {model.evidence.map((item) => (
            <li key={item.sourceId}>
              <strong>{item.title}</strong>
              <span>Revision: {item.revisionLabel}</span>
              <span>Locator: {item.locatorLabel}</span>
            </li>
          ))}
        </ol>
      </div>
      <div className="capability-result-view__grid">
        <ControlledList title="Assumptions" values={model.assumptions} emptyLabel="No assumptions recorded." />
        <ControlledList title="Limitations" values={model.limitations} emptyLabel="No limitations recorded." />
        <ControlledList title="Warnings" values={model.warnings} emptyLabel="No warnings recorded." />
      </div>
      <div className="capability-result-view__boundaries">
        <p>{model.vendorNeutralityLabel}</p>
        <p>{model.standardsBoundaryLabel}</p>
        <p>{model.proprietaryBoundaryLabel}</p>
        <p>{model.engineeringApprovalLabel}</p>
        <p>{model.operationalAuthorizationLabel}</p>
        <p><strong>Live transport remains inactive.</strong></p>
      </div>
    </section>
  );
}
