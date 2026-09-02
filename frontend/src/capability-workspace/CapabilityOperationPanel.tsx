import { SectionHeading, StatusBadge } from "../design-system";
import type { ProtectedCapabilityId } from "../capabilities";
import {
  createCapabilityOperationCatalogue,
  type CapabilityOperationViewModel,
} from "./operations";
import { getCapabilityVerticalSlice } from "./vertical-slices";

function OperationSummary({
  label,
  operation,
}: {
  readonly label: string;
  readonly operation: CapabilityOperationViewModel | null;
}) {
  return (
    <div className="capability-operation-panel__operation">
      <span className="data-label">{label}</span>
      {operation ? (
        <>
          <strong>{operation.method} {operation.pathTemplate}</strong>
          <span>{operation.responseModelLabel}</span>
          <code>{operation.operationKey}</code>
        </>
      ) : (
        <span>No accepted operation</span>
      )}
    </div>
  );
}

export function CapabilityOperationPanel({
  capabilityId,
}: {
  readonly capabilityId: ProtectedCapabilityId;
}) {
  const catalogue = createCapabilityOperationCatalogue(capabilityId);
  const verticalSlice = getCapabilityVerticalSlice(capabilityId);
  const headingId = `capability-operation-${capabilityId}-heading`;
  return (
    <section
      aria-labelledby={headingId}
      className="content-panel capability-operation-panel"
    >
      <SectionHeading
        eyebrow="Capability readiness"
        headingId={headingId}
        title="Capability operation readiness"
        description={verticalSlice.purpose}
      />
      <div className="capability-operation-panel__counts" aria-label="Accepted operation counts">
        <div><span className="data-label">Total</span><strong>{catalogue.totalOperationCount}</strong></div>
        <div><span className="data-label">Queries</span><strong>{catalogue.queryOperationCount}</strong></div>
        <div><span className="data-label">Commands</span><strong>{catalogue.commandOperationCount}</strong></div>
      </div>
      <div className="capability-operation-panel__status">
        <StatusBadge tone={catalogue.totalOperationCount > 0 ? "information" : "warning"}>
          {catalogue.totalOperationCount > 0 ? "In-memory contract ready" : "Unavailable"}
        </StatusBadge>
        <span>Live transport inactive</span>
        <span>Protected content not loaded</span>
      </div>
      <div className="capability-operation-panel__grid">
        <OperationSummary label="Representative query" operation={catalogue.representativeQuery} />
        <OperationSummary label="Representative command" operation={catalogue.representativeCommand} />
      </div>
      <ul className="capability-operation-panel__boundaries">
        <li>Query previews do not authorize execution.</li>
        <li>Commands require explicit user or authorized-organisation approval.</li>
        <li>No automatic retry, best-brand selection, or standards conformity claim is enabled.</li>
      </ul>
    </section>
  );
}
