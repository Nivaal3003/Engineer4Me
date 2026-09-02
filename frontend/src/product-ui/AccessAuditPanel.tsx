import { StatusBadge, type StatusTone } from "../design-system";

export interface AccessAuditPresentationRecord {
  readonly eventId: string;
  readonly occurredAt: string;
  readonly category: string;
  readonly outcome: "success" | "blocked" | "denied" | "error";
  readonly summary: string;
}

export interface AccessAuditPanelProps {
  readonly records: readonly AccessAuditPresentationRecord[];
}

const OUTCOME_TONES: Record<AccessAuditPresentationRecord["outcome"], StatusTone> = {
  success: "positive",
  blocked: "warning",
  denied: "critical",
  error: "critical",
};

export function AccessAuditPanel({ records }: AccessAuditPanelProps) {
  return (
    <section className="access-audit-panel" aria-labelledby="access-audit-heading">
      <div className="access-audit-panel__heading">
        <div>
          <p className="eyebrow">Audit readiness</p>
          <h2 id="access-audit-heading">Controlled authentication audit evidence</h2>
        </div>
        <StatusBadge tone="neutral">Local and bounded</StatusBadge>
      </div>
      {records.length === 0 ? (
        <div className="access-audit-panel__empty">
          <strong>No remote audit records loaded</strong>
          <p>
            The source model provides redacted, bounded in-memory evidence only. No audit API,
            browser persistence, Graph request, or identity-provider operation is active.
          </p>
        </div>
      ) : (
        <ol className="access-audit-panel__list">
          {records.map((record) => (
            <li key={record.eventId}>
              <div>
                <strong>{record.summary}</strong>
                <span>{record.category} · {record.occurredAt}</span>
              </div>
              <StatusBadge tone={OUTCOME_TONES[record.outcome]}>{record.outcome}</StatusBadge>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
