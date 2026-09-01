import type { ProductBoundary } from "../foundation";
import { SectionHeading, StatusBadge, type StatusTone } from "../design-system";

const TONES: Readonly<Record<ProductBoundary["disposition"], StatusTone>> = {
  required: "information",
  inactive: "neutral",
  blocked: "warning",
  deferred: "neutral",
};

export interface BoundaryNoticeProps {
  readonly boundaries: readonly ProductBoundary[];
}

function boundaryTitle(id: string): string {
  return id
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function BoundaryNotice({ boundaries }: BoundaryNoticeProps) {
  return (
    <section className="content-panel boundary-notice" aria-labelledby="boundary-heading">
      <SectionHeading
        eyebrow="Controlled boundaries"
        headingId="boundary-heading"
        title="Decision support without hidden claims"
        description="Product safeguards remain visible before engineering capability integration."
      />
      <ul className="boundary-list">
        {boundaries.map((boundary) => (
          <li key={boundary.id}>
            <div className="boundary-list__heading">
              <strong>{boundaryTitle(boundary.id)}</strong>
              <StatusBadge tone={TONES[boundary.disposition]}>
                {boundary.disposition}
              </StatusBadge>
            </div>
            <p>{boundary.rationale}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
