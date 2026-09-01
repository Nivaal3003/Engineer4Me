import type { ReactNode } from "react";
import { Button, StatusBadge, type StatusTone } from "../design-system";
import type { StateExperienceModel } from "./models";

export interface StateExperienceProps {
  readonly model: StateExperienceModel;
  readonly action?: ReactNode;
  readonly onRetry?: () => void;
}

const STATE_TONES: Readonly<Record<StateExperienceModel["kind"], StatusTone>> =
  Object.freeze({
    loading: "information",
    empty: "neutral",
    error: "critical",
    degraded: "warning",
    unavailable: "warning",
    not_found: "neutral",
  });

export function StateExperience({ model, action, onRetry }: StateExperienceProps) {
  const headingId = `state-experience-${model.kind}-heading`;
  const liveRole: "alert" | "status" | "region" =
    model.kind === "error"
      ? "alert"
      : model.kind === "loading" || model.kind === "degraded"
        ? "status"
        : "region";

  return (
    <section
      aria-labelledby={headingId}
      className={`state-experience state-experience--${model.kind}`}
      role={liveRole}
    >
      <div className="state-experience__heading">
        <div>
          <p className="eyebrow">{model.eyebrow}</p>
          <h1 id={headingId}>{model.title}</h1>
        </div>
        <StatusBadge tone={STATE_TONES[model.kind]}>{model.kind.replace("_", " ")}</StatusBadge>
      </div>

      {model.kind === "loading" ? (
        <span aria-label="Loading requested view" className="state-experience__progress" role="progressbar" />
      ) : null}

      <p className="state-experience__detail">{model.detail}</p>

      {model.guidance.length > 0 ? (
        <ul className="state-experience__guidance">
          {model.guidance.map((item) => <li key={item}>{item}</li>)}
        </ul>
      ) : null}

      {model.correlationId ? (
        <p className="state-experience__correlation">
          <span className="data-label">Correlation ID</span>
          <code>{model.correlationId}</code>
        </p>
      ) : null}

      {action || (model.retryAuthorized && onRetry) ? (
        <div className="state-experience__actions">
          {action}
          {model.retryAuthorized && onRetry ? (
            <Button onClick={onRetry}>Retry controlled request</Button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
