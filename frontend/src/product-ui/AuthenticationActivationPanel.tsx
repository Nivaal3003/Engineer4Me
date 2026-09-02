import { StatusBadge } from "../design-system";

export interface AuthenticationActivationPanelProps {
  readonly sourceReady: boolean;
  readonly interactiveExecutionReady: boolean;
  readonly missingGateLabels: readonly string[];
  readonly safeSummary: string;
}

export function AuthenticationActivationPanel({
  sourceReady,
  interactiveExecutionReady,
  missingGateLabels,
  safeSummary,
}: AuthenticationActivationPanelProps) {
  return (
    <section className="activation-panel" aria-labelledby="authentication-activation-heading">
      <div className="activation-panel__heading">
        <div>
          <p className="eyebrow">Activation readiness</p>
          <h2 id="authentication-activation-heading">Identity-provider activation gate</h2>
        </div>
        <StatusBadge tone={interactiveExecutionReady ? "positive" : "warning"}>
          {interactiveExecutionReady ? "Ready, inactive" : "Blocked"}
        </StatusBadge>
      </div>
      <p>{safeSummary}</p>
      <dl className="activation-panel__summary">
        <div><dt>Source readiness</dt><dd>{sourceReady ? "Ready" : "Blocked"}</dd></div>
        <div><dt>Interactive execution</dt><dd>{interactiveExecutionReady ? "Explicit action required" : "Not authorized"}</dd></div>
      </dl>
      {missingGateLabels.length > 0 ? (
        <ul className="activation-panel__gates">
          {missingGateLabels.map((gate) => <li key={gate}>{gate}</li>)}
        </ul>
      ) : null}
      <p className="activation-panel__boundary">
        No automatic sign-in, redirect handling, token acquisition, or identity-provider request is performed by this view.
      </p>
    </section>
  );
}
