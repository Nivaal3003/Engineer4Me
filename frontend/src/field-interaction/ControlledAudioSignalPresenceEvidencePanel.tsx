export interface ControlledAudioSignalPresenceEvidencePanelProps {
  readonly acceptedOutcome?: "signal_present" | "signal_absent" | "not_executed";
}

export function ControlledAudioSignalPresenceEvidencePanel({
  acceptedOutcome = "not_executed",
}: ControlledAudioSignalPresenceEvidencePanelProps) {
  const outcomeLabel = acceptedOutcome === "signal_present"
    ? "Local signal detected"
    : acceptedOutcome === "signal_absent"
      ? "No local signal detected"
      : "Execution evidence not yet accepted";

  return (
    <section
      aria-labelledby="controlled-signal-presence-heading"
      aria-label="Controlled local signal presence evidence"
      className="controlled-signal-presence-evidence"
    >
      <header>
        <p className="eyebrow">Phase 10 controlled evidence</p>
        <h2 id="controlled-signal-presence-heading">
          Local microphone signal-presence boundary
        </h2>
      </header>
      <p className="controlled-signal-presence-evidence__boundary">
        The application exposes no microphone or sample operation. A separate
        verifier checkpoint may retain only a boolean signal-present or
        signal-absent result after immediate in-memory buffer clearing and
        source teardown.
      </p>
      <dl>
        <dt>Accepted outcome</dt>
        <dd>{outcomeLabel}</dd>
        <dt>Maximum frame</dt>
        <dd>2,048 mono floating-point samples</dd>
        <dt>Maximum transient sample bytes</dt>
        <dd>8,192 bytes</dd>
        <dt>Numeric amplitude retained</dt>
        <dd>No</dd>
        <dt>Waveform retained</dt>
        <dd>No</dd>
        <dt>Recording, persistence, or transmission</dt>
        <dd>Not available</dd>
        <dt>Further voice interpretation</dt>
        <dd>Separate intervention and evidence required</dd>
      </dl>
    </section>
  );
}
