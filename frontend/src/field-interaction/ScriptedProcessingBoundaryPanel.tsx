import { createInertScriptedProcessingStatus } from "./inert-scripted-processing-status";
export function ScriptedProcessingBoundaryPanel() {
  const status = createInertScriptedProcessingStatus();
  return (
    <section className="scripted-processing-boundary" aria-labelledby="scripted-processing-boundary-heading">
      <h2 id="scripted-processing-boundary-heading">Scripted processing lifecycle boundary</h2>
      <p>Only declared scripted text fixtures can be simulated. No microphone, speech service, or background worker is available.</p>
      <dl>
        <dt>Context binding</dt><dd>Exact current reviewed text and attachment revision</dd>
        <dt>Cancelled, expired or superseded jobs</dt><dd>Result admission blocked; prior output cannot restore approval</dd>
        <dt>Accepted scripted result</dt><dd>Separate draft review required; never automatic execution</dd>
        <dt>Active job limit per simulation controller</dt><dd>{status.limits.maximumActiveJobs}</dd>
        <dt>Processing activation</dt><dd>Closed pending provider evidence and separate authorization</dd>
      </dl>
      <p>Simulation ticks are caller-supplied test data, not a live deadline guarantee. Releasing owned references does not erase caller-held copies.</p>
    </section>
  );
}
