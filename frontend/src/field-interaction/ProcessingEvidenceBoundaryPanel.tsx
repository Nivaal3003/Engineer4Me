import { createInertProcessingEvidenceStatus } from "./inert-processing-evidence-status";
export function ProcessingEvidenceBoundaryPanel() {
  const status = createInertProcessingEvidenceStatus();
  return <section className="processing-evidence-boundary" aria-labelledby="processing-evidence-boundary-heading">
    <h2 id="processing-evidence-boundary-heading">Processing evidence and scope boundary</h2>
    <p>No processing candidate is configured or selected. Declared review references do not verify their contents or authenticate a reviewer.</p>
    <p>Changing the processing revision, deployment, data location, retention policy, language or purpose requires a new dossier revision and fresh planning declarations.</p>
    <p>Revoked, expired or superseded declarations cannot support a current planning ticket. Simulated expiry is not a live deadline guarantee.</p>
    <p>Even complete planning declarations leave transcription, new media access and execution disabled. Provider selection, independent evidence validation, fresh consent and explicit execution approval remain separate gates.</p>
    <dl><dt>Required review categories</dt><dd>{status.requiredReviewCategories.length}</dd>
      <dt>Evidence content verified</dt><dd>No</dd><dt>Execution authorized</dt><dd>No</dd></dl>
  </section>;
}
