import { createInertTranscriptProcessingAdapter } from "./inert-transcript-processing-adapter";
export function TranscriptReviewBoundaryPanel() {
  const adapter = createInertTranscriptProcessingAdapter();
  return (
    <section className="transcript-review-boundary" aria-labelledby="transcript-review-boundary-heading">
      <h2 id="transcript-review-boundary-heading">Transcript provenance and revision review</h2>
      <p>Manual or scripted text can be reviewed in memory. No live transcription is available.</p>
      <p>A signal-presence result contains no words. It does not establish microphone failure, speech absence, or permission for another capture.</p>
      <dl>
        <dt>Review scope</dt><dd>Current text revision and declared attachment references only</dd>
        <dt>Approved review outcome</dt><dd>Local preview only; not engineering or operational approval</dd>
        <dt>Processing evidence still required</dt><dd>{adapter.readiness.missingGates.length} separate evidence gates</dd>
        <dt>Speech processing and action execution</dt><dd>Closed pending separate reviewed authorization</dd>
      </dl>
      <p>No microphone retry, provider selection, speech processing, backend request, or protected-content read is available here.</p>
    </section>
  );
}
