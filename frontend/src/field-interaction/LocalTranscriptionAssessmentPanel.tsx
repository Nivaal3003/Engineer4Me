import { localTranscriptionAssessmentStatus } from "./inert-local-transcription-assessment";
export function LocalTranscriptionAssessmentPanel() {
  const status = localTranscriptionAssessmentStatus();
  return (
    <section className="local-transcription-assessment-panel" aria-labelledby="local-transcription-assessment-heading">
      <h2 id="local-transcription-assessment-heading">Local-first transcription assessment</h2>
      <p>Local-only assessment is selected. The first candidate is {status.firstCandidate}; no engine or model is installed by this step.</p>
      <p>Artifact identifiers and supplied measurements are declarations, not independently verified runtime evidence. A passing scripted check is not measured speech accuracy.</p>
      <p>Desktop, on-device mobile, browser and customer-site processing require separate qualification. Manual text remains the alternative; audio is never automatically sent to a cloud service.</p>
      <p>Downloads, installation, microphone input, speech processing and deployment remain separately gated. Every future transcript requires fresh review before downstream action.</p>
    </section>
  );
}
