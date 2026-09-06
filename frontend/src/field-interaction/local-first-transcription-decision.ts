/** Owner-selected architecture direction. This is not a runtime or permission grant. */
export const LOCAL_FIRST_TRANSCRIPTION_DECISION = Object.freeze({
  decisionId: "phase10-local-first-owner-direction-v1",
  decisionBasis: "owner_chat_approval_of_recommendation",
  assessmentRoute: "local_only_first",
  architecture: "provider_independent_local_first",
  firstAssessmentCandidate: "whisper.cpp",
  optionalFutureRoutes: Object.freeze(["customer_controlled_site", "explicitly_approved_cloud"] as const),
  automaticCloudFallback: false,
  previousLiveCheckReusableAsSpeech: false,
  authenticatedExecutionApproval: false,
  modelDownloadAuthorized: false,
  runtimeInstallationAuthorized: false,
  speechExecutionAuthorized: false,
  mobileSupportEstablished: false,
} as const);

export function localTranscriptionFailureDisposition() {
  return Object.freeze({
    action: "offer_manual_text",
    uploadAudio: false,
    retryAutomatically: false,
    retainAudioForLater: false,
    authority: "planning_only",
  } as const);
}
