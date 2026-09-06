/** Arithmetic over supplied evaluation records. Does not perform ASR or independently verify measurements. */
import { assessmentInteger } from "./local-runtime-artifact-manifest";
import { requireIssuedLocalPilotPlan } from "./local-transcription-pilot-plan";
import type { LocalPilotPlan } from "./local-transcription-pilot-plan";
export interface LocalPilotMeasurement {
  readonly caseId: string; readonly inputSha256: string; readonly configurationSha256: string;
  readonly wordErrors: number; readonly criticalSemanticErrors: number; readonly inventedNonSpeechWords: number;
  readonly wallMilliseconds: number; readonly peakMemoryBytes: number;
  readonly resultAdmittedAfterInvalidation: boolean; readonly rawAudioPersisted: boolean;
  readonly audioTransmitted: boolean; readonly runtimeModelDownloadAttempted: boolean;
  readonly runtimeClosed: boolean; readonly deadlineExceeded: boolean;
}
export function reviewLocalPilotMeasurements(plan: LocalPilotPlan, basis: "scripted_fixture" | "declared_measurement", reports: readonly LocalPilotMeasurement[]) {
  requireIssuedLocalPilotPlan(plan);
  if (basis !== "scripted_fixture" && basis !== "declared_measurement") throw new Error("Measurement provenance differs");
  if (!Array.isArray(reports) || reports.length > plan.cases.length) throw new Error("Measurement count differs");
  const seen = new Set<string>(); const reasons = new Set<string>(); const times: number[] = [];
  let words = 0; let errors = 0; let peakMemory = 0;
  for (const report of reports) {
    if (!report || typeof report.caseId !== "string") throw new Error("Measurement case differs");
    if (seen.has(report.caseId)) throw new Error("Duplicate measurement case"); seen.add(report.caseId);
    const item = plan.cases.find((candidate) => candidate.caseId === report.caseId);
    if (!item || report.inputSha256 !== item.inputSha256 || report.configurationSha256 !== plan.configurationSha256) throw new Error("Measurement scope identity differs");
    const errorCount = assessmentInteger(report.wordErrors, 0, 4096, "Word errors");
    const critical = assessmentInteger(report.criticalSemanticErrors, 0, 4096, "Critical errors");
    const invented = assessmentInteger(report.inventedNonSpeechWords, 0, 4096, "Invented words");
    const wall = assessmentInteger(report.wallMilliseconds, 0, 600_000, "Wall time");
    const peak = assessmentInteger(report.peakMemoryBytes, 1, 68_719_476_736, "Peak memory");
    for (const field of ["resultAdmittedAfterInvalidation", "rawAudioPersisted", "audioTransmitted", "runtimeModelDownloadAttempted", "runtimeClosed", "deadlineExceeded"] as const) {
      if (typeof report[field] !== "boolean") throw new Error("Measurement boolean differs");
    }
    if (item.kind === "utterance") { words += item.referenceWordCount; errors += errorCount; }
    else if (errorCount !== 0) throw new Error("Non-utterance WER is not defined");
    if (item.kind !== "silence" && item.kind !== "noise" && invented !== 0) throw new Error("Non-speech measure in wrong case");
    if (critical > 0) reasons.add("critical_semantic_error");
    if (invented > 0) reasons.add("invented_text_on_non_speech");
    if (report.resultAdmittedAfterInvalidation) reasons.add("invalidated_result_admitted");
    if (report.rawAudioPersisted || report.audioTransmitted) reasons.add("audio_handling_boundary_breached");
    if (report.runtimeModelDownloadAttempted) reasons.add("runtime_download_attempted");
    if (!report.runtimeClosed) reasons.add("runtime_cleanup_unproven");
    if (report.deadlineExceeded || wall > plan.maximumWallMilliseconds) reasons.add("time_budget_exceeded");
    if (peak > plan.maximumPeakMemoryBytes) reasons.add("memory_budget_exceeded");
    times.push(wall); peakMemory = Math.max(peakMemory, peak);
  }
  const wordErrorRate = words === 0 ? null : errors / words; // May exceed 1 because insertions are errors too.
  if (wordErrorRate !== null && wordErrorRate > plan.maximumWordErrorRate) reasons.add("word_error_budget_exceeded");
  times.sort((a, b) => a - b);
  const state = reasons.size > 0 ? "blocked" : reports.length === 0 ? "no_results" : reports.length !== plan.cases.length ? "incomplete"
    : basis === "scripted_fixture" ? "scripted_criteria_met_not_measurement" : "declared_criteria_met_independent_review_required";
  return Object.freeze({state, basis, completedCaseCount: reports.length, expectedCaseCount: plan.cases.length,
    missingCaseIds: Object.freeze(plan.cases.filter((item) => !seen.has(item.caseId)).map((item) => item.caseId)),
    blockingReasons: Object.freeze([...reasons].sort()), wordErrorRate,
    p95WallMilliseconds: times.length === 0 ? null : times[Math.ceil(times.length * 0.95) - 1]!,
    maximumPeakMemoryBytes: reports.length === 0 ? null : peakMemory,
    measurementsIndependentlyVerified: false, productQualified: false, deploymentApproved: false,
    executionAuthorized: false, mobilePerformanceEstablished: false, subsequentTranscriptReviewRequired: true} as const);
}
