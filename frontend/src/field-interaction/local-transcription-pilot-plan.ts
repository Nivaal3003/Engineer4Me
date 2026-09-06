/** Immutable evaluation specification, not an ASR invocation or an input-rights approval. */
import { assessmentDigest, assessmentInteger, assessmentRef, requireIssuedLocalArtifactManifest } from "./local-runtime-artifact-manifest";
import type { LocalArtifactManifest } from "./local-runtime-artifact-manifest";
export const LOCAL_PILOT_CASE_KINDS = Object.freeze(["utterance", "silence", "noise", "cancellation", "supersession"] as const);
export type LocalPilotCaseKind = typeof LOCAL_PILOT_CASE_KINDS[number];
export interface LocalPilotCase {
  readonly caseId: string; readonly inputSha256: string; readonly kind: LocalPilotCaseKind;
  readonly inputDurationMilliseconds: number; readonly referenceWordCount: number;
}
export interface LocalPilotPlan {
  readonly planRef: string; readonly manifest: LocalArtifactManifest; readonly configurationSha256: string;
  readonly language: "en"; readonly cases: readonly LocalPilotCase[];
  readonly maximumWallMilliseconds: number; readonly maximumPeakMemoryBytes: number;
  readonly maximumWordErrorRate: number; readonly inputRightsVerified: false;
  readonly runtimeIsolationVerified: false; readonly executionAuthorized: false;
}
const issued = new WeakSet<object>();
export function createLocalPilotPlan(input: {
  readonly planRef: string; readonly manifest: LocalArtifactManifest; readonly configurationSha256: string;
  readonly language: "en"; readonly cases: readonly LocalPilotCase[]; readonly maximumWallMilliseconds: number;
  readonly maximumPeakMemoryBytes: number; readonly maximumWordErrorRate: number;
}): LocalPilotPlan {
  requireIssuedLocalArtifactManifest(input.manifest);
  if (input.language !== "en") throw new Error("Initial pilot is English only, not a product language limit");
  if (!Array.isArray(input.cases) || input.cases.length < 5 || input.cases.length > 64) throw new Error("Pilot case count differs");
  const ids = new Set<string>(); const kinds = new Set<LocalPilotCaseKind>();
  const cases = input.cases.map((item) => {
    if (!item || !LOCAL_PILOT_CASE_KINDS.includes(item.kind)) throw new Error("Pilot case kind differs");
    const id = assessmentRef(item.caseId, "Case"); if (ids.has(id)) throw new Error("Duplicate case ID"); ids.add(id); kinds.add(item.kind);
    const duration = assessmentInteger(item.inputDurationMilliseconds, 250, 15_000, "Input duration");
    const words = assessmentInteger(item.referenceWordCount, 0, 256, "Reference words");
    if ((item.kind === "utterance") !== (words > 0)) throw new Error("Reference words do not match case kind");
    return Object.freeze({caseId: id, inputSha256: assessmentDigest(item.inputSha256), kind: item.kind,
      inputDurationMilliseconds: duration, referenceWordCount: words});
  });
  if (!LOCAL_PILOT_CASE_KINDS.every((kind) => kinds.has(kind))) throw new Error("Every pilot case category is required");
  if (typeof input.maximumWordErrorRate !== "number" || !Number.isFinite(input.maximumWordErrorRate) || input.maximumWordErrorRate < 0 || input.maximumWordErrorRate > 0.5) throw new Error("Pilot WER threshold differs");
  const value: LocalPilotPlan = Object.freeze({planRef: assessmentRef(input.planRef, "Plan"), manifest: input.manifest,
    configurationSha256: assessmentDigest(input.configurationSha256), language: "en", cases: Object.freeze(cases),
    maximumWallMilliseconds: assessmentInteger(input.maximumWallMilliseconds, 100, 120_000, "Wall time"),
    maximumPeakMemoryBytes: assessmentInteger(input.maximumPeakMemoryBytes, 1, 4_294_967_296, "Peak memory"),
    maximumWordErrorRate: input.maximumWordErrorRate, inputRightsVerified: false, runtimeIsolationVerified: false, executionAuthorized: false});
  issued.add(value); return value;
}
export function requireIssuedLocalPilotPlan(plan: LocalPilotPlan): void {
  if (!plan || !issued.has(plan)) throw new Error("Pilot plan was not issued here");
}
