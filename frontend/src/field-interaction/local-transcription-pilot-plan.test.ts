import { describe, it, expect } from "vitest";
import { requireIssuedLocalPilotPlan } from "./local-transcription-pilot-plan";
import { createLocalArtifactManifest, LOCAL_ARTIFACT_ROLES } from "./local-runtime-artifact-manifest";
const D = "ab".repeat(32);
function manifestInput() { return {manifestRef:"assessment-1", engineCommit:"ab".repeat(20), modelRef:"base.en-candidate", platformRef:"cpu-reference-unqualified",
  artifacts: LOCAL_ARTIFACT_ROLES.map((role) => ({role, artifactRef:role+"-artifact", revision:"review-1", sha256:D, bytes:1024}))}; }
import { createLocalPilotPlan } from "./local-transcription-pilot-plan";
import type { LocalPilotCase } from "./local-transcription-pilot-plan";
function pilotInput() { return {planRef:"pilot-1", manifest:createLocalArtifactManifest(manifestInput()), configurationSha256:D, language:"en" as const,
  cases: (["utterance","silence","noise","cancellation","supersession"] as const).map((kind):LocalPilotCase=>({caseId:kind+"-1",kind,inputSha256:D,inputDurationMilliseconds:1000,referenceWordCount:kind==="utterance"?10:0})),
  maximumWallMilliseconds:2000, maximumPeakMemoryBytes:1_073_741_824, maximumWordErrorRate:0.1}; }
describe("local pilot specification",()=>{
 it("requires all five test categories and has no execution authority",()=>{const p=createLocalPilotPlan(pilotInput());expect(p.cases).toHaveLength(5);expect(p.executionAuthorized).toBe(false);expect(p.inputRightsVerified).toBe(false);expect(p.runtimeIsolationVerified).toBe(false);});
 it("rejects missing cancellation coverage",()=>{const i=pilotInput();i.cases[3]={...i.cases[3]!,kind:"noise"};expect(()=>createLocalPilotPlan(i)).toThrow(/category/i);});
 it("rejects duplicate case identifiers",()=>{const i=pilotInput();i.cases[1]={...i.cases[1]!,caseId:i.cases[0]!.caseId};expect(()=>createLocalPilotPlan(i)).toThrow(/duplicate/i);});
 it("requires meaningful utterance reference words",()=>{const i=pilotInput();i.cases[0]={...i.cases[0]!,referenceWordCount:0};expect(()=>createLocalPilotPlan(i)).toThrow(/reference/i);});
 it("rejects out-of-scope input duration",()=>{const i=pilotInput();i.cases[0]={...i.cases[0]!,inputDurationMilliseconds:15001};expect(()=>createLocalPilotPlan(i)).toThrow(/duration/i);});
 it("rejects invalid WER and budget thresholds",()=>{expect(()=>createLocalPilotPlan({...pilotInput(),maximumWordErrorRate:NaN})).toThrow(/WER/i);expect(()=>createLocalPilotPlan({...pilotInput(),maximumWallMilliseconds:0})).toThrow(/bound/i);});
 it("requires declared configuration digest and initial language",()=>{expect(()=>createLocalPilotPlan({...pilotInput(),configurationSha256:"main"})).toThrow(/digest/i);expect(()=>createLocalPilotPlan({...pilotInput(),language:"auto" as "en"})).toThrow(/English/i);});
 it("rejects copied manifest or copied plan",()=>{const i=pilotInput();expect(()=>createLocalPilotPlan({...i,manifest:{...i.manifest}})).toThrow(/issued/i);const p=createLocalPilotPlan(i);expect(()=>requireIssuedLocalPilotPlan({...p})).toThrow(/issued/i);});
 it("defensively snapshots cases",()=>{const i=pilotInput();const p=createLocalPilotPlan(i);i.cases[0]={...i.cases[0]!,caseId:"changed"};expect(p.cases[0]!.caseId).toBe("utterance-1");expect(Object.isFrozen(p.cases)).toBe(true);});
});
