import { describe, it, expect } from "vitest";
import { localTranscriptionAssessmentStatus } from "./inert-local-transcription-assessment";
describe("inert assessment status",()=>{
 it("records direction but exposes no install or processing action",()=>{const s=localTranscriptionAssessmentStatus();expect(s.ownerDirectionRecorded).toBe(true);expect(s.directionApprovalIsExecutionApproval).toBe(false);expect(s.downloadOperationAvailable).toBe(false);expect(s.processLaunchOperationAvailable).toBe(false);expect(s.sampleReadOperationAvailable).toBe(false);expect(s.speechOperationAvailable).toBe(false);});
 it("retains acquisition, security, rights and execution gates",()=>{expect(localTranscriptionAssessmentStatus().unresolvedGates).toHaveLength(8);expect(localTranscriptionAssessmentStatus().automaticCloudFallbackAvailable).toBe(false);});
 it("contains no callback or mutable gate array",()=>{const s=localTranscriptionAssessmentStatus();expect(Object.values(s).some(v=>typeof v==="function")).toBe(false);expect(Object.isFrozen(s.unresolvedGates)).toBe(true);});
});
