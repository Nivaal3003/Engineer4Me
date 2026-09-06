import { describe, it, expect } from "vitest";
import { LOCAL_FIRST_TRANSCRIPTION_DECISION as d, localTranscriptionFailureDisposition } from "./local-first-transcription-decision";
describe("owner local-first direction",()=>{
 it("records the selected route without granting execution",()=>{expect(d.assessmentRoute).toBe("local_only_first");expect(d.firstAssessmentCandidate).toBe("whisper.cpp");expect(d.speechExecutionAuthorized).toBe(false);expect(d.runtimeInstallationAuthorized).toBe(false);expect(d.authenticatedExecutionApproval).toBe(false);});
 it("does not infer mobile support or reuse historical speech",()=>{expect(d.mobileSupportEstablished).toBe(false);expect(d.previousLiveCheckReusableAsSpeech).toBe(false);});
 it("retains manual input without upload, queue or retry",()=>{expect(localTranscriptionFailureDisposition()).toEqual({action:"offer_manual_text",uploadAudio:false,retryAutomatically:false,retainAudioForLater:false,authority:"planning_only"});});
 it("freezes the direction and future route list",()=>{expect(Object.isFrozen(d)).toBe(true);expect(Object.isFrozen(d.optionalFutureRoutes)).toBe(true);expect(d.automaticCloudFallback).toBe(false);});
});
