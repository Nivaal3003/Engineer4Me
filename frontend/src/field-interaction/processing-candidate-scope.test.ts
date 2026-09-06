import { describe, expect, it } from "vitest";
import { assertIssuedProcessingCandidateScope, createProcessingCandidateScope } from "./processing-candidate-scope";
const input = () => ({ dossierId: "candidate-one", revision: 1, mode: "local_only_candidate", processingRef: "reviewed-engine-ref", processingRevision: "revision-one", processingRevisionSha256: "a".repeat(64), deploymentRef: "local-evaluation", dataLocationRef: "declared-device-only", retentionPolicySha256: "b".repeat(64), languageTag: "en-ZA", purpose: "transcription_evaluation_only" });
describe("processing candidate scope declarations", () => {
  it("preserves exact bounded metadata without selecting or verifying a provider", () => {
    const source = input(), value = createProcessingCandidateScope(source); source.languageTag = "fr";
    expect(value.languageTag).toBe("en-ZA"); expect(Object.isFrozen(value)).toBe(true);
    expect(value.providerSelectedByApplication).toBe(false); expect(value.artifactBytesVerified).toBe(false); expect(value.executionAuthorized).toBe(false);
    expect(() => assertIssuedProcessingCandidateScope(value)).not.toThrow();
  });
  it("allows an external candidate declaration without an endpoint or network capability", () => {
    const value = createProcessingCandidateScope({ ...input(), mode: "external_service_candidate" });
    expect(value.mode).toBe("external_service_candidate"); expect(value.executionAuthorized).toBe(false);
    expect("endpoint" in value).toBe(false);
  });
  it("rejects copies of issued scopes", () => {
    const value = createProcessingCandidateScope(input()); expect(() => assertIssuedProcessingCandidateScope({ ...value })).toThrow(/not issued/);
  });
  it("rejects accessor input without invoking the getter", () => {
    const source = input(); let calls = 0; Object.defineProperty(source, "processingRef", { enumerable: true, get() { calls += 1; return "hidden"; } });
    expect(() => createProcessingCandidateScope(source)).toThrow(/data fields/); expect(calls).toBe(0);
  });
  it("rejects extra symbols, hidden fields and inherited fields", () => {
    expect(() => createProcessingCandidateScope({ ...input(), [Symbol("hidden")]: 1 })).toThrow(/inventory/);
    const hidden = input(); Object.defineProperty(hidden, "extra", { value: 1 }); expect(() => createProcessingCandidateScope(hidden)).toThrow(/inventory/);
    expect(() => createProcessingCandidateScope(Object.create(input()))).toThrow(/prototype/);
  });
  it("rejects malformed metadata instead of normalizing it", () => {
    for (const change of [{ mode: "auto_select" }, { purpose: "execute_command" }, { revision: 0 }, { revision: 1.1 }, { revision: NaN }, { dossierId: " candidate-one" }, { processingRevisionSha256: "A".repeat(64) }, { retentionPolicySha256: "short" }, { languageTag: "en ZA" }, { languageTag: "en-" + "12345678-".repeat(10) + "xx" }]) {
      expect(() => createProcessingCandidateScope({ ...input(), ...change })).toThrow();
    }
  });
});
