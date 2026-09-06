import { describe, expect, it } from "vitest";
import { createScriptedTranscriptFixture, assertIssuedScriptedTranscriptFixture } from "./scripted-transcript-fixture";
const base = { fixtureId: "fixture535", languageTag: "en-ZA", text: "Do NOT change 4.5 bar.\n<script>not code</script>" };
describe("scripted text fixture provenance", () => {
  it("preserves exact text without claiming transcription or confidence", () => {
    const f = createScriptedTranscriptFixture(base);
    expect(f.text).toBe(base.text); expect(f.provenance).toBe("scripted_fixture");
    expect(f.speechToTextPerformed).toBe(false); expect(f.confidence).toBeNull(); expect(Object.isFrozen(f)).toBe(true);
    expect(() => assertIssuedScriptedTranscriptFixture(f)).not.toThrow();
    expect(() => assertIssuedScriptedTranscriptFixture({ ...f })).toThrow(/issued/i);
  });
  it("enforces text, identifier, language and exact metadata bounds", () => {
    for (const bad of [null, [], { ...base, text: "" }, { ...base, text: "x".repeat(4097) },
      { ...base, text: "bad\u0000" }, { ...base, fixtureId: " INVALID" }, { ...base, languageTag: "en_ZA" },
      { ...base, provider: "real" }, { ...base, [Symbol("hidden")]: "bad" }]) {
      expect(() => createScriptedTranscriptFixture(bad)).toThrow();
    }
    expect(createScriptedTranscriptFixture({ ...base, text: "x".repeat(4096) }).text.length).toBe(4096);
  });
  it("rejects accessors without calling the text getter", () => {
    let calls = 0;
    const bad = { fixtureId: "fixture535", languageTag: "en", get text() { calls += 1; return "secret"; } };
    expect(() => createScriptedTranscriptFixture(bad)).toThrow(/data fields/i); expect(calls).toBe(0);
  });
  it("rejects custom inherited fields", () => {
    expect(() => createScriptedTranscriptFixture(Object.assign(Object.create({ provider: true }), base))).toThrow(/prototype/i);
  });
});
