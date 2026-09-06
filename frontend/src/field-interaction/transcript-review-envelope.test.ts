import { describe, expect, it } from "vitest";
import { createTranscriptReviewEnvelope, assertIssuedTranscriptEnvelope } from "./transcript-review-envelope";
const input = () => ({ transcriptId: "test.envelope", sourceId: "manual.1", origin: "manual_text", languageTag: "en-ZA",
  text: "Do NOT change P-101.\nSetpoint = 10.5 kPa; not 105 kPa.", revision: 1, attachments: [] });
describe("bounded review envelope", () => {
  it("preserves exact engineering text, provenance, and immutable declared metadata", () => {
    const raw = input();
    const e = createTranscriptReviewEnvelope(raw);
    expect(e.text).toBe(raw.text); expect(e.confidence).toBe(null);
    expect(e.liveAudioProcessedByThisModule).toBe(false); expect(e.originVerified).toBe(false); expect(e.attachmentContentVerified).toBe(false);
    expect(Object.isFrozen(e)).toBe(true); expect(Object.isFrozen(e.attachments)).toBe(true);
    assertIssuedTranscriptEnvelope(e);
    expect(() => assertIssuedTranscriptEnvelope({ ...e })).toThrow(/issued/i);
  });
  it("rejects unsupported origins, injected fields, overlong text and misleading controls", () => {
    for (const patch of [{ origin: "live_transcript" }, { text: " " }, { text: "x".repeat(4097) },
      { text: "open\u202e valve" }, { revision: 0 }, { revision: NaN }, { transcriptId: "test.bad\n" }, { languageTag: "en\n" }, { rawAudio: "base64" }]) {
      expect(() => createTranscriptReviewEnvelope({ ...input(), ...patch })).toThrow();
    }
  });
  it("bounds attachment identities and distinguishes declarations from verified content", () => {
    const a = { sourceId: "drawing.1", revision: "R2", declaredSha256: "a".repeat(64) };
    const e = createTranscriptReviewEnvelope({ ...input(), attachments: [a] });
    a.revision = "R3"; expect(e.attachments[0]?.revision).toBe("R2");
    expect(() => createTranscriptReviewEnvelope({ ...input(), attachments: [a, a] })).toThrow(/duplicate/i);
    expect(() => createTranscriptReviewEnvelope({ ...input(), attachments: [{ ...a, content: "hidden" }] })).toThrow(/inventory/i);
    expect(() => createTranscriptReviewEnvelope({ ...input(), attachments: Array(9).fill(a) })).toThrow(/eight/i);
  });
});
