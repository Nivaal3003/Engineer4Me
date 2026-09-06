import { createTranscriptReviewEnvelope } from "./transcript-review-envelope";
import { scriptedFixtureData } from "./scripted-processing-policy";
export interface ScriptedTranscriptFixture {
  readonly fixtureId: string;
  readonly text: string;
  readonly languageTag: string;
  readonly provenance: "scripted_fixture";
  readonly speechToTextPerformed: false;
  readonly confidence: null;
}
const issuedFixtures = new WeakSet<object>();
/** Caller-provided text is a declared fixture, never an output from an actual provider. */
export function createScriptedTranscriptFixture(input: unknown): ScriptedTranscriptFixture {
  const value = scriptedFixtureData(input);
  const checked = createTranscriptReviewEnvelope({ transcriptId: "fixture-validation", sourceId: value.fixtureId,
    origin: "scripted_voice_transcript", languageTag: value.languageTag, text: value.text, revision: 1, attachments: [] });
  const fixture: ScriptedTranscriptFixture = Object.freeze({ fixtureId: checked.sourceId, text: checked.text,
    languageTag: checked.languageTag, provenance: "scripted_fixture", speechToTextPerformed: false, confidence: null });
  issuedFixtures.add(fixture);
  return fixture;
}
export function assertIssuedScriptedTranscriptFixture(value: ScriptedTranscriptFixture): void {
  if (!issuedFixtures.has(value)) throw new Error("Only an issued scripted fixture is permitted; real provider results remain gated.");
}
