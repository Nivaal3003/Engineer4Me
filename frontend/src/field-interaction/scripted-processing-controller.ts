import { assertCurrentRevisionBoundIntentPreview } from "./transcript-revision-review";
import type { createRevisionBoundIntentPreview } from "./transcript-revision-review";
import { createTranscriptReviewEnvelope } from "./transcript-review-envelope";
import type { TranscriptReviewEnvelope } from "./transcript-review-envelope";
import { assertIssuedScriptedTranscriptFixture } from "./scripted-transcript-fixture";
import type { ScriptedTranscriptFixture } from "./scripted-transcript-fixture";
import { assertScriptedProcessingTick, SCRIPTED_PROCESSING_LIMITS } from "./scripted-processing-policy";
export type ScriptedJobState = "queued" | "running" | "result_quarantined" | "cancelled" | "expired" | "superseded" | "consumed_for_fresh_review";
type Preview = ReturnType<typeof createRevisionBoundIntentPreview>;
export interface ScriptedJobTicket { readonly jobSerial: number; readonly simulationOnly: true; }
export interface ScriptedResultTicket { readonly jobSerial: number; readonly resultQuarantined: true; readonly executionAuthorized: false; }
export interface ScriptedJobSnapshot {
  readonly state: ScriptedJobState;
  readonly activeJobCount: number;
  readonly resultTextRetainedByController: boolean;
  readonly realTimeEnforcementPresent: false;
  readonly providerInvoked: false;
  readonly operationExecutionAuthorized: false;
}
export interface ScriptedProcessingController {
  queue(preview: Preview, fixture: ScriptedTranscriptFixture, tick: number): ScriptedJobTicket;
  start(ticket: ScriptedJobTicket, tick: number): void;
  deliver(ticket: ScriptedJobTicket, tick: number): ScriptedResultTicket;
  cancel(ticket: ScriptedJobTicket, tick: number): void;
  inspect(ticket: ScriptedJobTicket, tick: number): ScriptedJobSnapshot;
  takeForFreshReview(result: ScriptedResultTicket, transcriptId: string, tick: number): TranscriptReviewEnvelope;
  discardAll(): void;
}
interface Entry {
  state: ScriptedJobState;
  readonly createdTick: number;
  readonly serial: number;
  preview: Preview | null;
  fixture: ScriptedTranscriptFixture | null;
}
const controllers = new WeakSet<object>();
export function assertIssuedScriptedProcessingController(value: ScriptedProcessingController): void {
  if (!controllers.has(value)) throw new Error("An issued memory-only simulation controller is required.");
}
/** No timers, provider calls or user-input handlers. All transitions are explicit simulations. */
export function createScriptedProcessingController(): ScriptedProcessingController {
  const entries = new WeakMap<object, Entry>();
  const results = new WeakMap<object, Entry>();
  const active = new Set<Entry>();
  let serial = 0;
  let lastTick = 0;
  function time(tick: number): void {
    assertScriptedProcessingTick(tick);
    if (tick < lastTick) throw new Error("Simulation ticks cannot move backwards.");
    lastTick = tick;
  }
  function terminal(entry: Entry, state: ScriptedJobState): void {
    entry.state = state; entry.preview = null; entry.fixture = null; active.delete(entry);
  }
  function refresh(entry: Entry, tick: number): void {
    time(tick);
    if (!active.has(entry)) return;
    try {
      if (entry.preview === null) throw new Error("Missing context.");
      assertCurrentRevisionBoundIntentPreview(entry.preview);
    } catch { terminal(entry, "superseded"); return; }
    if (tick - entry.createdTick >= SCRIPTED_PROCESSING_LIMITS.maximumJobLifetimeTicks) terminal(entry, "expired");
  }
  function known(ticket: ScriptedJobTicket): Entry {
    const entry = entries.get(ticket);
    if (!entry) throw new Error("Unissued or cross-controller job ticket.");
    return entry;
  }
  function requireState(entry: Entry, tick: number, states: readonly ScriptedJobState[]): void {
    refresh(entry, tick);
    if (!states.includes(entry.state) || entry.preview === null || entry.fixture === null) {
      throw new Error("Scripted job is not admissible: " + entry.state);
    }
  }
  const controller: ScriptedProcessingController = Object.freeze({
    queue(preview: Preview, fixture: ScriptedTranscriptFixture, tick: number): ScriptedJobTicket {
      time(tick); assertCurrentRevisionBoundIntentPreview(preview); assertIssuedScriptedTranscriptFixture(fixture);
      // Expiration and supersession are checked on every explicit controller operation, not in the background.
      for (const entry of active) refresh(entry, tick);
      if (active.size >= SCRIPTED_PROCESSING_LIMITS.maximumActiveJobs) throw new Error("Sixteen active scripted jobs maximum.");
      if ([...active].some((entry) => entry.preview?.transcriptId === preview.transcriptId)) throw new Error("A job for this transcript is already active.");
      if (serial >= 1000000) throw new Error("Simulation identifier budget exhausted; create a new controller.");
      serial += 1;
      const ticket: ScriptedJobTicket = Object.freeze({ jobSerial: serial, simulationOnly: true });
      const entry: Entry = { state: "queued", createdTick: tick, serial, preview, fixture };
      entries.set(ticket, entry); active.add(entry); return ticket;
    },
    start(ticket: ScriptedJobTicket, tick: number): void {
      const entry = known(ticket); requireState(entry, tick, ["queued"]); entry.state = "running";
    },
    deliver(ticket: ScriptedJobTicket, tick: number): ScriptedResultTicket {
      const entry = known(ticket); requireState(entry, tick, ["running"]);
      const result: ScriptedResultTicket = Object.freeze({ jobSerial: entry.serial, resultQuarantined: true, executionAuthorized: false });
      entry.state = "result_quarantined"; results.set(result, entry); return result;
    },
    cancel(ticket: ScriptedJobTicket, tick: number): void {
      const entry = known(ticket); requireState(entry, tick, ["queued", "running", "result_quarantined"]); terminal(entry, "cancelled");
    },
    inspect(ticket: ScriptedJobTicket, tick: number): ScriptedJobSnapshot {
      const entry = known(ticket); refresh(entry, tick);
      return Object.freeze({ state: entry.state, activeJobCount: active.size, resultTextRetainedByController: entry.fixture !== null,
        realTimeEnforcementPresent: false, providerInvoked: false, operationExecutionAuthorized: false });
    },
    takeForFreshReview(result: ScriptedResultTicket, transcriptId: string, tick: number): TranscriptReviewEnvelope {
      const entry = results.get(result);
      if (!entry) throw new Error("Unissued or cross-controller result ticket.");
      requireState(entry, tick, ["result_quarantined"]);
      // Re-read after the check for strict null narrowing. Both are private, immutable input objects.
      const preview = entry.preview; const fixture = entry.fixture;
      if (preview === null || fixture === null) throw new Error("Scripted result was invalidated.");
      if (transcriptId === preview.transcriptId) throw new Error("Scripted results require a distinct new transcript identifier.");
      const envelope = createTranscriptReviewEnvelope({ transcriptId, sourceId: fixture.fixtureId,
        origin: "scripted_voice_transcript", languageTag: fixture.languageTag, text: fixture.text, revision: 1, attachments: preview.attachments });
      terminal(entry, "consumed_for_fresh_review");
      return envelope;
    },
    discardAll(): void { for (const entry of active) terminal(entry, "cancelled"); },
  });
  controllers.add(controller); return controller;
}
