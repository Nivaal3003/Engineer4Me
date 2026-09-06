import { assertIssuedProcessingCandidateScope, processingEvidenceInteger } from "./processing-candidate-scope";
import type { ProcessingCandidateScope } from "./processing-candidate-scope";
import { assertIssuedProcessingReviewDeclaration, assertProcessingReviewCategory, PROCESSING_REVIEW_CATEGORIES } from "./processing-review-declaration";
import type { ProcessingReviewCategory, ProcessingReviewDeclaration } from "./processing-review-declaration";
export interface ProcessingDossierHandle { readonly dossierId: string; readonly revision: number; readonly executionAuthorized: false; }
export interface ProcessingPlanningTicket { readonly dossierId: string; readonly revision: number; readonly generation: number; readonly planningOnly: true; readonly executionAuthorized: false; }
export interface ProcessingDossierSnapshot {
  readonly dossierId: string; readonly revision: number; readonly generation: number;
  readonly state: "evidence_required" | "declarations_complete_intervention_required";
  readonly missingCategories: readonly ProcessingReviewCategory[];
  readonly rejectedCategories: readonly ProcessingReviewCategory[];
  readonly expiredCategories: readonly ProcessingReviewCategory[];
  readonly needsReviewCategories: readonly ProcessingReviewCategory[];
  readonly acceptedDeclarationCount: number;
  readonly referencesVerified: false; readonly providerSelectedByApplication: false;
  readonly authenticatedReviewEstablished: false; readonly freshProcessingConsentRecorded: false;
  readonly executionAuthorized: false; readonly simulationTicksOnly: true;
}
export interface ProcessingDossierController {
  open(scope: ProcessingCandidateScope, tick: number): ProcessingDossierHandle;
  revise(handle: ProcessingDossierHandle, scope: ProcessingCandidateScope, tick: number): ProcessingDossierHandle;
  declareReview(handle: ProcessingDossierHandle, declaration: ProcessingReviewDeclaration, tick: number): void;
  revokeReview(handle: ProcessingDossierHandle, category: ProcessingReviewCategory, tick: number): void;
  inspect(handle: ProcessingDossierHandle, tick: number): ProcessingDossierSnapshot;
  issuePlanningTicket(handle: ProcessingDossierHandle, tick: number): ProcessingPlanningTicket;
  assertCurrentPlanningTicket(handle: ProcessingDossierHandle, ticket: ProcessingPlanningTicket, tick: number): void;
  discard(handle: ProcessingDossierHandle, tick: number): void;
}
type Entry = { scope: ProcessingCandidateScope; handle: ProcessingDossierHandle; generation: number; ticket: ProcessingPlanningTicket | null;
  reviews: Map<ProcessingReviewCategory, { declaration: ProcessingReviewDeclaration; expiresAt: number }>; };
const issuedControllers = new WeakSet<object>();
/** Memory-local identity checks, not an authentication or cross-process security boundary. */
export function assertIssuedProcessingDossierController(value: ProcessingDossierController): void {
  if (!issuedControllers.has(value)) throw new Error("Processing dossier controller is unissued.");
}
export function createProcessingDossierController(): ProcessingDossierController {
  const active = new Map<string, Entry>();
  const issuedHandles = new WeakMap<object, Entry>();
  const issuedTickets = new WeakMap<object, { handle: ProcessingDossierHandle; generation: number }>();
  const usedReviewDeclarations = new WeakSet<object>();
  let lastTick = 0;
  function time(tick: number): void {
    processingEvidenceInteger(tick, 0, 1000000000);
    if (tick < lastTick) throw new Error("Simulation ticks must be monotonic.");
    lastTick = tick;
  }
  function current(handle: ProcessingDossierHandle): Entry {
    const entry = issuedHandles.get(handle);
    if (!entry || active.get(entry.scope.dossierId) !== entry || entry.handle !== handle) throw new Error("Processing dossier is unissued, superseded or discarded.");
    return entry;
  }
  function openEntry(scope: ProcessingCandidateScope): ProcessingDossierHandle {
    const handle = Object.freeze({ dossierId: scope.dossierId, revision: scope.revision, executionAuthorized: false as const });
    const entry: Entry = { scope, handle, generation: 0, ticket: null, reviews: new Map() };
    active.set(scope.dossierId, entry); issuedHandles.set(handle, entry); return handle;
  }
  function bump(entry: Entry): void {
    if (entry.generation >= 1000000) throw new Error("Planning declaration revision limit reached; discard the dossier.");
    entry.generation += 1; entry.ticket = null;
  }
  function snapshot(entry: Entry, tick: number): ProcessingDossierSnapshot {
    const missing: ProcessingReviewCategory[] = [], rejected: ProcessingReviewCategory[] = [], expired: ProcessingReviewCategory[] = [], pending: ProcessingReviewCategory[] = [];
    let accepted = 0;
    for (const key of PROCESSING_REVIEW_CATEGORIES) {
      const review = entry.reviews.get(key);
      if (!review) missing.push(key);
      else if (tick >= review.expiresAt) expired.push(key);
      else if (review.declaration.decision === "rejected") rejected.push(key);
      else if (review.declaration.decision === "needs_review") pending.push(key);
      else accepted += 1;
    }
    return Object.freeze({ dossierId: entry.scope.dossierId, revision: entry.scope.revision, generation: entry.generation,
      state: accepted === PROCESSING_REVIEW_CATEGORIES.length ? "declarations_complete_intervention_required" as const : "evidence_required" as const,
      missingCategories: Object.freeze(missing), rejectedCategories: Object.freeze(rejected), expiredCategories: Object.freeze(expired), needsReviewCategories: Object.freeze(pending), acceptedDeclarationCount: accepted,
      referencesVerified: false, providerSelectedByApplication: false, authenticatedReviewEstablished: false,
      freshProcessingConsentRecorded: false, executionAuthorized: false, simulationTicksOnly: true });
  }
  const controller: ProcessingDossierController = Object.freeze({
    open(scope: ProcessingCandidateScope, tick: number) {
      assertIssuedProcessingCandidateScope(scope); time(tick);
      if (active.has(scope.dossierId)) throw new Error("Processing dossier identifier already active.");
      if (active.size >= 8) throw new Error("At most eight processing dossiers may be active.");
      return openEntry(scope);
    },
    revise(handle: ProcessingDossierHandle, scope: ProcessingCandidateScope, tick: number) {
      const entry = current(handle); assertIssuedProcessingCandidateScope(scope); time(tick);
      if (scope.dossierId !== entry.scope.dossierId || scope.revision !== entry.scope.revision + 1) throw new Error("Processing dossier revision must advance exactly once without changing its identifier.");
      entry.reviews.clear(); entry.ticket = null; active.delete(entry.scope.dossierId); return openEntry(scope);
    },
    declareReview(handle: ProcessingDossierHandle, declaration: ProcessingReviewDeclaration, tick: number) {
      const entry = current(handle); assertIssuedProcessingReviewDeclaration(declaration, entry.scope); time(tick);
      if (usedReviewDeclarations.has(declaration)) throw new Error("A review declaration cannot be reused to refresh validity.");
      bump(entry); usedReviewDeclarations.add(declaration);
      entry.reviews.set(declaration.category, { declaration, expiresAt: tick + declaration.validForSimulationTicks });
    },
    revokeReview(handle: ProcessingDossierHandle, category: ProcessingReviewCategory, tick: number) {
      const entry = current(handle); assertProcessingReviewCategory(category); time(tick);
      if (!entry.reviews.has(category)) throw new Error("No declared review exists to revoke.");
      bump(entry); entry.reviews.delete(category);
    },
    inspect(handle: ProcessingDossierHandle, tick: number) { const entry = current(handle); time(tick); return snapshot(entry, tick); },
    issuePlanningTicket(handle: ProcessingDossierHandle, tick: number) {
      const entry = current(handle); time(tick);
      if (snapshot(entry, tick).state !== "declarations_complete_intervention_required") throw new Error("Current planning declarations are incomplete.");
      if (entry.ticket) return entry.ticket;
      const ticket = Object.freeze({ dossierId: entry.scope.dossierId, revision: entry.scope.revision, generation: entry.generation, planningOnly: true as const, executionAuthorized: false as const });
      issuedTickets.set(ticket, { handle, generation: entry.generation }); entry.ticket = ticket; return ticket;
    },
    assertCurrentPlanningTicket(handle: ProcessingDossierHandle, ticket: ProcessingPlanningTicket, tick: number) {
      const entry = current(handle); time(tick); const issued = issuedTickets.get(ticket);
      if (!issued || issued.handle !== handle || issued.generation !== entry.generation || snapshot(entry, tick).state !== "declarations_complete_intervention_required") throw new Error("Planning ticket is unissued, stale, revoked or expired.");
    },
    discard(handle: ProcessingDossierHandle, tick: number) { const entry = current(handle); time(tick); entry.reviews.clear(); entry.ticket = null; active.delete(entry.scope.dossierId); },
  });
  issuedControllers.add(controller); return controller;
}
