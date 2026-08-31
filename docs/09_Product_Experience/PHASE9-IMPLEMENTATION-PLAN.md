# Engineer4Me Phase 9 — Mobile-First Product Experience & Frontend Integration

## Step 279: Inception, Phase 8 closure binding, and implementation-plan freeze

**Plan date:** 30 August 2026  
**Plan status:** Controlled inception baseline  
**Starting branch:** `feature/phase-8`  
**Starting commit:** `c7599bb22a1beee62340830f239643bca1a9a41b`  
**Starting tree:** `7bd59235a781207c98a6bec79202f93f8b28d7c2`  
**Future Phase 9 branch:** `feature/phase-9`  
**Closure basis:** Phase 8 `source_repository_and_verification_only`  
**Voice functionality:** Explicitly excluded; remains Phase 10  

---

## 1. Phase 9 objective

Phase 9 turns the controlled backend, security foundation, and minimal frontend
bootstrap into a usable, mobile-first Engineer4Me browser product.

The phase will deliver a production-quality web product experience that:

1. presents a coherent Engineer4Me application shell, navigation model, and
   responsive workspace;
2. integrates existing backend capabilities through typed, evidence-aware API
   clients;
3. exposes identity, organisation, role, entitlement, and audit context without
   weakening the Phase 8 fail-closed security boundary;
4. activates Microsoft Entra browser authentication only after separate,
   controlled configuration, redirect, CORS, CSP, network-client, PKCE, callback,
   and token-handling gates pass;
5. makes engineering evidence, assumptions, limitations, confidence, revision
   state, and approval ownership visible in the user interface;
6. provides mobile-first, keyboard-accessible, screen-reader-compatible flows
   aligned to WCAG 2.2 AA and a 44-pixel product target;
7. preserves vendor neutrality and never chooses a "best brand" for the user;
8. keeps final engineering approval, standards conformity, and operational
   authorization user-owned;
9. supports visible connectivity and future sync-state UX without enabling PWA
   caching or service workers initially; and
10. leaves voice commands and voice search for Phase 10.

---

## 2. Binding architecture

The Phase 9 architecture baseline is:

- client-side static browser SPA;
- React and React DOM 19 family;
- Vite 8 family;
- strict TypeScript and ESM;
- FastAPI remains a separate API;
- no server-side rendering;
- no React Server Components;
- no Node.js production application server;
- npm only, with `package-lock.json` lockfile version 3;
- direct `PublicClientApplication` use;
- `@azure/msal-react` remains forbidden initially;
- `sessionStorage` for the initial MSAL cache posture;
- exactly one controlled custom `system.networkClient`;
- MSAL default network transport remains forbidden;
- browser-history routing with controlled static fallback;
- mobile-first layout and accessibility;
- no service worker or PWA caching in the initial implementation.

The exact dependency versions already committed by Phase 8 remain the starting
baseline. Step 279 does not update, resolve, install, or execute dependencies.

---

## 3. Product workstreams

### 3.1 Product shell and information architecture

- responsive application shell;
- mobile and desktop navigation;
- route ownership and protected-route policy;
- organisation, project, and user-context selectors;
- consistent loading, empty, error, degraded, and unavailable states;
- evidence, confidence, warning, limitation, and approval-status components.

### 3.2 Authentication and access experience

- inactive-authentication and readiness states;
- controlled sign-in, callback, sign-out, and session-expiry experiences;
- role, tenant, entitlement, and access-denial presentation;
- no token exposure in URLs, logs, local storage, or user-visible diagnostics;
- exact redirect/origin/CSP/CORS and network-client proofs before activation.

### 3.3 Typed API integration

- one controlled API transport layer;
- consistent correlation, timeout, retry, cancellation, and error semantics;
- bearer-token attachment only for approved protected routes;
- typed client models for existing Engineer4Me APIs;
- evidence and traceability fields retained end-to-end.

### 3.4 Engineer4Me capability surfaces

Phase 9 will progressively expose existing controlled backend capabilities:

- selection and sizing;
- troubleshooting and fault intelligence;
- engineering knowledge and evidence;
- document ingestion and processing;
- calculations and design cases;
- level, DP flow, control-valve, analyzer, and datasheet workflows;
- security context, audit visibility, and controlled administration;
- project/workspace entry points for later multidisciplinary expansion.

### 3.5 Mobile, accessibility, and degraded connectivity

- WCAG 2.2 AA target;
- keyboard-only and screen-reader flows;
- 44-pixel minimum product interaction target;
- responsive layouts for phone, tablet, and desktop;
- visible online/offline/degraded status;
- no initial PWA caching, background sync, or service worker;
- no native Android or iOS packaging in Step 279.

### 3.6 Verification and closure

- TypeScript typecheck;
- deterministic Vite production builds;
- Vitest and React Testing Library;
- Playwright browser verification;
- axe-core plus manual accessibility review;
- zero uncontrolled external requests in isolated tests;
- backend regression retained;
- explicit closure record with deployment and conformity exclusions.

---

## 4. Controlled milestone sequence

1. **Step 279 — Inception and plan freeze**  
   Bind the exact Phase 8 closure, verify the repository and closure artifacts,
   confirm the Phase 9 branch is absent, and freeze this implementation plan.
   Read-only; no branch or source mutation.

2. **Step 280 — Phase 9 branch inception**  
   Create and push `feature/phase-9` from the exact Phase 8 final commit and
   materialize only the reviewed Phase 9 inception/architecture records.

3. **Frontend architecture and API inventory**  
   Bind the exact current frontend and backend surfaces, information
   architecture, route ownership, accessibility rules, and UI data contracts.

4. **Design system and product shell**  
   Implement the responsive shell, navigation, status components, evidence
   presentation, and accessible interaction primitives.

5. **Controlled API transport**  
   Implement the typed API client, correlation/error contracts, and the single
   controlled MSAL network-client integration seam.

6. **Authentication readiness and activation**  
   Keep authentication inactive until exact Entra configuration, origin,
   redirect, CSP, CORS, PKCE, callback, token, and logout gates pass. Activation
   is a separately reviewed milestone, not an inception action.

7. **Organisation, role, entitlement, and audit UX**  
   Expose approved user context and fail-closed denial/readiness experiences.

8. **Engineering capability integration**  
   Integrate the existing selection, troubleshooting, knowledge, ingestion,
   calculation, design, and datasheet APIs in reviewed vertical slices.

9. **Mobile/accessibility/degraded-connectivity hardening**  
   Complete WCAG, responsive, error-state, slow-network, and disconnected-state
   verification without initial PWA caching.

10. **Integrated verification and Phase 9 closure**  
    Complete deterministic builds, unit/component/E2E/accessibility/security
    checks, full backend regression, clean synchronized Git state, and a
    committed-HEAD closure archive.

The detailed numeric step allocation after Step 280 remains deliberately
unfrozen until the exact API and product-surface inventory is accepted.

---

## 5. Step 279 boundary

Step 279 is read-only with respect to Engineer4Me.

It may:

- verify the exact Phase 8 branch, commit, tree, tracking ref, origin, clean
  worktree, and empty index;
- perform read-only authoritative Git remote queries;
- verify the exact four-file Phase 8 closure artifact directory;
- verify selected committed frontend baseline blobs;
- verify that local and remote `feature/phase-9` refs are absent;
- verify the package, contract, plan, and their SHA-256 identities;
- print the accepted Phase 9 plan and successor status.

It may not:

- create `feature/phase-9`;
- write to the repository or Git index/object database/refs;
- commit, push, fetch, pull, merge, rebase, tag, or deploy;
- execute npm, install dependencies, build, test, or launch a browser;
- execute OAuth, PKCE, callbacks, tokens, Graph, or Entra mutation;
- activate authentication or the application;
- run migrations, DDL, bootstrap writes, Docker, or WSL mutation;
- enable service workers or PWA caching;
- add voice functionality;
- authorize Phase 9 implementation beyond the reviewed Step 280 handoff.

---

## 6. Step 279 acceptance criteria

Step 279 is accepted only when:

- the repository is on `feature/phase-8`;
- HEAD is `c7599bb22a1beee62340830f239643bca1a9a41b`;
- HEAD tree is `7bd59235a781207c98a6bec79202f93f8b28d7c2`;
- local tracking and authoritative origin match HEAD with zero divergence;
- the Git index is empty and the Git-visible worktree is clean;
- the exact Phase 8 closure artifacts match their accepted hashes and byte
  counts;
- selected frontend baseline blobs match the committed Phase 8 identities;
- local and remote `feature/phase-9` refs are absent;
- no disallowed mutation or execution occurs;
- the success marker and successor status are printed.

---

## 7. Step 280 handoff

After Step 279 acceptance, Step 280 may be prepared to:

1. revalidate the complete Step 279 result;
2. create `feature/phase-9` only from
   `c7599bb22a1beee62340830f239643bca1a9a41b`;
3. publish the branch through an explicit absent-ref lease;
4. add only reviewed Phase 9 inception and architecture records;
5. run syntax/static validation appropriate to those records;
6. commit and push one exact Phase 9 inception commit;
7. leave authentication, OAuth, migrations, deployment, service workers, and
   voice inactive.

No application feature implementation is authorized by Step 279 itself.
