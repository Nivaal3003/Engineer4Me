# Phase 10 Batch 535–546: scripted lifecycle and result quarantine

This is a source-only extension of the accepted revision-bound manual/scripted review. No microphone, file content, actual transcript provider, external/local AI, authentication, backend or operation executor is called.

## Pure simulation
A job binds an issued current review preview to an issued scripted text fixture. Fixtures are declared input, not audio-derived output. Explicit caller operations model queue, start, final delivery and cancellation. There are no promises, timers, workers or live clocks. A controller holds at most sixteen active jobs and one job per transcript. A final result is delivered at most once. Time is modeled with bounded monotonic caller-supplied ticks; 60000 ticks is a simulation limit, not a live timeout guarantee.

## Context and stale results
Each transition and result admission checks the original current preview. Editing its text, changing attachments, or discarding the source review invalidates the pending result. Cancellation, expiry, supersession and explicit discard release owned references and block result reuse. These checks do not prove authenticated approval or erase copies retained by a caller. Controllers are isolated by object identity, not by a remote security boundary.

## Result quarantine and new review
A result ticket contains no text and no execution authority. Explicit one-use admission creates a new envelope and a separate draft review. Exact fixture text and declared attachment references are preserved. No existing approval is transferred. If the new-review registry refuses admission, the ticket stays consumed; nothing resends or retries. This is not a transcription, translation, query allocation, command interpretation, or engineering decision.

## No activation
The workspace shows a static heading-labelled boundary panel only. There is no active entry, provider selector, microphone button, transcription control or backend request. Provider selection, licensing, privacy, data location, retention/deletion, quality, consent and execution approval still require a separate intervention gate before real transcription.

## Host evidence
The existing completed signal receipt is validated and preserved read-only, not repeated. Actual host acceptance requires the full 156-file frontend suite, two matching builds, Playwright discovery without browser launch, exact committed-tree validation, lease-guarded publication, fast-forward synchronization and an immutable acceptance archive. Pre-delivery synthetic tests are explicitly separate from these host checks.
