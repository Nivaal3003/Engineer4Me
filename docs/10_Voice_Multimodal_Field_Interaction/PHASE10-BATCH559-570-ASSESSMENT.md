# Local-first transcription implementation assessment — Batch 559–570

Status: source-only implementation and planning. The owner selected local-first assessment; no acquisition, compilation of an ASR engine, model load, audio capture or inference is approved or performed.

## Decision and actual scope

The owner's message “lets proceed with you recommendation” resolves the processing-route choice: local-only assessment first, with a provider-independent interface and separately approved future site or cloud options. It does not authenticate an execution reviewer, approve a binary, or make an external fallback permissible. The existing manual text, draft review, cancellation and stale-result controls remain in force. A route failure offers manual text, not audio retention or silent upload.

## Candidate narrowed for review

The first engine source candidate is whisper.cpp commit `371b5a7561823ab2bb32142d2751e35e7534727b` associated with v1.9.3. Its release page says **Pre-release**, whereas its pinned README says **Stable**. We preserve this discrepancy and require release/security review before an executable build is approved. Release notes include fixes for very short input and malformed model dimensions. They are not a complete vulnerability review. [S1–S3]

The first model candidate is **base.en**, unquantized, for an English CPU reference evaluation. A historical upstream model repository commit publishes its SHA-256 and byte count; these are recorded in the candidate JSON as **published metadata**, not proof that any model bytes have been acquired or verified. Neither a claimed current version nor a runtime approval is inferred. This starting candidate reduces the initial model/configuration matrix; small.en remains a later quality/resource comparator, not an additional installation. [S9]

Upstream code and model license declarations are initial evidence references, not complete redistribution clearance. Actual runtime dependencies, model conversion provenance, notices and input rights still need review. [S7,S10]

## Runtime design to assess, not activate

Assess a private CPU-only worker using a narrow library wrapper, not the upstream network server, continuous microphone example, or unrestricted shell command. The UI must not be assumed to execute a native binary directly. Browser/native bridging, deployment topology and authentication of that boundary remain unimplemented. Initial inference should use separately authorized rights-cleared fixture inputs, not reuse the historic one-frame receipt or open a microphone.

The source exposes a 16 kHz PCM interface, explicit GPU selection, context handling and an abort callback. The wrapper must independently impose input, output, wall-time and memory bounds; verify worker termination after cancellation; and prevent stale result admission. A callback alone is not a watchdog. Engine prints and debug output must be excluded from ordinary logs, since transcript and derived content can be sensitive. [S6]

For the prospective build recipe, explicitly exclude model download support, the HTTP server, SDL capture examples, RPC and unused accelerators. The published CMake definitions make those review targets concrete, but configuration switches are **not** an OS network boundary. Final source/dependency inventory, effective build configuration, exported runtime dependencies and sandbox evidence remain required. No build command, dependency installation or download is provided here. [S4,S5]

Buffer clearing is not proof of erasing paging files, crash dumps, allocator copies or OS buffers. The runtime evidence must state those limits. An on-device app, a browser/WASM deployment and a site server are different qualification targets; the CPU reference is none of those proofs. The source-only batch does not enable native packaging, service workers or PWA caching. [S3]

## Executable pure-data checks added to Engineer4Me

1. A frozen owner-direction record keeps route selection distinct from permission grants.
2. A manifest-declaration validator requires six artifact roles, full commit and digest identifiers, fixed revisions, unique references and bounded byte counts. It does not open files or validate the claimed artifact contents. Copies of internally issued manifests are not accepted as issued handles.
3. A pilot-plan validator binds the manifest, configuration digest and every expected case to a declared input digest. It requires utterance, silence, noise, cancellation and supersession coverage. These are declarations, not authenticated evidence or input-rights approval.
4. A result-review function rejects mixed configuration/input identities, duplicates, unknown cases and invalid counters. It distinguishes no results, incomplete results, blocked results, scripted criteria success and declared criteria success requiring independent review. It never emits execution or production approval.
5. Any critical semantic error, invented non-speech text, stale-result admission, audio persistence/transfer, runtime download attempt, unproven cleanup or resource exceedance blocks the declared evaluation result. Low average word error cannot override these failures.
6. A static accessible panel presents the owner-selected direction without a download, model, microphone, text entry or execution control.

## Evaluation protocol

The preserved 32 text-only case specifications are not recordings. They must later be paired with rights-cleared inputs covering the intended speakers, accents, equipment vocabulary and noise conditions. The result-review module supports 5–64 cases per declared plan and requires all five categories. It accepts English only for the **initial pilot**, not as a product-wide language decision.

Proposed first fixtures: 0.25–15 seconds of mono 16 kHz PCM per case. The source-only plan checks declared durations; it does not read or convert audio. A future worker must validate byte counts, samples, channels, format and true duration before the native model is called. Compression/container handling is a separate attack surface, not automatically allowed.

Record the complete engine/model/build/configuration and device identity, input digest, cold/warm timing policy, per-case wall time, peak memory, word errors, and human-reviewed critical semantic errors. Do not mix different models or device configurations in one report. Include negation, decimals, units and equipment-tag review; don't silently normalize away those differences. The mathematical word-error ratio may exceed one because insertions count as errors. Nearest-rank p95 uses observed cases and remains explicitly incomplete until every required case is present.

No particular latency, battery, memory or accuracy result is claimed. Budget values must be set in the declared plan before execution and justified for the target hardware; structural limits are safety bounds, not performance promises. A zero-error pilot is neither statistical proof nor general safety qualification. Whisper's model card warns about invented text and variable performance; future output remains an untrusted draft requiring explicit review. [S8]

## Next intervention boundary

Route selection is complete. Remaining blockers are concrete acquisition/build scope, source/binary/model provenance, the prerelease discrepancy and applicable fixes, dependency notices, resource/isolation design, authorized input rights, runtime review and fresh inference approval. Do not ask the owner to choose local versus cloud again. Do not install or execute ASR to satisfy these gates implicitly. The next acquisition proposal must enumerate the exact URLs/revisions, expected identities, destination, byte limits and no-execution boundary; subsequent inference remains separate.

## Validation limits

Current package construction checks use local synthetic Git repositories, simulated npm outputs and isolated TypeScript/Node assertion shims. They are not actual speech recognition or the complete Engineer4Me Vitest suite. The user's Windows runner still performs the real frontend tests and two builds before publication. Parent ZIP and receipt bytes are checked on that host; the construction environment has only their console-reported identities.

Sources S1–S10 are identified in `PHASE10-BATCH559-570-PUBLIC-SOURCES.json`. Public-source observations are dated 6 September 2026 and must be rechecked before acquisition. No source archive, model weights or ASR executable is included.
