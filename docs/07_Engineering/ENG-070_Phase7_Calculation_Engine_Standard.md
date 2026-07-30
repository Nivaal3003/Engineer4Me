# ENG-070 — Phase 7 Engineering Calculation Engine Standard

## Document control

| Field | Value |
| --- | --- |
| Document ID | ENG-070 |
| Title | Phase 7 Engineering Calculation Engine Standard |
| Revision | 0.1 |
| Status | Controlled implementation baseline |
| Owner | Engineer4Me |
| Phase | 7 — Engineering Calculations & Design Engine |
| Baseline commit | `6b669df21da6ad59ac5d896cfbf316aa3a9d9057` |
| Initial branch | `feature/engineering-calculations-phase-7` |
| Planned application version | `0.10.0` |
| Effective date | 30 July 2026 |

This standard defines the mandatory engineering, software, safety, evidence,
validation, audit, and legal controls for Phase 7. It contains no executable
engineering formula and does not approve any calculation method.

---

## 1. Purpose

The Engineer4Me calculation engine shall provide deterministic, traceable,
vendor-neutral engineering decision support. It shall preserve the distinction
between:

1. supplied facts;
2. extracted facts;
3. defaults;
4. assumptions;
5. derived values;
6. calculation results;
7. engineering hypotheses;
8. recommendations;
9. verification evidence; and
10. final decisions made by authorised people.

The engine shall not present an unverified numerical output as proof that an
installation, product, design, or operating action is safe or compliant.

---

## 2. Scope

The Phase 7 engine boundary includes:

- shared engineering quantities and unit conversion;
- pressure, signal, flow, uncertainty, and general engineering calculators;
- pressure and level calculations;
- a level application wizard;
- differential-pressure flow calculations;
- control-valve sizing;
- preliminary pressure-relief and safety-valve sizing;
- an analyzer application assistant;
- versioned design cases;
- append-only calculation records;
- controlled engineering datasheets;
- controlled integration with Engineering Knowledge and product selection;
- REST APIs, audit data, exports, and automated validation.

The following capabilities are outside Phase 7:

- speech recognition;
- voice search;
- voice commands;
- text-to-speech;
- offline voice processing;
- autonomous engineering approval;
- final hazardous-area certification;
- final SIL verification;
- transient simulation;
- computational fluid dynamics;
- finite-element analysis;
- proprietary Annubar correlations;
- automatic execution of uploaded or AI-generated formula text.

Voice functionality remains scheduled for Phase 10.

---

## 3. Normative language

The words **shall** and **must** identify mandatory requirements.

The word **should** identifies a recommendation that needs a recorded reason
when it is not followed.

The word **may** identifies a permitted option.

---

## 4. Core safety requirements

### E4M-CALC-001 — Safety precedence

Safety findings shall be evaluated and returned before product, sizing, or
design recommendations.

### E4M-CALC-002 — Blocking findings

A calculation with a blocking safety or applicability finding shall not return
the status `completed`.

### E4M-CALC-003 — Missing critical inputs

Missing safety-critical or applicability-critical inputs shall produce
`blocked`, `insufficient_input`, or `not_applicable`. The engine shall not
invent a value to continue.

### E4M-CALC-004 — Competent review

Each high-risk method shall state the required reviewer competency and the
site, manufacturer, standards, and legal checks that remain necessary.

### E4M-CALC-005 — Preliminary pressure-relief results

Pressure-relief and safety-valve outputs shall be labelled preliminary
engineering decision support and shall require independent review by a
competent pressure-systems engineer.

### E4M-CALC-006 — Site authority

Engineer4Me shall not override a site permit, isolation procedure, management
of change process, operating limit, manufacturer instruction, legal
requirement, or authorised engineering decision.

---

## 5. Executable-method controls

### E4M-CALC-010 — Allow-listed execution

Only a method explicitly registered in the application allow list may execute.

### E4M-CALC-011 — No dynamic expression execution

The application shall not use `eval`, `exec`, dynamic imports, spreadsheet
macros, shell execution, or equivalent mechanisms to run user-supplied,
document-extracted, or AI-generated formula text.

### E4M-CALC-012 — Method identity

Every executable method shall have:

- a permanent method ID;
- a method version;
- a calculation type;
- an implementation owner;
- a lifecycle status;
- required inputs and units;
- applicability limits;
- assumptions and exclusions;
- safety requirements;
- source and standards references;
- reference-vector provenance;
- reviewer records;
- an engine compatibility range.

### E4M-CALC-013 — Method lifecycle

The supported lifecycle shall include:

1. `draft`;
2. `technical_review`;
3. `safety_review`;
4. `standards_review`;
5. `approved`;
6. `superseded`;
7. `disabled`.

A method that requires controlled technical approval shall not execute in the
production-approved mode until all required reviews are complete.

### E4M-CALC-014 — Version immutability

A formula, coefficient rule, validity range, rounding rule, or standards
edition change shall create a new method version. Historical method versions
shall remain identifiable for calculation reproduction.

### E4M-CALC-015 — Extracted knowledge boundary

Phase 6 document processing may create draft formula knowledge or proposed
inputs. It shall not register executable calculation code.

---

## 6. Quantity and unit requirements

### E4M-CALC-020 — Explicit units

Every dimensional input and output shall carry an explicit supported unit.

### E4M-CALC-021 — Dimensional validation

The engine shall reject conversions or equations that mix incompatible
physical dimensions.

### E4M-CALC-022 — Pressure basis

Absolute, gauge, and differential pressure shall be represented as distinct
quantity kinds. Gauge-to-absolute conversion requires an explicit atmospheric
pressure.

### E4M-CALC-023 — Reference conditions

Standard or normal volumetric flow requires explicit reference absolute
pressure, reference temperature, and compressibility treatment. The words
standard and normal shall not be interpreted without those values.

### E4M-CALC-024 — Temperature

Temperature-dependent equations shall use an absolute temperature scale
internally where required. Values below absolute zero shall be rejected.

### E4M-CALC-025 — Finite values

NaN, positive infinity, and negative infinity shall be rejected at every public
input boundary and shall not appear in serialized output.

### E4M-CALC-026 — Rounding

Intermediate values shall not be rounded unless the controlled method
explicitly requires it. Presentation rounding and significant-figure metadata
shall be separate from the stored numerical result.

---

## 7. Calculation-result contract

Every result shall contain:

- run ID and deterministic fingerprint;
- method ID, method version, and engine version;
- execution timestamp;
- result status;
- supplied inputs and their origins;
- normalized inputs and canonical units;
- defaults and assumptions;
- missing inputs;
- validation and applicability findings;
- safety findings;
- calculation-step and formula identifiers;
- intermediate values needed for review;
- outputs with units;
- supported uncertainty or confidence information;
- standards and evidence references;
- limitations and exclusions;
- verification steps;
- required reviewer competency;
- decision-support disclaimer.

The supported result states shall be:

- `completed`;
- `completed_with_warnings`;
- `blocked`;
- `insufficient_input`;
- `not_applicable`;
- `failed`.

---

## 8. Numerical requirements

### E4M-CALC-030 — Determinism

The same method version and normalized input set shall produce the same
numerical result and fingerprint.

### E4M-CALC-031 — Solver limits

Every iterative method shall define:

- initial conditions;
- convergence tolerance;
- maximum iterations;
- non-convergence handling;
- traceable iteration outcome.

### E4M-CALC-032 — Domain checks

Physical and mathematical domain checks shall run before the related equation.
Examples include positive absolute pressure, valid geometry, non-zero span,
supported phase, required fluid properties, and valid denominator ranges.

### E4M-CALC-033 — Tolerances

Automated numerical tolerances shall be justified by engineering significance
and reference precision. A loose tolerance shall not be used to hide an
incorrect implementation.

### E4M-CALC-034 — Regime boundaries

Test coverage shall include values immediately below, at, and above method
regime transitions where the method defines those regimes.

---

## 9. Evidence and standards requirements

### E4M-CALC-040 — Controlled references

Every standards-derived method shall identify the standard publisher, number,
edition, applicable part, corrigenda status where relevant, and reviewed
implementation basis.

### E4M-CALC-041 — Rights protection

Engineer4Me shall not copy protected standards text, tables, figures, or
software without appropriate rights. Metadata and independently authored
implementation records shall remain distinguishable from licensed content.

### E4M-CALC-042 — Reference vectors

Every approved numerical method shall have independent reference vectors that
record:

- source;
- source version;
- inputs and units;
- expected outputs and units;
- rounding basis;
- accepted tolerance;
- reviewer.

### E4M-CALC-043 — Knowledge review

Calculation knowledge intended for approved use shall follow the existing
technical, safety, standards, and final-approval workflow.

---

## 10. Vendor, patent, and trademark requirements

### E4M-CALC-050 — Vendor-neutral core

Generic physical calculations shall remain separate from manufacturer-specific
catalogues, capacity factors, proprietary coefficients, and selection rules.

### E4M-CALC-051 — Manufacturer data

Manufacturer-specific factors shall carry manufacturer, document, revision,
model applicability, source, and verification metadata.

### E4M-CALC-052 — Annubar

Annubar shall be identified as a Rosemount/Emerson proprietary product name.
Engineer4Me shall not reproduce or reverse-engineer proprietary Annubar sizing
correlations.

### E4M-CALC-053 — Generic averaging Pitot

A generic averaging-Pitot method may use a user-supplied traceable coefficient.
Model-specific output requires authorised OEM data or an approved integration.

---

## 11. Design and analyzer requirements

### E4M-CALC-060 — Scenario-based recommendations

The level and analyzer assistants shall preserve multiple plausible scenarios
when evidence does not support one definitive conclusion.

### E4M-CALC-061 — Multidisciplinary context

Design findings shall consider instrumentation, process, mechanical, piping,
electrical, automation/control, safety, environmental, maintenance, and
reliability contributors where applicable.

### E4M-CALC-062 — Confidence

Confidence shall reflect input completeness, evidence quality, method
applicability, and unresolved assumptions. It shall not be a cosmetic score.

### E4M-CALC-063 — Verification

Every scenario shall identify the observations, assumptions, missing
information, recommended checks, acceptance evidence, and escalation
conditions.

---

## 12. Persistence and audit requirements

### E4M-CALC-070 — Append-only calculation runs

A stored calculation run shall not be edited in place. A changed input,
assumption, method, or method version creates a new run linked to the earlier
record where applicable.

### E4M-CALC-071 — Result fingerprint

The stored fingerprint shall cover the method identity, normalized inputs, and
material execution options using a documented canonical representation.

### E4M-CALC-072 — Reproduction

A historical result shall retain enough method, input, unit, assumption, and
engine metadata to explain and reproduce it subject to software retention.

### E4M-CALC-073 — Design revisions

Design cases and datasheets shall preserve revision identity, change reason,
creator, timestamps, linked calculations, source origins, and approval state.

---

## 13. Datasheet requirements

### E4M-CALC-080 — No invented values

Unknown engineering values shall remain visibly unknown. The generator shall
not fabricate values to make a datasheet appear complete.

### E4M-CALC-081 — Field origin

Each controlled field shall identify whether it is user supplied, document
extracted, calculated, selected, defaulted, or unknown.

### E4M-CALC-082 — Calculation linkage

Calculated datasheet fields shall link to the exact calculation run and method
version that produced them.

### E4M-CALC-083 — Safe workbook generation

Untrusted cell text shall be protected against spreadsheet-formula injection.
Generated workbooks shall be reopened during automated validation.

---

## 14. API and security requirements

### E4M-CALC-090 — Typed contracts

Public calculation endpoints shall use strict typed request and response
contracts. Unknown fields shall be rejected unless a reviewed compatibility
rule explicitly permits them.

### E4M-CALC-091 — Bounded input

Numeric magnitude, list length, text length, file size, payload size, and
iteration count shall be bounded.

### E4M-CALC-092 — Stable error translation

Validation, applicability, safety, method, persistence, and unexpected
execution errors shall map to deterministic public responses without exposing
secrets or internal stack traces.

### E4M-CALC-093 — Export paths

Export names and paths shall be generated or validated to prevent traversal,
overwriting unrelated files, or unsafe filesystem access.

### E4M-CALC-094 — Confidential inputs

Process inputs shall not be logged unnecessarily. Audit records shall contain
only the information required for engineering traceability and authorised
operations.

---

## 15. Automated validation requirements

Every calculation pack shall include, as applicable:

1. strict model tests;
2. unit and dimensional tests;
3. formula unit tests;
4. independent golden/reference vectors;
5. boundary and invalid-domain tests;
6. metamorphic or property tests;
7. convergence and non-convergence tests;
8. safety and applicability tests;
9. method registry and version tests;
10. repository and migration tests;
11. API and OpenAPI tests;
12. export and reopen tests;
13. malformed and adversarial input tests;
14. multidisciplinary end-to-end tests;
15. complete Phase 1–6 regression tests.

The Phase 6 closure baseline is:

- `1,593` backend tests passed;
- `165` subtests passed;
- `1` known warning;
- application version `0.9.0`.

The baseline count shall not decrease without an explicit reviewed test
replacement or removal justification.

---

## 16. Review and approval

| Review | Required focus |
| --- | --- |
| Technical | Equations, physical basis, units, domains, numerical method, and reference vectors |
| Safety | Hazards, blocked conditions, required actions, competency, and disclaimers |
| Standards | Edition, applicability, corrigenda, jurisdiction, implementation basis, and rights |
| Legal/compliance | OEM ownership, patents, trademarks, licences, protected content, and user-facing limitations |
| Software | Architecture, types, security, determinism, performance, persistence, and API behavior |
| Final approval | Evidence that every required gate and automated validation has completed |

Approval applies to a specific method version. It does not automatically apply
to a future revision.

---

## 17. Change control

Changes to this standard require:

1. a new document revision;
2. a change summary;
3. impact assessment against existing method versions and calculation records;
4. required technical, safety, standards, legal, and software review;
5. focused and full regression testing;
6. a clean committed and synchronized repository state.

This revision establishes the Phase 7 implementation boundary. It does not
enable an executable calculation method.
