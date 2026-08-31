# Engineer4Me Phase 9 Numeric Milestone Allocation

**Allocation ID:** `7b0cb4ab9cd01a0ecf3f5245fc245088c2a151d01c847acfb79cbba0d2fac1eb`
**Inventory review ID:** `ec602b651c9895759ee2fd85e6d04e771c968528bd3f0737cc4f5fdf4bb9fcb7`
**Frozen range:** Steps **283–378**
**Status:** Controlled allocation only; not blanket source-mutation or implementation authorization.

## Allocation basis

- Frontend source files: **6**
- Browser-route signals: **0**
- Backend effective operations: **93**
- Backend data contracts: **364**
- Backend Python parse errors requiring qualification: **4**

## Frozen milestone ranges

| Milestone | Steps | Controlled workstream | Purpose |
| --- | --- | --- | --- |
| 1 | 283–286 | inventory_qualification_and_frontend_foundation_gate | Dispose the four static Python parse errors, bind exact source/test/toolchain assumptions, and authorize only the reviewed frontend foundation. |
| 2 | 287–294 | toolchain_test_harness_and_source_architecture | Establish strict source boundaries, deterministic typecheck/build/unit/E2E harnesses, and isolated-network test controls before product UI expansion. |
| 3 | 295–306 | design_system_accessibility_primitives_and_product_shell | Implement tokens, typography, spacing, accessible controls, evidence/status primitives, responsive shell regions, and mobile-first interaction targets. |
| 4 | 307–316 | browser_routing_navigation_and_state_experience | Introduce controlled browser-history routing, protected-route ownership, navigation, loading, empty, error, degraded, unavailable, and not-found experiences. |
| 5 | 317–328 | controlled_api_transport_and_typed_contract_core | Create the single controlled transport, correlation/cancellation/error contracts, approved bearer-token seam, and typed API/domain contract foundations. |
| 6 | 329–344 | authentication_readiness_activation_and_session_experience | Prove configuration, redirect, origin, CORS, CSP, PKCE, callback, network client, token, logout, denial, expiry, and activation gates without weakening Phase 8. |
| 7 | 345–354 | organisation_role_entitlement_and_audit_experience | Expose approved organisation, tenant, role, entitlement, access-denial, audit, and controlled-administration context. |
| 8 | 355–366 | engineering_capability_vertical_slices | Integrate selection, troubleshooting, knowledge, ingestion, document processing, calculations, design cases, datasheets, and project entry points as reviewed vertical slices. |
| 9 | 367–372 | mobile_accessibility_and_degraded_connectivity_hardening | Complete responsive, keyboard, screen-reader, touch-target, slow-network, disconnected, and degraded-state hardening without service-worker caching. |
| 10 | 373–378 | integrated_verification_and_phase9_closure | Run deterministic builds, unit/component/E2E/accessibility/security checks, backend regression, synchronized Git verification, and committed-head closure evidence. |

## Control rules

- The ranges are contiguous and non-overlapping.
- Recovery packages retain the parent step number.
- Each step requires its own reviewed contract and acceptance gate.
- A later range never authorizes bypass of an earlier readiness, security, accessibility, or evidence gate.
- Authentication remains inactive until its separate gates pass.
- Service workers and PWA caching remain initially disabled.
- Native Android/iOS packaging is not authorized in this allocation.
- Voice remains deferred to Phase 10.

## Immediate successor

**Step 283:** Exact static-analysis parse-error source qualification and frontend foundation readiness
