/** Fail-closed Phase 9 product boundaries shared by future UI surfaces. */
export type BoundaryDisposition =
  | "required"
  | "inactive"
  | "blocked"
  | "deferred";

export interface ProductBoundary {
  readonly id: string;
  readonly disposition: BoundaryDisposition;
  readonly rationale: string;
}

export const PHASE_9_PRODUCT_BOUNDARIES = Object.freeze([
  {
    id: "authentication_activation",
    disposition: "inactive",
    rationale: "Separate configuration, redirect, origin, CORS, CSP, PKCE, callback, token, network-client, and logout gates are required.",
  },
  {
    id: "bearer_token_attachment",
    disposition: "blocked",
    rationale: "Tokens may be attached only by the later approved controlled transport on approved protected routes.",
  },
  {
    id: "service_worker_and_pwa_caching",
    disposition: "blocked",
    rationale: "Initial Phase 9 implementation must expose connectivity state without cache or background-sync activation.",
  },
  {
    id: "native_mobile_packaging",
    disposition: "deferred",
    rationale: "Android and iOS packaging are outside the current browser-product authorization.",
  },
  {
    id: "voice_functionality",
    disposition: "deferred",
    rationale: "Voice commands and voice search remain assigned to Phase 10.",
  },
  {
    id: "vendor_neutrality",
    disposition: "required",
    rationale: "The product may present evidence and calculations but must not choose a best brand for the user.",
  },
  {
    id: "standards_conformity",
    disposition: "required",
    rationale: "The UI must not claim conformity unless a separately controlled conformity basis exists.",
  },
  {
    id: "proprietary_and_trademark_identification",
    disposition: "required",
    rationale: "Generic categories, proprietary technologies, trademarks, ownership acknowledgements, and any claimed equivalence must remain explicitly distinguishable.",
  },
  {
    id: "engineering_and_operational_approval",
    disposition: "required",
    rationale: "Final engineering approval and operational authorization remain user or authorized-organisation responsibilities.",
  },
] satisfies readonly ProductBoundary[]);
