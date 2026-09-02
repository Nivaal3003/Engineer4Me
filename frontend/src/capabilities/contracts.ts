import {
  isJsonValue,
  type ApprovalStatus,
  type ConfidenceLevel,
  type EvidenceReference,
  type JsonValue,
} from "../contracts";
import {
  getCapabilityOperationAllocationByKey,
  type ProtectedCapabilityId,
} from "./operation-allocation";

export const CAPABILITY_RESULT_STATES = Object.freeze([
  "ready",
  "empty",
  "degraded",
] as const);
export type CapabilityResultState = (typeof CAPABILITY_RESULT_STATES)[number];

export interface CapabilityResultValue {
  readonly title: string;
  readonly summary: string;
  readonly itemCount: number;
  readonly payload: JsonValue;
}

export interface CapabilityResultApproval {
  readonly status: ApprovalStatus;
  readonly owner: string;
  readonly approvedAt: string | null;
}

export interface CapabilityResultControls {
  readonly vendorNeutrality: "required";
  readonly bestBrandDecisionOwner: "user_or_authorized_organisation";
  readonly standardsConformityClaim: "not_claimed";
  readonly proprietaryAndTrademarkIdentification: "required";
  readonly finalEngineeringApprovalOwner: "user_or_authorized_organisation";
  readonly operationalAuthorizationOwner: "user_or_authorized_organisation";
}

export interface CapabilityWorkspaceResult {
  readonly schemaVersion: 1;
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly state: CapabilityResultState;
  readonly value: CapabilityResultValue;
  readonly evidence: readonly EvidenceReference[];
  readonly assumptions: readonly string[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
  readonly confidence: ConfidenceLevel;
  readonly revision: string;
  readonly approval: CapabilityResultApproval;
  readonly controls: CapabilityResultControls;
}

export const CAPABILITY_RESULT_CONTROLS: CapabilityResultControls =
  Object.freeze({
    vendorNeutrality: "required",
    bestBrandDecisionOwner: "user_or_authorized_organisation",
    standardsConformityClaim: "not_claimed",
    proprietaryAndTrademarkIdentification: "required",
    finalEngineeringApprovalOwner: "user_or_authorized_organisation",
    operationalAuthorizationOwner: "user_or_authorized_organisation",
  });

const RESULT_KEYS = new Set([
  "schemaVersion",
  "capabilityId",
  "operationKey",
  "state",
  "value",
  "evidence",
  "assumptions",
  "limitations",
  "warnings",
  "confidence",
  "revision",
  "approval",
  "controls",
]);
const VALUE_KEYS = new Set(["title", "summary", "itemCount", "payload"]);
const EVIDENCE_KEYS = new Set(["sourceId", "title", "revision", "locator"]);
const APPROVAL_KEYS = new Set(["status", "owner", "approvedAt"]);
const CONTROL_KEYS = new Set(Object.keys(CAPABILITY_RESULT_CONTROLS));
const CONFIDENCE_LEVELS = new Set<ConfidenceLevel>([
  "not_assessed",
  "low",
  "medium",
  "high",
]);
const APPROVAL_STATUSES = new Set<ApprovalStatus>([
  "unreviewed",
  "review_required",
  "approved",
  "rejected",
]);

function exactRecord(
  value: unknown,
  keys: ReadonlySet<string>,
  label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !keys.has(key))) {
    throw new TypeError(`${label} contains an unexpected field.`);
  }
  return record;
}

function boundedText(
  value: unknown,
  label: string,
  maximum: number,
): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be text.`);
  }
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new TypeError(`${label} is outside the controlled text boundary.`);
  }
  return normalized;
}

function optionalBoundedText(
  value: unknown,
  label: string,
  maximum: number,
): string | null {
  if (value === null) return null;
  return boundedText(value, label, maximum);
}

function boundedTextArray(
  value: unknown,
  label: string,
  maximumItems: number,
  maximumText: number,
): readonly string[] {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new TypeError(`${label} must be a bounded array.`);
  }
  return Object.freeze(
    value.map((item, index) =>
      boundedText(item, `${label} item ${index + 1}`, maximumText),
    ),
  );
}

function canonicalTimestamp(value: unknown, label: string): string | null {
  if (value === null) return null;
  const timestamp = boundedText(value, label, 40);
  const parsed = new Date(timestamp);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString() !== timestamp) {
    throw new TypeError(`${label} must be a canonical UTC timestamp.`);
  }
  return timestamp;
}

function cloneJson(value: JsonValue): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function decodeEvidence(value: unknown): readonly EvidenceReference[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) {
    throw new TypeError("Capability evidence must contain between 1 and 50 references.");
  }
  return Object.freeze(
    value.map((item, index): EvidenceReference => {
      const input = exactRecord(
        item,
        EVIDENCE_KEYS,
        `Capability evidence ${index + 1}`,
      );
      return Object.freeze({
        sourceId: boundedText(input.sourceId, "Evidence source identifier", 160),
        title: boundedText(input.title, "Evidence title", 240),
        revision: optionalBoundedText(input.revision, "Evidence revision", 120),
        locator: optionalBoundedText(input.locator, "Evidence locator", 240),
      });
    }),
  );
}

export function decodeCapabilityWorkspaceResult(
  value: unknown,
  expected: {
    readonly capabilityId: ProtectedCapabilityId;
    readonly operationKey: string;
  },
): CapabilityWorkspaceResult {
  const input = exactRecord(value, RESULT_KEYS, "Capability workspace result");
  if (input.schemaVersion !== 1) {
    throw new TypeError("Capability result schema version is unsupported.");
  }
  if (input.capabilityId !== expected.capabilityId) {
    throw new TypeError("Capability result ownership differs from the request.");
  }
  if (input.operationKey !== expected.operationKey) {
    throw new TypeError("Capability result operation differs from the request.");
  }
  const allocation = getCapabilityOperationAllocationByKey(expected.operationKey);
  if (allocation.capabilityId !== expected.capabilityId) {
    throw new TypeError("Capability result operation is not allocated to this capability.");
  }
  if (!CAPABILITY_RESULT_STATES.includes(input.state as CapabilityResultState)) {
    throw new TypeError("Capability result state is unsupported.");
  }

  const valueInput = exactRecord(
    input.value,
    VALUE_KEYS,
    "Capability result value",
  );
  if (
    typeof valueInput.itemCount !== "number" ||
    !Number.isSafeInteger(valueInput.itemCount) ||
    valueInput.itemCount < 0 ||
    valueInput.itemCount > 10000
  ) {
    throw new TypeError("Capability item count is invalid.");
  }
  if (!isJsonValue(valueInput.payload)) {
    throw new TypeError("Capability payload must be a finite plain JSON value.");
  }
  const state = input.state as CapabilityResultState;
  if (state === "empty" && valueInput.itemCount !== 0) {
    throw new TypeError("An empty capability result must have an item count of zero.");
  }
  if (state === "ready" && valueInput.itemCount === 0) {
    throw new TypeError("A ready capability result must contain at least one item.");
  }

  if (!CONFIDENCE_LEVELS.has(input.confidence as ConfidenceLevel)) {
    throw new TypeError("Capability confidence is unsupported.");
  }
  const approvalInput = exactRecord(
    input.approval,
    APPROVAL_KEYS,
    "Capability approval",
  );
  if (!APPROVAL_STATUSES.has(approvalInput.status as ApprovalStatus)) {
    throw new TypeError("Capability approval status is unsupported.");
  }
  const approvedAt = canonicalTimestamp(
    approvalInput.approvedAt,
    "Capability approval timestamp",
  );
  if ((approvalInput.status === "approved") !== (approvedAt !== null)) {
    throw new TypeError("Capability approval status and timestamp are inconsistent.");
  }

  const controls = exactRecord(
    input.controls,
    CONTROL_KEYS,
    "Capability result controls",
  );
  for (const [key, expectedValue] of Object.entries(CAPABILITY_RESULT_CONTROLS)) {
    if (controls[key] !== expectedValue) {
      throw new TypeError(`Capability result control ${key} differs.`);
    }
  }

  return Object.freeze({
    schemaVersion: 1,
    capabilityId: expected.capabilityId,
    operationKey: expected.operationKey,
    state,
    value: Object.freeze({
      title: boundedText(valueInput.title, "Capability result title", 160),
      summary: boundedText(valueInput.summary, "Capability result summary", 1000),
      itemCount: valueInput.itemCount,
      payload: cloneJson(valueInput.payload),
    }),
    evidence: decodeEvidence(input.evidence),
    assumptions: boundedTextArray(input.assumptions, "Capability assumptions", 50, 500),
    limitations: boundedTextArray(input.limitations, "Capability limitations", 50, 500),
    warnings: boundedTextArray(input.warnings, "Capability warnings", 50, 500),
    confidence: input.confidence as ConfidenceLevel,
    revision: boundedText(input.revision, "Capability revision", 128),
    approval: Object.freeze({
      status: approvalInput.status as ApprovalStatus,
      owner: boundedText(approvalInput.owner, "Capability approval owner", 160),
      approvedAt,
    }),
    controls: CAPABILITY_RESULT_CONTROLS,
  });
}
