import {
  BACKEND_OPERATIONS,
  type ApiMethod,
  type BackendOperationDefinition,
} from "../api/operation-registry";
import type { CapabilityAreaId } from "../foundation";

export type ProtectedCapabilityId = Exclude<CapabilityAreaId, "home">;
export type CapabilityOperationMode = "query" | "command";

export interface CapabilityOperationAllocation {
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly method: ApiMethod;
  readonly pathTemplate: string;
  readonly mode: CapabilityOperationMode;
  readonly source: string;
  readonly sourceLine: number;
  readonly responseModel: string | null;
}

interface AllocationRule {
  readonly capabilityId: ProtectedCapabilityId;
  readonly pathPrefixes: readonly string[];
}

export const PROTECTED_CAPABILITY_IDS = Object.freeze([
  "selection",
  "troubleshooting",
  "knowledge",
  "ingestion",
  "calculations",
  "designs",
  "projects",
  "security",
] as const satisfies readonly ProtectedCapabilityId[]);

const ALLOCATION_RULES = Object.freeze([
  {
    capabilityId: "selection",
    pathPrefixes: [
      "/api/v1/manufacturers",
      "/api/v1/measurements",
      "/api/v1/product-families",
      "/api/v1/products",
      "/api/v1/protocols",
      "/api/v1/selections",
    ],
  },
  { capabilityId: "knowledge", pathPrefixes: ["/api/v1/knowledge"] },
  { capabilityId: "ingestion", pathPrefixes: ["/api/v1/ingestion"] },
  { capabilityId: "calculations", pathPrefixes: ["/api/v1/calculations"] },
  {
    capabilityId: "designs",
    pathPrefixes: ["/api/v1/design-runs", "/api/v1/designs"],
  },
] as const satisfies readonly AllocationRule[]);

function pathMatchesPrefix(pathTemplate: string, prefix: string): boolean {
  return pathTemplate === prefix || pathTemplate.startsWith(`${prefix}/`);
}

function capabilityForOperation(
  operation: BackendOperationDefinition,
): ProtectedCapabilityId {
  const matches = ALLOCATION_RULES.filter((rule) =>
    rule.pathPrefixes.some((prefix) =>
      pathMatchesPrefix(operation.pathTemplate, prefix),
    ),
  );
  if (matches.length !== 1) {
    throw new Error(
      `Protected operation ${operation.key} must have exactly one capability owner.`,
    );
  }
  return matches[0]!.capabilityId;
}

const PROTECTED_OPERATIONS = BACKEND_OPERATIONS.filter(
  (operation) => operation.frontendAccessPolicy === "authenticated",
);

export const PROTECTED_OPERATION_ALLOCATIONS = Object.freeze(
  PROTECTED_OPERATIONS.map((operation): CapabilityOperationAllocation =>
    Object.freeze({
      capabilityId: capabilityForOperation(operation),
      operationKey: operation.key,
      method: operation.method,
      pathTemplate: operation.pathTemplate,
      mode: operation.method === "GET" ? "query" : "command",
      source: operation.source,
      sourceLine: operation.sourceLine,
      responseModel: operation.responseModel,
    }),
  ),
);

const ALLOCATIONS_BY_CAPABILITY: ReadonlyMap<
  ProtectedCapabilityId,
  readonly CapabilityOperationAllocation[]
> = new Map(
  PROTECTED_CAPABILITY_IDS.map((capabilityId) => [
    capabilityId,
    Object.freeze(
      PROTECTED_OPERATION_ALLOCATIONS.filter(
        (allocation) => allocation.capabilityId === capabilityId,
      ),
    ),
  ] as const),
);

const ALLOCATION_BY_OPERATION_KEY: ReadonlyMap<
  string,
  CapabilityOperationAllocation
> = new Map(
  PROTECTED_OPERATION_ALLOCATIONS.map((allocation) => [
    allocation.operationKey,
    allocation,
  ] as const),
);

export function getCapabilityOperationAllocations(
  capabilityId: ProtectedCapabilityId,
): readonly CapabilityOperationAllocation[] {
  return ALLOCATIONS_BY_CAPABILITY.get(capabilityId) ?? Object.freeze([]);
}

export function getCapabilityOperationAllocationByKey(
  operationKey: string,
): CapabilityOperationAllocation {
  const allocation = ALLOCATION_BY_OPERATION_KEY.get(operationKey);
  if (!allocation) {
    throw new Error(`Operation ${operationKey} is not allocated to a protected capability.`);
  }
  return allocation;
}
