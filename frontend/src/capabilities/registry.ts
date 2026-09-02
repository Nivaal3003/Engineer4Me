import {
  PROTECTED_CAPABILITY_IDS,
  getCapabilityOperationAllocations,
  type CapabilityOperationAllocation,
  type ProtectedCapabilityId,
} from "./operation-allocation";

export type CapabilityAdapterReadinessState =
  | "prepared_in_memory_contract_only"
  | "no_accepted_backend_operation";

export interface ProtectedCapabilityAdapterDefinition {
  readonly capabilityId: ProtectedCapabilityId;
  readonly state: CapabilityAdapterReadinessState;
  readonly allocatedOperations: readonly CapabilityOperationAllocation[];
  readonly operationCount: number;
  readonly queryOperationCount: number;
  readonly commandOperationCount: number;
  readonly reason: string;
  readonly liveTransportActive: false;
  readonly automaticRetry: false;
  readonly protectedContentAvailable: false;
}

function createDefinition(
  capabilityId: ProtectedCapabilityId,
): ProtectedCapabilityAdapterDefinition {
  const allocatedOperations = getCapabilityOperationAllocations(capabilityId);
  const operationCount = allocatedOperations.length;
  return Object.freeze({
    capabilityId,
    state: operationCount > 0
      ? "prepared_in_memory_contract_only"
      : "no_accepted_backend_operation",
    allocatedOperations,
    operationCount,
    queryOperationCount: allocatedOperations.filter((item) => item.mode === "query").length,
    commandOperationCount: allocatedOperations.filter((item) => item.mode === "command").length,
    reason: operationCount > 0
      ? "Accepted backend operations are allocated for in-memory contract verification only."
      : "No accepted backend operation is allocated to this capability route.",
    liveTransportActive: false,
    automaticRetry: false,
    protectedContentAvailable: false,
  });
}

export const PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS = Object.freeze(
  PROTECTED_CAPABILITY_IDS.map(createDefinition),
);

const DEFINITIONS_BY_ID: ReadonlyMap<
  ProtectedCapabilityId,
  ProtectedCapabilityAdapterDefinition
> = new Map(
  PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS.map((definition) => [
    definition.capabilityId,
    definition,
  ] as const),
);

export function getProtectedCapabilityAdapterDefinition(
  capabilityId: ProtectedCapabilityId,
): ProtectedCapabilityAdapterDefinition {
  const definition = DEFINITIONS_BY_ID.get(capabilityId);
  if (!definition) {
    throw new Error(`Unknown protected capability adapter: ${capabilityId}`);
  }
  return definition;
}
