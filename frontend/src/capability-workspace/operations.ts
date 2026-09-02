import { isJsonValue, type JsonValue } from "../contracts";
import {
  getProtectedCapabilityAdapterDefinition,
  type CapabilityCommandAuthorization,
  type CapabilityOperationAllocation,
  type CapabilityOperationMode,
  type ProtectedCapabilityId,
} from "../capabilities";

export interface CapabilityOperationViewModel {
  readonly operationKey: string;
  readonly method: string;
  readonly mode: CapabilityOperationMode;
  readonly pathTemplate: string;
  readonly responseModelLabel: string;
  readonly sourceReference: string;
  readonly commandAuthorizationRequired: boolean;
}

export interface CapabilityOperationCatalogueViewModel {
  readonly capabilityId: ProtectedCapabilityId;
  readonly state: "prepared_in_memory_contract_only" | "no_accepted_backend_operation";
  readonly totalOperationCount: number;
  readonly queryOperationCount: number;
  readonly commandOperationCount: number;
  readonly representativeQuery: CapabilityOperationViewModel | null;
  readonly representativeCommand: CapabilityOperationViewModel | null;
  readonly liveTransportActive: false;
  readonly automaticRetry: false;
  readonly commandExecutionAutomatic: false;
}

export interface CapabilityRequestPreview {
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly mode: CapabilityOperationMode;
  readonly input: JsonValue;
  readonly commandAuthorization: CapabilityCommandAuthorization | null;
  readonly executionAuthorized: false;
  readonly liveTransportActive: false;
}

function operationView(
  operation: CapabilityOperationAllocation,
): CapabilityOperationViewModel {
  return Object.freeze({
    operationKey: operation.operationKey,
    method: operation.method,
    mode: operation.mode,
    pathTemplate: operation.pathTemplate,
    responseModelLabel: operation.responseModel ?? "No declared response model",
    sourceReference: `${operation.source}:${operation.sourceLine}`,
    commandAuthorizationRequired: operation.mode === "command",
  });
}

function sortOperations(
  operations: readonly CapabilityOperationAllocation[],
): readonly CapabilityOperationAllocation[] {
  return Object.freeze([...operations].sort((left, right) =>
    left.mode.localeCompare(right.mode) ||
    left.pathTemplate.localeCompare(right.pathTemplate) ||
    left.operationKey.localeCompare(right.operationKey),
  ));
}

export function createCapabilityOperationCatalogue(
  capabilityId: ProtectedCapabilityId,
): CapabilityOperationCatalogueViewModel {
  const definition = getProtectedCapabilityAdapterDefinition(capabilityId);
  const operations = sortOperations(definition.allocatedOperations);
  const queries = operations.filter((item) => item.mode === "query");
  const commands = operations.filter((item) => item.mode === "command");
  return Object.freeze({
    capabilityId,
    state: definition.state,
    totalOperationCount: definition.operationCount,
    queryOperationCount: queries.length,
    commandOperationCount: commands.length,
    representativeQuery: queries[0] ? operationView(queries[0]) : null,
    representativeCommand: commands[0] ? operationView(commands[0]) : null,
    liveTransportActive: false,
    automaticRetry: false,
    commandExecutionAutomatic: false,
  });
}

export function createCapabilityRequestPreview(input: {
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly operationMode: CapabilityOperationMode;
  readonly input: JsonValue;
  readonly commandAuthorization?: CapabilityCommandAuthorization;
}): CapabilityRequestPreview {
  if (!isJsonValue(input.input)) {
    throw new TypeError("Capability request preview input must be finite JSON.");
  }
  const catalogue = createCapabilityOperationCatalogue(input.capabilityId);
  const operation = catalogue.state === "prepared_in_memory_contract_only"
    ? getProtectedCapabilityAdapterDefinition(input.capabilityId).allocatedOperations.find(
        (item) => item.operationKey === input.operationKey,
      )
    : undefined;
  if (!operation || operation.mode !== input.operationMode) {
    throw new TypeError("Capability request preview operation is not owned by this workspace.");
  }
  if (operation.mode === "command") {
    if (
      input.commandAuthorization?.authorized !== true ||
      input.commandAuthorization.approvalOwner !== "user_or_authorized_organisation"
    ) {
      throw new TypeError("A command request preview requires explicit user or organisation authorization.");
    }
  } else if (input.commandAuthorization !== undefined) {
    throw new TypeError("A query request preview cannot include command authorization.");
  }
  return Object.freeze({
    capabilityId: input.capabilityId,
    operationKey: input.operationKey,
    mode: operation.mode,
    input: JSON.parse(JSON.stringify(input.input)) as JsonValue,
    commandAuthorization: input.commandAuthorization ?? null,
    executionAuthorized: false,
    liveTransportActive: false,
  });
}
