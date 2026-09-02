import { isJsonValue, type JsonValue } from "../contracts";
import {
  getCapabilityOperationAllocationByKey,
  type ProtectedCapabilityId,
} from "./operation-allocation";
import type { CapabilityWorkspaceResult } from "./contracts";

export type CapabilityAdapterErrorKind =
  | "adapter_unavailable"
  | "invalid_request"
  | "cancelled"
  | "script_exhausted"
  | "scripted_failure";

export class CapabilityAdapterError extends Error {
  readonly kind: CapabilityAdapterErrorKind;
  readonly safeMessage: string;
  readonly retryAutomatically = false;

  constructor(kind: CapabilityAdapterErrorKind, safeMessage: string) {
    super(safeMessage);
    this.name = "CapabilityAdapterError";
    this.kind = kind;
    this.safeMessage = safeMessage;
  }
}

export interface CapabilityCommandAuthorization {
  readonly authorized: true;
  readonly reason: string;
  readonly approvalOwner: "user_or_authorized_organisation";
}

export interface CapabilityAdapterRequest {
  readonly requestId: string;
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly input: JsonValue;
  readonly commandAuthorization?: CapabilityCommandAuthorization;
  readonly signal?: AbortSignal;
}

export interface ProtectedCapabilityAdapter {
  readonly executionMode: "inactive" | "in_memory_contract_only";
  readonly liveTransportActive: false;
  readonly automaticRetry: false;
  execute(request: CapabilityAdapterRequest): Promise<CapabilityWorkspaceResult>;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

export function validateCapabilityAdapterRequest(
  request: CapabilityAdapterRequest,
): void {
  if (!REQUEST_ID_PATTERN.test(request.requestId)) {
    throw new CapabilityAdapterError(
      "invalid_request",
      "The capability request identifier is invalid.",
    );
  }
  if (!isJsonValue(request.input)) {
    throw new CapabilityAdapterError(
      "invalid_request",
      "The capability request input is not finite JSON.",
    );
  }
  const allocation = getCapabilityOperationAllocationByKey(request.operationKey);
  if (allocation.capabilityId !== request.capabilityId) {
    throw new CapabilityAdapterError(
      "invalid_request",
      "The capability operation is not owned by the requested workspace.",
    );
  }
  if (allocation.mode === "command") {
    const authorization = request.commandAuthorization;
    if (
      authorization?.authorized !== true ||
      authorization.approvalOwner !== "user_or_authorized_organisation" ||
      typeof authorization.reason !== "string" ||
      authorization.reason.trim().length < 8 ||
      authorization.reason.trim().length > 512 ||
      /[\u0000-\u001f\u007f]/u.test(authorization.reason)
    ) {
      throw new CapabilityAdapterError(
        "invalid_request",
        "An explicit user or authorized-organisation command authorization is required.",
      );
    }
  } else if (request.commandAuthorization !== undefined) {
    throw new CapabilityAdapterError(
      "invalid_request",
      "Command authorization cannot be attached to a read-only capability query.",
    );
  }
  if (request.signal?.aborted) {
    throw new CapabilityAdapterError(
      "cancelled",
      "The capability request was cancelled before execution.",
    );
  }
}

export const INACTIVE_CAPABILITY_ADAPTER: ProtectedCapabilityAdapter =
  Object.freeze({
    executionMode: "inactive" as const,
    liveTransportActive: false as const,
    automaticRetry: false as const,
    execute: async () => {
      throw new CapabilityAdapterError(
        "adapter_unavailable",
        "The protected capability adapter is not active in the running application.",
      );
    },
  });
