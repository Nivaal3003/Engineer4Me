import { type JsonValue } from "../contracts";
import {
  CapabilityAdapterError,
  validateCapabilityAdapterRequest,
  type CapabilityAdapterRequest,
  type ProtectedCapabilityAdapter,
} from "./adapter";
import {
  decodeCapabilityWorkspaceResult,
  type CapabilityWorkspaceResult,
} from "./contracts";
import type { ProtectedCapabilityId } from "./operation-allocation";

export type ScriptedCapabilityAdapterEntry =
  | { readonly kind: "result"; readonly value: unknown }
  | { readonly kind: "failure"; readonly safeMessage: string };

export interface RecordedCapabilityAdapterCall {
  readonly requestId: string;
  readonly capabilityId: ProtectedCapabilityId;
  readonly operationKey: string;
  readonly input: JsonValue;
}

export interface ScriptedCapabilityAdapter {
  readonly adapter: ProtectedCapabilityAdapter;
  readonly calls: readonly RecordedCapabilityAdapterCall[];
  readonly networkRequestsPerformed: false;
  remaining(): number;
}

function safeFailureMessage(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 240 ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new TypeError("Scripted capability failure message is invalid.");
  }
  return normalized;
}

function cloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function createScriptedCapabilityAdapter(
  capabilityId: ProtectedCapabilityId,
  script: readonly ScriptedCapabilityAdapterEntry[],
): ScriptedCapabilityAdapter {
  const queue = [...script];
  const calls: RecordedCapabilityAdapterCall[] = [];
  const adapter: ProtectedCapabilityAdapter = Object.freeze({
    executionMode: "in_memory_contract_only" as const,
    liveTransportActive: false as const,
    automaticRetry: false as const,
    execute: async (
      request: CapabilityAdapterRequest,
    ): Promise<CapabilityWorkspaceResult> => {
      validateCapabilityAdapterRequest(request);
      if (request.capabilityId !== capabilityId) {
        throw new CapabilityAdapterError(
          "invalid_request",
          "The scripted adapter does not own the requested capability.",
        );
      }
      calls.push(Object.freeze({
        requestId: request.requestId,
        capabilityId: request.capabilityId,
        operationKey: request.operationKey,
        input: cloneJson(request.input),
      }));
      const entry = queue.shift();
      if (!entry) {
        throw new CapabilityAdapterError(
          "script_exhausted",
          "No in-memory capability response remains.",
        );
      }
      if (entry.kind === "failure") {
        throw new CapabilityAdapterError(
          "scripted_failure",
          safeFailureMessage(entry.safeMessage),
        );
      }
      return decodeCapabilityWorkspaceResult(entry.value, {
        capabilityId: request.capabilityId,
        operationKey: request.operationKey,
      });
    },
  });
  return Object.freeze({
    adapter,
    calls,
    networkRequestsPerformed: false as const,
    remaining: () => queue.length,
  });
}
