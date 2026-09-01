export type ApiTransportErrorKind =
  | "configuration"
  | "operation_not_registered"
  | "authorization_unavailable"
  | "request_cancelled"
  | "network"
  | "http"
  | "response_content_type"
  | "response_too_large"
  | "response_invalid_json";

export interface ApiTransportErrorDetails {
  readonly kind: ApiTransportErrorKind;
  readonly safeMessage: string;
  readonly correlationId: string | null;
  readonly status: number | null;
  readonly retryable: boolean;
}

export class ApiTransportError extends Error implements ApiTransportErrorDetails {
  readonly kind: ApiTransportErrorKind;
  readonly safeMessage: string;
  readonly correlationId: string | null;
  readonly status: number | null;
  readonly retryable: boolean;

  constructor(details: ApiTransportErrorDetails, options?: ErrorOptions) {
    super(details.safeMessage, options);
    this.name = "ApiTransportError";
    this.kind = details.kind;
    this.safeMessage = details.safeMessage;
    this.correlationId = details.correlationId;
    this.status = details.status;
    this.retryable = details.retryable;
  }
}

export function normalizeTransportFailure(
  error: unknown,
  correlationId: string | null,
): ApiTransportError {
  if (error instanceof ApiTransportError) {
    return error;
  }
  if (
    error instanceof DOMException &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  ) {
    return new ApiTransportError({
      kind: "request_cancelled",
      safeMessage: "The request was cancelled before completion.",
      correlationId,
      status: null,
      retryable: false,
    }, { cause: error });
  }
  return new ApiTransportError({
    kind: "network",
    safeMessage: "The controlled API request could not be completed.",
    correlationId,
    status: null,
    retryable: false,
  }, { cause: error });
}
