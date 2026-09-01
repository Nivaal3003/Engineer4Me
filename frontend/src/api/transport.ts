import { assertJsonValue, type JsonValue } from "../contracts";
import { createRequestAbortHandle } from "./cancellation";
import type { ApiTransportConfiguration } from "./configuration";
import { resolveSameOriginApiUrl } from "./configuration";
import { CORRELATION_ID_HEADER, validateCorrelationId } from "./correlation";
import { ApiTransportError, normalizeTransportFailure } from "./errors";
import { getBackendOperation } from "./operation-registry";
import { materializeOperationPath, type PathParameterValues } from "./path-parameters";
import { appendDeterministicQuery, type ApiQuery } from "./query";
import { readControlledJsonResponse } from "./response";
import {
  INACTIVE_BEARER_TOKEN_PROVIDER,
  bearerAuthorizationHeader,
  type BearerTokenProvider,
} from "./token";

export interface ApiTransportRequest {
  readonly operationKey: string;
  readonly pathParameters?: PathParameterValues;
  readonly query?: ApiQuery;
  readonly body?: JsonValue;
  readonly signal?: AbortSignal;
  readonly correlationId?: string;
}

export interface ApiTransportSuccess<T extends JsonValue | null = JsonValue | null> {
  readonly data: T;
  readonly status: number;
  readonly correlationId: string;
}

export interface ControlledApiTransport {
  execute<T extends JsonValue | null = JsonValue | null>(
    request: ApiTransportRequest,
  ): Promise<ApiTransportSuccess<T>>;
}

export interface ControlledApiTransportDependencies {
  readonly configuration: ApiTransportConfiguration;
  readonly fetcher: typeof fetch;
  readonly createCorrelationId: () => string;
  readonly tokenProvider?: BearerTokenProvider;
}

export function createControlledApiTransport(
  dependencies: ControlledApiTransportDependencies,
): ControlledApiTransport {
  const tokenProvider = dependencies.tokenProvider ?? INACTIVE_BEARER_TOKEN_PROVIDER;
  return Object.freeze({
    execute: async <T extends JsonValue | null = JsonValue | null>(
      request: ApiTransportRequest,
    ): Promise<ApiTransportSuccess<T>> => {
      const operation = getBackendOperation(request.operationKey);
      const correlationId = validateCorrelationId(
        request.correlationId ?? dependencies.createCorrelationId(),
      );
      const path = materializeOperationPath(
        operation.pathTemplate,
        request.pathParameters,
      );
      const url = appendDeterministicQuery(
        resolveSameOriginApiUrl(dependencies.configuration, path),
        request.query,
      );
      if ((operation.method === "GET" || operation.method === "DELETE") && request.body !== undefined) {
        throw new ApiTransportError({
          kind: "configuration",
          safeMessage: "This operation does not permit a JSON request body.",
          correlationId,
          status: null,
          retryable: false,
        });
      }
      const headers = new Headers({
        Accept: "application/json",
        [CORRELATION_ID_HEADER]: correlationId,
      });
      if (operation.frontendAccessPolicy === "authenticated") {
        const token = await tokenProvider.getAccessToken({ operation, correlationId });
        if (token === null) {
          throw new ApiTransportError({
            kind: "authorization_unavailable",
            safeMessage: "A controlled access token is required before this operation can run.",
            correlationId,
            status: null,
            retryable: false,
          });
        }
        headers.set("Authorization", bearerAuthorizationHeader(token));
      }
      let body: string | undefined;
      if (request.body !== undefined) {
        assertJsonValue(request.body);
        body = JSON.stringify(request.body);
        headers.set("Content-Type", "application/json");
      }
      const abort = createRequestAbortHandle({
        timeoutMs: dependencies.configuration.requestTimeoutMs,
        ...(request.signal ? { parentSignal: request.signal } : {}),
      });
      try {
        const requestInit: RequestInit = {
          method: operation.method,
          headers,
          signal: abort.signal,
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          referrerPolicy: "no-referrer",
          ...(body === undefined ? {} : { body }),
        };
        const response = await dependencies.fetcher(url, requestInit);
        if (!response.ok) {
          throw new ApiTransportError({
            kind: "http",
            safeMessage: "The API returned an unsuccessful response.",
            correlationId,
            status: response.status,
            retryable: false,
          });
        }
        const data = await readControlledJsonResponse({
          response,
          maximumBytes: dependencies.configuration.maximumResponseBytes,
          correlationId,
        });
        return Object.freeze({ data: data as T, status: response.status, correlationId });
      } catch (error) {
        throw normalizeTransportFailure(error, correlationId);
      } finally {
        abort.dispose();
      }
    },
  });
}
