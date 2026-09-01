import type { JsonValue } from "../contracts";
import { isJsonValue } from "../contracts";
import { ApiTransportError } from "./errors";

function isJsonContentType(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  const mediaType = value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

export async function readControlledJsonResponse(input: {
  readonly response: Response;
  readonly maximumBytes: number;
  readonly correlationId: string;
}): Promise<JsonValue | null> {
  if (input.response.status === 204 || input.response.status === 205) {
    return null;
  }
  const contentLength = input.response.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > input.maximumBytes) {
      throw new ApiTransportError({
        kind: "response_too_large",
        safeMessage: "The API response exceeded the controlled size limit.",
        correlationId: input.correlationId,
        status: input.response.status,
        retryable: false,
      });
    }
  }
  if (!isJsonContentType(input.response.headers.get("content-type"))) {
    throw new ApiTransportError({
      kind: "response_content_type",
      safeMessage: "The API response did not use an approved JSON content type.",
      correlationId: input.correlationId,
      status: input.response.status,
      retryable: false,
    });
  }
  const bytes = new Uint8Array(await input.response.arrayBuffer());
  if (bytes.byteLength > input.maximumBytes) {
    throw new ApiTransportError({
      kind: "response_too_large",
      safeMessage: "The API response exceeded the controlled size limit.",
      correlationId: input.correlationId,
      status: input.response.status,
      retryable: false,
    });
  }
  let parsed: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text.length === 0 || text.charCodeAt(0) === 0xfeff) {
      throw new Error("Empty or BOM-prefixed JSON is not accepted.");
    }
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw new ApiTransportError({
      kind: "response_invalid_json",
      safeMessage: "The API response was not valid UTF-8 JSON.",
      correlationId: input.correlationId,
      status: input.response.status,
      retryable: false,
    }, { cause: error });
  }
  if (!isJsonValue(parsed)) {
    throw new ApiTransportError({
      kind: "response_invalid_json",
      safeMessage: "The API response was outside the supported JSON value boundary.",
      correlationId: input.correlationId,
      status: input.response.status,
      retryable: false,
    });
  }
  return parsed;
}
