const FORBIDDEN_REQUEST_HEADER = /^(?:authorization|cookie|host|origin|proxy-authorization|referer|set-cookie)$/iu;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;
const JSON_MEDIA_TYPE = /^(?:application\/(?:json|[A-Za-z0-9.+-]+\+json))(?:\s*;.*)?$/iu;

export interface MsalNetworkRequestOptions {
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
}

export interface MsalNetworkResponse<T> {
  readonly headers: Readonly<Record<string, string>>;
  readonly body: T;
  readonly status: number;
}

export interface MsalNetworkModulePort {
  sendGetRequestAsync<T>(url: string, options?: MsalNetworkRequestOptions): Promise<MsalNetworkResponse<T>>;
  sendPostRequestAsync<T>(url: string, options?: MsalNetworkRequestOptions): Promise<MsalNetworkResponse<T>>;
}

export interface ControlledMsalNetworkDependencies {
  readonly allowedOrigins: readonly string[];
  readonly fetcher: typeof fetch;
  readonly timeoutMs?: number;
  readonly maximumResponseBytes?: number;
  readonly maximumRequestBodyBytes?: number;
}

function boundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) {
    throw new Error(`${label} is outside the controlled range.`);
  }
  return result;
}

function reviewedOrigin(value: string): string {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error("MSAL network origins must be credential-free HTTPS origins.");
  }
  return parsed.origin;
}

function requestHeaders(input: Readonly<Record<string, string>> | undefined): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(input ?? {})) {
    if (!HEADER_NAME.test(name) || FORBIDDEN_REQUEST_HEADER.test(name)) {
      throw new Error("MSAL network request contains a forbidden header name.");
    }
    if (value.length > 4096 || CONTROL_PATTERN.test(value)) {
      throw new Error("MSAL network request contains an unsafe header value.");
    }
    result.set(name, value);
  }
  result.set("Accept", "application/json");
  return result;
}

function responseHeaders(input: Headers): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  let count = 0;
  for (const [name, value] of input.entries()) {
    if (count >= 100) throw new Error("MSAL network response header count is unbounded.");
    if (!FORBIDDEN_REQUEST_HEADER.test(name) && value.length <= 4096 && !CONTROL_PATTERN.test(value)) {
      result[name.toLowerCase()] = value;
    }
    count += 1;
  }
  return Object.freeze(result);
}

export function createControlledMsalNetworkClient(
  dependencies: ControlledMsalNetworkDependencies,
): MsalNetworkModulePort {
  if (dependencies.allowedOrigins.length === 0 || dependencies.allowedOrigins.length > 16) {
    throw new Error("MSAL network origin allowlist must contain between 1 and 16 entries.");
  }
  const allowedOrigins = new Set(dependencies.allowedOrigins.map(reviewedOrigin));
  const timeoutMs = boundedInteger(dependencies.timeoutMs, 15_000, 120_000, "MSAL network timeout");
  const maximumResponseBytes = boundedInteger(
    dependencies.maximumResponseBytes,
    1_000_000,
    5_000_000,
    "MSAL network response bound",
  );
  const maximumRequestBodyBytes = boundedInteger(
    dependencies.maximumRequestBodyBytes,
    256_000,
    1_000_000,
    "MSAL network request-body bound",
  );

  async function send<T>(method: "GET" | "POST", value: string, options?: MsalNetworkRequestOptions): Promise<MsalNetworkResponse<T>> {
    const url = new URL(value);
    if (!allowedOrigins.has(url.origin) || url.protocol !== "https:" || url.username || url.password || url.hash) {
      throw new Error("MSAL network request crossed the reviewed authority-origin boundary.");
    }
    const body = options?.body;
    if (method === "GET" && body !== undefined) {
      throw new Error("MSAL GET requests cannot include a body.");
    }
    if (body !== undefined && new TextEncoder().encode(body).byteLength > maximumRequestBodyBytes) {
      throw new Error("MSAL network request body exceeds the controlled bound.");
    }
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await dependencies.fetcher(url, {
        method,
        headers: requestHeaders(options?.headers),
        ...(body === undefined ? {} : { body }),
        signal: controller.signal,
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      const contentType = response.headers.get("content-type") ?? "";
      if (!JSON_MEDIA_TYPE.test(contentType)) {
        throw new Error("MSAL network response is not an approved JSON media type.");
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > maximumResponseBytes) {
        throw new Error("MSAL network response exceeds the controlled byte bound.");
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const parsed = JSON.parse(text) as T;
      return Object.freeze({
        headers: responseHeaders(response.headers),
        body: parsed,
        status: response.status,
      });
    } finally {
      window.clearTimeout(timer);
    }
  }

  return Object.freeze({
    sendGetRequestAsync: <T>(url: string, options?: MsalNetworkRequestOptions) => send<T>("GET", url, options),
    sendPostRequestAsync: <T>(url: string, options?: MsalNetworkRequestOptions) => send<T>("POST", url, options),
  });
}
