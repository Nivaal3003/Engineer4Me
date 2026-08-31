/**
 * Default-deny network guard for the Vitest/jsdom environment.
 *
 * Unit and component tests must not make real network requests. Tests that need
 * transport behavior must use explicit in-memory fakes in later controlled
 * transport milestones.
 */
export const BLOCKED_UNIT_TEST_NETWORK_MESSAGE =
  "Engineer4Me unit-test network access is blocked by default." as const;

export class UnexpectedUnitTestNetworkRequestError extends Error {
  constructor(channel: "fetch" | "xml_http_request", target: string) {
    super(`${BLOCKED_UNIT_TEST_NETWORK_MESSAGE} channel=${channel}; target=${target}`);
    this.name = "UnexpectedUnitTestNetworkRequestError";
  }
}

function targetText(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof URL) {
    return value.toString();
  }
  if (typeof Request !== "undefined" && value instanceof Request) {
    return value.url;
  }
  return String(value);
}

export function installUnitTestNetworkGuard(): () => void {
  const globalWithOptionalFetch = globalThis as unknown as {
    fetch?: typeof fetch;
  };
  const originalFetch = globalWithOptionalFetch.fetch;
  const originalXhrOpen = XMLHttpRequest.prototype.open;
  let restored = false;

  globalWithOptionalFetch.fetch = ((input: RequestInfo | URL) =>
    Promise.reject(
      new UnexpectedUnitTestNetworkRequestError("fetch", targetText(input)),
    )) as typeof fetch;

  XMLHttpRequest.prototype.open = function blockedXmlHttpRequestOpen(
    _method: string,
    url: string | URL,
  ): void {
    throw new UnexpectedUnitTestNetworkRequestError(
      "xml_http_request",
      targetText(url),
    );
  } as unknown as typeof originalXhrOpen;

  return () => {
    if (restored) {
      return;
    }
    restored = true;
    if (originalFetch) {
      globalWithOptionalFetch.fetch = originalFetch;
    } else {
      delete globalWithOptionalFetch.fetch;
    }
    XMLHttpRequest.prototype.open = originalXhrOpen;
  };
}
