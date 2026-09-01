import { ApiTransportError, normalizeTransportFailure } from "./errors";

describe("API transport errors", () => {
  it("preserves already-normalized errors", () => {
    const error = new ApiTransportError({
      kind: "http",
      safeMessage: "Request failed.",
      correlationId: "e4m-00000000000000000000000000000000",
      status: 500,
      retryable: false,
    });
    expect(normalizeTransportFailure(error, null)).toBe(error);
  });

  it("does not disclose arbitrary underlying error text", () => {
    const normalized = normalizeTransportFailure(new Error("secret detail"), null);
    expect(normalized.safeMessage).toBe("The controlled API request could not be completed.");
    expect(normalized.safeMessage).not.toContain("secret detail");
  });
});
