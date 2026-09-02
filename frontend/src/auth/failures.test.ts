import { normalizeAuthenticationFailure } from "./failures";

describe("authentication failure normalization", () => {
  it("does not expose arbitrary provider error details", () => {
    const failure = normalizeAuthenticationFailure({
      name: "ProviderError",
      message: "access_token=secret-value",
      stack: "sensitive stack",
    }, "correlation-1");
    expect(failure.safeMessage).toBe("The identity provider operation could not be completed.");
    expect(JSON.stringify(failure)).not.toContain("secret-value");
    expect(failure.retryAutomatically).toBe(false);
  });

  it("classifies interaction-required and cancellation outcomes safely", () => {
    expect(normalizeAuthenticationFailure({ errorCode: "interaction_required" }, "corr-2").kind)
      .toBe("interaction_required");
    expect(normalizeAuthenticationFailure({ name: "AbortError" }, "corr-3").kind)
      .toBe("cancelled");
  });
});
