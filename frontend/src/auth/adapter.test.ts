import {
  AuthenticationActivationRequiredError,
  INACTIVE_AUTHENTICATION_PROVIDER,
} from "./adapter";

describe("inactive authentication provider", () => {
  it("does not initialize an account or return an access token", async () => {
    await expect(INACTIVE_AUTHENTICATION_PROVIDER.initialize()).resolves.toEqual({ state: "inactive" });
    await expect(INACTIVE_AUTHENTICATION_PROVIDER.requestAccessToken({
      apiScope: "api://example.test/access",
      correlationId: "correlation-1",
      operationKey: "operation-1",
      principalKey: "tenant-1:subject-1",
    })).resolves.toBeNull();
  });

  it("fails closed when interactive execution is requested", async () => {
    await expect(INACTIVE_AUTHENTICATION_PROVIDER.requestInteractiveSession("correlation-1"))
      .rejects.toBeInstanceOf(AuthenticationActivationRequiredError);
  });
});
