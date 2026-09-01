import {
  INACTIVE_BEARER_TOKEN_PROVIDER,
  bearerAuthorizationHeader,
} from "./token";
import { getBackendOperation } from "./operation-registry";

describe("approved bearer-token provider seam", () => {
  it("is inactive by default and performs no token acquisition", async () => {
    await expect(
      INACTIVE_BEARER_TOKEN_PROVIDER.getAccessToken({
        operation: getBackendOperation("get_root"),
        correlationId: "e4m-00000000000000000000000000000000",
      }),
    ).resolves.toBeNull();
  });

  it("rejects tokens containing whitespace or controls", () => {
    expect(bearerAuthorizationHeader("opaque-token")).toBe("Bearer opaque-token");
    expect(() => bearerAuthorizationHeader("token with spaces")).toThrow();
    expect(() => bearerAuthorizationHeader("token\nvalue")).toThrow();
  });
});
