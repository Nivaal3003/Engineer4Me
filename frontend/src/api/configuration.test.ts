import {
  createApiTransportConfiguration,
  resolveSameOriginApiUrl,
} from "./configuration";

describe("API transport configuration", () => {
  it("creates a bounded same-origin configuration", () => {
    const configuration = createApiTransportConfiguration({
      applicationOrigin: "https://engineer4me.example",
    });
    expect(resolveSameOriginApiUrl(configuration, "/api/v1/products").toString()).toBe(
      "https://engineer4me.example/api/v1/products",
    );
  });

  it("rejects cross-origin and ambiguous operation paths", () => {
    expect(() =>
      createApiTransportConfiguration({
        applicationOrigin: "https://engineer4me.example",
        apiOrigin: "https://api.example",
      }),
    ).toThrow("restricted to the application origin");
    const configuration = createApiTransportConfiguration({
      applicationOrigin: "https://engineer4me.example",
    });
    expect(() => resolveSameOriginApiUrl(configuration, "//external.example/path")).toThrow();
    expect(() => resolveSameOriginApiUrl(configuration, "/path?token=value")).toThrow();
  });
});
