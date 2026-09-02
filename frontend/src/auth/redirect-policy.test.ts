import {
  createAuthenticationRedirectPolicy,
  resolveAuthenticationReturnPath,
} from "./redirect-policy";

const ALLOWED_PATHS = ["/", "/selection", "/projects"] as const;

describe("authentication redirect policy", () => {
  it("permits only reviewed same-origin return paths", () => {
    const policy = createAuthenticationRedirectPolicy({
      applicationOrigin: "https://engineer4me.example/",
      allowedReturnPaths: ALLOWED_PATHS,
    });
    expect(resolveAuthenticationReturnPath(policy, "/selection")).toBe(
      "https://engineer4me.example/selection",
    );
    expect(policy.redirectUri).toBe("https://engineer4me.example/");
  });

  it("rejects external, protocol-relative, queried, and unreviewed return paths", () => {
    const policy = createAuthenticationRedirectPolicy({
      applicationOrigin: "https://engineer4me.example/",
      allowedReturnPaths: ALLOWED_PATHS,
    });
    for (const value of ["https://other.example/", "//other.example/", "/selection?next=/", "/unknown"]) {
      expect(() => resolveAuthenticationReturnPath(policy, value)).toThrow();
    }
  });

  it("permits HTTP only for an explicit loopback origin", () => {
    expect(createAuthenticationRedirectPolicy({
      applicationOrigin: "http://127.0.0.1:4173/",
      allowedReturnPaths: ["/"],
    }).applicationOrigin).toBe("http://127.0.0.1:4173");
    expect(() => createAuthenticationRedirectPolicy({
      applicationOrigin: "http://engineer4me.example/",
      allowedReturnPaths: ["/"],
    })).toThrow(/HTTPS/u);
  });
});
