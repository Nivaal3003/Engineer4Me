import {
  createControlledLoopbackResponseObservation,
  type ControlledResponseHeaderEntry,
} from "./loopback-response-observation";

const exactHeaders: readonly ControlledResponseHeaderEntry[] = [
  { name: "Content-Type", value: "text/html; charset=utf-8" },
  { name: "Cache-Control", value: "no-store" },
  { name: "Permissions-Policy", value: "microphone=(), camera=()" },
];

function observe(overrides: Partial<Parameters<
  typeof createControlledLoopbackResponseObservation
>[0]> = {}) {
  return createControlledLoopbackResponseObservation({
    observationId: "loopback-observation-fixture",
    source: "scripted_test_fixture",
    requestMethod: "GET",
    requestUrl: "http://127.0.0.1:43127/phase10-readiness",
    statusCode: 200,
    headers: exactHeaders,
    ...overrides,
  });
}

describe("controlled loopback response-header observation", () => {
  it("accepts the exact default-deny response on the controlled loopback path", () => {
    expect(observe()).toMatchObject({
      state: "accepted",
      exactDefaultDenyHeaderObserved: true,
      externalNetworkRequestPerformed: false,
      liveDeploymentHeaderRead: false,
      browserExecuted: false,
      permissionPromptShown: false,
      backendTransportActivated: false,
    });
  });

  it("rejects a semantically equivalent but non-canonical response value", () => {
    expect(observe({
      headers: [
        exactHeaders[0]!,
        exactHeaders[1]!,
        { name: "Permissions-Policy", value: "camera=(), microphone=()" },
      ],
    })).toMatchObject({
      state: "invalid",
      exactDefaultDenyHeaderObserved: false,
    });
  });

  it("rejects a non-loopback URL and a self-only permission profile", () => {
    expect(observe({
      requestUrl: "https://example.invalid/phase10-readiness",
      headers: [
        exactHeaders[0]!,
        exactHeaders[1]!,
        { name: "Permissions-Policy", value: "microphone=(self), camera=(self)" },
      ],
    })).toMatchObject({
      state: "invalid",
      exactDefaultDenyHeaderObserved: false,
    });
  });

  it("rejects duplicate policy headers and authentication or cookie surfaces", () => {
    const result = observe({
      headers: [
        ...exactHeaders,
        { name: "Permissions-Policy", value: "microphone=(), camera=()" },
        { name: "Set-Cookie", value: "session=forbidden" },
        { name: "WWW-Authenticate", value: "Bearer" },
      ],
    });
    expect(result.state).toBe("invalid");
    expect(result.blockingReasons).toEqual(expect.arrayContaining([
      "Duplicate permissions-policy response headers are not accepted.",
      "Prohibited set-cookie response header is present.",
      "Prohibited www-authenticate response header is present.",
    ]));
  });
});
