import { createApiTransportConfiguration } from "./configuration";
import { createScriptedFetch } from "./testing";
import { createControlledApiTransport } from "./transport";

const correlationId = "e4m-00000000000000000000000000000000";
const configuration = createApiTransportConfiguration({
  applicationOrigin: "https://engineer4me.example",
  requestTimeoutMs: 5_000,
  maximumResponseBytes: 10_000,
});

describe("controlled API transport", () => {
  it("executes a public operation only through the injected fetch seam", async () => {
    const scripted = createScriptedFetch([
      new Response('{"status":"ok"}', { headers: { "content-type": "application/json" } }),
    ]);
    const transport = createControlledApiTransport({
      configuration,
      fetcher: scripted.fetch,
      createCorrelationId: () => correlationId,
    });
    await expect(transport.execute({ operationKey: "get_root" })).resolves.toMatchObject({
      data: { status: "ok" },
      status: 200,
      correlationId,
    });
    expect(scripted.calls).toHaveLength(1);
    expect(String(scripted.calls[0]?.input)).toBe("https://engineer4me.example/");
    expect(new Headers(scripted.calls[0]?.init?.headers).get("authorization")).toBeNull();
  });

  it("fails before fetch when the inactive provider cannot authorize a protected operation", async () => {
    const scripted = createScriptedFetch([]);
    const transport = createControlledApiTransport({
      configuration,
      fetcher: scripted.fetch,
      createCorrelationId: () => correlationId,
    });
    await expect(
      transport.execute({ operationKey: "get_api_v1_products" }),
    ).rejects.toMatchObject({ kind: "authorization_unavailable" });
    expect(scripted.calls).toHaveLength(0);
  });

  it("attaches a validated bearer value supplied by an injected approved provider", async () => {
    const scripted = createScriptedFetch([
      new Response("[]", { headers: { "content-type": "application/json" } }),
    ]);
    const transport = createControlledApiTransport({
      configuration,
      fetcher: scripted.fetch,
      createCorrelationId: () => correlationId,
      tokenProvider: { getAccessToken: async () => "opaque-token" },
    });
    await transport.execute({ operationKey: "get_api_v1_products" });
    expect(new Headers(scripted.calls[0]?.init?.headers).get("authorization")).toBe(
      "Bearer opaque-token",
    );
  });

  it("encodes registered path parameters and deterministic query values", async () => {
    const scripted = createScriptedFetch([
      new Response('{"id":"case/one"}', { headers: { "content-type": "application/json" } }),
    ]);
    const transport = createControlledApiTransport({
      configuration,
      fetcher: scripted.fetch,
      createCorrelationId: () => correlationId,
      tokenProvider: { getAccessToken: async () => "opaque-token" },
    });
    const operation = "getDesignCase";
    await transport.execute({
      operationKey: operation,
      pathParameters: { design_case_id: "case/one" },
      query: { include: ["evidence", "revision"] },
    });
    expect(String(scripted.calls[0]?.input)).toContain(
      "/api/v1/designs/case%2Fone?include=evidence&include=revision",
    );
  });
});
