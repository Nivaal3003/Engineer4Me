import { createControlledMsalNetworkClient } from "./msal-network";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "x-request-id": "request-1" },
  });
}

describe("controlled MSAL network client", () => {
  it("uses only the injected fetcher and reviewed HTTPS authority origins", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ token_type: "Bearer" }));
    const client = createControlledMsalNetworkClient({
      allowedOrigins: ["https://engineer4me.ciamlogin.com/"],
      fetcher,
    });
    await expect(client.sendPostRequestAsync("https://engineer4me.ciamlogin.com/oauth2/v2.0/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code",
    })).resolves.toMatchObject({ status: 200, body: { token_type: "Bearer" } });
    expect(fetcher).toHaveBeenCalledTimes(1);
    const init = fetcher.mock.calls[0]?.[1];
    expect(init).toMatchObject({ credentials: "omit", redirect: "error", cache: "no-store" });
  });

  it("rejects unreviewed origins, credential headers, and non-JSON responses", async () => {
    const client = createControlledMsalNetworkClient({
      allowedOrigins: ["https://engineer4me.ciamlogin.com/"],
      fetcher: async () => new Response("not json", { headers: { "Content-Type": "text/plain" } }),
    });
    await expect(client.sendGetRequestAsync("https://other.example/configuration")).rejects.toThrow(/origin/u);
    await expect(client.sendGetRequestAsync("https://engineer4me.ciamlogin.com/configuration", {
      headers: { Authorization: "secret" },
    })).rejects.toThrow(/header/u);
    await expect(client.sendGetRequestAsync("https://engineer4me.ciamlogin.com/configuration"))
      .rejects.toThrow(/JSON/u);
  });
});
