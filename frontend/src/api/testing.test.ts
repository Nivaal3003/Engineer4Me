import { createScriptedFetch } from "./testing";

describe("in-memory scripted fetch", () => {
  it("records requests and returns responses in exact order", async () => {
    const scripted = createScriptedFetch([
      new Response('{"sequence":1}', { headers: { "content-type": "application/json" } }),
    ]);
    const response = await scripted.fetch("https://engineer4me.example/health");
    expect(await response.json()).toEqual({ sequence: 1 });
    expect(scripted.calls).toHaveLength(1);
  });

  it("fails closed when no scripted response remains", async () => {
    const scripted = createScriptedFetch([]);
    await expect(scripted.fetch("https://engineer4me.example/health")).rejects.toThrow(
      "No scripted response remains",
    );
  });
});
