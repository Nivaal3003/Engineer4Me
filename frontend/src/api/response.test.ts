import { readControlledJsonResponse } from "./response";

const correlationId = "e4m-00000000000000000000000000000000";

describe("controlled JSON response decoding", () => {
  it("accepts bounded UTF-8 JSON and no-content responses", async () => {
    await expect(
      readControlledJsonResponse({
        response: new Response('{"status":"ok"}', {
          headers: { "content-type": "application/json; charset=utf-8" },
        }),
        maximumBytes: 100,
        correlationId,
      }),
    ).resolves.toEqual({ status: "ok" });
    await expect(
      readControlledJsonResponse({
        response: new Response(null, { status: 204 }),
        maximumBytes: 100,
        correlationId,
      }),
    ).resolves.toBeNull();
  });

  it("rejects unapproved content types and oversized responses", async () => {
    await expect(
      readControlledJsonResponse({
        response: new Response("text", { headers: { "content-type": "text/plain" } }),
        maximumBytes: 100,
        correlationId,
      }),
    ).rejects.toMatchObject({ kind: "response_content_type" });
    await expect(
      readControlledJsonResponse({
        response: new Response('{"large":true}', {
          headers: { "content-type": "application/json", "content-length": "999" },
        }),
        maximumBytes: 10,
        correlationId,
      }),
    ).rejects.toMatchObject({ kind: "response_too_large" });
  });
});
