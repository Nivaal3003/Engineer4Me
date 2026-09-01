import { createStateExperience } from "./models";

describe("Engineer4Me state-experience models", () => {
  it("supports every controlled asynchronous and routing state", () => {
    const kinds = [
      "loading",
      "empty",
      "error",
      "degraded",
      "unavailable",
      "not_found",
    ] as const;
    expect(kinds.map((kind) => createStateExperience(kind).kind)).toEqual(kinds);
  });

  it("keeps retry fail closed unless explicitly authorized", () => {
    expect(createStateExperience("error").retryAuthorized).toBe(false);
    expect(
      createStateExperience("error", {
        correlationId: "corr-123",
        retryAuthorized: true,
      }),
    ).toMatchObject({ correlationId: "corr-123", retryAuthorized: true });
  });
});
