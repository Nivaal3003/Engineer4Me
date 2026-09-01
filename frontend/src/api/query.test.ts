import { appendDeterministicQuery } from "./query";

describe("deterministic API query encoding", () => {
  it("sorts keys and preserves repeated-value order", () => {
    const url = appendDeterministicQuery(
      new URL("https://engineer4me.example/api/v1/products"),
      { z: 2, a: ["first", "second"] },
    );
    expect(url.search).toBe("?a=first&a=second&z=2");
  });

  it("rejects non-finite values", () => {
    expect(() =>
      appendDeterministicQuery(new URL("https://engineer4me.example/"), { value: Infinity }),
    ).toThrow("must be finite");
  });
});
