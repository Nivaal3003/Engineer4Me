import {
  BLOCKED_UNIT_TEST_NETWORK_MESSAGE,
  UnexpectedUnitTestNetworkRequestError,
} from "./network-guard";

describe("Engineer4Me unit-test network guard", () => {
  it("blocks fetch before any external request can be issued", async () => {
    await expect(fetch("https://example.invalid/engineer4me")).rejects.toThrow(
      BLOCKED_UNIT_TEST_NETWORK_MESSAGE,
    );
  });

  it("blocks XMLHttpRequest before the request is opened", () => {
    const request = new XMLHttpRequest();

    expect(() =>
      request.open("GET", "https://example.invalid/engineer4me"),
    ).toThrow(UnexpectedUnitTestNetworkRequestError);
  });
});
