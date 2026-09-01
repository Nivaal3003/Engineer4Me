import {
  InvalidPageRequestError,
  PAGE_LIMIT_MAXIMUM,
  createPageEnvelope,
  createPageRequest,
} from "./pagination";

describe("pagination contracts", () => {
  it("creates bounded immutable page requests and envelopes", () => {
    const request = createPageRequest({ offset: 25, limit: 25 });
    const envelope = createPageEnvelope({ items: ["a", "b"], request, total: 100 });
    expect(request).toEqual({ offset: 25, limit: 25 });
    expect(envelope.nextOffset).toBeNull();
    expect(Object.isFrozen(envelope.items)).toBe(true);
  });

  it("fails closed on invalid limits", () => {
    expect(() => createPageRequest({ limit: 0 })).toThrow(InvalidPageRequestError);
    expect(() => createPageRequest({ limit: PAGE_LIMIT_MAXIMUM + 1 })).toThrow(
      InvalidPageRequestError,
    );
  });
});
