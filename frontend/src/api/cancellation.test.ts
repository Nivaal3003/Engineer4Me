import { createRequestAbortHandle } from "./cancellation";

describe("request cancellation", () => {
  it("propagates an already-aborted parent signal", () => {
    const parent = new AbortController();
    parent.abort("caller cancelled");
    const handle = createRequestAbortHandle({ timeoutMs: 1_000, parentSignal: parent.signal });
    expect(handle.signal.aborted).toBe(true);
    expect(handle.signal.reason).toBe("caller cancelled");
    handle.dispose();
  });

  it("aborts when the injected timeout callback fires", () => {
    const callbacks: Array<() => void> = [];
    const handle = createRequestAbortHandle({
      timeoutMs: 1_000,
      dependencies: {
        setTimeout: (next) => {
          callbacks.push(next);
          return 1 as unknown as ReturnType<typeof setTimeout>;
        },
        clearTimeout: () => undefined,
      },
    });
    expect(handle.signal.aborted).toBe(false);
    callbacks[0]?.();
    expect(handle.signal.aborted).toBe(true);
    handle.dispose();
  });
});
