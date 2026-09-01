export interface RequestAbortHandle {
  readonly signal: AbortSignal;
  dispose(): void;
}

export interface RequestAbortDependencies {
  readonly setTimeout: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>;
  readonly clearTimeout: (handle: ReturnType<typeof setTimeout>) => void;
}

const DEFAULT_ABORT_DEPENDENCIES: RequestAbortDependencies = Object.freeze({
  setTimeout: (callback: () => void, delayMs: number) =>
    globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle: ReturnType<typeof setTimeout>) =>
    globalThis.clearTimeout(handle),
});

export function createRequestAbortHandle(input: {
  readonly timeoutMs: number;
  readonly parentSignal?: AbortSignal;
  readonly dependencies?: RequestAbortDependencies;
}): RequestAbortHandle {
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > 120_000) {
    throw new Error("Request timeout must be a safe integer from 1 through 120000 milliseconds.");
  }
  const dependencies = input.dependencies ?? DEFAULT_ABORT_DEPENDENCIES;
  const controller = new AbortController();
  const abortFromParent = () => controller.abort(input.parentSignal?.reason);
  if (input.parentSignal?.aborted) {
    abortFromParent();
  } else {
    input.parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  }
  const timeout = dependencies.setTimeout(
    () => controller.abort(new DOMException("Request timeout", "TimeoutError")),
    input.timeoutMs,
  );
  let disposed = false;
  return Object.freeze({
    signal: controller.signal,
    dispose: () => {
      if (disposed) {
        return;
      }
      disposed = true;
      dependencies.clearTimeout(timeout);
      input.parentSignal?.removeEventListener("abort", abortFromParent);
    },
  });
}
