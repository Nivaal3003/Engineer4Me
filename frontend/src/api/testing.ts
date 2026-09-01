export interface RecordedFetchCall {
  readonly input: RequestInfo | URL;
  readonly init: RequestInit | undefined;
}

export interface ScriptedFetch {
  readonly fetch: typeof fetch;
  readonly calls: readonly RecordedFetchCall[];
}

export function createScriptedFetch(
  responses: readonly Response[],
): ScriptedFetch {
  const queue = [...responses];
  const calls: RecordedFetchCall[] = [];
  const scripted = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(Object.freeze({ input, init }));
    const response = queue.shift();
    if (!response) {
      throw new Error("No scripted response remains for the in-memory fetch.");
    }
    return response;
  }) as typeof fetch;
  return Object.freeze({ fetch: scripted, calls });
}
