/** Pure simulation policy. Caller-supplied ticks are not a real-time watchdog. */
export const SCRIPTED_PROCESSING_LIMITS = Object.freeze({
  maximumActiveJobs: 16,
  maximumJobLifetimeTicks: 60000,
  maximumTextCodeUnits: 4096,
  maximumFinalResultsPerJob: 1,
});
export function assertScriptedProcessingTick(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - SCRIPTED_PROCESSING_LIMITS.maximumJobLifetimeTicks) {
    throw new Error("Simulation ticks must be bounded nonnegative safe integers.");
  }
}
export function scriptedFixtureData(input: unknown): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("A scripted fixture must be a data object.");
  const prototype: unknown = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("Scripted fixture prototypes are not supported.");
  const fields = ["fixtureId", "languageTag", "text"];
  const keys = Reflect.ownKeys(input);
  if (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key))) {
    throw new Error("Scripted fixture field inventory differs.");
  }
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new Error("Scripted fixtures require own enumerable data fields.");
  }
  return input as Record<string, unknown>;
}
