export type ApiQueryScalar = boolean | number | string;
export type ApiQueryValue = ApiQueryScalar | readonly ApiQueryScalar[] | null | undefined;
export type ApiQuery = Readonly<Record<string, ApiQueryValue>>;

export function appendDeterministicQuery(url: URL, query: ApiQuery | undefined): URL {
  if (!query) {
    return url;
  }
  const result = new URL(url.toString());
  for (const key of Object.keys(query).sort()) {
    if (key.length === 0 || /[\u0000-\u001f\u007f]/.test(key)) {
      throw new Error("Query parameter names must be non-blank and control-free.");
    }
    const raw = query[key];
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      if (value === null || value === undefined) {
        continue;
      }
      if (typeof value === "number" && !Number.isFinite(value)) {
        throw new Error(`Query parameter ${key} must be finite.`);
      }
      result.searchParams.append(key, String(value));
    }
  }
  return result;
}
