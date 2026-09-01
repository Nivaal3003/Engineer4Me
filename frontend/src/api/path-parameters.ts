export type PathParameterValue = number | string;
export type PathParameterValues = Readonly<Record<string, PathParameterValue>>;

const PARAMETER_PATTERN = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

export function pathParameterNames(template: string): readonly string[] {
  return Object.freeze([...template.matchAll(PARAMETER_PATTERN)].map((match) => match[1]));
}

export function materializeOperationPath(
  template: string,
  supplied: PathParameterValues = {},
): string {
  const expected = pathParameterNames(template);
  const suppliedNames = Object.keys(supplied).sort();
  const expectedNames = [...expected].sort();
  if (
    suppliedNames.length !== expectedNames.length ||
    suppliedNames.some((name, index) => name !== expectedNames[index])
  ) {
    throw new Error("Operation path parameters do not exactly match the registered template.");
  }
  const path = template.replace(PARAMETER_PATTERN, (_token, name: string) => {
    const value = supplied[name];
    if (
      (typeof value !== "string" && typeof value !== "number") ||
      String(value).length === 0 ||
      (typeof value === "number" && !Number.isFinite(value))
    ) {
      throw new Error(`Invalid operation path parameter: ${name}`);
    }
    return encodeURIComponent(String(value));
  });
  if (path.includes("{") || path.includes("}")) {
    throw new Error("Operation path contains unresolved template tokens.");
  }
  return path;
}
