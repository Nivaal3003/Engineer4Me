import { materializeOperationPath, pathParameterNames } from "./path-parameters";

describe("operation path parameters", () => {
  it("encodes exact path parameters without permitting path injection", () => {
    const template = "/api/v1/designs/{design_case_id}/revisions/{revision_number}";
    expect(pathParameterNames(template)).toEqual(["design_case_id", "revision_number"]);
    expect(
      materializeOperationPath(template, {
        design_case_id: "case/one",
        revision_number: 2,
      }),
    ).toBe("/api/v1/designs/case%2Fone/revisions/2");
  });

  it("rejects missing and extra parameters", () => {
    expect(() => materializeOperationPath("/items/{item_id}")).toThrow();
    expect(() => materializeOperationPath("/items", { item_id: "1" })).toThrow();
  });
});
