import { normalizeIdentityAccount } from "./identity";

describe("identity-account normalization", () => {
  it("creates a tenant-bound principal key without retaining raw claims or tokens", () => {
    expect(normalizeIdentityAccount({
      subjectId: "subject-1",
      tenantId: "tenant-1",
      username: " engineer@example.test ",
      displayName: " Engineer Four ",
    })).toEqual({
      subjectId: "subject-1",
      tenantId: "tenant-1",
      principalKey: "8:tenant-1:9:subject-1",
      username: "engineer@example.test",
      displayName: "Engineer Four",
    });
  });

  it("uses an unambiguous length-prefixed principal key", () => {
    const left = normalizeIdentityAccount({ subjectId: "c", tenantId: "a:b" });
    const right = normalizeIdentityAccount({ subjectId: "b:c", tenantId: "a" });
    expect(left.principalKey).not.toBe(right.principalKey);
  });

  it("rejects missing or malformed identity ownership", () => {
    expect(() => normalizeIdentityAccount({ subjectId: "", tenantId: "tenant-1" })).toThrow();
    expect(() => normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant 1" })).toThrow();
  });
});
