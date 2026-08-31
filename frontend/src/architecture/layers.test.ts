import {
  classifySourceModule,
  evaluateSourceDependency,
  isSourceDependencyAllowed,
} from "./layers";

describe("Engineer4Me frontend source-layer contract", () => {
  it("classifies controlled source areas deterministically", () => {
    expect(classifySourceModule("src/main.tsx")).toBe("entrypoint");
    expect(classifySourceModule("src/App.tsx")).toBe("application");
    expect(classifySourceModule("src/architecture/layers.ts")).toBe(
      "architecture",
    );
    expect(classifySourceModule("src/foundation/evidence.ts")).toBe(
      "foundation",
    );
    expect(classifySourceModule("src/auth/config.ts")).toBe("authentication");
    expect(classifySourceModule("src/App.test.tsx")).toBe("test");
  });

  it("allows application code to depend on controlled foundation and auth", () => {
    expect(
      isSourceDependencyAllowed("src/App.tsx", "src/foundation/status.ts"),
    ).toBe(true);
    expect(
      isSourceDependencyAllowed("src/App.tsx", "src/auth/config.ts"),
    ).toBe(true);
  });

  it("fails closed when foundation code attempts to depend on auth", () => {
    const result = evaluateSourceDependency(
      "src/foundation/evidence.ts",
      "src/auth/config.ts",
    );

    expect(result).toMatchObject({
      fromLayer: "foundation",
      toLayer: "authentication",
      allowed: false,
    });
  });

  it("permits test code to inspect every source layer", () => {
    expect(
      isSourceDependencyAllowed(
        "src/architecture/layers.test.ts",
        "src/auth/config.ts",
      ),
    ).toBe(true);
  });
});
