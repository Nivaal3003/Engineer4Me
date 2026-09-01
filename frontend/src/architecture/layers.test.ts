import {
  classifySourceModule,
  evaluateSourceDependency,
  isSourceDependencyAllowed,
} from "./layers";

describe("Engineer4Me frontend source-layer contract", () => {
  it("classifies controlled source areas deterministically", () => {
    expect(classifySourceModule("src/main.tsx")).toBe("entrypoint");
    expect(classifySourceModule("src/App.tsx")).toBe("application");
    expect(classifySourceModule("src/shell/AppShell.tsx")).toBe("shell");
    expect(classifySourceModule("src/product-ui/EvidencePanel.tsx")).toBe("product_ui");
    expect(classifySourceModule("src/design-system/tokens.ts")).toBe("design_system");
    expect(classifySourceModule("src/architecture/layers.ts")).toBe("architecture");
    expect(classifySourceModule("src/foundation/evidence.ts")).toBe("foundation");
    expect(classifySourceModule("src/auth/config.ts")).toBe("authentication");
    expect(classifySourceModule("src/App.test.tsx")).toBe("test");
  });

  it("allows application code to compose shell, product UI, foundation, and auth", () => {
    expect(isSourceDependencyAllowed("src/App.tsx", "src/shell/AppShell.tsx")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/product-ui/EvidencePanel.tsx")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/foundation/status.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/auth/config.ts")).toBe(true);
  });

  it("fails closed when design-system code attempts to depend on auth", () => {
    const result = evaluateSourceDependency(
      "src/design-system/primitives.tsx",
      "src/auth/config.ts",
    );
    expect(result).toMatchObject({
      fromLayer: "design_system",
      toLayer: "authentication",
      allowed: false,
    });
  });

  it("permits test code to inspect every source layer", () => {
    expect(
      isSourceDependencyAllowed(
        "src/shell/AppShell.test.tsx",
        "src/auth/config.ts",
      ),
    ).toBe(true);
  });
});
