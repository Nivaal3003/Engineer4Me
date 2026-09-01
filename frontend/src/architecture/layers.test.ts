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
    expect(classifySourceModule("src/routing/routes.ts")).toBe("routing");
    expect(classifySourceModule("src/state-experience/StateExperience.tsx")).toBe("state_experience");
    expect(classifySourceModule("src/product-ui/EvidencePanel.tsx")).toBe("product_ui");
    expect(classifySourceModule("src/design-system/tokens.ts")).toBe("design_system");
    expect(classifySourceModule("src/architecture/layers.ts")).toBe("architecture");
    expect(classifySourceModule("src/foundation/evidence.ts")).toBe("foundation");
    expect(classifySourceModule("src/auth/config.ts")).toBe("authentication");
    expect(classifySourceModule("src/App.test.tsx")).toBe("test");
  });

  it("allows application and shell code to compose the controlled routing layers", () => {
    expect(isSourceDependencyAllowed("src/App.tsx", "src/routing/routes.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/state-experience/StateExperience.tsx")).toBe(true);
    expect(isSourceDependencyAllowed("src/shell/AppShell.tsx", "src/routing/RouteLifecycle.tsx")).toBe(true);
  });

  it("keeps routing and state experience independent of authentication activation", () => {
    expect(
      evaluateSourceDependency("src/routing/access.ts", "src/auth/config.ts"),
    ).toMatchObject({ fromLayer: "routing", toLayer: "authentication", allowed: false });
    expect(
      evaluateSourceDependency("src/state-experience/models.ts", "src/auth/config.ts"),
    ).toMatchObject({ fromLayer: "state_experience", toLayer: "authentication", allowed: false });
  });

  it("fails closed when design-system code attempts to depend on routing", () => {
    expect(
      evaluateSourceDependency("src/design-system/primitives.tsx", "src/routing/routes.ts"),
    ).toMatchObject({ fromLayer: "design_system", toLayer: "routing", allowed: false });
  });
});
