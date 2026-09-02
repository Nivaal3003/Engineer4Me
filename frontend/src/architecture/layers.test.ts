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
    expect(classifySourceModule("src/contracts/evidence.ts")).toBe("contracts");
    expect(classifySourceModule("src/api/transport.ts")).toBe("api");
    expect(classifySourceModule("src/auth/config.ts")).toBe("authentication");
    expect(classifySourceModule("src/api/transport.test.ts")).toBe("test");
  });

  it("allows application code to consume the controlled API and contract layers", () => {
    expect(isSourceDependencyAllowed("src/App.tsx", "src/api/index.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/contracts/index.ts")).toBe(true);
  });

  it("keeps the API core independent of authentication implementation and UI layers", () => {
    expect(
      evaluateSourceDependency("src/api/transport.ts", "src/auth/config.ts"),
    ).toMatchObject({ fromLayer: "api", toLayer: "authentication", allowed: false });
    expect(
      evaluateSourceDependency("src/api/transport.ts", "src/routing/routes.ts"),
    ).toMatchObject({ fromLayer: "api", toLayer: "routing", allowed: false });
    expect(
      evaluateSourceDependency("src/contracts/evidence.ts", "src/api/transport.ts"),
    ).toMatchObject({ fromLayer: "contracts", toLayer: "api", allowed: false });
  });

  it("permits a future authentication adapter to implement the approved API token seam", () => {
    expect(isSourceDependencyAllowed("src/auth/provider.ts", "src/api/token.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/routing/authentication-context.ts", "src/auth/session.ts")).toBe(true);
  });
});
