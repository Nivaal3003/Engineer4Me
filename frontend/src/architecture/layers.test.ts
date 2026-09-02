import { classifySourceModule, evaluateSourceDependency, isSourceDependencyAllowed } from "./layers";

describe("Engineer4Me frontend source-layer contract", () => {
  it("classifies controlled source areas deterministically", () => {
    expect(classifySourceModule("src/main.tsx")).toBe("entrypoint");
    expect(classifySourceModule("src/App.tsx")).toBe("application");
    expect(classifySourceModule("src/shell/AppShell.tsx")).toBe("shell");
    expect(classifySourceModule("src/routing/routes.ts")).toBe("routing");
    expect(classifySourceModule("src/workspaces/ProtectedWorkspace.tsx")).toBe("workspace");
    expect(classifySourceModule("src/capabilities/registry.ts")).toBe("capabilities");
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

  it("allows application code to consume workspace, API, contract, and authentication layers", () => {
    expect(isSourceDependencyAllowed("src/App.tsx", "src/workspaces/index.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/capabilities/index.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/api/index.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/contracts/index.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/App.tsx", "src/auth/index.ts")).toBe(true);
  });

  it("keeps API core independent of authentication, routing, and workspace implementations", () => {
    expect(evaluateSourceDependency("src/api/transport.ts", "src/auth/config.ts"))
      .toMatchObject({ fromLayer: "api", toLayer: "authentication", allowed: false });
    expect(evaluateSourceDependency("src/api/transport.ts", "src/workspaces/models.ts"))
      .toMatchObject({ fromLayer: "api", toLayer: "workspace", allowed: false });
    expect(evaluateSourceDependency("src/contracts/evidence.ts", "src/api/transport.ts"))
      .toMatchObject({ fromLayer: "contracts", toLayer: "api", allowed: false });
  });

  it("keeps capability adapters downstream of contracts and API inventory", () => {
    expect(isSourceDependencyAllowed("src/capabilities/registry.ts", "src/api/operation-registry.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/capabilities/contracts.ts", "src/contracts/json.ts")).toBe(true);
    expect(evaluateSourceDependency("src/api/transport.ts", "src/capabilities/registry.ts"))
      .toMatchObject({ fromLayer: "api", toLayer: "capabilities", allowed: false });
  });

  it("permits the controlled authentication and workspace bridges", () => {
    expect(isSourceDependencyAllowed("src/auth/msal-provider.ts", "src/api/token.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/workspaces/ProtectedWorkspace.tsx", "src/auth/session.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/workspaces/ProtectedWorkspace.tsx", "src/routing/access.ts")).toBe(true);
    expect(isSourceDependencyAllowed("src/workspaces/models.ts", "src/capabilities/registry.ts")).toBe(true);
  });
});
