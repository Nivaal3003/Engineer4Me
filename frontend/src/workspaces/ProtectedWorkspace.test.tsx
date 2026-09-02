import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { evaluateAuthenticationConfiguration } from "../auth/config";
import { createInitialAuthenticationSnapshot } from "../auth/session";
import { INACTIVE_ROUTE_ACCESS_CONTEXT, routeById } from "../routing";
import { ProtectedWorkspace } from "./ProtectedWorkspace";

describe("fail-closed protected workspace presentation", () => {
  it("shows operation readiness without disclosing protected data", () => {
    render(
      <MemoryRouter>
        <ProtectedWorkspace
          route={routeById("selection")}
          accessContext={INACTIVE_ROUTE_ACCESS_CONTEXT}
          authentication={createInitialAuthenticationSnapshot(evaluateAuthenticationConfiguration({}))}
          profileSource={{
            state: "unavailable",
            reason: "no_accepted_backend_authorization_profile_operation",
            operation: null,
          }}
          apiTransportActive={false}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Selection & sizing is not available" })).toBeInTheDocument();
    expect(screen.getByText("Authentication execution has not been activated.")).toBeInTheDocument();
    expect(screen.getByText(/22 accepted backend operations are allocated for in-memory contract verification only/)).toBeInTheDocument();
    expect(screen.getByText(/No engineering result, organisational record, or protected data/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Capability operation readiness" })).toBeInTheDocument();
    const counts = screen.getByLabelText("Accepted operation counts");
    expect(within(counts).getByText("22")).toBeInTheDocument();
    expect(within(counts).getByText("9")).toBeInTheDocument();
    expect(within(counts).getByText("13")).toBeInTheDocument();
    expect(screen.getByText("Live transport inactive")).toBeInTheDocument();
  });

  it("keeps a route with no accepted operation explicitly unavailable", () => {
    render(
      <MemoryRouter>
        <ProtectedWorkspace
          route={routeById("troubleshooting")}
          accessContext={INACTIVE_ROUTE_ACCESS_CONTEXT}
          authentication={createInitialAuthenticationSnapshot(evaluateAuthenticationConfiguration({}))}
          profileSource={{
            state: "unavailable",
            reason: "no_accepted_backend_authorization_profile_operation",
            operation: null,
          }}
          apiTransportActive={false}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Troubleshooting is not available" })).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getAllByText("No accepted operation")).toHaveLength(2);
    expect(screen.getByText("Protected content not loaded")).toBeInTheDocument();
  });
});
