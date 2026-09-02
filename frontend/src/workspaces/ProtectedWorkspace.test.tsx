import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { evaluateAuthenticationConfiguration } from "../auth/config";
import { createInitialAuthenticationSnapshot } from "../auth/session";
import { INACTIVE_ROUTE_ACCESS_CONTEXT, routeById } from "../routing";
import { ProtectedWorkspace } from "./ProtectedWorkspace";

it("renders a fail-closed protected workspace without protected data", () => {
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
  expect(screen.getByText(/No engineering result, organisational record, or protected data/)).toBeInTheDocument();
});
