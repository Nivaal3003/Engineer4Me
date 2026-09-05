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
    expect(screen.getByRole("heading", { name: "Voice and multimodal readiness" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Permission capability evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "User-gesture activation policy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Supported-browser readiness evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Local browser execution readiness" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Controlled headless browser navigation evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Controlled browser capability observation" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Microphone permission activation proposal" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Controlled microphone permission request evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Bounded microphone source-session proposal" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Controlled microphone source-session evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Bounded audio sample and signal-presence proposal" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Field interaction review preview" })).toBeInTheDocument();
    expect(screen.getByText("Microphone inactive")).toBeInTheDocument();
    expect(screen.getByText("Camera inactive")).toBeInTheDocument();
    expect(screen.getByText("No operation selected")).toBeInTheDocument();
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
    const operationReadiness = screen.getByRole("region", {
      name: "Capability operation readiness",
    });
    expect(within(operationReadiness).getByText("Unavailable")).toBeInTheDocument();
    expect(within(operationReadiness).getAllByText("No accepted operation")).toHaveLength(2);
    expect(within(operationReadiness).getByText("Protected content not loaded")).toBeInTheDocument();
    expect(screen.getByText(/No browser permission API/)).toBeInTheDocument();
    expect(screen.getByText("Read-only detection")).toBeInTheDocument();
    expect(screen.getByText("Intervention gate closed")).toBeInTheDocument();
    expect(screen.getByText("Deployment header unverified")).toBeInTheDocument();
    expect(screen.getByText("Loopback observation evidence")).toBeInTheDocument();
    expect(screen.getByText("Browser launch closed")).toBeInTheDocument();
    expect(screen.getByText("One loopback navigation controlled")).toBeInTheDocument();
    expect(screen.getByText("Application browser launch closed")).toBeInTheDocument();
    expect(screen.getByText("Read-only capability evidence")).toBeInTheDocument();
    expect(screen.getByText("Permission methods not invoked")).toBeInTheDocument();
    expect(screen.getByText("Consent not recorded")).toBeInTheDocument();
    expect(screen.getByText("Prompt execution gate closed")).toBeInTheDocument();
    expect(screen.getByText("Brief microphone activation disclosed")).toBeInTheDocument();
    expect(screen.getByText("Application request control unavailable")).toBeInTheDocument();
    expect(screen.getByText("Permission outcome imported")).toBeInTheDocument();
    expect(screen.getByText("Capture consent not recorded")).toBeInTheDocument();
    expect(screen.getByText("Execution gate closed")).toBeInTheDocument();
    expect(screen.getByText("Three-second source ceiling")).toBeInTheDocument();
    expect(screen.getByText("Audio samples remain inaccessible")).toBeInTheDocument();
    expect(screen.getByText("Application source-session control unavailable")).toBeInTheDocument();
    expect(screen.getByText("Sample access gate closed")).toBeInTheDocument();
    expect(screen.getByText("Application operation unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText(/No backend request, bearer-token attachment/)).toBeInTheDocument();
  });
});
