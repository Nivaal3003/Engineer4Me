import { render, screen } from "@testing-library/react";
import { LocalBrowserExecutionReadinessPanel } from "./LocalBrowserExecutionReadinessPanel";

describe("local browser execution readiness presentation", () => {
  it("shows the loopback evidence and separate intervention boundary without a launch control", () => {
    render(<LocalBrowserExecutionReadinessPanel />);
    expect(screen.getByRole("heading", { name: "Local browser execution readiness" })).toBeInTheDocument();
    expect(screen.getByText("Loopback proof controlled")).toBeInTheDocument();
    expect(screen.getByText("Browser launch closed")).toBeInTheDocument();
    expect(screen.getByText("Permission prompts closed")).toBeInTheDocument();
    expect(screen.getByText("Loopback observation evidence")).toBeInTheDocument();
    expect(screen.getByText("Acceptance archive only")).toBeInTheDocument();
    expect(screen.getByText("/phase10-readiness")).toBeInTheDocument();
    expect(screen.getByText("microphone=(), camera=()")).toBeInTheDocument();
    expect(screen.getByText(/No browser launch or navigation operation/)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
