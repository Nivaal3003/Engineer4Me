import { render, screen } from "@testing-library/react";
import { SupportedBrowserReadinessPanel } from "./SupportedBrowserReadinessPanel";

describe("supported-browser and deployment-header readiness presentation", () => {
  it("shows read-only evidence and closed activation boundaries without a control", () => {
    render(<SupportedBrowserReadinessPanel />);
    expect(screen.getByRole("heading", { name: "Supported-browser readiness evidence" })).toBeInTheDocument();
    expect(screen.getByText("Capability-based inspection")).toBeInTheDocument();
    expect(screen.getByText("Deployment header unverified")).toBeInTheDocument();
    expect(screen.getByText("Permission prompts closed")).toBeInTheDocument();
    expect(screen.getByText("Not collected")).toBeInTheDocument();
    expect(screen.getByText("microphone=(), camera=()")).toBeInTheDocument();
    expect(screen.getByText("microphone=(self), camera=(self)")).toBeInTheDocument();
    expect(screen.getByText(/No live response header or deployment platform/)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
