import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import App from "./App";

function renderApp(initialEntry = "/") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <App />
    </MemoryRouter>,
  );
}

describe("Engineer4Me controlled browser product", () => {
  it("renders the public workspace with explicit access and audit boundaries", () => {
    renderApp();
    expect(screen.getByRole("heading", { level: 1, name: "Engineering decisions, with evidence visible" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authentication and access status" })).toBeInTheDocument();
    expect(screen.getByText("No remote audit records loaded")).toBeInTheDocument();
    expect(screen.getByText("No standards conformity claim")).toBeInTheDocument();
    expect(screen.getByText(/Final engineering approval remains/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/iu })).not.toBeInTheDocument();
  });

  it("navigates to a protected route without disclosing protected content", async () => {
    const user = userEvent.setup();
    renderApp();
    const desktopNavigation = screen.getByRole("navigation", { name: "Desktop product navigation" });
    await user.click(within(desktopNavigation).getByRole("link", { name: "Selection & sizing" }));
    expect(screen.getByRole("heading", { level: 1, name: "Selection & sizing is not available" })).toBeInTheDocument();
    expect(screen.getByText(/Authentication is not active/)).toBeInTheDocument();
    expect(screen.getByText(/No engineering result, organisational record, or protected data/)).toBeInTheDocument();
    expect(screen.getAllByText(/backend authorization remains authoritative/iu).length).toBeGreaterThan(0);
  });

  it("renders an explicit not-found experience and returns to the workspace", async () => {
    const user = userEvent.setup();
    renderApp("/unknown-engineering-view");
    expect(screen.getByRole("heading", { level: 1, name: "The requested page does not exist" })).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Return to workspace" }));
    expect(screen.getByRole("heading", { level: 1, name: "Engineering decisions, with evidence visible" })).toBeInTheDocument();
  });

  it("keeps sign-in, API requests, retries, and protected administration inactive", () => {
    renderApp("/access-audit");
    expect(screen.getByRole("heading", { name: "Access & audit is not available" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /retry/iu })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/iu })).not.toBeInTheDocument();
  });
});
