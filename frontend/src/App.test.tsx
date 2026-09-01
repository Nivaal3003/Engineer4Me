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
  it("renders the public workspace route and explicit product boundaries", () => {
    renderApp();
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Engineering decisions, with evidence visible",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByText("No standards conformity claim")).toBeInTheDocument();
    expect(screen.getByText(/Final engineering approval remains/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/i })).not.toBeInTheDocument();
  });

  it("navigates to a protected route without disclosing protected content", async () => {
    const user = userEvent.setup();
    renderApp();
    const desktopNavigation = screen.getByRole("navigation", { name: "Desktop product navigation" });
    await user.click(within(desktopNavigation).getByRole("link", { name: "Selection & sizing" }));

    expect(screen.getByRole("heading", { level: 1, name: "Selection & sizing is not available" })).toBeInTheDocument();
    expect(screen.getByText(/Authentication is not active/)).toBeInTheDocument();
    expect(screen.getByText(/No engineering result, organisational record, or protected data/)).toBeInTheDocument();
    expect(screen.getByText(/backend authorization remains authoritative/i)).toBeInTheDocument();
    expect(within(desktopNavigation).getByRole("link", { name: "Selection & sizing" })).toHaveAttribute("aria-current", "page");
  });

  it("renders an explicit not-found experience and returns to the workspace", async () => {
    const user = userEvent.setup();
    renderApp("/unknown-engineering-view");
    expect(screen.getByRole("heading", { level: 1, name: "The requested page does not exist" })).toBeInTheDocument();
    expect(screen.getByText(/unknown-engineering-view/)).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Return to workspace" }));
    expect(screen.getByRole("heading", { level: 1, name: "Engineering decisions, with evidence visible" })).toBeInTheDocument();
  });

  it("keeps API transport, automatic retries, and protected administration inactive", () => {
    renderApp("/access-audit");
    expect(screen.getByRole("heading", { name: "Access & audit is not available" })).toBeInTheDocument();
    expect(screen.getByText(/Authentication is not active/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /retry/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/i })).not.toBeInTheDocument();
  });
});
