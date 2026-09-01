import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppShell } from "./AppShell";

describe("Engineer4Me mobile-first product shell", () => {
  it("provides semantic landmarks and a main-content skip target", () => {
    render(
      <AppShell authenticationLabel="Blocked" connectivityLabel="unknown">
        <h1>Workspace</h1>
      </AppShell>,
    );
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveAttribute("id", "main-content");
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute("href", "#main-content");
  });

  it("opens and closes mobile navigation without activating browser routing", async () => {
    const user = userEvent.setup();
    render(
      <AppShell authenticationLabel="Blocked" connectivityLabel="unknown">
        <h1>Workspace</h1>
      </AppShell>,
    );
    const navigation = screen.getByRole("navigation", { hidden: true });
    expect(navigation).toHaveAttribute("aria-label", "Mobile product navigation");
    expect(navigation).not.toBeVisible();

    const openButton = screen.getByRole("button", { name: "Open navigation" });
    expect(openButton).toHaveAttribute("aria-expanded", "false");
    await user.click(openButton);

    const visibleNavigation = screen.getByRole("navigation", { name: "Mobile product navigation" });
    expect(visibleNavigation).toBe(navigation);
    expect(navigation).toBeVisible();

    const closeButton = screen.getByRole("button", { name: "Close navigation" });
    expect(closeButton).toHaveAttribute("aria-expanded", "true");
    await user.click(closeButton);

    expect(navigation).not.toBeVisible();
    expect(screen.getByRole("navigation", { hidden: true })).toBe(navigation);
    expect(screen.getByRole("button", { name: "Open navigation" })).toHaveAttribute("aria-expanded", "false");
  });
});
