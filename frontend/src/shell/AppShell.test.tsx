import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AppShell } from "./AppShell";

function renderShell(initialEntry = "/") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AppShell
        accessProfileLabel="Not loaded"
        authenticationLabel="Configuration blocked"
        connectivityLabel="unknown"
        organisationLabel="Not selected"
        projectLabel="No project selected"
      >
        <h1>Workspace</h1>
      </AppShell>
    </MemoryRouter>,
  );
}

describe("Engineer4Me mobile-first routed product shell", () => {
  it("provides semantic landmarks, route navigation, and explicit workspace context", () => {
    renderShell();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveAttribute("id", "main-content");
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute("href", "#main-content");
    const context = screen.getByLabelText("Workspace context");
    expect(within(context).getByText("Not selected")).toBeInTheDocument();
    expect(within(context).getByText("Not loaded")).toBeInTheDocument();
    expect(within(context).getByText(/not persisted in browser storage/u)).toBeInTheDocument();

    const desktopNavigation = screen.getByRole("navigation", { name: "Desktop product navigation" });
    expect(within(desktopNavigation).getByRole("link", { name: "Home" })).toHaveAttribute("aria-current", "page");
    expect(within(desktopNavigation).getByRole("link", { name: "Selection & sizing" })).toHaveAttribute("href", "/selection");
  });

  it("opens, routes from, and closes mobile navigation", async () => {
    const user = userEvent.setup();
    renderShell();
    const navigation = document.getElementById("mobile-product-navigation");
    if (!navigation) throw new Error("Mobile product navigation is missing.");
    expect(navigation).not.toBeVisible();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    expect(screen.getByRole("navigation", { name: "Mobile product navigation" })).toBeVisible();
    await user.click(within(navigation).getByRole("link", { name: "Selection & sizing" }));
    expect(navigation).not.toBeVisible();
  });

  it("closes mobile navigation with Escape and restores toggle focus", async () => {
    const user = userEvent.setup();
    renderShell();
    const openButton = screen.getByRole("button", { name: "Open navigation" });
    await user.click(openButton);
    const navigation = screen.getByRole("navigation", { name: "Mobile product navigation" });
    navigation.focus();
    await user.keyboard("{Escape}");
    expect(navigation).not.toBeVisible();
    expect(openButton).toHaveFocus();
  });
});
