import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router";
import { RouteLifecycle } from "./RouteLifecycle";

function LifecycleFixture() {
  return (
    <>
      <RouteLifecycle />
      <Link to="/selection">Selection</Link>
      <main id="main-content" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<h1>Home</h1>} />
          <Route path="/selection" element={<h1>Selection</h1>} />
        </Routes>
      </main>
    </>
  );
}

describe("Engineer4Me route lifecycle", () => {
  it("updates the document title and focuses main content after navigation", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <LifecycleFixture />
      </MemoryRouter>,
    );

    await waitFor(() => expect(document.title).toBe("Home — Engineer4Me"));
    await user.click(screen.getByRole("link", { name: "Selection" }));

    await waitFor(() => {
      expect(document.title).toBe("Selection & sizing — Engineer4Me");
      expect(screen.getByRole("main")).toHaveFocus();
    });
  });
});
