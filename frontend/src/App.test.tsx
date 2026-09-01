import { render, screen } from "@testing-library/react";
import App from "./App";

describe("Engineer4Me mobile-first product foundation", () => {
  it("renders semantic shell regions and the controlled product message", () => {
    render(<App />);
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Engineering decisions, with evidence visible",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
  });

  it("keeps authentication, transport, routing, and approval boundaries fail closed", () => {
    render(<App />);
    expect(screen.getAllByText("Blocked").length).toBeGreaterThan(0);
    expect(screen.getByText("API transport")).toBeInTheDocument();
    expect(screen.getByText("No standards conformity claim")).toBeInTheDocument();
    expect(screen.getByText(/Final engineering approval remains/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/i })).not.toBeInTheDocument();
  });

  it("presents capability ownership without pretending integration is active", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Selection & sizing" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Troubleshooting" })).toBeInTheDocument();
    expect(screen.getAllByText("No route or API connection")).toHaveLength(6);
  });
});
