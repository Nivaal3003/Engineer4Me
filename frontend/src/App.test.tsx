import { render, screen } from "@testing-library/react";
import App from "./App";

describe("Engineer4Me frontend security bootstrap", () => {
  it("keeps authentication activation blocked by default", () => {
    render(<App />);

    expect(screen.getByText("Authentication activation")).toBeInTheDocument();
    expect(screen.getByText("Blocked")).toBeInTheDocument();
  });
});
