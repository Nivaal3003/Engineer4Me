import { render, screen } from "@testing-library/react";
import { INITIAL_PRODUCT_STATUS } from "../foundation";
import { StatusSummary } from "./StatusSummary";

describe("Engineer4Me product status summary", () => {
  it("keeps security and transport boundaries visibly inactive", () => {
    render(
      <StatusSummary
        authenticationStatus="Configuration review is incomplete."
        productStatus={INITIAL_PRODUCT_STATUS}
      />,
    );
    expect(screen.getByText("Authentication activation")).toBeInTheDocument();
    expect(screen.getByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("API transport")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
  });
});
