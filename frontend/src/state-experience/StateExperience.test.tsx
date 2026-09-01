import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createStateExperience } from "./models";
import { StateExperience } from "./StateExperience";

describe("Engineer4Me state experiences", () => {
  it("renders loading, empty, degraded, unavailable, and not-found states semantically", () => {
    const { rerender } = render(<StateExperience model={createStateExperience("loading")} />);
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Loading requested view" })).toBeInTheDocument();

    for (const kind of ["empty", "unavailable", "not_found"] as const) {
      const model = createStateExperience(kind);
      rerender(<StateExperience model={model} />);
      expect(screen.getByRole("region", { name: model.title })).toBeInTheDocument();
    }

    const degraded = createStateExperience("degraded");
    rerender(<StateExperience model={degraded} />);
    expect(screen.getByRole("status")).toHaveAccessibleName(degraded.title);
  });

  it("exposes controlled errors and only renders an authorized retry", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    const model = createStateExperience("error", {
      correlationId: "corr-456",
      retryAuthorized: true,
    });
    render(<StateExperience model={model} onRetry={onRetry} />);

    expect(screen.getByRole("alert")).toHaveAccessibleName(model.title);
    expect(screen.getByText("corr-456")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry controlled request" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
