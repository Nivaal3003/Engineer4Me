import { normalizeAuthenticationFailure } from "./failures";
import {
  beginExplicitAuthenticationCommand,
  createAuthenticationActivationRuntimeSnapshot,
  markAuthenticationRedirectPending,
  markAuthenticationRuntimeFailure,
} from "./runtime";

const READY = {
  sourceReady: true,
  interactiveExecutionReady: true,
  missingGates: [],
  safeSummary: "ready",
} as const;

describe("authentication activation runtime", () => {
  it("starts inactive and permits transitions only after an explicit command", () => {
    const initial = createAuthenticationActivationRuntimeSnapshot(READY);
    expect(initial).toMatchObject({ phase: "ready_inactive", automaticExecution: false, browserPersistence: false });
    expect(() => markAuthenticationRedirectPending(initial)).toThrow();
    const pending = beginExplicitAuthenticationCommand(initial, "begin_sign_in");
    expect(markAuthenticationRedirectPending(pending).phase).toBe("redirect_pending");
  });

  it("retains only normalized safe failure evidence", () => {
    const initial = createAuthenticationActivationRuntimeSnapshot(READY);
    const failed = markAuthenticationRuntimeFailure(
      initial,
      normalizeAuthenticationFailure({ message: "secret token" }, "correlation-1"),
    );
    expect(failed.phase).toBe("error");
    expect(JSON.stringify(failed)).not.toContain("secret token");
  });
});
