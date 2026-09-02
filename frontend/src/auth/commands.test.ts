import { evaluateAuthenticationCommand } from "./commands";

const READY = {
  sourceReady: true,
  interactiveExecutionReady: true,
  missingGates: [],
  safeSummary: "ready",
} as const;
const CONTEXT = {
  userInitiated: false,
  redirectReturnPresent: false,
  authenticatedIdentityPresent: false,
  backendAuthorizationPresent: false,
} as const;

describe("explicit authentication command policy", () => {
  it("forbids automatic sign-in and initialization", () => {
    expect(evaluateAuthenticationCommand(READY, "begin_sign_in", CONTEXT).allowed).toBe(false);
    expect(evaluateAuthenticationCommand(READY, "initialize", CONTEXT).allowed).toBe(false);
  });

  it("allows token acquisition only after identity and backend authorization", () => {
    expect(evaluateAuthenticationCommand(READY, "acquire_access_token", {
      ...CONTEXT,
      authenticatedIdentityPresent: true,
      backendAuthorizationPresent: true,
    }).allowed).toBe(true);
  });

  it("fails every command closed while activation evidence is incomplete", () => {
    expect(evaluateAuthenticationCommand({ ...READY, interactiveExecutionReady: false }, "begin_sign_in", {
      ...CONTEXT,
      userInitiated: true,
    }).allowed).toBe(false);
  });
});
