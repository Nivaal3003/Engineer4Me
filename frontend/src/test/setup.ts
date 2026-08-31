import "@testing-library/jest-dom/vitest";
import { afterAll, beforeAll } from "vitest";
import { installUnitTestNetworkGuard } from "./network-guard";

let restoreNetworkGuard: (() => void) | undefined;

beforeAll(() => {
  restoreNetworkGuard = installUnitTestNetworkGuard();
});

afterAll(() => {
  restoreNetworkGuard?.();
  restoreNetworkGuard = undefined;
});
