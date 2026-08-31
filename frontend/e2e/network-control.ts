import type { Page, Route } from "@playwright/test";

export const CONTROLLED_E2E_ORIGIN = "http://127.0.0.1:4173" as const;

const NON_NETWORK_PROTOCOLS = new Set(["about:", "blob:", "data:"]);

export function isAllowedE2eRequestUrl(value: string): boolean {
  const url = new URL(value);
  if (NON_NETWORK_PROTOCOLS.has(url.protocol)) {
    return true;
  }
  return url.origin === CONTROLLED_E2E_ORIGIN;
}

async function continueOrBlock(route: Route): Promise<void> {
  const requestUrl = route.request().url();
  if (isAllowedE2eRequestUrl(requestUrl)) {
    await route.continue();
    return;
  }
  await route.abort("blockedbyclient");
}

export async function installE2eNetworkControl(page: Page): Promise<void> {
  await page.route("**/*", continueOrBlock);
}
