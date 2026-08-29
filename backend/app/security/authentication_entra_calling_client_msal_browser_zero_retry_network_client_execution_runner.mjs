import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

if (process.argv.length !== 6) {
    throw new Error("exact runner arguments required");
}
if (typeof process.permission?.has !== "function") {
    throw new Error("Node permission model is required");
}

const harnessPath = process.argv[2];
const adapterPath = process.argv[3];
const expectedHarnessSha256 = process.argv[4];
const expectedAdapterSha256 = process.argv[5];
for (const digest of [expectedHarnessSha256, expectedAdapterSha256]) {
    if (!/^[0-9a-f]{64}$/u.test(digest)) {
        throw new Error("exact source digest arguments required");
    }
}

const permissions = Object.freeze({
    childProcess: process.permission.has("child"),
    worker: process.permission.has("worker"),
    fileSystemWrite: process.permission.has("fs.write"),
    addons: process.permission.has("addons"),
    wasi: process.permission.has("wasi"),
    inspector: process.permission.has("inspector"),
});
if (Object.values(permissions).some(Boolean)) {
    throw new Error("sealed runner received a forbidden permission");
}

const harness = await readFile(harnessPath);
const adapter = await readFile(adapterPath);
const harnessSha256 = createHash("sha256").update(harness).digest("hex");
const adapterSha256 = createHash("sha256").update(adapter).digest("hex");
if (
    harnessSha256 !== expectedHarnessSha256 ||
    adapterSha256 !== expectedAdapterSha256
) {
    throw new Error("sealed execution source identity changed");
}

Object.defineProperty(globalThis, "fetch", {
    value: () => {
        throw new Error("global fetch is forbidden by the sealed harness");
    },
    writable: false,
    configurable: false,
});

process.stdout.write(
    `${JSON.stringify({
        runnerSchemaVersion: 1,
        nodeVersion: process.version,
        harnessSha256,
        adapterSha256,
        permissions,
        globalFetchDisabled: true,
        operatingSystemNetworkCapabilityDenied: false,
    })}\n`,
);

process.argv = [process.execPath, harnessPath, adapterPath];
await import(pathToFileURL(harnessPath).href);
