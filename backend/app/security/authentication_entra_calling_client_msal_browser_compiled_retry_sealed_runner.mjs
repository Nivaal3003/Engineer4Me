import { pathToFileURL } from "node:url";

if (process.argv.length !== 5) {
    throw new Error("exact runner, harness, and compiled entry arguments required");
}
if (typeof process.permission?.has !== "function") {
    throw new Error("Node permission model is required");
}

const harnessPath = process.argv[2];
const compiledEntryPath = process.argv[3];
const expectedHarnessSha256 = process.argv[4];
if (!/^[0-9a-f]{64}$/.test(expectedHarnessSha256)) {
    throw new Error("exact harness digest argument required");
}

const permissions = Object.freeze({
    network: process.permission.has("net"),
    childProcess: process.permission.has("child"),
    worker: process.permission.has("worker"),
    fileSystemWrite: process.permission.has("fs.write"),
    addons: process.permission.has("addons"),
    wasi: process.permission.has("wasi"),
    inspector: process.permission.has("inspector"),
    ffi: process.permission.has("ffi"),
});
if (Object.values(permissions).some(Boolean)) {
    throw new Error("sealed runner received a forbidden permission");
}

process.stdout.write(
    `${JSON.stringify({
        runnerSchemaVersion: 1,
        nodeVersion: process.version,
        harnessSha256: expectedHarnessSha256,
        permissions,
    })}\n`,
);

process.argv = [process.execPath, harnessPath, compiledEntryPath];
await import(pathToFileURL(harnessPath).href);
