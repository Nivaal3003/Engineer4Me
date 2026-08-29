import { pathToFileURL } from "node:url";

if (process.argv.length !== 3) {
    throw new Error("exact compiled FetchClient path required");
}

globalThis.window = Object.freeze({ navigator: Object.freeze({ onLine: true }) });
const entryUrl = pathToFileURL(process.argv[2]).href;
const imported = await import(entryUrl);
if (typeof imported.FetchClient !== "function") {
    throw new Error("exact FetchClient export required");
}

const FetchClient = imported.FetchClient;
const tokenUrl = "https://login.microsoftonline.invalid/tenant/oauth2/v2.0/token";
const nonTokenUrl = "https://login.microsoftonline.invalid/tenant/not-token";
const requestOptions = Object.freeze({
    body: "client_id=fixture&code=fixture&code_verifier=fixture&redirect_uri=https%3A%2F%2Fapp.invalid%2Fcallback",
    headers: Object.freeze({ "content-type": "application/x-www-form-urlencoded" }),
    correlationId: "00000000-0000-4000-8000-000000000222",
});

function jsonResponse(status, body) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
    });
}

async function execute(name, url, outcomes) {
    const calls = [];
    const telemetry = [];
    globalThis.fetch = async (requestUrl, options) => {
        calls.push({
            url: requestUrl,
            method: options.method,
            body: options.body,
            headers: [...options.headers.entries()].sort(),
            time: Date.now(),
        });
        const outcome = outcomes[Math.min(calls.length - 1, outcomes.length - 1)];
        if (outcome instanceof Error) {
            throw outcome;
        }
        return outcome;
    };
    const performanceClient = {
        incrementFields(value, correlationId) {
            telemetry.push({ value, correlationId });
        },
    };
    let result = null;
    let errorName = null;
    try {
        result = await new FetchClient().sendPostRequestAsync(url, {
            ...requestOptions,
            performanceClient,
        });
    } catch (error) {
        errorName = error?.name ?? "Error";
    }
    return {
        name,
        attemptCount: calls.length,
        elapsedBetweenAttemptsMilliseconds:
            calls.length > 1 ? calls[1].time - calls[0].time : null,
        requestEquivalent:
            calls.length < 2 ||
            JSON.stringify({ ...calls[0], time: 0 }) ===
                JSON.stringify({ ...calls[1], time: 0 }),
        status: result?.status ?? null,
        errorName,
        telemetry,
    };
}

function transportError(name = "TypeError") {
    const error = new Error("synthetic transport failure");
    error.name = name;
    return error;
}

const scenarios = [];
scenarios.push(
    await execute("transport_failure_then_success", tokenUrl, [
        transportError(),
        jsonResponse(200, { ok: true }),
    ]),
);
scenarios.push(
    await execute("two_transport_failures", tokenUrl, [
        transportError(),
        transportError(),
    ]),
);
for (const status of [400, 429, 500]) {
    scenarios.push(
        await execute(`http_${status}_no_retry`, tokenUrl, [
            jsonResponse(status, { status }),
        ]),
    );
}
scenarios.push(
    await execute("oauth_error_no_retry", tokenUrl, [
        jsonResponse(400, { error: "invalid_grant" }),
    ]),
);
scenarios.push(
    await execute("abort_no_retry", tokenUrl, [transportError("AbortError")]),
);
scenarios.push(
    await execute("non_token_transport_failure", nonTokenUrl, [
        transportError(),
        jsonResponse(200, { ok: true }),
    ]),
);

const concurrentCalls = new Map();
globalThis.fetch = async (url, options) => {
    const key = options.body.includes("fixture") ? String(url) : "unknown";
    const count = (concurrentCalls.get(key) ?? 0) + 1;
    concurrentCalls.set(key, count);
    if (count === 1) {
        throw transportError();
    }
    return jsonResponse(200, { ok: true });
};
const concurrentStart = Date.now();
const concurrentResults = await Promise.all([
    new FetchClient().sendPostRequestAsync(`${tokenUrl}?case=a`, requestOptions),
    new FetchClient().sendPostRequestAsync(`${tokenUrl}?case=b`, requestOptions),
]);
scenarios.push({
    name: "concurrent_isolation",
    attemptCount: [...concurrentCalls.values()].reduce((a, b) => a + b, 0),
    perRequestAttempts: [...concurrentCalls.values()].sort(),
    elapsedMilliseconds: Date.now() - concurrentStart,
    statuses: concurrentResults.map((result) => result.status),
});

const equivalence = scenarios[0];
scenarios.push({
    name: "telemetry_and_request_equivalence",
    attemptCount: equivalence.attemptCount,
    requestEquivalent: equivalence.requestEquivalent,
    telemetry: equivalence.telemetry,
});

process.stdout.write(
    `${JSON.stringify({
        schemaVersion: 1,
        scenarioCount: scenarios.length,
        scenarios,
    })}\n`,
);
