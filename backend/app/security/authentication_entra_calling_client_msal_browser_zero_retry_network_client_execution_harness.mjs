import { pathToFileURL } from "node:url";

if (process.argv.length !== 3) {
    throw new Error("exact zero-retry adapter path required");
}

const adapterUrl = pathToFileURL(process.argv[2]).href;
const imported = await import(adapterUrl);
if (typeof imported.Engineer4MeMSALZeroRetryNetworkClient !== "function") {
    throw new Error("exact zero-retry adapter export required");
}

const Adapter = imported.Engineer4MeMSALZeroRetryNetworkClient;
const tokenEndpoint =
    "https://login.microsoftonline.invalid/tenant/oauth2/v2.0/token";
const metadataEndpoint =
    "https://login.microsoftonline.invalid/tenant/v2.0/.well-known/openid-configuration";
const postOptions = Object.freeze({
    body: "client_id=fixture&code=fixture&code_verifier=fixture",
    headers: Object.freeze({
        "content-type": "application/x-www-form-urlencoded;charset=utf-8",
    }),
});
const encoder = new TextEncoder();

function jsonResponse(status, value, extraHeaders = []) {
    const bytes = encoder.encode(JSON.stringify(value));
    return {
        status,
        headers: {
            entries() {
                return [
                    ["content-type", "application/json"],
                    ...extraHeaders,
                ][Symbol.iterator]();
            },
        },
        body: new ReadableStream({
            start(controller) {
                controller.enqueue(bytes);
                controller.close();
            },
        }),
    };
}

function oversizedResponse() {
    return {
        status: 200,
        headers: {
            entries() {
                return [["content-type", "application/json"]][Symbol.iterator]();
            },
        },
        body: new ReadableStream({
            start(controller) {
                controller.enqueue(new Uint8Array(1_048_577));
                controller.close();
            },
        }),
    };
}

function optionProjection(options) {
    return {
        cache: options.cache,
        credentials: options.credentials,
        hasAbortSignal:
            typeof options.signal === "object" &&
            typeof options.signal.aborted === "boolean",
        method: options.method,
        mode: options.mode,
        redirect: options.redirect,
        referrerPolicy: options.referrerPolicy,
    };
}

async function execute({ name, method = "POST", target = tokenEndpoint, options, fetch }) {
    const calls = [];
    const client = new Adapter({
        fetchImplementation: async (url, fetchOptions) => {
            calls.push({
                url,
                options: optionProjection(fetchOptions),
            });
            return fetch(url, fetchOptions, calls.length);
        },
        tokenEndpoint,
        allowedGetEndpoints: [metadataEndpoint],
    });
    let status = null;
    let bodyKind = null;
    let errorMessage = null;
    try {
        const result =
            method === "POST"
                ? await client.sendPostRequestAsync(target, options ?? postOptions)
                : await client.sendGetRequestAsync(target, options ?? {});
        status = result.status;
        bodyKind = result.body.error ? "oauth_error" : "success";
    } catch (error) {
        errorMessage = error?.message ?? "Error";
    }
    return {
        name,
        attemptCount: calls.length,
        status,
        bodyKind,
        errorMessage,
        optionProjection: calls.length === 1 ? calls[0].options : null,
    };
}

const scenarios = [];
scenarios.push(
    await execute({
        name: "post_success_once",
        fetch: async () => jsonResponse(200, { access_token: "synthetic" }),
    }),
);
scenarios.push(
    await execute({
        name: "get_success_once",
        method: "GET",
        target: metadataEndpoint,
        fetch: async () => jsonResponse(200, { issuer: "synthetic" }),
    }),
);
scenarios.push(
    await execute({
        name: "transport_failure_no_retry",
        fetch: async () => {
            throw new TypeError("private transport detail");
        },
    }),
);
scenarios.push(
    await execute({
        name: "abort_failure_no_retry",
        fetch: async () => {
            const error = new Error("private abort detail");
            error.name = "AbortError";
            throw error;
        },
    }),
);
scenarios.push(
    await execute({
        name: "invalid_json_no_retry",
        fetch: async () => {
            const bytes = encoder.encode("not-json");
            return {
                status: 200,
                headers: {
                    entries() {
                        return [["content-type", "application/json"]][Symbol.iterator]();
                    },
                },
                body: new ReadableStream({
                    start(controller) {
                        controller.enqueue(bytes);
                        controller.close();
                    },
                }),
            };
        },
    }),
);
scenarios.push(
    await execute({
        name: "http_400_returned_once",
        fetch: async () => jsonResponse(400, { status: 400 }),
    }),
);
scenarios.push(
    await execute({
        name: "oauth_invalid_grant_returned_once",
        fetch: async () => jsonResponse(400, { error: "invalid_grant" }),
    }),
);
scenarios.push(
    await execute({
        name: "wrong_post_target_rejected_before_fetch",
        target: "https://login.microsoftonline.invalid/tenant/not-token",
        fetch: async () => jsonResponse(200, { ok: true }),
    }),
);
scenarios.push(
    await execute({
        name: "forbidden_header_rejected_before_fetch",
        options: {
            body: postOptions.body,
            headers: { authorization: "private" },
        },
        fetch: async () => jsonResponse(200, { ok: true }),
    }),
);
scenarios.push(
    await execute({
        name: "unapproved_get_rejected_before_fetch",
        method: "GET",
        target: "https://login.microsoftonline.invalid/tenant/unapproved",
        fetch: async () => jsonResponse(200, { ok: true }),
    }),
);
scenarios.push(
    await execute({
        name: "get_body_rejected_before_fetch",
        method: "GET",
        target: metadataEndpoint,
        options: { body: "forbidden" },
        fetch: async () => jsonResponse(200, { ok: true }),
    }),
);
scenarios.push(
    await execute({
        name: "oversized_response_no_retry",
        fetch: async () => oversizedResponse(),
    }),
);
scenarios.push(
    await execute({
        name: "duplicate_response_header_no_retry",
        fetch: async () =>
            jsonResponse(200, { ok: true }, [["Content-Type", "application/json"]]),
    }),
);
scenarios.push(
    await execute({
        name: "timeout_abort_no_retry",
        fetch: async (_url, options) =>
            new Promise((_resolve, reject) => {
                options.signal.addEventListener(
                    "abort",
                    () => reject(new Error("private timeout detail")),
                    { once: true },
                );
            }),
    }),
);

let concurrentAttempts = 0;
const concurrentClient = new Adapter({
    fetchImplementation: async () => {
        concurrentAttempts += 1;
        return jsonResponse(200, { ok: true });
    },
    tokenEndpoint,
    allowedGetEndpoints: [],
});
const concurrent = await Promise.all([
    concurrentClient.sendPostRequestAsync(tokenEndpoint, postOptions),
    concurrentClient.sendPostRequestAsync(tokenEndpoint, postOptions),
]);
scenarios.push({
    name: "concurrent_calls_one_attempt_each",
    attemptCount: concurrentAttempts,
    perRequestAttempts: [1, 1],
    statuses: concurrent.map((result) => result.status),
    bodyKind: "success",
    errorMessage: null,
    optionProjection: null,
});

process.stdout.write(
    `${JSON.stringify({
        schemaVersion: 1,
        scenarioCount: scenarios.length,
        scenarios,
    })}\n`,
);
