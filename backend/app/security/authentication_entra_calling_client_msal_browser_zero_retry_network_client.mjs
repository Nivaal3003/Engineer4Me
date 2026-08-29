const TOKEN_POST_ATTEMPTS = 1;
const TOKEN_POST_RETRIES = 0;
const REQUEST_TIMEOUT_MILLISECONDS = 10_000;
const MAXIMUM_RESPONSE_BYTES = 1_048_576;

const FORBIDDEN_REQUEST_HEADERS = new Set([
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "transfer-encoding",
]);

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

function exactUrl(value, label) {
    if (typeof value !== "string" || value.length === 0 || value.length > 2_048) {
        throw new TypeError(`${label} is invalid`);
    }
    const parsed = new URL(value);
    if (
        parsed.protocol !== "https:" ||
        parsed.username !== "" ||
        parsed.password !== "" ||
        parsed.hash !== "" ||
        parsed.port !== "" ||
        parsed.href !== value
    ) {
        throw new TypeError(`${label} is invalid`);
    }
    return value;
}

function normalizeRequestHeaders(value) {
    if (value === undefined) {
        return Object.freeze({});
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("request headers are invalid");
    }
    const normalized = Object.create(null);
    for (const [rawName, rawValue] of Object.entries(value)) {
        if (
            !HEADER_NAME.test(rawName) ||
            typeof rawValue !== "string" ||
            rawValue !== rawValue.trim() ||
            /[\u0000-\u001f\u007f]/u.test(rawValue)
        ) {
            throw new TypeError("request headers are invalid");
        }
        const name = rawName.toLowerCase();
        if (
            FORBIDDEN_REQUEST_HEADERS.has(name) ||
            Object.prototype.hasOwnProperty.call(normalized, name)
        ) {
            throw new TypeError("request headers are invalid");
        }
        normalized[name] = rawValue;
    }
    return Object.freeze(normalized);
}

function normalizeResponseHeaders(headers) {
    if (headers === null || typeof headers !== "object" || !headers.entries) {
        throw new TypeError("response headers are invalid");
    }
    const normalized = Object.create(null);
    for (const entry of headers.entries()) {
        if (!Array.isArray(entry) || entry.length !== 2) {
            throw new TypeError("response headers are invalid");
        }
        const [rawName, rawValue] = entry;
        if (
            typeof rawName !== "string" ||
            !HEADER_NAME.test(rawName) ||
            typeof rawValue !== "string" ||
            rawValue !== rawValue.trim() ||
            /[\u0000-\u001f\u007f]/u.test(rawValue)
        ) {
            throw new TypeError("response headers are invalid");
        }
        const name = rawName.toLowerCase();
        if (Object.prototype.hasOwnProperty.call(normalized, name)) {
            throw new TypeError("response headers are invalid");
        }
        normalized[name] = rawValue;
    }
    return Object.freeze(normalized);
}

async function readBoundedJsonBody(response) {
    if (
        response === null ||
        typeof response !== "object" ||
        !Number.isInteger(response.status) ||
        response.status < 100 ||
        response.status > 599 ||
        response.body === null ||
        typeof response.body !== "object" ||
        typeof response.body.getReader !== "function"
    ) {
        throw new TypeError("response is invalid");
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
        for (;;) {
            const result = await reader.read();
            if (
                result === null ||
                typeof result !== "object" ||
                typeof result.done !== "boolean"
            ) {
                throw new TypeError("response stream is invalid");
            }
            if (result.done) {
                if (result.value !== undefined) {
                    throw new TypeError("response stream is invalid");
                }
                break;
            }
            if (!(result.value instanceof Uint8Array) || result.value.byteLength === 0) {
                throw new TypeError("response stream is invalid");
            }
            total += result.value.byteLength;
            if (total > MAXIMUM_RESPONSE_BYTES) {
                throw new RangeError("response body is too large");
            }
            chunks.push(result.value);
        }
    } finally {
        reader.releaseLock?.();
    }
    const bodyBytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bodyBytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
    const body = JSON.parse(text);
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw new TypeError("response JSON is invalid");
    }
    return Object.freeze({
        body,
        headers: normalizeResponseHeaders(response.headers),
        status: response.status,
    });
}

class Engineer4MeMSALZeroRetryNetworkClient {
    #allowedGetEndpoints;
    #fetchImplementation;
    #tokenEndpoint;

    constructor({ fetchImplementation, tokenEndpoint, allowedGetEndpoints }) {
        if (typeof fetchImplementation !== "function") {
            throw new TypeError("fetch implementation is invalid");
        }
        if (!Array.isArray(allowedGetEndpoints) || allowedGetEndpoints.length > 16) {
            throw new TypeError("allowed GET endpoints are invalid");
        }
        const getEndpoints = allowedGetEndpoints.map((value) => exactUrl(value, "GET endpoint"));
        if (new Set(getEndpoints).size !== getEndpoints.length) {
            throw new TypeError("allowed GET endpoints are invalid");
        }
        this.#fetchImplementation = fetchImplementation;
        this.#tokenEndpoint = exactUrl(tokenEndpoint, "token endpoint");
        this.#allowedGetEndpoints = new Set(getEndpoints);
    }

    async #send(url, options, method) {
        if (typeof url !== "string" || options === null || typeof options !== "object") {
            throw new TypeError("network request is invalid");
        }
        if (
            (method === "POST" && url !== this.#tokenEndpoint) ||
            (method === "GET" && !this.#allowedGetEndpoints.has(url))
        ) {
            throw new TypeError("network request target is not approved");
        }
        const headers = normalizeRequestHeaders(options.headers);
        let body;
        if (method === "POST") {
            if (typeof options.body !== "string" || options.body.length > 131_072) {
                throw new TypeError("token request body is invalid");
            }
            body = options.body;
        } else if (options.body !== undefined) {
            throw new TypeError("GET request body is forbidden");
        }
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MILLISECONDS);
        try {
            const response = await this.#fetchImplementation(url, {
                body,
                cache: "no-store",
                credentials: "omit",
                headers,
                method,
                mode: "cors",
                redirect: "error",
                referrerPolicy: "no-referrer",
                signal: controller.signal,
            });
            return await readBoundedJsonBody(response);
        } catch {
            throw new Error("MSAL network request failed");
        } finally {
            clearTimeout(timeout);
            body = undefined;
        }
    }

    async sendGetRequestAsync(url, options = {}) {
        return this.#send(url, options, "GET");
    }

    async sendPostRequestAsync(url, options) {
        return this.#send(url, options, "POST");
    }
}

export {
    Engineer4MeMSALZeroRetryNetworkClient,
    MAXIMUM_RESPONSE_BYTES,
    REQUEST_TIMEOUT_MILLISECONDS,
    TOKEN_POST_ATTEMPTS,
    TOKEN_POST_RETRIES,
};
