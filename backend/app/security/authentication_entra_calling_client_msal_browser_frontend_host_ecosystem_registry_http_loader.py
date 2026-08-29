"""Bounded live official-registry loader for the Step 236 frontend tuple.

This module owns the only Step 236 network path.  It accepts no URL, host,
package name, version, header, credential, proxy, redirect, or retry choice
from its caller.  The CLI reads one bounded authorization document, obtains a
closed set of public npm and Node.js metadata responses, delegates the pure
compatibility decision to the sibling probe, and writes one canonical receipt.

It never downloads a package tarball or Node.js binary and never invokes npm,
Node.js, a browser, OAuth, or an application endpoint.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import quote

import httpx

_CANONICAL_MODULE_NAME = (
    "app.security."
    "authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_registry_http_loader"
)
if __name__ == "__main__":
    _canonical_name = getattr(__spec__, "name", None)
    _current_module = sys.modules.get(__name__)
    _existing_module = (
        sys.modules.get(_canonical_name) if type(_canonical_name) is str else None
    )
    if (
        _canonical_name != _CANONICAL_MODULE_NAME
        or _current_module is None
        or (_existing_module is not None and _existing_module is not _current_module)
    ):
        raise RuntimeError("Step 236 CLI module identity cannot be bound safely")
    sys.modules[_CANONICAL_MODULE_NAME] = _current_module

NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
NODE_DISTRIBUTION_ORIGIN = "https://nodejs.org"
NODE_VERSION = "24.19.0"
NODE_VERSION_TAG = "v24.19.0"
NPM_VERSION = "11.17.0"

MAX_AUTHORIZATION_BYTES = 16_384
MAX_REQUEST_COUNT = 27
MAX_AGGREGATE_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_NPM_METADATA_BYTES = 512 * 1024
MAX_NPM_KEYS_BYTES = 128 * 1024
MAX_NPM_ADVISORY_BYTES = 1024 * 1024
MAX_NODE_INDEX_BYTES = 2 * 1024 * 1024
MAX_NODE_SHASUMS_BYTES = 512 * 1024
MAX_ADVISORY_REQUEST_BYTES = 16_384
MAX_RESPONSE_HEADER_COUNT = 64
MAX_RESPONSE_HEADER_BYTES = 16_384
EXECUTION_DEADLINE_SECONDS = 90.0
USER_AGENT = "Engineer4Me-Step236-OfficialRegistryProof/1"


@dataclass(frozen=True, slots=True)
class EcosystemPackageSelection:
    name: str
    version: str
    role: Literal[
        "production_direct",
        "development_direct",
        "mandatory_transitive_anchor",
        "toolchain",
    ]


DIRECT_PACKAGES = (
    EcosystemPackageSelection(
        "@azure/msal-browser", "5.18.0", "production_direct"
    ),
    EcosystemPackageSelection("react", "19.2.8", "production_direct"),
    EcosystemPackageSelection("react-dom", "19.2.8", "production_direct"),
    EcosystemPackageSelection("react-router", "8.3.0", "production_direct"),
    EcosystemPackageSelection(
        "@axe-core/playwright", "4.13.0", "development_direct"
    ),
    EcosystemPackageSelection(
        "@playwright/test", "1.62.1", "development_direct"
    ),
    EcosystemPackageSelection(
        "@testing-library/dom", "10.4.1", "development_direct"
    ),
    EcosystemPackageSelection(
        "@testing-library/jest-dom", "7.0.1", "development_direct"
    ),
    EcosystemPackageSelection(
        "@testing-library/react", "16.3.2", "development_direct"
    ),
    EcosystemPackageSelection(
        "@testing-library/user-event", "14.6.5", "development_direct"
    ),
    EcosystemPackageSelection("@types/node", "24.13.3", "development_direct"),
    EcosystemPackageSelection("@types/react", "19.2.18", "development_direct"),
    EcosystemPackageSelection(
        "@types/react-dom", "19.2.4", "development_direct"
    ),
    EcosystemPackageSelection(
        "@vitejs/plugin-react", "6.0.5", "development_direct"
    ),
    EcosystemPackageSelection("axe-core", "4.13.0", "development_direct"),
    EcosystemPackageSelection("jsdom", "30.0.1", "development_direct"),
    EcosystemPackageSelection("typescript", "6.0.2", "development_direct"),
    EcosystemPackageSelection("vite", "8.2.1", "development_direct"),
    EcosystemPackageSelection("vitest", "4.1.11", "development_direct"),
)
TRANSITIVE_ANCHOR_PACKAGES = (
    EcosystemPackageSelection(
        "@azure/msal-common", "16.12.0", "mandatory_transitive_anchor"
    ),
    EcosystemPackageSelection(
        "playwright", "1.62.1", "mandatory_transitive_anchor"
    ),
    EcosystemPackageSelection(
        "playwright-core", "1.62.1", "mandatory_transitive_anchor"
    ),
)
SELECTED_PACKAGES = DIRECT_PACKAGES + TRANSITIVE_ANCHOR_PACKAGES
TOOLCHAIN_NPM_PACKAGE = EcosystemPackageSelection(
    "npm", NPM_VERSION, "toolchain"
)


@dataclass(frozen=True, slots=True)
class _RequestSpec:
    request_id: str
    method: Literal["GET", "POST"]
    url: str
    accepted_media_types: tuple[str, ...]
    maximum_response_bytes: int
    request_body: bytes | None = None
    allow_missing_content_type: bool = False


@dataclass(frozen=True, slots=True)
class BoundedOfficialHttpResponse:
    request_id: str
    method: str
    url: str
    status_code: int
    media_type: str
    body: bytes
    body_sha256: str


@dataclass(frozen=True, slots=True)
class LiveEcosystemRegistryEvidence:
    evidence_source: Literal[
        "live_bounded_official_https", "synthetic_mock_transport"
    ]
    requests: tuple[BoundedOfficialHttpResponse, ...]
    request_count: int
    aggregate_response_bytes: int
    redirects_followed: int
    automatic_retries: int
    environment_proxy_configuration_used: bool
    credentials_sent: bool
    package_tarball_downloaded: bool
    node_binary_downloaded: bool
    _loader_attestation: object = field(repr=False, compare=False)


class EcosystemRegistryHttpLoaderError(RuntimeError):
    """Sanitized bounded official-registry transport failure."""


_LIVE_EVIDENCE_ATTESTATION = object()
_SYNTHETIC_EVIDENCE_ATTESTATION = object()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _package_metadata_url(selection: EcosystemPackageSelection) -> str:
    encoded_name = quote(selection.name, safe="@")
    return f"{NPM_REGISTRY_ORIGIN}/{encoded_name}/{selection.version}"


def _advisory_request_body() -> bytes:
    packages = {
        selection.name: [selection.version]
        for selection in SELECTED_PACKAGES + (TOOLCHAIN_NPM_PACKAGE,)
    }
    body = _canonical(packages)
    if not body or len(body) > MAX_ADVISORY_REQUEST_BYTES:
        raise EcosystemRegistryHttpLoaderError(
            "official registry advisory request is outside the approved bound"
        )
    return body


def _request_specs() -> tuple[_RequestSpec, ...]:
    package_specs = tuple(
        _RequestSpec(
            request_id=f"npm-package:{selection.name}@{selection.version}",
            method="GET",
            url=_package_metadata_url(selection),
            accepted_media_types=("application/json",),
            maximum_response_bytes=MAX_NPM_METADATA_BYTES,
        )
        for selection in SELECTED_PACKAGES + (TOOLCHAIN_NPM_PACKAGE,)
    )
    return package_specs + (
        _RequestSpec(
            request_id="npm-signing-keys",
            method="GET",
            url=f"{NPM_REGISTRY_ORIGIN}/-/npm/v1/keys",
            accepted_media_types=("application/json",),
            maximum_response_bytes=MAX_NPM_KEYS_BYTES,
        ),
        _RequestSpec(
            request_id="npm-direct-advisories",
            method="POST",
            url=f"{NPM_REGISTRY_ORIGIN}/-/npm/v1/security/advisories/bulk",
            accepted_media_types=("application/json",),
            maximum_response_bytes=MAX_NPM_ADVISORY_BYTES,
            request_body=_advisory_request_body(),
            allow_missing_content_type=True,
        ),
        _RequestSpec(
            request_id="node-release-index",
            method="GET",
            url=f"{NODE_DISTRIBUTION_ORIGIN}/dist/index.json",
            accepted_media_types=("application/json", "text/json"),
            maximum_response_bytes=MAX_NODE_INDEX_BYTES,
        ),
        _RequestSpec(
            request_id="node-release-shasums",
            method="GET",
            url=(
                f"{NODE_DISTRIBUTION_ORIGIN}/dist/{NODE_VERSION_TAG}/"
                "SHASUMS256.txt"
            ),
            accepted_media_types=("text/plain", "application/octet-stream"),
            maximum_response_bytes=MAX_NODE_SHASUMS_BYTES,
        ),
    )


def official_request_contract_projection() -> tuple[dict[str, object], ...]:
    """Expose only the closed request correlation contract to the pure probe."""

    return tuple(
        {
            "request_id": spec.request_id,
            "method": spec.method,
            "url": spec.url,
            "accepted_media_types": spec.accepted_media_types,
            "allow_missing_content_type": spec.allow_missing_content_type,
        }
        for spec in _request_specs()
    )


def _validated_content_length(
    response: httpx.Response, maximum_response_bytes: int
) -> None:
    value = response.headers.get("content-length")
    if value is None:
        return
    if not value.isascii() or not value.isdecimal():
        raise EcosystemRegistryHttpLoaderError(
            "official registry response content length is invalid"
        )
    length = int(value)
    if length < 0 or length > maximum_response_bytes:
        raise EcosystemRegistryHttpLoaderError(
            "official registry response exceeds its approved bound"
        )


def _validate_response_headers(response: httpx.Response) -> None:
    raw_headers = response.headers.raw
    if len(raw_headers) > MAX_RESPONSE_HEADER_COUNT:
        raise EcosystemRegistryHttpLoaderError(
            "official registry response header count exceeds its approved bound"
        )
    total = 0
    token_bytes = frozenset(
        b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )
    for name, value in raw_headers:
        total += len(name) + len(value)
        if total > MAX_RESPONSE_HEADER_BYTES:
            raise EcosystemRegistryHttpLoaderError(
                "official registry response headers exceed their approved bound"
            )
        if not name or any(byte not in token_bytes for byte in name) or any(
            byte != 9 and not 32 <= byte <= 126 for byte in value
        ):
            raise EcosystemRegistryHttpLoaderError(
                "official registry response header is not canonical ASCII"
            )


def _read_response(
    client: httpx.Client,
    spec: _RequestSpec,
    *,
    deadline: float,
) -> BoundedOfficialHttpResponse:
    if time.monotonic() >= deadline:
        raise EcosystemRegistryHttpLoaderError(
            "official registry execution exceeded its approved deadline"
        )
    headers = {
        "Accept": ", ".join(spec.accepted_media_types),
        "Accept-Encoding": "identity",
        "User-Agent": USER_AGENT,
    }
    if spec.method == "POST":
        headers["Content-Type"] = "application/json"

    try:
        with client.stream(
            spec.method,
            spec.url,
            headers=headers,
            content=spec.request_body,
        ) as response:
            forbidden_request_headers = {
                "authorization",
                "cookie",
                "proxy-authorization",
            }
            if forbidden_request_headers.intersection(response.request.headers):
                raise EcosystemRegistryHttpLoaderError(
                    "official registry request credentials are forbidden"
                )
            if response.history:
                raise EcosystemRegistryHttpLoaderError(
                    "official registry redirect is forbidden"
                )
            if response.request.method != spec.method:
                raise EcosystemRegistryHttpLoaderError(
                    "official registry response method is not exact"
                )
            if response.request.url != httpx.URL(spec.url):
                raise EcosystemRegistryHttpLoaderError(
                    "official registry response URL is not exact"
                )
            if response.status_code != 200:
                raise EcosystemRegistryHttpLoaderError(
                    "official registry response status is not accepted"
                )
            _validate_response_headers(response)
            content_encoding = response.headers.get("content-encoding", "").strip()
            if content_encoding.lower() not in ("", "identity"):
                raise EcosystemRegistryHttpLoaderError(
                    "encoded official registry response is forbidden"
                )
            raw_content_type = response.headers.get("content-type")
            if raw_content_type is None:
                if not spec.allow_missing_content_type:
                    raise EcosystemRegistryHttpLoaderError(
                        "official registry response media type is missing"
                    )
                media_type = "absent"
            else:
                media_type = raw_content_type.split(";", 1)[0].strip().lower()
                if media_type not in spec.accepted_media_types:
                    raise EcosystemRegistryHttpLoaderError(
                        "official registry response media type is not accepted"
                    )
            _validated_content_length(response, spec.maximum_response_bytes)
            if response.is_stream_consumed or response.is_closed:
                raise EcosystemRegistryHttpLoaderError(
                    "official registry response stream is not unread"
                )
            buffer = bytearray()
            for chunk in response.iter_raw():
                if time.monotonic() >= deadline:
                    raise EcosystemRegistryHttpLoaderError(
                        "official registry execution exceeded its approved deadline"
                    )
                if len(buffer) + len(chunk) > spec.maximum_response_bytes:
                    raise EcosystemRegistryHttpLoaderError(
                        "official registry response exceeds its approved bound"
                    )
                buffer.extend(chunk)
    except EcosystemRegistryHttpLoaderError:
        raise
    except (httpx.HTTPError, httpx.StreamError, OSError, ValueError) as error:
        raise EcosystemRegistryHttpLoaderError(
            "official registry request failed"
        ) from error
    finally:
        try:
            client.cookies.clear()
        except Exception as error:
            raise EcosystemRegistryHttpLoaderError(
                "official registry response cookie state could not be cleared"
            ) from error

    body = bytes(buffer)
    if not body:
        raise EcosystemRegistryHttpLoaderError(
            "official registry response body is empty"
        )
    return BoundedOfficialHttpResponse(
        request_id=spec.request_id,
        method=spec.method,
        url=spec.url,
        status_code=200,
        media_type=media_type,
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
    )


def _load_ecosystem_registry_evidence(
    *,
    transport: httpx.BaseTransport | None,
    evidence_source: Literal[
        "live_bounded_official_https", "synthetic_mock_transport"
    ],
    attestation: object,
) -> LiveEcosystemRegistryEvidence:
    specs = _request_specs()
    if len(specs) != MAX_REQUEST_COUNT:
        raise EcosystemRegistryHttpLoaderError(
            "official registry request inventory is not exact"
        )
    timeout = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    deadline = time.monotonic() + EXECUTION_DEADLINE_SECONDS
    responses: list[BoundedOfficialHttpResponse] = []
    aggregate = 0
    try:
        with httpx.Client(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            limits=limits,
            transport=transport,
            http2=False,
        ) as client:
            for spec in specs:
                response = _read_response(client, spec, deadline=deadline)
                aggregate += len(response.body)
                if aggregate > MAX_AGGREGATE_RESPONSE_BYTES:
                    raise EcosystemRegistryHttpLoaderError(
                        "official registry aggregate response exceeds its approved bound"
                    )
                responses.append(response)
    except EcosystemRegistryHttpLoaderError:
        raise
    except (httpx.HTTPError, OSError, ValueError) as error:
        raise EcosystemRegistryHttpLoaderError(
            "official registry transport initialization failed"
        ) from error

    if len(responses) != MAX_REQUEST_COUNT:
        raise EcosystemRegistryHttpLoaderError(
            "official registry response inventory is not exact"
        )
    return LiveEcosystemRegistryEvidence(
        evidence_source=evidence_source,
        requests=tuple(responses),
        request_count=len(responses),
        aggregate_response_bytes=aggregate,
        redirects_followed=0,
        automatic_retries=0,
        environment_proxy_configuration_used=False,
        credentials_sent=False,
        package_tarball_downloaded=False,
        node_binary_downloaded=False,
        _loader_attestation=attestation,
    )


def _load_live_ecosystem_registry_evidence(
    validated_authorization: object,
) -> LiveEcosystemRegistryEvidence:
    """Private live path reachable by the CLI after pure authorization."""

    from app.security.authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe import (
        EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization,
    )

    if type(validated_authorization) is not EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization:
        raise EcosystemRegistryHttpLoaderError(
            "validated ecosystem network authorization is required"
        )
    return _load_ecosystem_registry_evidence(
        transport=None,
        evidence_source="live_bounded_official_https",
        attestation=_LIVE_EVIDENCE_ATTESTATION,
    )


def load_synthetic_ecosystem_registry_evidence(
    *, transport: httpx.BaseTransport
) -> LiveEcosystemRegistryEvidence:
    """Load mocked test evidence that cannot satisfy the live proof gate."""

    if transport is None:
        raise TypeError("an explicit synthetic transport is required")
    return _load_ecosystem_registry_evidence(
        transport=transport,
        evidence_source="synthetic_mock_transport",
        attestation=_SYNTHETIC_EVIDENCE_ATTESTATION,
    )


def is_attested_live_ecosystem_registry_evidence(evidence: object) -> bool:
    """Return true only for evidence made by the non-injectable live path."""

    return (
        type(evidence) is LiveEcosystemRegistryEvidence
        and evidence.evidence_source == "live_bounded_official_https"
        and evidence._loader_attestation is _LIVE_EVIDENCE_ATTESTATION
    )


def _read_authorization() -> bytes:
    authorization = sys.stdin.buffer.read(MAX_AUTHORIZATION_BYTES + 1)
    if not authorization or len(authorization) > MAX_AUTHORIZATION_BYTES:
        raise EcosystemRegistryHttpLoaderError(
            "official registry authorization size is invalid"
        )
    return authorization


def main() -> int:
    """Run the sole live Step 236 path and emit one sanitized receipt line."""

    try:
        authorization = _read_authorization()
        from app.security.authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe import (
            load_entra_calling_client_msal_frontend_host_ecosystem_compatibility,
            render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt,
            validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization,
        )

        validated_authorization = validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
            authorization
        )
        evidence = _load_live_ecosystem_registry_evidence(validated_authorization)
        receipt = load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, evidence
        )
        rendered = render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt(
            receipt
        )
        sys.stdout.buffer.write(rendered + b"\n")
        return 0
    except Exception:
        sys.stderr.write("Step 236 official registry compatibility proof failed.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BoundedOfficialHttpResponse",
    "DIRECT_PACKAGES",
    "EcosystemPackageSelection",
    "EcosystemRegistryHttpLoaderError",
    "LiveEcosystemRegistryEvidence",
    "MAX_AUTHORIZATION_BYTES",
    "MAX_REQUEST_COUNT",
    "NODE_DISTRIBUTION_ORIGIN",
    "NODE_VERSION",
    "NODE_VERSION_TAG",
    "NPM_REGISTRY_ORIGIN",
    "NPM_VERSION",
    "SELECTED_PACKAGES",
    "TRANSITIVE_ANCHOR_PACKAGES",
    "TOOLCHAIN_NPM_PACKAGE",
    "is_attested_live_ecosystem_registry_evidence",
    "load_synthetic_ecosystem_registry_evidence",
    "main",
    "official_request_contract_projection",
]
