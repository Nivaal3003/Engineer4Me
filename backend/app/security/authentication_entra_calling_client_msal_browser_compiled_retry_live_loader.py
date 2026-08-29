"""Bounded one-shot npm transport for the Step 223 dual-artifact proof.

The sealed path performs four exact Azure MSAL npm registry GETs without
credentials, request bodies, proxies, redirects, retries, or compression. An
injected transport is always synthetic and cannot create live attestation.
"""

from __future__ import annotations

import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

BROWSER_PACKAGE_NAME = "@azure/msal-browser"
BROWSER_VERSION = "5.18.0"
COMMON_PACKAGE_NAME = "@azure/msal-common"
COMMON_VERSION = "16.12.0"
NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
BROWSER_METADATA_URL = "https://registry.npmjs.org/%40azure%2Fmsal-browser/5.18.0"
BROWSER_TARBALL_URL = (
    "https://registry.npmjs.org/@azure/msal-browser/-/msal-browser-5.18.0.tgz"
)
COMMON_METADATA_URL = "https://registry.npmjs.org/%40azure%2Fmsal-common/16.12.0"
COMMON_TARBALL_URL = (
    "https://registry.npmjs.org/@azure/msal-common/-/msal-common-16.12.0.tgz"
)

HTTP_TIMEOUT_SECONDS = 15
MAX_HEADER_BYTES = 16_384
MAX_HEADER_COUNT = 128
MAX_METADATA_BYTES = 524_288
MAX_TARBALL_BYTES = 8_388_608

_JSON_MEDIA_TYPES = frozenset({"application/json"})
_TARBALL_MEDIA_TYPES = frozenset(
    {"application/octet-stream", "application/gzip", "application/x-gzip"}
)
_VISIBLE_ASCII = re.compile(r"[\x20-\x7e]+\Z")


class EntraCallingClientMSALCompiledRetryLiveHTTPError(RuntimeError):
    """Sanitized failure at the Step 223 transport boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class _RedirectRejected(RuntimeError):
    """Private redirect rejection marker."""


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryLiveHTTPRequest:
    sequence: int
    resource: Literal[
        "browser_metadata",
        "browser_tarball",
        "common_metadata",
        "common_tarball",
    ]
    method: str
    url: str
    accept: str
    accept_encoding: str
    connection: str
    user_agent: str
    authorization: None
    body: None

    def __post_init__(self) -> None:
        expected = {
            "browser_metadata": (1, BROWSER_METADATA_URL, "application/json"),
            "browser_tarball": (
                2,
                BROWSER_TARBALL_URL,
                "application/octet-stream",
            ),
            "common_metadata": (3, COMMON_METADATA_URL, "application/json"),
            "common_tarball": (
                4,
                COMMON_TARBALL_URL,
                "application/octet-stream",
            ),
        }
        scalar_values = (
            self.resource,
            self.method,
            self.url,
            self.accept,
            self.accept_encoding,
            self.connection,
            self.user_agent,
        )
        if (
            type(self.sequence) is not int
            or any(type(value) is not str for value in scalar_values)
            or self.resource not in expected
            or self.authorization is not None
            or self.body is not None
        ):
            raise ValueError("compiled retry live request contract is invalid")
        sequence, url, accept = expected[self.resource]
        if (
            self.sequence != sequence
            or self.method != "GET"
            or self.url != url
            or self.accept != accept
            or self.accept_encoding != "identity"
            or self.connection != "close"
            or self.user_agent != "Engineer4Me-Step223/1"
        ):
            raise ValueError("compiled retry live request contract is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryLiveHTTPResponse:
    request: EntraCallingClientMSALCompiledRetryLiveHTTPRequest
    status_code: int
    content_type: str
    body: bytes
    final_url: str
    header_bytes: int
    content_length: int | None
    live_https_attested: bool
    tls_certificate_chain_checked: bool
    tls_hostname_checked: bool
    proxy_bypassed: bool
    redirects_rejected: bool
    retries_disabled: bool
    response_source_authenticity_checked: bool

    def __post_init__(self) -> None:
        if type(self.request) is not EntraCallingClientMSALCompiledRetryLiveHTTPRequest:
            raise ValueError("compiled retry live response request is invalid")
        self.request.__post_init__()
        metadata = self.request.resource.endswith("metadata")
        media_types = _JSON_MEDIA_TYPES if metadata else _TARBALL_MEDIA_TYPES
        body_limit = MAX_METADATA_BYTES if metadata else MAX_TARBALL_BYTES
        attestations = (
            self.live_https_attested,
            self.tls_certificate_chain_checked,
            self.tls_hostname_checked,
            self.proxy_bypassed,
            self.redirects_rejected,
            self.retries_disabled,
            self.response_source_authenticity_checked,
        )
        if (
            type(self.status_code) is not int
            or self.status_code != 200
            or type(self.content_type) is not str
            or _normalized_media_type(self.content_type) not in media_types
            or type(self.body) is not bytes
            or not 1 <= len(self.body) <= body_limit
            or type(self.final_url) is not str
            or self.final_url != self.request.url
            or type(self.header_bytes) is not int
            or not 1 <= self.header_bytes <= MAX_HEADER_BYTES
            or (
                self.content_length is not None
                and (
                    type(self.content_length) is not int
                    or self.content_length != len(self.body)
                )
            )
            or any(type(value) is not bool for value in attestations)
            or not (all(attestations) or not any(attestations))
        ):
            raise ValueError("compiled retry live response contract is invalid")


RequestTuple = tuple[
    EntraCallingClientMSALCompiledRetryLiveHTTPRequest,
    EntraCallingClientMSALCompiledRetryLiveHTTPRequest,
    EntraCallingClientMSALCompiledRetryLiveHTTPRequest,
    EntraCallingClientMSALCompiledRetryLiveHTTPRequest,
]
ResponseTuple = tuple[
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
]


class EntraCallingClientMSALCompiledRetryLiveHTTPTransport(Protocol):
    def __call__(self, requests: RequestTuple) -> ResponseTuple: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        raise _RedirectRejected("redirect rejected")


def _normalized_media_type(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 256
        or value != value.strip(" \t")
        or _VISIBLE_ASCII.fullmatch(value) is None
    ):
        raise ValueError("content type is invalid")
    parts = [part.strip() for part in value.split(";")]
    media_type = parts[0].lower()
    if len(parts) == 1:
        return media_type
    if len(parts) != 2 or parts[1].lower() != "charset=utf-8":
        raise ValueError("content type parameter is invalid")
    return media_type


def build_entra_calling_client_msal_compiled_retry_live_request_plan() -> RequestTuple:
    """Return the immutable four-request global npm plan."""

    values = (
        (1, "browser_metadata", BROWSER_METADATA_URL, "application/json"),
        (2, "browser_tarball", BROWSER_TARBALL_URL, "application/octet-stream"),
        (3, "common_metadata", COMMON_METADATA_URL, "application/json"),
        (4, "common_tarball", COMMON_TARBALL_URL, "application/octet-stream"),
    )
    return tuple(
        EntraCallingClientMSALCompiledRetryLiveHTTPRequest(
            sequence=sequence,
            resource=resource,
            method="GET",
            url=url,
            accept=accept,
            accept_encoding="identity",
            connection="close",
            user_agent="Engineer4Me-Step223/1",
            authorization=None,
            body=None,
        )
        for sequence, resource, url, accept in values
    )  # type: ignore[return-value]


def _validate_request_plan(requests: object) -> RequestTuple:
    if type(requests) is not tuple or len(requests) != 4:
        raise _ArgumentTypeError("exact four-request tuple is required")
    if any(
        type(request) is not EntraCallingClientMSALCompiledRetryLiveHTTPRequest
        for request in requests
    ):
        raise _ArgumentTypeError("exact compiled retry request objects are required")
    for request in requests:
        request.__post_init__()
    expected = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    if requests != expected:
        raise ValueError("compiled retry request plan changed")
    return requests


def _header_bytes(headers: object) -> int:
    items = list(headers.items())
    if len(items) > MAX_HEADER_COUNT:
        raise ValueError("response header count exceeded")
    total = 2
    for name, value in items:
        if type(name) is not str or type(value) is not str:
            raise ValueError("response header type is invalid")
        try:
            total += len(name.encode("ascii")) + len(value.encode("ascii")) + 4
        except UnicodeEncodeError as error:
            raise ValueError("response header is not ASCII") from error
    if not 1 <= total <= MAX_HEADER_BYTES:
        raise ValueError("response header bytes exceeded")
    return total


def _content_length(headers: object) -> int | None:
    values = headers.get_all("Content-Length", [])
    if not values:
        return None
    if len(values) != 1 or re.fullmatch(r"0|[1-9][0-9]*", values[0]) is None:
        raise ValueError("content length is invalid")
    return int(values[0])


def _response_limit(request: EntraCallingClientMSALCompiledRetryLiveHTTPRequest) -> int:
    return (
        MAX_METADATA_BYTES
        if request.resource.endswith("metadata")
        else MAX_TARBALL_BYTES
    )


def _sealed_transport(requests: RequestTuple) -> ResponseTuple:
    validated = _validate_request_plan(requests)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs()
    opener = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )
    responses: list[EntraCallingClientMSALCompiledRetryLiveHTTPResponse] = []
    for request_plan in validated:
        headers = None
        body = None
        request = Request(
            request_plan.url,
            method="GET",
            headers={
                "Accept": request_plan.accept,
                "Accept-Encoding": request_plan.accept_encoding,
                "Connection": request_plan.connection,
                "User-Agent": request_plan.user_agent,
            },
        )
        response = None
        try:
            response = opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)
            headers = response.headers
            if headers.get_all("Content-Encoding", []):
                raise ValueError("response content encoding is forbidden")
            content_length = _content_length(headers)
            limit = _response_limit(request_plan)
            if content_length is not None and not 1 <= content_length <= limit:
                raise ValueError("response content length exceeded")
            body = response.read(limit + 1)
            if not 1 <= len(body) <= limit:
                raise ValueError("response body bound exceeded")
            if content_length is not None and content_length != len(body):
                raise ValueError("response content length mismatch")
            responses.append(
                EntraCallingClientMSALCompiledRetryLiveHTTPResponse(
                    request=request_plan,
                    status_code=response.getcode(),
                    content_type=headers.get("Content-Type", ""),
                    body=body,
                    final_url=response.geturl(),
                    header_bytes=_header_bytes(headers),
                    content_length=content_length,
                    live_https_attested=True,
                    tls_certificate_chain_checked=True,
                    tls_hostname_checked=True,
                    proxy_bypassed=True,
                    redirects_rejected=True,
                    retries_disabled=True,
                    response_source_authenticity_checked=True,
                )
            )
        finally:
            if response is not None:
                response.close()
            response = None
            request = None
            headers = None
            body = None
    if len(responses) != 4:
        raise ValueError("compiled retry response plan incomplete")
    return tuple(responses)  # type: ignore[return-value]


_CAPTURED_SEALED_TRANSPORT = _sealed_transport


def _scrub(error: BaseException) -> tuple[bool, bool]:
    pending = [error]
    seen: set[int] = set()
    interrupted = False
    terminated = False
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted |= isinstance(current, KeyboardInterrupt)
        terminated |= isinstance(current, SystemExit)
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        children = getattr(current, "exceptions", ())
        if type(children) is tuple:
            pending.extend(
                child for child in children if isinstance(child, BaseException)
            )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001,S110
            pass
    return interrupted, terminated


class BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader:
    """Consume one exact dual-artifact request tuple."""

    __slots__ = ("_consumed", "_sealed", "_transport")

    def __init__(
        self,
        transport: EntraCallingClientMSALCompiledRetryLiveHTTPTransport | None = None,
    ) -> None:
        if transport is not None and not isinstance(transport, Callable):
            self = None  # noqa: PLW0642
            transport = None
            raise TypeError("compiled retry transport must be callable")
        self._transport = _CAPTURED_SEALED_TRANSPORT if transport is None else transport
        self._sealed = transport is None
        self._consumed = False

    def load(self, requests: object) -> ResponseTuple:
        if self._consumed:
            self = None  # noqa: PLW0642
            requests = None
            raise EntraCallingClientMSALCompiledRetryLiveHTTPError(
                "compiled retry transport already consumed"
            )
        self._consumed = True
        transport = self._transport
        self._transport = None
        sealed = self._sealed
        validated = None
        responses = None
        error = None
        invalid = False
        interrupted = False
        terminated = False
        try:
            validated = _validate_request_plan(requests)
            responses = transport(validated)
            if type(responses) is not tuple or len(responses) != 4:
                raise ValueError("exact four-response tuple is required")
            for expected, response in zip(validated, responses, strict=True):
                if (
                    type(response)
                    is not EntraCallingClientMSALCompiledRetryLiveHTTPResponse
                ):
                    raise ValueError("exact compiled retry responses are required")
                response.__post_init__()
                if response.request != expected:
                    raise ValueError("compiled retry response order changed")
                if sealed != response.live_https_attested:
                    raise ValueError("compiled retry response provenance mismatch")
                if not sealed and any(
                    (
                        response.live_https_attested,
                        response.tls_certificate_chain_checked,
                        response.tls_hostname_checked,
                        response.proxy_bypassed,
                        response.redirects_rejected,
                        response.retries_disabled,
                        response.response_source_authenticity_checked,
                    )
                ):
                    raise ValueError("injected transport cannot attest live evidence")
        except _ArgumentTypeError as caught:
            error = caught
            invalid = True
        except BaseException as caught:  # noqa: BLE001
            error = caught
        finally:
            if error is not None:
                interrupted, terminated = _scrub(error)
                responses = None
            error = None
            transport = None
            validated = None
            requests = None
            self = None  # noqa: PLW0642
        if interrupted:
            raise KeyboardInterrupt("compiled retry live transport interrupted")
        if terminated:
            raise SystemExit("compiled retry live transport terminated")
        if invalid:
            raise TypeError("compiled retry live transport inputs are invalid")
        if responses is None:
            raise EntraCallingClientMSALCompiledRetryLiveHTTPError(
                "compiled retry live transport failed"
            )
        return responses


__all__ = [
    "BROWSER_METADATA_URL",
    "BROWSER_PACKAGE_NAME",
    "BROWSER_TARBALL_URL",
    "BROWSER_VERSION",
    "COMMON_METADATA_URL",
    "COMMON_PACKAGE_NAME",
    "COMMON_TARBALL_URL",
    "COMMON_VERSION",
    "HTTP_TIMEOUT_SECONDS",
    "MAX_HEADER_BYTES",
    "MAX_METADATA_BYTES",
    "MAX_TARBALL_BYTES",
    "NPM_REGISTRY_ORIGIN",
    "BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader",
    "EntraCallingClientMSALCompiledRetryLiveHTTPError",
    "EntraCallingClientMSALCompiledRetryLiveHTTPRequest",
    "EntraCallingClientMSALCompiledRetryLiveHTTPResponse",
    "EntraCallingClientMSALCompiledRetryLiveHTTPTransport",
    "build_entra_calling_client_msal_compiled_retry_live_request_plan",
]
