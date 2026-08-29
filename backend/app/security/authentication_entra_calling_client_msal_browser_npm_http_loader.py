"""Bounded one-shot HTTPS transport for the Step 219 npm artifact proof.

The public loader accepts one immutable three-request plan. The module-owned
path performs three ordered GETs without credentials, request bodies, proxies,
redirects, retries, or compression. An injected executor is always synthetic
and cannot create live-source attestation.
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
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

MSAL_BROWSER_NPM_PACKAGE_NAME = "@azure/msal-browser"
MSAL_BROWSER_NPM_REVIEWED_VERSION = "5.17.3"
MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION = "5.18.0"
NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
NPM_DIST_TAGS_URL = (
    "https://registry.npmjs.org/-/package/%40azure%2Fmsal-browser/dist-tags"
)
NPM_VERSION_METADATA_URL = "https://registry.npmjs.org/%40azure%2Fmsal-browser/5.17.3"
NPM_TARBALL_URL = (
    "https://registry.npmjs.org/@azure/msal-browser/-/msal-browser-5.17.3.tgz"
)

NPM_HTTP_TIMEOUT_SECONDS = 10
NPM_MAX_RESPONSE_HEADER_BYTES = 16_384
NPM_MAX_RESPONSE_HEADER_COUNT = 128
NPM_MAX_DIST_TAGS_BYTES = 16_384
NPM_MAX_VERSION_METADATA_BYTES = 262_144
NPM_MAX_TARBALL_BYTES = 8_388_608

_JSON_MEDIA_TYPES = frozenset({"application/json"})
_TARBALL_MEDIA_TYPES = frozenset(
    {"application/octet-stream", "application/gzip", "application/x-gzip"}
)
_VISIBLE_ASCII = re.compile(r"[\x20-\x7e]+\Z")


class EntraCallingClientMSALBrowserNpmHTTPError(RuntimeError):
    """Sanitized failure at the npm transport boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class _RedirectRejected(RuntimeError):
    """Private redirect rejection marker."""


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALBrowserNpmHTTPRequest:
    sequence: int
    resource: Literal["dist_tags", "version_metadata", "tarball"]
    method: str
    url: str
    accept: str
    accept_encoding: str
    body: None

    def __post_init__(self) -> None:
        expected = {
            "dist_tags": (1, NPM_DIST_TAGS_URL, "application/json"),
            "version_metadata": (2, NPM_VERSION_METADATA_URL, "application/json"),
            "tarball": (3, NPM_TARBALL_URL, "application/octet-stream"),
        }
        if (
            type(self.sequence) is not int
            or type(self.resource) is not str
            or self.resource not in expected
            or type(self.method) is not str
            or type(self.url) is not str
            or type(self.accept) is not str
            or type(self.accept_encoding) is not str
            or self.body is not None
        ):
            raise ValueError("npm request contract is invalid")
        sequence, url, accept = expected[self.resource]
        if (
            self.sequence != sequence
            or self.method != "GET"
            or self.url != url
            or self.accept != accept
            or self.accept_encoding != "identity"
        ):
            raise ValueError("npm request contract is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALBrowserNpmHTTPResponse:
    request: EntraCallingClientMSALBrowserNpmHTTPRequest
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
        if type(self.request) is not EntraCallingClientMSALBrowserNpmHTTPRequest:
            raise ValueError("npm response request is invalid")
        self.request.__post_init__()
        limit = _body_limit(self.request.resource)
        media_types = (
            _JSON_MEDIA_TYPES
            if self.request.resource != "tarball"
            else _TARBALL_MEDIA_TYPES
        )
        booleans = (
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
            or not self.body
            or len(self.body) > limit
            or type(self.final_url) is not str
            or self.final_url != self.request.url
            or type(self.header_bytes) is not int
            or not 1 <= self.header_bytes <= NPM_MAX_RESPONSE_HEADER_BYTES
            or (
                self.content_length is not None
                and (
                    type(self.content_length) is not int
                    or self.content_length != len(self.body)
                )
            )
            or any(type(value) is not bool for value in booleans)
            or not (all(booleans) or not any(booleans))
        ):
            raise ValueError("npm response contract is invalid")


class EntraCallingClientMSALBrowserNpmHTTPTransport(Protocol):
    def __call__(
        self,
        requests: tuple[
            EntraCallingClientMSALBrowserNpmHTTPRequest,
            EntraCallingClientMSALBrowserNpmHTTPRequest,
            EntraCallingClientMSALBrowserNpmHTTPRequest,
        ],
    ) -> tuple[
        EntraCallingClientMSALBrowserNpmHTTPResponse,
        EntraCallingClientMSALBrowserNpmHTTPResponse,
        EntraCallingClientMSALBrowserNpmHTTPResponse,
    ]: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        raise _RedirectRejected("redirect rejected")


def _body_limit(resource: str) -> int:
    return {
        "dist_tags": NPM_MAX_DIST_TAGS_BYTES,
        "version_metadata": NPM_MAX_VERSION_METADATA_BYTES,
        "tarball": NPM_MAX_TARBALL_BYTES,
    }[resource]


def _normalized_media_type(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 256
        or _VISIBLE_ASCII.fullmatch(value) is None
        or value != value.strip(" \t")
    ):
        raise ValueError("content type is invalid")
    parts = [part.strip() for part in value.split(";")]
    media_type = parts[0].lower()
    if len(parts) == 1:
        return media_type
    if len(parts) != 2 or parts[1].lower() != "charset=utf-8":
        raise ValueError("content type parameter is invalid")
    return media_type


def build_entra_calling_client_msal_browser_npm_request_plan() -> tuple[
    EntraCallingClientMSALBrowserNpmHTTPRequest,
    EntraCallingClientMSALBrowserNpmHTTPRequest,
    EntraCallingClientMSALBrowserNpmHTTPRequest,
]:
    """Return the immutable three-request global-registry plan."""

    return (
        EntraCallingClientMSALBrowserNpmHTTPRequest(
            sequence=1,
            resource="dist_tags",
            method="GET",
            url=NPM_DIST_TAGS_URL,
            accept="application/json",
            accept_encoding="identity",
            body=None,
        ),
        EntraCallingClientMSALBrowserNpmHTTPRequest(
            sequence=2,
            resource="version_metadata",
            method="GET",
            url=NPM_VERSION_METADATA_URL,
            accept="application/json",
            accept_encoding="identity",
            body=None,
        ),
        EntraCallingClientMSALBrowserNpmHTTPRequest(
            sequence=3,
            resource="tarball",
            method="GET",
            url=NPM_TARBALL_URL,
            accept="application/octet-stream",
            accept_encoding="identity",
            body=None,
        ),
    )


def _validate_request_plan(
    requests: object,
) -> tuple[
    EntraCallingClientMSALBrowserNpmHTTPRequest,
    EntraCallingClientMSALBrowserNpmHTTPRequest,
    EntraCallingClientMSALBrowserNpmHTTPRequest,
]:
    if type(requests) is not tuple or len(requests) != 3:
        raise _ArgumentTypeError("exact three-request tuple is required")
    if any(
        type(request) is not EntraCallingClientMSALBrowserNpmHTTPRequest
        for request in requests
    ):
        raise _ArgumentTypeError("exact npm request objects are required")
    for request in requests:
        request.__post_init__()
    expected = build_entra_calling_client_msal_browser_npm_request_plan()
    if requests != expected:
        raise ValueError("npm request plan mismatch")
    return requests


def _build_sealed_opener() -> OpenerDirector:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.keylog_filename = None
    opener = build_opener(
        ProxyHandler({}),
        _NoRedirectHandler(),
        HTTPSHandler(context=context),
    )
    opener.addheaders = []
    return opener


_SEALED_OPENER_FACTORY = _build_sealed_opener


def _header_values(headers: object, name: str) -> list[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name, [])
        if values is None:
            return []
        return [str(value) for value in values]
    value = getattr(headers, "get", lambda _name, _default=None: _default)(name)
    return [] if value is None else [str(value)]


def _validate_headers(headers: object) -> tuple[str, int | None, int]:
    raw_items = getattr(headers, "raw_items", None)
    items = list(raw_items()) if callable(raw_items) else list(headers.items())
    if not 1 <= len(items) <= NPM_MAX_RESPONSE_HEADER_COUNT:
        raise ValueError("response header count is invalid")
    header_bytes = 2
    for name, value in items:
        if (
            type(name) is not str
            or type(value) is not str
            or not name
            or len(name) > 128
            or len(value) > 4096
            or _VISIBLE_ASCII.fullmatch(name) is None
            or _VISIBLE_ASCII.fullmatch(value) is None
            or name != name.strip(" \t")
            or value != value.strip(" \t")
        ):
            raise ValueError("response header text is invalid")
        header_bytes += len(name.encode("ascii")) + len(value.encode("ascii")) + 4
    if header_bytes > NPM_MAX_RESPONSE_HEADER_BYTES:
        raise ValueError("response headers are too large")

    content_types = _header_values(headers, "Content-Type")
    if len(content_types) != 1:
        raise ValueError("exactly one content type is required")
    content_lengths = _header_values(headers, "Content-Length")
    if len(content_lengths) > 1:
        raise ValueError("duplicate content length")
    for forbidden in ("Content-Encoding", "Location", "Set-Cookie"):
        if _header_values(headers, forbidden):
            raise ValueError("forbidden response header")
    content_length = None
    if content_lengths:
        raw_length = content_lengths[0]
        if (
            not raw_length
            or len(raw_length) > 20
            or not raw_length.isascii()
            or not raw_length.isdecimal()
        ):
            raise ValueError("content length is invalid")
        content_length = int(raw_length)
    return content_types[0], content_length, header_bytes


def _make_response(
    *,
    request: EntraCallingClientMSALBrowserNpmHTTPRequest,
    status_code: int,
    content_type: str,
    body: bytes,
    final_url: str,
    header_bytes: int,
    content_length: int | None,
    attested: bool,
) -> EntraCallingClientMSALBrowserNpmHTTPResponse:
    return EntraCallingClientMSALBrowserNpmHTTPResponse(
        request=request,
        status_code=status_code,
        content_type=content_type,
        body=body,
        final_url=final_url,
        header_bytes=header_bytes,
        content_length=content_length,
        live_https_attested=attested,
        tls_certificate_chain_checked=attested,
        tls_hostname_checked=attested,
        proxy_bypassed=attested,
        redirects_rejected=attested,
        retries_disabled=attested,
        response_source_authenticity_checked=attested,
    )


def _execute_with_opener_factory(
    requests: tuple[
        EntraCallingClientMSALBrowserNpmHTTPRequest,
        EntraCallingClientMSALBrowserNpmHTTPRequest,
        EntraCallingClientMSALBrowserNpmHTTPRequest,
    ],
    *,
    opener_factory: Callable[[], OpenerDirector],
) -> tuple[
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
]:
    attested = opener_factory is _SEALED_OPENER_FACTORY
    responses: list[EntraCallingClientMSALBrowserNpmHTTPResponse] = []
    raw_response = None
    raw_request = None
    body = None
    headers = None
    error = None
    try:
        for request in requests:
            opener = opener_factory()
            raw_request = Request(
                request.url,
                data=None,
                headers={
                    "Accept": request.accept,
                    "Accept-Encoding": request.accept_encoding,
                    "Connection": "close",
                },
                method="GET",
            )
            raw_response = opener.open(
                raw_request,
                timeout=NPM_HTTP_TIMEOUT_SECONDS,
            )
            status_code = raw_response.getcode()
            final_url = raw_response.geturl()
            headers = raw_response.headers
            content_type, content_length, header_bytes = _validate_headers(headers)
            limit = _body_limit(request.resource)
            if content_length is not None and content_length > limit:
                raise ValueError("response body is too large")
            body = raw_response.read(limit + 1)
            if type(body) is not bytes or not body or len(body) > limit:
                raise ValueError("response body boundary is invalid")
            if content_length is not None and content_length != len(body):
                raise ValueError("content length mismatch")
            responses.append(
                _make_response(
                    request=request,
                    status_code=status_code,
                    content_type=content_type,
                    body=body,
                    final_url=final_url,
                    header_bytes=header_bytes,
                    content_length=content_length,
                    attested=attested,
                )
            )
            raw_response.close()
            raw_response = None
            raw_request = None
            body = None
            headers = None
    except BaseException as caught:  # noqa: BLE001 - detached below
        error = caught
    finally:
        if raw_response is not None:
            try:
                raw_response.close()
            except BaseException as close_error:  # noqa: BLE001
                if error is None:
                    error = close_error
        raw_response = None
        raw_request = None
        body = None
        headers = None
        opener_factory = None
    if error is not None:
        interrupted, terminated = _scrub_exception_graph(error)
        error = None
        responses.clear()
        if interrupted:
            raise KeyboardInterrupt("npm artifact transport interrupted")
        if terminated:
            raise SystemExit("npm artifact transport terminated")
        raise EntraCallingClientMSALBrowserNpmHTTPError("npm artifact transport failed")
    if len(responses) != 3:
        responses.clear()
        raise EntraCallingClientMSALBrowserNpmHTTPError("npm artifact transport failed")
    return responses[0], responses[1], responses[2]


def _default_execute(
    requests: tuple[
        EntraCallingClientMSALBrowserNpmHTTPRequest,
        EntraCallingClientMSALBrowserNpmHTTPRequest,
        EntraCallingClientMSALBrowserNpmHTTPRequest,
    ],
) -> tuple[
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
]:
    return _execute_with_opener_factory(
        requests,
        opener_factory=_SEALED_OPENER_FACTORY,
    )


def _scrub_exception_graph(error: BaseException) -> tuple[bool, bool]:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    interrupted = False
    terminated = False
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted = interrupted or isinstance(current, KeyboardInterrupt)
        terminated = terminated or isinstance(current, SystemExit)
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
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
        except BaseException:  # noqa: BLE001,S110  # pragma: no cover
            pass
    return interrupted, terminated


class BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader:
    """One-shot exact-plan transport with synthetic/live provenance split."""

    def __init__(
        self,
        *,
        executor: EntraCallingClientMSALBrowserNpmHTTPTransport | None = None,
    ) -> None:
        if executor is not None and not callable(executor):
            executor = None
            del self
            raise TypeError("npm executor must be callable")
        self._executor = executor
        self._sealed_live = executor is None
        self._consumed = False

    def __call__(
        self,
        requests: tuple[
            EntraCallingClientMSALBrowserNpmHTTPRequest,
            EntraCallingClientMSALBrowserNpmHTTPRequest,
            EntraCallingClientMSALBrowserNpmHTTPRequest,
        ],
    ) -> tuple[
        EntraCallingClientMSALBrowserNpmHTTPResponse,
        EntraCallingClientMSALBrowserNpmHTTPResponse,
        EntraCallingClientMSALBrowserNpmHTTPResponse,
    ]:
        if self._consumed:
            del self
            requests = None
            raise EntraCallingClientMSALBrowserNpmHTTPError(
                "npm artifact transport is already consumed"
            )
        self._consumed = True
        result = None
        error = None
        invalid_call = False
        interrupted = False
        terminated = False
        executor = self._executor
        sealed_live = self._sealed_live
        try:
            validated = _validate_request_plan(requests)
            result = _default_execute(validated) if sealed_live else executor(validated)
            if type(result) is not tuple or len(result) != 3:
                raise ValueError("exact response tuple is required")
            for expected_request, response in zip(validated, result, strict=True):
                if type(response) is not EntraCallingClientMSALBrowserNpmHTTPResponse:
                    raise ValueError("exact response objects are required")
                response.__post_init__()
                if response.request != expected_request:
                    raise ValueError("response order mismatch")
                if not sealed_live and response.live_https_attested:
                    raise ValueError("injected executor cannot attest live source")
                if sealed_live and not response.live_https_attested:
                    raise ValueError("sealed executor did not attest live source")
        except _ArgumentTypeError as caught:
            error = caught
            invalid_call = True
        except BaseException as caught:  # noqa: BLE001 - sanitize boundary
            error = caught
        finally:
            self._executor = None
            if error is not None:
                interrupted, terminated = _scrub_exception_graph(error)
                result = None
            error = None
            executor = None
            requests = None
        if interrupted:
            result = None
            raise KeyboardInterrupt("npm artifact transport interrupted")
        if terminated:
            result = None
            raise SystemExit("npm artifact transport terminated")
        if invalid_call:
            result = None
            raise TypeError("npm artifact transport inputs are invalid")
        if result is None:
            raise EntraCallingClientMSALBrowserNpmHTTPError(
                "npm artifact transport failed"
            )
        return result

    def close(self) -> None:
        self._executor = None
        self._consumed = True


__all__ = [
    "MSAL_BROWSER_NPM_PACKAGE_NAME",
    "MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION",
    "MSAL_BROWSER_NPM_REVIEWED_VERSION",
    "NPM_DIST_TAGS_URL",
    "NPM_HTTP_TIMEOUT_SECONDS",
    "NPM_MAX_DIST_TAGS_BYTES",
    "NPM_MAX_RESPONSE_HEADER_BYTES",
    "NPM_MAX_TARBALL_BYTES",
    "NPM_MAX_VERSION_METADATA_BYTES",
    "NPM_REGISTRY_ORIGIN",
    "NPM_TARBALL_URL",
    "NPM_VERSION_METADATA_URL",
    "BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader",
    "EntraCallingClientMSALBrowserNpmHTTPError",
    "EntraCallingClientMSALBrowserNpmHTTPRequest",
    "EntraCallingClientMSALBrowserNpmHTTPResponse",
    "EntraCallingClientMSALBrowserNpmHTTPTransport",
    "build_entra_calling_client_msal_browser_npm_request_plan",
]
