"""Bounded direct HTTPS transport for the Step 208 Microsoft Graph proof.

The loader has one narrow purpose: execute a prevalidated GET request against
the global Microsoft Graph v1.0 endpoint.  It disables proxies and redirects,
performs no retries, and reads at most the request byte limit.  An operator must
supply one ephemeral delegated work/school bearer token directly; the loader
does not acquire it, persist it, parse it, hash it, log it, or return it.

Passing an ``open_url`` test seam deliberately disables live HTTPS attestation.
Only the module-owned default HTTPS path can produce an attested response.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID


ENTRA_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS = 10.0
MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES = 16_384
MAX_ENTRA_GRAPH_BEARER_TOKEN_BYTES = 16_384
ENTRA_GRAPH_INVENTORY_USER_AGENT = "Engineer4Me-Entra-Inventory-Probe/1.0"
_APPLICATION_SELECT = "id,appId,deletedDateTime"
_SERVICE_PRINCIPAL_SELECT = (
    "id,appId,appOwnerOrganizationId,servicePrincipalType,accountEnabled,"
    "disabledByMicrosoftStatus,deletedDateTime"
)


class EntraGraphHTTPError(RuntimeError):
    """Sanitized failure at the controlled Microsoft Graph HTTP boundary."""


@dataclass(frozen=True, slots=True)
class EntraGraphInventoryRequest:
    """One immutable request that a transport must execute exactly."""

    sequence: int
    role: Literal["api", "calling_client"]
    resource: Literal["application", "service_principal"]
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: None
    timeout_seconds: float
    maximum_response_bytes: int
    follow_redirects: bool
    maximum_retries: int
    proxy_allowed: bool

    def __post_init__(self) -> None:
        expected_collection = {
            "application": "applications",
            "service_principal": "servicePrincipals",
        }.get(self.resource)
        split = None
        object_id = ""
        try:
            split = urlsplit(self.url)
            object_id = split.path.rsplit("/", 1)[-1]
            parsed_object_id = UUID(object_id)
        except (AttributeError, TypeError, ValueError):
            parsed_object_id = None
        expected_select = {
            "application": _APPLICATION_SELECT,
            "service_principal": _SERVICE_PRINCIPAL_SELECT,
        }.get(self.resource)
        expected_path_prefix = f"/v1.0/{expected_collection}/"
        if (
            type(self.sequence) is not int
            or self.sequence not in range(1, 5)
            or self.role not in {"api", "calling_client"}
            or expected_collection is None
            or split is None
            or self.method != "GET"
            or split.scheme != "https"
            or split.netloc != "graph.microsoft.com"
            or not split.path.startswith(expected_path_prefix)
            or split.path.count("/") != 3
            or parsed_object_id is None
            or parsed_object_id.int == 0
            or str(parsed_object_id) != object_id
            or split.query != f"$select={expected_select}"
            or split.fragment
            or split.username is not None
            or split.password is not None
            or split.port is not None
            or self.url
            != (
                f"{ENTRA_GRAPH_BASE_URL}/{expected_collection}/{object_id}"
                f"?$select={expected_select}"
            )
            or self.headers
            != (("Accept", "application/json"), ("Accept-Encoding", "identity"))
            or self.body is not None
            or type(self.timeout_seconds) is not float
            or self.timeout_seconds
            != ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS
            or type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes
            != MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES
            or self.follow_redirects is not False
            or type(self.maximum_retries) is not int
            or self.maximum_retries != 0
            or self.proxy_allowed is not False
        ):
            raise ValueError("Microsoft Graph inventory request is invalid")


_LIVE_HTTPS_ATTESTATION = object()


class EntraGraphInventoryResponse:
    """A bounded response; public construction is always synthetic evidence."""

    __slots__ = (
        "status_code",
        "final_url",
        "content_type",
        "body",
        "tls_peer_verified",
        "redirect_count",
        "attempt_count",
        "_attestation",
    )

    def __init__(
        self,
        *,
        status_code: int,
        final_url: str,
        content_type: str,
        body: bytes,
        tls_peer_verified: bool = False,
        redirect_count: int = 0,
        attempt_count: int = 1,
    ) -> None:
        self.status_code = status_code
        self.final_url = final_url
        self.content_type = content_type
        self.body = body
        self.tls_peer_verified = tls_peer_verified
        self.redirect_count = redirect_count
        self.attempt_count = attempt_count
        self._attestation = None
        self.validate()

    @property
    def live_https_attested(self) -> bool:
        return self._attestation is _LIVE_HTTPS_ATTESTATION

    def validate(self) -> None:
        if (
            type(self.status_code) is not int
            or type(self.final_url) is not str
            or type(self.content_type) is not str
            or not isinstance(self.body, bytes)
            or type(self.tls_peer_verified) is not bool
            or type(self.redirect_count) is not int
            or type(self.attempt_count) is not int
            or self.redirect_count != 0
            or self.attempt_count != 1
            or (self.live_https_attested and self.tls_peer_verified is not True)
            or (not self.live_https_attested and self.tls_peer_verified is not False)
        ):
            raise ValueError("Microsoft Graph inventory response is invalid")


def _attested_live_response(
    *,
    status_code: int,
    final_url: str,
    content_type: str,
    body: bytes,
) -> EntraGraphInventoryResponse:
    response = object.__new__(EntraGraphInventoryResponse)
    response.status_code = status_code
    response.final_url = final_url
    response.content_type = content_type
    response.body = body
    response.tls_peer_verified = True
    response.redirect_count = 0
    response.attempt_count = 1
    response._attestation = _LIVE_HTTPS_ATTESTATION
    response.validate()
    return response


class EntraGraphInventoryTransport(Protocol):
    def __call__(
        self, request: EntraGraphInventoryRequest
    ) -> EntraGraphInventoryResponse: ...


class HTTPSResponse(Protocol):
    status: int
    headers: object

    def geturl(self) -> str: ...
    def read(self, amount: int = -1) -> bytes: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...


OpenURL = Callable[[Request, float], HTTPSResponse]


class _DenyRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        raise EntraGraphHTTPError("Microsoft Graph redirects are not permitted")


def _default_open(request: Request, timeout: float) -> HTTPSResponse:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    opener = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=context),
        _DenyRedirects(),
    )
    return opener.open(request, timeout=timeout)


_MODULE_OWNED_DEFAULT_OPEN = _default_open


def _valid_bearer_token(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= MAX_ENTRA_GRAPH_BEARER_TOKEN_BYTES
        and not value.startswith("Bearer ")
        and all(character not in value for character in "\x00\r\n\t ")
    )


class BoundedHTTPSEntraGraphInventoryLoader:
    """Execute approved Graph requests with one ephemeral delegated token."""

    _CONTENT_TYPES = frozenset({"application/json"})

    def __init__(
        self,
        *,
        delegated_access_token: str,
        open_url: OpenURL | None = None,
    ) -> None:
        if not _valid_bearer_token(delegated_access_token):
            raise ValueError("delegated Microsoft Graph access token is invalid")
        self._delegated_access_token = delegated_access_token
        selected_open = _default_open if open_url is None else open_url
        self._open_url = selected_open
        self._default_transport = (
            open_url is None and selected_open is _MODULE_OWNED_DEFAULT_OPEN
        )

    def __call__(
        self, request: EntraGraphInventoryRequest
    ) -> EntraGraphInventoryResponse:
        if type(request) is not EntraGraphInventoryRequest:
            raise TypeError("Microsoft Graph inventory request is required")
        try:
            request.__post_init__()
        except ValueError:
            raise EntraGraphHTTPError(
                "Microsoft Graph inventory request is invalid"
            ) from None
        if not _valid_bearer_token(self._delegated_access_token):
            raise EntraGraphHTTPError(
                "delegated Microsoft Graph access token is no longer available"
            )
        raw_request = Request(
            request.url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {self._delegated_access_token}",
                "User-Agent": ENTRA_GRAPH_INVENTORY_USER_AGENT,
            },
        )
        try:
            with self._open_url(raw_request, request.timeout_seconds) as response:
                if type(response.status) is not int or response.status != 200:
                    raise EntraGraphHTTPError(
                        "Microsoft Graph returned a non-success status"
                    )
                final_url = response.geturl()
                if final_url != request.url:
                    raise EntraGraphHTTPError(
                        "Microsoft Graph response source changed"
                    )
                content_type_header = response.headers.get("Content-Type", "")
                content_type = str(content_type_header).strip()
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type not in self._CONTENT_TYPES:
                    raise EntraGraphHTTPError(
                        "Microsoft Graph response content type is not accepted"
                    )
                content_encoding = str(
                    response.headers.get("Content-Encoding", "")
                ).strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise EntraGraphHTTPError(
                        "Microsoft Graph response encoding is not accepted"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except (TypeError, ValueError):
                        raise EntraGraphHTTPError(
                            "Microsoft Graph response content length is invalid"
                        ) from None
                    if (
                        declared_length < 0
                        or declared_length > request.maximum_response_bytes
                    ):
                        raise EntraGraphHTTPError(
                            "Microsoft Graph response exceeds the size limit"
                        )
                body = response.read(request.maximum_response_bytes + 1)
                if not isinstance(body, bytes) or len(body) > request.maximum_response_bytes:
                    raise EntraGraphHTTPError(
                        "Microsoft Graph response exceeds the size limit"
                    )
        except EntraGraphHTTPError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
            raise EntraGraphHTTPError(
                "Microsoft Graph HTTPS retrieval failed"
            ) from None

        if self._default_transport:
            return _attested_live_response(
                status_code=response.status,
                final_url=final_url,
                content_type=content_type,
                body=body,
            )
        return EntraGraphInventoryResponse(
            status_code=response.status,
            final_url=final_url,
            content_type=content_type,
            body=body,
        )

    def close(self) -> None:
        """Release this loader's only retained reference to the opaque token."""

        self._delegated_access_token = None


__all__ = [
    "ENTRA_GRAPH_BASE_URL",
    "ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS",
    "ENTRA_GRAPH_INVENTORY_USER_AGENT",
    "MAX_ENTRA_GRAPH_BEARER_TOKEN_BYTES",
    "MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES",
    "BoundedHTTPSEntraGraphInventoryLoader",
    "EntraGraphHTTPError",
    "EntraGraphInventoryRequest",
    "EntraGraphInventoryResponse",
    "EntraGraphInventoryTransport",
    "HTTPSResponse",
    "OpenURL",
]
