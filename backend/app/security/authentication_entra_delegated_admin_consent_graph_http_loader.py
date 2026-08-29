"""Bounded direct HTTPS transport for the Step 210 consent-grant proof.

The loader executes one prevalidated read-only Microsoft Graph v1.0 collection
query.  Proxies, redirects, retries, request bodies, and response compression
are disabled.  The caller supplies one ephemeral opaque token intended for a
delegated work/school operator flow; this module does not acquire, parse, hash,
log, render, return, or prove the token type.

An injected opener is a deterministic test seam and can never produce live
provider evidence.  Only the captured module-owned direct HTTPS path can seal a
response as live.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID


ENTRA_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS = 10.0
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES = 32_768
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_BEARER_TOKEN_BYTES = 16_384
ENTRA_DELEGATED_ADMIN_CONSENT_USER_AGENT = (
    "Engineer4Me-Entra-Delegated-Consent-Probe/1.0"
)


class EntraDelegatedAdminConsentGraphHTTPError(RuntimeError):
    """Sanitized failure at the controlled Graph consent HTTP boundary."""


def consent_grant_filter(
    *,
    client_service_principal_object_id: str,
    resource_service_principal_object_id: str,
) -> str:
    """Return the one canonical OData filter supported by this transport."""

    for value in (
        client_service_principal_object_id,
        resource_service_principal_object_id,
    ):
        try:
            parsed = UUID(value)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("canonical service-principal object IDs are required") from None
        if parsed.int == 0 or str(parsed) != value:
            raise ValueError("canonical service-principal object IDs are required")
    return (
        f"clientId eq '{client_service_principal_object_id}' and "
        f"resourceId eq '{resource_service_principal_object_id}' and "
        "consentType eq 'AllPrincipals' and principalId eq null"
    )


def consent_grant_query_url(
    *,
    client_service_principal_object_id: str,
    resource_service_principal_object_id: str,
) -> str:
    filter_value = consent_grant_filter(
        client_service_principal_object_id=client_service_principal_object_id,
        resource_service_principal_object_id=resource_service_principal_object_id,
    )
    return (
        f"{ENTRA_GRAPH_BASE_URL}/oauth2PermissionGrants?$filter="
        f"{quote(filter_value, safe='')}"
    )


@dataclass(frozen=True, slots=True)
class EntraDelegatedAdminConsentGraphRequest:
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
        try:
            split = urlsplit(self.url)
            prefix = f"{ENTRA_GRAPH_BASE_URL}/oauth2PermissionGrants?$filter="
            encoded_filter = self.url.removeprefix(prefix)
            from urllib.parse import unquote

            decoded_filter = unquote(encoded_filter)
            parts = decoded_filter.split(" and ")
            client = parts[0].removeprefix("clientId eq '").removesuffix("'")
            resource = parts[1].removeprefix("resourceId eq '").removesuffix("'")
            expected_url = consent_grant_query_url(
                client_service_principal_object_id=client,
                resource_service_principal_object_id=resource,
            )
        except (IndexError, TypeError, ValueError):
            split = None
            expected_url = ""
        if (
            self.method != "GET"
            or split is None
            or split.scheme != "https"
            or split.netloc != "graph.microsoft.com"
            or split.path != "/v1.0/oauth2PermissionGrants"
            or split.fragment
            or split.username is not None
            or split.password is not None
            or split.port is not None
            or self.url != expected_url
            or self.headers
            != (("Accept", "application/json"), ("Accept-Encoding", "identity"))
            or self.body is not None
            or type(self.timeout_seconds) is not float
            or self.timeout_seconds
            != ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS
            or type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes
            != MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES
            or self.follow_redirects is not False
            or type(self.maximum_retries) is not int
            or self.maximum_retries != 0
            or self.proxy_allowed is not False
        ):
            raise ValueError("Microsoft Graph consent-grant request is invalid")


_LIVE_HTTPS_ATTESTATION = object()


class EntraDelegatedAdminConsentGraphResponse:
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
            raise ValueError("Microsoft Graph consent-grant response is invalid")


def _attested_live_response(
    *,
    status_code: int,
    final_url: str,
    content_type: str,
    body: bytes,
) -> EntraDelegatedAdminConsentGraphResponse:
    response = object.__new__(EntraDelegatedAdminConsentGraphResponse)
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


class EntraDelegatedAdminConsentGraphTransport(Protocol):
    def __call__(
        self,
        request: EntraDelegatedAdminConsentGraphRequest,
    ) -> EntraDelegatedAdminConsentGraphResponse: ...


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
        raise EntraDelegatedAdminConsentGraphHTTPError(
            "Microsoft Graph consent-grant redirects are not permitted"
        )


def _default_open(request: Request, timeout: float) -> HTTPSResponse:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # ``create_default_context`` honors ambient SSLKEYLOGFILE.  Never permit
    # this bearer-carrying boundary to persist TLS session secrets.
    context.keylog_filename = None
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
        len(encoded) <= MAX_ENTRA_DELEGATED_ADMIN_CONSENT_BEARER_TOKEN_BYTES
        and not value.startswith("Bearer ")
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


class BoundedHTTPSEntraDelegatedAdminConsentGraphLoader:
    """Execute one exact read-only grant query with an ephemeral token."""

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
        self._consumed = False

    def __call__(
        self,
        request: EntraDelegatedAdminConsentGraphRequest,
    ) -> EntraDelegatedAdminConsentGraphResponse:
        if self._consumed:
            raise EntraDelegatedAdminConsentGraphHTTPError(
                "Microsoft Graph consent-grant loader is already consumed"
            )
        self._consumed = True
        try:
            return self._execute(request)
        finally:
            self._delegated_access_token = None

    def _execute(
        self,
        request: EntraDelegatedAdminConsentGraphRequest,
    ) -> EntraDelegatedAdminConsentGraphResponse:
        if type(request) is not EntraDelegatedAdminConsentGraphRequest:
            raise TypeError("Microsoft Graph consent-grant request is required")
        try:
            request.__post_init__()
        except ValueError:
            raise EntraDelegatedAdminConsentGraphHTTPError(
                "Microsoft Graph consent-grant request is invalid"
            ) from None
        if not _valid_bearer_token(self._delegated_access_token):
            raise EntraDelegatedAdminConsentGraphHTTPError(
                "delegated Microsoft Graph access token is no longer available"
            )
        raw_request = Request(
            request.url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {self._delegated_access_token}",
                "User-Agent": ENTRA_DELEGATED_ADMIN_CONSENT_USER_AGENT,
            },
        )
        try:
            with self._open_url(raw_request, request.timeout_seconds) as response:
                if type(response.status) is not int or response.status != 200:
                    raise EntraDelegatedAdminConsentGraphHTTPError(
                        "Microsoft Graph returned a non-success status"
                    )
                final_url = response.geturl()
                if final_url != request.url:
                    raise EntraDelegatedAdminConsentGraphHTTPError(
                        "Microsoft Graph consent-grant response source changed"
                    )
                content_type = str(
                    response.headers.get("Content-Type", "")
                ).strip()
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise EntraDelegatedAdminConsentGraphHTTPError(
                        "Microsoft Graph response content type is not accepted"
                    )
                content_encoding = str(
                    response.headers.get("Content-Encoding", "")
                ).strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise EntraDelegatedAdminConsentGraphHTTPError(
                        "Microsoft Graph response encoding is not accepted"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except (TypeError, ValueError):
                        raise EntraDelegatedAdminConsentGraphHTTPError(
                            "Microsoft Graph response content length is invalid"
                        ) from None
                    if (
                        declared_length < 0
                        or declared_length > request.maximum_response_bytes
                    ):
                        raise EntraDelegatedAdminConsentGraphHTTPError(
                            "Microsoft Graph response exceeds the size limit"
                        )
                body = response.read(request.maximum_response_bytes + 1)
                if (
                    not isinstance(body, bytes)
                    or len(body) > request.maximum_response_bytes
                ):
                    raise EntraDelegatedAdminConsentGraphHTTPError(
                        "Microsoft Graph response exceeds the size limit"
                    )
        except EntraDelegatedAdminConsentGraphHTTPError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
            raise EntraDelegatedAdminConsentGraphHTTPError(
                "Microsoft Graph HTTPS retrieval failed"
            ) from None

        if self._default_transport:
            return _attested_live_response(
                status_code=response.status,
                final_url=final_url,
                content_type=content_type,
                body=body,
            )
        return EntraDelegatedAdminConsentGraphResponse(
            status_code=response.status,
            final_url=final_url,
            content_type=content_type,
            body=body,
        )

    def close(self) -> None:
        """Release this loader's only retained reference to the opaque token."""

        self._delegated_access_token = None
        self._consumed = True


__all__ = [
    "ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS",
    "ENTRA_DELEGATED_ADMIN_CONSENT_USER_AGENT",
    "ENTRA_GRAPH_BASE_URL",
    "MAX_ENTRA_DELEGATED_ADMIN_CONSENT_BEARER_TOKEN_BYTES",
    "MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES",
    "BoundedHTTPSEntraDelegatedAdminConsentGraphLoader",
    "EntraDelegatedAdminConsentGraphHTTPError",
    "EntraDelegatedAdminConsentGraphRequest",
    "EntraDelegatedAdminConsentGraphResponse",
    "EntraDelegatedAdminConsentGraphTransport",
    "HTTPSResponse",
    "OpenURL",
    "consent_grant_filter",
    "consent_grant_query_url",
]
