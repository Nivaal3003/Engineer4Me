"""Bounded HTTPS transport for the Step 213 calling-client proof.

The loader executes exactly three ordered Microsoft Graph v1.0 GETs bound to
one immutable application object ID: the application, its owners, and its
federated identity credentials.  Proxies, redirects, retries, request bodies,
response compression, batching, unrelated collection discovery, and paging are disabled.  One
ephemeral opaque token intended for a delegated work/school operator is
supplied by the caller.  This module does not acquire, parse, hash, log,
render, return, or prove that token.

An injected or rebound opener is a deterministic test seam and can never
produce live provider evidence.  Only the captured module-owned direct HTTPS
path can seal the response as live.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol, Self
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
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS = 10.0
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES = 65_536
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES = 16_384
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES = 8_192
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_BEARER_TOKEN_BYTES = 16_384
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_USER_AGENT = (
    "Engineer4Me-Entra-Calling-Client-Registration-Probe/1.0"
)
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT = 3
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT = (
    "id,appId,deletedDateTime,disabledByMicrosoftStatus,displayName,description,"
    "notes,signInAudience,spa,web,publicClient,isFallbackPublicClient,"
    "isDeviceOnlyAuthSupported,nativeAuthenticationApisEnabled,"
    "oauth2RequiredPostResponse,passwordCredentials,keyCredentials,"
    "requiredResourceAccess,identifierUris,appRoles,api,optionalClaims,"
    "groupMembershipClaims,tokenEncryptionKeyId,addIns,info"
)


class EntraCallingClientRegistrationGraphHTTPError(RuntimeError):
    """Sanitized failure at the controlled Graph application boundary."""


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def entra_calling_client_registration_graph_url(
    *,
    application_object_id: str,
    resource: Literal[
        "calling_client_application",
        "owners",
        "federated_identity_credentials",
    ],
) -> str:
    """Return one of the three exact object-bound Graph URLs."""

    if not _canonical_uuid(application_object_id):
        raise ValueError("a canonical nonzero application object ID is required")
    base = f"{ENTRA_GRAPH_BASE_URL}/applications/{application_object_id}"
    if resource == "calling_client_application":
        return (
            f"{base}"
            f"?$select={ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT}"
        )
    if resource == "owners":
        return f"{base}/owners?$select=id"
    if resource == "federated_identity_credentials":
        return f"{base}/federatedIdentityCredentials?$select=id"
    raise ValueError("a supported calling-client Graph resource is required")


@dataclass(frozen=True, slots=True)
class EntraCallingClientRegistrationGraphRequest:
    """One immutable request in the exact ordered three-read Graph plan."""

    sequence: int
    resource: Literal[
        "calling_client_application",
        "owners",
        "federated_identity_credentials",
    ]
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
        split = None
        application_object_id = ""
        try:
            split = urlsplit(self.url)
            segments = split.path.split("/")
            application_object_id = segments[3]
            expected_url = entra_calling_client_registration_graph_url(
                application_object_id=application_object_id,
                resource=self.resource,
            )
        except (IndexError, TypeError, ValueError):
            expected_url = ""
        expected_sequence = {
            "calling_client_application": 1,
            "owners": 2,
            "federated_identity_credentials": 3,
        }.get(self.resource)
        expected_maximum_response_bytes = {
            "calling_client_application": (
                MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES
            ),
            "owners": MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES,
            "federated_identity_credentials": (
                MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES
            ),
        }.get(self.resource)
        expected_path = {
            "calling_client_application": (
                f"/v1.0/applications/{application_object_id}"
            ),
            "owners": f"/v1.0/applications/{application_object_id}/owners",
            "federated_identity_credentials": (
                f"/v1.0/applications/{application_object_id}"
                "/federatedIdentityCredentials"
            ),
        }.get(self.resource)
        if (
            type(self.sequence) is not int
            or self.sequence != expected_sequence
            or split is None
            or self.method != "GET"
            or split.scheme != "https"
            or split.netloc != "graph.microsoft.com"
            or split.path != expected_path
            or split.fragment
            or split.username is not None
            or split.password is not None
            or split.port is not None
            or not _canonical_uuid(application_object_id)
            or self.url != expected_url
            or self.headers
            != (("Accept", "application/json"), ("Accept-Encoding", "identity"))
            or self.body is not None
            or type(self.timeout_seconds) is not float
            or self.timeout_seconds
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS
            or type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes != expected_maximum_response_bytes
            or self.follow_redirects is not False
            or type(self.maximum_retries) is not int
            or self.maximum_retries != 0
            or self.proxy_allowed is not False
        ):
            raise ValueError("Microsoft Graph calling-client request is invalid")


_LIVE_HTTPS_ATTESTATION = object()


class EntraCallingClientRegistrationGraphResponse:
    """A bounded response; public construction is always synthetic evidence."""

    __slots__ = (
        "_attestation",
        "attempt_count",
        "body",
        "content_type",
        "final_url",
        "redirect_count",
        "status_code",
        "tls_peer_verified",
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
            raise ValueError("Microsoft Graph calling-client response is invalid")


def _attested_live_response(
    *,
    status_code: int,
    final_url: str,
    content_type: str,
    body: bytes,
) -> EntraCallingClientRegistrationGraphResponse:
    response = object.__new__(EntraCallingClientRegistrationGraphResponse)
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


EntraCallingClientRegistrationGraphRequestPlan = tuple[
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphRequest,
]
EntraCallingClientRegistrationGraphResponseSet = tuple[
    EntraCallingClientRegistrationGraphResponse,
    EntraCallingClientRegistrationGraphResponse,
    EntraCallingClientRegistrationGraphResponse,
]


class EntraCallingClientRegistrationGraphTransport(Protocol):
    def __call__(
        self,
        requests: EntraCallingClientRegistrationGraphRequestPlan,
    ) -> EntraCallingClientRegistrationGraphResponseSet: ...


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
        raise EntraCallingClientRegistrationGraphHTTPError(
            "Microsoft Graph calling-client redirects are not permitted"
        )


def _default_open(request: Request, timeout: float) -> HTTPSResponse:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # ``create_default_context`` honors ambient SSLKEYLOGFILE.  This
    # bearer-carrying boundary must never persist TLS session secrets.
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
        len(encoded) <= MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_BEARER_TOKEN_BYTES
        and not value.startswith("Bearer ")
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


class BoundedHTTPSEntraCallingClientRegistrationGraphLoader:
    """Execute the ordered three-read plan once with one opaque token."""

    def __init__(
        self,
        *,
        delegated_access_token: str,
        open_url: OpenURL | None = None,
    ) -> None:
        token = delegated_access_token
        try:
            if not _valid_bearer_token(token):
                raise ValueError("delegated Microsoft Graph access token is invalid")
            self._delegated_access_token = token
            selected_open = _default_open if open_url is None else open_url
            self._open_url = selected_open
            self._default_transport = (
                open_url is None and selected_open is _MODULE_OWNED_DEFAULT_OPEN
            )
            self._consumed = False
        finally:
            delegated_access_token = None
            token = None

    def __call__(
        self,
        requests: EntraCallingClientRegistrationGraphRequestPlan,
    ) -> EntraCallingClientRegistrationGraphResponseSet:
        if self._consumed:
            raise EntraCallingClientRegistrationGraphHTTPError(
                "Microsoft Graph calling-client loader is already consumed"
            )
        # Consume before request-plan validation so no rejected invocation can
        # leave a reusable token-bearing loader behind.
        self._consumed = True
        delegated_access_token = self._delegated_access_token
        responses: list[EntraCallingClientRegistrationGraphResponse] | None = []
        try:
            self._validate_request_plan(requests)
            for request in requests:
                responses.append(
                    self._execute(
                        request,
                        delegated_access_token=delegated_access_token,
                    )
                )
            return responses[0], responses[1], responses[2]
        finally:
            self._delegated_access_token = None
            delegated_access_token = None
            responses = None

    @staticmethod
    def _validate_request_plan(
        requests: EntraCallingClientRegistrationGraphRequestPlan,
    ) -> None:
        if type(requests) is not tuple or len(requests) != 3:
            raise EntraCallingClientRegistrationGraphHTTPError(
                "Microsoft Graph calling-client request plan is invalid"
            )
        expected = (
            (1, "calling_client_application"),
            (2, "owners"),
            (3, "federated_identity_credentials"),
        )
        object_ids: list[str] = []
        for request, (sequence, resource) in zip(requests, expected, strict=True):
            if (
                type(request) is not EntraCallingClientRegistrationGraphRequest
                or request.sequence != sequence
                or request.resource != resource
            ):
                raise EntraCallingClientRegistrationGraphHTTPError(
                    "Microsoft Graph calling-client request plan is invalid"
                )
            try:
                request.__post_init__()
                object_id = urlsplit(request.url).path.split("/")[3]
            except (IndexError, TypeError, ValueError):
                raise EntraCallingClientRegistrationGraphHTTPError(
                    "Microsoft Graph calling-client request plan is invalid"
                ) from None
            object_ids.append(object_id)
        if len(set(object_ids)) != 1:
            raise EntraCallingClientRegistrationGraphHTTPError(
                "Microsoft Graph requests do not target the same application"
            )

    def _execute(
        self,
        request: EntraCallingClientRegistrationGraphRequest,
        *,
        delegated_access_token: str,
    ) -> EntraCallingClientRegistrationGraphResponse:
        failed = False
        interrupted = False
        system_exit = False
        raw_headers = None
        raw_request = None
        response = None
        status_code = None
        final_url = None
        content_type = None
        body = None
        try:
            if not _valid_bearer_token(delegated_access_token):
                raise EntraCallingClientRegistrationGraphHTTPError(
                    "delegated Microsoft Graph access token is no longer available"
                )
            raw_headers = {name: value for name, value in request.headers}
            raw_headers.update(
                {
                    "Authorization": f"Bearer {delegated_access_token}",
                    "User-Agent": ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_USER_AGENT,
                }
            )
            raw_request = Request(request.url, method="GET", headers=raw_headers)
            with self._open_url(raw_request, request.timeout_seconds) as response:
                if type(response.status) is not int or response.status != 200:
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph returned a non-success status"
                    )
                status_code = response.status
                final_url = response.geturl()
                if type(final_url) is not str or final_url != request.url:
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph calling-client response source changed"
                    )
                content_type_header = response.headers.get("Content-Type", "")
                if (
                    type(content_type_header) is not str
                    or not 1 <= len(content_type_header) <= 512
                    or any(character in content_type_header for character in "\x00\r\n")
                ):
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph response content type is not accepted"
                    )
                content_type = content_type_header.strip()
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph response content type is not accepted"
                    )
                content_encoding_header = response.headers.get("Content-Encoding", "")
                if (
                    type(content_encoding_header) is not str
                    or len(content_encoding_header) > 64
                    or any(
                        character in content_encoding_header for character in "\x00\r\n"
                    )
                ):
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph response encoding is not accepted"
                    )
                content_encoding = content_encoding_header.strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph response encoding is not accepted"
                    )
                content_length = response.headers.get("Content-Length")
                declared_length = None
                if content_length is not None:
                    if (
                        type(content_length) is not str
                        or not 1 <= len(content_length) <= 20
                        or not content_length.isascii()
                        or not content_length.isdecimal()
                    ):
                        raise EntraCallingClientRegistrationGraphHTTPError(
                            "Microsoft Graph response content length is invalid"
                        )
                    declared_length = int(content_length)
                    if declared_length > request.maximum_response_bytes:
                        raise EntraCallingClientRegistrationGraphHTTPError(
                            "Microsoft Graph response exceeds the size limit"
                        )
                body = response.read(request.maximum_response_bytes + 1)
                if (
                    not isinstance(body, bytes)
                    or len(body) > request.maximum_response_bytes
                    or (declared_length is not None and declared_length != len(body))
                ):
                    raise EntraCallingClientRegistrationGraphHTTPError(
                        "Microsoft Graph response exceeds the size limit"
                    )
        except KeyboardInterrupt:
            interrupted = True
        except SystemExit:
            system_exit = True
        # This secret-bearing boundary must scrub even non-Exception failures.
        except BaseException:  # noqa: BLE001
            failed = True
        finally:
            delegated_access_token = None
            raw_headers = None
            raw_request = None
            response = None
        if interrupted:
            raise KeyboardInterrupt(
                "Microsoft Graph calling-client retrieval interrupted"
            )
        if system_exit:
            raise SystemExit("Microsoft Graph calling-client retrieval terminated")
        if failed:
            raise EntraCallingClientRegistrationGraphHTTPError(
                "Microsoft Graph HTTPS retrieval failed"
            )

        if self._default_transport:
            return _attested_live_response(
                status_code=status_code,
                final_url=final_url,
                content_type=content_type,
                body=body,
            )
        return EntraCallingClientRegistrationGraphResponse(
            status_code=status_code,
            final_url=final_url,
            content_type=content_type,
            body=body,
        )

    def close(self) -> None:
        """Release the only retained token reference and seal the loader."""

        self._delegated_access_token = None
        self._consumed = True


__all__ = [
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT",
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT",
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS",
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_USER_AGENT",
    "ENTRA_GRAPH_BASE_URL",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_BEARER_TOKEN_BYTES",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES",
    "BoundedHTTPSEntraCallingClientRegistrationGraphLoader",
    "EntraCallingClientRegistrationGraphHTTPError",
    "EntraCallingClientRegistrationGraphRequest",
    "EntraCallingClientRegistrationGraphRequestPlan",
    "EntraCallingClientRegistrationGraphResponse",
    "EntraCallingClientRegistrationGraphResponseSet",
    "EntraCallingClientRegistrationGraphTransport",
    "HTTPSResponse",
    "OpenURL",
    "entra_calling_client_registration_graph_url",
]
