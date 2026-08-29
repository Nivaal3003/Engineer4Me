"""Bounded HTTPS transport for the Step 212 External ID user-flow proof.

The loader executes exactly two ordered Microsoft Graph v1.0 GET requests:
one selected user-flow entity read and one selected included-application read.
Proxies, redirects, retries, request bodies, and response compression are
disabled.  One ephemeral opaque token intended for a delegated work/school
operator is supplied by the caller.  This module does not acquire, parse,
hash, log, render, return, or prove that token.

An injected opener is a deterministic test seam and can never produce live
provider evidence.  Only the captured module-owned direct HTTPS path can seal
responses as live.
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
ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS = 10.0
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES = 32_768
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_BEARER_TOKEN_BYTES = 16_384
ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT = (
    "Engineer4Me-Entra-External-ID-User-Flow-Probe/1.0"
)
ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT = 2
_USER_FLOW_SELECT = "id,conditions"
_INCLUDE_APPLICATIONS_SELECT = "appId"


class EntraExternalIdUserFlowGraphHTTPError(RuntimeError):
    """Sanitized failure at the controlled Graph user-flow HTTP boundary."""


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def entra_external_id_user_flow_graph_url(
    *,
    user_flow_id: str,
    resource: Literal["user_flow", "include_applications"],
) -> str:
    """Return one of the two exact flow-bound Graph URLs."""

    if not _canonical_uuid(user_flow_id):
        raise ValueError("a canonical nonzero user-flow ID is required")
    base = f"{ENTRA_GRAPH_BASE_URL}/identity/authenticationEventsFlows/{user_flow_id}"
    if resource == "user_flow":
        return f"{base}?$select={_USER_FLOW_SELECT}"
    if resource == "include_applications":
        return (
            f"{base}/conditions/applications/includeApplications"
            f"?$select={_INCLUDE_APPLICATIONS_SELECT}"
        )
    raise ValueError("a supported user-flow Graph resource is required")


@dataclass(frozen=True, slots=True)
class EntraExternalIdUserFlowGraphRequest:
    """One immutable request in the exact two-read Graph plan."""

    sequence: int
    resource: Literal["user_flow", "include_applications"]
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
        user_flow_id = ""
        try:
            split = urlsplit(self.url)
            segments = split.path.split("/")
            user_flow_id = segments[4]
            expected_url = entra_external_id_user_flow_graph_url(
                user_flow_id=user_flow_id,
                resource=self.resource,
            )
        except (IndexError, TypeError, ValueError):
            expected_url = ""
        expected_sequence = {
            "user_flow": 1,
            "include_applications": 2,
        }.get(self.resource)
        expected_headers = (
            (
                ("Accept", "application/json"),
                ("Accept-Encoding", "identity"),
            )
            if self.resource == "user_flow"
            else (
                ("Accept", "application/json"),
                ("Accept-Encoding", "identity"),
                ("Content-Type", "application/json"),
            )
        )
        if (
            type(self.sequence) is not int
            or self.sequence != expected_sequence
            or split is None
            or self.method != "GET"
            or split.scheme != "https"
            or split.netloc != "graph.microsoft.com"
            or split.fragment
            or split.username is not None
            or split.password is not None
            or split.port is not None
            or self.url != expected_url
            or self.headers != expected_headers
            or self.body is not None
            or type(self.timeout_seconds) is not float
            or self.timeout_seconds != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS
            or type(self.maximum_response_bytes) is not int
            or self.maximum_response_bytes
            != MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES
            or self.follow_redirects is not False
            or type(self.maximum_retries) is not int
            or self.maximum_retries != 0
            or self.proxy_allowed is not False
        ):
            raise ValueError("Microsoft Graph user-flow request is invalid")


_LIVE_HTTPS_ATTESTATION = object()


class EntraExternalIdUserFlowGraphResponse:
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
            raise ValueError("Microsoft Graph user-flow response is invalid")


def _attested_live_response(
    *,
    status_code: int,
    final_url: str,
    content_type: str,
    body: bytes,
) -> EntraExternalIdUserFlowGraphResponse:
    response = object.__new__(EntraExternalIdUserFlowGraphResponse)
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


EntraExternalIdUserFlowGraphRequestPlan = tuple[
    EntraExternalIdUserFlowGraphRequest,
    EntraExternalIdUserFlowGraphRequest,
]
EntraExternalIdUserFlowGraphResponsePair = tuple[
    EntraExternalIdUserFlowGraphResponse,
    EntraExternalIdUserFlowGraphResponse,
]


class EntraExternalIdUserFlowGraphTransport(Protocol):
    def __call__(
        self,
        requests: EntraExternalIdUserFlowGraphRequestPlan,
    ) -> EntraExternalIdUserFlowGraphResponsePair: ...


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
        raise EntraExternalIdUserFlowGraphHTTPError(
            "Microsoft Graph user-flow redirects are not permitted"
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
        len(encoded) <= MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_BEARER_TOKEN_BYTES
        and not value.startswith("Bearer ")
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


class BoundedHTTPSEntraExternalIdUserFlowGraphLoader:
    """Execute the exact ordered two-read plan with one ephemeral token."""

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
        requests: EntraExternalIdUserFlowGraphRequestPlan,
    ) -> EntraExternalIdUserFlowGraphResponsePair:
        if self._consumed:
            raise EntraExternalIdUserFlowGraphHTTPError(
                "Microsoft Graph user-flow loader is already consumed"
            )
        self._consumed = True
        delegated_access_token = self._delegated_access_token
        try:
            self._validate_request_plan(requests)
            first_response = self._execute(
                requests[0],
                delegated_access_token=delegated_access_token,
            )
            second_response = self._execute(
                requests[1],
                delegated_access_token=delegated_access_token,
            )
            return first_response, second_response
        finally:
            self._delegated_access_token = None
            delegated_access_token = None

    @staticmethod
    def _validate_request_plan(
        requests: EntraExternalIdUserFlowGraphRequestPlan,
    ) -> None:
        if type(requests) is not tuple or len(requests) != 2:
            raise EntraExternalIdUserFlowGraphHTTPError(
                "Microsoft Graph user-flow request plan is invalid"
            )
        expected = ((1, "user_flow"), (2, "include_applications"))
        user_flow_ids: list[str] = []
        for request, (sequence, resource) in zip(requests, expected, strict=True):
            if (
                type(request) is not EntraExternalIdUserFlowGraphRequest
                or request.sequence != sequence
                or request.resource != resource
            ):
                raise EntraExternalIdUserFlowGraphHTTPError(
                    "Microsoft Graph user-flow request plan is invalid"
                )
            try:
                request.__post_init__()
                split = urlsplit(request.url)
                user_flow_id = split.path.split("/")[4]
            except (IndexError, TypeError, ValueError):
                invalid_request = True
            else:
                invalid_request = False
            if invalid_request:
                raise EntraExternalIdUserFlowGraphHTTPError(
                    "Microsoft Graph user-flow request plan is invalid"
                )
            if not _canonical_uuid(user_flow_id):
                raise EntraExternalIdUserFlowGraphHTTPError(
                    "Microsoft Graph user-flow request plan is invalid"
                )
            user_flow_ids.append(user_flow_id)
        if len(set(user_flow_ids)) != 1:
            raise EntraExternalIdUserFlowGraphHTTPError(
                "Microsoft Graph requests do not target the same user flow"
            )

    def _execute(
        self,
        request: EntraExternalIdUserFlowGraphRequest,
        *,
        delegated_access_token: str,
    ) -> EntraExternalIdUserFlowGraphResponse:
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
                raise EntraExternalIdUserFlowGraphHTTPError(
                    "delegated Microsoft Graph access token is no longer available"
                )
            raw_headers = {name: value for name, value in request.headers}
            raw_headers.update(
                {
                    "Authorization": f"Bearer {delegated_access_token}",
                    "User-Agent": ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT,
                }
            )
            raw_request = Request(
                request.url,
                method="GET",
                headers=raw_headers,
            )
            with self._open_url(raw_request, request.timeout_seconds) as response:
                if type(response.status) is not int or response.status != 200:
                    raise EntraExternalIdUserFlowGraphHTTPError(
                        "Microsoft Graph returned a non-success status"
                    )
                status_code = response.status
                final_url = response.geturl()
                if type(final_url) is not str or final_url != request.url:
                    raise EntraExternalIdUserFlowGraphHTTPError(
                        "Microsoft Graph user-flow response source changed"
                    )
                content_type_header = response.headers.get("Content-Type", "")
                if (
                    type(content_type_header) is not str
                    or not 1 <= len(content_type_header) <= 512
                    or any(character in content_type_header for character in "\x00\r\n")
                ):
                    raise EntraExternalIdUserFlowGraphHTTPError(
                        "Microsoft Graph response content type is not accepted"
                    )
                content_type = content_type_header.strip()
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise EntraExternalIdUserFlowGraphHTTPError(
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
                    raise EntraExternalIdUserFlowGraphHTTPError(
                        "Microsoft Graph response encoding is not accepted"
                    )
                content_encoding = content_encoding_header.strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise EntraExternalIdUserFlowGraphHTTPError(
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
                        raise EntraExternalIdUserFlowGraphHTTPError(
                            "Microsoft Graph response content length is invalid"
                        )
                    declared_length = int(content_length)
                    if declared_length > request.maximum_response_bytes:
                        raise EntraExternalIdUserFlowGraphHTTPError(
                            "Microsoft Graph response exceeds the size limit"
                        )
                body = response.read(request.maximum_response_bytes + 1)
                if (
                    not isinstance(body, bytes)
                    or len(body) > request.maximum_response_bytes
                    or (declared_length is not None and declared_length != len(body))
                ):
                    raise EntraExternalIdUserFlowGraphHTTPError(
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
            raise KeyboardInterrupt("Microsoft Graph user-flow retrieval interrupted")
        if system_exit:
            raise SystemExit("Microsoft Graph user-flow retrieval terminated")
        if failed:
            raise EntraExternalIdUserFlowGraphHTTPError(
                "Microsoft Graph HTTPS retrieval failed"
            )

        if self._default_transport:
            return _attested_live_response(
                status_code=status_code,
                final_url=final_url,
                content_type=content_type,
                body=body,
            )
        return EntraExternalIdUserFlowGraphResponse(
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
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT",
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS",
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT",
    "ENTRA_GRAPH_BASE_URL",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_BEARER_TOKEN_BYTES",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES",
    "BoundedHTTPSEntraExternalIdUserFlowGraphLoader",
    "EntraExternalIdUserFlowGraphHTTPError",
    "EntraExternalIdUserFlowGraphRequest",
    "EntraExternalIdUserFlowGraphRequestPlan",
    "EntraExternalIdUserFlowGraphResponse",
    "EntraExternalIdUserFlowGraphResponsePair",
    "EntraExternalIdUserFlowGraphTransport",
    "HTTPSResponse",
    "OpenURL",
    "entra_external_id_user_flow_graph_url",
]
