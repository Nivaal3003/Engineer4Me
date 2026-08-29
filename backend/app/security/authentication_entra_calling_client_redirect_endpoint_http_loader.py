"""One-shot bounded HTTPS transport for approved SPA redirect endpoints.

The loader validates the complete request plan before I/O, resolves each exact
hostname once, rejects every non-public address, pins every TLS connection to a
pre-resolved address while retaining the original hostname for SNI, certificate
validation, and the Host header, and executes the exact ordered GET plan.

Publicly constructed observations and responses are synthetic.  Only this
module's captured resolver and socket/TLS implementation can seal a result as
live HTTPS evidence.  The transport never uses a proxy, follows a redirect,
retries a request, sends credentials/cookies/a body, or enables compression.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import quote, urlsplit, urlunsplit

from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN,
    FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT,
    FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
    FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES,
)

ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS = 10.0
ENTRA_REDIRECT_ENDPOINT_MAX_RAW_DNS_ADDRESSES_PER_HOST = 16
ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST = 8
ENTRA_REDIRECT_ENDPOINT_MAX_RESPONSE_HEADER_COUNT = 100
ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_COUNT = 1_024
ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_LINE_BYTES = 1_024
ENTRA_REDIRECT_ENDPOINT_MAX_CHUNKED_WIRE_BYTES = (
    FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES + 16_384
)
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_UNSUPPORTED_ENTRA_REDIRECT_CHARACTERS = frozenset("!$'(),;")
_CAPTURED_GETADDRINFO = socket.getaddrinfo
_CAPTURED_SOCKET = socket.socket
_CAPTURED_AF_UNSPEC = socket.AF_UNSPEC
_CAPTURED_AF_INET = socket.AF_INET
_CAPTURED_AF_INET6 = socket.AF_INET6
_CAPTURED_SOCK_STREAM = socket.SOCK_STREAM
_CAPTURED_IPPROTO_TCP = socket.IPPROTO_TCP
_CAPTURED_SSL_CONTEXT = ssl.SSLContext
_CAPTURED_PROTOCOL_TLS_CLIENT = ssl.PROTOCOL_TLS_CLIENT
_CAPTURED_SERVER_AUTH = ssl.Purpose.SERVER_AUTH
_CAPTURED_CERT_REQUIRED = ssl.CERT_REQUIRED
_CAPTURED_TLS_VERSION_1_2 = ssl.TLSVersion.TLSv1_2
_CAPTURED_MONOTONIC = time.monotonic


class EntraCallingClientRedirectEndpointHTTPError(RuntimeError):
    """Sanitized failure at the controlled redirect-endpoint boundary."""


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
        for attribute in ("__context__", "__cause__"):
            try:
                linked = BaseException.__getattribute__(current, attribute)
            except BaseException:  # noqa: BLE001  # pragma: no cover
                linked = None
            if isinstance(linked, BaseException):
                pending.append(linked)
        try:
            children = BaseException.__getattribute__(current, "exceptions")
        except BaseException:  # noqa: BLE001
            children = ()
        if type(children) is tuple:
            pending.extend(
                child for child in children if isinstance(child, BaseException)
            )
        try:
            notes = BaseException.__getattribute__(current, "__notes__")
            if isinstance(notes, list):
                notes.clear()
        except BaseException:  # noqa: BLE001,S110
            pass
        try:
            namespace = BaseException.__getattribute__(current, "__dict__")
            if isinstance(namespace, dict):
                namespace.clear()
        except BaseException:  # noqa: BLE001,S110  # pragma: no cover
            pass
        for attribute, value in (
            ("args", ()),
            ("__traceback__", None),
            ("__context__", None),
            ("__cause__", None),
            ("__suppress_context__", True),
        ):
            try:
                BaseException.__setattr__(current, attribute, value)
            except BaseException:  # noqa: BLE001,S110  # pragma: no cover
                pass
    return interrupted, terminated


def _is_public_ip(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        str(address) == value
        and address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not getattr(address, "is_site_local", False)
        and not (
            isinstance(address, ipaddress.IPv6Address)
            and (address.ipv4_mapped is not None or address.scope_id is not None)
        )
    )


def _canonical_hostname(value: object) -> bool:
    if type(value) is not str or _DNS_NAME.fullmatch(value) is None:
        return False
    if any(label.startswith("xn--") for label in value.split(".")):
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    labels = value.split(".")
    return bool(
        b"." in encoded
        and all(
            1 <= len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    )


def _canonical_redirect_uri(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 256:
        return False
    if any(
        character == "\\"
        or character == "%"
        or character in _UNSUPPORTED_ENTRA_REDIRECT_CHARACTERS
        or character.isspace()
        or ord(character) < 0x20
        or ord(character) > 0x7E
        for character in value
    ):
        return False
    try:
        split = urlsplit(value)
        port = split.port
    except ValueError:
        return False
    return bool(
        split.scheme == "https"
        and _canonical_hostname(split.hostname)
        and split.netloc == split.hostname
        and port is None
        and split.username is None
        and split.password is None
        and split.path.startswith("/")
        and split.path not in {"", "/"}
        and "//" not in split.path
        and not any(segment in {".", ".."} for segment in split.path.split("/"))
        and not split.query
        and not split.fragment
        and "*" not in value
        and urlunsplit(("https", split.hostname, split.path, "", "")) == value
    )


def _vector_url(redirect_uri: str, vector_name: str) -> str:
    target = quote(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET, safe="")
    return f"{redirect_uri}?{vector_name}={target}"


@dataclass(frozen=True, slots=True)
class EntraCallingClientRedirectEndpointRequest:
    """One immutable GET in the exact per-endpoint ten-request plan."""

    sequence: int
    endpoint_sequence: int
    request_sequence_for_endpoint: int
    kind: Literal["baseline", "hostile_origin", "bounded_open_redirect_vector"]
    vector_name: str | None
    redirect_uri: str
    method: str
    url: str
    hostname: str
    port: int
    headers: tuple[tuple[str, str], ...]
    body: None
    total_timeout_seconds: float
    maximum_header_bytes: int
    maximum_body_bytes: int
    follow_redirects: bool
    maximum_retries: int
    proxy_allowed: bool
    compression_allowed: bool

    def __post_init__(self) -> None:
        expected_kind = ""
        expected_vector = None
        expected_url = ""
        expected_headers: tuple[tuple[str, str], ...] = ()
        request_index = self.request_sequence_for_endpoint
        if request_index == 1:
            expected_kind = "baseline"
            expected_url = self.redirect_uri
            expected_headers = (
                ("Accept", "text/html"),
                ("Accept-Encoding", "identity"),
            )
        elif request_index == 2:
            expected_kind = "hostile_origin"
            expected_url = self.redirect_uri
            expected_headers = (
                ("Accept", "text/html"),
                ("Accept-Encoding", "identity"),
                ("Origin", FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN),
            )
        elif 3 <= request_index <= FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT:
            expected_kind = "bounded_open_redirect_vector"
            expected_vector = FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES[
                request_index - 3
            ]
            expected_url = _vector_url(self.redirect_uri, expected_vector)
            expected_headers = (
                ("Accept", "text/html"),
                ("Accept-Encoding", "identity"),
            )
        split = urlsplit(self.redirect_uri) if type(self.redirect_uri) is str else None
        if (
            type(self.sequence) is not int
            or self.sequence < 1
            or type(self.endpoint_sequence) is not int
            or not 1 <= self.endpoint_sequence <= 3
            or type(request_index) is not int
            or not 1
            <= request_index
            <= FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            or self.sequence
            != (self.endpoint_sequence - 1)
            * FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            + request_index
            or not _canonical_redirect_uri(self.redirect_uri)
            or split is None
            or type(self.kind) is not str
            or (self.vector_name is not None and type(self.vector_name) is not str)
            or type(self.method) is not str
            or type(self.url) is not str
            or type(self.hostname) is not str
            or type(self.port) is not int
            or type(self.headers) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                for item in self.headers
            )
            or self.hostname != split.hostname
            or self.kind != expected_kind
            or self.vector_name != expected_vector
            or self.method != "GET"
            or self.url != expected_url
            or self.port != 443
            or self.headers != expected_headers
            or self.body is not None
            or type(self.total_timeout_seconds) is not float
            or self.total_timeout_seconds
            != ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS
            or type(self.maximum_header_bytes) is not int
            or self.maximum_header_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
            or type(self.maximum_body_bytes) is not int
            or self.maximum_body_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES
            or self.follow_redirects is not False
            or type(self.maximum_retries) is not int
            or self.maximum_retries != 0
            or self.proxy_allowed is not False
            or self.compression_allowed is not False
        ):
            raise ValueError("Entra redirect endpoint request is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientRedirectEndpointDNSObservation:
    """Normalized shape for one planned or observed hostname-resolution call."""

    hostname: str
    resolved_addresses: tuple[str, ...]
    resolver_call_count: int = 1

    def __post_init__(self) -> None:
        if (
            not _canonical_hostname(self.hostname)
            or type(self.resolved_addresses) is not tuple
            or not 1
            <= len(self.resolved_addresses)
            <= ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST
            or any(type(value) is not str for value in self.resolved_addresses)
            or self.resolved_addresses
            != tuple(
                sorted(
                    self.resolved_addresses,
                    key=lambda value: (
                        ipaddress.ip_address(value).version,
                        ipaddress.ip_address(value).packed,
                    ),
                )
            )
            or len(set(self.resolved_addresses)) != len(self.resolved_addresses)
            or any(not _is_public_ip(value) for value in self.resolved_addresses)
            or type(self.resolver_call_count) is not int
            or self.resolver_call_count != 1
        ):
            raise ValueError("Entra redirect endpoint DNS observation is invalid")


_LIVE_HTTPS_ATTESTATION = object()


class EntraCallingClientRedirectEndpointResponse:
    """One bounded response; public construction is synthetic evidence."""

    __slots__ = (
        "_attestation",
        "attempt_count",
        "body",
        "certificate_chain_verified",
        "connected_address",
        "connected_peer_preresolved",
        "final_url",
        "header_bytes",
        "headers",
        "hostname_verified",
        "redirect_count",
        "request_url",
        "status_code",
        "tls_version",
    )

    def __init__(
        self,
        *,
        request_url: str,
        status_code: int,
        final_url: str,
        headers: tuple[tuple[str, str], ...],
        header_bytes: int,
        body: bytes,
        connected_address: str,
        connected_peer_preresolved: bool,
        tls_version: str,
        certificate_chain_verified: bool,
        hostname_verified: bool,
        redirect_count: int = 0,
        attempt_count: int = 1,
    ) -> None:
        self.request_url = request_url
        self.status_code = status_code
        self.final_url = final_url
        self.headers = headers
        self.header_bytes = header_bytes
        self.body = body
        self.connected_address = connected_address
        self.connected_peer_preresolved = connected_peer_preresolved
        self.tls_version = tls_version
        self.certificate_chain_verified = certificate_chain_verified
        self.hostname_verified = hostname_verified
        self.redirect_count = redirect_count
        self.attempt_count = attempt_count
        self._attestation = None
        self.validate()

    @property
    def live_https_attested(self) -> bool:
        return self._attestation is _LIVE_HTTPS_ATTESTATION

    def validate(self) -> None:
        normalized_minimum = 0
        names: list[str] = []
        headers_valid = type(self.headers) is tuple
        if headers_valid:
            normalized_minimum = len("HTTP/1.1 200\r\n") + 2
            for item in self.headers:
                if type(item) is not tuple or len(item) != 2:
                    headers_valid = False
                    break
                name, value = item
                if type(name) is not str or type(value) is not str:
                    headers_valid = False
                    break
                try:
                    encoded_name = name.encode("ascii")
                    encoded_value = value.encode("ascii")
                except (AttributeError, UnicodeEncodeError):
                    headers_valid = False
                    break
                if (
                    not name
                    or name != name.lower()
                    or _HEADER_NAME.fullmatch(encoded_name) is None
                    or value != value.strip(" \t")
                    or any(byte < 0x20 and byte != 0x09 for byte in encoded_value)
                    or b"\x7f" in encoded_value
                ):
                    headers_valid = False
                    break
                names.append(name)
                normalized_minimum += len(encoded_name) + 2 + len(encoded_value) + 2
        headers_valid = bool(headers_valid and len(names) == len(set(names)))
        if (
            type(self.request_url) is not str
            or type(self.status_code) is not int
            or not 100 <= self.status_code <= 599
            or type(self.final_url) is not str
            or not headers_valid
            or len(self.headers) > ENTRA_REDIRECT_ENDPOINT_MAX_RESPONSE_HEADER_COUNT
            or type(self.header_bytes) is not int
            or (
                self.live_https_attested
                and not normalized_minimum
                <= self.header_bytes
                <= FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
            )
            or (
                not self.live_https_attested and self.header_bytes != normalized_minimum
            )
            or type(self.body) is not bytes
            or len(self.body) > FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES
            or not _is_public_ip(self.connected_address)
            or type(self.connected_peer_preresolved) is not bool
            or self.tls_version not in {"TLSv1.2", "TLSv1.3"}
            or type(self.certificate_chain_verified) is not bool
            or type(self.hostname_verified) is not bool
            or type(self.redirect_count) is not int
            or self.redirect_count != 0
            or type(self.attempt_count) is not int
            or self.attempt_count != 1
            or self.connected_peer_preresolved is not self.live_https_attested
            or self.certificate_chain_verified is not self.live_https_attested
            or self.hostname_verified is not self.live_https_attested
        ):
            raise ValueError("Entra redirect endpoint response is invalid")


def _attested_live_response(
    *,
    request_url: str,
    status_code: int,
    headers: tuple[tuple[str, str], ...],
    header_bytes: int,
    body: bytes,
    connected_address: str,
    tls_version: str,
) -> EntraCallingClientRedirectEndpointResponse:
    response = object.__new__(EntraCallingClientRedirectEndpointResponse)
    response.request_url = request_url
    response.status_code = status_code
    response.final_url = request_url
    response.headers = headers
    response.header_bytes = header_bytes
    response.body = body
    response.connected_address = connected_address
    response.connected_peer_preresolved = True
    response.tls_version = tls_version
    response.certificate_chain_verified = True
    response.hostname_verified = True
    response.redirect_count = 0
    response.attempt_count = 1
    response._attestation = _LIVE_HTTPS_ATTESTATION
    response.validate()
    return response


class EntraCallingClientRedirectEndpointTransportResult:
    """All DNS observations and endpoint responses from one consumed loader."""

    __slots__ = ("_attestation", "dns_observations", "responses")

    def __init__(
        self,
        *,
        dns_observations: tuple[EntraCallingClientRedirectEndpointDNSObservation, ...],
        responses: tuple[EntraCallingClientRedirectEndpointResponse, ...],
    ) -> None:
        self.dns_observations = dns_observations
        self.responses = responses
        self._attestation = None
        self.validate()

    @property
    def live_https_attested(self) -> bool:
        return self._attestation is _LIVE_HTTPS_ATTESTATION

    def validate(self) -> None:
        if type(self.dns_observations) is tuple:
            for observation in self.dns_observations:
                if (
                    type(observation)
                    is EntraCallingClientRedirectEndpointDNSObservation
                ):
                    observation.__post_init__()
        if type(self.responses) is tuple:
            for response in self.responses:
                if type(response) is EntraCallingClientRedirectEndpointResponse:
                    response.validate()
        if (
            type(self.dns_observations) is not tuple
            or not 1 <= len(self.dns_observations) <= 3
            or any(
                type(value) is not EntraCallingClientRedirectEndpointDNSObservation
                for value in self.dns_observations
            )
            or tuple(value.hostname for value in self.dns_observations)
            != tuple(sorted(value.hostname for value in self.dns_observations))
            or len({value.hostname for value in self.dns_observations})
            != len(self.dns_observations)
            or type(self.responses) is not tuple
            or not 10 <= len(self.responses) <= 30
            or len(self.responses)
            % FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            != 0
            or any(
                type(value) is not EntraCallingClientRedirectEndpointResponse
                for value in self.responses
            )
            or (
                self.live_https_attested
                and any(not value.live_https_attested for value in self.responses)
            )
            or (
                not self.live_https_attested
                and any(value.live_https_attested for value in self.responses)
            )
        ):
            raise ValueError("Entra redirect endpoint transport result is invalid")


def _attested_live_result(
    *,
    dns_observations: tuple[EntraCallingClientRedirectEndpointDNSObservation, ...],
    responses: tuple[EntraCallingClientRedirectEndpointResponse, ...],
) -> EntraCallingClientRedirectEndpointTransportResult:
    result = object.__new__(EntraCallingClientRedirectEndpointTransportResult)
    result.dns_observations = dns_observations
    result.responses = responses
    result._attestation = _LIVE_HTTPS_ATTESTATION
    result.validate()
    return result


EntraCallingClientRedirectEndpointRequestPlan = tuple[
    EntraCallingClientRedirectEndpointRequest, ...
]


class EntraCallingClientRedirectEndpointTransport(Protocol):
    def __call__(
        self,
        requests: EntraCallingClientRedirectEndpointRequestPlan,
    ) -> EntraCallingClientRedirectEndpointTransportResult: ...


Resolver = Callable[[str, int], EntraCallingClientRedirectEndpointDNSObservation]
RequestExecutor = Callable[
    [
        EntraCallingClientRedirectEndpointRequest,
        EntraCallingClientRedirectEndpointDNSObservation,
    ],
    EntraCallingClientRedirectEndpointResponse,
]


def _resolve_internal(
    hostname: str,
    port: int,
    _getaddrinfo: Callable[..., object] = _CAPTURED_GETADDRINFO,
) -> EntraCallingClientRedirectEndpointDNSObservation:
    raw = _getaddrinfo(
        hostname,
        port,
        family=_CAPTURED_AF_UNSPEC,
        type=_CAPTURED_SOCK_STREAM,
        proto=_CAPTURED_IPPROTO_TCP,
    )
    if (
        type(raw) is not list
        or not 1 <= len(raw) <= ENTRA_REDIRECT_ENDPOINT_MAX_RAW_DNS_ADDRESSES_PER_HOST
    ):
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint DNS resolution failed"
        )
    addresses: set[str] = set()
    for entry in raw:
        try:
            if type(entry) is not tuple or len(entry) != 5:
                raise ValueError
            family, socktype, protocol, canonical_name, sockaddr = entry
            if (
                type(family) is not type(_CAPTURED_AF_INET)
                or family not in {_CAPTURED_AF_INET, _CAPTURED_AF_INET6}
                or type(socktype) is not type(_CAPTURED_SOCK_STREAM)
                or socktype != _CAPTURED_SOCK_STREAM
                or type(protocol) is not type(_CAPTURED_IPPROTO_TCP)
                or protocol != _CAPTURED_IPPROTO_TCP
                or type(canonical_name) is not str
                or type(sockaddr) is not tuple
            ):
                raise ValueError
            if family == _CAPTURED_AF_INET:
                if (
                    len(sockaddr) != 2
                    or type(sockaddr[0]) is not str
                    or type(sockaddr[1]) is not int
                    or sockaddr[1] != 443
                ):
                    raise ValueError
            elif (
                len(sockaddr) != 4
                or type(sockaddr[0]) is not str
                or type(sockaddr[1]) is not int
                or type(sockaddr[2]) is not int
                or type(sockaddr[3]) is not int
                or sockaddr[1] != 443
                or sockaddr[2] != 0
                or sockaddr[3] != 0
            ):
                raise ValueError
            parsed_address = ipaddress.ip_address(sockaddr[0])
            if (family == _CAPTURED_AF_INET and parsed_address.version != 4) or (
                family == _CAPTURED_AF_INET6 and parsed_address.version != 6
            ):
                raise ValueError
            address = str(parsed_address)
        except (IndexError, TypeError, ValueError):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint DNS response is invalid"
            ) from None
        addresses.add(address)
    ordered = tuple(
        sorted(
            addresses,
            key=lambda value: (
                ipaddress.ip_address(value).version,
                ipaddress.ip_address(value).packed,
            ),
        )
    )
    try:
        return EntraCallingClientRedirectEndpointDNSObservation(
            hostname=hostname,
            resolved_addresses=ordered,
        )
    except ValueError:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint DNS addresses are not accepted"
        ) from None


def _default_resolve(
    hostname: str,
    port: int,
    _internal: Callable[
        [str, int], EntraCallingClientRedirectEndpointDNSObservation
    ] = _resolve_internal,
) -> EntraCallingClientRedirectEndpointDNSObservation:
    """Resolve exactly once and bound the accepted address collection."""

    result = None
    error = None
    failed = False
    interrupted = False
    terminated = False
    try:
        result = _internal(hostname, port)
    except KeyboardInterrupt as caught:
        error = caught
        interrupted = True
    except SystemExit as caught:
        error = caught
        terminated = True
    except BaseException as caught:  # noqa: BLE001 - sanitize resolver context
        error = caught
        failed = True
    finally:
        if error is not None:
            nested_interrupted, nested_terminated = _scrub_exception_graph(error)
            interrupted = interrupted or nested_interrupted
            terminated = terminated or nested_terminated
        error = None
        hostname = None
        port = None
        _internal = None
    if interrupted:
        result = None
        raise KeyboardInterrupt("redirect endpoint DNS resolution interrupted")
    if terminated:
        result = None
        raise SystemExit("redirect endpoint DNS resolution terminated")
    if failed or result is None:
        result = None
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint DNS resolution failed"
        )
    return result


def _request_bytes(request: EntraCallingClientRedirectEndpointRequest) -> bytes:
    split = urlsplit(request.url)
    target = split.path + (f"?{split.query}" if split.query else "")
    headers = [
        ("Host", request.hostname),
        *request.headers,
        ("Connection", "close"),
    ]
    material = [f"GET {target} HTTP/1.1", *(f"{k}: {v}" for k, v in headers), "", ""]
    try:
        encoded = "\r\n".join(material).encode("ascii")
    except UnicodeEncodeError:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint request is not ASCII"
        ) from None
    if len(encoded) > FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint request headers exceed the limit"
        )
    return encoded


def _parse_response_head(
    raw_head: bytes,
) -> tuple[int, tuple[tuple[str, str], ...]]:
    if len(raw_head) > FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint response headers exceed the limit"
        )
    lines = raw_head.split(b"\r\n")
    if not lines or len(lines) - 1 > ENTRA_REDIRECT_ENDPOINT_MAX_RESPONSE_HEADER_COUNT:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint response header count is invalid"
        )
    match = re.fullmatch(rb"HTTP/1\.1 ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0])
    if match is None:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint response status line is invalid"
        )
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line[:1] in b" \t" or b":" not in line:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response header is invalid"
            )
        raw_name, raw_value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response header name is invalid"
            )
        value = raw_value.strip(b" \t")
        if (
            any(byte < 0x20 and byte != 0x09 for byte in value)
            or b"\x7f" in value
            or any(byte > 0x7E for byte in value)
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response header value is invalid"
            )
        try:
            headers.append((raw_name.decode("ascii").lower(), value.decode("ascii")))
        except UnicodeDecodeError:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response header name is invalid"
            ) from None
    normalized = tuple(headers)
    if len({name for name, _ in normalized}) != len(normalized):
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint response contains a duplicate header"
        )
    return int(match.group(1)), normalized


def _single_header(
    headers: tuple[tuple[str, str], ...],
    name: str,
) -> str | None:
    values = [value for key, value in headers if key == name]
    if len(values) > 1:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint response contains a duplicate framing header"
        )
    return values[0] if values else None


def _normalized_response_header_bytes(
    status_code: int,
    headers: tuple[tuple[str, str], ...],
) -> int:
    return (
        len(f"HTTP/1.1 {status_code:03d}\r\n")
        + sum(
            len(name.encode("ascii")) + 2 + len(value.encode("ascii")) + 2
            for name, value in headers
        )
        + 2
    )


def _remaining_timeout(
    deadline: float,
    _clock: Callable[[], float] = _CAPTURED_MONOTONIC,
) -> float:
    remaining = deadline - _clock()
    if remaining <= 0:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint request deadline expired"
        )
    return remaining


def _recv_bounded(
    connection: object,
    amount: int,
    deadline: float,
    clock: Callable[[], float] = _CAPTURED_MONOTONIC,
) -> bytes:
    connection.settimeout(_remaining_timeout(deadline, clock))
    value = connection.recv(amount)
    if type(value) is not bytes:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint socket returned invalid bytes"
        )
    return value


def _decode_chunked_body(
    *,
    connection: object,
    initial: bytes,
    deadline: float,
    maximum_body_bytes: int,
    clock: Callable[[], float] = _CAPTURED_MONOTONIC,
) -> bytes:
    buffer = bytearray(initial)
    decoded = bytearray()
    raw_wire_bytes = len(initial)
    chunk_count = 0
    if raw_wire_bytes > ENTRA_REDIRECT_ENDPOINT_MAX_CHUNKED_WIRE_BYTES:
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint chunked wire body exceeds the limit"
        )

    def receive() -> None:
        nonlocal raw_wire_bytes
        chunk = _recv_bounded(connection, 16_384, deadline, clock)
        if not chunk:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint chunked body is incomplete"
            )
        raw_wire_bytes += len(chunk)
        if raw_wire_bytes > ENTRA_REDIRECT_ENDPOINT_MAX_CHUNKED_WIRE_BYTES:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint chunked wire body exceeds the limit"
            )
        buffer.extend(chunk)

    def read_line() -> bytes:
        while True:
            delimiter = buffer.find(b"\r\n")
            if delimiter >= 0:
                if delimiter > ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_LINE_BYTES:
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint chunk line exceeds the limit"
                    )
                line = bytes(buffer[:delimiter])
                del buffer[: delimiter + 2]
                return line
            if len(buffer) > ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_LINE_BYTES:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint chunk line exceeds the limit"
                )
            receive()

    while True:
        size_line = read_line()
        if (
            not size_line
            or b";" in size_line
            or re.fullmatch(rb"[0-9A-Fa-f]+", size_line) is None
            or len(size_line) > 16
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint chunk size is invalid"
            )
        size = int(size_line, 16)
        if size == 0:
            if read_line() != b"" or buffer:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint chunk trailers are not accepted"
                )
            return bytes(decoded)
        chunk_count += 1
        if (
            chunk_count > ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_COUNT
            or size > maximum_body_bytes - len(decoded)
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint decoded chunked body exceeds the limit"
            )
        required = size + 2
        while len(buffer) < required:
            receive()
        if bytes(buffer[size:required]) != b"\r\n":
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint chunk data is invalid"
            )
        decoded.extend(buffer[:size])
        del buffer[:required]


def _default_execute(
    request: EntraCallingClientRedirectEndpointRequest,
    observation: EntraCallingClientRedirectEndpointDNSObservation,
    _socket_factory: Callable[..., object] = _CAPTURED_SOCKET,
    _context_factory: Callable[..., object] = _CAPTURED_SSL_CONTEXT,
    _clock: Callable[[], float] = _CAPTURED_MONOTONIC,
) -> EntraCallingClientRedirectEndpointResponse:
    """Execute one direct, IP-pinned TLS request without retry or redirect."""

    address = None
    family = None
    endpoint = None
    plain_socket = None
    tls_socket = None
    context = None
    received = None
    body = None
    body_buffer = None
    initial_body = None
    chunk = None
    headers = None
    raw_length = None
    transfer_encoding = None
    encoded_request = None
    peer = None
    raw_peer = None
    tls_peer = None
    raw_tls_peer = None
    tls_version = None
    status = None
    header_bytes = None
    declared_length = None
    delimiter = None
    remaining_body = None
    result = None
    error = None
    interrupted = False
    terminated = False
    failed = False
    deadline = None
    live_dependencies = False
    try:
        if type(request) is not EntraCallingClientRedirectEndpointRequest:
            raise TypeError("redirect endpoint request type is invalid")
        if type(observation) is not EntraCallingClientRedirectEndpointDNSObservation:
            raise TypeError("redirect endpoint DNS observation type is invalid")
        request.__post_init__()
        observation.__post_init__()
        address = observation.resolved_addresses[0]
        family = (
            _CAPTURED_AF_INET6
            if ipaddress.ip_address(address).version == 6
            else _CAPTURED_AF_INET
        )
        endpoint = (
            (address, request.port, 0, 0)
            if family == _CAPTURED_AF_INET6
            else (address, request.port)
        )
        live_dependencies = bool(
            _socket_factory is _CAPTURED_SOCKET
            and _context_factory is _CAPTURED_SSL_CONTEXT
            and _clock is _CAPTURED_MONOTONIC
        )
        deadline = _clock() + request.total_timeout_seconds
        plain_socket = _socket_factory(
            family,
            _CAPTURED_SOCK_STREAM,
            _CAPTURED_IPPROTO_TCP,
        )
        plain_socket.settimeout(_remaining_timeout(deadline, _clock))
        plain_socket.connect(endpoint)
        raw_peer = plain_socket.getpeername()
        peer = str(ipaddress.ip_address(raw_peer[0]))
        if (
            peer != address
            or raw_peer[1] != 443
            or peer not in observation.resolved_addresses
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint connected peer was not pre-resolved"
            )
        context = _context_factory(_CAPTURED_PROTOCOL_TLS_CLIENT)
        context.load_default_certs(_CAPTURED_SERVER_AUTH)
        context.verify_mode = _CAPTURED_CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = _CAPTURED_TLS_VERSION_1_2
        context.set_alpn_protocols(["http/1.1"])
        if context.keylog_filename is not None:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint TLS key logging is not accepted"
            )
        plain_socket.settimeout(_remaining_timeout(deadline, _clock))
        tls_socket = context.wrap_socket(
            plain_socket,
            server_hostname=request.hostname,
            suppress_ragged_eofs=False,
        )
        plain_socket = None
        raw_tls_peer = tls_socket.getpeername()
        tls_peer = str(ipaddress.ip_address(raw_tls_peer[0]))
        if (
            tls_peer != address
            or raw_tls_peer[1] != 443
            or tls_peer not in observation.resolved_addresses
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint TLS peer was not pre-resolved"
            )
        tls_version = tls_socket.version()
        if (
            tls_version not in {"TLSv1.2", "TLSv1.3"}
            or tls_socket.selected_alpn_protocol() not in {None, "http/1.1"}
            or not tls_socket.getpeercert()
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint TLS session is not accepted"
            )
        encoded_request = _request_bytes(request)
        tls_socket.settimeout(_remaining_timeout(deadline, _clock))
        tls_socket.sendall(encoded_request)
        received = bytearray()
        delimiter = -1
        while delimiter < 0:
            chunk = _recv_bounded(tls_socket, 4_096, deadline, _clock)
            if not chunk:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint response headers are incomplete"
                )
            received.extend(chunk)
            delimiter = received.find(b"\r\n\r\n")
            if delimiter < 0 and len(received) > request.maximum_header_bytes:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint response headers exceed the limit"
                )
        header_bytes = delimiter + 4
        if header_bytes > request.maximum_header_bytes:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response headers exceed the limit"
            )
        status, headers = _parse_response_head(bytes(received[:delimiter]))
        if status != 200:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint returned a non-success status"
            )
        transfer_encoding = _single_header(headers, "transfer-encoding")
        raw_length = _single_header(headers, "content-length")
        if transfer_encoding is not None and raw_length is not None:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response framing is ambiguous"
            )
        if (
            transfer_encoding is not None
            and transfer_encoding.strip().lower() != "chunked"
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint transfer encoding is not accepted"
            )
        declared_length = None
        if raw_length is not None:
            if (
                not 1 <= len(raw_length) <= 20
                or not raw_length.isascii()
                or not raw_length.isdecimal()
                or (len(raw_length) > 1 and raw_length.startswith("0"))
            ):
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint content length is invalid"
                )
            declared_length = int(raw_length)
            if declared_length > request.maximum_body_bytes:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint response body exceeds the limit"
                )
        initial_body = bytes(received[header_bytes:])
        if transfer_encoding is not None:
            body = _decode_chunked_body(
                connection=tls_socket,
                initial=initial_body,
                deadline=deadline,
                maximum_body_bytes=request.maximum_body_bytes,
                clock=_clock,
            )
        else:
            body_buffer = bytearray(initial_body)
            if declared_length is not None and len(body_buffer) > declared_length:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint response body exceeds its declared length"
                )
            while declared_length is None or len(body_buffer) < declared_length:
                remaining_body = request.maximum_body_bytes + 1 - len(body_buffer)
                chunk = _recv_bounded(
                    tls_socket,
                    min(16_384, remaining_body),
                    deadline,
                    _clock,
                )
                if not chunk:
                    break
                body_buffer.extend(chunk)
                if len(body_buffer) > request.maximum_body_bytes:
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint response body exceeds the limit"
                    )
            if declared_length is not None and len(body_buffer) != declared_length:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint response body length is invalid"
                )
            body = bytes(body_buffer)
        if len(body) > request.maximum_body_bytes:
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint response body exceeds the limit"
            )
        if live_dependencies:
            result = _attested_live_response(
                request_url=request.url,
                status_code=status,
                headers=headers,
                header_bytes=header_bytes,
                body=body,
                connected_address=address,
                tls_version=tls_version,
            )
        else:
            result = EntraCallingClientRedirectEndpointResponse(
                request_url=request.url,
                status_code=status,
                final_url=request.url,
                headers=headers,
                header_bytes=_normalized_response_header_bytes(status, headers),
                body=body,
                connected_address=address,
                connected_peer_preresolved=False,
                tls_version=tls_version,
                certificate_chain_verified=False,
                hostname_verified=False,
            )
    except KeyboardInterrupt as caught:
        error = caught
        interrupted = True
    except SystemExit as caught:
        error = caught
        terminated = True
    except BaseException as caught:  # noqa: BLE001 - sanitize socket/TLS context
        error = caught
        failed = True
    finally:
        for connection in (tls_socket, plain_socket):
            if connection is not None:
                try:
                    connection.close()
                except KeyboardInterrupt as close_error:
                    _, nested_terminated = _scrub_exception_graph(close_error)
                    interrupted = True
                    terminated = terminated or nested_terminated
                except SystemExit as close_error:
                    nested_interrupted, _ = _scrub_exception_graph(close_error)
                    interrupted = interrupted or nested_interrupted
                    terminated = True
                except BaseException as close_error:  # noqa: BLE001
                    nested_interrupted, nested_terminated = _scrub_exception_graph(
                        close_error
                    )
                    interrupted = interrupted or nested_interrupted
                    terminated = terminated or nested_terminated
                    failed = True
        connection = None
        if error is not None:
            nested_interrupted, nested_terminated = _scrub_exception_graph(error)
            interrupted = interrupted or nested_interrupted
            terminated = terminated or nested_terminated
        request = None
        observation = None
        address = None
        endpoint = None
        peer = None
        raw_peer = None
        raw_tls_peer = None
        tls_peer = None
        tls_version = None
        status = None
        header_bytes = None
        declared_length = None
        delimiter = None
        remaining_body = None
        family = None
        deadline = None
        live_dependencies = False
        context = None
        received = None
        body = None
        body_buffer = None
        initial_body = None
        chunk = None
        headers = None
        raw_length = None
        transfer_encoding = None
        encoded_request = None
        tls_socket = None
        plain_socket = None
        _socket_factory = None
        _context_factory = None
        _clock = None
        error = None
    if interrupted:
        result = None
        raise KeyboardInterrupt("redirect endpoint HTTPS request interrupted")
    if terminated:
        result = None
        raise SystemExit("redirect endpoint HTTPS request terminated")
    if failed or result is None:
        result = None
        raise EntraCallingClientRedirectEndpointHTTPError(
            "redirect endpoint direct HTTPS request failed"
        )
    return result


_MODULE_OWNED_DEFAULT_RESOLVE = _default_resolve
_MODULE_OWNED_DEFAULT_EXECUTE = _default_execute


class BoundedHTTPSEntraCallingClientRedirectEndpointLoader:
    """Consume one exact request plan and return bounded observations once."""

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        request_executor: RequestExecutor | None = None,
    ) -> None:
        if (resolver is None) is not (request_executor is None):
            resolver = None
            request_executor = None
            self = None  # noqa: PLW0642 - detach injected dependencies from traceback
            raise TypeError(
                "redirect endpoint transport dependencies must both be sealed or injected"
            )
        selected_resolver = _default_resolve if resolver is None else resolver
        selected_executor = (
            _default_execute if request_executor is None else request_executor
        )
        if not callable(selected_resolver) or not callable(selected_executor):
            resolver = None
            request_executor = None
            selected_resolver = None
            selected_executor = None
            self = None  # noqa: PLW0642 - detach injected dependencies from traceback
            raise TypeError("redirect endpoint transport dependencies must be callable")
        self._resolver = selected_resolver
        self._request_executor = selected_executor
        self._default_transport = bool(
            resolver is None
            and request_executor is None
            and selected_resolver is _MODULE_OWNED_DEFAULT_RESOLVE
            and selected_executor is _MODULE_OWNED_DEFAULT_EXECUTE
        )
        self._consumed = False

    def __call__(
        self,
        requests: EntraCallingClientRedirectEndpointRequestPlan,
    ) -> EntraCallingClientRedirectEndpointTransportResult:
        if self._consumed:
            self._resolver = None
            self._request_executor = None
            self._default_transport = False
            requests = None
            self = None  # noqa: PLW0642 - detach injected dependencies from traceback
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint loader is already consumed"
            )
        self._consumed = True
        resolver = self._resolver
        request_executor = self._request_executor
        default_transport = self._default_transport
        self._resolver = None
        self._request_executor = None
        self._default_transport = False
        self = None  # noqa: PLW0642 - detach injected dependencies from traceback
        observations: list[EntraCallingClientRedirectEndpointDNSObservation] = []
        responses: list[EntraCallingClientRedirectEndpointResponse] = []
        result = None
        error = None
        interrupted = False
        terminated = False
        failed = False
        hostnames = None
        by_hostname = None
        hostname = None
        observation = None
        request = None
        response = None
        observations_tuple = None
        responses_tuple = None
        try:
            BoundedHTTPSEntraCallingClientRedirectEndpointLoader._validate_request_plan(
                requests
            )
            hostnames = tuple(sorted({request.hostname for request in requests}))
            by_hostname = {}
            for hostname in hostnames:
                observation = resolver(
                    hostname,
                    443,
                )
                if (
                    type(observation)
                    is not EntraCallingClientRedirectEndpointDNSObservation
                    or observation.hostname != hostname
                ):
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint resolver returned invalid evidence"
                    )
                observation.__post_init__()
                observations.append(observation)
                by_hostname[hostname] = observation
            for request in requests:
                response = request_executor(
                    request,
                    by_hostname[request.hostname],
                )
                if type(response) is not EntraCallingClientRedirectEndpointResponse:
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint executor returned invalid evidence"
                    )
                response.validate()
                if (
                    response.request_url != request.url
                    or response.final_url != request.url
                ):
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint response source changed"
                    )
                if (
                    response.connected_address
                    != by_hostname[request.hostname].resolved_addresses[0]
                ):
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "redirect endpoint connected peer was not pre-resolved"
                    )
                if default_transport and not response.live_https_attested:
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "live redirect endpoint response is not attested"
                    )
                if not default_transport and response.live_https_attested:
                    raise EntraCallingClientRedirectEndpointHTTPError(
                        "attested response is not accepted from an injected transport"
                    )
                responses.append(response)
            observations_tuple = tuple(observations)
            responses_tuple = tuple(responses)
            if default_transport:
                result = _attested_live_result(
                    dns_observations=observations_tuple,
                    responses=responses_tuple,
                )
            else:
                result = EntraCallingClientRedirectEndpointTransportResult(
                    dns_observations=observations_tuple,
                    responses=responses_tuple,
                )
        except KeyboardInterrupt as caught:
            error = caught
            interrupted = True
        except SystemExit as caught:
            error = caught
            terminated = True
        except BaseException as caught:  # noqa: BLE001 - sanitize all dependencies
            error = caught
            failed = True
        finally:
            if error is not None:
                nested_interrupted, nested_terminated = _scrub_exception_graph(error)
                interrupted = interrupted or nested_interrupted
                terminated = terminated or nested_terminated
            error = None
            observations = []
            responses = []
            requests = None
            hostnames = None
            by_hostname = None
            hostname = None
            observation = None
            request = None
            response = None
            observations_tuple = None
            responses_tuple = None
            resolver = None
            request_executor = None
            default_transport = False
        if interrupted:
            result = None
            raise KeyboardInterrupt("redirect endpoint transport interrupted")
        if terminated:
            result = None
            raise SystemExit("redirect endpoint transport terminated")
        if failed or result is None:
            result = None
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint transport failed"
            )
        return result

    @staticmethod
    def _validate_request_plan(
        requests: EntraCallingClientRedirectEndpointRequestPlan,
    ) -> None:
        if (
            type(requests) is not tuple
            or not 10 <= len(requests) <= 30
            or len(requests) % FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT != 0
        ):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint request plan is invalid"
            )
        endpoints: list[str] = []
        for index, request in enumerate(requests, start=1):
            if type(request) is not EntraCallingClientRedirectEndpointRequest:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint request plan is invalid"
                )
            try:
                request.__post_init__()
            except ValueError:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint request plan is invalid"
                ) from None
            endpoint_sequence = (index - 1) // 10 + 1
            within_sequence = (index - 1) % 10 + 1
            if (
                request.sequence != index
                or request.endpoint_sequence != endpoint_sequence
                or request.request_sequence_for_endpoint != within_sequence
            ):
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint request plan order is invalid"
                )
            if within_sequence == 1:
                endpoints.append(request.redirect_uri)
            elif request.redirect_uri != endpoints[-1]:
                raise EntraCallingClientRedirectEndpointHTTPError(
                    "redirect endpoint request group is invalid"
                )
        if endpoints != sorted(endpoints) or len(endpoints) != len(set(endpoints)):
            raise EntraCallingClientRedirectEndpointHTTPError(
                "redirect endpoint targets are not exact sorted unique URIs"
            )

    def close(self) -> None:
        """Seal the loader against all future use."""

        self._consumed = True
        self._resolver = None
        self._request_executor = None
        self._default_transport = False


__all__ = [
    "ENTRA_REDIRECT_ENDPOINT_MAX_CHUNKED_WIRE_BYTES",
    "ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_COUNT",
    "ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_LINE_BYTES",
    "ENTRA_REDIRECT_ENDPOINT_MAX_RAW_DNS_ADDRESSES_PER_HOST",
    "ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST",
    "ENTRA_REDIRECT_ENDPOINT_MAX_RESPONSE_HEADER_COUNT",
    "ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS",
    "BoundedHTTPSEntraCallingClientRedirectEndpointLoader",
    "EntraCallingClientRedirectEndpointDNSObservation",
    "EntraCallingClientRedirectEndpointHTTPError",
    "EntraCallingClientRedirectEndpointRequest",
    "EntraCallingClientRedirectEndpointRequestPlan",
    "EntraCallingClientRedirectEndpointResponse",
    "EntraCallingClientRedirectEndpointTransport",
    "EntraCallingClientRedirectEndpointTransportResult",
    "RequestExecutor",
    "Resolver",
]
