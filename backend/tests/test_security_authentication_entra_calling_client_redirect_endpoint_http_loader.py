"""Tests for the bounded SPA redirect-endpoint HTTPS transport."""

from __future__ import annotations

import builtins
import ssl
from dataclasses import replace
from urllib.parse import quote, urlsplit

import pytest

import app.security.authentication_entra_calling_client_redirect_endpoint_http_loader as module
from app.security.authentication_entra_calling_client_redirect_endpoint_http_loader import (
    ENTRA_REDIRECT_ENDPOINT_MAX_RAW_DNS_ADDRESSES_PER_HOST,
    ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST,
    ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS,
    BoundedHTTPSEntraCallingClientRedirectEndpointLoader,
    EntraCallingClientRedirectEndpointDNSObservation,
    EntraCallingClientRedirectEndpointHTTPError,
    EntraCallingClientRedirectEndpointRequest,
    EntraCallingClientRedirectEndpointResponse,
    EntraCallingClientRedirectEndpointTransportResult,
)
from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN,
    FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
    FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES,
)

URI = "https://app.engineer4me.invalid/auth/callback"
URI_2 = "https://portal.engineer4me.invalid/auth/callback"
PUBLIC_IP = "8.8.8.8"
PUBLIC_IP_2 = "9.9.9.9"


class StrSubclass(str):
    pass


class TupleSubclass(tuple):
    pass


def request_plan(uris=(URI,)):
    requests = []
    target = quote(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET, safe="")
    for endpoint_sequence, uri in enumerate(uris, start=1):
        definitions = [
            (
                "baseline",
                None,
                uri,
                (("Accept", "text/html"), ("Accept-Encoding", "identity")),
            ),
            (
                "hostile_origin",
                None,
                uri,
                (
                    ("Accept", "text/html"),
                    ("Accept-Encoding", "identity"),
                    ("Origin", FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN),
                ),
            ),
        ]
        definitions.extend(
            (
                "bounded_open_redirect_vector",
                vector,
                f"{uri}?{vector}={target}",
                (("Accept", "text/html"), ("Accept-Encoding", "identity")),
            )
            for vector in FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
        )
        for within, (kind, vector, url, headers) in enumerate(definitions, start=1):
            requests.append(
                EntraCallingClientRedirectEndpointRequest(
                    sequence=len(requests) + 1,
                    endpoint_sequence=endpoint_sequence,
                    request_sequence_for_endpoint=within,
                    kind=kind,
                    vector_name=vector,
                    redirect_uri=uri,
                    method="GET",
                    url=url,
                    hostname=urlsplit(uri).hostname,
                    port=443,
                    headers=headers,
                    body=None,
                    total_timeout_seconds=(
                        ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS
                    ),
                    maximum_header_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
                    maximum_body_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
                    follow_redirects=False,
                    maximum_retries=0,
                    proxy_allowed=False,
                    compression_allowed=False,
                )
            )
    return tuple(requests)


def header_bytes(headers, status=200):
    return (
        len(f"HTTP/1.1 {status:03d}\r\n")
        + sum(len(name) + 2 + len(value) + 2 for name, value in headers)
        + 2
    )


def synthetic_response(
    request, *, address=PUBLIC_IP, headers=None, body=b"x", **changes
):
    headers = headers or (("content-type", "text/html; charset=utf-8"),)
    values = {
        "request_url": request.url,
        "status_code": 200,
        "final_url": request.url,
        "headers": headers,
        "header_bytes": header_bytes(headers),
        "body": body,
        "connected_address": address,
        "connected_peer_preresolved": False,
        "tls_version": "TLSv1.3",
        "certificate_chain_verified": False,
        "hostname_verified": False,
    }
    values.update(changes)
    return EntraCallingClientRedirectEndpointResponse(**values)


def observation(hostname="app.engineer4me.invalid", addresses=(PUBLIC_IP,)):
    return EntraCallingClientRedirectEndpointDNSObservation(
        hostname=hostname,
        resolved_addresses=addresses,
    )


def test_exact_request_plan_contract_accepts_one_to_three_sorted_targets():
    for uris in ((URI,), (URI, URI_2)):
        plan = request_plan(uris)
        assert len(plan) == 10 * len(uris)
        assert [value.sequence for value in plan] == list(range(1, len(plan) + 1))
        assert [value.kind for value in plan[:2]] == ["baseline", "hostile_origin"]
        assert tuple(value.vector_name for value in plan[2:10]) == (
            FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "POST"),
        ("port", 444),
        ("port", 443.0),
        ("body", b"x"),
        ("follow_redirects", True),
        ("maximum_retries", 1),
        ("proxy_allowed", True),
        ("compression_allowed", True),
        ("total_timeout_seconds", 11.0),
        ("maximum_header_bytes", 1),
        ("maximum_body_bytes", 1),
        ("hostname", "evil.invalid"),
        ("url", "https://evil.invalid/"),
        ("kind", StrSubclass("baseline")),
        ("method", StrSubclass("GET")),
        ("redirect_uri", StrSubclass(URI)),
        ("hostname", StrSubclass("app.engineer4me.invalid")),
        ("url", StrSubclass(URI)),
        (
            "headers",
            TupleSubclass((("Accept", "text/html"), ("Accept-Encoding", "identity"))),
        ),
        (
            "headers",
            (
                (StrSubclass("Accept"), "text/html"),
                ("Accept-Encoding", "identity"),
            ),
        ),
    ],
)
def test_request_rejects_every_transport_widening(field, value):
    with pytest.raises(ValueError):
        replace(request_plan()[0], **{field: value})


def test_request_rejects_vector_name_string_subclass():
    with pytest.raises(ValueError):
        replace(
            request_plan()[2],
            vector_name=StrSubclass(
                FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES[0]
            ),
        )


@pytest.mark.parametrize(
    "uri",
    [
        "http://app.engineer4me.invalid/auth/callback",
        "https://app.engineer4me.invalid/",
        "https://app.engineer4me.invalid/a//b",
        "https://app.engineer4me.invalid/a/../b",
        "https://app.engineer4me.invalid/a%2fb",
        "https://xn--name.invalid/auth/callback",
        "https://app.engineer4me.invalid:443/auth/callback",
        "https://user@app.engineer4me.invalid/auth/callback",
        "https://app.engineer4me.invalid/auth/callback?q=1",
    ],
)
def test_request_rejects_noncanonical_step205_redirect_targets(uri):
    with pytest.raises(ValueError):
        replace(request_plan()[0], redirect_uri=uri)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "::ffff:8.8.8.8",
        "2606:4700:4700::ABCD",
        "2606:4700:4700:0:0:0:0:1111",
        "2606:4700:4700::1111%eth0",
    ],
)
def test_dns_observation_rejects_every_nonpublic_address_class(address):
    with pytest.raises(ValueError):
        observation(addresses=(address,))


def test_dns_observation_requires_unique_deterministic_packed_order_and_bounds():
    assert observation(addresses=(PUBLIC_IP, "2606:4700:4700::1111"))
    with pytest.raises(ValueError):
        observation(addresses=("2606:4700:4700::1111", PUBLIC_IP))
    with pytest.raises(ValueError):
        observation(addresses=(PUBLIC_IP, PUBLIC_IP))
    with pytest.raises(ValueError):
        observation(
            addresses=(
                "2606:4700:4700::1111",
                "2606:4700:4700:0:0:0:0:1111",
            )
        )
    with pytest.raises(ValueError):
        observation(addresses=tuple(f"8.8.8.{value}" for value in range(1, 10)))


def raw_entry(address, *, family=None, socktype=None, protocol=None, port=443, scope=0):
    family = family or (
        module._CAPTURED_AF_INET6 if ":" in address else module._CAPTURED_AF_INET
    )
    sockaddr = (
        (address, port, 0, scope)
        if family == module._CAPTURED_AF_INET6
        else (address, port)
    )
    return (
        family,
        module._CAPTURED_SOCK_STREAM if socktype is None else socktype,
        module._CAPTURED_IPPROTO_TCP if protocol is None else protocol,
        "",
        sockaddr,
    )


def resolve_from(raw):
    return module._resolve_internal(
        "app.engineer4me.invalid",
        443,
        _getaddrinfo=lambda *args, **kwargs: raw,
    )


def test_raw_dns_tuple_is_exact_and_ipv4_first_sorted():
    result = resolve_from(
        [
            raw_entry("2606:4700:4700::1111"),
            raw_entry(PUBLIC_IP_2),
            raw_entry(PUBLIC_IP),
        ]
    )
    assert result.resolved_addresses == (
        PUBLIC_IP,
        PUBLIC_IP_2,
        "2606:4700:4700::1111",
    )


def test_resolver_uses_one_exact_captured_getaddrinfo_call_shape():
    calls = []

    def getaddrinfo(*args, **kwargs):
        calls.append((args, kwargs))
        return [raw_entry(PUBLIC_IP)]

    result = module._resolve_internal(
        "app.engineer4me.invalid",
        443,
        _getaddrinfo=getaddrinfo,
    )
    assert result.resolved_addresses == (PUBLIC_IP,)
    assert calls == [
        (
            ("app.engineer4me.invalid", 443),
            {
                "family": module._CAPTURED_AF_UNSPEC,
                "type": module._CAPTURED_SOCK_STREAM,
                "proto": module._CAPTURED_IPPROTO_TCP,
            },
        )
    ]
    assert module._resolve_internal.__defaults__ == (module._CAPTURED_GETADDRINFO,)
    assert module._default_execute.__defaults__ == (
        module._CAPTURED_SOCKET,
        module._CAPTURED_SSL_CONTEXT,
        module._CAPTURED_MONOTONIC,
    )


@pytest.mark.parametrize(
    "raw",
    [
        [raw_entry(PUBLIC_IP, family=999)],
        [raw_entry(PUBLIC_IP, socktype=999)],
        [raw_entry(PUBLIC_IP, protocol=999)],
        [raw_entry(PUBLIC_IP, port=444)],
        [raw_entry("2606:4700:4700::1111", scope=2)],
        [raw_entry(PUBLIC_IP, family=module._CAPTURED_AF_INET6)],
    ],
)
def test_raw_dns_family_type_protocol_port_scope_and_version_must_match(raw):
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        resolve_from(raw)


@pytest.mark.parametrize(
    "raw",
    [
        (raw_entry(PUBLIC_IP),),
        [list(raw_entry(PUBLIC_IP))],
        [(module._CAPTURED_AF_INET, module._CAPTURED_SOCK_STREAM)],
        [
            (
                module._CAPTURED_AF_INET,
                module._CAPTURED_SOCK_STREAM,
                module._CAPTURED_IPPROTO_TCP,
                "",
                (b"8.8.8.8", 443),
            )
        ],
        [
            (
                module._CAPTURED_AF_INET,
                module._CAPTURED_SOCK_STREAM,
                module._CAPTURED_IPPROTO_TCP,
                "",
                (int.from_bytes(b"\x08\x08\x08\x08"), 443),
            )
        ],
        [raw_entry(PUBLIC_IP, family=True)],
        [raw_entry(PUBLIC_IP, socktype=True)],
        [raw_entry(PUBLIC_IP, protocol=True)],
        [raw_entry(PUBLIC_IP, port=True)],
        [raw_entry("2606:4700:4700::1111", scope=False)],
    ],
)
def test_raw_dns_requires_exact_container_address_and_integer_shapes(raw):
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        resolve_from(raw)


def test_raw_dns_caps_raw_and_unique_addresses():
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        resolve_from(
            [raw_entry(PUBLIC_IP)]
            * (ENTRA_REDIRECT_ENDPOINT_MAX_RAW_DNS_ADDRESSES_PER_HOST + 1)
        )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        resolve_from(
            [
                raw_entry(f"8.8.4.{index}")
                for index in range(
                    1, ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST + 2
                )
            ]
        )


def test_injected_loader_resolves_all_hosts_before_requests_and_once_per_host():
    events = []

    def resolver(hostname, port):
        events.append(("resolve", hostname, port))
        return observation(hostname)

    def executor(request, resolved):
        events.append(("execute", request.hostname, resolved.hostname))
        return synthetic_response(request)

    result = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=resolver,
        request_executor=executor,
    )(request_plan((URI, URI_2)))
    assert [event[0] for event in events[:2]] == ["resolve", "resolve"]
    assert [event[1] for event in events[:2]] == sorted(
        ["app.engineer4me.invalid", "portal.engineer4me.invalid"]
    )
    assert len([event for event in events if event[0] == "execute"]) == 20
    assert result.live_https_attested is False
    assert all(response.live_https_attested is False for response in result.responses)


def test_shared_hostname_resolves_once_and_second_address_is_never_accepted():
    second_uri = "https://app.engineer4me.invalid/auth/silent-callback"
    calls = []

    def resolver(hostname, port):
        calls.append((hostname, port))
        return observation(addresses=(PUBLIC_IP, PUBLIC_IP_2))

    def bad_executor(request, resolved):
        return synthetic_response(request, address=PUBLIC_IP_2)

    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=resolver,
        request_executor=bad_executor,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        loader(request_plan((URI, second_uri)))
    assert calls == [("app.engineer4me.invalid", 443)]
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        loader(request_plan((URI, second_uri)))


def test_any_rejected_plan_consumes_loader_before_dns():
    calls = []
    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=lambda *args: calls.append(args),
        request_executor=lambda *args: None,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        loader(request_plan()[:-1])
    assert calls == []
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        loader(request_plan())


@pytest.mark.parametrize(
    "headers",
    [
        (("Bad Name", "x"),),
        (("Content-Type", "x"),),
        (("x", " leading"),),
        (("x", "trailing "),),
        (("x", "a\r\nb"),),
        (("x", "\x7f"),),
        (("x", "é"),),
        (("x", "a"), ("x", "b")),
    ],
)
def test_public_response_rejects_non_live_header_forms(headers):
    with pytest.raises(ValueError):
        synthetic_response(request_plan()[0], headers=headers)


def test_public_response_header_bytes_are_exact_and_live_flags_unforgeable():
    request = request_plan()[0]
    response = synthetic_response(request)
    with pytest.raises(ValueError):
        synthetic_response(request, header_bytes=response.header_bytes + 1)
    for field in (
        "connected_peer_preresolved",
        "certificate_chain_verified",
        "hostname_verified",
    ):
        with pytest.raises(ValueError):
            synthetic_response(request, **{field: True})


def test_transport_result_revalidates_post_construction_observation_and_response_tamper():
    request = request_plan()[0]
    dns = observation()
    response = synthetic_response(request)
    result = EntraCallingClientRedirectEndpointTransportResult(
        dns_observations=(dns,),
        responses=tuple(synthetic_response(value) for value in request_plan()),
    )
    object.__setattr__(dns, "resolved_addresses", ("127.0.0.1",))
    with pytest.raises(ValueError):
        result.validate()
    object.__setattr__(dns, "resolved_addresses", (PUBLIC_IP,))
    response.body = bytearray(b"x")
    with pytest.raises(ValueError):
        response.validate()


def test_injected_dependencies_and_public_objects_never_confer_live_attestation():
    plan = request_plan()
    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=lambda hostname, port: observation(hostname),
        request_executor=lambda request, resolved: synthetic_response(request),
    )
    result = loader(plan)
    assert not result.live_https_attested
    assert not any(value.live_https_attested for value in result.responses)


@pytest.mark.parametrize("missing", ["resolver", "executor"])
def test_partial_dependency_injection_is_rejected_before_any_io(missing):
    calls = []

    def resolver(hostname, port):
        calls.append(("resolver", hostname, port))
        return observation(hostname)

    def executor(request, resolved):
        calls.append(("executor", request.url))
        return synthetic_response(request)

    kwargs = (
        {"resolver": None, "request_executor": executor}
        if missing == "resolver"
        else {"resolver": resolver, "request_executor": None}
    )
    with pytest.raises(TypeError):
        BoundedHTTPSEntraCallingClientRedirectEndpointLoader(**kwargs)
    assert calls == []


class FakeTLSSocket:
    def __init__(
        self,
        raw,
        *,
        peer=(PUBLIC_IP, 443),
        tls_version="TLSv1.3",
        alpn="http/1.1",
        certificate=None,
        close_failure=None,
        recv_failure=None,
    ):
        self.chunks = list(raw if isinstance(raw, list) else [raw])
        self.peer = peer
        self.tls_version = tls_version
        self.alpn = alpn
        self.certificate = (
            {"subject": "synthetic"} if certificate is None else certificate
        )
        self.close_failure = close_failure
        self.recv_failure = recv_failure
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.underlying = None

    def settimeout(self, value):
        self.timeouts.append(value)

    def getpeername(self):
        return self.peer

    def version(self):
        return self.tls_version

    def selected_alpn_protocol(self):
        return self.alpn

    def getpeercert(self):
        return self.certificate

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, amount):
        if self.recv_failure is not None:
            raise self.recv_failure
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        if len(value) <= amount:
            return value
        self.chunks.insert(0, value[amount:])
        return value[:amount]

    def close(self):
        self.closed = True
        if self.underlying is not None:
            self.underlying.closed = True
        if self.close_failure is not None:
            raise self.close_failure


class FakePlainSocket:
    def __init__(self, tls, *, peer=(PUBLIC_IP, 443)):
        self.tls = tls
        self.peer = peer
        self.timeouts = []
        self.connected = []
        self.factory_args = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, value):
        self.connected.append(value)

    def getpeername(self):
        return self.peer

    def close(self):
        self.closed = True


class FakeContext:
    def __init__(self, tls, *, keylog_filename=None):
        self.tls = tls
        self.loaded_purpose = None
        self.verify_mode = None
        self.check_hostname = None
        self.minimum_version = None
        self.keylog_filename = keylog_filename
        self.alpn_protocols = None
        self.server_hostname = None
        self.factory_protocols = []
        self.suppress_ragged_eofs = None

    def load_default_certs(self, purpose):
        self.loaded_purpose = purpose

    def set_alpn_protocols(self, values):
        self.alpn_protocols = values

    def wrap_socket(self, plain, *, server_hostname, suppress_ragged_eofs):
        self.server_hostname = server_hostname
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self.tls.underlying = plain
        return self.tls


def raw_response(*, status="200 OK", headers=("Content-Length: 1",), body=b"x"):
    head = f"HTTP/1.1 {status}\r\n" + "\r\n".join(headers) + "\r\n\r\n"
    return head.encode() + body


def execute_raw(
    raw=None,
    *,
    plain_peer=(PUBLIC_IP, 443),
    tls_peer=(PUBLIC_IP, 443),
    tls_version="TLSv1.3",
    alpn="http/1.1",
    certificate=None,
    keylog_filename=None,
    close_failure=None,
    recv_failure=None,
    clock=lambda: 0.0,
):
    tls = FakeTLSSocket(
        raw_response() if raw is None else raw,
        peer=tls_peer,
        tls_version=tls_version,
        alpn=alpn,
        certificate=certificate,
        close_failure=close_failure,
        recv_failure=recv_failure,
    )
    plain = FakePlainSocket(tls, peer=plain_peer)
    context = FakeContext(tls, keylog_filename=keylog_filename)

    def socket_factory(*args):
        plain.factory_args.append(args)
        return plain

    def context_factory(protocol):
        context.factory_protocols.append(protocol)
        return context

    result = module._default_execute(
        request_plan()[0],
        observation(),
        _socket_factory=socket_factory,
        _context_factory=context_factory,
        _clock=clock,
    )
    return result, plain, tls, context


@pytest.mark.parametrize("alpn", [None, "http/1.1"])
def test_default_execute_pins_peer_sni_host_trust_tls_and_exact_request(alpn):
    result, plain, tls, context = execute_raw(alpn=alpn)
    assert result.live_https_attested is False
    assert result.connected_address == PUBLIC_IP
    assert result.body == b"x"
    assert plain.factory_args == [
        (
            module._CAPTURED_AF_INET,
            module._CAPTURED_SOCK_STREAM,
            module._CAPTURED_IPPROTO_TCP,
        )
    ]
    assert plain.connected == [(PUBLIC_IP, 443)]
    assert context.loaded_purpose == module._CAPTURED_SERVER_AUTH
    assert context.verify_mode == module._CAPTURED_CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == module._CAPTURED_TLS_VERSION_1_2
    assert context.keylog_filename is None
    assert context.alpn_protocols == ["http/1.1"]
    assert context.server_hostname == "app.engineer4me.invalid"
    assert context.suppress_ragged_eofs is False
    assert context.factory_protocols == [module._CAPTURED_PROTOCOL_TLS_CLIENT]
    sent = tls.sent[0]
    assert sent == (
        b"GET /auth/callback HTTP/1.1\r\n"
        b"Host: app.engineer4me.invalid\r\n"
        b"Accept: text/html\r\n"
        b"Accept-Encoding: identity\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    assert plain.closed is True
    assert tls.closed is True
    assert all(0 < value <= 10.0 for value in plain.timeouts + tls.timeouts)


@pytest.mark.parametrize(
    "changes",
    [
        {"plain_peer": (PUBLIC_IP_2, 443)},
        {"plain_peer": (PUBLIC_IP, 444)},
        {"tls_peer": (PUBLIC_IP_2, 443)},
        {"tls_peer": (PUBLIC_IP, 444)},
        {"tls_version": "TLSv1.1"},
        {"tls_version": "unknown"},
        {"alpn": "h2"},
        {"certificate": {}},
    ],
)
def test_default_execute_rejects_peer_tls_alpn_and_certificate_widening(changes):
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(**changes)


def test_default_execute_rejects_preexisting_tls_keylog_destination():
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(keylog_filename="SECRET-ambient-keylog")


def test_default_execute_accepts_exact_header_count_cap_and_rejects_cap_plus_one():
    accepted = tuple(f"X-{index}: x" for index in range(99)) + ("Content-Length: 1",)
    result, _, _, _ = execute_raw(raw_response(headers=accepted))
    assert result.body == b"x"
    rejected = tuple(f"X-{index}: x" for index in range(100)) + ("Content-Length: 1",)
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(raw_response(headers=rejected))


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx",
        raw_response(status="100 Continue"),
        raw_response(status="302 Found"),
        b"HTTP/1.1 200 OK\nContent-Length: 1\n\nx",
        b"HTTP/1.1 200 OK\r\n folded: x\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nX: a\r\nX: b\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nx",
    ],
)
def test_default_execute_rejects_status_crlf_header_and_framing_ambiguity(raw):
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", b"x"),
        (b"HTTP/1.1 200 OK\r\n\r\nx", b"x"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"1\r\nx\r\n0\r\n\r\n",
            b"x",
        ),
    ],
)
def test_default_execute_accepts_content_length_close_and_strict_chunked(raw, expected):
    result, _, _, _ = execute_raw(raw)
    assert result.body == expected


def test_close_delimited_response_requires_clean_tls_eof_not_ragged_eof():
    raw = [
        b"HTTP/1.1 200 OK\r\n\r\nx",
        ssl.SSLEOFError("SECRET-RAGGED-TLS-EOF-215"),
    ]
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError) as caught:
        execute_raw(raw)
    assert "SECRET-RAGGED" not in exception_material(caught.value)


@pytest.mark.parametrize(
    "body",
    [
        b"1;x=y\r\nx\r\n0\r\n\r\n",
        b"1\r\nxX\r\n0\r\n\r\n",
        b"z\r\nx\r\n0\r\n\r\n",
        b"1\r\nx\r\n0\r\nTrailer: x\r\n\r\n",
        b"1\r\nx\r\n",
    ],
)
def test_default_execute_rejects_chunk_extension_size_data_trailer_and_truncation(body):
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(raw)


def test_default_execute_enforces_all_chunk_line_count_wire_decode_and_terminal_bounds():
    too_many_chunks = (
        b"1\r\nx\r\n" * (module.ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_COUNT + 1)
        + b"0\r\n\r\n"
    )
    cases = (
        b"0" * (module.ENTRA_REDIRECT_ENDPOINT_MAX_CHUNK_LINE_BYTES + 1) + b"\r\n\r\n",
        too_many_chunks,
        f"{FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES + 1:x}\r\n".encode(),
        b"0\r\n\r\nx",
    )
    for body in cases:
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
        with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
            execute_raw(raw)

    class UnusedConnection:
        def settimeout(self, value):
            raise AssertionError("wire cap must reject before receive")

    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        module._decode_chunked_body(
            connection=UnusedConnection(),
            initial=b"x" * (module.ENTRA_REDIRECT_ENDPOINT_MAX_CHUNKED_WIRE_BYTES + 1),
            deadline=10.0,
            maximum_body_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
            clock=lambda: 0.0,
        )


def test_default_execute_rejects_close_delimited_overflow_nonbytes_and_cl_extra():
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(
            b"HTTP/1.1 200 OK\r\n\r\n"
            + b"x" * (FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES + 1)
        )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw("not-socket-bytes")
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(raw_response(headers=("Content-Length: 1",), body=b"xx"))


def test_default_execute_enforces_header_body_and_remaining_time_bounds():
    oversized_headers = (
        b"HTTP/1.1 200 OK\r\nX: "
        + b"a" * FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
        + b"\r\n\r\n"
    )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(oversized_headers)
    oversized_body = raw_response(
        headers=(f"Content-Length: {FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES + 1}",),
        body=b"",
    )
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(oversized_body)
    ticks = iter((0.0, 11.0))
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(clock=lambda: next(ticks))


def test_default_execute_uses_one_decreasing_deadline_across_network_operations():
    ticks = iter((100.0, 101.0, 102.0, 103.0, 104.0))
    _, plain, tls, _ = execute_raw(clock=lambda: next(ticks))
    assert plain.timeouts + tls.timeouts == [9.0, 8.0, 7.0, 6.0]


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit()])
def test_default_execute_preserves_interruption_or_termination_during_close(failure):
    with pytest.raises(type(failure)) as caught:
        execute_raw(close_failure=failure)
    assert caught.value.args == (
        "redirect endpoint HTTPS request interrupted",
    ) or caught.value.args == ("redirect endpoint HTTPS request terminated",)


def exception_material(error):
    pending = [error]
    seen = set()
    values = []

    def visit(value):
        if id(value) in seen:
            return
        seen.add(id(value))
        if isinstance(value, (str, bytes, bytearray, int, float, bool, type(None))):
            values.append(repr(value))
            return
        if isinstance(value, dict):
            for key, item in value.items():
                visit(key)
                visit(item)
            return
        if isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                visit(item)
            return
        closure = getattr(value, "__closure__", None)
        if closure:
            for cell in closure:
                try:
                    visit(cell.cell_contents)
                except ValueError:
                    pass
        try:
            namespace = object.__getattribute__(value, "__dict__")
        except (AttributeError, TypeError):
            namespace = None
        if isinstance(namespace, dict):
            visit(namespace)

    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.extend(str(value) for value in current.args)
        for linked in (current.__cause__, current.__context__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        for child in getattr(current, "exceptions", ()):
            if isinstance(child, BaseException):
                pending.append(child)
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                for value in traceback.tb_frame.f_locals.values():
                    visit(value)
            traceback = traceback.tb_next
    return "\n".join(values)


def test_default_execute_detaches_raw_uri_host_ip_header_body_and_nested_failure():
    secret = "SECRET-RAW-BODY-215"
    failure = RuntimeError(secret, URI, PUBLIC_IP, b"Authorization: secret")
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError) as caught:
        execute_raw(recv_failure=failure)
    material = exception_material(caught.value)
    for value in (secret, URI, "app.engineer4me.invalid", PUBLIC_IP, "Authorization"):
        assert value not in material


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_default_execute_scrubs_raising_clock_and_dependency_closure(failure):
    secret = "SECRET-CLOCK-CLOSURE-215"

    def broken_clock():
        raise failure(secret, URI, PUBLIC_IP)

    expected = (
        EntraCallingClientRedirectEndpointHTTPError
        if failure is RuntimeError
        else failure
    )
    with pytest.raises(expected) as caught:
        execute_raw(clock=broken_clock)
    material = exception_material(caught.value)
    for value in (secret, URI, "app.engineer4me.invalid", PUBLIC_IP):
        assert value not in material


def test_default_execute_sanitizes_noncallable_clock_and_mutated_inputs():
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        execute_raw(clock=None)

    request = request_plan()[0]
    object.__setattr__(request, "hostname", "SECRET-MUTATED-HOST.invalid")
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError) as caught:
        module._default_execute(
            request,
            observation(),
            _socket_factory=lambda *args: None,
            _context_factory=lambda protocol: None,
            _clock=lambda: 0.0,
        )
    assert "SECRET-MUTATED-HOST" not in exception_material(caught.value)


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_default_resolver_preserves_control_flow_and_scrubs_dependency(failure_type):
    secret = "SECRET-RESOLVER-DEPENDENCY-215"
    original = failure_type(secret, URI, PUBLIC_IP)

    def broken(hostname, port):
        raise original

    expected = (
        EntraCallingClientRedirectEndpointHTTPError
        if failure_type is RuntimeError
        else failure_type
    )
    with pytest.raises(expected) as caught:
        module._default_resolve(
            "app.engineer4me.invalid",
            443,
            _internal=broken,
        )
    assert original.args == ()
    assert original.__traceback__ is None
    assert original.__cause__ is None
    assert original.__context__ is None
    for value in (secret, URI, PUBLIC_IP):
        assert value not in exception_material(caught.value)


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_injected_loader_preserves_control_flow_and_scrubs_dependency(failure_type):
    secret = "SECRET-LOADER-DEPENDENCY-215"
    original = failure_type(secret, URI, PUBLIC_IP)

    def broken(hostname, port):
        raise original

    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=broken,
        request_executor=lambda request, resolved: synthetic_response(request),
    )
    expected = (
        EntraCallingClientRedirectEndpointHTTPError
        if failure_type is RuntimeError
        else failure_type
    )
    with pytest.raises(expected) as caught:
        loader(request_plan())
    assert original.args == ()
    assert original.__traceback__ is None
    assert original.__cause__ is None
    assert original.__context__ is None
    for value in (secret, URI, PUBLIC_IP):
        assert value not in exception_material(caught.value)


def test_exception_group_children_notes_and_custom_attributes_are_scrubbed():
    secret = "SECRET-EXCEPTION-GROUP-CHILD-215"
    child = ValueError(secret, URI, PUBLIC_IP)
    child.add_note(secret)
    child.private_evidence = secret
    group = builtins.ExceptionGroup(secret, [child])

    def broken(hostname, port):
        raise group

    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        module._default_resolve(
            "app.engineer4me.invalid",
            443,
            _internal=broken,
        )
    for error in (group, child):
        assert error.args == ()
        assert error.__traceback__ is None
        assert error.__cause__ is None
        assert error.__context__ is None
        assert error.__dict__ == {}


def test_exception_scrub_bypasses_hostile_custom_attribute_getter():
    secret = "SECRET-HOSTILE-EXCEPTION-GETTER-215"

    class HostileError(RuntimeError):
        def __getattribute__(self, name):
            if name in {
                "__cause__",
                "__context__",
                "exceptions",
                "__notes__",
                "__dict__",
            }:
                raise RuntimeError(secret)
            return super().__getattribute__(name)

    original = HostileError(secret, URI, PUBLIC_IP)

    def broken(hostname, port):
        raise original

    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError) as caught:
        module._default_resolve(
            "app.engineer4me.invalid",
            443,
            _internal=broken,
        )
    assert BaseException.__getattribute__(original, "args") == ()
    assert BaseException.__getattribute__(original, "__traceback__") is None
    assert BaseException.__getattribute__(original, "__dict__") == {}
    for value in (secret, URI, PUBLIC_IP):
        assert value not in exception_material(caught.value)


def test_constructor_and_consumed_errors_detach_injected_dependency_closures():
    secret = "SECRET-CONSTRUCTOR-DEPENDENCY-215"

    def resolver(hostname, port):
        assert secret
        return observation(hostname)

    def executor(request, resolved):
        assert secret
        return synthetic_response(request)

    for kwargs in (
        {"resolver": resolver, "request_executor": None},
        {"resolver": None, "request_executor": executor},
        {"resolver": object(), "request_executor": executor},
    ):
        with pytest.raises(TypeError) as caught:
            BoundedHTTPSEntraCallingClientRedirectEndpointLoader(**kwargs)
        assert secret not in exception_material(caught.value)

    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=resolver,
        request_executor=executor,
    )
    loader(request_plan())
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError) as caught:
        loader(request_plan())
    assert secret not in exception_material(caught.value)


def test_close_before_use_clears_dependencies_and_seals_loader():
    loader = BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
        resolver=lambda hostname, port: observation(hostname),
        request_executor=lambda request, resolved: synthetic_response(request),
    )
    loader.close()
    assert loader._resolver is None
    assert loader._request_executor is None
    assert loader._default_transport is False
    with pytest.raises(EntraCallingClientRedirectEndpointHTTPError):
        loader(request_plan())


def grouped_control_flow(secret, kinds):
    children = [
        KeyboardInterrupt(secret) if kind == "keyboard" else SystemExit(secret)
        for kind in kinds
    ]
    return builtins.BaseExceptionGroup(secret, children), children


@pytest.mark.parametrize(
    ("kinds", "expected"),
    [
        (("keyboard",), KeyboardInterrupt),
        (("system",), SystemExit),
        (("system", "keyboard"), KeyboardInterrupt),
    ],
)
def test_nested_control_flow_is_preserved_across_resolver_executor_loader_and_close(
    kinds,
    expected,
):
    secret = "SECRET-NESTED-CONTROL-FLOW-215"

    def invoke_resolver(group):
        def broken(hostname, port):
            raise group

        module._default_resolve(
            "app.engineer4me.invalid",
            443,
            _internal=broken,
        )

    def invoke_executor(group):
        execute_raw(recv_failure=group)

    def invoke_loader(group):
        def broken(hostname, port):
            raise group

        BoundedHTTPSEntraCallingClientRedirectEndpointLoader(
            resolver=broken,
            request_executor=lambda request, resolved: synthetic_response(request),
        )(request_plan())

    def invoke_close(group):
        execute_raw(close_failure=group)

    for invoke in (invoke_resolver, invoke_executor, invoke_loader, invoke_close):
        group, children = grouped_control_flow(secret, kinds)
        with pytest.raises(expected) as caught:
            invoke(group)
        for value in (secret, URI, PUBLIC_IP):
            assert value not in exception_material(caught.value)
        for child in children:
            assert child.args == ()
            assert child.__traceback__ is None
