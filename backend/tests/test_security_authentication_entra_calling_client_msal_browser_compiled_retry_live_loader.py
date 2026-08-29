"""Tests for the bounded Step 223 npm HTTPS loader."""

from __future__ import annotations

import inspect
from builtins import BaseExceptionGroup
from dataclasses import replace

import pytest

import app.security.authentication_entra_calling_client_msal_browser_compiled_retry_live_loader as module
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_live_loader import (
    BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader,
    EntraCallingClientMSALCompiledRetryLiveHTTPError,
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
    build_entra_calling_client_msal_compiled_retry_live_request_plan,
)


def response(request, *, live=False, **changes):
    values = {
        "request": request,
        "status_code": 200,
        "content_type": (
            "application/json"
            if request.resource.endswith("metadata")
            else "application/octet-stream"
        ),
        "body": b"x",
        "final_url": request.url,
        "header_bytes": 32,
        "content_length": 1,
        "live_https_attested": live,
        "tls_certificate_chain_checked": live,
        "tls_hostname_checked": live,
        "proxy_bypassed": live,
        "redirects_rejected": live,
        "retries_disabled": live,
        "response_source_authenticity_checked": live,
    }
    values.update(changes)
    return EntraCallingClientMSALCompiledRetryLiveHTTPResponse(**values)


def synthetic_transport(requests):
    return tuple(response(request) for request in requests)


class FakeHeaders:
    def __init__(self, values):
        self.values = values

    def items(self):
        return list(self.values)

    def get_all(self, name, default=None):
        found = [value for key, value in self.values if key.lower() == name.lower()]
        return found or ([] if default is None else default)

    def get(self, name, default=None):
        found = self.get_all(name, [])
        return found[0] if found else default


class FakeRawResponse:
    def __init__(self, request, body=b"x", extra_headers=(), final_url=None):
        media = (
            "application/json"
            if request.resource.endswith("metadata")
            else "application/octet-stream"
        )
        self.request = request
        self.body = body
        self.headers = FakeHeaders(
            [
                ("Content-Type", media),
                ("Content-Length", str(len(body))),
                *extra_headers,
            ]
        )
        self.final_url = request.url if final_url is None else final_url
        self.closed = False

    def read(self, limit):
        assert limit in (module.MAX_METADATA_BYTES + 1, module.MAX_TARBALL_BYTES + 1)
        return self.body

    def getcode(self):
        return 200

    def geturl(self):
        return self.final_url

    def close(self):
        self.closed = True


def exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(item) for item in current.args)))
        pending.extend(
            item
            for item in (current.__context__, current.__cause__)
            if isinstance(item, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(
                    repr(item) for item in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(material)


def test_exact_request_plan_is_fixed_ordered_get_only_and_credential_free():
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    assert type(plan) is tuple
    assert [request.sequence for request in plan] == [1, 2, 3, 4]
    assert [request.resource for request in plan] == [
        "browser_metadata",
        "browser_tarball",
        "common_metadata",
        "common_tarball",
    ]
    assert [request.url for request in plan] == [
        module.BROWSER_METADATA_URL,
        module.BROWSER_TARBALL_URL,
        module.COMMON_METADATA_URL,
        module.COMMON_TARBALL_URL,
    ]
    assert all(request.method == "GET" for request in plan)
    assert all(request.accept_encoding == "identity" for request in plan)
    assert all(request.connection == "close" for request in plan)
    assert all(request.user_agent == "Engineer4Me-Step223/1" for request in plan)
    assert all(request.authorization is None for request in plan)
    assert all(request.body is None for request in plan)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("sequence", True),
        ("sequence", 5),
        ("resource", "other"),
        ("method", "POST"),
        ("url", "https://example.invalid"),
        ("accept", "*/*"),
        ("accept_encoding", "gzip"),
        ("connection", "keep-alive"),
        ("user_agent", "other"),
        ("authorization", "Bearer secret"),
        ("body", b"x"),
    ],
)
def test_request_contract_rejects_every_changed_surface(field, invalid):
    request = build_entra_calling_client_msal_compiled_retry_live_request_plan()[0]
    with pytest.raises(ValueError):
        replace(request, **{field: invalid})


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("status_code", True),
        ("status_code", 201),
        ("content_type", "text/html"),
        ("body", bytearray(b"x")),
        ("body", b""),
        ("final_url", "https://example.invalid"),
        ("header_bytes", True),
        ("header_bytes", 0),
        ("content_length", True),
        ("content_length", 2),
    ],
)
def test_response_contract_rejects_invalid_scalar_and_boundaries(field, invalid):
    request = build_entra_calling_client_msal_compiled_retry_live_request_plan()[0]
    with pytest.raises(ValueError):
        response(request, **{field: invalid})


def test_response_provenance_is_all_live_or_all_synthetic():
    request = build_entra_calling_client_msal_compiled_retry_live_request_plan()[0]
    live = response(request, live=True)
    synthetic = response(request)
    assert live.live_https_attested is True
    assert synthetic.live_https_attested is False
    with pytest.raises(ValueError):
        replace(live, tls_hostname_checked=False)


def test_injected_transport_is_synthetic_and_loader_is_one_shot():
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    loader = BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(
        synthetic_transport
    )
    responses = loader.load(plan)
    assert len(responses) == 4
    assert all(not item.live_https_attested for item in responses)
    with pytest.raises(EntraCallingClientMSALCompiledRetryLiveHTTPError):
        loader.load(plan)


def test_sealed_raw_transport_uses_exact_tls_opener_headers_and_bounds(monkeypatch):
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    raw_responses = [FakeRawResponse(request) for request in plan]
    opened = []
    captured_handlers = []

    class Context:
        minimum_version = None
        check_hostname = False
        verify_mode = None

        def load_default_certs(self):
            self.default_certs_loaded = True

    context = Context()

    class Opener:
        def open(self, request, timeout):
            index = len(opened)
            opened.append((request, timeout))
            return raw_responses[index]

    def context_factory(protocol):
        assert protocol == module.ssl.PROTOCOL_TLS_CLIENT
        return context

    def opener_factory(*handlers):
        captured_handlers.extend(handlers)
        return Opener()

    monkeypatch.setattr(module.ssl, "SSLContext", context_factory)
    monkeypatch.setattr(module, "build_opener", opener_factory)
    responses = module._sealed_transport(plan)
    assert len(responses) == 4
    assert all(item.live_https_attested for item in responses)
    assert context.minimum_version == module.ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is True
    assert context.verify_mode == module.ssl.CERT_REQUIRED
    assert context.default_certs_loaded is True
    assert any(type(handler) is module.ProxyHandler for handler in captured_handlers)
    assert any(type(handler) is module.HTTPSHandler for handler in captured_handlers)
    assert any(
        type(handler) is module._NoRedirectHandler for handler in captured_handlers
    )
    assert [request.full_url for request, _timeout in opened] == [
        item.url for item in plan
    ]
    assert all(request.get_method() == "GET" for request, _timeout in opened)
    assert all(timeout == module.HTTP_TIMEOUT_SECONDS for _request, timeout in opened)
    for (request, _timeout), expected in zip(opened, plan, strict=True):
        headers = {name.lower(): value for name, value in request.header_items()}
        assert headers == {
            "accept": expected.accept,
            "accept-encoding": expected.accept_encoding,
            "connection": expected.connection,
            "user-agent": expected.user_agent,
        }
    assert all(item.closed for item in raw_responses)


@pytest.mark.parametrize(
    "change",
    [
        {"extra_headers": (("Content-Encoding", "gzip"),)},
        {"extra_headers": (("Content-Length", "1"),)},
        {"final_url": "https://example.invalid"},
        {"body": b""},
    ],
)
def test_sealed_raw_transport_fails_closed_on_response_changes(monkeypatch, change):
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    values = [FakeRawResponse(request) for request in plan]
    values[0] = FakeRawResponse(plan[0], **change)

    class Context:
        minimum_version = None
        check_hostname = False
        verify_mode = None

        def load_default_certs(self):
            pass

    class Opener:
        index = 0

        def open(self, _request, timeout):
            assert timeout == module.HTTP_TIMEOUT_SECONDS
            result = values[self.index]
            self.index += 1
            return result

    monkeypatch.setattr(module.ssl, "SSLContext", lambda _protocol: Context())
    monkeypatch.setattr(module, "build_opener", lambda *_handlers: Opener())
    with pytest.raises((ValueError, EntraCallingClientMSALCompiledRetryLiveHTTPError)):
        module._sealed_transport(plan)


def test_injected_transport_cannot_claim_live_attestation():
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()

    def forged(requests):
        return tuple(response(request, live=True) for request in requests)

    with pytest.raises(EntraCallingClientMSALCompiledRetryLiveHTTPError):
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(forged).load(plan)


@pytest.mark.parametrize("requests", [None, [], (), (object(),) * 4])
def test_invalid_plan_types_are_sanitized_type_errors(requests):
    with pytest.raises(TypeError) as caught:
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(
            synthetic_transport
        ).load(requests)
    assert caught.value.__context__ is None


def test_swapped_request_order_fails_before_transport():
    calls = []
    plan = list(build_entra_calling_client_msal_compiled_retry_live_request_plan())
    plan[0], plan[1] = plan[1], plan[0]

    def transport(requests):
        calls.append(requests)
        return ()

    with pytest.raises(EntraCallingClientMSALCompiledRetryLiveHTTPError):
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(transport).load(
            tuple(plan)
        )
    assert calls == []


def test_response_order_and_exact_tuple_are_required():
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()

    def swapped(requests):
        values = [response(request) for request in requests]
        values[0], values[1] = values[1], values[0]
        return tuple(values)

    with pytest.raises(EntraCallingClientMSALCompiledRetryLiveHTTPError):
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(swapped).load(plan)


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_control_flow_is_sanitized_and_preserved(control):
    secret = "loader-control-secret"

    def fail(_requests):
        raise BaseExceptionGroup("secret-group", [control(secret)])

    with pytest.raises(control) as caught:
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(fail).load(
            build_entra_calling_client_msal_compiled_retry_live_request_plan()
        )
    assert secret not in exception_material(caught.value)


def test_generic_exception_graph_is_detached_and_secret_free():
    secret = "loader-generic-secret"

    def fail(_requests):
        raise BaseExceptionGroup("secret-group", [ValueError(secret)])

    with pytest.raises(EntraCallingClientMSALCompiledRetryLiveHTTPError) as caught:
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(fail).load(
            build_entra_calling_client_msal_compiled_retry_live_request_plan()
        )
    assert secret not in exception_material(caught.value)


def test_noncallable_transport_is_a_fresh_type_error():
    with pytest.raises(TypeError) as caught:
        BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader(object())
    assert caught.value.__context__ is None


def test_source_has_fixed_global_registry_controls_and_no_mutation_method():
    source = inspect.getsource(module)
    assert module.NPM_REGISTRY_ORIGIN == "https://registry.npmjs.org"
    assert "ProxyHandler({})" in source
    assert "ssl.PROTOCOL_TLS_CLIENT" in source
    assert "ssl.TLSVersion.TLSv1_2" in source
    assert '"Accept-Encoding": request_plan.accept_encoding' in source
    assert '"Connection": request_plan.connection' in source
    assert '"User-Agent": request_plan.user_agent' in source
    assert "POST" not in source
    assert "PUT" not in source
    assert "PATCH" not in source
    assert "DELETE" not in source


def test_public_exports_are_exact_and_unique():
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
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
    }
