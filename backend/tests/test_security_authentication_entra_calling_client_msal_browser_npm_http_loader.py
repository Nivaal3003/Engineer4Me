"""Tests for the bounded MSAL Browser npm registry transport."""

from __future__ import annotations

import inspect
import ssl
from dataclasses import fields
from email.message import Message

import pytest

import app.security.authentication_entra_calling_client_msal_browser_npm_http_loader as module
from app.security.authentication_entra_calling_client_msal_browser_npm_http_loader import (
    MSAL_BROWSER_NPM_PACKAGE_NAME,
    MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION,
    MSAL_BROWSER_NPM_REVIEWED_VERSION,
    NPM_DIST_TAGS_URL,
    NPM_MAX_DIST_TAGS_BYTES,
    NPM_MAX_RESPONSE_HEADER_BYTES,
    NPM_MAX_TARBALL_BYTES,
    NPM_MAX_VERSION_METADATA_BYTES,
    NPM_REGISTRY_ORIGIN,
    NPM_TARBALL_URL,
    NPM_VERSION_METADATA_URL,
    BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader,
    EntraCallingClientMSALBrowserNpmHTTPError,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    build_entra_calling_client_msal_browser_npm_request_plan,
)


def response(request, body=b"{}", *, live=False, **changes):
    values = {
        "request": request,
        "status_code": 200,
        "content_type": (
            "application/octet-stream"
            if request.resource == "tarball"
            else "application/json; charset=utf-8"
        ),
        "body": body,
        "final_url": request.url,
        "header_bytes": 80,
        "content_length": len(body),
        "live_https_attested": live,
        "tls_certificate_chain_checked": live,
        "tls_hostname_checked": live,
        "proxy_bypassed": live,
        "redirects_rejected": live,
        "retries_disabled": live,
        "response_source_authenticity_checked": live,
    }
    values.update(changes)
    return EntraCallingClientMSALBrowserNpmHTTPResponse(**values)


def responses(plan=None, *, live=False):
    plan = plan or build_entra_calling_client_msal_browser_npm_request_plan()
    return tuple(response(request, live=live) for request in plan)


def unsafe_replace(instance, **changes):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(instance, field.name))
        )
    return clone


def production_exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(value) for value in current.args)))
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(
                    repr(value) for value in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(material)


def test_public_constants_and_exact_request_plan():
    plan = build_entra_calling_client_msal_browser_npm_request_plan()
    assert MSAL_BROWSER_NPM_PACKAGE_NAME == "@azure/msal-browser"
    assert MSAL_BROWSER_NPM_REVIEWED_VERSION == "5.17.3"
    assert MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION == "5.18.0"
    assert NPM_REGISTRY_ORIGIN == "https://registry.npmjs.org"
    assert tuple(request.sequence for request in plan) == (1, 2, 3)
    assert tuple(request.resource for request in plan) == (
        "dist_tags",
        "version_metadata",
        "tarball",
    )
    assert tuple(request.url for request in plan) == (
        NPM_DIST_TAGS_URL,
        NPM_VERSION_METADATA_URL,
        NPM_TARBALL_URL,
    )
    assert all(request.method == "GET" for request in plan)
    assert all(request.accept_encoding == "identity" for request in plan)
    assert all(request.body is None for request in plan)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("sequence", True),
        ("sequence", 2),
        ("resource", "tarball"),
        ("method", "POST"),
        ("url", "https://example.invalid"),
        ("accept", "*/*"),
        ("accept_encoding", "gzip"),
        ("body", b"x"),
    ],
)
def test_request_objects_revalidate_every_field(field, invalid):
    request = build_entra_calling_client_msal_browser_npm_request_plan()[0]
    tampered = unsafe_replace(request, **{field: invalid})
    with pytest.raises(ValueError, match="request contract"):
        tampered.__post_init__()


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("status_code", True),
        ("status_code", 302),
        ("content_type", "text/html"),
        ("content_type", " application/json"),
        ("content_type", "application/json; charset=latin1"),
        ("body", bytearray(b"{}")),
        ("body", b""),
        ("final_url", "https://example.invalid"),
        ("header_bytes", True),
        ("header_bytes", 0),
        ("header_bytes", NPM_MAX_RESPONSE_HEADER_BYTES + 1),
        ("content_length", True),
        ("content_length", 3),
        ("live_https_attested", True),
    ],
)
def test_response_objects_revalidate_every_boundary(field, invalid):
    valid = responses()[0]
    tampered = unsafe_replace(valid, **{field: invalid})
    with pytest.raises(ValueError):
        tampered.__post_init__()


def test_each_response_body_limit_is_exact():
    plan = build_entra_calling_client_msal_browser_npm_request_plan()
    for request, limit in zip(
        plan,
        (
            NPM_MAX_DIST_TAGS_BYTES,
            NPM_MAX_VERSION_METADATA_BYTES,
            NPM_MAX_TARBALL_BYTES,
        ),
        strict=True,
    ):
        response(request, b"x" * limit)
        with pytest.raises(ValueError):
            response(request, b"x" * (limit + 1))


def test_injected_transport_is_one_shot_and_never_live():
    plan = build_entra_calling_client_msal_browser_npm_request_plan()
    calls = []

    def executor(requests_value):
        calls.append(requests_value)
        return responses(requests_value)

    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader(executor=executor)
    assert loader(plan) == responses(plan)
    assert calls == [plan]
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError, match="consumed"):
        loader(plan)
    assert calls == [plan]


@pytest.mark.parametrize(
    "invalid",
    [None, [], (), (object(), object(), object())],
)
def test_invalid_plan_consumes_before_zero_io(invalid):
    calls = []
    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader(
        executor=lambda value: calls.append(value)
    )
    with pytest.raises(TypeError):
        loader(invalid)
    assert calls == []
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError, match="consumed"):
        loader(build_entra_calling_client_msal_browser_npm_request_plan())


def test_tampered_second_request_fails_before_zero_io():
    plan = list(build_entra_calling_client_msal_browser_npm_request_plan())
    plan[1] = unsafe_replace(plan[1], url="https://example.invalid")
    calls = []
    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader(
        executor=lambda value: calls.append(value)
    )
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError):
        loader(tuple(plan))
    assert calls == []


def test_injected_transport_cannot_claim_live_attestation():
    plan = build_entra_calling_client_msal_browser_npm_request_plan()
    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader(
        executor=lambda value: responses(value, live=True)
    )
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError):
        loader(plan)


@pytest.mark.parametrize(
    "failure", [ValueError("secret"), KeyboardInterrupt("secret"), SystemExit("secret")]
)
def test_transport_failures_are_sanitized_and_consume(failure):
    plan = build_entra_calling_client_msal_browser_npm_request_plan()

    def executor(_requests):
        raise failure

    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader(executor=executor)
    expected = (
        type(failure)
        if isinstance(failure, (KeyboardInterrupt, SystemExit))
        else EntraCallingClientMSALBrowserNpmHTTPError
    )
    with pytest.raises(expected) as caught:
        loader(plan)
    assert "secret" not in production_exception_material(caught.value)
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError, match="consumed"):
        loader(plan)


class FakeRawResponse:
    def __init__(
        self, request, body=b"{}", *, headers=None, status=200, final_url=None
    ):
        self._request = request
        self._body = body
        self._status = status
        self._final_url = final_url or request.full_url
        self.headers = headers or self._headers(body)
        self.closed = False

    @staticmethod
    def _headers(body):
        headers = Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
        return headers

    def getcode(self):
        return self._status

    def geturl(self):
        return self._final_url

    def read(self, maximum):
        assert maximum > len(self._body)
        return self._body

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, captured, **changes):
        self.captured = captured
        self.changes = changes

    def open(self, request, timeout):
        self.captured.append((request, timeout))
        body = self.changes.get(
            "body", b"artifact" if request.full_url == NPM_TARBALL_URL else b"{}"
        )
        headers = self.changes.get("headers")
        if headers is None:
            headers = Message()
            headers["Content-Type"] = (
                "application/octet-stream"
                if request.full_url == NPM_TARBALL_URL
                else "application/json"
            )
            headers["Content-Length"] = str(len(body))
        return FakeRawResponse(
            request,
            body,
            headers=headers,
            status=self.changes.get("status", 200),
            final_url=self.changes.get("final_url"),
        )


def test_injected_raw_opener_exercises_wire_request_but_is_synthetic():
    captured = []
    result = module._execute_with_opener_factory(
        build_entra_calling_client_msal_browser_npm_request_plan(),
        opener_factory=lambda: FakeOpener(captured),
    )
    assert len(captured) == 3
    assert all(
        request.method == "GET" and request.data is None for request, _ in captured
    )
    assert all(timeout == 10 for _, timeout in captured)
    for request, _ in captured:
        headers = {key.lower(): value for key, value in request.header_items()}
        assert headers["accept-encoding"] == "identity"
        assert headers["connection"] == "close"
        assert "authorization" not in headers
        assert "cookie" not in headers
        assert "user-agent" not in headers
    assert all(not item.live_https_attested for item in result)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": 302},
        {"final_url": "https://example.invalid"},
        {"body": b""},
    ],
)
def test_raw_opener_rejects_status_redirect_and_empty_body(changes):
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError):
        module._execute_with_opener_factory(
            build_entra_calling_client_msal_browser_npm_request_plan(),
            opener_factory=lambda: FakeOpener([], **changes),
        )


@pytest.mark.parametrize("name", ["Content-Encoding", "Location", "Set-Cookie"])
def test_raw_opener_rejects_forbidden_response_headers(name):
    headers = Message()
    headers["Content-Type"] = "application/json"
    headers[name] = "x"
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError):
        module._execute_with_opener_factory(
            build_entra_calling_client_msal_browser_npm_request_plan(),
            opener_factory=lambda: FakeOpener([], headers=headers),
        )


@pytest.mark.parametrize("name", ["Content-Type", "Content-Length"])
def test_raw_opener_rejects_duplicate_singleton_headers(name):
    headers = Message()
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = "2"
    headers[name] = "application/json" if name == "Content-Type" else "2"
    with pytest.raises(EntraCallingClientMSALBrowserNpmHTTPError):
        module._execute_with_opener_factory(
            build_entra_calling_client_msal_browser_npm_request_plan(),
            opener_factory=lambda: FakeOpener([], headers=headers),
        )


def test_sealed_opener_source_declares_tls_proxy_and_redirect_controls():
    source = inspect.getsource(module._build_sealed_opener)
    assert "ssl.PROTOCOL_TLS_CLIENT" in source
    assert "ssl.TLSVersion.TLSv1_2" in source
    assert "ssl.CERT_REQUIRED" in source
    assert "check_hostname = True" in source
    assert "keylog_filename = None" in source
    assert "ProxyHandler({})" in source
    assert "_NoRedirectHandler()" in source
    assert ssl.PROTOCOL_TLS_CLIENT is not None


def test_loader_public_surface_is_pairless_one_shot_only():
    source = inspect.getsource(BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader)
    assert "def __call__" in source
    assert "self._consumed = True" in source
    assert "def execute_one" not in source
    assert "def get(" not in source
