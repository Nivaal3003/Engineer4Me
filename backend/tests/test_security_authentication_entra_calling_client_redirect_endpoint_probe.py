"""Tests for the controlled SPA redirect-endpoint security proof."""

from __future__ import annotations

import builtins
import hashlib
import json
import socket
import ssl
import urllib.request
from dataclasses import fields, replace

import pytest
from test_security_authentication_entra_calling_client_redirect_endpoint_readiness import (
    values as readiness_values,
)
from test_security_authentication_entra_calling_client_registration_probe import (
    CALLING_CLIENT_APPLICATION_ID,
    CALLING_CLIENT_OBJECT_ID,
    authorization,
    prerequisites,
)
from test_security_authentication_entra_calling_client_registration_probe import (
    SyntheticTransport as RegistrationTransport,
)

import app.security.authentication_entra_calling_client_redirect_endpoint_probe as module
from app.security.authentication_entra_calling_client_redirect_endpoint_http_loader import (
    EntraCallingClientRedirectEndpointDNSObservation,
    EntraCallingClientRedirectEndpointResponse,
    EntraCallingClientRedirectEndpointTransportResult,
)
from app.security.authentication_entra_calling_client_redirect_endpoint_probe import (
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE,
    EntraCallingClientRedirectEndpointProbeError,
    render_entra_calling_client_redirect_endpoint_probe_receipt,
    validate_entra_calling_client_redirect_endpoint_probe,
)

PUBLIC_IP = "8.8.8.8"
PUBLIC_IP_2 = "9.9.9.9"
CALLBACK_BODY = (
    b'<!doctype html><html><head><script src="/callback.js"></script>'
    b'</head><body><a href="/">Home</a></body></html>'
)
EXACT_CSP = (
    "default-src 'self'; script-src 'self'; base-uri 'none'; "
    "object-src 'none'; frame-ancestors 'none'; form-action 'none'"
)


def good_headers(**replacements):
    values = {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "referrer-policy": "no-referrer",
        "cache-control": "private, no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy": EXACT_CSP,
    }
    values.update(replacements)
    return tuple(values.items())


def normalized_header_bytes(headers, status=200):
    return (
        len(f"HTTP/1.1 {status:03d}\r\n")
        + sum(len(name) + 2 + len(value) + 2 for name, value in headers)
        + 2
    )


def response(
    request, *, headers=None, body=CALLBACK_BODY, address=PUBLIC_IP, **changes
):
    headers = good_headers() if headers is None else headers
    values = {
        "request_url": request.url,
        "status_code": 200,
        "final_url": request.url,
        "headers": headers,
        "header_bytes": normalized_header_bytes(headers),
        "body": body,
        "connected_address": address,
        "connected_peer_preresolved": False,
        "tls_version": "TLSv1.3",
        "certificate_chain_verified": False,
        "hostname_verified": False,
    }
    values.update(changes)
    return EntraCallingClientRedirectEndpointResponse(**values)


class EndpointTransport:
    def __init__(self, mutator=None, *, addresses=(PUBLIC_IP,)):
        self.mutator = mutator
        self.addresses = addresses
        self.plans = []

    def __call__(self, plan):
        self.plans.append(plan)
        hostnames = tuple(sorted({request.hostname for request in plan}))
        observations = tuple(
            EntraCallingClientRedirectEndpointDNSObservation(
                hostname=hostname,
                resolved_addresses=self.addresses,
            )
            for hostname in hostnames
        )
        responses = [response(request) for request in plan]
        if self.mutator is not None:
            self.mutator(plan, observations, responses)
        return EntraCallingClientRedirectEndpointTransportResult(
            dns_observations=observations,
            responses=tuple(responses),
        )


def inputs(*, endpoint_transport=None, registration_transport=None):
    prerequisite = prerequisites()
    return {
        "document": json.dumps(
            readiness_values(prerequisite), separators=(",", ":")
        ).encode(),
        **prerequisite,
        "authorization": authorization(),
        "calling_client_registration_transport": (
            registration_transport or RegistrationTransport()
        ),
        "endpoint_transport": endpoint_transport or EndpointTransport(),
    }


def load(**changes):
    values = inputs()
    values.update(changes)
    return validate_entra_calling_client_redirect_endpoint_probe(**values)


def test_valid_synthetic_proof_is_precise_private_and_canonical():
    receipt = load()
    assert (
        receipt.receipt_type
        == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE
    )
    assert (
        receipt.validation_scope == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE
    )
    assert receipt.synthetic_transport_used is True
    assert receipt.step213_live_https_attested is False
    assert receipt.endpoint_live_https_attested is False
    assert receipt.sealed_provider_io_performed is False
    assert receipt.sealed_network_io_performed is False
    assert receipt.injected_transport_side_effects_checked is False
    assert receipt.application_configuration_mutation_performed is False
    assert receipt.dns_configuration_mutation_performed is False
    assert receipt.endpoint_configuration_mutation_performed is False
    assert receipt.read_operation_side_effects_checked is False
    assert receipt.sealed_dns_resolution_call_count == 0
    assert receipt.desired_distinct_hostname_count == 1
    assert receipt.resolved_address_count == 1
    assert receipt.sealed_tcp_connection_count == 0
    assert receipt.sealed_tls_handshake_count == 0
    assert receipt.desired_redirect_endpoint_count == 2
    assert receipt.total_endpoint_request_count == 20
    assert receipt.response_count == 20
    rendered = render_entra_calling_client_redirect_endpoint_probe_receipt(receipt)
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    for raw in (
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        "https://app.engineer4me.invalid/auth/callback",
        "app.engineer4me.invalid",
        PUBLIC_IP,
        CALLBACK_BODY.decode(),
    ):
        assert raw not in rendered


def test_enforced_header_profile_digest_is_independently_bound_and_tamper_checked():
    receipt = load()
    expected_names = frozenset(
        {
            "access-control-allow-credentials",
            "access-control-allow-origin",
            "alt-svc",
            "content-encoding",
            "content-location",
            "content-security-policy-report-only",
            "cross-origin-embedder-policy-report-only",
            "cross-origin-opener-policy-report-only",
            "document-policy-report-only",
            "link",
            "location",
            "nel",
            "refresh",
            "report-to",
            "reporting-endpoints",
            "set-cookie",
        }
    )
    assert module._FORBIDDEN_RESPONSE_HEADERS == expected_names
    names = sorted(module._FORBIDDEN_RESPONSE_HEADERS)
    canonical = json.dumps(names, separators=(",", ":")).encode()
    digest = hashlib.sha256()
    for value in (
        b"engineer4me-step215-evidence-v1",
        b"enforced_response_header_profile",
        b"1",
        canonical,
    ):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    assert receipt.enforced_response_header_profile_sha256 == digest.hexdigest()
    replacement = ("0" if digest.hexdigest()[0] != "0" else "1") + digest.hexdigest()[
        1:
    ]
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, enforced_response_header_profile_sha256=replacement)
    object.__setattr__(receipt, "enforced_response_header_profile_sha256", replacement)
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_entra_calling_client_redirect_endpoint_probe_receipt(receipt)


@pytest.mark.parametrize(
    "invalid_digest",
    ["+" + "a" * 63, "-" + "a" * 63, " " + "a" * 63, "a" * 63 + " "],
)
def test_sha256_fields_reject_signed_or_whitespace_padded_hex(invalid_digest):
    assert len(invalid_digest) == 64
    assert module._is_lower_sha256(invalid_digest) is False
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(load(), configuration_sha256=invalid_digest)


def test_resolved_address_count_is_per_hostname_and_cannot_fall_below_host_count():
    receipt = load()
    two_hosts = replace(
        receipt,
        desired_distinct_hostname_count=2,
        resolved_address_count=2,
        selected_address_count=2,
    )
    assert two_hosts.resolved_address_count == 2
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(two_hosts, resolved_address_count=1)


def test_receipt_accepts_only_the_complete_live_flag_and_sealed_count_partition():
    synthetic = load()
    live = replace(
        synthetic,
        synthetic_transport_used=False,
        sealed_dns_resolution_call_count=(synthetic.desired_distinct_hostname_count),
        sealed_tcp_connection_count=synthetic.response_count,
        sealed_tls_handshake_count=synthetic.response_count,
        **{field: True for field in module._DYNAMIC_LIVE_FIELDS},
    )
    assert (
        json.loads(render_entra_calling_client_redirect_endpoint_probe_receipt(live))[
            "sealed_network_io_performed"
        ]
        is True
    )
    for field in module._DYNAMIC_LIVE_FIELDS:
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(live, **{field: False})
    for field in (
        "sealed_dns_resolution_call_count",
        "sealed_tcp_connection_count",
        "sealed_tls_handshake_count",
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(live, **{field: 0})


def test_request_plan_exactly_matches_step214_order_and_derived_targets():
    endpoint = EndpointTransport()
    receipt = load(endpoint_transport=endpoint)
    plan = endpoint.plans[0]
    assert len(plan) == receipt.total_endpoint_request_count == 20
    assert [value.sequence for value in plan] == list(range(1, 21))
    for start in (0, 10):
        assert plan[start].kind == "baseline"
        assert plan[start + 1].kind == "hostile_origin"
        assert tuple(value.vector_name for value in plan[start + 2 : start + 10]) == (
            "continue",
            "next",
            "redirect",
            "redirect_uri",
            "return",
            "returnUrl",
            "target",
            "url",
        )


def test_step214_preflight_and_step213_complete_before_endpoint_transport(monkeypatch):
    events = []
    original_prepare = module._prepare
    original_registration = module._MODULE_OWNED_STEP213_VALIDATE

    def prepare(**kwargs):
        events.append("step214")
        return original_prepare(**kwargs)

    def registration(**kwargs):
        events.append("step213")
        return original_registration(**kwargs)

    class Endpoint(EndpointTransport):
        def __call__(self, plan):
            events.append("endpoint")
            return super().__call__(plan)

    monkeypatch.setattr(module, "_prepare", prepare)
    monkeypatch.setattr(module, "_MODULE_OWNED_STEP213_VALIDATE", registration)
    load(endpoint_transport=Endpoint())
    assert events == ["step214", "step213", "endpoint"]


def test_step213_failure_emits_no_receipt_and_never_calls_endpoint():
    endpoint_calls = []

    class BrokenRegistration:
        def __call__(self, plan):
            raise RuntimeError("provider failure")

    class Endpoint(EndpointTransport):
        def __call__(self, plan):
            endpoint_calls.append(plan)
            return super().__call__(plan)

    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        load(
            calling_client_registration_transport=BrokenRegistration(),
            endpoint_transport=Endpoint(),
        )
    assert endpoint_calls == []


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id_sha256",
        "calling_client_application_id_sha256",
        "calling_client_application_object_id_sha256",
    ],
)
def test_step213_identity_hashes_are_explicitly_rebound_to_step214_documents(
    monkeypatch,
    field,
):
    original = module._MODULE_OWNED_STEP213_VALIDATE

    def tampered(**kwargs):
        receipt = original(**kwargs)
        value = getattr(receipt, field)
        replacement = ("0" if value[0] != "0" else "1") + value[1:]
        object.__setattr__(receipt, field, replacement)
        return receipt

    monkeypatch.setattr(module, "_MODULE_OWNED_STEP213_VALIDATE", tampered)
    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        load()


@pytest.mark.parametrize(
    "content_type",
    [
        "text/html",
        "text/html; charset=latin-1",
        "application/xhtml+xml; charset=utf-8",
        "text/html; charset=utf-8; profile=x",
        "text/html, text/html; charset=utf-8",
    ],
)
def test_content_type_requires_exact_html_utf8_single_parameter(content_type):
    item = response(
        type("R", (), {"url": "https://app.engineer4me.invalid/auth/callback"})(),
        headers=good_headers(**{"content-type": content_type}),
    )
    with pytest.raises(ValueError):
        module._security_projection(item)


@pytest.mark.parametrize(
    "name",
    [
        "location",
        "refresh",
        "set-cookie",
        "content-encoding",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "content-security-policy-report-only",
        "content-location",
        "link",
        "nel",
        "report-to",
        "reporting-endpoints",
        "alt-svc",
        "cross-origin-opener-policy-report-only",
        "cross-origin-embedder-policy-report-only",
        "document-policy-report-only",
    ],
)
def test_every_forbidden_response_header_rejects(name):
    headers = good_headers()
    item = response(
        type("R", (), {"url": "https://app.engineer4me.invalid/auth/callback"})(),
        headers=(*headers, (name, "x")),
    )
    with pytest.raises(ValueError):
        module._security_projection(item)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("strict-transport-security", "max-age=31535999"),
        ("strict-transport-security", "max-age=31536000; MAX-AGE=31536000"),
        ("strict-transport-security", "max-age=31536000; x=y"),
        ("strict-transport-security", 'max-age="31536000"'),
        ("referrer-policy", "origin"),
        ("cache-control", "private"),
        ("cache-control", "no-store, NO-STORE"),
        ("x-content-type-options", "sniff"),
    ],
)
def test_required_security_header_semantics_are_fail_closed(name, value):
    item = response(
        type("R", (), {"url": "https://app.engineer4me.invalid/auth/callback"})(),
        headers=good_headers(**{name: value}),
    )
    with pytest.raises(ValueError):
        module._security_projection(item)


@pytest.mark.parametrize(
    "csp",
    [
        "default-src 'self'; script-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'",
        EXACT_CSP + "; connect-src https://evil.example",
        EXACT_CSP + "; img-src 'self'",
        EXACT_CSP + "; report-uri /report",
        EXACT_CSP + "; default-src 'self'",
        EXACT_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"),
        EXACT_CSP.replace("script-src 'self'", "script-src https:"),
        EXACT_CSP.replace("script-src 'self'", "script-src *"),
        EXACT_CSP.replace("script-src 'self'", "script-src 'nonce-abc'"),
        EXACT_CSP.replace(
            "default-src 'self';", "default-src 'self', script-src 'self';"
        ),
    ],
)
def test_csp_is_exact_six_directive_closed_world(csp):
    item = response(
        type("R", (), {"url": "https://app.engineer4me.invalid/auth/callback"})(),
        headers=good_headers(**{"content-security-policy": csp}),
    )
    with pytest.raises(ValueError):
        module._security_projection(item)


def test_csp_directive_order_and_ascii_case_are_normalized():
    assert module._EXACT_CSP == {
        "base-uri": ("'none'",),
        "default-src": ("'self'",),
        "form-action": ("'none'",),
        "frame-ancestors": ("'none'",),
        "object-src": ("'none'",),
        "script-src": ("'self'",),
    }
    assert {
        "base",
        "embed",
        "form",
        "iframe",
        "math",
        "object",
        "style",
        "svg",
    } <= module._FORBIDDEN_HTML_ELEMENTS
    csp = (
        "FORM-ACTION 'NONE'; OBJECT-SRC 'NONE'; SCRIPT-SRC 'SELF'; "
        "DEFAULT-SRC 'SELF'; FRAME-ANCESTORS 'NONE'; BASE-URI 'NONE'"
    )
    item = response(
        type("R", (), {"url": "https://app.engineer4me.invalid/auth/callback"})(),
        headers=good_headers(**{"content-security-policy": csp}),
    )
    assert module._security_projection(item)


@pytest.mark.parametrize(
    "html",
    [
        '<base href="/">',
        '<form action="/submit"></form>',
        '<iframe src="/frame"></iframe>',
        '<object data="/x"></object>',
        '<embed src="/x">',
        '<svg><a href="/x"></a></svg>',
        '<math><a href="/x"></a></math>',
        "<style>body{background:url(/x)}</style>",
        '<div style="background:url(/x)"></div>',
        '<div xml:base="https://evil.example"><a href="/x"></a></div>',
        '<div filter="url(https://evil.example/x)"></div>',
        '<animate attributeName="href" to="https://evil.example"></animate>',
        '<meta http-equiv="refresh" content="0;url=https://evil.example">',
        '<meta name="referrer" content="unsafe-url">',
        '<img src="/x" referrerpolicy="unsafe-url">',
        '<img attributionsrc="/report" src="/x">',
        "<script>alert(1)</script>",
        '<script src="/ok">alert(1)</script>',
        '<script src="/ok"><!-- alert(1) --></script>',
        '<img src="/x" onerror="evil()">',
        '<img src="/x" x:onerror="evil()">',
        '<img src="https://evil.example/x">',
        '<img src="//evil.example/x">',
        '<img src="/a\\b">',
        '<img src="/%2f%2fevil.example">',
        '<img src="/a/../b">',
        '<img src="/a//b">',
        '<img src="/é">',
        '<img src="/x" SRC="/y">',
        '<svg:svg><a href="/x"></a></svg:svg>',
        "</iframe>",
        "</x:svg>",
        '<link href="javascript:alert(1)">',
        '<button x:action="https://evil.example/x">x</button>',
        '<video x:poster="https://evil.example/x"></video>',
        '<a x:ping="/ok https://evil.example/p" href="/ok">x</a>',
        '<img x:srcset="/a 1x, https://evil.example/b 2x">',
        '<img srcset="/a 1x, https://evil.example/b 2x">',
        '<a ping="/ok https://evil.example/p" href="/ok">x</a>',
        '<img imagesrcset="/a 1x, //evil.example/b 2x">',
    ],
)
def test_static_html_rejects_active_origin_navigation_and_url_bypasses(html):
    with pytest.raises((UnicodeDecodeError, ValueError)):
        module._validate_callback_html(html.encode("utf-8"))


@pytest.mark.parametrize(
    "html",
    [
        '<link rel="stylesheet" href="/assets/app.css">',
        '<img src="/assets/logo.png" srcset="/a.png 1x, /b.png 2x">',
        '<a href="/auth/done" ping="/audit /audit2">Done</a>',
        '<script src="/assets/callback.js"> \n </script>',
        '<svgish xlink:href="/safe"></svgish>',
    ],
)
def test_static_html_allows_only_bounded_root_relative_static_urls(html):
    module._validate_callback_html(html.encode())


def test_utf8_bom_invalid_utf8_empty_and_oversized_url_lists_reject():
    for body in (b"", b"\xef\xbb\xbf<html></html>", b"\xff"):
        with pytest.raises((UnicodeDecodeError, ValueError)):
            module._validate_callback_html(body)
    ping = " ".join(f"/p{value}" for value in range(33))
    with pytest.raises(ValueError):
        module._validate_callback_html(f'<a href="/" ping="{ping}">x</a>'.encode())
    for html in (
        '<MeTa NaMe="ref&#101;rrer" content="unsafe-url">',
        '<a href="&#x2f;&#x2f;evil.example/x">x</a>',
        '<img SRC="/x" ReFeRrErPoLiCy="unsafe-url">',
        '<div XmL:BaSe="https://evil.example"><a href="/x">x</a></div>',
        f'<a href="/{"x" * 2_048}">x</a>',
        '<a href="/x\x7f">x</a>',
    ):
        with pytest.raises(ValueError):
            module._validate_callback_html(html.encode())


def test_variant_body_or_normalized_security_projection_mismatch_rejects():
    def body_mutator(plan, observations, responses):
        responses[1] = response(plan[1], body=b"<html><body>different</body></html>")

    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        load(endpoint_transport=EndpointTransport(body_mutator))

    def header_mutator(plan, observations, responses):
        headers = good_headers(**{"cache-control": "no-store, max-age=0"})
        responses[2] = response(plan[2], headers=headers)

    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        load(endpoint_transport=EndpointTransport(header_mutator))


def test_exact_first_selected_address_is_required_for_every_response():
    def mutator(plan, observations, responses):
        responses[0] = response(plan[0], address=PUBLIC_IP_2)

    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        load(
            endpoint_transport=EndpointTransport(
                mutator,
                addresses=(PUBLIC_IP, PUBLIC_IP_2),
            )
        )


def invalid_value(receipt, field):
    value = getattr(receipt, field.name)
    if field.name.endswith("_sha256"):
        return ""
    if type(value) is str:
        return ""
    if type(value) is bool:
        return not value
    if type(value) is int:
        return True
    if type(value) is float:
        return 10
    raise AssertionError(field.name)


def test_every_receipt_field_is_tamper_checked_by_post_init_and_renderer():
    receipt = load()
    names = [field.name for field in fields(receipt)]
    assert len(names) == len(set(names))
    for field in fields(receipt):
        bad = invalid_value(receipt, field)
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **{field.name: bad})
        fresh = load()
        object.__setattr__(fresh, field.name, bad)
        with pytest.raises(ValueError, match="receipt is invalid"):
            render_entra_calling_client_redirect_endpoint_probe_receipt(fresh)


class BytesSubclass(bytes):
    pass


@pytest.mark.parametrize(
    "field",
    [
        "document",
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
    ],
)
def test_source_documents_require_exact_bytes_not_subclasses(field):
    values = inputs()
    values[field] = BytesSubclass(values[field])
    with pytest.raises(TypeError, match="inputs are invalid"):
        validate_entra_calling_client_redirect_endpoint_probe(**values)


def exception_graph_text(error):
    pending = [error]
    seen = set()
    material = []

    def visit(value):
        if id(value) in seen:
            return
        seen.add(id(value))
        if isinstance(value, (str, bytes, bytearray, int, float, bool, type(None))):
            material.append(repr(value))
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
        material.extend(str(value) for value in current.args)
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
    return "\n".join(material)


def test_nested_transport_failure_is_fresh_and_omits_raw_endpoint_evidence():
    secret = "SECRET-BODY-215"
    retained = {}

    class BrokenEndpoint:
        def __call__(self, plan):
            try:
                raise RuntimeError(secret, plan[0].url, PUBLIC_IP)
            except RuntimeError as inner:
                child = ValueError(secret)
                child.add_note(secret)
                child.private_evidence = secret
                group = builtins.ExceptionGroup(secret, [child, inner])
                retained.update(group=group, child=child, inner=inner)
                raise group from inner

    with pytest.raises(EntraCallingClientRedirectEndpointProbeError) as caught:
        load(endpoint_transport=BrokenEndpoint())
    material = exception_graph_text(caught.value)
    for raw in (
        secret,
        "app.engineer4me.invalid",
        "https://app.engineer4me.invalid/auth/callback",
        PUBLIC_IP,
    ):
        assert raw not in material
    for error in retained.values():
        assert error.args == ()
        assert error.__traceback__ is None
        assert error.__cause__ is None
        assert error.__context__ is None
        assert error.__dict__ == {}


@pytest.mark.parametrize(
    ("kinds", "expected"),
    [
        (("keyboard",), KeyboardInterrupt),
        (("system",), SystemExit),
        (("system", "keyboard"), KeyboardInterrupt),
    ],
)
def test_probe_preserves_nested_control_flow_with_keyboard_precedence(
    kinds,
    expected,
):
    secret = "SECRET-PROBE-NESTED-CONTROL-215"
    children = [
        KeyboardInterrupt(secret) if kind == "keyboard" else SystemExit(secret)
        for kind in kinds
    ]
    group = builtins.BaseExceptionGroup(secret, children)

    class BrokenEndpoint:
        def __call__(self, plan):
            raise group

    with pytest.raises(expected) as caught:
        load(endpoint_transport=BrokenEndpoint())
    assert secret not in exception_graph_text(caught.value)
    for child in children:
        assert child.args == ()
        assert child.__traceback__ is None


def test_synthetic_path_has_no_hidden_operational_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    assert load().synthetic_transport_used is True


def test_live_orchestration_is_preflight_then_step213_then_endpoint_and_clears_token(
    monkeypatch,
):
    events = []
    token = "opaque-secret-token"
    sentinel = object()

    monkeypatch.setattr(
        module, "_prepare", lambda **kwargs: events.append("step214") or {}
    )

    def live_registration(**kwargs):
        assert kwargs["delegated_access_token"] == token
        events.append("step213")
        return object()

    monkeypatch.setattr(module, "_MODULE_OWNED_STEP213_LIVE", live_registration)
    monkeypatch.setattr(
        module,
        "_validate_registration_receipt",
        lambda *args, **kwargs: "{}",
    )

    class Loader:
        def __init__(self):
            events.append("loader")

        def close(self):
            events.append("close")

    monkeypatch.setattr(module, "_MODULE_OWNED_ENDPOINT_LOADER", Loader)
    monkeypatch.setattr(
        module,
        "_evaluate",
        lambda **kwargs: events.append("endpoint") or sentinel,
    )
    prerequisite = prerequisites()
    result = module.probe_live_entra_calling_client_redirect_endpoint(
        document=json.dumps(readiness_values(prerequisite)).encode(),
        **prerequisite,
        authorization=authorization(),
        delegated_access_token=token,
    )
    assert result is sentinel
    assert events == ["step214", "step213", "loader", "endpoint", "close"]


def test_live_step213_failure_constructs_no_endpoint_loader(monkeypatch):
    constructed = []
    prerequisite = prerequisites()
    monkeypatch.setattr(module, "_prepare", lambda **kwargs: {})

    def broken(**kwargs):
        raise RuntimeError("graph failed")

    monkeypatch.setattr(module, "_MODULE_OWNED_STEP213_LIVE", broken)
    monkeypatch.setattr(
        module,
        "_MODULE_OWNED_ENDPOINT_LOADER",
        lambda: constructed.append(True),
    )
    with pytest.raises(EntraCallingClientRedirectEndpointProbeError):
        module.probe_live_entra_calling_client_redirect_endpoint(
            document=json.dumps(readiness_values(prerequisite)).encode(),
            **prerequisite,
            authorization=authorization(),
            delegated_access_token="opaque-secret-token",
        )
    assert constructed == []
