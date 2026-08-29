"""Tests for offline Microsoft Entra calling-client MSAL Browser readiness."""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
import os
import socket
import ssl
import urllib.request
from dataclasses import fields, replace
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_readiness import (
    ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE,
    ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE,
    ENTRA_CALLING_CLIENT_MSAL_BROWSER_SOURCE,
    MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_BYTES,
    MSAL_BROWSER_APPLICATION_TYPE,
    MSAL_BROWSER_CACHE_LOCATION,
    MSAL_BROWSER_CONSUMPTION,
    MSAL_BROWSER_INTERACTION_TYPE,
    MSAL_BROWSER_PACKAGE_NAME,
    MSAL_BROWSER_PROTOCOL_MODE,
    MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT,
    MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH,
    MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT,
    MSAL_BROWSER_REDIRECT_HANDLER,
    MSAL_BROWSER_REVIEW_DATE,
    MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS,
    MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT,
    MSAL_BROWSER_REVIEWED_VERSION,
    MSAL_BROWSER_SUPPORTED_MAJOR,
    EntraCallingClientMSALBrowserReadinessError,
    load_entra_calling_client_msal_browser_readiness,
    render_entra_calling_client_msal_browser_readiness_receipt,
)
from app.security.authentication_entra_calling_client_pkce_runtime_readiness import (
    load_entra_calling_client_pkce_runtime_readiness,
)
from tests import (
    test_security_authentication_entra_calling_client_pkce_runtime_readiness as step216,
)


def prerequisites(redirect_uris=(step216.step214.REDIRECT_URI,)):
    prior = step216.prerequisites(redirect_uris)
    pkce_document = json.dumps(step216.values(prior), separators=(",", ":")).encode()
    pkce_receipt = load_entra_calling_client_pkce_runtime_readiness(
        document=pkce_document,
        **prior,
    )
    return {
        **prior,
        "pkce_runtime_control_document": pkce_document,
        "approved_pkce_runtime_control_document_sha256": (
            pkce_receipt.pkce_runtime_control_document_sha256
        ),
    }


def values(prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return {
        "document_type": ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_MSAL_BROWSER_SOURCE,
        "approved_pkce_runtime_control_document_sha256": prerequisite[
            "approved_pkce_runtime_control_document_sha256"
        ],
        "control_profile": ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE,
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    body = values(prerequisite) if value is None else value
    return load_entra_calling_client_msal_browser_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
        **prerequisite,
    )


def framed(label, *values):
    digest = hashlib.sha256()
    for value in ("engineer4me-step217-v1", label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def unsafe_replace(receipt, **changes):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(receipt, field.name))
        )
    return clone


def exception_material(error):
    values = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.append(repr(current))
        values.extend(repr(value) for value in current.args)
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        children = getattr(current, "exceptions", ())
        if isinstance(children, tuple):
            pending.extend(children)
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                values.extend(
                    repr(value) for value in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(values)


def test_valid_receipt_binds_step216_and_stays_offline():
    receipt = load()
    assert receipt.receipt_type == ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE
    assert receipt.validation_scope == ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE
    assert receipt.control_profile == ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE
    assert receipt.desired_redirect_endpoint_count == 1
    assert all(
        getattr(receipt, name) is True for name in module._STRUCTURAL_TRUE_FIELDS
    )
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )
    assert receipt.step216_csp_gap_remains_blocking is True
    assert receipt.step216_no_retry_conflict_detected is True
    assert receipt.reviewed_candidate_approved_for_integration is False
    assert receipt.reviewed_candidate_compatible_with_step216 is False
    assert receipt.package_selection_ready is False
    assert receipt.activation_ready is False


def test_public_package_and_integration_constants_are_exact():
    receipt = load()
    assert receipt.package_name == MSAL_BROWSER_PACKAGE_NAME == "@azure/msal-browser"
    assert receipt.reviewed_package_version == MSAL_BROWSER_REVIEWED_VERSION == "5.17.3"
    assert receipt.package_review_date == MSAL_BROWSER_REVIEW_DATE == "2026-08-15"
    assert receipt.reviewed_package_major == MSAL_BROWSER_SUPPORTED_MAJOR == 5
    assert (
        receipt.package_consumption
        == MSAL_BROWSER_CONSUMPTION
        == "package_manager_and_bundler"
    )
    assert (
        receipt.application_type
        == MSAL_BROWSER_APPLICATION_TYPE
        == "standard_public_client_application"
    )
    assert receipt.interaction_type == MSAL_BROWSER_INTERACTION_TYPE == "redirect_only"
    assert receipt.protocol_mode == MSAL_BROWSER_PROTOCOL_MODE == "AAD"
    assert receipt.cache_location == MSAL_BROWSER_CACHE_LOCATION == "sessionStorage"
    assert (
        receipt.redirect_handler
        == MSAL_BROWSER_REDIRECT_HANDLER
        == "handleRedirectPromise"
    )
    assert (
        receipt.redirect_bridge_script
        == MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT
        == "/auth/msal-redirect-bridge.js"
    )
    assert (
        receipt.redirect_bridge_package_subpath
        == MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH
        == "@azure/msal-browser/redirect-bridge"
    )
    assert (
        receipt.redirect_bridge_export
        == MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT
        == "broadcastResponseToMainFrame"
    )
    assert (
        receipt.reviewed_token_post_retry_count
        == MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
        == 1
    )
    assert (
        receipt.reviewed_token_post_retry_backoff_milliseconds
        == MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS
        == 100
    )


def test_package_selection_profile_is_independently_bound():
    receipt = load()
    expected = canonical(
        {
            "package": "@azure/msal-browser",
            "reviewed_candidate_version": "5.17.3",
            "review_date": "2026-08-15",
            "exact_version_specifier": "5.17.3",
            "allowed_consumption": "package_manager_and_bundler",
            "cdn_allowed": False,
            "semver_range_allowed": False,
            "latest_tag_allowed": False,
            "package_manager_selection_checked": False,
            "registry_or_mirror_selection_checked": False,
            "full_dependency_lock_required": True,
            "lockfile_integrity_required": True,
            "version_revalidation_before_install_required": True,
            "reviewed_token_post_transport_retry_count": 1,
            "reviewed_token_post_transport_retry_backoff_milliseconds": 100,
            "step216_required_token_post_retry_count": 0,
            "step216_retry_compatible": False,
            "candidate_approved_for_integration": False,
            "framework_wrapper": "none_until_frontend_framework_selected",
        }
    )
    assert receipt.msal_package_selection_profile_sha256 == framed(
        "msal_package_selection_profile", expected
    )


def test_configuration_bridge_initialization_and_transition_hashes_are_exact():
    prerequisite = prerequisites(
        (step216.step214.REDIRECT_URI, step216.step214.REDIRECT_URI_2)
    )
    receipt = load(prerequisite=prerequisite)
    tenant = step216.step214.TENANT_ID
    client = step216.step214.CALLING_CLIENT_APPLICATION_ID
    redirects = [step216.step214.REDIRECT_URI, step216.step214.REDIRECT_URI_2]
    origin = "https://synthetic.ciamlogin.com"
    authority = f"{origin}/{tenant}"
    config = canonical(
        {
            "application_type": "standard_public_client_application",
            "auth": {
                "clientId": client,
                "authority": authority,
                "knownAuthorities": ["synthetic.ciamlogin.com"],
                "permittedRedirectUris": redirects,
                "redirectUriSelection": "exact_registered_value_per_request",
                "postLogoutRedirectUri": "not_selected",
            },
            "cache": {
                "cacheLocation": "sessionStorage",
                "temporaryCacheLocationOverrideAllowed": False,
                "storeAuthStateInCookie": False,
                "secureCookiesConfigured": False,
            },
            "system": {
                "protocolMode": "AAD",
                "allowRedirectInIframe": False,
                "piiLoggingEnabled": False,
                "nestedApplicationAuthenticationAllowed": False,
            },
            "runtimeImplementationChecked": False,
        }
    )
    bridge = canonical(
        {
            "redirectUris": redirects,
            "dedicatedDocumentRequired": True,
            "externalBridgeScript": "/auth/msal-redirect-bridge.js",
            "packageSubpath": "@azure/msal-browser/redirect-bridge",
            "requiredExport": "broadcastResponseToMainFrame",
            "scriptMustBeSameOriginRootRelative": True,
            "inlineScriptAllowed": False,
            "routerAllowed": False,
            "businessLogicAllowed": False,
            "additionalJavaScriptAllowed": False,
            "crossOriginOpenerPolicyHeaderAllowed": False,
            "crossOriginOpenerPolicyReportOnlyHeaderAllowed": False,
            "callbackDocumentTransitionRequired": True,
            "successorEndpointProofRequired": True,
            "deployed": False,
        }
    )
    initialization = canonical(
        {
            "applicationType": "standard_public_client_application",
            "initializeMustResolveBeforeOtherApis": True,
            "interactionType": "redirect_only",
            "popupApisAllowed": False,
            "redirectHandler": "handleRedirectPromise",
            "redirectHandlerBeforeAccountOrTokenUse": True,
            "rawRedirectHashOverrideAllowed": False,
            "rawTokenOrAccountLoggingAllowed": False,
            "executed": False,
        }
    )
    transition = canonical(
        {
            "step216CurrentDirectiveCount": 6,
            "tokenExchangeIntermediateDirectiveCount": 7,
            "authorityOrigin": origin,
            "connectSrcRequired": ["'self'", origin],
            "crossOriginOpenerPolicyHeaderAllowedOnRedirectBridge": False,
            "redirectBridgeDocumentChangeRequired": True,
            "finalApiOriginPolicyChecked": False,
            "deploymentChecked": False,
            "successorEndpointProofChecked": False,
        }
    )
    assert receipt.msal_configuration_profile_sha256 == framed(
        "msal_configuration_profile", config
    )
    assert receipt.redirect_bridge_profile_sha256 == framed(
        "redirect_bridge_profile", bridge
    )
    assert receipt.initialization_profile_sha256 == framed(
        "initialization_profile", initialization
    )
    assert receipt.csp_and_endpoint_transition_profile_sha256 == framed(
        "csp_and_endpoint_transition_profile", transition
    )


def test_identity_authority_redirect_and_source_hashes_are_independent():
    prerequisite = prerequisites()
    receipt = load(prerequisite=prerequisite)
    tenant = step216.step214.TENANT_ID
    origin = "https://synthetic.ciamlogin.com"
    assert receipt.tenant_id_sha256 == framed("tenant_id", tenant)
    assert receipt.calling_client_application_id_sha256 == framed(
        "calling_client_application_id", step216.step214.CALLING_CLIENT_APPLICATION_ID
    )
    assert receipt.calling_client_application_object_id_sha256 == framed(
        "calling_client_application_object_id", step216.step214.CALLING_CLIENT_OBJECT_ID
    )
    assert receipt.api_application_id_sha256 == framed(
        "api_application_id", step216.step214.API_APPLICATION_ID
    )
    assert receipt.api_delegated_scope_id_sha256 == framed(
        "api_delegated_scope_id", step216.step214.API_SCOPE_ID
    )
    assert receipt.spa_redirect_uris_sha256 == framed(
        "spa_redirect_uris", "1", step216.step214.REDIRECT_URI
    )
    assert receipt.authority_origin_sha256 == framed("authority_origin", origin)
    assert receipt.authority_sha256 == framed("authority", f"{origin}/{tenant}")
    assert receipt.known_authorities_sha256 == framed(
        "known_authorities", "synthetic.ciamlogin.com"
    )
    assert (
        receipt.pkce_runtime_control_document_sha256
        == hashlib.sha256(
            canonical(json.loads(prerequisite["pkce_runtime_control_document"]))
        ).hexdigest()
    )


def test_three_redirects_change_only_derived_counts_and_profiles():
    redirects = (
        step216.step214.REDIRECT_URI,
        step216.step214.REDIRECT_URI_2,
        step216.step214.REDIRECT_URI_3,
    )
    receipt = load(prerequisite=prerequisites(redirects))
    assert receipt.desired_redirect_endpoint_count == 3
    assert receipt.known_authority_count == 1
    assert receipt.current_callback_csp_directive_count == 6
    assert receipt.required_transition_csp_directive_count == 7


def test_receipt_omits_every_raw_identity_uri_host_and_document():
    prerequisite = prerequisites(
        (
            step216.step214.REDIRECT_URI,
            step216.step214.REDIRECT_URI_2,
            step216.step214.REDIRECT_URI_3,
        )
    )
    rendered = render_entra_calling_client_msal_browser_readiness_receipt(
        load(prerequisite=prerequisite)
    )
    forbidden = {
        step216.step214.TENANT_ID,
        step216.step214.API_APPLICATION_ID,
        step216.step214.API_APPLICATION_OBJECT_ID,
        step216.step214.API_SERVICE_PRINCIPAL_OBJECT_ID,
        step216.step214.API_SCOPE_ID,
        step216.step214.CALLING_CLIENT_APPLICATION_ID,
        step216.step214.CALLING_CLIENT_OBJECT_ID,
        step216.step214.CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        step216.step214.REDIRECT_URI,
        step216.step214.REDIRECT_URI_2,
        step216.step214.REDIRECT_URI_3,
        "synthetic.ciamlogin.com",
    }
    forbidden.update({step216.step214.OWNER_ID, step216.step214.OWNER_ID_2})
    for value in forbidden:
        assert value not in rendered
    for raw_document in (
        prerequisite["api_registration_document"],
        prerequisite["calling_client_registration_document"],
        prerequisite["inventory_document"],
        prerequisite["redirect_endpoint_control_document"],
        prerequisite["pkce_runtime_control_document"],
    ):
        assert raw_document.decode() not in rendered


@pytest.mark.parametrize(
    "field",
    [
        "document_type",
        "source",
        "control_profile",
    ],
)
def test_document_literals_are_exact(field):
    body = values()
    body[field] = str(body[field]) + "-wrong"
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
        load(body)


@pytest.mark.parametrize("invalid", [True, False, 0, 2, 1.0, "1", None, [], {}])
def test_schema_version_is_exact_integer_one(invalid):
    body = values()
    body["schema_version"] = invalid
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
        load(body)


def test_document_rejects_extra_missing_root_and_nested_duplicates():
    prerequisite = prerequisites()
    body = values(prerequisite)
    cases = [
        b"[]",
        json.dumps({**body, "extra": True}).encode(),
        json.dumps(
            {key: value for key, value in body.items() if key != "source"}
        ).encode(),
        b'{"document_type":"x","document_type":"y"}',
        b'{"document_type":"x","nested":{"a":1,"a":2}}',
    ]
    for document in cases:
        with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
            load_entra_calling_client_msal_browser_readiness(
                document=document, **prerequisite
            )


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"{",
        b'"scalar"',
        b"\xff",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"x":true}',
    ],
)
def test_malformed_documents_fail_sanitized(document):
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError) as caught:
        load_entra_calling_client_msal_browser_readiness(
            document=document, **prerequisites()
        )
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_document_size_depth_and_container_bounds_fail_closed():
    prerequisite = prerequisites()
    oversized = b" " * (MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_BYTES + 1)
    deeply_nested = b'{"a":{"b":{"c":{"d":1}}}}'
    too_many = json.dumps({str(index): [] for index in range(9)}).encode()
    for document in (oversized, deeply_nested, too_many):
        with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
            load_entra_calling_client_msal_browser_readiness(
                document=document, **prerequisite
            )


def test_step216_rerun_occurs_before_step217_document_parsing(monkeypatch):
    prerequisite = prerequisites()
    marker = "step216-prerequisite-first"

    def fail_first(**kwargs):
        del kwargs
        raise KeyboardInterrupt(marker)

    monkeypatch.setattr(
        module, "load_entra_calling_client_pkce_runtime_readiness", fail_first
    )
    with pytest.raises(KeyboardInterrupt, match="readiness interrupted"):
        load_entra_calling_client_msal_browser_readiness(
            document=b"not-json", **prerequisite
        )


def test_independently_approved_pkce_digest_is_required():
    prerequisite = prerequisites()
    prerequisite["approved_pkce_runtime_control_document_sha256"] = "0" * 64
    body = values(prerequisite)
    body["approved_pkce_runtime_control_document_sha256"] = "0" * 64
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
        load(body, prerequisite)


def test_schema_valid_reblessed_pkce_tamper_is_rejected():
    prerequisite = prerequisites()
    parsed = json.loads(prerequisite["pkce_runtime_control_document"])
    parsed["source"] = parsed["source"] + "-wrong"
    tampered = json.dumps(parsed, separators=(",", ":")).encode()
    prerequisite["pkce_runtime_control_document"] = tampered
    prerequisite["approved_pkce_runtime_control_document_sha256"] = hashlib.sha256(
        tampered
    ).hexdigest()
    body = values(prerequisite)
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
        load(body, prerequisite)


@pytest.mark.parametrize(
    "argument",
    [
        "document",
        "pkce_runtime_control_document",
        "redirect_endpoint_control_document",
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
    ],
)
def test_document_arguments_require_exact_bytes(argument):
    prerequisite = prerequisites()
    kwargs = {"document": json.dumps(values(prerequisite)).encode(), **prerequisite}
    kwargs[argument] = bytearray(kwargs[argument])
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_msal_browser_readiness(**kwargs)


@pytest.mark.parametrize(
    "argument",
    [
        "approved_pkce_runtime_control_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
@pytest.mark.parametrize("invalid", ["0" * 63, "0" * 65, "A" * 64, 0, True, None])
def test_digest_arguments_require_lowercase_sha256(argument, invalid):
    prerequisite = prerequisites()
    kwargs = {"document": json.dumps(values(prerequisite)).encode(), **prerequisite}
    kwargs[argument] = invalid
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_msal_browser_readiness(**kwargs)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (BaseExceptionGroup("outer", [SystemExit("secret")]), SystemExit),
        (
            BaseExceptionGroup(
                "outer",
                [SystemExit("secret"), KeyboardInterrupt("secret")],
            ),
            KeyboardInterrupt,
        ),
    ],
)
def test_nested_keyboard_interrupt_and_system_exit_are_preserved(
    monkeypatch, error, expected
):
    def fail(**kwargs):
        del kwargs
        raise error

    monkeypatch.setattr(
        module, "load_entra_calling_client_pkce_runtime_readiness", fail
    )
    with pytest.raises(expected) as caught:
        load_entra_calling_client_msal_browser_readiness(
            document=b"secret-step217-document", **prerequisites()
        )
    assert "secret" not in exception_material(caught.value)


def test_public_error_graph_and_production_frames_omit_raw_evidence(monkeypatch):
    secret = "secret-step217-evidence"

    def fail(**kwargs):
        del kwargs
        raise ExceptionGroup(secret, [ValueError(secret)])

    monkeypatch.setattr(
        module, "load_entra_calling_client_pkce_runtime_readiness", fail
    )
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError) as caught:
        load_entra_calling_client_msal_browser_readiness(
            document=secret.encode(), **prerequisites()
        )
    assert secret not in exception_material(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_every_receipt_boolean_is_exhaustively_integrity_enforced():
    receipt = load()
    bool_fields = [field.name for field in fields(receipt) if field.type == "bool"]
    assert set(bool_fields) == set(module._STRUCTURAL_TRUE_FIELDS) | set(
        module._DEFERRED_FALSE_FIELDS
    )
    assert set(module._STRUCTURAL_TRUE_FIELDS).isdisjoint(module._DEFERRED_FALSE_FIELDS)
    for name in bool_fields:
        forged = unsafe_replace(receipt, **{name: not getattr(receipt, name)})
        with pytest.raises(ValueError):
            forged.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_msal_browser_readiness_receipt(forged)


@pytest.mark.parametrize("invalid", [True, False, 0.0, "1", None, [], {}])
def test_every_receipt_count_rejects_wrong_exact_type(invalid):
    receipt = load()
    for name in module._COUNT_FIELDS:
        forged = unsafe_replace(receipt, **{name: invalid})
        with pytest.raises(ValueError):
            forged.__post_init__()


def test_every_public_receipt_string_is_exactly_enforced():
    receipt = load()
    for name in module._PUBLIC_STRING_FIELDS:
        forged = unsafe_replace(receipt, **{name: getattr(receipt, name) + "-wrong"})
        with pytest.raises(ValueError):
            forged.__post_init__()


def test_every_digest_rejects_shape_case_and_non_string():
    receipt = load()
    digest_fields = [
        field.name for field in fields(receipt) if field.name.endswith("_sha256")
    ]
    for name in digest_fields:
        for invalid in ("0" * 63, "A" * 64, 0, True, None):
            forged = unsafe_replace(receipt, **{name: invalid})
            with pytest.raises(ValueError):
                forged.__post_init__()


@pytest.mark.parametrize(
    "field",
    [
        "approved_inventory_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
        "approved_pkce_runtime_control_document_sha256",
    ],
)
def test_paired_source_digests_reject_valid_shape_mismatch(field):
    receipt = load()
    forged = unsafe_replace(receipt, **{field: "0" * 64})
    with pytest.raises(ValueError):
        forged.__post_init__()


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = render_entra_calling_client_msal_browser_readiness_receipt(receipt)
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(TypeError):
        render_entra_calling_client_msal_browser_readiness_receipt({})
    forged = unsafe_replace(receipt, activation_ready=True)
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_browser_readiness_receipt(forged)


def test_no_io_occurs_during_offline_validation(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("I/O was attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    receipt = load()
    assert receipt.filesystem_io_performed is False
    assert receipt.network_io_performed is False
    assert receipt.browser_io_performed is False


def test_source_ast_has_no_io_imports_and_receipt_fields_are_unique():
    source = inspect.getsource(module)
    tree = ast.parse(source)
    forbidden_roots = {"subprocess", "http", "requests", "socket", "ssl"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(forbidden_roots)
    receipt_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALBrowserReadinessReceipt"
    )
    names = [
        node.target.id
        for node in receipt_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(names) == len(set(names)) == len(fields(load()))
    assert set(module._PUBLIC_STRING_FIELDS).issubset(names)
    assert set(module._COUNT_FIELDS).issubset(names)


def test_exact_authority_custom_port_and_noncanonical_issuer_are_rejected():
    prerequisite = prerequisites()
    preview = replace(
        prerequisite["authentication_preview"],
        issuer=prerequisite["authentication_preview"].issuer + ":443",
    )
    prerequisite["authentication_preview"] = preview
    with pytest.raises(EntraCallingClientMSALBrowserReadinessError):
        load(prerequisite=prerequisite)


def test_step217_does_not_claim_frontend_package_or_runtime_state():
    receipt = load()
    false_names = {
        "package_registry_metadata_checked",
        "package_version_current_checked",
        "package_tarball_integrity_checked",
        "package_manager_selected",
        "dependency_lockfile_created",
        "frontend_source_tree_present_checked",
        "package_installed",
        "reviewed_candidate_approved_for_integration",
        "reviewed_candidate_compatible_with_step216",
        "package_selection_ready",
        "msal_configuration_implemented",
        "redirect_handler_executed",
        "revised_csp_deployed",
        "runtime_pkce_s256_checked",
        "authorization_code_redeemed",
        "real_engineer4me_api_call_checked",
        "activation_ready",
    }
    assert false_names.issubset(module._DEFERRED_FALSE_FIELDS)
    assert all(getattr(receipt, name) is False for name in false_names)
