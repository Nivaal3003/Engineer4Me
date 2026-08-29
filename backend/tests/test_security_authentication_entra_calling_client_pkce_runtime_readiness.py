"""Tests for offline Microsoft Entra SPA PKCE runtime readiness."""

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

import app.security.authentication_entra_calling_client_pkce_runtime_readiness as module
from app.security.authentication_entra_calling_client_pkce_runtime_readiness import (
    ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE,
    ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE,
    ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SOURCE,
    FUTURE_AUTHORIZATION_NAVIGATION_MODE,
    FUTURE_AUTHORIZATION_RESPONSE_MODE,
    FUTURE_AUTHORIZATION_RESPONSE_TYPE,
    FUTURE_NONCE_MAXIMUM_LENGTH,
    FUTURE_NONCE_MINIMUM_ENTROPY_BITS,
    FUTURE_OIDC_SCOPE_ORDER,
    FUTURE_PKCE_METHOD,
    FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH,
    FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS,
    FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH,
    FUTURE_STATE_MAXIMUM_LENGTH,
    FUTURE_STATE_MINIMUM_ENTROPY_BITS,
    FUTURE_TOKEN_FETCH_CACHE_MODE,
    FUTURE_TOKEN_FETCH_CREDENTIALS_MODE,
    FUTURE_TOKEN_FETCH_REDIRECT_MODE,
    FUTURE_TOKEN_GRANT_TYPE,
    FUTURE_TOKEN_REQUEST_CONTENT_TYPE,
    FUTURE_TOKEN_REQUEST_METHOD,
    FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS,
    FUTURE_TRANSACTION_STORAGE,
    MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_BYTES,
    EntraCallingClientPKCERuntimeReadinessError,
    EntraCallingClientPKCERuntimeReadinessReceipt,
    load_entra_calling_client_pkce_runtime_readiness,
    render_entra_calling_client_pkce_runtime_readiness_receipt,
)
from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    load_entra_calling_client_redirect_endpoint_readiness,
)
from tests import (
    test_security_authentication_entra_calling_client_redirect_endpoint_readiness as step214,
)


def prerequisites(redirect_uris=(step214.REDIRECT_URI,)):
    prior = step214.prerequisites(redirect_uris)
    redirect_values = step214.values(prior)
    redirect_document = json.dumps(
        redirect_values,
        separators=(",", ":"),
    ).encode()
    redirect_receipt = load_entra_calling_client_redirect_endpoint_readiness(
        document=redirect_document,
        **prior,
    )
    return {
        **prior,
        "redirect_endpoint_control_document": redirect_document,
        "approved_redirect_endpoint_control_document_sha256": (
            redirect_receipt.redirect_endpoint_control_document_sha256
        ),
    }


def values(prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return {
        "document_type": ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SOURCE,
        "approved_configuration_sha256": (
            prerequisite["authentication_preview"].configuration_sha256
        ),
        "approved_api_registration_document_sha256": prerequisite[
            "accepted_api_registration_document_sha256"
        ],
        "approved_calling_client_registration_document_sha256": prerequisite[
            "accepted_calling_client_registration_document_sha256"
        ],
        "approved_inventory_document_sha256": prerequisite[
            "approved_inventory_document_sha256"
        ],
        "approved_redirect_endpoint_control_document_sha256": prerequisite[
            "approved_redirect_endpoint_control_document_sha256"
        ],
        "control_profile": ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE,
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    body = values(prerequisite) if value is None else value
    return load_entra_calling_client_pkce_runtime_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
        **prerequisite,
    )


def framed(label, *values):
    digest = hashlib.sha256()
    for value in ("engineer4me-step216-v1", label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


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


def test_valid_profile_binds_sources_and_stays_fail_closed():
    receipt = load()
    assert receipt.receipt_type == ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE
    assert receipt.validation_scope == ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE
    assert receipt.control_profile == ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE
    assert receipt.desired_redirect_endpoint_count == 1
    assert receipt.desired_oidc_scope_count == 3
    assert receipt.desired_api_scope_count == 1
    assert receipt.desired_total_scope_count == 4
    assert all(
        getattr(receipt, name) is True for name in module._STRUCTURAL_TRUE_FIELDS
    )
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )
    assert receipt.runtime_connect_src_transition_required is True
    assert receipt.runtime_csp_transition_deployed is False
    assert receipt.activation_ready is False


def test_exact_public_protocol_constants_are_frozen():
    receipt = load()
    assert receipt.authorization_response_type == "code"
    assert receipt.authorization_response_mode == "query"
    assert receipt.token_grant_type == "authorization_code"
    assert receipt.pkce_method == "S256"
    assert receipt.transaction_storage == "sessionStorage"
    assert receipt.authorization_navigation_mode == "top_level_same_window"
    assert receipt.token_request_method == "POST"
    assert receipt.token_request_content_type == "application/x-www-form-urlencoded"
    assert receipt.token_fetch_credentials_mode == "omit"
    assert receipt.token_fetch_redirect_mode == "error"
    assert receipt.token_fetch_cache_mode == "no-store"
    assert FUTURE_AUTHORIZATION_RESPONSE_TYPE == "code"
    assert FUTURE_AUTHORIZATION_RESPONSE_MODE == "query"
    assert FUTURE_TOKEN_GRANT_TYPE == "authorization_code"
    assert FUTURE_PKCE_METHOD == "S256"
    assert FUTURE_TRANSACTION_STORAGE == "sessionStorage"
    assert FUTURE_AUTHORIZATION_NAVIGATION_MODE == "top_level_same_window"
    assert FUTURE_TOKEN_REQUEST_METHOD == "POST"
    assert FUTURE_TOKEN_REQUEST_CONTENT_TYPE == "application/x-www-form-urlencoded"
    assert FUTURE_TOKEN_FETCH_CREDENTIALS_MODE == "omit"
    assert FUTURE_TOKEN_FETCH_REDIRECT_MODE == "error"
    assert FUTURE_TOKEN_FETCH_CACHE_MODE == "no-store"


def test_entropy_bounds_and_expiry_profile_are_exact():
    receipt = load()
    assert receipt.pkce_verifier_minimum_entropy_bits == 256
    assert receipt.state_minimum_entropy_bits == 128
    assert receipt.nonce_minimum_entropy_bits == 128
    assert receipt.pkce_verifier_minimum_length == 43
    assert receipt.pkce_verifier_maximum_length == 128
    assert receipt.state_maximum_length == 512
    assert receipt.nonce_maximum_length == 512
    assert receipt.transaction_maximum_age_seconds == 600
    assert FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS == 256
    assert FUTURE_STATE_MINIMUM_ENTROPY_BITS == 128
    assert FUTURE_NONCE_MINIMUM_ENTROPY_BITS == 128
    assert FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH == 43
    assert FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH == 128
    assert FUTURE_STATE_MAXIMUM_LENGTH == 512
    assert FUTURE_NONCE_MAXIMUM_LENGTH == 512
    assert FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS == 600


def test_authorization_required_parameter_subset_excludes_verifier():
    prerequisite = prerequisites((step214.REDIRECT_URI, step214.REDIRECT_URI_2))
    projection = module._validated_projection(
        authentication_preview=prerequisite["authentication_preview"],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
    )
    plan = json.loads(module._authorization_request_template(projection))
    assert len(plan) == 2
    expected_endpoint = (
        f"https://synthetic.ciamlogin.com/{step214.TENANT_ID}/oauth2/v2.0/authorize"
    )
    expected_scope = f"openid profile offline_access api://{step214.API_APPLICATION_ID}/access_as_user"
    for entry, redirect_uri in zip(
        plan,
        (step214.REDIRECT_URI, step214.REDIRECT_URI_2),
        strict=True,
    ):
        assert entry["endpoint"] == expected_endpoint
        assert entry["navigation"] == "top_level_same_window"
        assert entry["projection"] == (
            "required_application_parameter_subset_not_wire_payload"
        )
        assert entry["supported_library_managed_parameters_may_be_added"] is True
        assert entry["parameters"] == [
            ["client_id", step214.CALLING_CLIENT_APPLICATION_ID],
            ["response_type", "code"],
            ["redirect_uri", redirect_uri],
            ["response_mode", "query"],
            ["scope", expected_scope],
            ["code_challenge", "<S256_BASE64URL_SHA256_OF_VERIFIER>"],
            ["code_challenge_method", "S256"],
            ["state", "<UNIQUE_OPAQUE_SUPPORTED_LIBRARY_STATE>"],
            ["nonce", "<UNIQUE_OPAQUE_SUPPORTED_LIBRARY_NONCE>"],
        ]
        flattened = json.dumps(entry)
        assert (
            "code_verifier"
            not in flattened.split('"parameters"')[1].split('"forbidden_parameters"')[0]
        )
        assert "client_secret" in entry["forbidden_parameters"]
        assert "login_hint" in entry["forbidden_parameters"]


def test_token_required_parameter_subset_is_public_client_post():
    prerequisite = prerequisites((step214.REDIRECT_URI,))
    projection = module._validated_projection(
        authentication_preview=prerequisite["authentication_preview"],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
    )
    plan = json.loads(module._token_request_template(projection))
    assert plan == [
        {
            "endpoint": f"https://synthetic.ciamlogin.com/{step214.TENANT_ID}/oauth2/v2.0/token",
            "method": "POST",
            "content_type": "application/x-www-form-urlencoded",
            "projection": "required_application_parameter_subset_not_wire_payload",
            "supported_library_managed_parameters_may_be_added": True,
            "browser_origin": "https://app.engineer4me.invalid",
            "fetch": {
                "credentials": "omit",
                "redirect": "error",
                "cache": "no-store",
                "retry_count": 0,
            },
            "form_fields": [
                ["client_id", step214.CALLING_CLIENT_APPLICATION_ID],
                ["grant_type", "authorization_code"],
                ["code", "<ONE_TIME_AUTHORIZATION_CODE>"],
                ["redirect_uri", step214.REDIRECT_URI],
                [
                    "scope",
                    f"openid profile offline_access api://{step214.API_APPLICATION_ID}/access_as_user",
                ],
                ["code_verifier", "<ONE_TIME_PKCE_VERIFIER>"],
            ],
            "forbidden_fields": [
                "client_secret",
                "client_assertion",
                "client_assertion_type",
                "password",
                "refresh_token",
            ],
            "authorization_header": None,
            "cookie": None,
            "maximum_request_bytes": 16_384,
            "maximum_response_bytes": 65_536,
        }
    ]


def test_csp_transition_is_explicit_seven_directive_future_state():
    prerequisite = prerequisites()
    projection = module._validated_projection(
        authentication_preview=prerequisite["authentication_preview"],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
    )
    profile = json.loads(module._runtime_csp_transition_profile(projection))
    assert profile["step215_current_exact_directive_count"] == 6
    assert profile["step215_current_connect_src_present"] is False
    assert profile["deployment_checked"] is False
    assert profile["endpoint_reproof_required"] is True
    assert profile["engineer4me_api_origin_policy_checked"] is False
    assert profile["token_exchange_intermediate_exact_directives"] == {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "connect-src": ["'self'", "https://synthetic.ciamlogin.com"],
        "base-uri": ["'none'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "form-action": ["'none'"],
    }


def test_storage_and_callback_profiles_are_exact():
    storage = json.loads(module._transaction_storage_profile())
    callback = json.loads(module._callback_validation_profile())
    assert storage["storage"] == "sessionStorage"
    assert storage["maximum_age_seconds"] == 600
    assert storage["single_use"] is True
    assert storage["local_storage_allowed"] is False
    assert storage["cookie_storage_allowed"] is False
    assert storage["url_storage_allowed"] is False
    assert storage["logged_values_allowed"] is False
    assert set(storage["values"]) == {"code_verifier", "state", "nonce"}
    assert storage["values"]["code_verifier"] == {
        "minimum_entropy_bits": 256,
        "encoding": "base64url_without_padding",
        "minimum_length": 43,
        "maximum_length": 128,
    }
    assert storage["values"]["state"] == {
        "minimum_entropy_bits": 128,
        "encoding": "opaque_supported_library_serialization",
        "maximum_length": 512,
    }
    assert storage["values"]["nonce"] == storage["values"]["state"]
    assert callback["response_exclusivity"] == "exactly_one_of_code_or_error"
    assert callback["state"] == "required_exact_single_use_unexpired_match"
    assert callback["raw_error_display"] is False
    assert callback["raw_value_logging"] is False
    assert callback["provider_parameter_parsing"] == (
        "supported_microsoft_authentication_library_required"
    )


def test_three_redirects_change_count_and_request_plan_hashes():
    one = load()
    three = load(
        prerequisite=prerequisites(
            (step214.REDIRECT_URI, step214.REDIRECT_URI_2, step214.REDIRECT_URI_3)
        )
    )
    assert one.desired_redirect_endpoint_count == 1
    assert three.desired_redirect_endpoint_count == 3
    assert (
        one.authorization_request_template_sha256
        != three.authorization_request_template_sha256
    )
    assert one.token_request_template_sha256 != three.token_request_template_sha256
    assert one.spa_redirect_uris_sha256 != three.spa_redirect_uris_sha256


def test_receipt_hashes_independently_bind_endpoints_scopes_and_profiles():
    prerequisite = prerequisites()
    receipt = load(prerequisite=prerequisite)
    origin = "https://synthetic.ciamlogin.com"
    authority = f"{origin}/{step214.TENANT_ID}"
    api_scope = f"api://{step214.API_APPLICATION_ID}/access_as_user"
    projection = module._validated_projection(
        authentication_preview=prerequisite["authentication_preview"],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
    )
    assert receipt.authorization_server_origin_sha256 == framed(
        "authorization_server_origin", origin
    )
    assert receipt.authorization_endpoint_sha256 == framed(
        "authorization_endpoint", f"{authority}/oauth2/v2.0/authorize"
    )
    assert receipt.token_endpoint_sha256 == framed(
        "token_endpoint", f"{authority}/oauth2/v2.0/token"
    )
    assert receipt.oidc_scope_set_sha256 == framed(
        "oidc_scope_set", "openid", "profile", "offline_access"
    )
    assert receipt.api_scope_sha256 == framed("api_scope", api_scope)
    assert receipt.complete_scope_set_sha256 == framed(
        "complete_scope_set", "openid", "profile", "offline_access", api_scope
    )
    assert receipt.authorization_request_template_sha256 == framed(
        "authorization_request_template",
        module._authorization_request_template(projection),
    )
    assert receipt.token_request_template_sha256 == framed(
        "token_request_template", module._token_request_template(projection)
    )
    assert receipt.runtime_csp_transition_profile_sha256 == framed(
        "runtime_csp_transition_profile",
        module._runtime_csp_transition_profile(projection),
    )


def test_receipt_is_privacy_minimized_for_all_raw_inputs():
    prerequisite = prerequisites(
        (step214.REDIRECT_URI, step214.REDIRECT_URI_2, step214.REDIRECT_URI_3)
    )
    rendered = render_entra_calling_client_pkce_runtime_readiness_receipt(
        load(prerequisite=prerequisite)
    )
    raw_values = (
        step214.TENANT_ID,
        step214.API_APPLICATION_ID,
        step214.API_APPLICATION_OBJECT_ID,
        step214.API_SCOPE_ID,
        step214.CALLING_CLIENT_APPLICATION_ID,
        step214.CALLING_CLIENT_OBJECT_ID,
        step214.API_SERVICE_PRINCIPAL_OBJECT_ID,
        step214.CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        step214.OWNER_ID,
        step214.OWNER_ID_2,
        step214.REDIRECT_URI,
        step214.REDIRECT_URI_2,
        step214.REDIRECT_URI_3,
        step214.ISSUER,
        "synthetic.ciamlogin.com",
        f"api://{step214.API_APPLICATION_ID}/access_as_user",
    )
    assert all(value not in rendered for value in raw_values)
    assert "code_verifier" not in rendered
    assert "authorization_code" in rendered  # fixed public grant literal only


@pytest.mark.parametrize(
    "field",
    (
        "document_type",
        "source",
        "control_profile",
        "approved_configuration_sha256",
        "approved_api_registration_document_sha256",
        "approved_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
    ),
)
def test_every_document_string_is_exact_or_digest_bound(field):
    prerequisite = prerequisites()
    value = values(prerequisite)
    value[field] = "0" * 64 if field.startswith("approved_") else "wrong"
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load(value=value, prerequisite=prerequisite)


@pytest.mark.parametrize("invalid", [True, 1.0, "1", None, [], {}])
def test_schema_version_requires_exact_integer_one(invalid):
    value = values()
    value["schema_version"] = invalid
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load(value=value)


def test_document_rejects_extra_missing_duplicate_and_nested_duplicate_keys():
    prerequisite = prerequisites()
    value = values(prerequisite)
    extra = {**value, "extra": True}
    missing = dict(value)
    del missing["control_profile"]
    for candidate in (extra, missing):
        with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
            load(value=candidate, prerequisite=prerequisite)
    duplicate = json.dumps(value)[:-1] + ',"source":"duplicate"}'
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load_entra_calling_client_pkce_runtime_readiness(
            document=duplicate.encode(),
            **prerequisite,
        )
    nested = json.dumps(value)[:-1] + ',"extra":{"x":1,"x":2}}'
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load_entra_calling_client_pkce_runtime_readiness(
            document=nested.encode(),
            **prerequisite,
        )


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"[]",
        b"null",
        b"{",
        b"\xff",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
    ],
)
def test_malformed_documents_fail_with_sanitized_public_error(document):
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError) as caught:
        load_entra_calling_client_pkce_runtime_readiness(
            document=document,
            **prerequisites(),
        )
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_document_size_depth_and_container_limits_fail_closed():
    prerequisite = prerequisites()
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load_entra_calling_client_pkce_runtime_readiness(
            document=b"{"
            + b" " * MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_BYTES
            + b"}",
            **prerequisite,
        )
    value = values(prerequisite)
    value["extra"] = {"a": {"b": {"c": 1}}}
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load(value=value, prerequisite=prerequisite)


def test_step214_preflight_runs_before_step216_document_parsing(monkeypatch):
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise ValueError("step214-first")

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_redirect_endpoint_readiness",
        fail,
    )
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load_entra_calling_client_pkce_runtime_readiness(
            document=b"not-json",
            **prerequisites(),
        )
    assert len(calls) == 1


def test_independently_approved_redirect_digest_is_required():
    prerequisite = prerequisites()
    prerequisite["approved_redirect_endpoint_control_document_sha256"] = "0" * 64
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError):
        load_entra_calling_client_pkce_runtime_readiness(
            document=json.dumps(values(prerequisite)).encode(),
            **prerequisite,
        )


@pytest.mark.parametrize(
    "argument",
    [
        "document",
        "redirect_endpoint_control_document",
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
    ],
)
def test_document_arguments_require_bytes(argument):
    prerequisite = prerequisites()
    kwargs = {
        "document": json.dumps(values(prerequisite)).encode(),
        **prerequisite,
    }
    kwargs[argument] = "not-bytes"
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_pkce_runtime_readiness(**kwargs)


@pytest.mark.parametrize(
    "argument",
    [
        "approved_redirect_endpoint_control_document_sha256",
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
def test_digest_arguments_require_exact_lower_sha256(argument):
    prerequisite = prerequisites()
    kwargs = {
        "document": json.dumps(values(prerequisite)).encode(),
        **prerequisite,
    }
    kwargs[argument] = "A" * 64
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_pkce_runtime_readiness(**kwargs)


def test_nested_keyboard_interrupt_and_system_exit_are_preserved(monkeypatch):
    prerequisite = prerequisites()
    document = json.dumps(values(prerequisite)).encode()

    def interrupt(**kwargs):
        del kwargs
        raise builtins.BaseExceptionGroup(
            "secret-group", [SystemExit("secret"), KeyboardInterrupt("secret")]
        )

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_redirect_endpoint_readiness",
        interrupt,
    )
    with pytest.raises(KeyboardInterrupt, match="readiness interrupted") as caught:
        load_entra_calling_client_pkce_runtime_readiness(
            document=document,
            **prerequisite,
        )
    assert "secret" not in exception_material(caught.value)


def test_public_error_graph_and_production_frames_omit_untrusted_values():
    secret = "step216-secret-sentinel"
    prerequisite = prerequisites()
    with pytest.raises(EntraCallingClientPKCERuntimeReadinessError) as caught:
        load_entra_calling_client_pkce_runtime_readiness(
            document=(
                f'{{"secret":"{secret}","nested":{{"value":"{step214.REDIRECT_URI}"}}}}'
            ).encode(),
            **prerequisite,
        )
    material = exception_material(caught.value)
    assert secret not in material
    assert step214.REDIRECT_URI not in material
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_every_receipt_boolean_is_exhaustively_integrity_enforced():
    receipt = load()
    bool_fields = {
        field.name
        for field in fields(receipt)
        if field.type is bool or field.type == "bool"
    }
    partition = set(module._STRUCTURAL_TRUE_FIELDS) | set(module._DEFERRED_FALSE_FIELDS)
    assert bool_fields == partition
    assert not set(module._STRUCTURAL_TRUE_FIELDS) & set(module._DEFERRED_FALSE_FIELDS)
    for field in module._STRUCTURAL_TRUE_FIELDS:
        tampered = unsafe_replace(receipt, **{field: False})
        with pytest.raises(ValueError):
            tampered.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_pkce_runtime_readiness_receipt(tampered)
    for field in module._DEFERRED_FALSE_FIELDS:
        tampered = unsafe_replace(receipt, **{field: True})
        with pytest.raises(ValueError):
            tampered.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_pkce_runtime_readiness_receipt(tampered)


def test_every_receipt_count_rejects_boolean_substitution():
    receipt = load()
    for field in module._COUNT_FIELDS:
        tampered = unsafe_replace(receipt, **{field: True})
        with pytest.raises(ValueError):
            tampered.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_pkce_runtime_readiness_receipt(tampered)


def test_every_public_receipt_string_is_exactly_enforced():
    receipt = load()
    for field in module._PUBLIC_STRING_FIELDS:
        tampered = unsafe_replace(receipt, **{field: "wrong"})
        with pytest.raises(ValueError):
            tampered.__post_init__()
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            tampered = unsafe_replace(receipt, **{field.name: "A" * 64})
            with pytest.raises(ValueError):
                tampered.__post_init__()


@pytest.mark.parametrize(
    "field",
    [
        "approved_inventory_document_sha256",
        "inventory_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
        "redirect_endpoint_control_document_sha256",
    ],
)
def test_receipt_paired_source_digests_reject_valid_shape_mismatch(field):
    receipt = load()
    tampered = unsafe_replace(receipt, **{field: "0" * 64})
    with pytest.raises(ValueError):
        tampered.__post_init__()
    with pytest.raises(ValueError):
        render_entra_calling_client_pkce_runtime_readiness_receipt(tampered)


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = render_entra_calling_client_pkce_runtime_readiness_receipt(receipt)
    assert rendered == json.dumps(
        json.loads(rendered),
        sort_keys=True,
        separators=(",", ":"),
    )
    with pytest.raises(TypeError):
        render_entra_calling_client_pkce_runtime_readiness_receipt(object())
    with pytest.raises(ValueError):
        render_entra_calling_client_pkce_runtime_readiness_receipt(
            unsafe_replace(receipt, activation_ready=True)
        )


def test_no_io_occurs_during_offline_validation(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("I/O is forbidden")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    receipt = load()
    assert receipt.provider_io_performed is False
    assert receipt.browser_io_performed is False
    assert receipt.network_io_performed is False


def test_source_ast_has_no_io_imports_and_receipt_fields_are_unique():
    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"requests", "httpx", "socket", "ssl", "subprocess"}
    receipt_fields = [
        field.name for field in fields(EntraCallingClientPKCERuntimeReadinessReceipt)
    ]
    assert len(receipt_fields) == len(set(receipt_fields))
    assert "client_secret" not in receipt_fields
    assert "code_verifier" not in receipt_fields
    assert "authorization_code" not in receipt_fields


def test_authority_derivation_rejects_noncanonical_custom_port():
    prerequisite = prerequisites()
    preview = replace(
        prerequisite["authentication_preview"],
        issuer=f"https://synthetic.ciamlogin.com:443/{step214.TENANT_ID}/v2.0",
    )
    with pytest.raises(ValueError, match="canonical authority"):
        module._validated_projection(
            authentication_preview=preview,
            calling_client_registration_document=prerequisite[
                "calling_client_registration_document"
            ],
        )


def test_scope_order_is_exact_and_no_graph_scope_is_added():
    assert FUTURE_OIDC_SCOPE_ORDER == ("openid", "profile", "offline_access")
    prerequisite = prerequisites()
    projection = module._validated_projection(
        authentication_preview=prerequisite["authentication_preview"],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
    )
    authorization = module._authorization_request_template(projection).decode()
    assert "User.Read" not in authorization
    assert "Directory.Read" not in authorization
    assert "https://graph.microsoft.com" not in authorization


def test_runtime_csp_gap_prevents_activation_claim():
    receipt = load()
    assert receipt.normalized_required_parameter_subsets_only is True
    assert receipt.exact_runtime_wire_query_checked is False
    assert receipt.exact_runtime_wire_form_checked is False
    assert receipt.step215_six_directive_csp_token_exchange_gap_recorded is True
    assert receipt.runtime_connect_src_transition_required is True
    assert receipt.endpoint_reproof_after_csp_transition_required is True
    assert receipt.runtime_csp_transition_deployed is False
    assert receipt.runtime_csp_transition_endpoint_reproved is False
    assert receipt.authorization_server_discovery_checked is False
    assert receipt.authorization_server_reachability_checked is False
    assert receipt.external_tenant_classification_checked is False
    assert receipt.live_user_flow_association_checked is False
    assert receipt.live_delegated_consent_checked is False
    assert receipt.runtime_redirect_uri_match_checked is False
    assert receipt.runtime_browser_origin_checked is False
    assert receipt.runtime_no_client_secret_checked is False
    assert receipt.runtime_oidc_scopes_requested_checked is False
    assert receipt.runtime_api_scope_requested_checked is False
    assert receipt.token_endpoint_cors_checked is False
    assert receipt.activation_ready is False
