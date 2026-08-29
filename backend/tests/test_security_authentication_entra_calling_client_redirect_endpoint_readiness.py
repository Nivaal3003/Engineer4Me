"""Tests for offline SPA redirect-endpoint security-control readiness."""

from __future__ import annotations

import builtins
import hashlib
import inspect
import json
import os
import socket
import ssl
import urllib.request
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_redirect_endpoint_readiness as module
from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
)
from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE,
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE,
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE,
    FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES,
    MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_BYTES,
    EntraCallingClientRedirectEndpointReadinessError,
    load_entra_calling_client_redirect_endpoint_readiness,
    render_entra_calling_client_redirect_endpoint_readiness_receipt,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    ENTRA_CALLING_CLIENT_ARCHITECTURE,
    ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
    load_entra_calling_client_registration_readiness,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)

TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
API_APPLICATION_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
API_SCOPE_ID = "dddddddd-eeee-4fff-8aaa-bbbbbbbb0500"
CALLING_CLIENT_APPLICATION_ID = "11111111-2222-4333-8444-555555555555"
CALLING_CLIENT_OBJECT_ID = "22222222-3333-4444-8555-666666666666"
API_SERVICE_PRINCIPAL_OBJECT_ID = "33333333-4444-4555-8666-777777777777"
CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID = "44444444-5555-4666-8777-888888888888"
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
REDIRECT_URI = "https://app.engineer4me.invalid/auth/callback"
REDIRECT_URI_2 = "https://app.engineer4me.invalid/auth/silent-callback"
REDIRECT_URI_3 = "https://portal.engineer4me.invalid/auth/callback"
ISSUER = f"https://synthetic.ciamlogin.com/{TENANT_ID}/v2.0"


def authentication_preview():
    document = {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": API_APPLICATION_ID,
            "jwks_url": "https://synthetic.ciamlogin.com/discovery/v2.0/keys",
            "algorithms": ["RS256"],
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": TENANT_ID,
            "microsoft_entra_api_application_id": API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": "access_as_user",
            "microsoft_entra_calling_client_application_id": (
                CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": "0",
        },
    }
    return load_authentication_readiness_document(json.dumps(document).encode()).preview


def api_registration_values(preview):
    return {
        "document_type": ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "approved_configuration_sha256": preview.configuration_sha256,
        "registration": {
            "tenant_id": TENANT_ID,
            "api_application_id": API_APPLICATION_ID,
            "application_object_id": API_APPLICATION_OBJECT_ID,
            "display_name": "Engineer4Me API",
            "description": None,
            "notes": None,
            "marketing_url": None,
            "privacy_statement_url": None,
            "support_url": None,
            "terms_of_service_url": None,
            "logo_configured": False,
            "owner_object_ids": [OWNER_ID],
            "sign_in_audience": "AzureADMyOrg",
            "requested_access_token_version": 2,
            "accept_mapped_claims": False,
            "identifier_uris": [f"api://{API_APPLICATION_ID}"],
            "delegated_scopes": [
                {
                    "scope_id": API_SCOPE_ID,
                    "value": "access_as_user",
                    "consent": "admins_only",
                    "enabled": True,
                    "admin_consent_display_name": (
                        "Access Engineer4Me as the signed-in user"
                    ),
                    "admin_consent_description": (
                        "Allow this application to access Engineer4Me as the "
                        "signed-in user."
                    ),
                    "user_consent_display_name": None,
                    "user_consent_description": None,
                }
            ],
            "web_redirect_uris": [],
            "spa_redirect_uris": [],
            "public_client_redirect_uris": [],
            "implicit_access_token_enabled": False,
            "implicit_id_token_enabled": False,
            "public_client_fallback_enabled": False,
            "password_credential_ids": [],
            "key_credential_ids": [],
            "federated_identity_credential_ids": [],
            "app_role_ids": [],
            "preauthorized_client_application_ids": [],
            "known_client_application_ids": [],
            "required_resource_application_ids": [],
            "optional_claims_configured": False,
            "group_membership_claims_configured": False,
            "token_encryption_key_configured": False,
            "add_in_ids": [],
            "home_page_url": None,
            "logout_url": None,
        },
    }


def calling_client_values(preview, api_receipt, redirect_uris):
    return {
        "document_type": ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "registration": {
            "tenant_id": TENANT_ID,
            "api_application_id": API_APPLICATION_ID,
            "api_application_object_id": API_APPLICATION_OBJECT_ID,
            "api_delegated_scope_id": API_SCOPE_ID,
            "calling_client_application_id": CALLING_CLIENT_APPLICATION_ID,
            "calling_client_application_object_id": CALLING_CLIENT_OBJECT_ID,
            "display_name": "Engineer4Me Web",
            "description": None,
            "notes": None,
            "marketing_url": None,
            "privacy_statement_url": None,
            "support_url": None,
            "terms_of_service_url": None,
            "desired_logo_configured": False,
            "owner_object_ids": [OWNER_ID, OWNER_ID_2],
            "desired_sign_in_audience": "AzureADMyOrg",
            "desired_client_architecture": ENTRA_CALLING_CLIENT_ARCHITECTURE,
            "desired_browser_flow": "authorization_code_pkce",
            "desired_pkce_method": "S256",
            "desired_client_authentication_method": "none",
            "desired_authorization_code_flow_enabled": True,
            "desired_pkce_required": True,
            "spa_redirect_uris": list(redirect_uris),
            "web_redirect_uris": [],
            "public_client_redirect_uris": [],
            "desired_implicit_access_token_enabled": False,
            "desired_implicit_id_token_enabled": False,
            "desired_public_client_fallback_enabled": False,
            "desired_native_authentication_apis_enabled": "none",
            "desired_device_only_auth_supported": False,
            "desired_device_code_flow_enabled": False,
            "desired_resource_owner_password_flow_enabled": False,
            "desired_client_credentials_flow_enabled": False,
            "desired_on_behalf_of_flow_enabled": False,
            "password_credential_ids": [],
            "key_credential_ids": [],
            "federated_identity_credential_ids": [],
            "required_resource_access": [
                {
                    "resource_application_id": API_APPLICATION_ID,
                    "delegated_scope_id": API_SCOPE_ID,
                    "permission_type": "Scope",
                    "scope_value": "access_as_user",
                }
            ],
            "microsoft_graph_permission_ids": [],
            "identifier_uris": [],
            "exposed_delegated_scope_ids": [],
            "app_role_ids": [],
            "preauthorized_client_application_ids": [],
            "known_client_application_ids": [],
            "desired_optional_claims_configured": False,
            "desired_group_membership_claims_configured": False,
            "desired_token_encryption_key_configured": False,
            "desired_api_accept_mapped_claims": False,
            "desired_oauth2_required_post_response": False,
            "add_in_ids": [],
            "desired_runtime_oidc_scopes": ["offline_access", "openid", "profile"],
            "desired_runtime_api_scope": (f"api://{API_APPLICATION_ID}/access_as_user"),
            "home_page_url": None,
            "logout_url": None,
        },
    }


def inventory_values(preview, registration):
    return {
        "document_type": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": registration[
            "accepted_api_registration_document_sha256"
        ],
        "approved_calling_client_registration_document_sha256": registration[
            "accepted_calling_client_registration_document_sha256"
        ],
        "inventory": {
            "tenant_id": TENANT_ID,
            "applications": [
                {
                    "role": "api",
                    "application_id": API_APPLICATION_ID,
                    "application_object_id": API_APPLICATION_OBJECT_ID,
                },
                {
                    "role": "calling_client",
                    "application_id": CALLING_CLIENT_APPLICATION_ID,
                    "application_object_id": CALLING_CLIENT_OBJECT_ID,
                },
            ],
            "service_principals": [
                {
                    "role": "api",
                    "service_principal_object_id": API_SERVICE_PRINCIPAL_OBJECT_ID,
                    "application_id": API_APPLICATION_ID,
                    "application_owner_organization_id": TENANT_ID,
                    "service_principal_type": "Application",
                    "account_enabled": True,
                    "disabled_by_microsoft_status": None,
                },
                {
                    "role": "calling_client",
                    "service_principal_object_id": (
                        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID
                    ),
                    "application_id": CALLING_CLIENT_APPLICATION_ID,
                    "application_owner_organization_id": TENANT_ID,
                    "service_principal_type": "Application",
                    "account_enabled": True,
                    "disabled_by_microsoft_status": "NotDisabled",
                },
            ],
        },
    }


def prerequisites(redirect_uris=(REDIRECT_URI,)):
    preview = authentication_preview()
    api_document = json.dumps(api_registration_values(preview)).encode()
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    client_document = json.dumps(
        calling_client_values(preview, api_receipt, redirect_uris)
    ).encode()
    client_receipt = load_entra_calling_client_registration_readiness(
        document=client_document,
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    registration = {
        "api_registration_document": api_document,
        "accepted_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "calling_client_registration_document": client_document,
        "accepted_calling_client_registration_document_sha256": (
            client_receipt.client_registration_document_sha256
        ),
    }
    inventory_document = json.dumps(inventory_values(preview, registration)).encode()
    inventory_receipt = load_entra_application_service_principal_inventory_readiness(
        document=inventory_document,
        authentication_preview=preview,
        **registration,
    )
    return {
        "authentication_preview": preview,
        **registration,
        "inventory_document": inventory_document,
        "approved_inventory_document_sha256": (
            inventory_receipt.inventory_document_sha256
        ),
    }


def values(prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return {
        "document_type": ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE,
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
        "control_profile": ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE,
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return load_entra_calling_client_redirect_endpoint_readiness(
        document=json.dumps(
            values(prerequisite) if value is None else value,
            separators=(",", ":"),
        ).encode(),
        **prerequisite,
    )


def test_valid_minimum_profile_binds_every_prerequisite_and_defers_live_state():
    receipt = load()
    assert receipt.receipt_type == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE
    assert receipt.source == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE
    assert receipt.validation_scope == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE
    assert (
        receipt.control_profile
        == ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE
    )
    assert receipt.desired_redirect_endpoint_count == 1
    assert receipt.desired_distinct_hostname_count == 1
    assert receipt.future_dns_resolution_call_count == 1
    assert receipt.future_https_request_count_per_endpoint == 10
    assert receipt.future_total_https_request_count == 10
    assert receipt.future_open_redirect_vector_count == 8
    for name in module._STRUCTURAL_TRUE_FIELDS:
        assert getattr(receipt, name) is True
    for name in module._DEFERRED_FALSE_FIELDS:
        assert getattr(receipt, name) is False


def test_three_redirects_derive_exact_counts_and_distinct_hosts():
    prerequisite = prerequisites((REDIRECT_URI, REDIRECT_URI_2, REDIRECT_URI_3))
    receipt = load(prerequisite=prerequisite)
    assert receipt.desired_redirect_endpoint_count == 3
    assert receipt.desired_distinct_hostname_count == 2
    assert receipt.future_dns_resolution_call_count == 2
    assert receipt.future_total_https_request_count == 30


def test_shared_hostname_is_deduplicated_only_for_future_dns_plan():
    receipt = load(prerequisite=prerequisites((REDIRECT_URI, REDIRECT_URI_2)))
    assert receipt.desired_redirect_endpoint_count == 2
    assert receipt.desired_distinct_hostname_count == 1
    assert receipt.future_dns_resolution_call_count == 1
    assert receipt.future_total_https_request_count == 20


def test_future_request_plan_is_exact_and_each_vector_uses_baseline_headers():
    redirects = (REDIRECT_URI, REDIRECT_URI_2)
    plan = json.loads(module._future_request_plan(redirects))
    assert len(plan) == 20
    expected_vectors = [
        "continue",
        "next",
        "redirect",
        "redirect_uri",
        "return",
        "returnUrl",
        "target",
        "url",
    ]
    assert list(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES) == expected_vectors
    assert FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN == "https://attacker.invalid"
    assert FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET == (
        "https://attacker.invalid/steal"
    )
    encoded_target = "https%3A%2F%2Fattacker.invalid%2Fsteal"
    baseline_headers = [["Accept", "text/html"], ["Accept-Encoding", "identity"]]
    for endpoint_index, redirect_uri in enumerate(redirects):
        entries = plan[endpoint_index * 10 : endpoint_index * 10 + 10]
        assert entries[0]["kind"] == "baseline"
        assert entries[0]["url"] == redirect_uri
        assert entries[0]["headers"] == baseline_headers
        assert entries[1]["kind"] == "hostile_origin"
        assert entries[1]["headers"] == baseline_headers + [
            ["Origin", "https://attacker.invalid"]
        ]
        for offset, vector_name in enumerate(expected_vectors, start=2):
            entry = entries[offset]
            assert entry["kind"] == "bounded_open_redirect_vector"
            assert entry["vector_name"] == vector_name
            assert entry["url"] == (f"{redirect_uri}?{vector_name}={encoded_target}")
            assert entry["headers"] == baseline_headers
            assert "Origin" not in str(entry["headers"])
        for entry in entries:
            assert entry["method"] == "GET"
            assert entry["port"] == 443
            assert entry["body"] is None
            assert entry["authorization"] is None
            assert entry["cookie"] is None
            assert entry["proxy"] is False
            assert entry["follow_redirects"] is False
            assert entry["retries"] == 0
            assert entry["compression"] is False


def test_fixed_header_csp_html_and_vector_profiles_are_complete():
    headers = json.loads(module._security_header_profile())
    assert headers == {
        "forbidden_response_headers": [
            "location",
            "set-cookie",
            "content-encoding",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ],
        "strict_transport_security": {
            "required": True,
            "minimum_max_age_seconds": 31_536_000,
        },
        "referrer-policy": "no-referrer",
        "cache-control_required_directive": "no-store",
        "x-content-type-options": "nosniff",
    }
    csp = json.loads(module._content_security_policy_profile())
    assert csp["required_directives"] == {
        "base-uri": ["'none'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "form-action": ["'none'"],
        "default-src": ["'self'"],
        "script-src": ["'self'"],
    }
    assert csp["forbidden_source_expressions"] == [
        "*",
        "http:",
        "https:",
        "data:",
        "blob:",
        "filesystem:",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
    ]
    assert csp["forbidden_reporting_directives"] == ["report-uri", "report-to"]
    html = json.loads(module._html_profile())
    assert html["forbidden_elements"] == ["base", "form", "iframe", "object", "embed"]
    assert html["forbidden_behaviors"] == [
        "meta_refresh",
        "inline_script",
        "inline_event_handler",
    ]
    assert html["analysis_scope"] == "static HTML URL-bearing attributes only"
    assert html["allowed_static_url_bearing_attributes"] == (
        "same-origin root-relative paths only"
    )
    assert html["all_other_static_url_forms_forbidden"] is True
    assert html["forbidden_static_url_forms"] == [
        "cross-origin",
        "protocol-relative",
        "javascript:",
        "data:",
        "blob:",
        "filesystem:",
    ]
    vectors = json.loads(module._open_redirect_vector_plan())
    assert vectors["ordered_names"] == list(
        FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
    )
    assert vectors["claim_boundary"] == "bounded_server_side_vector_set_only"


def test_rendered_receipt_is_canonical_private_and_complete():
    prerequisite = prerequisites((REDIRECT_URI, REDIRECT_URI_2, REDIRECT_URI_3))
    receipt = load(prerequisite=prerequisite)
    rendered = render_entra_calling_client_redirect_endpoint_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert set(parsed) == {field.name for field in fields(receipt)}
    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    for raw in (
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SCOPE_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        API_SERVICE_PRINCIPAL_OBJECT_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        OWNER_ID,
        OWNER_ID_2,
        REDIRECT_URI,
        REDIRECT_URI_2,
        REDIRECT_URI_3,
        "app.engineer4me.invalid",
        "portal.engineer4me.invalid",
        ISSUER,
        "https://synthetic.ciamlogin.com/discovery/v2.0/keys",
        f"api://{API_APPLICATION_ID}/access_as_user",
        "access_as_user",
        prerequisite["api_registration_document"].decode(),
        prerequisite["calling_client_registration_document"].decode(),
        prerequisite["inventory_document"].decode(),
    ):
        assert raw not in rendered
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            digest = getattr(receipt, field.name)
            assert len(digest) == 64
            assert digest == digest.lower()
            int(digest, 16)


def test_document_digest_is_canonical_across_key_order_and_whitespace():
    prerequisite = prerequisites()
    original = values(prerequisite)
    reversed_value = dict(reversed(list(original.items())))
    first = load_entra_calling_client_redirect_endpoint_readiness(
        document=json.dumps(original, indent=2).encode(),
        **prerequisite,
    )
    second = load_entra_calling_client_redirect_endpoint_readiness(
        document=json.dumps(reversed_value, separators=(",", ":")).encode(),
        **prerequisite,
    )
    assert first == second


def test_document_has_no_redirect_or_step213_input_surface():
    value = values()
    assert "redirect" not in " ".join(value).lower()
    signature = inspect.signature(load_entra_calling_client_redirect_endpoint_readiness)
    assert not any("step213" in name.lower() for name in signature.parameters)
    assert not any("probe" in name.lower() for name in signature.parameters)
    for forbidden in (
        "redirect_uris",
        "spa_redirect_uris",
        "redirect_endpoints",
        "step213_receipt",
        "registration_probe_receipt",
    ):
        changed = values()
        changed[forbidden] = []
        with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
            load(changed)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("document_type", "wrong"),
        ("document_type", None),
        ("schema_version", 2),
        ("schema_version", True),
        ("schema_version", "1"),
        ("source", "microsoft_graph_v1_0"),
        ("source", None),
        ("control_profile", "custom"),
        ("control_profile", None),
    ],
)
def test_document_requires_exact_contract_scalars(field, replacement):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)


@pytest.mark.parametrize(
    "field",
    [
        "document_type",
        "schema_version",
        "source",
        "approved_configuration_sha256",
        "approved_api_registration_document_sha256",
        "approved_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
        "control_profile",
    ],
)
def test_document_rejects_every_missing_or_null_field(field):
    value = values()
    value.pop(field)
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)
    value = values()
    value[field] = None
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)


@pytest.mark.parametrize(
    "field",
    [
        "approved_configuration_sha256",
        "approved_api_registration_document_sha256",
        "approved_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
def test_document_rejects_wrong_uppercase_or_nonstring_digest(field):
    value = values()
    value[field] = "0" * 64
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)
    value = values()
    value[field] = "A" * 64
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)
    value = values()
    value[field] = 1
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value)


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"not-json",
        b"[]",
        b"null",
        b'"text"',
        b"\xff",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
    ],
)
def test_document_rejects_empty_invalid_nonobject_utf8_or_nonfinite(document):
    prerequisite = prerequisites()
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load_entra_calling_client_redirect_endpoint_readiness(
            document=document,
            **prerequisite,
        )


def test_document_rejects_duplicate_deep_wide_and_oversize_structures():
    prerequisite = prerequisites()
    duplicate = (
        b'{"document_type":"'
        + ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_TYPE.encode()
        + b'","document_type":"duplicate"}'
    )
    candidates = [
        duplicate,
        json.dumps({"a": {"b": {"c": {"d": 1}}}}).encode(),
        json.dumps({str(index): {} for index in range(10)}).encode(),
        b"{"
        + b'"padding":"'
        + b"x" * MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_BYTES
        + b'"}',
    ]
    for document in candidates:
        with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
            load_entra_calling_client_redirect_endpoint_readiness(
                document=document,
                **prerequisite,
            )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("document", "text"),
        ("document", bytearray(b"{}")),
        ("authentication_preview", None),
        ("api_registration_document", "text"),
        ("calling_client_registration_document", "text"),
        ("inventory_document", "text"),
        ("accepted_api_registration_document_sha256", None),
        ("accepted_api_registration_document_sha256", "0"),
        ("accepted_calling_client_registration_document_sha256", None),
        ("approved_inventory_document_sha256", None),
    ],
)
def test_public_argument_type_and_digest_shape_failures_remain_type_error(
    field,
    replacement,
):
    prerequisite = prerequisites()
    arguments = {
        "document": json.dumps(values(prerequisite)).encode(),
        **prerequisite,
    }
    arguments[field] = replacement
    with pytest.raises(TypeError) as captured:
        load_entra_calling_client_redirect_endpoint_readiness(**arguments)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "field",
    [
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
def test_prerequisite_digests_cannot_be_swapped_or_reblessed(field):
    prerequisite = prerequisites()
    prerequisite[field] = "0" * 64
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(prerequisite=prerequisite)


def test_inventory_identity_mapping_tamper_cannot_be_reblessed():
    prerequisite = prerequisites()
    inventory = json.loads(prerequisite["inventory_document"])
    inventory["inventory"]["service_principals"][1]["application_id"] = (
        API_APPLICATION_ID
    )
    prerequisite["inventory_document"] = json.dumps(inventory).encode()
    prerequisite["approved_inventory_document_sha256"] = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(prerequisite=prerequisite)


def _canonical_document_digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_fully_reblessed_api_application_identity_tamper_fails_configuration_binding():
    prerequisite = prerequisites()
    replacement = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
    api = json.loads(prerequisite["api_registration_document"])
    api["registration"]["api_application_id"] = replacement
    api["registration"]["identifier_uris"] = [f"api://{replacement}"]
    api_digest = _canonical_document_digest(api)

    client = json.loads(prerequisite["calling_client_registration_document"])
    client["approved_api_registration_document_sha256"] = api_digest
    client["registration"]["api_application_id"] = replacement
    client["registration"]["required_resource_access"][0]["resource_application_id"] = (
        replacement
    )
    client["registration"]["desired_runtime_api_scope"] = (
        f"api://{replacement}/access_as_user"
    )
    client_digest = _canonical_document_digest(client)

    inventory = json.loads(prerequisite["inventory_document"])
    inventory["approved_api_registration_document_sha256"] = api_digest
    inventory["approved_calling_client_registration_document_sha256"] = client_digest
    inventory["inventory"]["applications"][0]["application_id"] = replacement
    inventory["inventory"]["service_principals"][0]["application_id"] = replacement
    inventory_digest = _canonical_document_digest(inventory)

    prerequisite.update(
        api_registration_document=json.dumps(api).encode(),
        accepted_api_registration_document_sha256=api_digest,
        calling_client_registration_document=json.dumps(client).encode(),
        accepted_calling_client_registration_document_sha256=client_digest,
        inventory_document=json.dumps(inventory).encode(),
        approved_inventory_document_sha256=inventory_digest,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(prerequisite=prerequisite)


def test_fully_reblessed_calling_client_identity_tamper_fails_configuration_binding():
    prerequisite = prerequisites()
    replacement = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
    client = json.loads(prerequisite["calling_client_registration_document"])
    client["registration"]["calling_client_application_id"] = replacement
    client_digest = _canonical_document_digest(client)

    inventory = json.loads(prerequisite["inventory_document"])
    inventory["approved_calling_client_registration_document_sha256"] = client_digest
    inventory["inventory"]["applications"][1]["application_id"] = replacement
    inventory["inventory"]["service_principals"][1]["application_id"] = replacement
    inventory_digest = _canonical_document_digest(inventory)

    prerequisite.update(
        calling_client_registration_document=json.dumps(client).encode(),
        accepted_calling_client_registration_document_sha256=client_digest,
        inventory_document=json.dumps(inventory).encode(),
        approved_inventory_document_sha256=inventory_digest,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(prerequisite=prerequisite)


def test_prerequisite_validation_finishes_before_step214_document_trust(monkeypatch):
    prerequisite = prerequisites()
    inventory = json.loads(prerequisite["inventory_document"])
    inventory["source"] = "untrusted_inventory_source"
    prerequisite["inventory_document"] = json.dumps(inventory).encode()
    prerequisite["approved_inventory_document_sha256"] = _canonical_document_digest(
        inventory
    )
    called = False

    def forbidden_document_validation(parsed):
        del parsed
        nonlocal called
        called = True
        raise AssertionError("Step 214 document was trusted early")

    monkeypatch.setattr(
        module,
        "_require_exact_document_scalars",
        forbidden_document_validation,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError):
        load(value=values(prerequisite), prerequisite=prerequisite)
    assert called is False


@pytest.mark.parametrize(
    "redirects",
    [
        [],
        [REDIRECT_URI, REDIRECT_URI],
        [REDIRECT_URI_2, REDIRECT_URI],
        ["http://app.engineer4me.invalid/auth/callback"],
        ["https://app.engineer4me.invalid/auth/callback?next=x"],
        ["https://app.engineer4me.invalid/auth/callback#fragment"],
        ["https://app.engineer4me.invalid:443/auth/callback"],
        ["https://127.0.0.1/auth/callback"],
        ["https://localhost/auth/callback"],
        ["https://xn--e1afmkfd.invalid/auth/callback"],
        ["https://app.engineer4me.invalid/auth/%63allback"],
        ["https://app.engineer4me.invalid/auth/../callback"],
        ["https://app.engineer4me.invalid/auth\\callback"],
        ["https://*.engineer4me.invalid/auth/callback"],
    ],
)
def test_invalid_step205_redirect_sets_fail_before_step214_document_trust(redirects):
    preview = authentication_preview()
    api_document = json.dumps(api_registration_values(preview)).encode()
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    client_document = json.dumps(
        calling_client_values(preview, api_receipt, redirects)
    ).encode()
    with pytest.raises(ValueError):
        load_entra_calling_client_registration_readiness(
            document=client_document,
            authentication_preview=preview,
            api_registration_document=api_document,
            accepted_api_registration_document_sha256=(
                api_receipt.registration_document_sha256
            ),
        )


def test_receipt_post_init_and_renderer_reject_every_field_tamper():
    receipt = load()
    receipt_fields = fields(receipt)
    assert len({field.name for field in receipt_fields}) == len(receipt_fields)
    for field in receipt_fields:
        name = field.name
        original = getattr(receipt, name)
        if name.endswith("_sha256"):
            replacement = "g" * 64
        elif name in module._PUBLIC_STRING_FIELDS:
            replacement = object()
        elif type(original) is int:
            replacement = True
        elif type(original) is bool:
            replacement = not original
        else:
            raise AssertionError(f"unclassified receipt field: {name}")
        changed = object.__new__(type(receipt))
        for candidate in receipt_fields:
            object.__setattr__(
                changed,
                candidate.name,
                replacement
                if candidate.name == name
                else getattr(receipt, candidate.name),
            )
        with pytest.raises(ValueError):
            changed.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_redirect_endpoint_readiness_receipt(changed)


def test_cors_vector_and_runtime_claim_boundaries_remain_precise():
    receipt = load()
    assert receipt.acao_header_absent_required is True
    assert receipt.acac_header_absent_required is True
    assert receipt.redirect_application_cors_checked is False
    assert receipt.entra_token_endpoint_cors_checked is False
    assert receipt.bounded_server_side_redirect_vectors_rejected is False
    assert receipt.open_redirect_behavior_checked is False
    assert receipt.runtime_pkce_s256_checked is False
    assert receipt.application_mutation_performed is False
    assert receipt.endpoint_mutation_performed is False
    assert receipt.activation_ready is False


def test_loader_performs_no_file_environment_dns_tls_or_http_io(monkeypatch):
    prerequisite = prerequisites()

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("I/O was attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    receipt = load(prerequisite=prerequisite)
    assert receipt.provider_io_performed is False
    assert receipt.network_io_performed is False


def test_untrusted_exception_graph_is_scrubbed_and_internal_typeerror_is_not_input_error(
    monkeypatch,
):
    prerequisite = prerequisites()
    secrets = [TENANT_ID, REDIRECT_URI, "Authorization: Bearer secret-token"]
    originals = []

    def fail(**kwargs):
        del kwargs
        try:
            inner = RuntimeError(secrets[2])
            originals.append(inner)
            raise inner
        except RuntimeError as inner:
            outer = TypeError(f"{secrets[0]} {secrets[1]}")
            originals.append(outer)
            raise outer from inner

    monkeypatch.setattr(
        module,
        "load_entra_application_service_principal_inventory_readiness",
        fail,
    )
    with pytest.raises(EntraCallingClientRedirectEndpointReadinessError) as captured:
        load(prerequisite=prerequisite)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
    rendered = repr(captured.value)
    assert all(secret not in rendered for secret in secrets)
    assert len(originals) == 2
    for original in originals:
        assert original.args == ()
        assert original.__traceback__ is None
        assert original.__context__ is None
        assert original.__cause__ is None
        assert all(secret not in repr(original) for secret in secrets)
    traceback = captured.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename == module.__file__:
            local_text = repr(traceback.tb_frame.f_locals)
            assert all(secret not in local_text for secret in secrets)
        traceback = traceback.tb_next


@pytest.mark.parametrize(
    ("error_type", "expected_type"),
    [(KeyboardInterrupt, KeyboardInterrupt), (SystemExit, SystemExit)],
)
def test_interrupt_and_termination_are_fresh_context_free(
    monkeypatch, error_type, expected_type
):
    prerequisite = prerequisites()
    originals = []

    def fail(**kwargs):
        del kwargs
        original = error_type(REDIRECT_URI)
        originals.append(original)
        raise original

    monkeypatch.setattr(
        module,
        "load_entra_application_service_principal_inventory_readiness",
        fail,
    )
    with pytest.raises(expected_type) as captured:
        load(prerequisite=prerequisite)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
    assert REDIRECT_URI not in repr(captured.value)
    assert len(originals) == 1
    assert originals[0].args == ()
    assert originals[0].__traceback__ is None
    assert originals[0].__context__ is None
    assert originals[0].__cause__ is None


def test_renderer_rejects_wrong_type_and_receipt_digest_binding_is_exact():
    with pytest.raises(TypeError):
        render_entra_calling_client_redirect_endpoint_readiness_receipt(object())
    receipt = load()
    assert (
        receipt.approved_inventory_document_sha256 == receipt.inventory_document_sha256
    )
    changed = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(changed, field.name, getattr(receipt, field.name))
    object.__setattr__(changed, "inventory_document_sha256", "0" * 64)
    with pytest.raises(ValueError):
        changed.__post_init__()


def test_fixed_plan_constants_and_cross_invariants_are_exact():
    assert module.FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT == (
        2 + len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
    )
    receipt = load()
    assert receipt.future_request_method == "GET"
    assert receipt.future_minimum_tls_version == "1.2"
    assert receipt.future_expected_status_code == 200
    assert receipt.future_expected_media_type == "text/html"
    assert receipt.future_expected_charset == "utf-8"
    assert receipt.future_max_header_bytes == 16_384
    assert receipt.future_max_body_bytes == 262_144
    assert receipt.future_hsts_minimum_max_age_seconds == 31_536_000


def test_receipt_hashes_independently_bind_exact_targets_identities_and_profiles():
    redirects = (REDIRECT_URI, REDIRECT_URI_2, REDIRECT_URI_3)
    prerequisite = prerequisites(redirects)
    receipt = load(prerequisite=prerequisite)

    def canonical(value):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()

    def framed(label, *values):
        digest = hashlib.sha256()
        material = ("engineer4me-step214-v1", label, str(len(values)), *values)
        for value in material:
            encoded = value if isinstance(value, bytes) else value.encode()
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()

    baseline_headers = [["Accept", "text/html"], ["Accept-Encoding", "identity"]]
    encoded_target = "https%3A%2F%2Fattacker.invalid%2Fsteal"
    requests = []
    sequence = 0
    for uri in redirects:
        sequence += 1
        baseline = {
            "sequence": sequence,
            "kind": "baseline",
            "method": "GET",
            "url": uri,
            "port": 443,
            "headers": baseline_headers,
            "body": None,
            "authorization": None,
            "cookie": None,
            "proxy": False,
            "follow_redirects": False,
            "retries": 0,
            "compression": False,
        }
        requests.append(baseline)
        sequence += 1
        requests.append(
            {
                **baseline,
                "sequence": sequence,
                "kind": "hostile_origin",
                "headers": baseline_headers + [["Origin", "https://attacker.invalid"]],
            }
        )
        for vector in (
            "continue",
            "next",
            "redirect",
            "redirect_uri",
            "return",
            "returnUrl",
            "target",
            "url",
        ):
            sequence += 1
            requests.append(
                {
                    **baseline,
                    "sequence": sequence,
                    "kind": "bounded_open_redirect_vector",
                    "vector_name": vector,
                    "url": f"{uri}?{vector}={encoded_target}",
                }
            )
    assert [entry["sequence"] for entry in requests] == list(range(1, 31))
    assert receipt.spa_redirect_uris_sha256 == framed(
        "spa_redirect_uris", "3", *redirects
    )
    assert receipt.redirect_hostnames_sha256 == framed(
        "redirect_hostnames",
        "2",
        "app.engineer4me.invalid",
        "portal.engineer4me.invalid",
    )
    assert receipt.calling_client_service_principal_app_id_mapping_sha256 == framed(
        "calling_client_service_principal_app_id_mapping",
        TENANT_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
    )
    assert receipt.tenant_id_sha256 == framed("tenant_id", TENANT_ID)
    assert receipt.calling_client_application_id_sha256 == framed(
        "calling_client_application_id", CALLING_CLIENT_APPLICATION_ID
    )
    assert receipt.calling_client_application_object_id_sha256 == framed(
        "calling_client_application_object_id", CALLING_CLIENT_OBJECT_ID
    )
    assert receipt.calling_client_service_principal_object_id_sha256 == framed(
        "calling_client_service_principal_object_id",
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
    )
    assert receipt.configuration_sha256 == (
        prerequisite["authentication_preview"].configuration_sha256
    )
    assert (
        receipt.api_registration_document_sha256
        == prerequisite["accepted_api_registration_document_sha256"]
    )
    assert (
        receipt.calling_client_registration_document_sha256
        == prerequisite["accepted_calling_client_registration_document_sha256"]
    )
    assert (
        receipt.inventory_document_sha256
        == prerequisite["approved_inventory_document_sha256"]
    )
    assert (
        receipt.approved_inventory_document_sha256
        == prerequisite["approved_inventory_document_sha256"]
    )
    assert receipt.redirect_endpoint_control_document_sha256 == (
        _canonical_document_digest(values(prerequisite))
    )
    inventory_receipt = load_entra_application_service_principal_inventory_readiness(
        document=prerequisite["inventory_document"],
        authentication_preview=prerequisite["authentication_preview"],
        api_registration_document=prerequisite["api_registration_document"],
        accepted_api_registration_document_sha256=prerequisite[
            "accepted_api_registration_document_sha256"
        ],
        calling_client_registration_document=prerequisite[
            "calling_client_registration_document"
        ],
        accepted_calling_client_registration_document_sha256=prerequisite[
            "accepted_calling_client_registration_document_sha256"
        ],
    )
    assert (
        receipt.offline_inventory_receipt_sha256
        == hashlib.sha256(
            render_entra_application_service_principal_inventory_readiness_receipt(
                inventory_receipt
            ).encode()
        ).hexdigest()
    )
    assert receipt.future_endpoint_request_plan_sha256 == framed(
        "future_endpoint_request_plan", canonical(requests)
    )

    header_profile = {
        "forbidden_response_headers": [
            "location",
            "set-cookie",
            "content-encoding",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ],
        "strict_transport_security": {
            "required": True,
            "minimum_max_age_seconds": 31_536_000,
        },
        "referrer-policy": "no-referrer",
        "cache-control_required_directive": "no-store",
        "x-content-type-options": "nosniff",
    }
    csp_profile = {
        "required_directives": {
            "base-uri": ["'none'"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'none'"],
            "default-src": ["'self'"],
            "script-src": ["'self'"],
        },
        "forbidden_source_expressions": [
            "*",
            "http:",
            "https:",
            "data:",
            "blob:",
            "filesystem:",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "'unsafe-hashes'",
        ],
        "forbidden_reporting_directives": ["report-uri", "report-to"],
    }
    html_profile = {
        "forbidden_elements": ["base", "form", "iframe", "object", "embed"],
        "forbidden_behaviors": [
            "meta_refresh",
            "inline_script",
            "inline_event_handler",
        ],
        "analysis_scope": "static HTML URL-bearing attributes only",
        "allowed_static_url_bearing_attributes": (
            "same-origin root-relative paths only"
        ),
        "all_other_static_url_forms_forbidden": True,
        "forbidden_static_url_forms": [
            "cross-origin",
            "protocol-relative",
            "javascript:",
            "data:",
            "blob:",
            "filesystem:",
        ],
    }
    vector_profile = {
        "ordered_names": [
            "continue",
            "next",
            "redirect",
            "redirect_uri",
            "return",
            "returnUrl",
            "target",
            "url",
        ],
        "target": "https://attacker.invalid/steal",
        "claim_boundary": "bounded_server_side_vector_set_only",
    }
    assert receipt.future_security_header_profile_sha256 == framed(
        "future_security_header_profile", canonical(header_profile)
    )
    assert receipt.future_content_security_policy_profile_sha256 == framed(
        "future_content_security_policy_profile", canonical(csp_profile)
    )
    assert receipt.future_html_profile_sha256 == framed(
        "future_html_profile", canonical(html_profile)
    )
    assert receipt.future_open_redirect_vector_plan_sha256 == framed(
        "future_open_redirect_vector_plan", canonical(vector_profile)
    )


def test_target_set_hashes_change_with_one_two_and_three_endpoints():
    one = load(prerequisite=prerequisites((REDIRECT_URI,)))
    two = load(prerequisite=prerequisites((REDIRECT_URI, REDIRECT_URI_2)))
    three = load(
        prerequisite=prerequisites((REDIRECT_URI, REDIRECT_URI_2, REDIRECT_URI_3))
    )
    assert (
        len(
            {
                one.spa_redirect_uris_sha256,
                two.spa_redirect_uris_sha256,
                three.spa_redirect_uris_sha256,
            }
        )
        == 3
    )
    assert (
        len(
            {
                one.future_endpoint_request_plan_sha256,
                two.future_endpoint_request_plan_sha256,
                three.future_endpoint_request_plan_sha256,
            }
        )
        == 3
    )
    assert one.redirect_hostnames_sha256 == two.redirect_hostnames_sha256
    assert two.redirect_hostnames_sha256 != three.redirect_hostnames_sha256
