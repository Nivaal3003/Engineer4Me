"""Tests for the offline Microsoft Entra browser-SPA desired state."""

from __future__ import annotations

import builtins
from copy import deepcopy
from dataclasses import replace
import json
from uuid import UUID

import pytest

from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    ENTRA_CALLING_CLIENT_ARCHITECTURE,
    ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_REGISTRATION_SCOPE,
    MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_BYTES,
    EntraCallingClientRegistrationReadinessError,
    entra_calling_client_registration_receipt_matches_identity,
    load_entra_calling_client_registration_readiness,
    render_entra_calling_client_registration_readiness_receipt,
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
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
REDIRECT_URI = "https://app.engineer4me.invalid/auth/callback"
REDIRECT_URI_2 = "https://app.engineer4me.invalid/auth/complete"
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
    return load_authentication_readiness_document(
        json.dumps(document).encode()
    ).preview


def api_registration_values(preview=None):
    preview = preview or authentication_preview()
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
                        "Allow this application to access Engineer4Me as the signed-in user."
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


def api_registration_receipt(preview=None):
    preview = preview or authentication_preview()
    return load_entra_api_registration_readiness(
        document=api_registration_document(preview),
        authentication_preview=preview,
    )


def api_registration_document(preview=None):
    preview = preview or authentication_preview()
    return json.dumps(api_registration_values(preview)).encode()


def api_prerequisites(preview=None):
    preview = preview or authentication_preview()
    document = api_registration_document(preview)
    receipt = load_entra_api_registration_readiness(
        document=document,
        authentication_preview=preview,
    )
    return {
        "api_registration_document": document,
        "accepted_api_registration_document_sha256": (
            receipt.registration_document_sha256
        ),
    }


def values(preview=None, api_receipt=None):
    preview = preview or authentication_preview()
    api_receipt = api_receipt or api_registration_receipt(preview)
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
            "spa_redirect_uris": [REDIRECT_URI],
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
            "desired_runtime_api_scope": f"api://{API_APPLICATION_ID}/access_as_user",
            "home_page_url": None,
            "logout_url": None,
        },
    }


def encoded(value=None, preview=None, api_receipt=None):
    return json.dumps(
        values(preview, api_receipt) if value is None else value
    ).encode()


def load(
    value=None,
    preview=None,
    api_document=None,
    accepted_api_digest=None,
):
    preview = preview or authentication_preview()
    api_document = api_document or api_registration_document(preview)
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    accepted_api_digest = (
        accepted_api_digest or api_receipt.registration_document_sha256
    )
    return load_entra_calling_client_registration_readiness(
        document=encoded(value, preview, api_receipt),
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=accepted_api_digest,
    )


def test_valid_spa_registration_binds_and_renders_private_canonical_receipt():
    receipt = load()
    rendered = render_entra_calling_client_registration_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["receipt_type"] == ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE
    assert parsed["validation_scope"] == ENTRA_CALLING_CLIENT_REGISTRATION_SCOPE
    assert parsed["schema_version"] == 1
    assert parsed["desired_client_architecture"] == ENTRA_CALLING_CLIENT_ARCHITECTURE
    assert parsed["desired_browser_flow"] == "authorization_code_pkce"
    assert parsed["desired_pkce_method"] == "S256"
    assert parsed["desired_client_authentication_method"] == "none"
    assert parsed["desired_sign_in_audience"] == "AzureADMyOrg"
    assert parsed["desired_authorization_code_flow_enabled"] is True
    assert parsed["desired_pkce_required"] is True
    assert parsed["desired_implicit_access_token_enabled"] is False
    assert parsed["desired_implicit_id_token_enabled"] is False
    assert parsed["desired_public_client_fallback_enabled"] is False
    assert parsed["desired_native_authentication_apis_enabled"] == "none"
    assert parsed["desired_device_only_auth_supported"] is False
    assert parsed["desired_device_code_flow_enabled"] is False
    assert parsed["desired_resource_owner_password_flow_enabled"] is False
    assert parsed["desired_client_credentials_flow_enabled"] is False
    assert parsed["desired_on_behalf_of_flow_enabled"] is False
    assert parsed["desired_client_secret_allowed"] is False
    assert parsed["desired_logo_configured"] is False
    assert parsed["desired_optional_claims_configured"] is False
    assert parsed["desired_group_membership_claims_configured"] is False
    assert parsed["desired_token_encryption_key_configured"] is False
    assert parsed["desired_api_accept_mapped_claims"] is False
    assert parsed["desired_oauth2_required_post_response"] is False
    assert parsed["desired_offline_access"] is True
    assert parsed["desired_permission_type"] == "Scope"
    assert parsed["desired_delegated_scope_value"] == "access_as_user"
    assert parsed["desired_delegated_scope_consent"] == "admins_only"
    assert parsed["configuration_bound"] is True
    assert parsed["api_registration_bound"] is True
    assert parsed["required_resource_access_bound"] is True
    assert parsed["desired_state_validated"] is True
    assert parsed["desired_spa_platform_configured"] is True
    assert parsed["redirect_uri_syntax_validated"] is True
    assert parsed["desired_owner_count"] == 2
    assert parsed["desired_spa_redirect_uri_count"] == 1
    assert parsed["desired_required_resource_access_count"] == 1
    assert parsed["desired_microsoft_graph_permission_count"] == 0
    assert parsed["desired_password_credential_count"] == 0
    assert parsed["desired_key_credential_count"] == 0
    assert parsed["desired_federated_identity_credential_count"] == 0
    assert parsed["desired_exposed_delegated_scope_count"] == 0
    assert parsed["desired_app_role_count"] == 0
    assert parsed["desired_web_redirect_uri_count"] == 0
    assert parsed["desired_public_client_redirect_uri_count"] == 0
    assert parsed["desired_identifier_uri_count"] == 0
    assert parsed["desired_preauthorized_client_count"] == 0
    assert parsed["desired_known_client_count"] == 0
    assert parsed["desired_add_in_count"] == 0
    assert parsed["desired_info_url_count"] == 0
    assert parsed["desired_runtime_oidc_scope_count"] == 3
    for flag in (
        "provider_state_checked",
        "live_registration_checked",
        "live_application_exists_checked",
        "delegated_permission_grant_checked",
        "admin_consent_checked",
        "service_principal_checked",
        "user_flow_checked",
        "provider_ownership_checked",
        "owner_tenant_membership_checked",
        "tenant_external_status_checked",
        "runtime_pkce_s256_checked",
        "runtime_azpacr_public_client_checked",
        "redirect_endpoint_ownership_checked",
        "redirect_tls_checked",
        "open_redirect_behavior_checked",
        "application_creation_performed",
        "activation_ready",
    ):
        assert parsed[flag] is False
    for digest_key in (
        "configuration_sha256",
        "api_registration_document_sha256",
        "client_registration_document_sha256",
        "tenant_id_sha256",
        "api_application_id_sha256",
        "api_application_object_id_sha256",
        "api_delegated_scope_id_sha256",
        "calling_client_application_id_sha256",
        "calling_client_application_object_id_sha256",
        "display_name_sha256",
        "owner_object_ids_sha256",
        "spa_redirect_uris_sha256",
        "desired_runtime_oidc_scopes_sha256",
        "desired_runtime_api_scope_sha256",
        "required_resource_access_sha256",
    ):
        assert len(parsed[digest_key]) == 64
        assert parsed[digest_key] == parsed[digest_key].lower()
        int(parsed[digest_key], 16)
    for raw in (
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SCOPE_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        OWNER_ID,
        OWNER_ID_2,
        REDIRECT_URI,
        "Engineer4Me Web",
        f"api://{API_APPLICATION_ID}/access_as_user",
    ):
        assert raw not in rendered


def test_canonical_digest_ignores_json_whitespace_and_key_order():
    preview = authentication_preview()
    api_document = api_registration_document(preview)
    api_receipt = api_registration_receipt(preview)
    original = values(preview, api_receipt)
    reversed_root = dict(reversed(list(original.items())))
    reversed_root["registration"] = dict(
        reversed(list(original["registration"].items()))
    )
    left = load_entra_calling_client_registration_readiness(
        document=json.dumps(original, separators=(",", ":")).encode(),
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    right = load_entra_calling_client_registration_readiness(
        document=json.dumps(reversed_root, indent=2).encode(),
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    assert (
        left.client_registration_document_sha256
        == right.client_registration_document_sha256
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        (
            "calling_client_application_object_id",
            "33333333-4444-4555-8666-777777777777",
        ),
        (
            "owner_object_ids",
            [
                "33333333-4444-4555-8666-777777777777",
                "44444444-5555-4666-8777-888888888888",
            ],
        ),
        ("spa_redirect_uris", [REDIRECT_URI_2]),
    ],
)
def test_document_digest_changes_for_material_desired_state(field, replacement):
    original = values()
    changed = deepcopy(original)
    changed["registration"][field] = replacement
    assert load(original).client_registration_document_sha256 != (
        load(changed).client_registration_document_sha256
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", "33333333-4444-4555-8666-777777777777"),
        ("calling_client_application_id", "44444444-5555-4666-8777-888888888888"),
    ],
)
def test_registration_rejects_authentication_identity_mismatch(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="does not match authentication",
    ):
        load(value)


def test_registration_rejects_api_application_mismatch_with_authentication():
    replacement = "33333333-4444-4555-8666-777777777777"
    value = values()
    value["registration"]["api_application_id"] = replacement
    value["registration"]["required_resource_access"][0][
        "resource_application_id"
    ] = replacement
    value["registration"]["desired_runtime_api_scope"] = (
        f"api://{replacement}/access_as_user"
    )
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="does not match authentication",
    ):
        load(value)


def test_registration_rejects_unapproved_configuration_digest():
    value = values()
    value["approved_configuration_sha256"] = "0" * 64
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="does not match authentication",
    ):
        load(value)


def test_registration_rejects_unapproved_api_registration_digest():
    value = values()
    value["approved_api_registration_document_sha256"] = "0" * 64
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="does not match API registration",
    ):
        load(value)


def test_registration_requires_independently_accepted_api_document_digest():
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="accepted digest",
    ):
        load(accepted_api_digest="0" * 64)


def test_registration_revalidates_original_api_document_instead_of_a_receipt():
    preview = authentication_preview()
    api_values = api_registration_values(preview)
    api_values["registration"]["delegated_scopes"][0]["consent"] = (
        "admins_and_users"
    )
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="not locally validated",
    ):
        load_entra_calling_client_registration_readiness(
            document=encoded(),
            authentication_preview=preview,
            api_registration_document=json.dumps(api_values).encode(),
            accepted_api_registration_document_sha256=(
                api_registration_receipt(preview).registration_document_sha256
            ),
        )


def test_registration_rejects_self_consistent_unaccepted_api_document():
    preview = authentication_preview()
    api_values = api_registration_values(preview)
    replacement_scope = "33333333-4444-4555-8666-777777777777"
    api_values["registration"]["delegated_scopes"][0]["scope_id"] = (
        replacement_scope
    )
    changed_document = json.dumps(api_values).encode()
    changed_receipt = load_entra_api_registration_readiness(
        document=changed_document,
        authentication_preview=preview,
    )
    client_values = values(preview)
    client_values["approved_api_registration_document_sha256"] = (
        changed_receipt.registration_document_sha256
    )
    client_values["registration"]["api_delegated_scope_id"] = replacement_scope
    client_values["registration"]["required_resource_access"][0][
        "delegated_scope_id"
    ] = replacement_scope
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="accepted digest",
    ):
        load(
            client_values,
            preview,
            changed_document,
            api_registration_receipt(preview).registration_document_sha256,
        )


def test_provider_neutral_authentication_preview_is_rejected():
    document = {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": "https://identity.engineer4me.invalid",
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.invalid/jwks.json",
            "algorithms": ["RS256"],
        },
    }
    preview = load_authentication_readiness_document(
        json.dumps(document).encode()
    ).preview
    entra_preview = authentication_preview()
    api_document = api_registration_document(entra_preview)
    api_receipt = api_registration_receipt(entra_preview)
    value = values(entra_preview, api_receipt)
    value["approved_configuration_sha256"] = preview.configuration_sha256
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load_entra_calling_client_registration_readiness(
            document=json.dumps(value).encode(),
            authentication_preview=preview,
            api_registration_document=api_document,
            accepted_api_registration_document_sha256=(
                api_receipt.registration_document_sha256
            ),
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", TENANT_ID.upper()),
        ("api_application_id", API_APPLICATION_ID.replace("-", "")),
        ("api_application_object_id", API_APPLICATION_OBJECT_ID.upper()),
        ("api_delegated_scope_id", "{" + API_SCOPE_ID + "}"),
        ("calling_client_application_id", "00000000-0000-0000-0000-000000000000"),
        ("calling_client_application_object_id", 42),
    ],
)
def test_registration_rejects_noncanonical_or_zero_uuid_inputs(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="contract validation",
    ):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("calling_client_application_id", API_APPLICATION_ID),
        ("calling_client_application_id", API_APPLICATION_OBJECT_ID),
        (
            "calling_client_application_object_id",
            CALLING_CLIENT_APPLICATION_ID,
        ),
        (
            "calling_client_application_object_id",
            API_APPLICATION_OBJECT_ID,
        ),
        ("owner_object_ids", [API_SCOPE_ID]),
    ],
)
def test_registration_rejects_confused_identifiers(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="contract validation",
    ):
        load(value)


@pytest.mark.parametrize(
    "owners",
    [
        [],
        [OWNER_ID],
        [OWNER_ID, OWNER_ID],
        [OWNER_ID_2, OWNER_ID],
        [
            OWNER_ID,
            OWNER_ID_2,
            "33333333-4444-4555-8666-777777777777",
            "44444444-5555-4666-8777-888888888888",
            "55555555-6666-4777-8888-999999999999",
            "66666666-7777-4888-8999-aaaaaaaaaaaa",
        ],
    ],
)
def test_registration_requires_bounded_unique_sorted_owners(owners):
    value = values()
    value["registration"]["owner_object_ids"] = owners
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://app.engineer4me.invalid/auth/callback",
        "https://localhost/auth/callback",
        "https://APP.engineer4me.invalid/auth/callback",
        "https://app.engineer4me.invalid:443/auth/callback",
        "https://user@app.engineer4me.invalid/auth/callback",
        "https://app.engineer4me.invalid/",
        "https://app.engineer4me.invalid/auth//callback",
        "https://app.engineer4me.invalid/auth/%63allback",
        "https://app.engineer4me.invalid/auth/callback?next=x",
        "https://app.engineer4me.invalid/auth/callback#fragment",
        "https://*.engineer4me.invalid/auth/callback",
        "https://xn--engineer4me-9za.invalid/auth/callback",
        "https://127.0.0.1/auth/callback",
        "https://app.engineer4me.invalid/auth/./callback",
        "https://app.engineer4me.invalid/auth/../callback",
        "https://app.engineer4me.invalid/auth/call back",
        "https://app.engineer4me.invalid/auth/!callback",
        "https://app.engineer4me.invalid/auth/$callback",
        "https://app.engineer4me.invalid/auth/'callback",
        "https://app.engineer4me.invalid/auth/(callback",
        "https://app.engineer4me.invalid/auth/)callback",
        "https://app.engineer4me.invalid/auth/,callback",
        "https://app.engineer4me.invalid/auth/;callback",
        "https://app.engineer4me.invalid/" + "a" * 300,
    ],
)
def test_registration_rejects_noncanonical_spa_redirect_uri(redirect_uri):
    value = values()
    value["registration"]["spa_redirect_uris"] = [redirect_uri]
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="contract validation",
    ):
        load(value)


@pytest.mark.parametrize(
    "redirects",
    [
        [REDIRECT_URI, REDIRECT_URI],
        [REDIRECT_URI_2, REDIRECT_URI],
        [
            REDIRECT_URI,
            REDIRECT_URI_2,
            "https://app.engineer4me.invalid/auth/third",
            "https://app.engineer4me.invalid/auth/fourth",
        ],
    ],
)
def test_registration_requires_bounded_unique_sorted_redirect_uris(redirects):
    value = values()
    value["registration"]["spa_redirect_uris"] = redirects
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


def test_registration_accepts_maximum_sorted_spa_redirect_uris():
    value = values()
    value["registration"]["spa_redirect_uris"] = [
        REDIRECT_URI,
        REDIRECT_URI_2,
        "https://app.engineer4me.invalid/auth/third",
    ]
    receipt = load(value)
    assert receipt.desired_spa_redirect_uri_count == MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("display_name", "Engineer4Me API"),
        ("description", "public description"),
        ("notes", "operator note"),
        ("marketing_url", "https://engineer4me.invalid"),
        ("privacy_statement_url", "https://engineer4me.invalid/privacy"),
        ("support_url", "https://engineer4me.invalid/support"),
        ("terms_of_service_url", "https://engineer4me.invalid/terms"),
        ("desired_logo_configured", True),
        ("desired_sign_in_audience", "AzureADMultipleOrgs"),
        ("desired_client_architecture", "confidential_web_bff"),
        ("desired_browser_flow", "implicit"),
        ("desired_pkce_method", "plain"),
        ("desired_client_authentication_method", "client_secret_post"),
        ("desired_authorization_code_flow_enabled", False),
        ("desired_pkce_required", False),
        ("spa_redirect_uris", []),
        ("web_redirect_uris", [REDIRECT_URI]),
        ("public_client_redirect_uris", [REDIRECT_URI]),
        ("desired_implicit_access_token_enabled", True),
        ("desired_implicit_id_token_enabled", True),
        ("desired_public_client_fallback_enabled", True),
        ("desired_native_authentication_apis_enabled", "all"),
        ("desired_device_only_auth_supported", True),
        ("desired_device_code_flow_enabled", True),
        ("desired_resource_owner_password_flow_enabled", True),
        ("desired_client_credentials_flow_enabled", True),
        ("desired_on_behalf_of_flow_enabled", True),
        ("password_credential_ids", ["33333333-4444-4555-8666-777777777777"]),
        ("key_credential_ids", ["33333333-4444-4555-8666-777777777777"]),
        (
            "federated_identity_credential_ids",
            ["33333333-4444-4555-8666-777777777777"],
        ),
        (
            "microsoft_graph_permission_ids",
            ["33333333-4444-4555-8666-777777777777"],
        ),
        ("identifier_uris", ["api://client"]),
        (
            "exposed_delegated_scope_ids",
            ["33333333-4444-4555-8666-777777777777"],
        ),
        ("app_role_ids", ["33333333-4444-4555-8666-777777777777"]),
        (
            "preauthorized_client_application_ids",
            ["33333333-4444-4555-8666-777777777777"],
        ),
        (
            "known_client_application_ids",
            ["33333333-4444-4555-8666-777777777777"],
        ),
        ("desired_optional_claims_configured", True),
        ("desired_group_membership_claims_configured", True),
        ("desired_token_encryption_key_configured", True),
        ("desired_api_accept_mapped_claims", True),
        ("desired_oauth2_required_post_response", True),
        ("add_in_ids", ["33333333-4444-4555-8666-777777777777"]),
        ("home_page_url", "https://app.engineer4me.invalid"),
        ("logout_url", "https://app.engineer4me.invalid/logout"),
    ],
)
def test_registration_rejects_unapproved_client_surface(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="contract validation",
    ):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("desired_logo_configured", 0),
        ("desired_authorization_code_flow_enabled", 1),
        ("desired_pkce_required", "true"),
        ("desired_implicit_access_token_enabled", "false"),
    ],
)
def test_registration_rejects_nonboolean_boolean_fields(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


@pytest.mark.parametrize(
    "access",
    [
        [],
        [
            {
                "resource_application_id": API_APPLICATION_ID,
                "delegated_scope_id": API_SCOPE_ID,
                "permission_type": "Role",
                "scope_value": "access_as_user",
            }
        ],
        [
            {
                "resource_application_id": CALLING_CLIENT_APPLICATION_ID,
                "delegated_scope_id": API_SCOPE_ID,
                "permission_type": "Scope",
                "scope_value": "access_as_user",
            }
        ],
        [
            {
                "resource_application_id": (
                    "00000003-0000-0000-c000-000000000000"
                ),
                "delegated_scope_id": (
                    "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                ),
                "permission_type": "Scope",
                "scope_value": "access_as_user",
            }
        ],
        [
            {
                "resource_application_id": API_APPLICATION_ID,
                "delegated_scope_id": "33333333-4444-4555-8666-777777777777",
                "permission_type": "Scope",
                "scope_value": "access_as_user",
            }
        ],
        [
            {
                "resource_application_id": API_APPLICATION_ID,
                "delegated_scope_id": API_SCOPE_ID,
                "permission_type": "Scope",
                "scope_value": "wrong_scope",
            }
        ],
    ],
)
def test_registration_requires_one_exact_delegated_api_permission(access):
    value = values()
    value["registration"]["required_resource_access"] = access
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


def test_registration_rejects_multiple_required_resource_entries():
    value = values()
    value["registration"]["required_resource_access"] *= 2
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("desired_runtime_oidc_scopes", ["openid", "profile"]),
        ("desired_runtime_oidc_scopes", ["openid", "profile", "offline_access"]),
        ("desired_runtime_oidc_scopes", ["email", "openid", "profile"]),
        ("desired_runtime_api_scope", f"api://{API_APPLICATION_ID}/wrong_scope"),
    ],
)
def test_registration_rejects_unapproved_runtime_scope_contract(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("approved_configuration_sha256", "A" * 64),
        ("approved_configuration_sha256", "0" * 63),
        ("approved_configuration_sha256", "g" * 64),
        ("approved_api_registration_document_sha256", "A" * 64),
        ("approved_api_registration_document_sha256", "0" * 63),
        ("approved_api_registration_document_sha256", "g" * 64),
    ],
)
def test_registration_rejects_noncanonical_digest_fields(field, replacement):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


def test_registration_rejects_unknown_fields():
    value = values()
    value["registration"]["client_secret"] = "not-allowed"
    with pytest.raises(EntraCallingClientRegistrationReadinessError):
        load(value)


def test_nonbytes_document_is_rejected_before_parsing():
    with pytest.raises(TypeError, match="must be bytes"):
        load_entra_calling_client_registration_readiness(
            document="{}",
            authentication_preview=authentication_preview(),
            **api_prerequisites(),
        )


def test_wrong_prerequisite_types_are_rejected():
    preview = authentication_preview()
    with pytest.raises(TypeError, match="preview"):
        load_entra_calling_client_registration_readiness(
            document=encoded(),
            authentication_preview=object(),
            **api_prerequisites(preview),
        )
    with pytest.raises(TypeError, match="document must be bytes"):
        load_entra_calling_client_registration_readiness(
            document=encoded(),
            authentication_preview=preview,
            api_registration_document=object(),
            accepted_api_registration_document_sha256="0" * 64,
        )
    with pytest.raises(TypeError, match="digest"):
        load_entra_calling_client_registration_readiness(
            document=encoded(),
            authentication_preview=preview,
            api_registration_document=api_registration_document(preview),
            accepted_api_registration_document_sha256=object(),
        )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (b"", "empty"),
        (b"\xff", "UTF-8"),
        (b"[]", "root"),
        (b'{"x":1,"x":2}', "duplicate"),
        (b'{"x":NaN}', "non-finite"),
        (b"{", "valid JSON"),
    ],
)
def test_malformed_documents_fail_sanitized(document, message):
    with pytest.raises(EntraCallingClientRegistrationReadinessError, match=message):
        load_entra_calling_client_registration_readiness(
            document=document,
            authentication_preview=authentication_preview(),
            **api_prerequisites(),
        )


def test_document_byte_limit_is_enforced_before_json_validation():
    oversized = b"{" + b" " * MAX_ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_BYTES
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="byte limit",
    ):
        load_entra_calling_client_registration_readiness(
            document=oversized,
            authentication_preview=authentication_preview(),
            **api_prerequisites(),
        )


def test_document_nesting_limit_is_enforced():
    value = values()
    value["noise"] = [[[[[[[[[["too-deep"]]]]]]]]]]
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="nesting limit",
    ):
        load(value)


def test_document_container_limit_is_enforced():
    value = values()
    value["noise"] = [[] for _ in range(300)]
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="structure limit",
    ):
        load(value)


def test_loader_performs_no_file_environment_or_network_io(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("external or global I/O is forbidden")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    assert load().desired_state_validated is True


def test_forged_authentication_preview_is_rejected():
    preview = authentication_preview()
    api_receipt = api_registration_receipt(preview)
    forged = replace(preview, configuration_sha256="0" * 64)
    with pytest.raises(
        EntraCallingClientRegistrationReadinessError,
        match="prerequisite",
    ):
        load_entra_calling_client_registration_readiness(
            document=encoded(values(preview, api_receipt)),
            authentication_preview=forged,
            **api_prerequisites(preview),
        )


def test_receipt_renderer_requires_exact_receipt_type():
    with pytest.raises(TypeError, match="receipt"):
        render_entra_calling_client_registration_readiness_receipt(object())


def test_privacy_preserving_identity_matcher_accepts_exact_registration_ids():
    assert entra_calling_client_registration_receipt_matches_identity(
        load(),
        tenant_id=UUID(TENANT_ID),
        api_application_id=UUID(API_APPLICATION_ID),
        api_application_object_id=UUID(API_APPLICATION_OBJECT_ID),
        api_delegated_scope_id=UUID(API_SCOPE_ID),
        calling_client_application_id=UUID(CALLING_CLIENT_APPLICATION_ID),
        calling_client_application_object_id=UUID(CALLING_CLIENT_OBJECT_ID),
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", UUID("00000000-0000-4000-8000-000000000201")),
        ("api_application_id", UUID("00000000-0000-4000-8000-000000000202")),
        (
            "api_application_object_id",
            UUID("00000000-0000-4000-8000-000000000203"),
        ),
        (
            "api_delegated_scope_id",
            UUID("00000000-0000-4000-8000-000000000204"),
        ),
        (
            "calling_client_application_id",
            UUID("00000000-0000-4000-8000-000000000205"),
        ),
        (
            "calling_client_application_object_id",
            UUID("00000000-0000-4000-8000-000000000206"),
        ),
    ],
)
def test_privacy_preserving_identity_matcher_rejects_any_identity_mismatch(
    field,
    replacement,
):
    arguments = {
        "tenant_id": UUID(TENANT_ID),
        "api_application_id": UUID(API_APPLICATION_ID),
        "api_application_object_id": UUID(API_APPLICATION_OBJECT_ID),
        "api_delegated_scope_id": UUID(API_SCOPE_ID),
        "calling_client_application_id": UUID(CALLING_CLIENT_APPLICATION_ID),
        "calling_client_application_object_id": UUID(CALLING_CLIENT_OBJECT_ID),
    }
    arguments[field] = replacement
    assert not entra_calling_client_registration_receipt_matches_identity(
        load(),
        **arguments,
    )


def test_privacy_preserving_identity_matcher_rejects_types_zero_and_forgery():
    receipt = load()
    exact = {
        "tenant_id": UUID(TENANT_ID),
        "api_application_id": UUID(API_APPLICATION_ID),
        "api_application_object_id": UUID(API_APPLICATION_OBJECT_ID),
        "api_delegated_scope_id": UUID(API_SCOPE_ID),
        "calling_client_application_id": UUID(CALLING_CLIENT_APPLICATION_ID),
        "calling_client_application_object_id": UUID(CALLING_CLIENT_OBJECT_ID),
    }
    assert not entra_calling_client_registration_receipt_matches_identity(
        object(),
        **exact,
    )
    assert not entra_calling_client_registration_receipt_matches_identity(
        receipt,
        **{**exact, "tenant_id": TENANT_ID},
    )
    for field in exact:
        assert not entra_calling_client_registration_receipt_matches_identity(
            receipt,
            **{**exact, field: UUID(int=0)},
        )
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, calling_client_application_id_sha256="0" * 63)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("configuration_sha256", "0" * 63),
        ("desired_client_architecture", "confidential_web_bff"),
        ("desired_pkce_method", "plain"),
        ("desired_spa_redirect_uri_count", 0),
        ("desired_microsoft_graph_permission_count", 1),
        ("desired_client_secret_allowed", True),
        ("configuration_bound", False),
        ("api_registration_bound", False),
        ("desired_state_validated", False),
        ("provider_state_checked", True),
        ("runtime_pkce_s256_checked", True),
        ("runtime_azpacr_public_client_checked", True),
        ("admin_consent_checked", True),
        ("activation_ready", True),
    ],
)
def test_receipt_renderer_rejects_forged_evidence(field, replacement):
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_entra_calling_client_registration_readiness_receipt(
            replace(load(), **{field: replacement})
        )
