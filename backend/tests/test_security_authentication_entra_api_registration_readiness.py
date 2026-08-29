"""Tests for the offline Microsoft Entra API-registration desired state."""

from __future__ import annotations

import builtins
from copy import deepcopy
from dataclasses import replace
import json
from uuid import UUID

import pytest

from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    ENTRA_API_REGISTRATION_RECEIPT_TYPE,
    ENTRA_API_REGISTRATION_SCOPE,
    MAX_ENTRA_API_REGISTRATION_DOCUMENT_BYTES,
    EntraAPIRegistrationReadinessError,
    entra_api_registration_receipt_matches_identity,
    load_entra_api_registration_readiness,
    render_entra_api_registration_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)


TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
CALLING_CLIENT_APPLICATION_ID = "11111111-2222-4333-8444-555555555555"
APPLICATION_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
SCOPE_ID = "dddddddd-eeee-4fff-8aaa-bbbbbbbb0500"
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
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
            "microsoft_entra_calling_client_application_id": (
                CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_delegated_scope": "access_as_user",
            "microsoft_entra_required_azpacr": "0",
        },
    }
    return load_authentication_readiness_document(
        json.dumps(document).encode()
    ).preview


def values():
    preview = authentication_preview()
    return {
        "document_type": ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "approved_configuration_sha256": preview.configuration_sha256,
        "registration": {
            "tenant_id": TENANT_ID,
            "api_application_id": API_APPLICATION_ID,
            "application_object_id": APPLICATION_OBJECT_ID,
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
                    "scope_id": SCOPE_ID,
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


def encoded(value=None):
    return json.dumps(values() if value is None else value).encode()


def load(value=None, preview=None):
    return load_entra_api_registration_readiness(
        document=encoded(value),
        authentication_preview=preview or authentication_preview(),
    )


def test_valid_registration_is_bound_and_renders_one_canonical_private_receipt():
    preview = authentication_preview()
    assert preview.microsoft_entra_required_delegated_scope == "access_as_user"
    assert preview.microsoft_entra_required_azpacr == "0"
    assert (
        preview.microsoft_entra_calling_client_application_id
        == CALLING_CLIENT_APPLICATION_ID
    )
    receipt = load()
    rendered = render_entra_api_registration_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["configuration_bound"] is True
    assert parsed["receipt_type"] == ENTRA_API_REGISTRATION_RECEIPT_TYPE
    assert parsed["schema_version"] == 1
    assert parsed["sign_in_audience"] == "AzureADMyOrg"
    assert parsed["requested_access_token_version"] == 2
    assert parsed["delegated_scope_value"] == "access_as_user"
    assert parsed["delegated_scope_consent"] == "admins_only"
    assert parsed["delegated_scope_enabled"] is True
    assert parsed["accept_mapped_claims"] is False
    assert parsed["validation_scope"] == ENTRA_API_REGISTRATION_SCOPE
    assert parsed["desired_redirect_uri_count"] == 0
    assert parsed["desired_password_key_credential_count"] == 0
    assert parsed["desired_app_role_count"] == 0
    assert parsed["desired_preauthorized_client_count"] == 0
    assert parsed["desired_known_client_count"] == 0
    assert parsed["desired_required_resource_count"] == 0
    assert parsed["desired_federated_identity_credential_count"] == 0
    assert parsed["desired_optional_claims_configured"] is False
    assert parsed["desired_group_membership_claims_configured"] is False
    assert parsed["desired_token_encryption_key_configured"] is False
    assert parsed["desired_add_in_count"] == 0
    assert parsed["owner_count"] == 1
    assert parsed["application_creation_performed"] is False
    assert parsed["provider_state_checked"] is False
    assert parsed["live_registration_checked"] is False
    assert parsed["live_application_exists_checked"] is False
    assert parsed["admin_consent_checked"] is False
    assert parsed["calling_client_registration_checked"] is False
    assert parsed["user_flow_checked"] is False
    assert parsed["runtime_scope_enforcement"] is False
    assert parsed["delegated_token_enforcement"] is False
    assert parsed["roleless_app_token_rejection"] is False
    assert parsed["calling_client_identity_checked"] is False
    assert parsed["azp_checked"] is False
    assert parsed["service_principal_checked"] is False
    assert parsed["service_principal_assignment_required_checked"] is False
    assert parsed["service_principal_lock_checked"] is False
    assert parsed["claims_policy_assignments_checked"] is False
    assert parsed["provider_ownership_checked"] is False
    assert parsed["owner_tenant_membership_checked"] is False
    assert parsed["activation_ready"] is False
    for digest_key in (
        "configuration_sha256",
        "registration_document_sha256",
        "tenant_id_sha256",
        "api_application_id_sha256",
        "application_object_id_sha256",
        "display_name_sha256",
        "owner_object_ids_sha256",
        "delegated_scope_id_sha256",
        "identifier_uri_sha256",
    ):
        assert len(parsed[digest_key]) == 64
        assert parsed[digest_key] == parsed[digest_key].lower()
        int(parsed[digest_key], 16)
    for raw in (
        TENANT_ID,
        API_APPLICATION_ID,
        CALLING_CLIENT_APPLICATION_ID,
        APPLICATION_OBJECT_ID,
        SCOPE_ID,
        OWNER_ID,
        f"api://{API_APPLICATION_ID}",
        ISSUER,
        "Engineer4Me API",
        "Access Engineer4Me as the signed-in user",
    ):
        assert raw not in rendered


def test_privacy_preserving_identity_matcher_accepts_exact_registration_ids():
    receipt = load()
    assert entra_api_registration_receipt_matches_identity(
        receipt,
        tenant_id=UUID(TENANT_ID),
        api_application_id=UUID(API_APPLICATION_ID),
        api_application_object_id=UUID(APPLICATION_OBJECT_ID),
        delegated_scope_id=UUID(SCOPE_ID),
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", UUID("00000000-0000-4000-8000-000000000201")),
        ("api_application_id", UUID("00000000-0000-4000-8000-000000000202")),
        (
            "api_application_object_id",
            UUID("00000000-0000-4000-8000-000000000204"),
        ),
        ("delegated_scope_id", UUID("00000000-0000-4000-8000-000000000203")),
    ],
)
def test_privacy_preserving_identity_matcher_rejects_any_identity_mismatch(
    field,
    replacement,
):
    arguments = {
        "tenant_id": UUID(TENANT_ID),
        "api_application_id": UUID(API_APPLICATION_ID),
        "api_application_object_id": UUID(APPLICATION_OBJECT_ID),
        "delegated_scope_id": UUID(SCOPE_ID),
    }
    arguments[field] = replacement
    assert not entra_api_registration_receipt_matches_identity(load(), **arguments)


def test_privacy_preserving_identity_matcher_rejects_types_zero_and_forgery():
    receipt = load()
    exact = {
        "tenant_id": UUID(TENANT_ID),
        "api_application_id": UUID(API_APPLICATION_ID),
        "api_application_object_id": UUID(APPLICATION_OBJECT_ID),
        "delegated_scope_id": UUID(SCOPE_ID),
    }
    assert not entra_api_registration_receipt_matches_identity(
        object(),
        **exact,
    )
    assert not entra_api_registration_receipt_matches_identity(
        receipt,
        tenant_id=TENANT_ID,
        api_application_id=UUID(API_APPLICATION_ID),
        api_application_object_id=UUID(APPLICATION_OBJECT_ID),
        delegated_scope_id=UUID(SCOPE_ID),
    )
    assert not entra_api_registration_receipt_matches_identity(
        receipt,
        tenant_id=UUID(int=0),
        api_application_id=UUID(API_APPLICATION_ID),
        api_application_object_id=UUID(APPLICATION_OBJECT_ID),
        delegated_scope_id=UUID(SCOPE_ID),
    )
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, delegated_scope_id_sha256="0" * 63)


def test_canonical_digest_ignores_json_whitespace_and_key_order():
    original = values()
    reversed_root = dict(reversed(list(original.items())))
    reversed_root["registration"] = dict(
        reversed(list(original["registration"].items()))
    )
    left = load_entra_api_registration_readiness(
        document=json.dumps(original, separators=(",", ":")).encode(),
        authentication_preview=authentication_preview(),
    )
    right = load_entra_api_registration_readiness(
        document=json.dumps(reversed_root, indent=2).encode(),
        authentication_preview=authentication_preview(),
    )
    assert left.registration_document_sha256 == right.registration_document_sha256
    assert render_entra_api_registration_readiness_receipt(left).replace(
        left.registration_document_sha256,
        right.registration_document_sha256,
    ) == render_entra_api_registration_readiness_receipt(right)


def test_registration_digest_changes_for_every_material_desired_state_change():
    original = values()
    left = load(original)
    changes = (
        ("application_object_id", "00000000-0000-4000-8000-000000000101"),
        ("owner_object_ids", ["00000000-0000-4000-8000-000000000102"]),
        (
            "delegated_scopes",
            [
                {
                    "scope_id": "00000000-0000-4000-8000-000000000103",
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
        ),
    )
    for field, replacement in changes:
        changed = deepcopy(original)
        changed["registration"][field] = replacement
        assert load(changed).registration_document_sha256 != (
            left.registration_document_sha256
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", "00000000-0000-4000-8000-000000000001"),
        ("api_application_id", "00000000-0000-4000-8000-000000000002"),
    ],
)
def test_registration_rejects_identity_mismatch_with_authentication(field, replacement):
    value = values()
    value["registration"][field] = replacement
    if field == "api_application_id":
        value["registration"]["identifier_uris"] = [f"api://{replacement}"]
    with pytest.raises(EntraAPIRegistrationReadinessError, match="does not match"):
        load(value)


def test_registration_rejects_unapproved_configuration_digest():
    value = values()
    value["approved_configuration_sha256"] = "0" * 64
    with pytest.raises(EntraAPIRegistrationReadinessError, match="does not match"):
        load(value)


@pytest.mark.parametrize(
    "scope",
    [None, "wrong_scope", "access_as_user extra_scope"],
)
def test_registration_rejects_preview_without_exact_delegated_scope_binding(scope):
    preview = replace(
        authentication_preview(),
        microsoft_entra_required_delegated_scope=scope,
    )
    with pytest.raises(
        EntraAPIRegistrationReadinessError,
        match="preview is not locally validated",
    ):
        load(values(), preview)


def test_provider_neutral_authentication_preview_is_rejected():
    document = {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": "https://identity.engineer4me.test",
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.test/jwks.json",
            "algorithms": ["RS256"],
        },
    }
    preview = load_authentication_readiness_document(
        json.dumps(document).encode()
    ).preview
    value = values()
    value["approved_configuration_sha256"] = preview.configuration_sha256
    with pytest.raises(EntraAPIRegistrationReadinessError, match="does not match"):
        load(value, preview)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("application_object_id", API_APPLICATION_ID),
        ("owner_object_ids", [OWNER_ID, OWNER_ID]),
        ("owner_object_ids", [SCOPE_ID]),
        ("owner_object_ids", [OWNER_ID_2, OWNER_ID]),
        (
            "owner_object_ids",
            [
                OWNER_ID,
                OWNER_ID_2,
                "00000000-0000-4000-8000-000000000109",
                "00000000-0000-4000-8000-00000000010a",
                "00000000-0000-4000-8000-00000000010b",
                "00000000-0000-4000-8000-00000000010c",
            ],
        ),
        ("display_name", "Engineer4Me Client"),
        ("description", "public description"),
        ("notes", "operator note"),
        ("marketing_url", "https://engineer4me.com"),
        ("privacy_statement_url", "https://engineer4me.com/privacy"),
        ("support_url", "https://engineer4me.com/support"),
        ("terms_of_service_url", "https://engineer4me.com/terms"),
        ("logo_configured", True),
        ("identifier_uris", [f"api://{UUID(int=1)}"]),
        ("identifier_uris", [f"api://{API_APPLICATION_ID}", "api://extra"]),
        ("delegated_scopes", []),
        (
            "delegated_scopes",
            [
                {
                    "scope_id": SCOPE_ID,
                    "value": "access_as_user",
                    "consent": "admins_only",
                    "enabled": False,
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
        ),
        (
            "delegated_scopes",
            [
                {
                    "scope_id": SCOPE_ID,
                    "value": "wrong_scope",
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
        ),
        (
            "delegated_scopes",
            [
                {
                    "scope_id": SCOPE_ID,
                    "value": "access_as_user",
                    "consent": "admins_and_users",
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
        ),
        ("sign_in_audience", "AzureADMultipleOrgs"),
        ("requested_access_token_version", 1),
        ("requested_access_token_version", None),
        ("accept_mapped_claims", True),
        ("web_redirect_uris", ["https://client.invalid/callback"]),
        ("spa_redirect_uris", ["https://client.invalid/callback"]),
        ("public_client_redirect_uris", ["http://localhost/callback"]),
        ("implicit_access_token_enabled", True),
        ("implicit_id_token_enabled", True),
        ("public_client_fallback_enabled", True),
        ("password_credential_ids", ["00000000-0000-4000-8000-000000000003"]),
        ("key_credential_ids", ["00000000-0000-4000-8000-000000000004"]),
        (
            "federated_identity_credential_ids",
            ["00000000-0000-4000-8000-000000000104"],
        ),
        ("app_role_ids", ["00000000-0000-4000-8000-000000000005"]),
        (
            "preauthorized_client_application_ids",
            ["00000000-0000-4000-8000-000000000006"],
        ),
        (
            "known_client_application_ids",
            ["00000000-0000-4000-8000-000000000106"],
        ),
        (
            "required_resource_application_ids",
            ["00000000-0000-4000-8000-000000000107"],
        ),
        ("optional_claims_configured", True),
        ("group_membership_claims_configured", True),
        ("token_encryption_key_configured", True),
        ("add_in_ids", ["00000000-0000-4000-8000-000000000108"]),
        ("home_page_url", "https://engineer4me.com"),
        ("logout_url", "https://engineer4me.com/logout"),
    ],
)
def test_registration_rejects_unsafe_or_ambiguous_desired_state(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(EntraAPIRegistrationReadinessError, match="contract"):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", TENANT_ID.upper()),
        ("api_application_id", API_APPLICATION_ID.upper()),
        ("application_object_id", APPLICATION_OBJECT_ID.upper()),
        ("owner_object_ids", [OWNER_ID.upper()]),
    ],
)
def test_registration_rejects_noncanonical_uuid_text(field, replacement):
    value = values()
    value["registration"][field] = replacement
    with pytest.raises(EntraAPIRegistrationReadinessError, match="contract"):
        load(value)


@pytest.mark.parametrize(
    "field",
    ["tenant_id", "api_application_id", "application_object_id"],
)
def test_registration_rejects_nil_primary_identifiers(field):
    value = values()
    value["registration"][field] = "00000000-0000-0000-0000-000000000000"
    if field == "api_application_id":
        value["registration"]["identifier_uris"] = [
            "api://00000000-0000-0000-0000-000000000000"
        ]
    with pytest.raises(EntraAPIRegistrationReadinessError, match="contract"):
        load(value)


def test_registration_rejects_nil_scope_or_owner_identifier():
    for target in ("scope", "owner"):
        value = values()
        if target == "scope":
            value["registration"]["delegated_scopes"][0]["scope_id"] = (
                "00000000-0000-0000-0000-000000000000"
            )
        else:
            value["registration"]["owner_object_ids"] = [
                "00000000-0000-0000-0000-000000000000"
            ]
        with pytest.raises(EntraAPIRegistrationReadinessError, match="contract"):
            load(value)


def test_document_rejects_unknown_or_sensitive_fields_without_disclosure():
    sentinel = "private-client-secret-step202"
    for field in ("client_secret", "password", "private_key", "access_token"):
        value = values()
        value[field] = sentinel
        with pytest.raises(EntraAPIRegistrationReadinessError) as captured:
            load(value)
        assert sentinel not in str(captured.value)
        assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"not-json",
        b"[]",
        b'"scalar"',
        b'{"document_type":"x","document_type":"y"}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b"\xff",
    ],
)
def test_document_rejects_malformed_duplicate_nonfinite_or_nonobject_input(document):
    with pytest.raises(EntraAPIRegistrationReadinessError):
        load_entra_api_registration_readiness(
            document=document,
            authentication_preview=authentication_preview(),
        )


def test_document_rejects_oversized_input_and_nonbytes():
    with pytest.raises(EntraAPIRegistrationReadinessError, match="byte limit"):
        load_entra_api_registration_readiness(
            document=b"x" * (MAX_ENTRA_API_REGISTRATION_DOCUMENT_BYTES + 1),
            authentication_preview=authentication_preview(),
        )


def test_document_rejects_excessive_nesting_with_sanitized_error():
    nested: object = "leaf"
    for _ in range(20):
        nested = [nested]
    with pytest.raises(
        EntraAPIRegistrationReadinessError,
        match="nesting limit",
    ) as captured:
        load_entra_api_registration_readiness(
            document=json.dumps({"nested": nested}).encode(),
            authentication_preview=authentication_preview(),
        )
    assert captured.value.__cause__ is None
    with pytest.raises(TypeError):
        load_entra_api_registration_readiness(
            document="not-bytes",  # type: ignore[arg-type]
            authentication_preview=authentication_preview(),
        )


def test_receipt_forgery_and_wrong_renderer_type_fail_closed():
    receipt = load()
    for field in (
        "activation_ready",
        "provider_state_checked",
        "live_registration_checked",
        "live_application_exists_checked",
        "admin_consent_checked",
        "calling_client_registration_checked",
        "runtime_scope_enforcement",
        "delegated_token_enforcement",
        "roleless_app_token_rejection",
        "calling_client_identity_checked",
        "azp_checked",
        "service_principal_checked",
        "service_principal_assignment_required_checked",
        "service_principal_lock_checked",
        "claims_policy_assignments_checked",
        "provider_ownership_checked",
        "owner_tenant_membership_checked",
        "application_creation_performed",
    ):
        with pytest.raises(ValueError):
            render_entra_api_registration_readiness_receipt(
                replace(receipt, **{field: True})
            )
    with pytest.raises(TypeError):
        render_entra_api_registration_readiness_receipt(object())  # type: ignore[arg-type]


def test_parser_uses_no_file_environment_network_database_or_application_io(
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external or global I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    receipt = load()
    assert receipt.configuration_bound is True
    assert receipt.live_registration_checked is False
