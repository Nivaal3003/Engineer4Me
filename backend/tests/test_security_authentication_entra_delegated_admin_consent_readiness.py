"""Tests for the offline Entra delegated admin-consent desired state."""

from __future__ import annotations

import builtins
from dataclasses import fields, replace
import json
import subprocess

import pytest

from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
    load_entra_application_service_principal_inventory_readiness,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    ENTRA_CALLING_CLIENT_ARCHITECTURE,
    ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
    load_entra_calling_client_registration_readiness,
)
from app.security.authentication_entra_delegated_admin_consent_readiness import (
    ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_TYPE,
    ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE,
    ENTRA_DELEGATED_ADMIN_CONSENT_REQUIRED_SCOPE,
    ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE,
    ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE,
    ENTRA_DELEGATED_ADMIN_CONSENT_TYPE,
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_BYTES,
    EntraDelegatedAdminConsentReadinessError,
    load_entra_delegated_admin_consent_readiness,
    render_entra_delegated_admin_consent_readiness_receipt,
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
CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID = (
    "44444444-5555-4666-8777-888888888888"
)
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
REDIRECT_URI = "https://app.engineer4me.invalid/auth/callback"
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


def calling_client_values(preview, api_receipt):
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
            "desired_runtime_api_scope": (
                f"api://{API_APPLICATION_ID}/access_as_user"
            ),
            "home_page_url": None,
            "logout_url": None,
        },
    }


def inventory_values(preview, registration):
    return {
        "document_type": (
            ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE
        ),
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


def prerequisites():
    preview = authentication_preview()
    api_document = json.dumps(api_registration_values(preview)).encode()
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    client_document = json.dumps(
        calling_client_values(preview, api_receipt)
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
    inventory_document = json.dumps(
        inventory_values(preview, registration)
    ).encode()
    inventory_receipt = (
        load_entra_application_service_principal_inventory_readiness(
            document=inventory_document,
            authentication_preview=preview,
            **registration,
        )
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
        "document_type": ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE,
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
        "grant": {
            "clientId": CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
            "consentType": ENTRA_DELEGATED_ADMIN_CONSENT_TYPE,
            "principalId": None,
            "resourceId": API_SERVICE_PRINCIPAL_OBJECT_ID,
            "scope": ENTRA_DELEGATED_ADMIN_CONSENT_REQUIRED_SCOPE,
        },
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return load_entra_delegated_admin_consent_readiness(
        document=json.dumps(
            values(prerequisite) if value is None else value
        ).encode(),
        **prerequisite,
    )


def test_valid_desired_state_binds_exact_service_principals_and_scope():
    receipt = load()
    assert receipt.receipt_type == ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.source == ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE
    assert receipt.validation_scope == ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE
    assert receipt.desired_grant_count == 1
    assert receipt.desired_scope_count == 1
    assert receipt.configuration_bound is True
    assert receipt.api_registration_bound is True
    assert receipt.calling_client_registration_bound is True
    assert receipt.approved_inventory_digest_bound is True
    assert receipt.client_service_principal_bound is True
    assert receipt.resource_service_principal_bound is True
    assert receipt.application_ids_not_used_as_principal_ids is True
    assert receipt.tenant_wide_consent_type_validated is True
    assert receipt.null_principal_id_validated is True
    assert receipt.exact_delegated_scope_validated is True
    assert receipt.single_scope_validated is True
    assert (
        receipt.normalized_oauth2_permission_grant_desired_shape_validated
        is True
    )
    assert (
        receipt.provider_generated_grant_id_excluded_from_desired_state
        is True
    )
    assert receipt.ready_to_post_payload is False
    assert receipt.offline_desired_state_validated is True


def test_receipt_preserves_all_provider_and_mutation_boundaries_as_false():
    receipt = load()
    for field in (
        "provider_io_performed",
        "provider_state_checked",
        "source_authenticity_checked",
        "live_service_principal_inventory_checked",
        "delegated_permission_grant_checked",
        "exact_existing_grant_count_checked",
        "duplicate_or_overlapping_grants_checked",
        "admin_consent_checked",
        "admin_consent_effectiveness_checked",
        "consent_propagation_checked",
        "operator_identity_checked",
        "operator_role_checked",
        "operator_authorization_checked",
        "graph_permission_grant_checked",
        "tenant_policy_checked",
        "user_assignment_checked",
        "user_flow_checked",
        "conditional_access_checked",
        "runtime_pkce_s256_checked",
        "real_signed_token_scope_checked",
        "grant_creation_performed",
        "grant_update_performed",
        "grant_deletion_performed",
        "application_mutation_performed",
        "service_principal_mutation_performed",
        "activation_ready",
        "ready_to_post_payload",
    ):
        assert getattr(receipt, field) is False


def test_rendered_receipt_is_canonical_private_and_omits_raw_grant_state():
    receipt = load()
    rendered = render_entra_delegated_admin_consent_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert set(parsed) == {field.name for field in fields(receipt)}
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
        "access_as_user",
        "AllPrincipals",
        "clientId",
        "resourceId",
        "principalId",
    ):
        assert raw not in rendered
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            digest = getattr(receipt, field.name)
            assert len(digest) == 64
            assert digest == digest.lower()
            int(digest, 16)


def test_canonical_document_digest_ignores_key_order_and_whitespace():
    prerequisite = prerequisites()
    original = values(prerequisite)
    reversed_document = dict(reversed(list(original.items())))
    reversed_document["grant"] = dict(
        reversed(list(original["grant"].items()))
    )
    compact = load_entra_delegated_admin_consent_readiness(
        document=json.dumps(original, separators=(",", ":")).encode(),
        **prerequisite,
    )
    pretty = load_entra_delegated_admin_consent_readiness(
        document=json.dumps(reversed_document, indent=2).encode(),
        **prerequisite,
    )
    assert compact == pretty


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("clientId", CALLING_CLIENT_APPLICATION_ID),
        ("clientId", CALLING_CLIENT_OBJECT_ID),
        ("clientId", API_APPLICATION_OBJECT_ID),
        ("clientId", API_SERVICE_PRINCIPAL_OBJECT_ID),
        ("clientId", API_APPLICATION_ID),
        ("resourceId", API_APPLICATION_ID),
        ("resourceId", API_APPLICATION_OBJECT_ID),
        ("resourceId", CALLING_CLIENT_OBJECT_ID),
        ("resourceId", CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID),
        ("resourceId", CALLING_CLIENT_APPLICATION_ID),
        ("clientId", "55555555-6666-4777-8888-999999999999"),
        ("resourceId", "66666666-7777-4888-8999-aaaaaaaaaaaa"),
    ],
)
def test_grant_rejects_app_id_object_id_role_reversal_or_equal_principals(
    field,
    replacement,
):
    value = values()
    value["grant"][field] = replacement
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("consentType", "Principal"),
        ("consentType", "allprincipals"),
        ("consentType", "AllPrincipals "),
        ("consentType", None),
        ("principalId", OWNER_ID),
        ("principalId", ""),
        ("principalId", False),
        ("scope", "User.Read"),
        ("scope", "access_as_user User.Read"),
        ("scope", "openid access_as_user"),
        ("scope", " access_as_user"),
        ("scope", "access_as_user "),
        ("scope", "ACCESS_AS_USER"),
        ("scope", ""),
        ("scope", None),
    ],
)
def test_grant_rejects_non_tenant_wide_principal_or_any_scope_widening(
    field,
    replacement,
):
    value = values()
    value["grant"][field] = replacement
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


def test_principal_id_must_be_explicitly_present_and_null():
    value = values()
    value["grant"].pop("principalId")
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize("field", ["id", "@odata.id", "@odata.type", "owner"])
def test_grant_rejects_provider_generated_annotations_or_unknown_fields(field):
    value = values()
    value["grant"][field] = "provider-value"
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize(
    "field",
    [
        "client_service_principal_object_id",
        "consent_type",
        "principal_id",
        "resource_service_principal_object_id",
    ],
)
def test_grant_rejects_internal_model_field_aliases(field):
    value = values()
    value["grant"][field] = value["grant"].pop(
        {
            "client_service_principal_object_id": "clientId",
            "consent_type": "consentType",
            "principal_id": "principalId",
            "resource_service_principal_object_id": "resourceId",
        }[field]
    )
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("document_type", "wrong"),
        ("schema_version", 2),
        ("schema_version", True),
        ("source", "microsoft_graph_beta"),
        ("approved_configuration_sha256", "0" * 64),
        ("approved_api_registration_document_sha256", "0" * 64),
        ("approved_calling_client_registration_document_sha256", "0" * 64),
        ("approved_inventory_document_sha256", "0" * 64),
    ],
)
def test_document_rejects_wrong_contract_or_prerequisite_digest(
    field,
    replacement,
):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        "A" * 64,
        "0" * 63,
        "g" * 64,
        1,
        True,
        None,
    ],
)
def test_document_rejects_noncanonical_approved_inventory_digest(replacement):
    value = values()
    value["approved_inventory_document_sha256"] = replacement
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


def test_independent_approved_inventory_digest_rejects_substitution_before_use():
    prerequisite = prerequisites()
    prerequisite["approved_inventory_document_sha256"] = "0" * 64
    value = values(prerequisite)
    with pytest.raises(
        EntraDelegatedAdminConsentReadinessError,
        match="approved digest",
    ):
        load(value, prerequisite)


def test_new_valid_projection_cannot_replace_the_approved_service_principal():
    prerequisite = prerequisites()
    inventory = json.loads(prerequisite["inventory_document"])
    inventory["inventory"]["service_principals"][1][
        "service_principal_object_id"
    ] = "55555555-6666-4777-8888-999999999999"
    prerequisite["inventory_document"] = json.dumps(inventory).encode()
    value = values(prerequisite)
    with pytest.raises(
        EntraDelegatedAdminConsentReadinessError,
        match="approved digest",
    ):
        load(value, prerequisite)


@pytest.mark.parametrize(
    "digest_field",
    [
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
    ],
)
def test_altered_accepted_registration_digest_rejects_prerequisite_chain(
    digest_field,
):
    prerequisite = prerequisites()
    prerequisite[digest_field] = "0" * 64
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(values(), prerequisite)


@pytest.mark.parametrize(
    "replacement",
    [
        "00000000-0000-0000-0000-000000000000",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEE0200",
        API_SERVICE_PRINCIPAL_OBJECT_ID.replace("-", ""),
        f"{{{API_SERVICE_PRINCIPAL_OBJECT_ID}}}",
        f"urn:uuid:{API_SERVICE_PRINCIPAL_OBJECT_ID}",
        1,
        True,
        None,
    ],
)
def test_grant_rejects_zero_noncanonical_or_wrong_type_uuids(replacement):
    value = values()
    value["grant"]["resourceId"] = replacement
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(value)


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"[]",
        b"null",
        b"not-json",
        b"\xff",
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
        b'{"schema_version":-Infinity}',
        b'{"schema_version":1,"schema_version":1}',
    ],
)
def test_parser_rejects_empty_non_object_malformed_or_ambiguous_json(document):
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load_entra_delegated_admin_consent_readiness(
            document=document,
            **prerequisites(),
        )


def test_parser_rejects_oversized_deep_or_container_heavy_documents():
    prerequisite = prerequisites()
    oversized = b"{" + b" " * MAX_ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_BYTES + b"}"
    with pytest.raises(EntraDelegatedAdminConsentReadinessError, match="byte"):
        load_entra_delegated_admin_consent_readiness(
            document=oversized,
            **prerequisite,
        )
    deep = values(prerequisite)
    deep["extra"] = {"a": {"b": {"c": {"d": {"e": {}}}}}}
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(deep, prerequisite)
    heavy = values(prerequisite)
    heavy["extra"] = [{} for _ in range(20)]
    with pytest.raises(EntraDelegatedAdminConsentReadinessError):
        load(heavy, prerequisite)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("provider_io_performed", True),
        ("provider_state_checked", True),
        ("delegated_permission_grant_checked", True),
        ("admin_consent_checked", True),
        ("grant_creation_performed", True),
        ("ready_to_post_payload", True),
        ("activation_ready", True),
        ("approved_inventory_document_sha256", "0" * 64),
        ("desired_grant_count", 2),
        ("desired_scope_count", 2),
    ],
)
def test_receipt_cannot_promote_deferred_checks_or_break_invariants(
    field,
    replacement,
):
    with pytest.raises(ValueError):
        replace(load(), **{field: replacement})


def test_renderer_revalidates_exact_type_and_receipt_invariants():
    with pytest.raises(TypeError):
        render_entra_delegated_admin_consent_readiness_receipt(object())


def test_loader_requires_bytes_and_explicit_canonical_inventory_digest():
    prerequisite = prerequisites()
    with pytest.raises(TypeError):
        load_entra_delegated_admin_consent_readiness(
            document="not-bytes",
            **prerequisite,
        )
    with pytest.raises(TypeError):
        load_entra_delegated_admin_consent_readiness(
            document=json.dumps(values(prerequisite)).encode(),
            **prerequisite
            | {"approved_inventory_document_sha256": "A" * 64},
        )


def test_loader_performs_no_file_environment_database_or_network_io(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("unexpected I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    receipt = load()
    assert receipt.provider_io_performed is False
