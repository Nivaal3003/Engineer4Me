"""Tests for the offline Entra application/service-principal projection."""

from __future__ import annotations

import builtins
from dataclasses import fields, replace
import json

import pytest

from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCOPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
    MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_BYTES,
    EntraApplicationServicePrincipalInventoryReadinessError,
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
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


def api_registration_document(preview=None):
    return json.dumps(api_registration_values(preview)).encode()


def calling_client_values(preview=None, api_receipt=None):
    preview = preview or authentication_preview()
    api_receipt = api_receipt or load_entra_api_registration_readiness(
        document=api_registration_document(preview),
        authentication_preview=preview,
    )
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
            "desired_runtime_oidc_scopes": [
                "offline_access",
                "openid",
                "profile",
            ],
            "desired_runtime_api_scope": (
                f"api://{API_APPLICATION_ID}/access_as_user"
            ),
            "home_page_url": None,
            "logout_url": None,
        },
    }


def registration_prerequisites(preview=None):
    preview = preview or authentication_preview()
    api_document = api_registration_document(preview)
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
    return {
        "api_registration_document": api_document,
        "accepted_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "calling_client_registration_document": client_document,
        "accepted_calling_client_registration_document_sha256": (
            client_receipt.client_registration_document_sha256
        ),
    }


def values(preview=None, prerequisites=None):
    preview = preview or authentication_preview()
    prerequisites = prerequisites or registration_prerequisites(preview)
    return {
        "document_type": (
            ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE
        ),
        "schema_version": 1,
        "source": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": (
            prerequisites["accepted_api_registration_document_sha256"]
        ),
        "approved_calling_client_registration_document_sha256": (
            prerequisites[
                "accepted_calling_client_registration_document_sha256"
            ]
        ),
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
                    "service_principal_object_id": (
                        API_SERVICE_PRINCIPAL_OBJECT_ID
                    ),
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


def encoded(value=None, preview=None, prerequisites=None):
    return json.dumps(
        values(preview, prerequisites) if value is None else value
    ).encode()


def load(value=None, preview=None, prerequisites=None):
    preview = preview or authentication_preview()
    prerequisites = prerequisites or registration_prerequisites(preview)
    return load_entra_application_service_principal_inventory_readiness(
        document=encoded(value, preview, prerequisites),
        authentication_preview=preview,
        **prerequisites,
    )


def test_valid_projection_binds_and_renders_private_canonical_receipt():
    receipt = load()
    assert receipt.receipt_type == (
        ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE
    )
    assert receipt.schema_version == 1
    assert receipt.source == ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE
    assert receipt.application_count == 2
    assert receipt.service_principal_count == 2
    assert receipt.enabled_service_principal_count == 2
    assert receipt.not_disabled_service_principal_count == 2
    assert receipt.configuration_bound is True
    assert receipt.api_registration_bound is True
    assert receipt.calling_client_registration_bound is True
    assert receipt.application_identity_projection_validated is True
    assert receipt.service_principal_identity_projection_validated is True
    assert receipt.application_service_principal_relationships_validated is True
    assert receipt.tenant_ownership_projection_validated is True
    assert receipt.account_enabled_projection_validated is True
    assert receipt.service_principal_type_projection_validated is True
    assert receipt.microsoft_disablement_projection_validated is True
    assert receipt.local_projection_validated is True

    parsed = json.loads(
        render_entra_application_service_principal_inventory_readiness_receipt(
            receipt
        )
    )
    assert set(parsed) == {field.name for field in fields(receipt)} | {
        "validation_scope"
    }
    assert parsed["validation_scope"] == (
        ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCOPE
    )
    for name in (
        "provider_state_checked",
        "provider_io_performed",
        "live_inventory_checked",
        "source_authenticity_checked",
        "provider_ownership_checked",
        "owner_tenant_membership_checked",
        "tenant_external_status_checked",
        "application_credential_inventory_checked",
        "service_principal_credential_inventory_checked",
        "service_principal_assignment_required_checked",
        "service_principal_lock_checked",
        "claims_policy_assignments_checked",
        "delegated_permission_grant_checked",
        "admin_consent_checked",
        "user_flow_checked",
        "conditional_access_checked",
        "runtime_pkce_s256_checked",
        "runtime_azpacr_public_client_checked",
        "real_signed_token_checked",
        "redirect_endpoint_ownership_checked",
        "redirect_tls_checked",
        "open_redirect_behavior_checked",
        "application_creation_performed",
        "service_principal_creation_performed",
        "activation_ready",
    ):
        assert parsed[name] is False


def test_receipt_omits_raw_provider_identifiers_and_registration_metadata():
    rendered = (
        render_entra_application_service_principal_inventory_readiness_receipt(
            load()
        )
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
        "Engineer4Me API",
        "Engineer4Me Web",
        "access_as_user",
        "api://",
        "Authorization",
        "Bearer ",
    ):
        assert raw not in rendered


def test_all_receipt_digests_are_canonical_lowercase_sha256():
    receipt = load()
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            value = getattr(receipt, field.name)
            assert len(value) == 64
            assert value == value.lower()
            int(value, 16)


def test_canonical_digest_ignores_json_whitespace_and_key_order():
    original = values()
    reversed_root = dict(reversed(list(original.items())))
    reversed_root["inventory"] = dict(
        reversed(list(original["inventory"].items()))
    )
    prerequisites = registration_prerequisites()
    preview = authentication_preview()
    left = load_entra_application_service_principal_inventory_readiness(
        document=json.dumps(original, separators=(",", ":")).encode(),
        authentication_preview=preview,
        **prerequisites,
    )
    right = load_entra_application_service_principal_inventory_readiness(
        document=json.dumps(reversed_root, indent=2).encode(),
        authentication_preview=preview,
        **prerequisites,
    )
    assert left == right


def test_service_principal_identity_changes_only_related_projection_evidence():
    original = load()
    changed = values()
    changed["inventory"]["service_principals"][0][
        "service_principal_object_id"
    ] = "55555555-6666-4777-8888-999999999999"
    revised = load(changed)
    assert revised.inventory_document_sha256 != original.inventory_document_sha256
    assert revised.api_service_principal_object_id_sha256 != (
        original.api_service_principal_object_id_sha256
    )
    assert revised.api_application_service_principal_relationship_sha256 != (
        original.api_application_service_principal_relationship_sha256
    )
    assert revised.api_application_id_sha256 == original.api_application_id_sha256
    assert revised.calling_client_service_principal_object_id_sha256 == (
        original.calling_client_service_principal_object_id_sha256
    )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("inventory", "tenant_id"), "00000000-0000-4000-8000-000000000201"),
        (
            ("inventory", "applications", 0, "application_id"),
            "00000000-0000-4000-8000-000000000202",
        ),
        (
            ("inventory", "applications", 0, "application_object_id"),
            "00000000-0000-4000-8000-000000000203",
        ),
        (
            ("inventory", "applications", 1, "application_id"),
            "00000000-0000-4000-8000-000000000204",
        ),
        (
            ("inventory", "applications", 1, "application_object_id"),
            "00000000-0000-4000-8000-000000000205",
        ),
        (
            ("inventory", "service_principals", 0, "application_id"),
            CALLING_CLIENT_APPLICATION_ID,
        ),
        (
            (
                "inventory",
                "service_principals",
                0,
                "application_owner_organization_id",
            ),
            "00000000-0000-4000-8000-000000000207",
        ),
        (
            ("inventory", "service_principals", 1, "application_id"),
            API_APPLICATION_ID,
        ),
        (
            (
                "inventory",
                "service_principals",
                1,
                "application_owner_organization_id",
            ),
            "00000000-0000-4000-8000-000000000209",
        ),
    ],
)
def test_projection_rejects_any_identity_or_relationship_mismatch(path, replacement):
    value = values()
    target = value
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("collection", "replacement"),
    [
        ("applications", []),
        ("applications", [{"role": "api"}]),
        ("service_principals", []),
        ("service_principals", [{"role": "api"}]),
    ],
)
def test_projection_requires_exact_two_entry_collections(collection, replacement):
    value = values()
    value["inventory"][collection] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize("collection", ["applications", "service_principals"])
def test_projection_requires_canonical_api_then_client_role_order(collection):
    value = values()
    value["inventory"][collection].reverse()
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize("collection", ["applications", "service_principals"])
def test_projection_rejects_duplicate_roles(collection):
    value = values()
    value["inventory"][collection][1]["role"] = "api"
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("service_principal_type", "ManagedIdentity"),
        ("service_principal_type", "AgentIdentityBlueprintPrincipal"),
        ("account_enabled", False),
        ("account_enabled", 1),
        ("account_enabled", "true"),
        ("account_enabled", None),
    ],
)
def test_projection_rejects_wrong_or_disabled_service_principal(field, replacement):
    value = values()
    value["inventory"]["service_principals"][0][field] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        "DisabledDueToViolationOfServicesAgreement",
        "DisabledByMicrosoft",
        "notdisabled",
        "",
        False,
        0,
        [],
        {},
    ],
)
def test_projection_rejects_any_unapproved_microsoft_disabled_status(replacement):
    value = values()
    value["inventory"]["service_principals"][0][
        "disabled_by_microsoft_status"
    ] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        "00000000-0000-0000-0000-000000000000",
        "{bbbbbbbb-cccc-4ddd-8eee-ffffffff0300}",
        "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFF0300",
        "bbbbbbbbcccc4ddd8eeeffffffff0300",
        "urn:uuid:bbbbbbbb-cccc-4ddd-8eee-ffffffff0300",
        " bbbbbbbb-cccc-4ddd-8eee-ffffffff0300",
        1,
        True,
        None,
    ],
)
def test_projection_rejects_noncanonical_or_zero_uuid_inputs(replacement):
    value = values()
    value["inventory"]["applications"][0]["application_id"] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
    ],
)
def test_projection_rejects_confused_or_duplicate_identifiers(replacement):
    value = values()
    value["inventory"]["service_principals"][0][
        "service_principal_object_id"
    ] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("principal_index", "owner_id"),
    [
        (0, OWNER_ID),
        (1, OWNER_ID_2),
    ],
)
def test_projection_rejects_service_principal_collision_with_reviewed_owner(
    principal_index,
    owner_id,
):
    value = values()
    value["inventory"]["service_principals"][principal_index][
        "service_principal_object_id"
    ] = owner_id
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="identities",
    ):
        load(value)


@pytest.mark.parametrize(
    ("application_index", "owner_id"),
    [
        (0, OWNER_ID),
        (1, OWNER_ID_2),
    ],
)
def test_projection_rejects_application_object_collision_with_reviewed_owner(
    application_index,
    owner_id,
):
    value = values()
    value["inventory"]["applications"][application_index][
        "application_object_id"
    ] = owner_id
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="identities",
    ):
        load(value)


def test_projection_allows_one_reviewed_owner_shared_across_both_applications():
    preview = authentication_preview()
    api_values = api_registration_values(preview)
    api_document = json.dumps(api_values).encode()
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    client_values = calling_client_values(preview, api_receipt)
    client_values["registration"]["owner_object_ids"] = [OWNER_ID, OWNER_ID_2]
    client_document = json.dumps(client_values).encode()
    client_receipt = load_entra_calling_client_registration_readiness(
        document=client_document,
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    prerequisites = {
        "api_registration_document": api_document,
        "accepted_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "calling_client_registration_document": client_document,
        "accepted_calling_client_registration_document_sha256": (
            client_receipt.client_registration_document_sha256
        ),
    }
    receipt = load(
        values(preview, prerequisites),
        preview=preview,
        prerequisites=prerequisites,
    )
    assert receipt.local_projection_validated is True


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("document_type", "wrong"),
        ("schema_version", 2),
        ("schema_version", True),
        ("source", "microsoft_graph_beta"),
        ("source", "portal_copy"),
        ("source", None),
        ("approved_configuration_sha256", "0" * 64),
        ("approved_api_registration_document_sha256", "0" * 64),
        ("approved_calling_client_registration_document_sha256", "0" * 64),
    ],
)
def test_projection_rejects_wrong_contract_or_approval_binding(field, replacement):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("approved_configuration_sha256", "A" * 64),
        ("approved_configuration_sha256", "0" * 63),
        ("approved_configuration_sha256", "g" * 64),
        ("approved_api_registration_document_sha256", 1),
        ("approved_calling_client_registration_document_sha256", None),
    ],
)
def test_projection_rejects_noncanonical_digest_fields(field, replacement):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraApplicationServicePrincipalInventoryReadinessError):
        load(value)


def test_projection_rejects_unknown_fields_at_every_boundary():
    mutations = []
    root = values()
    root["access_token"] = "forbidden"
    mutations.append(root)
    inventory = values()
    inventory["inventory"]["provider_checked"] = True
    mutations.append(inventory)
    application = values()
    application["inventory"]["applications"][0]["display_name"] = "forbidden"
    mutations.append(application)
    principal = values()
    principal["inventory"]["service_principals"][0]["client_secret"] = "x"
    mutations.append(principal)
    for value in mutations:
        with pytest.raises(
            EntraApplicationServicePrincipalInventoryReadinessError
        ):
            load(value)


def test_projection_requires_independently_accepted_registration_digests():
    preview = authentication_preview()
    prerequisites = registration_prerequisites(preview)
    for field in (
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
    ):
        altered = dict(prerequisites)
        altered[field] = "0" * 64
        with pytest.raises(
            EntraApplicationServicePrincipalInventoryReadinessError,
            match="accepted|digests",
        ):
            load_entra_application_service_principal_inventory_readiness(
                document=encoded(values(preview, prerequisites)),
                authentication_preview=preview,
                **altered,
            )


def test_projection_revalidates_raw_registration_documents_not_receipts():
    preview = authentication_preview()
    prerequisites = registration_prerequisites(preview)
    altered = dict(prerequisites)
    changed_api = api_registration_values(preview)
    changed_api["registration"]["display_name"] = "Wrong API"
    altered["api_registration_document"] = json.dumps(changed_api).encode()
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="registration evidence",
    ):
        load_entra_application_service_principal_inventory_readiness(
            document=encoded(values(preview, prerequisites)),
            authentication_preview=preview,
            **altered,
        )


def test_projection_rejects_self_consistent_but_unaccepted_client_document():
    preview = authentication_preview()
    prerequisites = registration_prerequisites(preview)
    api_document = prerequisites["api_registration_document"]
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    changed = calling_client_values(preview, api_receipt)
    changed["registration"]["spa_redirect_uris"] = [
        "https://other.engineer4me.invalid/auth/callback"
    ]
    changed_document = json.dumps(changed).encode()
    changed_receipt = load_entra_calling_client_registration_readiness(
        document=changed_document,
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    altered = dict(prerequisites)
    altered["calling_client_registration_document"] = changed_document
    altered["accepted_calling_client_registration_document_sha256"] = (
        changed_receipt.client_registration_document_sha256
    )
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="authentication readiness",
    ):
        load_entra_application_service_principal_inventory_readiness(
            document=encoded(values(preview, prerequisites)),
            authentication_preview=preview,
            **altered,
        )


def test_forged_step206_preview_is_rejected_before_projection_acceptance():
    preview = authentication_preview()
    prerequisites = registration_prerequisites(preview)
    forged = replace(preview, microsoft_entra_required_azpacr=None)
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="prerequisite",
    ):
        load_entra_application_service_principal_inventory_readiness(
            document=encoded(values(preview, prerequisites)),
            authentication_preview=forged,
            **prerequisites,
        )


def test_nonbytes_and_wrong_prerequisite_types_are_rejected():
    preview = authentication_preview()
    prerequisites = registration_prerequisites(preview)
    with pytest.raises(TypeError, match="document must be bytes"):
        load_entra_application_service_principal_inventory_readiness(
            document="{}",
            authentication_preview=preview,
            **prerequisites,
        )
    for field, replacement, message in (
        ("authentication_preview", object(), "preview"),
        ("api_registration_document", object(), "API registration document"),
        (
            "calling_client_registration_document",
            object(),
            "calling-client document",
        ),
        ("accepted_api_registration_document_sha256", object(), "digest"),
        (
            "accepted_calling_client_registration_document_sha256",
            object(),
            "digest",
        ),
    ):
        arguments = {
            "document": encoded(values(preview, prerequisites)),
            "authentication_preview": preview,
            **prerequisites,
        }
        arguments[field] = replacement
        with pytest.raises(TypeError, match=message):
            load_entra_application_service_principal_inventory_readiness(
                **arguments
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
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match=message,
    ):
        load_entra_application_service_principal_inventory_readiness(
            document=document,
            authentication_preview=authentication_preview(),
            **registration_prerequisites(),
        )


def test_document_byte_limit_is_enforced_before_json_validation():
    oversized = (
        b"{" + b" " * MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_BYTES
    )
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="byte limit",
    ):
        load_entra_application_service_principal_inventory_readiness(
            document=oversized,
            authentication_preview=authentication_preview(),
            **registration_prerequisites(),
        )


def test_document_nesting_limit_is_enforced():
    value = values()
    value["noise"] = [[[[[[[[[["too-deep"]]]]]]]]]]
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="nesting limit",
    ):
        load(value)


def test_document_container_limit_is_enforced():
    value = values()
    value["noise"] = [[] for _ in range(140)]
    with pytest.raises(
        EntraApplicationServicePrincipalInventoryReadinessError,
        match="structure limit",
    ):
        load(value)


def test_loader_performs_no_file_environment_network_or_provider_io(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("external or global I/O is forbidden")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    assert load().local_projection_validated is True


def test_receipt_renderer_requires_exact_receipt_type():
    with pytest.raises(TypeError, match="receipt"):
        render_entra_application_service_principal_inventory_readiness_receipt(
            object()
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("schema_version", True),
        ("source", "microsoft_graph_beta"),
        ("configuration_sha256", "0" * 63),
        ("inventory_document_sha256", "g" * 64),
        ("application_count", 1),
        ("application_count", True),
        ("service_principal_count", 3),
        ("enabled_service_principal_count", 1),
        ("not_disabled_service_principal_count", 1),
        ("configuration_bound", False),
        ("api_registration_bound", False),
        ("calling_client_registration_bound", False),
        ("application_identity_projection_validated", False),
        ("service_principal_identity_projection_validated", False),
        ("application_service_principal_relationships_validated", False),
        ("tenant_ownership_projection_validated", False),
        ("account_enabled_projection_validated", False),
        ("service_principal_type_projection_validated", False),
        ("microsoft_disablement_projection_validated", False),
        ("local_projection_validated", False),
        ("provider_state_checked", True),
        ("provider_io_performed", True),
        ("live_inventory_checked", True),
        ("source_authenticity_checked", True),
        ("provider_ownership_checked", True),
        ("owner_tenant_membership_checked", True),
        ("tenant_external_status_checked", True),
        ("application_credential_inventory_checked", True),
        ("service_principal_credential_inventory_checked", True),
        ("service_principal_assignment_required_checked", True),
        ("service_principal_lock_checked", True),
        ("claims_policy_assignments_checked", True),
        ("delegated_permission_grant_checked", True),
        ("admin_consent_checked", True),
        ("user_flow_checked", True),
        ("conditional_access_checked", True),
        ("runtime_pkce_s256_checked", True),
        ("runtime_azpacr_public_client_checked", True),
        ("real_signed_token_checked", True),
        ("redirect_endpoint_ownership_checked", True),
        ("redirect_tls_checked", True),
        ("open_redirect_behavior_checked", True),
        ("application_creation_performed", True),
        ("service_principal_creation_performed", True),
        ("activation_ready", True),
    ],
)
def test_receipt_renderer_rejects_forged_or_overstated_evidence(field, replacement):
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_entra_application_service_principal_inventory_readiness_receipt(
            replace(load(), **{field: replacement})
        )
