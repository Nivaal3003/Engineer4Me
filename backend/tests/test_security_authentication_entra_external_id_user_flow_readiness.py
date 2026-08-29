"""Tests for the offline External ID user-flow application projection."""

from __future__ import annotations

import builtins
import copy
from dataclasses import fields
import json
import socket

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
from app.security.authentication_entra_external_id_user_flow_readiness import (
    ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_BYTES,
    EntraExternalIdUserFlowReadinessError,
    load_entra_external_id_user_flow_readiness,
    render_entra_external_id_user_flow_readiness_receipt,
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
USER_FLOW_ID = "55555555-6666-4777-8abc-999999999999"
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
    client_document = json.dumps(calling_client_values(preview, api_receipt)).encode()
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
        "document_type": ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE,
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
        "user_flow": {
            "id": USER_FLOW_ID,
            "@odata.type": ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
            "conditions": {
                "applications": {
                    "includeAllApplications": False,
                    "includeApplications": [
                        {"appId": CALLING_CLIENT_APPLICATION_ID}
                    ],
                }
            },
        },
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return load_entra_external_id_user_flow_readiness(
        document=json.dumps(
            values(prerequisite) if value is None else value
        ).encode(),
        **prerequisite,
    )


def test_valid_projection_binds_flow_to_calling_client_application_and_local_sp():
    receipt = load()
    assert receipt.receipt_type == ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.source == ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE
    assert receipt.validation_scope == ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE
    assert receipt.desired_user_flow_count == 1
    assert receipt.desired_included_application_count == 1
    for name in (
        "configuration_bound",
        "tenant_id_bound",
        "api_registration_bound",
        "calling_client_registration_bound",
        "approved_inventory_digest_bound",
        "canonical_user_flow_id_validated",
        "user_flow_id_collision_separation_validated",
        "external_users_self_service_sign_up_flow_type_validated",
        "include_all_applications_false_validated",
        "exact_single_included_application_validated",
        "calling_client_application_id_bound",
        "calling_client_service_principal_app_id_mapping_validated",
        "application_id_used_for_association",
        "api_application_id_not_used_for_association",
        "application_object_id_not_used_for_association",
        "service_principal_object_id_not_used_for_association",
        "registration_owner_ids_not_used_as_user_flow_id",
        "calling_client_service_principal_projection_validated",
        "normalized_read_projection_validated",
        "offline_desired_state_validated",
    ):
        assert getattr(receipt, name) is True


def test_receipt_preserves_every_live_policy_runtime_and_mutation_boundary_false():
    receipt = load()
    validated = {
        "configuration_bound",
        "tenant_id_bound",
        "api_registration_bound",
        "calling_client_registration_bound",
        "approved_inventory_digest_bound",
        "canonical_user_flow_id_validated",
        "user_flow_id_collision_separation_validated",
        "external_users_self_service_sign_up_flow_type_validated",
        "include_all_applications_false_validated",
        "exact_single_included_application_validated",
        "calling_client_application_id_bound",
        "calling_client_service_principal_app_id_mapping_validated",
        "application_id_used_for_association",
        "api_application_id_not_used_for_association",
        "application_object_id_not_used_for_association",
        "service_principal_object_id_not_used_for_association",
        "registration_owner_ids_not_used_as_user_flow_id",
        "calling_client_service_principal_projection_validated",
        "normalized_read_projection_validated",
        "offline_desired_state_validated",
    }
    for field in fields(receipt):
        value = getattr(receipt, field.name)
        if isinstance(value, bool) and field.name not in validated:
            assert value is False


def test_rendered_receipt_is_canonical_private_and_omits_raw_identities():
    receipt = load()
    rendered = render_entra_external_id_user_flow_readiness_receipt(receipt)
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
        USER_FLOW_ID,
        OWNER_ID,
        OWNER_ID_2,
        REDIRECT_URI,
        "appId",
        "includeApplications",
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
    reversed_document["user_flow"] = dict(
        reversed(list(original["user_flow"].items()))
    )
    compact = load_entra_external_id_user_flow_readiness(
        document=json.dumps(original, separators=(",", ":")).encode(),
        **prerequisite,
    )
    pretty = load_entra_external_id_user_flow_readiness(
        document=json.dumps(reversed_document, indent=2).encode(),
        **prerequisite,
    )
    assert compact == pretty


@pytest.mark.parametrize(
    "replacement",
    [
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
    ],
)
def test_user_flow_id_rejects_every_known_identity_collision(replacement):
    value = values()
    value["user_flow"]["id"] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SERVICE_PRINCIPAL_OBJECT_ID,
        CALLING_CLIENT_OBJECT_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        TENANT_ID,
        API_SCOPE_ID,
        OWNER_ID,
        USER_FLOW_ID,
        "66666666-7777-4888-8999-aaaaaaaaaaaa",
    ],
)
def test_association_rejects_any_identity_other_than_calling_client_app_id(
    replacement,
):
    value = values()
    value["user_flow"]["conditions"]["applications"]["includeApplications"][0][
        "appId"
    ] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        "#microsoft.graph.authenticationEventsFlow",
        "#microsoft.graph.externalUsersSelfServiceSignupEventsFlow",
        "microsoft.graph.externalUsersSelfServiceSignUpEventsFlow",
        "#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow ",
        "#Microsoft.Graph.externalUsersSelfServiceSignUpEventsFlow",
        "",
        None,
    ],
)
def test_user_flow_requires_exact_external_users_wire_type(replacement):
    value = values()
    value["user_flow"]["@odata.type"] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize("replacement", [True, 0, 1, "false", None, [], {}])
def test_include_all_applications_requires_exact_boolean_false(replacement):
    value = values()
    value["user_flow"]["conditions"]["applications"][
        "includeAllApplications"
    ] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    "replacement",
    [
        [],
        [
            {"appId": CALLING_CLIENT_APPLICATION_ID},
            {"appId": CALLING_CLIENT_APPLICATION_ID},
        ],
        None,
        {},
        "calling-client",
    ],
)
def test_include_applications_requires_exactly_one_entry(replacement):
    value = values()
    value["user_flow"]["conditions"]["applications"][
        "includeApplications"
    ] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    "field",
    ["@odata.type", "id", "application_id", "description", "servicePrincipalId"],
)
def test_included_application_rejects_annotations_aliases_and_unknown_fields(field):
    value = values()
    value["user_flow"]["conditions"]["applications"]["includeApplications"][0][
        field
    ] = "unexpected"
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "unexpected"),
        (("user_flow",), "displayName"),
        (("user_flow",), "description"),
        (("user_flow",), "priority"),
        (("user_flow",), "onInteractiveAuthFlowStart"),
        (("user_flow",), "onAuthenticationMethodLoadStart"),
        (("user_flow",), "onAttributeCollection"),
        (("user_flow",), "onUserCreateStart"),
        (("user_flow", "conditions"), "@odata.type"),
        (("user_flow", "conditions"), "users"),
        (("user_flow", "conditions", "applications"), "excludeApplications"),
    ],
)
def test_projection_rejects_full_policy_fields_or_any_unknown_field(path, field):
    value = values()
    target = value
    for part in path:
        target = target[part]
    target[field] = "out-of-scope"
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("user_flow", "id"), "00000000-0000-0000-0000-000000000000"),
        (("user_flow", "id"), USER_FLOW_ID.upper()),
        (("user_flow", "id"), USER_FLOW_ID.replace("-", "")),
        (("user_flow", "id"), "{" + USER_FLOW_ID + "}"),
        (("user_flow", "id"), None),
        (
            (
                "user_flow",
                "conditions",
                "applications",
                "includeApplications",
                0,
                "appId",
            ),
            "00000000-0000-0000-0000-000000000000",
        ),
        (
            (
                "user_flow",
                "conditions",
                "applications",
                "includeApplications",
                0,
                "appId",
            ),
            "{" + CALLING_CLIENT_APPLICATION_ID + "}",
        ),
        (
            (
                "user_flow",
                "conditions",
                "applications",
                "includeApplications",
                0,
                "appId",
            ),
            CALLING_CLIENT_APPLICATION_ID.replace("-", ""),
        ),
        (
            (
                "user_flow",
                "conditions",
                "applications",
                "includeApplications",
                0,
                "appId",
            ),
            1,
        ),
    ],
)
def test_all_uuid_inputs_require_canonical_nonzero_text(path, replacement):
    value = values()
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
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
def test_document_rejects_each_unapproved_or_noncanonical_digest(field):
    value = values()
    value[field] = "0" * 64
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)
    value = values()
    value[field] = value[field].upper()
    if any(character.isalpha() for character in value[field]):
        with pytest.raises(EntraExternalIdUserFlowReadinessError):
            load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("document_type", "wrong"),
        ("document_type", None),
        ("schema_version", 2),
        ("schema_version", True),
        ("source", "microsoft_graph_beta"),
        ("source", None),
    ],
)
def test_document_requires_exact_contract_identity(field, replacement):
    value = values()
    value[field] = replacement
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "document_type"),
        ((), "schema_version"),
        ((), "source"),
        ((), "approved_configuration_sha256"),
        ((), "approved_api_registration_document_sha256"),
        ((), "approved_calling_client_registration_document_sha256"),
        ((), "approved_inventory_document_sha256"),
        ((), "user_flow"),
        (("user_flow",), "id"),
        (("user_flow",), "@odata.type"),
        (("user_flow",), "conditions"),
        (("user_flow", "conditions"), "applications"),
        (
            ("user_flow", "conditions", "applications"),
            "includeAllApplications",
        ),
        (("user_flow", "conditions", "applications"), "includeApplications"),
    ],
)
def test_projection_rejects_every_missing_required_field(path, field):
    value = values()
    target = value
    for part in path:
        target = target[part]
    target.pop(field)
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


def test_included_application_requires_wire_app_id_not_internal_alias():
    value = values()
    entry = value["user_flow"]["conditions"]["applications"][
        "includeApplications"
    ][0]
    entry["application_id"] = entry.pop("appId")
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


def test_user_flow_requires_wire_aliases_not_internal_model_names():
    value = values()
    value["user_flow"]["user_flow_id"] = value["user_flow"].pop("id")
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(value)


def test_independently_approved_inventory_digest_is_mandatory():
    prerequisite = prerequisites()
    prerequisite["approved_inventory_document_sha256"] = "0" * 64
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(prerequisite=prerequisite)


@pytest.mark.parametrize(
    "field",
    [
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
    ],
)
def test_each_registration_document_must_match_its_accepted_digest(field):
    prerequisite = prerequisites()
    prerequisite[field] = "0" * 64
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(prerequisite=prerequisite)


def test_tampered_inventory_cannot_be_reblessed_by_only_changing_outer_digest():
    prerequisite = prerequisites()
    inventory = json.loads(prerequisite["inventory_document"])
    inventory["inventory"]["applications"][1]["application_id"] = (
        "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
    )
    prerequisite["inventory_document"] = json.dumps(inventory).encode()
    prerequisite["approved_inventory_document_sha256"] = (
        __import__("hashlib").sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load(prerequisite=prerequisite)


@pytest.mark.parametrize(
    "document",
    [b"", b"not-json", b"[]", b"null", b'"text"', b"\xff", b'{"a":NaN}'],
)
def test_document_rejects_empty_invalid_non_object_or_nonfinite_json(document):
    prerequisite = prerequisites()
    with pytest.raises(EntraExternalIdUserFlowReadinessError):
        load_entra_external_id_user_flow_readiness(
            document=document,
            **prerequisite,
        )


def test_document_rejects_duplicate_keys_at_any_depth():
    prerequisite = prerequisites()
    duplicate = (
        b'{"document_type":"'
        + ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE.encode()
        + b'","document_type":"duplicate"}'
    )
    with pytest.raises(
        EntraExternalIdUserFlowReadinessError,
        match="duplicate key",
    ):
        load_entra_external_id_user_flow_readiness(
            document=duplicate,
            **prerequisite,
        )
    compact = json.dumps(values(prerequisite), separators=(",", ":"))
    needle = f'"appId":"{CALLING_CLIENT_APPLICATION_ID}"'
    nested_duplicate = compact.replace(
        needle,
        (
            f'"appId":"{CALLING_CLIENT_APPLICATION_ID}",'
            f'"appId":"{CALLING_CLIENT_APPLICATION_ID}"'
        ),
        1,
    ).encode()
    with pytest.raises(
        EntraExternalIdUserFlowReadinessError,
        match="duplicate key",
    ):
        load_entra_external_id_user_flow_readiness(
            document=nested_duplicate,
            **prerequisite,
        )


def test_document_rejects_oversized_input_before_json_validation():
    prerequisite = prerequisites()
    with pytest.raises(EntraExternalIdUserFlowReadinessError, match="byte limit"):
        load_entra_external_id_user_flow_readiness(
            document=b"{" + b" " * MAX_ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_BYTES,
            **prerequisite,
        )


def test_document_rejects_excessive_nesting_and_container_count():
    prerequisite = prerequisites()
    nested = {"leaf": True}
    for _ in range(9):
        nested = {"nested": nested}
    for value in (nested, {"containers": [[] for _ in range(40)]}):
        with pytest.raises(EntraExternalIdUserFlowReadinessError):
            load_entra_external_id_user_flow_readiness(
                document=json.dumps(value).encode(),
                **prerequisite,
            )


@pytest.mark.parametrize("replacement", [None, "document", bytearray(b"{}"), {}])
def test_primary_document_requires_immutable_bytes(replacement):
    prerequisite = prerequisites()
    with pytest.raises(TypeError):
        load_entra_external_id_user_flow_readiness(
            document=replacement,
            **prerequisite,
        )


@pytest.mark.parametrize("replacement", [None, "inventory", bytearray(b"{}"), {}])
def test_inventory_document_requires_immutable_bytes(replacement):
    prerequisite = prerequisites()
    prerequisite["inventory_document"] = replacement
    with pytest.raises(TypeError):
        load(prerequisite=prerequisite)


@pytest.mark.parametrize("replacement", [None, b"0" * 64, "0" * 63, "G" * 64])
def test_approved_inventory_digest_requires_lowercase_sha256_text(replacement):
    prerequisite = prerequisites()
    prerequisite["approved_inventory_document_sha256"] = replacement
    with pytest.raises(TypeError):
        load(prerequisite=prerequisite)


def test_loader_performs_no_file_network_environment_database_or_provider_io(
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("I/O boundary crossed")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    receipt = load()
    assert receipt.provider_io_performed is False


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("schema_version", True),
        ("source", "wrong"),
        ("validation_scope", "wrong"),
        ("desired_user_flow_count", 0),
        ("desired_user_flow_count", True),
        ("desired_included_application_count", 2),
        ("configuration_bound", False),
        ("normalized_read_projection_validated", False),
        ("ready_to_post_payload", True),
        ("provider_state_checked", True),
        ("activation_ready", True),
        ("user_flow_id_sha256", "0" * 63),
        ("user_flow_id_sha256", "A" * 64),
        ("approved_inventory_document_sha256", "0" * 64),
    ],
)
def test_receipt_rejects_any_tampered_identity_count_or_boundary(field, replacement):
    receipt = _tampered_receipt(load(), **{field: replacement})
    with pytest.raises(ValueError):
        receipt.__post_init__()
    with pytest.raises(ValueError):
        render_entra_external_id_user_flow_readiness_receipt(receipt)


def _tampered_receipt(receipt, **changes):
    tampered = copy.copy(receipt)
    for name, value in changes.items():
        object.__setattr__(tampered, name, value)
    return tampered


def test_every_receipt_boolean_is_individually_integrity_enforced():
    receipt = load()
    boolean_fields = [
        field.name
        for field in fields(receipt)
        if isinstance(getattr(receipt, field.name), bool)
    ]
    assert len(boolean_fields) >= 70
    for name in boolean_fields:
        tampered = _tampered_receipt(
            receipt,
            **{name: not getattr(receipt, name)},
        )
        with pytest.raises(ValueError, match="receipt is invalid"):
            tampered.__post_init__()
        with pytest.raises(ValueError, match="receipt is invalid"):
            render_entra_external_id_user_flow_readiness_receipt(tampered)


@pytest.mark.parametrize("replacement", [None, {}, "receipt", object()])
def test_renderer_requires_exact_receipt_type(replacement):
    with pytest.raises(TypeError):
        render_entra_external_id_user_flow_readiness_receipt(replacement)


def test_distinct_flow_and_association_inputs_produce_distinct_evidence_hashes():
    original = load()
    other = values()
    other["user_flow"]["id"] = "88888888-9999-4aaa-8bbb-cccccccccccc"
    changed = load(other)
    assert original.user_flow_id_sha256 != changed.user_flow_id_sha256
    assert (
        original.user_flow_calling_client_association_sha256
        != changed.user_flow_calling_client_association_sha256
    )
    assert (
        original.calling_client_service_principal_app_id_mapping_sha256
        == changed.calling_client_service_principal_app_id_mapping_sha256
    )


def test_domain_separated_evidence_hashes_do_not_alias_each_other():
    receipt = load()
    digest_fields = [
        (field.name, getattr(receipt, field.name))
        for field in fields(receipt)
        if field.name.endswith("_sha256")
    ]
    duplicate_groups = {
        digest: {name for name, value in digest_fields if value == digest}
        for _, digest in digest_fields
        if sum(value == digest for _, value in digest_fields) > 1
    }
    assert set(map(frozenset, duplicate_groups.values())) == {
        frozenset(
            {
                "approved_inventory_document_sha256",
                "inventory_document_sha256",
            }
        )
    }
