"""Tests for the controlled Microsoft Graph identity-inventory proof gate."""

from __future__ import annotations

from dataclasses import fields, replace
import inspect
import json

import pytest

from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_application_service_principal_inventory_probe import (
    ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID,
    ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION,
    ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE,
    ENTRA_GRAPH_INVENTORY_PROBE_SCOPE,
    ENTRA_GRAPH_INVENTORY_REQUEST_COUNT,
    EntraGraphInventoryAuthorizationContract,
    EntraGraphInventoryProbeError,
    probe_live_entra_application_service_principal_inventory,
    render_entra_graph_inventory_probe_receipt,
    validate_entra_application_service_principal_inventory_probe,
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
from app.security.authentication_entra_graph_http_loader import (
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES,
    EntraGraphInventoryResponse,
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


def inventory_values(preview, prerequisites):
    return {
        "document_type": (
            ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE
        ),
        "schema_version": 1,
        "source": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": prerequisites[
            "accepted_api_registration_document_sha256"
        ],
        "approved_calling_client_registration_document_sha256": prerequisites[
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
        "inventory_document": inventory_document,
        "approved_inventory_document_sha256": (
            inventory_receipt.inventory_document_sha256
        ),
        "authentication_preview": preview,
        **registration,
    }


def authorization():
    return EntraGraphInventoryAuthorizationContract(
        permission_type="delegated_work_school",
        permission_name=ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION,
        permission_id=ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID,
        consent_requirement="admin",
        credential_origin="out_of_band_operator",
    )


def graph_body(request, **changes):
    if request.resource == "application":
        value = {
            "id": (
                API_APPLICATION_OBJECT_ID
                if request.role == "api"
                else CALLING_CLIENT_OBJECT_ID
            ),
            "appId": (
                API_APPLICATION_ID
                if request.role == "api"
                else CALLING_CLIENT_APPLICATION_ID
            ),
            "deletedDateTime": None,
        }
    else:
        value = {
            "id": (
                API_SERVICE_PRINCIPAL_OBJECT_ID
                if request.role == "api"
                else CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID
            ),
            "appId": (
                API_APPLICATION_ID
                if request.role == "api"
                else CALLING_CLIENT_APPLICATION_ID
            ),
            "appOwnerOrganizationId": TENANT_ID,
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "disabledByMicrosoftStatus": (
                None if request.role == "api" else "NotDisabled"
            ),
            "deletedDateTime": None,
        }
    value.update(changes)
    return value


class SyntheticTransport:
    def __init__(self, mutate=None, response_changes=None):
        self.calls = []
        self.mutate = mutate
        self.response_changes = response_changes or {}

    def __call__(self, request):
        self.calls.append(request)
        value = graph_body(request)
        if self.mutate is not None:
            value = self.mutate(request, value)
        changes = dict(self.response_changes)
        body = changes.pop("body", json.dumps(value).encode())
        return EntraGraphInventoryResponse(
            status_code=changes.pop("status_code", 200),
            final_url=changes.pop("final_url", request.url),
            content_type=changes.pop("content_type", "application/json"),
            body=body,
            **changes,
        )


def validate(transport=None, supplied=None):
    return validate_entra_application_service_principal_inventory_probe(
        **(supplied or prerequisites()),
        authorization=authorization(),
        transport=transport or SyntheticTransport(),
    )


def test_valid_synthetic_probe_binds_exact_plan_without_provider_claims():
    transport = SyntheticTransport()
    receipt = validate(transport)
    assert receipt.receipt_type == ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE
    assert receipt.validation_scope == ENTRA_GRAPH_INVENTORY_PROBE_SCOPE
    assert receipt.request_count == ENTRA_GRAPH_INVENTORY_REQUEST_COUNT == 4
    assert receipt.response_count == 4
    assert receipt.approved_inventory_digest_bound is True
    assert receipt.application_identity_match_validated is True
    assert receipt.service_principal_identity_match_validated is True
    assert receipt.application_service_principal_relationships_validated is True
    assert receipt.tenant_ownership_validated is True
    assert receipt.least_privilege_delegated_permission_contract_validated is True
    assert receipt.application_permission_contract_rejected is True
    assert receipt.synthetic_transport_used is True
    assert receipt.live_https_transport_attested is False
    assert receipt.provider_io_performed is False
    assert receipt.provider_state_checked is False
    assert receipt.live_inventory_checked is False
    assert receipt.source_authenticity_checked is False
    assert receipt.actual_token_type_checked is False
    assert receipt.app_only_token_checked is False
    assert receipt.work_school_account_checked is False
    assert len(transport.calls) == 4


def test_request_plan_is_exact_ordered_read_only_object_id_gets():
    transport = SyntheticTransport()
    validate(transport)
    assert [(item.sequence, item.role, item.resource) for item in transport.calls] == [
        (1, "api", "application"),
        (2, "calling_client", "application"),
        (3, "api", "service_principal"),
        (4, "calling_client", "service_principal"),
    ]
    assert [item.method for item in transport.calls] == ["GET"] * 4
    assert [item.body for item in transport.calls] == [None] * 4
    assert all(item.url.startswith(f"{ENTRA_GRAPH_BASE_URL}/") for item in transport.calls)
    assert all("?$select=" in item.url for item in transport.calls)
    assert all("deletedDateTime" in item.url for item in transport.calls)
    assert all("$filter" not in item.url and "$expand" not in item.url for item in transport.calls)
    assert all(item.follow_redirects is False for item in transport.calls)
    assert all(item.maximum_retries == 0 for item in transport.calls)
    assert all(item.proxy_allowed is False for item in transport.calls)


def test_receipt_is_canonical_private_and_omits_tokens_and_raw_identifiers():
    rendered = render_entra_graph_inventory_probe_receipt(validate())
    parsed = json.loads(rendered)
    receipt = validate()
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
        "Bearer ",
        "opaque.delegated.graph.token",
    ):
        assert raw not in rendered
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            value = getattr(receipt, field.name)
            assert len(value) == 64
            assert value == value.lower()
            int(value, 16)


def test_approved_inventory_digest_is_an_independent_fail_before_io_gate():
    supplied = prerequisites()
    supplied["approved_inventory_document_sha256"] = "0" * 64
    transport = SyntheticTransport()
    with pytest.raises(EntraGraphInventoryProbeError, match="approved digest"):
        validate(transport, supplied)
    assert transport.calls == []


def test_newly_valid_but_unapproved_projection_cannot_choose_probe_targets():
    supplied = prerequisites()
    document = json.loads(supplied["inventory_document"])
    document["inventory"]["service_principals"][0][
        "service_principal_object_id"
    ] = "55555555-6666-4777-8888-999999999999"
    supplied["inventory_document"] = json.dumps(document).encode()
    transport = SyntheticTransport()
    with pytest.raises(EntraGraphInventoryProbeError, match="approved digest"):
        validate(transport, supplied)
    assert transport.calls == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("permission_type", "application"),
        ("permission_type", "delegated_personal"),
        ("permission_name", "Application.ReadWrite.All"),
        ("permission_name", "Directory.Read.All"),
        ("permission_id", "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"),
        ("consent_requirement", "user"),
        ("credential_origin", "engineer4me_api"),
    ],
)
def test_authorization_contract_rejects_app_only_write_or_wrong_boundaries(
    field,
    replacement,
):
    with pytest.raises(ValueError):
        replace(authorization(), **{field: replacement})


@pytest.mark.parametrize(
    ("resource", "role", "field", "replacement"),
    [
        ("application", "api", "id", CALLING_CLIENT_OBJECT_ID),
        ("application", "api", "appId", CALLING_CLIENT_APPLICATION_ID),
        ("application", "calling_client", "id", API_APPLICATION_OBJECT_ID),
        ("application", "calling_client", "appId", API_APPLICATION_ID),
        (
            "service_principal",
            "api",
            "id",
            CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        ),
        (
            "service_principal",
            "api",
            "appId",
            CALLING_CLIENT_APPLICATION_ID,
        ),
        (
            "service_principal",
            "api",
            "appOwnerOrganizationId",
            OWNER_ID,
        ),
        (
            "service_principal",
            "calling_client",
            "id",
            API_SERVICE_PRINCIPAL_OBJECT_ID,
        ),
        (
            "service_principal",
            "calling_client",
            "appId",
            API_APPLICATION_ID,
        ),
    ],
)
def test_probe_rejects_every_identity_and_relationship_mismatch(
    resource,
    role,
    field,
    replacement,
):
    def mutate(request, value):
        if request.resource == resource and request.role == role:
            value[field] = replacement
        return value

    with pytest.raises(EntraGraphInventoryProbeError, match="does not match"):
        validate(SyntheticTransport(mutate=mutate))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("servicePrincipalType", "ManagedIdentity"),
        ("servicePrincipalType", "AgentIdentityBlueprintPrincipal"),
        ("accountEnabled", False),
        ("accountEnabled", 1),
        ("disabledByMicrosoftStatus", "DisabledByMicrosoft"),
        ("disabledByMicrosoftStatus", "notdisabled"),
        ("deletedDateTime", "2026-08-13T00:00:00Z"),
    ],
)
def test_probe_rejects_wrong_type_disabled_or_deleted_principals(field, replacement):
    def mutate(request, value):
        if request.resource == "service_principal" and request.role == "api":
            value[field] = replacement
        return value

    with pytest.raises(EntraGraphInventoryProbeError):
        validate(SyntheticTransport(mutate=mutate))


@pytest.mark.parametrize(
    ("resource", "odata_type"),
    [
        ("application", "#microsoft.graph.agentIdentityBlueprint"),
        (
            "service_principal",
            "#microsoft.graph.agentIdentityBlueprintPrincipal",
        ),
    ],
)
def test_probe_rejects_derived_agent_identity_odata_types(resource, odata_type):
    def mutate(request, value):
        if request.resource == resource and request.role == "api":
            value["@odata.type"] = odata_type
        return value

    with pytest.raises(EntraGraphInventoryProbeError, match="schema"):
        validate(SyntheticTransport(mutate=mutate))


@pytest.mark.parametrize("field", ["value", "@odata.nextLink", "@odata.count"])
def test_probe_rejects_collection_envelopes_paging_and_count(field):
    def mutate(request, value):
        if request.sequence == 1:
            value[field] = [] if field == "value" else 1
        return value

    with pytest.raises(EntraGraphInventoryProbeError, match="collection or paging"):
        validate(SyntheticTransport(mutate=mutate))


def test_probe_rejects_unselected_unknown_fields_instead_of_hashing_ambiguously():
    def mutate(request, value):
        if request.sequence == 1:
            value["displayName"] = "unexpected"
        return value

    with pytest.raises(EntraGraphInventoryProbeError, match="selected contract"):
        validate(SyntheticTransport(mutate=mutate))


@pytest.mark.parametrize(
    ("resource", "field"),
    [
        ("application", "id"),
        ("application", "appId"),
        ("application", "deletedDateTime"),
        ("service_principal", "appOwnerOrganizationId"),
        ("service_principal", "servicePrincipalType"),
        ("service_principal", "accountEnabled"),
        ("service_principal", "disabledByMicrosoftStatus"),
    ],
)
def test_probe_requires_every_explicitly_selected_field(resource, field):
    def mutate(request, value):
        if request.resource == resource and request.role == "api":
            value.pop(field)
        return value

    with pytest.raises(EntraGraphInventoryProbeError):
        validate(SyntheticTransport(mutate=mutate))


def test_probe_accepts_exact_base_odata_types_and_entity_contexts():
    def mutate(request, value):
        collection = (
            "applications"
            if request.resource == "application"
            else "servicePrincipals"
        )
        value["@odata.type"] = (
            "#microsoft.graph.application"
            if request.resource == "application"
            else "#microsoft.graph.servicePrincipal"
        )
        value["@odata.context"] = (
            f"{ENTRA_GRAPH_BASE_URL}/$metadata#{collection}(id)/$entity"
        )
        return value

    receipt = validate(SyntheticTransport(mutate=mutate))
    assert receipt.response_schema_validated is True


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/JSON; Charset=UTF-8",
        "application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8",
        "application/json;odata.metadata=full;odata.streaming=false;ieee754compatible=true",
        "application/json;odata.metadata=none",
    ],
)
def test_probe_accepts_bounded_official_json_and_odata_content_types(content_type):
    receipt = validate(SyntheticTransport(response_changes={"content_type": content_type}))
    assert receipt.response_schema_validated is True


@pytest.mark.parametrize(
    "content_type",
    [
        "text/json",
        "application/json;profile=unexpected",
        "application/json;charset=latin-1",
        "application/json;charset=utf-8;charset=utf-8",
        "application/json;odata.streaming=yes",
        "application/json;odata.metadata=other",
        "application/json;bad",
        "application/json;;charset=utf-8",
        "application/json\r\nX-Test: yes",
    ],
)
def test_probe_rejects_unknown_duplicate_or_malformed_content_type_parameters(
    content_type,
):
    with pytest.raises(EntraGraphInventoryProbeError, match="transport contract"):
        validate(SyntheticTransport(response_changes={"content_type": content_type}))


@pytest.mark.parametrize(
    "response_changes",
    [
        {"status_code": 201},
        {"status_code": True},
        {"final_url": f"{ENTRA_GRAPH_BASE_URL}/v1.0/changed"},
        {"body": b""},
        {"body": b"not-json"},
        {"body": b"\xff"},
        {"body": b"[]"},
        {"body": b'{"id":"a","id":"b"}'},
        {"body": b'{"id":NaN}'},
        {"body": b"x" * (MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES + 1)},
    ],
)
def test_probe_rejects_untrusted_status_source_and_body_shapes(response_changes):
    with pytest.raises(EntraGraphInventoryProbeError):
        validate(SyntheticTransport(response_changes=response_changes))


@pytest.mark.parametrize(
    "replacement",
    [
        "00000000-0000-0000-0000-000000000000",
        API_APPLICATION_ID.upper(),
        API_APPLICATION_ID.replace("-", ""),
        f"{{{API_APPLICATION_ID}}}",
        1,
        True,
        None,
    ],
)
def test_probe_rejects_noncanonical_graph_uuid_values(replacement):
    def mutate(request, value):
        if request.sequence == 1:
            value["appId"] = replacement
        return value

    with pytest.raises(EntraGraphInventoryProbeError, match="identity"):
        validate(SyntheticTransport(mutate=mutate))


def test_synthetic_entrypoint_rejects_even_sealed_live_responses(monkeypatch):
    from app.security import authentication_entra_graph_http_loader as graph_http

    original = EntraGraphInventoryResponse

    class AttestedTransport:
        def __call__(self, request):
            return graph_http._attested_live_response(
                status_code=200,
                final_url=request.url,
                content_type="application/json",
                body=json.dumps(graph_body(request)).encode(),
            )

    assert original is EntraGraphInventoryResponse
    with pytest.raises(EntraGraphInventoryProbeError, match="not accepted"):
        validate(AttestedTransport())


def test_transport_failure_is_sanitized_and_returns_no_partial_receipt():
    class FailsThird:
        def __init__(self):
            self.calls = []

        def __call__(self, request):
            self.calls.append(request)
            if request.sequence == 3:
                raise RuntimeError("secret provider internals")
            return EntraGraphInventoryResponse(
                status_code=200,
                final_url=request.url,
                content_type="application/json",
                body=json.dumps(graph_body(request)).encode(),
            )

    transport = FailsThird()
    with pytest.raises(EntraGraphInventoryProbeError, match="transport failed") as error:
        validate(transport)
    assert "secret provider internals" not in str(error.value)
    assert len(transport.calls) == 3


def test_live_entrypoint_has_no_transport_or_http_opener_injection_parameter():
    parameters = inspect.signature(
        probe_live_entra_application_service_principal_inventory
    ).parameters
    assert "delegated_access_token" in parameters
    assert "transport" not in parameters
    assert "open_url" not in parameters


def test_render_revalidates_receipt_and_rejects_tampering():
    receipt = validate()
    with pytest.raises(ValueError):
        render_entra_graph_inventory_probe_receipt(
            replace(receipt, provider_state_checked=True)
        )
    with pytest.raises(ValueError):
        render_entra_graph_inventory_probe_receipt(
            replace(receipt, approved_inventory_document_sha256="0" * 64)
        )
    with pytest.raises(TypeError):
        render_entra_graph_inventory_probe_receipt(object())


@pytest.mark.parametrize(
    "field",
    [
        "authorization_token_claims_checked",
        "actual_token_type_checked",
        "app_only_token_checked",
        "work_school_account_checked",
        "provider_permission_grant_checked",
        "admin_consent_checked",
        "token_tenant_checked",
        "token_graph_audience_checked",
        "atomic_inventory_snapshot_checked",
        "concurrent_provider_mutation_checked",
        "activation_ready",
    ],
)
def test_receipt_cannot_promote_declared_or_deferred_checks_to_evidence(field):
    with pytest.raises(ValueError):
        replace(validate(), **{field: True})
