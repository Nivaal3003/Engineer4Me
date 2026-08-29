"""Tests for the controlled Step 212 Microsoft Graph user-flow proof."""

from __future__ import annotations

import builtins
import copy
import json
import socket
from dataclasses import fields
from typing import Self

import app.security.authentication_entra_external_id_user_flow_graph_http_loader as loader_module
import app.security.authentication_entra_external_id_user_flow_probe as module
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
from app.security.authentication_entra_external_id_user_flow_graph_http_loader import (
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES,
    EntraExternalIdUserFlowGraphResponse,
)
from app.security.authentication_entra_external_id_user_flow_probe import (
    ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE,
    ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID,
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE,
    ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID,
    ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TOTAL_RESPONSE_BYTES,
    EntraExternalIdUserFlowGraphAuthorizationContract,
    EntraExternalIdUserFlowGraphProbeError,
    probe_live_entra_external_id_user_flow_graph,
    render_entra_external_id_user_flow_graph_probe_receipt,
    validate_entra_external_id_user_flow_graph_probe,
)
from app.security.authentication_entra_external_id_user_flow_readiness import (
    ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
    ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE,
    load_entra_external_id_user_flow_readiness,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)

TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
API_APPLICATION_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
API_SCOPE_ID = "dddddddd-eeee-4fff-8aaa-bbbbbbbb0500"
CALLING_CLIENT_APPLICATION_ID = "11111111-2222-4333-8abc-555555555555"
CALLING_CLIENT_OBJECT_ID = "22222222-3333-4444-8def-666666666666"
API_SERVICE_PRINCIPAL_OBJECT_ID = "33333333-4444-4555-8abc-777777777777"
CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID = "44444444-5555-4666-8def-888888888888"
USER_FLOW_ID = "55555555-6666-4777-8abc-999999999999"
OTHER_USER_FLOW_ID = "66666666-7777-4888-9abc-aaaaaaaaaaaa"
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
REDIRECT_URI = "https://app.engineer4me.invalid/auth/callback"
ISSUER = f"https://synthetic.ciamlogin.com/{TENANT_ID}/v2.0"
TOKEN = "step212-sentinel-opaque-token"
FLOW_CONTEXT = (
    "https://graph.microsoft.com/v1.0/$metadata#identity/"
    "authenticationEventsFlows(id,conditions)/$entity"
)
NAV_CONTEXT = (
    "https://graph.microsoft.com/v1.0/$metadata#identity/"
    f"authenticationEventsFlows('{USER_FLOW_ID}')/microsoft.graph."
    "externalUsersSelfServiceSignUpEventsFlow/conditions/applications/"
    "includeApplications"
)
COLLECTION_CONTEXT = (
    "https://graph.microsoft.com/v1.0/$metadata#identity/"
    f"authenticationEventsFlows('{USER_FLOW_ID}')/conditions/applications/"
    "includeApplications(appId)"
)
_UNSET = object()


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
            "desired_runtime_api_scope": (f"api://{API_APPLICATION_ID}/access_as_user"),
            "home_page_url": None,
            "logout_url": None,
        },
    }


def inventory_values(preview, registration):
    return {
        "document_type": (ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE),
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


def user_flow_values(prerequisite):
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
                    "includeApplications": [{"appId": CALLING_CLIENT_APPLICATION_ID}],
                }
            },
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
    inventory_receipt = load_entra_application_service_principal_inventory_readiness(
        document=inventory_document,
        authentication_preview=preview,
        **registration,
    )
    prerequisite = {
        "authentication_preview": preview,
        **registration,
        "inventory_document": inventory_document,
        "approved_inventory_document_sha256": (
            inventory_receipt.inventory_document_sha256
        ),
    }
    user_flow_document = json.dumps(
        user_flow_values(prerequisite), separators=(",", ":")
    ).encode()
    user_flow_receipt = load_entra_external_id_user_flow_readiness(
        document=user_flow_document,
        **prerequisite,
    )
    return {
        **prerequisite,
        "user_flow_document": user_flow_document,
        "approved_user_flow_document_sha256": (
            user_flow_receipt.desired_state_document_sha256
        ),
    }


def authorization():
    return EntraExternalIdUserFlowGraphAuthorizationContract(
        permission_type="delegated_work_school",
        permission_name=ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION,
        permission_id=ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID,
        consent_requirement="admin",
        credential_origin="out_of_band_operator",
        least_privileged_role_name=ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE,
        least_privileged_role_template_id=(
            ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID
        ),
    )


def flow_body(
    *,
    envelope: bool = False,
    context: bool = False,
    nested_types: bool = False,
    navigation: object = "absent",
):
    applications = {"includeAllApplications": False}
    if nested_types:
        applications["@odata.type"] = (
            "#microsoft.graph.authenticationConditionsApplications"
        )
    if navigation != "absent":
        applications["includeApplications@odata.context"] = NAV_CONTEXT
        applications["includeApplications"] = navigation
    conditions = {"applications": applications}
    if nested_types:
        conditions["@odata.type"] = "#microsoft.graph.authenticationConditions"
    entity = {
        "@odata.type": ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
        "id": USER_FLOW_ID,
        "conditions": conditions,
    }
    if context:
        entity["@odata.context"] = FLOW_CONTEXT
    return {"value": entity} if envelope else entity


def collection_body(*, context: bool = False, entry_type: bool = False):
    entry = {"appId": CALLING_CLIENT_APPLICATION_ID}
    if entry_type:
        entry["@odata.type"] = "#microsoft.graph.authenticationConditionApplication"
    result = {"value": [entry]}
    if context:
        result["@odata.context"] = COLLECTION_CONTEXT
    return result


def synthetic_responses(
    plan,
    *,
    flow: object | bytes | None = None,
    collection: object | bytes | None = None,
    flow_response_changes: dict[str, object] | None = None,
    collection_response_changes: dict[str, object] | None = None,
):
    def encoded(value):
        return value if isinstance(value, bytes) else json.dumps(value).encode()

    flow_bytes = encoded(flow_body() if flow is None else flow)
    collection_bytes = encoded(collection_body() if collection is None else collection)
    flow_values = {
        "status_code": 200,
        "final_url": plan[0].url,
        "content_type": "application/json",
        "body": flow_bytes,
    }
    collection_values = {
        "status_code": 200,
        "final_url": plan[1].url,
        "content_type": "application/json",
        "body": collection_bytes,
    }
    flow_values.update(flow_response_changes or {})
    collection_values.update(collection_response_changes or {})
    return (
        EntraExternalIdUserFlowGraphResponse(**flow_values),
        EntraExternalIdUserFlowGraphResponse(**collection_values),
    )


class SyntheticTransport:
    def __init__(
        self,
        *,
        flow: object | bytes | None = None,
        collection: object | bytes | None = None,
        response_pair: object = _UNSET,
    ) -> None:
        self.flow = flow
        self.collection = collection
        self.response_pair = response_pair
        self.plans = []

    def __call__(self, plan):
        self.plans.append(plan)
        if self.response_pair is not _UNSET:
            return self.response_pair
        return synthetic_responses(
            plan,
            flow=self.flow,
            collection=self.collection,
        )


def validate(
    *,
    prerequisite=None,
    transport=None,
):
    prerequisite = prerequisite or prerequisites()
    transport = transport or SyntheticTransport()
    return validate_entra_external_id_user_flow_graph_probe(
        **prerequisite,
        authorization=authorization(),
        transport=transport,
    )


def assert_no_token_in_production_exception_graph(
    error: BaseException,
    token: str,
) -> None:
    production_modules = {module.__name__, loader_module.__name__}
    pending = [error]
    seen_errors: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen_errors:
            continue
        seen_errors.add(id(current))
        assert token not in str(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_globals.get("__name__") in production_modules:
                values: list[object] = list(frame.f_locals.values())
                inspected: set[int] = set()
                while values:
                    value = values.pop()
                    if id(value) in inspected:
                        continue
                    inspected.add(id(value))
                    if isinstance(value, str):
                        assert token not in value
                    elif isinstance(value, bytes):
                        assert token.encode() not in value
                    elif isinstance(value, dict):
                        values.extend(value.keys())
                        values.extend(value.values())
                    elif isinstance(value, (list, tuple, set, frozenset)):
                        values.extend(value)
                    elif hasattr(value, "header_items"):
                        values.extend(value.header_items())
                    if hasattr(value, "_delegated_access_token"):
                        values.append(value._delegated_access_token)
            traceback = traceback.tb_next


def test_synthetic_probe_validates_exact_two_read_projection_without_live_claims():
    transport = SyntheticTransport()
    receipt = validate(transport=transport)
    assert receipt.receipt_type == ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.validation_scope == ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE
    assert receipt.request_count == ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT
    assert receipt.response_count == ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT
    assert receipt.user_flow_response_shape == "direct"
    assert receipt.total_response_bytes == (
        receipt.user_flow_response_bytes + receipt.include_applications_response_bytes
    )
    assert len(transport.plans) == 1
    plan = transport.plans[0]
    assert type(plan) is tuple and len(plan) == 2
    assert [(item.sequence, item.resource, item.method) for item in plan] == [
        (1, "user_flow", "GET"),
        (2, "include_applications", "GET"),
    ]
    assert plan[0].url.endswith(f"/{USER_FLOW_ID}?$select=id,conditions")
    assert plan[1].url.endswith(
        f"/{USER_FLOW_ID}/conditions/applications/includeApplications?$select=appId"
    )

    live_fields = {
        "live_https_transport_attested",
        "provider_io_performed",
        "provider_state_checked",
        "source_authenticity_checked",
        "user_flow_id_returned_by_graph_checked",
        "live_user_flow_checked",
        "live_user_flow_type_checked",
        "live_user_flow_application_association_checked",
        "live_include_all_applications_checked",
        "live_included_application_count_checked",
    }
    assert receipt.synthetic_transport_used is True
    for name in live_fields:
        assert getattr(receipt, name) is False


def test_all_static_validations_are_true_and_all_deferred_boundaries_false():
    receipt = validate()
    expected_true = {
        "synthetic_transport_used",
        "approved_user_flow_digest_bound",
        "offline_user_flow_projection_revalidated",
        "configuration_bound",
        "approved_inventory_digest_bound",
        "exact_two_get_request_plan_validated",
        "sequential_request_order_validated",
        "same_user_flow_id_in_both_requests_validated",
        "graph_global_v1_endpoint_validated",
        "read_only_methods_validated",
        "exact_select_projections_validated",
        "no_request_body_validated",
        "no_proxy_redirect_retry_compression_validated",
        "response_bounds_validated",
        "response_json_integrity_validated",
        "response_schema_validated",
        "direct_or_documented_envelope_validated",
        "canonical_user_flow_id_validated",
        "external_users_self_service_sign_up_flow_type_validated",
        "include_all_applications_false_validated",
        "materialized_navigation_constrained",
        "exact_include_applications_collection_validated",
        "collection_paging_and_count_rejected",
        "exact_single_included_application_validated",
        "calling_client_application_id_bound",
        "calling_client_service_principal_projection_revalidated",
        "calling_client_service_principal_app_id_mapping_validated",
        "least_privilege_delegated_permission_contract_validated",
        "least_privilege_role_intent_validated",
        "out_of_band_operator_contract_validated",
        "application_permission_contract_rejected",
    }
    for field in fields(receipt):
        value = getattr(receipt, field.name)
        if isinstance(value, bool):
            assert value is (field.name in expected_true)


@pytest.mark.parametrize("envelope", [False, True])
def test_direct_and_exact_documented_anomalous_envelope_are_supported(envelope):
    receipt = validate(transport=SyntheticTransport(flow=flow_body(envelope=envelope)))
    expected = "documented_value_envelope" if envelope else "direct"
    assert receipt.user_flow_response_shape == expected


def test_exact_optional_odata_metadata_and_materialized_navigation_are_supported():
    included = [
        {
            "appId": CALLING_CLIENT_APPLICATION_ID,
            "@odata.type": "#microsoft.graph.authenticationConditionApplication",
        }
    ]
    receipt = validate(
        transport=SyntheticTransport(
            flow=flow_body(
                context=True,
                nested_types=True,
                navigation=included,
            ),
            collection=collection_body(context=True, entry_type=True),
        )
    )
    assert receipt.materialized_navigation_constrained is True
    assert receipt.response_schema_validated is True


def test_full_documented_graph_json_media_type_is_supported_for_both_responses():
    media_type = (
        "application/json;odata.metadata=minimal;odata.streaming=true;"
        "IEEE754Compatible=false;charset=utf-8"
    )

    def transport(plan):
        responses = synthetic_responses(plan)
        for response in responses:
            object.__setattr__(response, "content_type", media_type)
        return responses

    receipt = validate(transport=transport)
    assert receipt.response_json_integrity_validated is True
    assert receipt.response_schema_validated is True


@pytest.mark.parametrize("navigation", ["absent", []])
def test_embedded_navigation_may_be_absent_or_empty(navigation):
    receipt = validate(
        transport=SyntheticTransport(flow=flow_body(navigation=navigation))
    )
    assert receipt.exact_single_included_application_validated is True


def test_rendered_receipt_is_canonical_private_and_omits_raw_evidence():
    receipt = validate()
    rendered = render_entra_external_id_user_flow_graph_probe_receipt(receipt)
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
        TOKEN,
        "access_as_user",
        "Engineer4Me API",
        "Engineer4Me Web",
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


def test_synthetic_probe_performs_no_file_socket_environment_or_provider_io(
    monkeypatch,
):
    def denied(*args, **kwargs):
        del args, kwargs
        raise AssertionError("forbidden external I/O")

    monkeypatch.setattr(builtins, "open", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    transport = SyntheticTransport()
    receipt = validate(transport=transport)
    assert len(transport.plans) == 1
    assert receipt.provider_io_performed is False


@pytest.mark.parametrize(
    "case",
    [
        "root_array",
        "empty_envelope",
        "envelope_extra",
        "value_array",
        "missing_type",
        "extra_field",
        "wrong_type",
        "wrong_id",
        "zero_id",
        "uppercase_id",
        "braced_id",
        "hyphenless_id",
        "wrong_context",
        "null_conditions",
        "extra_condition",
        "wrong_conditions_type",
        "extra_applications_field",
        "wrong_applications_type",
        "include_all_true",
        "include_all_numeric_zero",
        "include_all_numeric_one",
        "include_all_float_zero",
        "include_all_null",
        "include_all_array",
        "include_all_object",
        "include_all_string_false",
        "missing_include_all",
        "wrong_nav_context",
        "nav_not_list",
        "nav_two_items",
        "nav_wrong_app",
        "nav_extra_field",
        "nav_wrong_entry_type",
        "nav_next_link",
        "root_next_link",
        "root_count",
    ],
)
def test_flow_response_rejects_any_schema_identity_type_or_scope_widening(case):
    value = flow_body()
    if case == "root_array":
        value = [value]
    elif case == "empty_envelope":
        value = {"value": {}}
    elif case == "envelope_extra":
        value = {"value": value, "@odata.context": FLOW_CONTEXT}
    elif case == "value_array":
        value = {"value": [value]}
    else:
        entity = value
        applications = entity["conditions"]["applications"]
        if case == "missing_type":
            del entity["@odata.type"]
        elif case == "extra_field":
            entity["displayName"] = "out-of-scope"
        elif case == "wrong_type":
            entity["@odata.type"] = "#microsoft.graph.authenticationEventsFlow"
        elif case == "wrong_id":
            entity["id"] = OTHER_USER_FLOW_ID
        elif case == "zero_id":
            entity["id"] = "00000000-0000-0000-0000-000000000000"
        elif case == "uppercase_id":
            entity["id"] = USER_FLOW_ID.upper()
        elif case == "braced_id":
            entity["id"] = "{" + USER_FLOW_ID + "}"
        elif case == "hyphenless_id":
            entity["id"] = USER_FLOW_ID.replace("-", "")
        elif case == "wrong_context":
            entity["@odata.context"] = FLOW_CONTEXT.replace("(id,conditions)", "")
        elif case == "null_conditions":
            entity["conditions"] = None
        elif case == "extra_condition":
            entity["conditions"]["users"] = {}
        elif case == "wrong_conditions_type":
            entity["conditions"]["@odata.type"] = (
                "#microsoft.graph.authenticationConditionsExtra"
            )
        elif case == "extra_applications_field":
            applications["excludeApplications"] = []
        elif case == "wrong_applications_type":
            applications["@odata.type"] = (
                "#microsoft.graph.authenticationConditionsApplicationsExtra"
            )
        elif case == "include_all_true":
            applications["includeAllApplications"] = True
        elif case == "include_all_numeric_zero":
            applications["includeAllApplications"] = 0
        elif case == "include_all_numeric_one":
            applications["includeAllApplications"] = 1
        elif case == "include_all_float_zero":
            applications["includeAllApplications"] = 0.0
        elif case == "include_all_null":
            applications["includeAllApplications"] = None
        elif case == "include_all_array":
            applications["includeAllApplications"] = []
        elif case == "include_all_object":
            applications["includeAllApplications"] = {}
        elif case == "include_all_string_false":
            applications["includeAllApplications"] = "false"
        elif case == "missing_include_all":
            del applications["includeAllApplications"]
        elif case == "wrong_nav_context":
            applications["includeApplications@odata.context"] = NAV_CONTEXT + "/x"
        elif case == "nav_not_list":
            applications["includeApplications"] = {}
        elif case == "nav_two_items":
            applications["includeApplications"] = [
                {"appId": CALLING_CLIENT_APPLICATION_ID},
                {"appId": CALLING_CLIENT_APPLICATION_ID},
            ]
        elif case == "nav_wrong_app":
            applications["includeApplications"] = [{"appId": API_APPLICATION_ID}]
        elif case == "nav_extra_field":
            applications["includeApplications"] = [
                {
                    "appId": CALLING_CLIENT_APPLICATION_ID,
                    "id": CALLING_CLIENT_OBJECT_ID,
                }
            ]
        elif case == "nav_wrong_entry_type":
            applications["includeApplications"] = [
                {
                    "appId": CALLING_CLIENT_APPLICATION_ID,
                    "@odata.type": "#microsoft.graph.application",
                }
            ]
        elif case == "nav_next_link":
            applications["includeApplications@odata.nextLink"] = "https://next"
        elif case == "root_next_link":
            entity["@odata.nextLink"] = "https://next"
        elif case == "root_count":
            entity["@odata.count"] = 1
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        validate(transport=SyntheticTransport(flow=value))


@pytest.mark.parametrize(
    "case",
    [
        "root_array",
        "missing_value",
        "extra_field",
        "next_link",
        "count",
        "wrong_context",
        "value_object",
        "empty",
        "two",
        "entry_not_object",
        "missing_app_id",
        "wrong_app_id",
        "zero_app_id",
        "uppercase_app_id",
        "braced_app_id",
        "hyphenless_app_id",
        "app_object_id_alias",
        "service_principal_alias",
        "extra_entry_field",
        "wrong_entry_type",
    ],
)
def test_include_applications_response_rejects_any_collection_or_alias_widening(
    case,
):
    value = collection_body(context=True, entry_type=True)
    entry = value["value"][0]
    if case == "root_array":
        value = [value]
    elif case == "missing_value":
        value = {"@odata.context": COLLECTION_CONTEXT}
    elif case == "extra_field":
        value["unexpected"] = True
    elif case == "next_link":
        value["@odata.nextLink"] = "https://next"
    elif case == "count":
        value["@odata.count"] = 1
    elif case == "wrong_context":
        value["@odata.context"] = COLLECTION_CONTEXT.removesuffix("(appId)")
    elif case == "value_object":
        value["value"] = entry
    elif case == "empty":
        value["value"] = []
    elif case == "two":
        value["value"] = [entry, copy.deepcopy(entry)]
    elif case == "entry_not_object":
        value["value"] = [CALLING_CLIENT_APPLICATION_ID]
    elif case == "missing_app_id":
        del entry["appId"]
    elif case == "wrong_app_id":
        entry["appId"] = API_APPLICATION_ID
    elif case == "zero_app_id":
        entry["appId"] = "00000000-0000-0000-0000-000000000000"
    elif case == "uppercase_app_id":
        entry["appId"] = CALLING_CLIENT_APPLICATION_ID.upper()
    elif case == "braced_app_id":
        entry["appId"] = "{" + CALLING_CLIENT_APPLICATION_ID + "}"
    elif case == "hyphenless_app_id":
        entry["appId"] = CALLING_CLIENT_APPLICATION_ID.replace("-", "")
    elif case == "app_object_id_alias":
        entry["applicationObjectId"] = CALLING_CLIENT_OBJECT_ID
    elif case == "service_principal_alias":
        entry["servicePrincipalId"] = CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID
    elif case == "extra_entry_field":
        entry["displayName"] = "Engineer4Me Web"
    elif case == "wrong_entry_type":
        entry["@odata.type"] = "#microsoft.graph.application"
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        validate(transport=SyntheticTransport(collection=value))


@pytest.mark.parametrize(
    ("resource", "body"),
    [
        ("flow", b""),
        ("flow", b"not-json"),
        ("flow", b"\xff"),
        ("flow", b'{"id":"one","id":"two"}'),
        (
            "flow",
            (
                b'{"@odata.type":"x","id":"x","conditions":'
                b'{"applications":{"includeAllApplications":false,'
                b'"includeAllApplications":false}}}'
            ),
        ),
        ("flow", b'{"value":NaN}'),
        ("flow", b'{"value":Infinity}'),
        ("collection", b""),
        ("collection", b"[]"),
        ("collection", b'{"value":['),
        ("collection", b'{"value":[],"value":[]}'),
        ("collection", b'{"value":-Infinity}'),
    ],
)
def test_response_json_rejects_empty_malformed_duplicate_or_nonfinite_body(
    resource,
    body,
):
    transport = (
        SyntheticTransport(flow=body)
        if resource == "flow"
        else SyntheticTransport(collection=body)
    )
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        validate(transport=transport)


def test_response_json_rejects_excessive_nesting_before_schema_validation():
    nested: object = "leaf"
    for _ in range(12):
        nested = {"nested": nested}
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError, match="nesting"):
        validate(transport=SyntheticTransport(flow=nested))


def test_response_json_rejects_excessive_container_count_before_schema_validation():
    value = {f"key{index}": {} for index in range(70)}
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError, match="structure"):
        validate(transport=SyntheticTransport(flow=value))


@pytest.mark.parametrize("resource_index", [0, 1])
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("status_code", 201),
        ("status_code", True),
        ("final_url", "https://graph.microsoft.com/v1.0/other"),
        ("content_type", "text/html"),
        ("content_type", "application/json; charset=iso-8859-1"),
        ("content_type", "application/json; charset=utf-8; charset=utf-8"),
        ("content_type", "application/json; unknown=true"),
        ("content_type", "application/json\r\nX: y"),
        ("body", b""),
        (
            "body",
            b"x" * (MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1),
        ),
    ],
)
def test_probe_revalidates_every_public_response_transport_boundary(
    resource_index,
    field,
    replacement,
):
    prerequisite = prerequisites()

    def transport(plan):
        responses = list(synthetic_responses(plan))
        object.__setattr__(responses[resource_index], field, replacement)
        return tuple(responses)

    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        validate(prerequisite=prerequisite, transport=transport)


@pytest.mark.parametrize(
    "response_pair",
    [
        (),
        (None,),
        (None, None),
        [None, None],
        None,
        "responses",
    ],
)
def test_probe_rejects_non_exact_response_pair(response_pair):
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        validate(transport=SyntheticTransport(response_pair=response_pair))


def test_transport_failure_is_sanitized_after_original_context_is_discarded():
    class FailingTransport:
        def __call__(self, plan):
            del plan
            raise RuntimeError("secret upstream detail")

    with pytest.raises(EntraExternalIdUserFlowGraphProbeError) as error:
        validate(transport=FailingTransport())
    assert "secret upstream detail" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("permission_type", "application"),
        ("permission_name", "EventListener.ReadWrite.All"),
        ("permission_id", "00000000-0000-0000-0000-000000000000"),
        ("consent_requirement", "user"),
        ("credential_origin", "environment"),
        ("least_privileged_role_name", "Global Administrator"),
        (
            "least_privileged_role_template_id",
            "00000000-0000-0000-0000-000000000000",
        ),
    ],
)
def test_authorization_contract_rejects_any_permission_or_role_widening(
    field,
    replacement,
):
    values = {
        "permission_type": "delegated_work_school",
        "permission_name": ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION,
        "permission_id": ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID,
        "consent_requirement": "admin",
        "credential_origin": "out_of_band_operator",
        "least_privileged_role_name": (ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE),
        "least_privileged_role_template_id": (
            ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID
        ),
    }
    values[field] = replacement
    with pytest.raises(ValueError, match="authorization is invalid"):
        EntraExternalIdUserFlowGraphAuthorizationContract(**values)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("approved_user_flow_document_sha256", "0" * 64),
        ("approved_user_flow_document_sha256", "A" * 64),
        ("approved_user_flow_document_sha256", "short"),
        ("approved_inventory_document_sha256", "0" * 64),
        ("user_flow_document", b"{}"),
        ("inventory_document", b"{}"),
        ("api_registration_document", b"{}"),
        ("calling_client_registration_document", b"{}"),
    ],
)
def test_probe_rejects_any_unapproved_or_malformed_prerequisite(field, replacement):
    prerequisite = prerequisites()
    prerequisite[field] = replacement
    expected = (TypeError, EntraExternalIdUserFlowGraphProbeError)
    with pytest.raises(expected):
        validate(prerequisite=prerequisite)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("user_flow_document", "json"),
        ("approved_user_flow_document_sha256", None),
    ],
)
def test_probe_rejects_wrong_prerequisite_scalar_types(field, replacement):
    prerequisite = prerequisites()
    prerequisite[field] = replacement
    with pytest.raises(TypeError):
        validate(prerequisite=prerequisite)


def test_every_boolean_receipt_field_is_fail_closed_in_post_init_and_renderer():
    receipt = validate()
    for field in fields(receipt):
        current = getattr(receipt, field.name)
        if type(current) is not bool:
            continue
        tampered = copy.copy(receipt)
        object.__setattr__(tampered, field.name, not current)
        with pytest.raises(ValueError, match="receipt is invalid"):
            tampered.__post_init__()
        with pytest.raises(ValueError, match="receipt is invalid"):
            render_entra_external_id_user_flow_graph_probe_receipt(tampered)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("schema_version", 2),
        ("schema_version", True),
        ("validation_scope", "wrong"),
        ("graph_api_version", "beta"),
        ("user_flow_response_shape", "value_array"),
        ("request_count", 1),
        ("request_count", True),
        ("response_count", 1),
        ("user_flow_response_bytes", 0),
        (
            "user_flow_response_bytes",
            MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1,
        ),
        ("include_applications_response_bytes", 0),
        (
            "include_applications_response_bytes",
            MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1,
        ),
        ("total_response_bytes", 0),
        (
            "total_response_bytes",
            MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TOTAL_RESPONSE_BYTES + 1,
        ),
        ("configuration_sha256", "A" * 64),
        ("request_plan_sha256", "0" * 63),
        ("approved_inventory_document_sha256", "0" * 64),
        ("approved_user_flow_document_sha256", "0" * 64),
    ],
)
def test_receipt_rejects_scalar_count_digest_or_shape_tampering(field, replacement):
    receipt = validate()
    tampered = copy.copy(receipt)
    object.__setattr__(tampered, field, replacement)
    with pytest.raises(ValueError, match="receipt is invalid"):
        tampered.__post_init__()
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_entra_external_id_user_flow_graph_probe_receipt(tampered)


def test_receipt_rejects_individual_byte_counts_that_do_not_sum_to_total():
    receipt = validate()
    tampered = copy.copy(receipt)
    object.__setattr__(
        tampered,
        "user_flow_response_bytes",
        receipt.user_flow_response_bytes + 1,
    )
    with pytest.raises(ValueError, match="receipt is invalid"):
        tampered.__post_init__()


def test_render_rejects_wrong_receipt_type():
    with pytest.raises(TypeError, match="receipt is required"):
        render_entra_external_id_user_flow_graph_probe_receipt(object())


class LiveRawResponse:
    def __init__(self, url: str, body: bytes) -> None:
        self.status = 200
        self._url = url
        self._body = body
        self.headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            "Content-Length": str(len(body)),
        }

    def geturl(self) -> str:
        return self._url

    def read(self, amount: int = -1) -> bytes:
        assert amount == MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1
        return self._body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args


def live_arguments(token: str = TOKEN):
    return {
        **prerequisites(),
        "authorization": authorization(),
        "delegated_access_token": token,
    }


def attested_pair(plan):
    public = synthetic_responses(plan)
    return tuple(
        loader_module._attested_live_response(
            status_code=response.status_code,
            final_url=response.final_url,
            content_type=response.content_type,
            body=response.body,
        )
        for response in public
    )


def test_live_entrypoint_maps_only_a_fully_attested_pair_to_provider_evidence(
    monkeypatch,
):
    observed = {}

    class FakeModuleOwnedLoader:
        def __init__(self, *, delegated_access_token):
            observed["token"] = delegated_access_token
            observed["closed"] = False

        def __call__(self, plan):
            observed["plan"] = plan
            return attested_pair(plan)

        def close(self):
            observed["closed"] = True
            observed["token"] = None

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraExternalIdUserFlowGraphLoader",
        FakeModuleOwnedLoader,
    )
    receipt = probe_live_entra_external_id_user_flow_graph(**live_arguments())
    assert observed["closed"] is True
    assert observed["token"] is None
    assert len(observed["plan"]) == 2
    assert receipt.synthetic_transport_used is False
    for name in (
        "live_https_transport_attested",
        "provider_io_performed",
        "provider_state_checked",
        "source_authenticity_checked",
        "user_flow_id_returned_by_graph_checked",
        "live_user_flow_checked",
        "live_user_flow_type_checked",
        "live_user_flow_application_association_checked",
        "live_include_all_applications_checked",
        "live_included_application_count_checked",
    ):
        assert getattr(receipt, name) is True
    for name in (
        "provider_tenant_ownership_checked",
        "tenant_external_status_checked",
        "live_calling_client_service_principal_checked",
        "application_single_user_flow_uniqueness_checked",
        "atomic_provider_snapshot_checked",
        "concurrent_provider_mutation_checked",
        "response_freshness_checked",
        "operator_token_event_listener_read_all_permission_checked",
        "operator_token_event_listener_read_all_admin_consent_checked",
        "delegated_operator_role_checked",
        "activation_ready",
    ):
        assert getattr(receipt, name) is False


def test_live_entrypoint_rejects_public_synthetic_response_pair(monkeypatch):
    class SyntheticLoader:
        def __init__(self, *, delegated_access_token):
            self.token = delegated_access_token

        def __call__(self, plan):
            return synthetic_responses(plan)

        def close(self):
            self.token = None

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraExternalIdUserFlowGraphLoader",
        SyntheticLoader,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError, match="not attested"):
        probe_live_entra_external_id_user_flow_graph(**live_arguments())


def test_synthetic_entrypoint_rejects_attested_provider_response_pair():
    class AttestedTransport:
        def __call__(self, plan):
            return attested_pair(plan)

    with pytest.raises(EntraExternalIdUserFlowGraphProbeError, match="not accepted"):
        validate(transport=AttestedTransport())


def test_live_entrypoint_rejects_mixed_attested_and_synthetic_pair(monkeypatch):
    class MixedLoader:
        def __init__(self, *, delegated_access_token):
            self.token = delegated_access_token

        def __call__(self, plan):
            live = attested_pair(plan)
            public = synthetic_responses(plan)
            return live[0], public[1]

        def close(self):
            self.token = None

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraExternalIdUserFlowGraphLoader",
        MixedLoader,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError, match="not attested"):
        probe_live_entra_external_id_user_flow_graph(**live_arguments())


@pytest.mark.parametrize("failure_call", [1, 2])
def test_live_read_exception_is_context_free_and_scrubs_token_recursively(
    monkeypatch,
    failure_call,
):
    calls = 0

    def failing_open(raw_request, timeout):
        nonlocal calls
        del timeout
        calls += 1
        if calls == failure_call:
            raise RuntimeError(f"upstream retained {TOKEN}")
        return LiveRawResponse(
            raw_request.full_url,
            json.dumps(flow_body()).encode(),
        )

    monkeypatch.setattr(loader_module, "_default_open", failing_open)
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError) as error:
        probe_live_entra_external_id_user_flow_graph(**live_arguments())
    assert calls == failure_call
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_token_in_production_exception_graph(error.value, TOKEN)


@pytest.mark.parametrize("failure_call", [1, 2])
@pytest.mark.parametrize(
    ("exception_type", "expected_message"),
    [
        (KeyboardInterrupt, "retrieval interrupted"),
        (SystemExit, "retrieval terminated"),
    ],
)
def test_live_base_exception_scrubs_token_on_either_read(
    monkeypatch,
    failure_call,
    exception_type,
    expected_message,
):
    calls = 0

    def failing_open(raw_request, timeout):
        nonlocal calls
        del timeout
        calls += 1
        if calls == failure_call:
            raise exception_type(f"base exception retained {TOKEN}")
        return LiveRawResponse(
            raw_request.full_url,
            json.dumps(flow_body()).encode(),
        )

    monkeypatch.setattr(loader_module, "_default_open", failing_open)
    with pytest.raises(exception_type, match=expected_message) as error:
        probe_live_entra_external_id_user_flow_graph(**live_arguments())
    assert calls == failure_call
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_token_in_production_exception_graph(error.value, TOKEN)


def test_live_constructor_failure_scrubs_invalid_token_from_all_production_frames():
    invalid_token = "invalid step212 sentinel token"
    with pytest.raises(ValueError, match="token is invalid") as error:
        probe_live_entra_external_id_user_flow_graph(**live_arguments(invalid_token))
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_token_in_production_exception_graph(error.value, invalid_token)


def test_first_live_read_may_complete_before_second_failure_but_no_receipt_emits(
    monkeypatch,
):
    calls = []

    def partial_open(raw_request, timeout):
        del timeout
        calls.append(raw_request.full_url)
        if len(calls) == 2:
            raise OSError("second read failed")
        return LiveRawResponse(
            raw_request.full_url,
            json.dumps(flow_body()).encode(),
        )

    monkeypatch.setattr(loader_module, "_default_open", partial_open)
    with pytest.raises(EntraExternalIdUserFlowGraphProbeError):
        probe_live_entra_external_id_user_flow_graph(**live_arguments())
    assert len(calls) == 2
    assert calls[0].endswith(f"/{USER_FLOW_ID}?$select=id,conditions")
    assert calls[1].endswith(
        f"/{USER_FLOW_ID}/conditions/applications/includeApplications?$select=appId"
    )
