"""Controlled Graph proof of one External ID user-flow application link.

The probe reruns one exact digest-approved Step 211 offline projection, emits
two immutable Microsoft Graph v1.0 GET requests through an explicit transport,
and compares bounded responses with the approved user-flow and calling-client
identities.  The two reads are sequential but not an atomic provider snapshot.

Only responses sealed by the module-owned HTTPS loader can confer live provider
evidence.  Public response objects and injected HTTP openers remain synthetic,
even when their bodies exactly match the approved projection.

Official contract references:
* https://learn.microsoft.com/en-us/graph/api/authenticationeventsflow-get?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/authenticationconditionsapplications-list-includeapplications?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/permissions-reference
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from uuid import UUID

from app.security.authentication_entra_external_id_user_flow_graph_http_loader import (
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT,
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES,
    BoundedHTTPSEntraExternalIdUserFlowGraphLoader,
    EntraExternalIdUserFlowGraphRequest,
    EntraExternalIdUserFlowGraphRequestPlan,
    EntraExternalIdUserFlowGraphResponse,
    EntraExternalIdUserFlowGraphTransport,
    entra_external_id_user_flow_graph_url,
)
from app.security.authentication_entra_external_id_user_flow_readiness import (
    ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
    EntraExternalIdUserFlowReadinessError,
    load_entra_external_id_user_flow_readiness,
    render_entra_external_id_user_flow_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)

ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_external_id_user_flow_graph_probe_receipt"
)
ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCHEMA_VERSION = 1
ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE = (
    "controlled_read_only_graph_user_flow_calling_client_association_proof"
)
ENTRA_GRAPH_API_VERSION = "v1.0"
ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION = "EventListener.Read.All"
ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID = (
    "f7dd3bed-5eec-48da-bc73-1c0ef50bc9a1"
)
ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE = "External ID User Flow Administrator"
ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID = (
    "6e591065-9bad-43ed-90f3-e9424366d2f0"
)
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TOTAL_RESPONSE_BYTES = (
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT
    * MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES
)
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_NESTING_DEPTH = 8
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_CONTAINERS = 64
_SHA256_HEX_LENGTH = 64
_ENTRY_ODATA_TYPE = "#microsoft.graph.authenticationConditionApplication"
_CONDITIONS_ODATA_TYPE = "#microsoft.graph.authenticationConditions"
_APPLICATIONS_ODATA_TYPE = "#microsoft.graph.authenticationConditionsApplications"
_SELECTED_FLOW_CONTEXT = (
    f"{ENTRA_GRAPH_BASE_URL}/$metadata#identity/"
    "authenticationEventsFlows(id,conditions)/$entity"
)


class EntraExternalIdUserFlowGraphProbeError(ValueError):
    """Sanitized rejection of invalid prerequisites or Graph evidence."""


@dataclass(frozen=True, slots=True)
class EntraExternalIdUserFlowGraphAuthorizationContract:
    """Declared least-privilege operator boundary, never token evidence."""

    permission_type: Literal["delegated_work_school"]
    permission_name: str
    permission_id: str
    consent_requirement: Literal["admin"]
    credential_origin: Literal["out_of_band_operator"]
    least_privileged_role_name: str
    least_privileged_role_template_id: str

    def __post_init__(self) -> None:
        if (
            self.permission_type != "delegated_work_school"
            or self.permission_name != ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION
            or self.permission_id
            != ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID
            or self.consent_requirement != "admin"
            or self.credential_origin != "out_of_band_operator"
            or self.least_privileged_role_name
            != ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE
            or self.least_privileged_role_template_id
            != ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID
        ):
            raise ValueError("Microsoft Graph user-flow authorization is invalid")


@dataclass(frozen=True, slots=True)
class EntraExternalIdUserFlowGraphProbeReceipt:
    receipt_type: str
    schema_version: int
    validation_scope: str
    graph_api_version: str
    authorization_permission_type: str
    authorization_permission_name: str
    authorization_permission_id: str
    authorization_consent_requirement: str
    authorization_credential_origin: str
    authorization_least_privileged_role_name: str
    authorization_least_privileged_role_template_id: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    approved_user_flow_document_sha256: str
    user_flow_document_sha256: str
    offline_user_flow_receipt_sha256: str
    request_plan_sha256: str
    user_flow_response_sha256: str
    include_applications_response_sha256: str
    tenant_id_sha256: str
    user_flow_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_service_principal_object_id_sha256: str
    calling_client_service_principal_app_id_mapping_sha256: str
    user_flow_calling_client_association_sha256: str
    user_flow_response_shape: str
    request_count: int
    response_count: int
    user_flow_response_bytes: int
    include_applications_response_bytes: int
    total_response_bytes: int
    approved_user_flow_digest_bound: bool
    offline_user_flow_projection_revalidated: bool
    configuration_bound: bool
    approved_inventory_digest_bound: bool
    exact_two_get_request_plan_validated: bool
    sequential_request_order_validated: bool
    same_user_flow_id_in_both_requests_validated: bool
    graph_global_v1_endpoint_validated: bool
    read_only_methods_validated: bool
    exact_select_projections_validated: bool
    no_request_body_validated: bool
    no_proxy_redirect_retry_compression_validated: bool
    response_bounds_validated: bool
    response_json_integrity_validated: bool
    response_schema_validated: bool
    direct_or_documented_envelope_validated: bool
    canonical_user_flow_id_validated: bool
    external_users_self_service_sign_up_flow_type_validated: bool
    include_all_applications_false_validated: bool
    materialized_navigation_constrained: bool
    exact_include_applications_collection_validated: bool
    collection_paging_and_count_rejected: bool
    exact_single_included_application_validated: bool
    calling_client_application_id_bound: bool
    calling_client_service_principal_projection_revalidated: bool
    calling_client_service_principal_app_id_mapping_validated: bool
    least_privilege_delegated_permission_contract_validated: bool
    least_privilege_role_intent_validated: bool
    out_of_band_operator_contract_validated: bool
    application_permission_contract_rejected: bool
    synthetic_transport_used: bool
    live_https_transport_attested: bool
    provider_io_performed: bool
    provider_state_checked: bool
    source_authenticity_checked: bool
    user_flow_id_returned_by_graph_checked: bool
    live_user_flow_checked: bool
    live_user_flow_type_checked: bool
    live_user_flow_application_association_checked: bool
    live_include_all_applications_checked: bool
    live_included_application_count_checked: bool
    provider_tenant_ownership_checked: bool
    tenant_external_status_checked: bool
    live_calling_client_service_principal_checked: bool
    application_single_user_flow_uniqueness_checked: bool
    other_user_flow_associations_checked: bool
    authorization_token_claims_checked: bool
    actual_token_type_checked: bool
    app_only_token_checked: bool
    work_school_account_checked: bool
    token_tenant_checked: bool
    token_graph_audience_checked: bool
    operator_token_event_listener_read_all_permission_checked: bool
    operator_token_event_listener_read_all_admin_consent_checked: bool
    delegated_operator_identity_checked: bool
    delegated_operator_role_checked: bool
    delegated_operator_authorization_checked: bool
    atomic_provider_snapshot_checked: bool
    concurrent_provider_mutation_checked: bool
    response_freshness_checked: bool
    user_flow_display_name_checked: bool
    user_flow_description_checked: bool
    identity_providers_checked: bool
    authentication_methods_checked: bool
    sign_up_allowed_checked: bool
    attribute_collection_checked: bool
    page_layout_checked: bool
    custom_attributes_checked: bool
    token_claims_checked: bool
    user_type_to_create_checked: bool
    priority_checked: bool
    localization_checked: bool
    language_customization_checked: bool
    session_behavior_checked: bool
    api_connectors_checked: bool
    custom_authentication_extensions_checked: bool
    password_reset_checked: bool
    multifactor_authentication_checked: bool
    terms_consent_checked: bool
    branding_checked: bool
    custom_domain_checked: bool
    conditional_access_checked: bool
    tenant_policy_checked: bool
    runtime_user_flow_executed: bool
    real_customer_sign_up_checked: bool
    real_customer_sign_in_checked: bool
    real_signed_token_checked: bool
    user_flow_creation_performed: bool
    user_flow_update_performed: bool
    user_flow_deletion_performed: bool
    application_association_creation_performed: bool
    application_association_deletion_performed: bool
    application_mutation_performed: bool
    service_principal_mutation_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        validated = (
            self.approved_user_flow_digest_bound,
            self.offline_user_flow_projection_revalidated,
            self.configuration_bound,
            self.approved_inventory_digest_bound,
            self.exact_two_get_request_plan_validated,
            self.sequential_request_order_validated,
            self.same_user_flow_id_in_both_requests_validated,
            self.graph_global_v1_endpoint_validated,
            self.read_only_methods_validated,
            self.exact_select_projections_validated,
            self.no_request_body_validated,
            self.no_proxy_redirect_retry_compression_validated,
            self.response_bounds_validated,
            self.response_json_integrity_validated,
            self.response_schema_validated,
            self.direct_or_documented_envelope_validated,
            self.canonical_user_flow_id_validated,
            self.external_users_self_service_sign_up_flow_type_validated,
            self.include_all_applications_false_validated,
            self.materialized_navigation_constrained,
            self.exact_include_applications_collection_validated,
            self.collection_paging_and_count_rejected,
            self.exact_single_included_application_validated,
            self.calling_client_application_id_bound,
            self.calling_client_service_principal_projection_revalidated,
            self.calling_client_service_principal_app_id_mapping_validated,
            self.least_privilege_delegated_permission_contract_validated,
            self.least_privilege_role_intent_validated,
            self.out_of_band_operator_contract_validated,
            self.application_permission_contract_rejected,
        )
        deferred = (
            self.provider_tenant_ownership_checked,
            self.tenant_external_status_checked,
            self.live_calling_client_service_principal_checked,
            self.application_single_user_flow_uniqueness_checked,
            self.other_user_flow_associations_checked,
            self.authorization_token_claims_checked,
            self.actual_token_type_checked,
            self.app_only_token_checked,
            self.work_school_account_checked,
            self.token_tenant_checked,
            self.token_graph_audience_checked,
            self.operator_token_event_listener_read_all_permission_checked,
            self.operator_token_event_listener_read_all_admin_consent_checked,
            self.delegated_operator_identity_checked,
            self.delegated_operator_role_checked,
            self.delegated_operator_authorization_checked,
            self.atomic_provider_snapshot_checked,
            self.concurrent_provider_mutation_checked,
            self.response_freshness_checked,
            self.user_flow_display_name_checked,
            self.user_flow_description_checked,
            self.identity_providers_checked,
            self.authentication_methods_checked,
            self.sign_up_allowed_checked,
            self.attribute_collection_checked,
            self.page_layout_checked,
            self.custom_attributes_checked,
            self.token_claims_checked,
            self.user_type_to_create_checked,
            self.priority_checked,
            self.localization_checked,
            self.language_customization_checked,
            self.session_behavior_checked,
            self.api_connectors_checked,
            self.custom_authentication_extensions_checked,
            self.password_reset_checked,
            self.multifactor_authentication_checked,
            self.terms_consent_checked,
            self.branding_checked,
            self.custom_domain_checked,
            self.conditional_access_checked,
            self.tenant_policy_checked,
            self.runtime_user_flow_executed,
            self.real_customer_sign_up_checked,
            self.real_customer_sign_in_checked,
            self.real_signed_token_checked,
            self.user_flow_creation_performed,
            self.user_flow_update_performed,
            self.user_flow_deletion_performed,
            self.application_association_creation_performed,
            self.application_association_deletion_performed,
            self.application_mutation_performed,
            self.service_principal_mutation_performed,
            self.activation_ready,
        )
        live = self.live_https_transport_attested
        live_evidence = (
            self.provider_io_performed,
            self.provider_state_checked,
            self.source_authenticity_checked,
            self.user_flow_id_returned_by_graph_checked,
            self.live_user_flow_checked,
            self.live_user_flow_type_checked,
            self.live_user_flow_application_association_checked,
            self.live_include_all_applications_checked,
            self.live_included_application_count_checked,
        )
        if (
            self.receipt_type != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCHEMA_VERSION
            or self.validation_scope != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE
            or self.graph_api_version != ENTRA_GRAPH_API_VERSION
            or self.authorization_permission_type != "delegated_work_school"
            or self.authorization_permission_name
            != ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION
            or self.authorization_permission_id
            != ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID
            or self.authorization_consent_requirement != "admin"
            or self.authorization_credential_origin != "out_of_band_operator"
            or self.authorization_least_privileged_role_name
            != ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE
            or self.authorization_least_privileged_role_template_id
            != ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_user_flow_document_sha256,
                self.user_flow_document_sha256,
            )
            or self.user_flow_response_shape
            not in {"direct", "documented_value_envelope"}
            or type(self.request_count) is not int
            or self.request_count != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT
            or type(self.response_count) is not int
            or self.response_count != ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT
            or type(self.user_flow_response_bytes) is not int
            or not 0
            < self.user_flow_response_bytes
            <= MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES
            or type(self.include_applications_response_bytes) is not int
            or not 0
            < self.include_applications_response_bytes
            <= MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES
            or type(self.total_response_bytes) is not int
            or not 0
            < self.total_response_bytes
            <= MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TOTAL_RESPONSE_BYTES
            or self.total_response_bytes
            != self.user_flow_response_bytes + self.include_applications_response_bytes
            or any(value is not True for value in validated)
            or any(value is not False for value in deferred)
            or type(self.synthetic_transport_used) is not bool
            or type(live) is not bool
            or self.synthetic_transport_used is live
            or any(value is not live for value in live_evidence)
        ):
            raise ValueError("Microsoft Graph user-flow probe receipt is invalid")


def _is_lower_sha256(value: object) -> bool:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or value != value.lower()
    ):
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _evidence_sha256(label: str, *materials: bytes) -> str:
    framed = b"engineer4me-step212-v1\x00" + str(len(label)).encode("ascii")
    framed += b":" + label.encode("ascii") + str(len(materials)).encode("ascii")
    for material in materials:
        framed += b":" + str(len(material)).encode("ascii") + b":" + material
    return hashlib.sha256(framed).hexdigest()


def _identity_sha256(label: str, *values: str) -> str:
    return _evidence_sha256(
        label,
        *(value.encode("utf-8") for value in values),
    )


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraExternalIdUserFlowGraphProbeError(
                "Microsoft Graph response contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise EntraExternalIdUserFlowGraphProbeError(
        "Microsoft Graph response contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph response contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_NESTING_DEPTH:
                raise EntraExternalIdUserFlowGraphProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_NESTING_DEPTH:
                raise EntraExternalIdUserFlowGraphProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_CONTAINERS:
            raise EntraExternalIdUserFlowGraphProbeError(
                "Microsoft Graph response exceeds the structure limit"
            )


def _content_type_is_json(value: object) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or any(character in value for character in "\x00\r\n")
    ):
        return False
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        return False
    allowed = {
        "odata.metadata": frozenset({"minimal", "full", "none"}),
        "odata.streaming": frozenset({"true", "false"}),
        "ieee754compatible": frozenset({"true", "false"}),
        "charset": frozenset({"utf-8"}),
    }
    seen: set[str] = set()
    for parameter in parts[1:]:
        if parameter.count("=") != 1:
            return False
        name, parameter_value = (
            component.strip().lower() for component in parameter.split("=", 1)
        )
        if (
            not name
            or name in seen
            or name not in allowed
            or parameter_value not in allowed[name]
        ):
            return False
        seen.add(name)
    return True


def _parse_response_json(
    response: EntraExternalIdUserFlowGraphResponse,
    request: EntraExternalIdUserFlowGraphRequest,
) -> tuple[dict[str, Any], bytes]:
    if type(response) is not EntraExternalIdUserFlowGraphResponse:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph transport returned an invalid response"
        )
    try:
        response.validate()
    except ValueError:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph transport returned an invalid response"
        ) from None
    if (
        response.status_code != 200
        or not hmac.compare_digest(response.final_url, request.url)
        or not _content_type_is_json(response.content_type)
        or not response.body
        or len(response.body) > request.maximum_response_bytes
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph response failed the transport contract"
        )
    try:
        decoded = response.body.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph response must be UTF-8 JSON"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
    except EntraExternalIdUserFlowGraphProbeError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph response is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph response root must be an object"
        )
    _require_bounded_structure(parsed)
    return parsed, _canonical_bytes(parsed)


def _navigation_context(user_flow_id: str) -> str:
    return (
        f"{ENTRA_GRAPH_BASE_URL}/$metadata#identity/authenticationEventsFlows"
        f"('{user_flow_id}')/microsoft.graph."
        "externalUsersSelfServiceSignUpEventsFlow/conditions/applications/"
        "includeApplications"
    )


def _selected_collection_context(user_flow_id: str) -> str:
    return (
        f"{ENTRA_GRAPH_BASE_URL}/$metadata#identity/authenticationEventsFlows"
        f"('{user_flow_id}')/conditions/applications/includeApplications(appId)"
    )


def _validate_application_entry(value: object, application_id: str) -> None:
    if not isinstance(value, dict):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included application is invalid"
        )
    if not {"appId"}.issubset(value) or not set(value).issubset(
        {"appId", "@odata.type"}
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included application fields are invalid"
        )
    if (
        not _canonical_uuid(value.get("appId"))
        or value["appId"] != application_id
        or ("@odata.type" in value and value["@odata.type"] != _ENTRY_ODATA_TYPE)
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included application identity is invalid"
        )


def _validate_user_flow_response(
    parsed: dict[str, Any],
    *,
    user_flow_id: str,
    application_id: str,
) -> Literal["direct", "documented_value_envelope"]:
    if set(parsed) == {"value"}:
        candidate = parsed["value"]
        response_shape: Literal["direct", "documented_value_envelope"] = (
            "documented_value_envelope"
        )
    else:
        candidate = parsed
        response_shape = "direct"
    if not isinstance(candidate, dict):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow entity is invalid"
        )
    required = {"@odata.type", "id", "conditions"}
    allowed = required | {"@odata.context"}
    if not required.issubset(candidate) or not set(candidate).issubset(allowed):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow fields do not match the selected contract"
        )
    if (
        candidate["@odata.type"] != ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE
        or not _canonical_uuid(candidate["id"])
        or candidate["id"] != user_flow_id
        or (
            "@odata.context" in candidate
            and candidate["@odata.context"] != _SELECTED_FLOW_CONTEXT
        )
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow identity or type is invalid"
        )
    conditions = candidate["conditions"]
    if (
        not isinstance(conditions, dict)
        or not {"applications"}.issubset(conditions)
        or not set(conditions).issubset({"applications", "@odata.type"})
        or (
            "@odata.type" in conditions
            and conditions["@odata.type"] != _CONDITIONS_ODATA_TYPE
        )
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow conditions are invalid"
        )
    applications = conditions["applications"]
    required_applications = {"includeAllApplications"}
    allowed_applications = required_applications | {
        "@odata.type",
        "includeApplications@odata.context",
        "includeApplications",
    }
    if (
        not isinstance(applications, dict)
        or not required_applications.issubset(applications)
        or not set(applications).issubset(allowed_applications)
        or type(applications["includeAllApplications"]) is not bool
        or applications["includeAllApplications"] is not False
        or (
            "@odata.type" in applications
            and applications["@odata.type"] != _APPLICATIONS_ODATA_TYPE
        )
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow application conditions are invalid"
        )
    if "includeApplications@odata.context" in applications and applications[
        "includeApplications@odata.context"
    ] != _navigation_context(user_flow_id):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph materialized navigation context is invalid"
        )
    if "includeApplications" in applications:
        included = applications["includeApplications"]
        if not isinstance(included, list) or len(included) > 1:
            raise EntraExternalIdUserFlowGraphProbeError(
                "Microsoft Graph materialized navigation is invalid"
            )
        if included:
            _validate_application_entry(included[0], application_id)
    return response_shape


def _validate_include_applications_response(
    parsed: dict[str, Any],
    *,
    user_flow_id: str,
    application_id: str,
) -> None:
    if set(parsed) not in (
        {"value"},
        {"@odata.context", "value"},
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included-applications collection fields are invalid"
        )
    if "@odata.context" in parsed and parsed[
        "@odata.context"
    ] != _selected_collection_context(user_flow_id):
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included-applications context is invalid"
        )
    value = parsed["value"]
    if not isinstance(value, list) or len(value) != 1:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph included-applications count is invalid"
        )
    _validate_application_entry(value[0], application_id)


def _approved_identities(
    *,
    user_flow_document: bytes,
    inventory_document: bytes,
) -> dict[str, str]:
    """Recover public identities only after the Step 211 loader succeeds."""

    try:
        user_flow = json.loads(user_flow_document.decode("utf-8"))["user_flow"]
        inventory = json.loads(inventory_document.decode("utf-8"))["inventory"]
        applications = {entry["role"]: entry for entry in inventory["applications"]}
        principals = {entry["role"]: entry for entry in inventory["service_principals"]}
        identities = {
            "tenant_id": inventory["tenant_id"],
            "user_flow_id": user_flow["id"],
            "calling_client_application_id": user_flow["conditions"]["applications"][
                "includeApplications"
            ][0]["appId"],
            "calling_client_inventory_application_id": applications["calling_client"][
                "application_id"
            ],
            "calling_client_service_principal_object_id": principals["calling_client"][
                "service_principal_object_id"
            ],
            "calling_client_service_principal_app_id": principals["calling_client"][
                "application_id"
            ],
        }
    except (IndexError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraExternalIdUserFlowGraphProbeError(
            "approved user-flow identity evidence cannot be reconstructed"
        ) from None
    if any(not _canonical_uuid(value) for value in identities.values()):
        raise EntraExternalIdUserFlowGraphProbeError(
            "approved user-flow identity evidence cannot be reconstructed"
        )
    if not (
        identities["calling_client_application_id"]
        == identities["calling_client_inventory_application_id"]
        == identities["calling_client_service_principal_app_id"]
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "approved calling-client identity mapping is invalid"
        )
    return identities


def _request_plan(user_flow_id: str) -> EntraExternalIdUserFlowGraphRequestPlan:
    definitions: tuple[
        tuple[int, Literal["user_flow", "include_applications"]], ...
    ] = (
        (1, "user_flow"),
        (2, "include_applications"),
    )
    requests = tuple(
        EntraExternalIdUserFlowGraphRequest(
            sequence=sequence,
            resource=resource,
            method="GET",
            url=entra_external_id_user_flow_graph_url(
                user_flow_id=user_flow_id,
                resource=resource,
            ),
            headers=(
                (
                    ("Accept", "application/json"),
                    ("Accept-Encoding", "identity"),
                )
                if resource == "user_flow"
                else (
                    ("Accept", "application/json"),
                    ("Accept-Encoding", "identity"),
                    ("Content-Type", "application/json"),
                )
            ),
            body=None,
            timeout_seconds=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
            maximum_response_bytes=(
                MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES
            ),
            follow_redirects=False,
            maximum_retries=0,
            proxy_allowed=False,
        )
        for sequence, resource in definitions
    )
    return requests


def _run_entra_external_id_user_flow_graph_probe(
    *,
    user_flow_document: bytes,
    approved_user_flow_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraExternalIdUserFlowGraphAuthorizationContract,
    transport: EntraExternalIdUserFlowGraphTransport,
    _live_transport_expected: bool,
) -> EntraExternalIdUserFlowGraphProbeReceipt:
    if not isinstance(user_flow_document, bytes):
        raise TypeError("approved Entra user-flow document must be bytes")
    if not _is_lower_sha256(approved_user_flow_document_sha256):
        raise TypeError("approved Entra user-flow document digest is required")
    if type(authorization) is not EntraExternalIdUserFlowGraphAuthorizationContract:
        raise TypeError("Microsoft Graph user-flow authorization is required")
    try:
        authorization.__post_init__()
    except ValueError:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow authorization is invalid"
        ) from None
    if not callable(transport):
        raise TypeError("an explicit Microsoft Graph user-flow transport is required")
    if type(_live_transport_expected) is not bool:
        raise TypeError("private Microsoft Graph user-flow transport mode is required")

    try:
        offline_receipt = load_entra_external_id_user_flow_readiness(
            document=user_flow_document,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
            calling_client_registration_document=calling_client_registration_document,
            accepted_calling_client_registration_document_sha256=(
                accepted_calling_client_registration_document_sha256
            ),
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
        )
    except (TypeError, ValueError, EntraExternalIdUserFlowReadinessError):
        raise EntraExternalIdUserFlowGraphProbeError(
            "approved offline user-flow evidence is not valid"
        ) from None
    if not hmac.compare_digest(
        offline_receipt.desired_state_document_sha256,
        approved_user_flow_document_sha256,
    ):
        raise EntraExternalIdUserFlowGraphProbeError(
            "offline user-flow evidence does not match its approved digest"
        )

    identities = _approved_identities(
        user_flow_document=user_flow_document,
        inventory_document=inventory_document,
    )
    requests = _request_plan(identities["user_flow_id"])
    responses: list[EntraExternalIdUserFlowGraphResponse] = []
    canonical_responses: list[bytes] = []
    response_shape: Literal["direct", "documented_value_envelope"] | None = None
    transport_failed = False
    try:
        response_pair = transport(requests)
    # Arbitrary injected transports are untrusted at this public boundary.
    except Exception:  # noqa: BLE001
        transport_failed = True
        response_pair = None
    if transport_failed:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow transport failed"
        )
    if type(response_pair) is not tuple or len(response_pair) != 2:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow transport returned an invalid response pair"
        )
    for request, response in zip(requests, response_pair, strict=True):
        parsed, canonical = _parse_response_json(response, request)
        if request.resource == "user_flow":
            response_shape = _validate_user_flow_response(
                parsed,
                user_flow_id=identities["user_flow_id"],
                application_id=identities["calling_client_application_id"],
            )
        else:
            _validate_include_applications_response(
                parsed,
                user_flow_id=identities["user_flow_id"],
                application_id=identities["calling_client_application_id"],
            )
        if _live_transport_expected and not response.live_https_attested:
            raise EntraExternalIdUserFlowGraphProbeError(
                "live Microsoft Graph user-flow provenance is not attested"
            )
        if not _live_transport_expected and response.live_https_attested:
            raise EntraExternalIdUserFlowGraphProbeError(
                "attested responses are not accepted by synthetic validation"
            )
        responses.append(response)
        canonical_responses.append(canonical)
    if response_shape not in {"direct", "documented_value_envelope"}:
        raise EntraExternalIdUserFlowGraphProbeError(
            "Microsoft Graph user-flow response shape is invalid"
        )

    request_plan_material = _canonical_bytes(
        [
            {
                "sequence": request.sequence,
                "resource": request.resource,
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
                "timeout_seconds": request.timeout_seconds,
                "maximum_response_bytes": request.maximum_response_bytes,
                "follow_redirects": request.follow_redirects,
                "maximum_retries": request.maximum_retries,
                "proxy_allowed": request.proxy_allowed,
            }
            for request in requests
        ]
    )
    live = _live_transport_expected
    return EntraExternalIdUserFlowGraphProbeReceipt(
        receipt_type=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE,
        schema_version=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCHEMA_VERSION,
        validation_scope=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE,
        graph_api_version=ENTRA_GRAPH_API_VERSION,
        authorization_permission_type=authorization.permission_type,
        authorization_permission_name=authorization.permission_name,
        authorization_permission_id=authorization.permission_id,
        authorization_consent_requirement=authorization.consent_requirement,
        authorization_credential_origin=authorization.credential_origin,
        authorization_least_privileged_role_name=(
            authorization.least_privileged_role_name
        ),
        authorization_least_privileged_role_template_id=(
            authorization.least_privileged_role_template_id
        ),
        configuration_sha256=offline_receipt.configuration_sha256,
        api_registration_document_sha256=(
            offline_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            offline_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        inventory_document_sha256=offline_receipt.inventory_document_sha256,
        approved_user_flow_document_sha256=approved_user_flow_document_sha256,
        user_flow_document_sha256=offline_receipt.desired_state_document_sha256,
        offline_user_flow_receipt_sha256=hashlib.sha256(
            render_entra_external_id_user_flow_readiness_receipt(
                offline_receipt
            ).encode("utf-8")
        ).hexdigest(),
        request_plan_sha256=_evidence_sha256("request_plan", request_plan_material),
        user_flow_response_sha256=_evidence_sha256(
            "user_flow_response",
            canonical_responses[0],
        ),
        include_applications_response_sha256=_evidence_sha256(
            "include_applications_response",
            canonical_responses[1],
        ),
        tenant_id_sha256=_identity_sha256("tenant_id", identities["tenant_id"]),
        user_flow_id_sha256=_identity_sha256(
            "user_flow_id", identities["user_flow_id"]
        ),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            identities["calling_client_application_id"],
        ),
        calling_client_service_principal_object_id_sha256=_identity_sha256(
            "calling_client_service_principal_object_id",
            identities["calling_client_service_principal_object_id"],
        ),
        calling_client_service_principal_app_id_mapping_sha256=_identity_sha256(
            "calling_client_service_principal_app_id_mapping",
            identities["tenant_id"],
            identities["calling_client_application_id"],
            identities["calling_client_service_principal_object_id"],
        ),
        user_flow_calling_client_association_sha256=_identity_sha256(
            "user_flow_calling_client_association",
            identities["tenant_id"],
            identities["user_flow_id"],
            ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE,
            "includeAllApplications=false",
            identities["calling_client_application_id"],
        ),
        user_flow_response_shape=response_shape,
        request_count=len(requests),
        response_count=len(responses),
        user_flow_response_bytes=len(responses[0].body),
        include_applications_response_bytes=len(responses[1].body),
        total_response_bytes=sum(len(response.body) for response in responses),
        approved_user_flow_digest_bound=True,
        offline_user_flow_projection_revalidated=True,
        configuration_bound=True,
        approved_inventory_digest_bound=True,
        exact_two_get_request_plan_validated=True,
        sequential_request_order_validated=True,
        same_user_flow_id_in_both_requests_validated=True,
        graph_global_v1_endpoint_validated=True,
        read_only_methods_validated=True,
        exact_select_projections_validated=True,
        no_request_body_validated=True,
        no_proxy_redirect_retry_compression_validated=True,
        response_bounds_validated=True,
        response_json_integrity_validated=True,
        response_schema_validated=True,
        direct_or_documented_envelope_validated=True,
        canonical_user_flow_id_validated=True,
        external_users_self_service_sign_up_flow_type_validated=True,
        include_all_applications_false_validated=True,
        materialized_navigation_constrained=True,
        exact_include_applications_collection_validated=True,
        collection_paging_and_count_rejected=True,
        exact_single_included_application_validated=True,
        calling_client_application_id_bound=True,
        calling_client_service_principal_projection_revalidated=True,
        calling_client_service_principal_app_id_mapping_validated=True,
        least_privilege_delegated_permission_contract_validated=True,
        least_privilege_role_intent_validated=True,
        out_of_band_operator_contract_validated=True,
        application_permission_contract_rejected=True,
        synthetic_transport_used=not live,
        live_https_transport_attested=live,
        provider_io_performed=live,
        provider_state_checked=live,
        source_authenticity_checked=live,
        user_flow_id_returned_by_graph_checked=live,
        live_user_flow_checked=live,
        live_user_flow_type_checked=live,
        live_user_flow_application_association_checked=live,
        live_include_all_applications_checked=live,
        live_included_application_count_checked=live,
        provider_tenant_ownership_checked=False,
        tenant_external_status_checked=False,
        live_calling_client_service_principal_checked=False,
        application_single_user_flow_uniqueness_checked=False,
        other_user_flow_associations_checked=False,
        authorization_token_claims_checked=False,
        actual_token_type_checked=False,
        app_only_token_checked=False,
        work_school_account_checked=False,
        token_tenant_checked=False,
        token_graph_audience_checked=False,
        operator_token_event_listener_read_all_permission_checked=False,
        operator_token_event_listener_read_all_admin_consent_checked=False,
        delegated_operator_identity_checked=False,
        delegated_operator_role_checked=False,
        delegated_operator_authorization_checked=False,
        atomic_provider_snapshot_checked=False,
        concurrent_provider_mutation_checked=False,
        response_freshness_checked=False,
        user_flow_display_name_checked=False,
        user_flow_description_checked=False,
        identity_providers_checked=False,
        authentication_methods_checked=False,
        sign_up_allowed_checked=False,
        attribute_collection_checked=False,
        page_layout_checked=False,
        custom_attributes_checked=False,
        token_claims_checked=False,
        user_type_to_create_checked=False,
        priority_checked=False,
        localization_checked=False,
        language_customization_checked=False,
        session_behavior_checked=False,
        api_connectors_checked=False,
        custom_authentication_extensions_checked=False,
        password_reset_checked=False,
        multifactor_authentication_checked=False,
        terms_consent_checked=False,
        branding_checked=False,
        custom_domain_checked=False,
        conditional_access_checked=False,
        tenant_policy_checked=False,
        runtime_user_flow_executed=False,
        real_customer_sign_up_checked=False,
        real_customer_sign_in_checked=False,
        real_signed_token_checked=False,
        user_flow_creation_performed=False,
        user_flow_update_performed=False,
        user_flow_deletion_performed=False,
        application_association_creation_performed=False,
        application_association_deletion_performed=False,
        application_mutation_performed=False,
        service_principal_mutation_performed=False,
        activation_ready=False,
    )


def validate_entra_external_id_user_flow_graph_probe(
    *,
    user_flow_document: bytes,
    approved_user_flow_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraExternalIdUserFlowGraphAuthorizationContract,
    transport: EntraExternalIdUserFlowGraphTransport,
) -> EntraExternalIdUserFlowGraphProbeReceipt:
    """Validate deterministic responses; never emit live-provider evidence."""

    return _run_entra_external_id_user_flow_graph_probe(
        user_flow_document=user_flow_document,
        approved_user_flow_document_sha256=approved_user_flow_document_sha256,
        authentication_preview=authentication_preview,
        api_registration_document=api_registration_document,
        accepted_api_registration_document_sha256=(
            accepted_api_registration_document_sha256
        ),
        calling_client_registration_document=calling_client_registration_document,
        accepted_calling_client_registration_document_sha256=(
            accepted_calling_client_registration_document_sha256
        ),
        inventory_document=inventory_document,
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        authorization=authorization,
        transport=transport,
        _live_transport_expected=False,
    )


def probe_live_entra_external_id_user_flow_graph(
    *,
    user_flow_document: bytes,
    approved_user_flow_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraExternalIdUserFlowGraphAuthorizationContract,
    delegated_access_token: str,
) -> EntraExternalIdUserFlowGraphProbeReceipt:
    """Perform the sealed two-read HTTPS proof with one opaque token.

    The reads are not atomic.  The first GET can complete before a failure on
    the second GET.  Such a failure emits no receipt and performs no mutation.
    """

    loader = None
    try:
        loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
            delegated_access_token=delegated_access_token
        )
    finally:
        delegated_access_token = None
    try:
        return _run_entra_external_id_user_flow_graph_probe(
            user_flow_document=user_flow_document,
            approved_user_flow_document_sha256=approved_user_flow_document_sha256,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
            calling_client_registration_document=calling_client_registration_document,
            accepted_calling_client_registration_document_sha256=(
                accepted_calling_client_registration_document_sha256
            ),
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
            authorization=authorization,
            transport=loader,
            _live_transport_expected=True,
        )
    finally:
        loader.close()


def render_entra_external_id_user_flow_graph_probe_receipt(
    receipt: EntraExternalIdUserFlowGraphProbeReceipt,
) -> str:
    """Render canonical privacy-minimized proof evidence."""

    if type(receipt) is not EntraExternalIdUserFlowGraphProbeReceipt:
        raise TypeError("Microsoft Graph user-flow probe receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_ADMINISTRATOR_ROLE_TEMPLATE_ID",
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_RECEIPT_TYPE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCHEMA_VERSION",
    "ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_PROBE_SCOPE",
    "ENTRA_GRAPH_API_VERSION",
    "ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_DELEGATED_PERMISSION_ID",
    "ENTRA_GRAPH_EVENT_LISTENER_READ_ALL_PERMISSION",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_CONTAINERS",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_NESTING_DEPTH",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TOTAL_RESPONSE_BYTES",
    "EntraExternalIdUserFlowGraphAuthorizationContract",
    "EntraExternalIdUserFlowGraphProbeError",
    "EntraExternalIdUserFlowGraphProbeReceipt",
    "probe_live_entra_external_id_user_flow_graph",
    "render_entra_external_id_user_flow_graph_probe_receipt",
    "validate_entra_external_id_user_flow_graph_probe",
]
