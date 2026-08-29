"""Offline desired state for one External ID user-flow application link.

This module validates a deliberately narrow, normalized Microsoft Graph v1.0
read-state projection.  It binds one user-flow identity, intended for an
External ID external-tenant context, to the already approved Engineer4Me
browser calling-client application identity.
It revalidates the Step 207 application/service-principal projection so the
calling client is locally projected to have a service principal.

The subset is not a Microsoft Graph create, update, or association request.  It
does not describe the full user-flow policy, serialize a write payload, read
files or environment variables, contact a provider, open a database session,
or mutate any local or provider resource.

Official contract references:
* https://learn.microsoft.com/en-us/graph/api/resources/externalusersselfservicesignupeventsflow?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/identitycontainer-list-authenticationeventsflows?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/authenticationconditionsapplications-post-includeapplications?view=graph-rest-1.0
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, ValidationError, model_validator

from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    EntraApplicationServicePrincipalInventoryReadinessError,
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel


ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_external_id_user_flow_calling_client_"
    "association_readiness"
)
ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_external_id_user_flow_calling_client_"
    "association_readiness_receipt"
)
ENTRA_EXTERNAL_ID_USER_FLOW_SCHEMA_VERSION = 1
ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE = (
    "microsoft_graph_v1_0_external_users_self_service_sign_up_events_flow"
)
ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE = (
    "offline_exact_user_flow_calling_client_association_read_projection_only"
)
ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE = (
    "#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow"
)
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_BYTES = 8_192
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_NESTING_DEPTH = 6
MAX_ENTRA_EXTERNAL_ID_USER_FLOW_CONTAINERS = 32
_SHA256_HEX_LENGTH = 64


class EntraExternalIdUserFlowReadinessError(ValueError):
    """Sanitized rejection of an invalid local user-flow projection."""


class EntraExternalIdUserFlowIncludedApplication(SecurityModel):
    application_id: UUID = Field(alias="appId")

    @model_validator(mode="after")
    def validate_application_id(
        self,
    ) -> "EntraExternalIdUserFlowIncludedApplication":
        if self.application_id.int == 0:
            raise ValueError("included application identity must be nonzero")
        return self


class EntraExternalIdUserFlowApplicationsCondition(SecurityModel):
    include_all_applications: Literal[False] = Field(alias="includeAllApplications")
    include_applications: tuple[
        EntraExternalIdUserFlowIncludedApplication,
        ...,
    ] = Field(alias="includeApplications", min_length=1, max_length=1)


class EntraExternalIdUserFlowConditions(SecurityModel):
    applications: EntraExternalIdUserFlowApplicationsCondition


class EntraExternalIdUserFlowProjection(SecurityModel):
    user_flow_id: UUID = Field(alias="id")
    odata_type: Literal[
        "#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow"
    ] = Field(alias="@odata.type")
    conditions: EntraExternalIdUserFlowConditions

    @model_validator(mode="after")
    def validate_user_flow_id(self) -> "EntraExternalIdUserFlowProjection":
        if self.user_flow_id.int == 0:
            raise ValueError("user-flow identity must be nonzero")
        return self


class EntraExternalIdUserFlowDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_external_id_user_flow_calling_client_"
        "association_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "microsoft_graph_v1_0_external_users_self_service_sign_up_events_flow"
    ]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    approved_calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    user_flow: EntraExternalIdUserFlowProjection

    @model_validator(mode="after")
    def validate_digests(self) -> "EntraExternalIdUserFlowDocument":
        digests = (
            self.approved_configuration_sha256,
            self.approved_api_registration_document_sha256,
            self.approved_calling_client_registration_document_sha256,
            self.approved_inventory_document_sha256,
        )
        if any(not _is_lower_sha256(value) for value in digests):
            raise ValueError("approved digests must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraExternalIdUserFlowReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    offline_inventory_receipt_sha256: str
    desired_state_document_sha256: str
    tenant_id_sha256: str
    user_flow_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    calling_client_service_principal_object_id_sha256: str
    calling_client_service_principal_app_id_mapping_sha256: str
    user_flow_calling_client_association_sha256: str
    desired_user_flow_count: int
    desired_included_application_count: int
    configuration_bound: bool
    tenant_id_bound: bool
    api_registration_bound: bool
    calling_client_registration_bound: bool
    approved_inventory_digest_bound: bool
    canonical_user_flow_id_validated: bool
    user_flow_id_collision_separation_validated: bool
    external_users_self_service_sign_up_flow_type_validated: bool
    include_all_applications_false_validated: bool
    exact_single_included_application_validated: bool
    calling_client_application_id_bound: bool
    calling_client_service_principal_app_id_mapping_validated: bool
    application_id_used_for_association: bool
    api_application_id_not_used_for_association: bool
    application_object_id_not_used_for_association: bool
    service_principal_object_id_not_used_for_association: bool
    registration_owner_ids_not_used_as_user_flow_id: bool
    calling_client_service_principal_projection_validated: bool
    normalized_read_projection_validated: bool
    offline_desired_state_validated: bool
    ready_to_post_payload: bool
    provider_io_performed: bool
    provider_state_checked: bool
    source_authenticity_checked: bool
    user_flow_id_provider_origin_checked: bool
    provider_tenant_ownership_checked: bool
    tenant_external_status_checked: bool
    live_user_flow_checked: bool
    live_user_flow_type_checked: bool
    live_user_flow_application_association_checked: bool
    live_include_all_applications_checked: bool
    live_included_application_count_checked: bool
    live_calling_client_service_principal_checked: bool
    application_single_user_flow_uniqueness_checked: bool
    other_user_flow_associations_checked: bool
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
    graph_permission_grant_checked: bool
    operator_identity_checked: bool
    operator_role_checked: bool
    operator_authorization_checked: bool
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
            self.configuration_bound,
            self.tenant_id_bound,
            self.api_registration_bound,
            self.calling_client_registration_bound,
            self.approved_inventory_digest_bound,
            self.canonical_user_flow_id_validated,
            self.user_flow_id_collision_separation_validated,
            self.external_users_self_service_sign_up_flow_type_validated,
            self.include_all_applications_false_validated,
            self.exact_single_included_application_validated,
            self.calling_client_application_id_bound,
            self.calling_client_service_principal_app_id_mapping_validated,
            self.application_id_used_for_association,
            self.api_application_id_not_used_for_association,
            self.application_object_id_not_used_for_association,
            self.service_principal_object_id_not_used_for_association,
            self.registration_owner_ids_not_used_as_user_flow_id,
            self.calling_client_service_principal_projection_validated,
            self.normalized_read_projection_validated,
            self.offline_desired_state_validated,
        )
        deferred = (
            self.ready_to_post_payload,
            self.provider_io_performed,
            self.provider_state_checked,
            self.source_authenticity_checked,
            self.user_flow_id_provider_origin_checked,
            self.provider_tenant_ownership_checked,
            self.tenant_external_status_checked,
            self.live_user_flow_checked,
            self.live_user_flow_type_checked,
            self.live_user_flow_application_association_checked,
            self.live_include_all_applications_checked,
            self.live_included_application_count_checked,
            self.live_calling_client_service_principal_checked,
            self.application_single_user_flow_uniqueness_checked,
            self.other_user_flow_associations_checked,
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
            self.graph_permission_grant_checked,
            self.operator_identity_checked,
            self.operator_role_checked,
            self.operator_authorization_checked,
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
        if (
            self.receipt_type != ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_EXTERNAL_ID_USER_FLOW_SCHEMA_VERSION
            or self.source != ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE
            or self.validation_scope != ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or type(self.desired_user_flow_count) is not int
            or self.desired_user_flow_count != 1
            or type(self.desired_included_application_count) is not int
            or self.desired_included_application_count != 1
            or any(value is not True for value in validated)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra External ID user-flow receipt is invalid")


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


def _identity_sha256(label: str, *values: str) -> str:
    framed = ("engineer4me-step211-v1", label, str(len(values)), *values)
    material = "".join(f"{len(value)}:{value}" for value in framed).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraExternalIdUserFlowReadinessError(
                "Entra External ID user-flow document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise EntraExternalIdUserFlowReadinessError(
        "Entra External ID user-flow document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_NESTING_DEPTH:
                raise EntraExternalIdUserFlowReadinessError(
                    "Entra External ID user-flow document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_NESTING_DEPTH:
                raise EntraExternalIdUserFlowReadinessError(
                    "Entra External ID user-flow document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_CONTAINERS:
            raise EntraExternalIdUserFlowReadinessError(
                "Entra External ID user-flow document exceeds the structure limit"
            )


def _is_canonical_uuid_text(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _require_exact_scalar_inputs(parsed: dict[str, Any]) -> None:
    if set(parsed) != {
        "document_type",
        "schema_version",
        "source",
        "approved_configuration_sha256",
        "approved_api_registration_document_sha256",
        "approved_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
        "user_flow",
    }:
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document failed contract validation"
        )
    if (
        type(parsed.get("document_type")) is not str
        or type(parsed.get("schema_version")) is not int
        or type(parsed.get("source")) is not str
        or type(parsed.get("approved_configuration_sha256")) is not str
        or type(parsed.get("approved_api_registration_document_sha256")) is not str
        or type(
            parsed.get("approved_calling_client_registration_document_sha256")
        )
        is not str
        or type(parsed.get("approved_inventory_document_sha256")) is not str
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document failed contract validation"
        )
    user_flow = parsed.get("user_flow")
    if (
        not isinstance(user_flow, dict)
        or set(user_flow) != {"id", "@odata.type", "conditions"}
        or not _is_canonical_uuid_text(user_flow.get("id"))
        or type(user_flow.get("@odata.type")) is not str
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document failed contract validation"
        )
    conditions = user_flow.get("conditions")
    applications = (
        conditions.get("applications")
        if isinstance(conditions, dict) and set(conditions) == {"applications"}
        else None
    )
    included = (
        applications.get("includeApplications")
        if isinstance(applications, dict)
        else None
    )
    if (
        not isinstance(applications, dict)
        or set(applications)
        != {"includeAllApplications", "includeApplications"}
        or type(applications.get("includeAllApplications")) is not bool
        or not isinstance(included, list)
        or len(included) != 1
        or not isinstance(included[0], dict)
        or set(included[0]) != {"appId"}
        or not _is_canonical_uuid_text(included[0].get("appId"))
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document failed contract validation"
        )


def _validated_identity_projection(
    *,
    api_registration_document: bytes,
    calling_client_registration_document: bytes,
    inventory_document: bytes,
) -> tuple[dict[str, str], frozenset[str]]:
    """Recover public IDs only after the Step 207 loader has succeeded."""

    try:
        api_values = json.loads(api_registration_document.decode("utf-8"))[
            "registration"
        ]
        client_values = json.loads(
            calling_client_registration_document.decode("utf-8")
        )["registration"]
        inventory = json.loads(inventory_document.decode("utf-8"))["inventory"]
        applications = {entry["role"]: entry for entry in inventory["applications"]}
        principals = {
            entry["role"]: entry for entry in inventory["service_principals"]
        }
        identities = {
            "tenant_id": inventory["tenant_id"],
            "api_application_id": applications["api"]["application_id"],
            "api_application_object_id": applications["api"][
                "application_object_id"
            ],
            "api_service_principal_object_id": principals["api"][
                "service_principal_object_id"
            ],
            "calling_client_application_id": applications["calling_client"][
                "application_id"
            ],
            "calling_client_application_object_id": applications["calling_client"][
                "application_object_id"
            ],
            "calling_client_service_principal_object_id": principals[
                "calling_client"
            ]["service_principal_object_id"],
            "api_delegated_scope_id": api_values["delegated_scopes"][0]["scope_id"],
        }
        owners = (*api_values["owner_object_ids"], *client_values["owner_object_ids"])
    except (IndexError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraExternalIdUserFlowReadinessError(
            "approved identity projection cannot be reconstructed"
        ) from None
    all_identifiers = (*identities.values(), *owners)
    if any(not _is_canonical_uuid_text(value) for value in all_identifiers):
        raise EntraExternalIdUserFlowReadinessError(
            "approved identity projection cannot be reconstructed"
        )
    return identities, frozenset(all_identifiers)


def load_entra_external_id_user_flow_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraExternalIdUserFlowReadinessReceipt:
    """Validate one exact offline user-flow/calling-client read projection."""

    if not isinstance(document, bytes):
        raise TypeError("Entra External ID user-flow document must be bytes")
    if not isinstance(inventory_document, bytes):
        raise TypeError("approved Entra inventory document must be bytes")
    if not _is_lower_sha256(approved_inventory_document_sha256):
        raise TypeError("approved Entra inventory document digest is required")
    try:
        inventory_receipt = (
            load_entra_application_service_principal_inventory_readiness(
                document=inventory_document,
                authentication_preview=authentication_preview,
                api_registration_document=api_registration_document,
                accepted_api_registration_document_sha256=(
                    accepted_api_registration_document_sha256
                ),
                calling_client_registration_document=(
                    calling_client_registration_document
                ),
                accepted_calling_client_registration_document_sha256=(
                    accepted_calling_client_registration_document_sha256
                ),
            )
        )
    except (
        TypeError,
        ValueError,
        EntraApplicationServicePrincipalInventoryReadinessError,
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "approved offline inventory evidence is not valid"
        ) from None
    if not hmac.compare_digest(
        inventory_receipt.inventory_document_sha256,
        approved_inventory_document_sha256,
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "offline inventory does not match its approved digest"
        )

    if not document:
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document is empty"
        )
    if len(document) > MAX_ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_BYTES:
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except EntraExternalIdUserFlowReadinessError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document root must be an object"
        )
    _require_bounded_structure(parsed)
    _require_exact_scalar_inputs(parsed)
    try:
        canonical_document = _canonical_bytes(parsed)
        validated = EntraExternalIdUserFlowDocument.model_validate_json(
            canonical_document
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraExternalIdUserFlowReadinessError(
            "Entra External ID user-flow document failed contract validation"
        ) from None

    identities, collision_identifiers = _validated_identity_projection(
        api_registration_document=api_registration_document,
        calling_client_registration_document=calling_client_registration_document,
        inventory_document=inventory_document,
    )
    user_flow = validated.user_flow
    association = user_flow.conditions.applications.include_applications[0]
    user_flow_id = str(user_flow.user_flow_id)
    application_id = str(association.application_id)
    if (
        authentication_preview.token_profile != "microsoft_entra_v2"
        or authentication_preview.microsoft_entra_required_azpacr != "0"
        or not hmac.compare_digest(
            validated.approved_configuration_sha256,
            inventory_receipt.configuration_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_api_registration_document_sha256,
            inventory_receipt.api_registration_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_calling_client_registration_document_sha256,
            inventory_receipt.calling_client_registration_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_inventory_document_sha256,
            approved_inventory_document_sha256,
        )
        or application_id != identities["calling_client_application_id"]
        or application_id == identities["calling_client_application_object_id"]
        or application_id
        == identities["calling_client_service_principal_object_id"]
        or application_id == identities["api_application_id"]
        or user_flow_id in collision_identifiers
    ):
        raise EntraExternalIdUserFlowReadinessError(
            "user-flow association does not match approved identity evidence"
        )

    return EntraExternalIdUserFlowReadinessReceipt(
        receipt_type=ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE,
        schema_version=ENTRA_EXTERNAL_ID_USER_FLOW_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE,
        configuration_sha256=inventory_receipt.configuration_sha256,
        api_registration_document_sha256=(
            inventory_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            inventory_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        inventory_document_sha256=inventory_receipt.inventory_document_sha256,
        offline_inventory_receipt_sha256=hashlib.sha256(
            render_entra_application_service_principal_inventory_readiness_receipt(
                inventory_receipt
            ).encode("utf-8")
        ).hexdigest(),
        desired_state_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        tenant_id_sha256=_identity_sha256("tenant_id", identities["tenant_id"]),
        user_flow_id_sha256=_identity_sha256("user_flow_id", user_flow_id),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            application_id,
        ),
        calling_client_application_object_id_sha256=_identity_sha256(
            "calling_client_application_object_id",
            identities["calling_client_application_object_id"],
        ),
        calling_client_service_principal_object_id_sha256=_identity_sha256(
            "calling_client_service_principal_object_id",
            identities["calling_client_service_principal_object_id"],
        ),
        calling_client_service_principal_app_id_mapping_sha256=_identity_sha256(
            "calling_client_service_principal_app_id_mapping",
            identities["tenant_id"],
            application_id,
            identities["calling_client_service_principal_object_id"],
        ),
        user_flow_calling_client_association_sha256=_identity_sha256(
            "user_flow_calling_client_association",
            identities["tenant_id"],
            user_flow_id,
            user_flow.odata_type,
            "includeAllApplications=false",
            application_id,
        ),
        desired_user_flow_count=1,
        desired_included_application_count=1,
        configuration_bound=True,
        tenant_id_bound=True,
        api_registration_bound=True,
        calling_client_registration_bound=True,
        approved_inventory_digest_bound=True,
        canonical_user_flow_id_validated=True,
        user_flow_id_collision_separation_validated=True,
        external_users_self_service_sign_up_flow_type_validated=True,
        include_all_applications_false_validated=True,
        exact_single_included_application_validated=True,
        calling_client_application_id_bound=True,
        calling_client_service_principal_app_id_mapping_validated=True,
        application_id_used_for_association=True,
        api_application_id_not_used_for_association=True,
        application_object_id_not_used_for_association=True,
        service_principal_object_id_not_used_for_association=True,
        registration_owner_ids_not_used_as_user_flow_id=True,
        calling_client_service_principal_projection_validated=True,
        normalized_read_projection_validated=True,
        offline_desired_state_validated=True,
        ready_to_post_payload=False,
        provider_io_performed=False,
        provider_state_checked=False,
        source_authenticity_checked=False,
        user_flow_id_provider_origin_checked=False,
        provider_tenant_ownership_checked=False,
        tenant_external_status_checked=False,
        live_user_flow_checked=False,
        live_user_flow_type_checked=False,
        live_user_flow_application_association_checked=False,
        live_include_all_applications_checked=False,
        live_included_application_count_checked=False,
        live_calling_client_service_principal_checked=False,
        application_single_user_flow_uniqueness_checked=False,
        other_user_flow_associations_checked=False,
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
        graph_permission_grant_checked=False,
        operator_identity_checked=False,
        operator_role_checked=False,
        operator_authorization_checked=False,
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


def render_entra_external_id_user_flow_readiness_receipt(
    receipt: EntraExternalIdUserFlowReadinessReceipt,
) -> str:
    """Render canonical, privacy-minimized local projection evidence."""

    if type(receipt) is not EntraExternalIdUserFlowReadinessReceipt:
        raise TypeError("Entra External ID user-flow receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_TYPE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_ODATA_TYPE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_RECEIPT_TYPE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_SCHEMA_VERSION",
    "ENTRA_EXTERNAL_ID_USER_FLOW_SCOPE",
    "ENTRA_EXTERNAL_ID_USER_FLOW_SOURCE",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_CONTAINERS",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_DOCUMENT_BYTES",
    "MAX_ENTRA_EXTERNAL_ID_USER_FLOW_NESTING_DEPTH",
    "EntraExternalIdUserFlowReadinessError",
    "EntraExternalIdUserFlowReadinessReceipt",
    "load_entra_external_id_user_flow_readiness",
    "render_entra_external_id_user_flow_readiness_receipt",
]
