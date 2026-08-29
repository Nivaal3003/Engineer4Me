"""Offline desired-state contract for one Entra delegated admin-consent grant.

This module validates an exact normalized desired subset shaped from Microsoft
Graph ``oAuth2PermissionGrant`` against the configuration, registration
documents, and independently digest-approved Step 207 application/service-
principal inventory.  It performs no provider I/O and cannot create, update,
merge, replace, revoke, or confirm a consent grant.

Official contract references:
* https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent
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


ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_delegated_admin_consent_readiness"
)
ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_delegated_admin_consent_readiness_receipt"
)
ENTRA_DELEGATED_ADMIN_CONSENT_SCHEMA_VERSION = 1
ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE = (
    "microsoft_graph_v1_0_oauth2_permission_grant"
)
ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE = (
    "offline_exact_delegated_admin_consent_grant_desired_state_only"
)
ENTRA_DELEGATED_ADMIN_CONSENT_TYPE = "AllPrincipals"
ENTRA_DELEGATED_ADMIN_CONSENT_REQUIRED_SCOPE = "access_as_user"
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_BYTES = 8_192
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_NESTING_DEPTH = 4
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_CONTAINERS = 16
_SHA256_HEX_LENGTH = 64


class EntraDelegatedAdminConsentReadinessError(ValueError):
    """Sanitized rejection of an invalid local desired-state document."""


class EntraDelegatedAdminConsentGrant(SecurityModel):
    client_service_principal_object_id: UUID = Field(alias="clientId")
    consent_type: Literal["AllPrincipals"] = Field(alias="consentType")
    principal_id: Literal[None] = Field(alias="principalId")
    resource_service_principal_object_id: UUID = Field(alias="resourceId")
    scope: Literal["access_as_user"]

    @model_validator(mode="after")
    def validate_distinct_principals(self) -> "EntraDelegatedAdminConsentGrant":
        if (
            self.client_service_principal_object_id.int == 0
            or self.resource_service_principal_object_id.int == 0
            or self.client_service_principal_object_id
            == self.resource_service_principal_object_id
        ):
            raise ValueError("consent grant service principals must be distinct")
        return self


class EntraDelegatedAdminConsentDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_delegated_admin_consent_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["microsoft_graph_v1_0_oauth2_permission_grant"]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    approved_calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    grant: EntraDelegatedAdminConsentGrant

    @model_validator(mode="after")
    def validate_digests(self) -> "EntraDelegatedAdminConsentDocument":
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
class EntraDelegatedAdminConsentReadinessReceipt:
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
    client_service_principal_object_id_sha256: str
    resource_service_principal_object_id_sha256: str
    api_delegated_scope_id_sha256: str
    delegated_scope_value_sha256: str
    delegated_grant_relationship_sha256: str
    desired_grant_count: int
    desired_scope_count: int
    configuration_bound: bool
    api_registration_bound: bool
    calling_client_registration_bound: bool
    approved_inventory_digest_bound: bool
    client_service_principal_bound: bool
    resource_service_principal_bound: bool
    application_ids_not_used_as_principal_ids: bool
    tenant_wide_consent_type_validated: bool
    null_principal_id_validated: bool
    exact_delegated_scope_validated: bool
    single_scope_validated: bool
    normalized_oauth2_permission_grant_desired_shape_validated: bool
    provider_generated_grant_id_excluded_from_desired_state: bool
    ready_to_post_payload: bool
    offline_desired_state_validated: bool
    provider_io_performed: bool
    provider_state_checked: bool
    source_authenticity_checked: bool
    live_service_principal_inventory_checked: bool
    delegated_permission_grant_checked: bool
    exact_existing_grant_count_checked: bool
    duplicate_or_overlapping_grants_checked: bool
    admin_consent_checked: bool
    admin_consent_effectiveness_checked: bool
    consent_propagation_checked: bool
    operator_identity_checked: bool
    operator_role_checked: bool
    operator_authorization_checked: bool
    graph_permission_grant_checked: bool
    tenant_policy_checked: bool
    user_assignment_checked: bool
    user_flow_checked: bool
    conditional_access_checked: bool
    runtime_pkce_s256_checked: bool
    real_signed_token_scope_checked: bool
    grant_creation_performed: bool
    grant_update_performed: bool
    grant_deletion_performed: bool
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
            self.api_registration_bound,
            self.calling_client_registration_bound,
            self.approved_inventory_digest_bound,
            self.client_service_principal_bound,
            self.resource_service_principal_bound,
            self.application_ids_not_used_as_principal_ids,
            self.tenant_wide_consent_type_validated,
            self.null_principal_id_validated,
            self.exact_delegated_scope_validated,
            self.single_scope_validated,
            self.normalized_oauth2_permission_grant_desired_shape_validated,
            self.provider_generated_grant_id_excluded_from_desired_state,
            self.offline_desired_state_validated,
        )
        deferred = (
            self.provider_io_performed,
            self.provider_state_checked,
            self.source_authenticity_checked,
            self.live_service_principal_inventory_checked,
            self.delegated_permission_grant_checked,
            self.exact_existing_grant_count_checked,
            self.duplicate_or_overlapping_grants_checked,
            self.admin_consent_checked,
            self.admin_consent_effectiveness_checked,
            self.consent_propagation_checked,
            self.operator_identity_checked,
            self.operator_role_checked,
            self.operator_authorization_checked,
            self.graph_permission_grant_checked,
            self.tenant_policy_checked,
            self.user_assignment_checked,
            self.user_flow_checked,
            self.conditional_access_checked,
            self.runtime_pkce_s256_checked,
            self.real_signed_token_scope_checked,
            self.grant_creation_performed,
            self.grant_update_performed,
            self.grant_deletion_performed,
            self.application_mutation_performed,
            self.service_principal_mutation_performed,
            self.activation_ready,
            self.ready_to_post_payload,
        )
        if (
            self.receipt_type != ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_DELEGATED_ADMIN_CONSENT_SCHEMA_VERSION
            or self.source != ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE
            or self.validation_scope != ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or type(self.desired_grant_count) is not int
            or self.desired_grant_count != 1
            or type(self.desired_scope_count) is not int
            or self.desired_scope_count != 1
            or any(value is not True for value in validated)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra delegated admin-consent receipt is invalid")


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
    framed = ("engineer4me-step209-v1", label, str(len(values)), *values)
    material = "".join(f"{len(value)}:{value}" for value in framed).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraDelegatedAdminConsentReadinessError(
                "Entra delegated admin-consent document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise EntraDelegatedAdminConsentReadinessError(
        "Entra delegated admin-consent document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_NESTING_DEPTH:
                raise EntraDelegatedAdminConsentReadinessError(
                    "Entra delegated admin-consent document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_NESTING_DEPTH:
                raise EntraDelegatedAdminConsentReadinessError(
                    "Entra delegated admin-consent document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_CONTAINERS:
            raise EntraDelegatedAdminConsentReadinessError(
                "Entra delegated admin-consent document exceeds the structure limit"
            )


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _require_exact_scalar_inputs(parsed: dict[str, Any]) -> None:
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
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document failed contract validation"
        )
    grant = parsed.get("grant")
    if (
        not isinstance(grant, dict)
        or not _canonical_uuid(grant.get("clientId"))
        or not _canonical_uuid(grant.get("resourceId"))
        or type(grant.get("consentType")) is not str
        or "principalId" not in grant
        or grant["principalId"] is not None
        or type(grant.get("scope")) is not str
    ):
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document failed contract validation"
        )


def _inventory_identities(document: bytes) -> dict[str, str]:
    """Recover public identities only after the strict Step 207 load succeeds."""

    try:
        parsed = json.loads(document.decode("utf-8"))
        inventory = parsed["inventory"]
        applications = {entry["role"]: entry for entry in inventory["applications"]}
        principals = {
            entry["role"]: entry for entry in inventory["service_principals"]
        }
        return {
            "tenant_id": inventory["tenant_id"],
            "api_application_id": applications["api"]["application_id"],
            "calling_client_application_id": applications["calling_client"][
                "application_id"
            ],
            "api_service_principal_object_id": principals["api"][
                "service_principal_object_id"
            ],
            "calling_client_service_principal_object_id": principals[
                "calling_client"
            ]["service_principal_object_id"],
        }
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraDelegatedAdminConsentReadinessError(
            "approved inventory identities cannot be reconstructed"
        ) from None


def _api_scope_id(document: bytes) -> str:
    """Recover the approved API scope identity after strict prerequisites load."""

    try:
        parsed = json.loads(document.decode("utf-8"))
        value = parsed["registration"]["delegated_scopes"][0]["scope_id"]
    except (KeyError, IndexError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraDelegatedAdminConsentReadinessError(
            "approved API scope identity cannot be reconstructed"
        ) from None
    if not _canonical_uuid(value):
        raise EntraDelegatedAdminConsentReadinessError(
            "approved API scope identity cannot be reconstructed"
        )
    return value


def load_entra_delegated_admin_consent_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraDelegatedAdminConsentReadinessReceipt:
    """Validate one exact offline tenant-wide delegated grant desired state."""

    if not isinstance(document, bytes):
        raise TypeError("Entra delegated admin-consent document must be bytes")
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
        raise EntraDelegatedAdminConsentReadinessError(
            "approved offline inventory evidence is not valid"
        ) from None
    if not hmac.compare_digest(
        inventory_receipt.inventory_document_sha256,
        approved_inventory_document_sha256,
    ):
        raise EntraDelegatedAdminConsentReadinessError(
            "offline inventory does not match its approved digest"
        )

    if not document:
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document is empty"
        )
    if len(document) > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_BYTES:
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except EntraDelegatedAdminConsentReadinessError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document root must be an object"
        )
    _require_bounded_structure(parsed)
    _require_exact_scalar_inputs(parsed)
    try:
        canonical_document = _canonical_bytes(parsed)
        validated = EntraDelegatedAdminConsentDocument.model_validate_json(
            canonical_document
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraDelegatedAdminConsentReadinessError(
            "Entra delegated admin-consent document failed contract validation"
        ) from None

    identities = _inventory_identities(inventory_document)
    grant = validated.grant
    scope_id = _api_scope_id(api_registration_document)
    client_id = str(grant.client_service_principal_object_id)
    resource_id = str(grant.resource_service_principal_object_id)
    if (
        authentication_preview.token_profile != "microsoft_entra_v2"
        or authentication_preview.microsoft_entra_required_delegated_scope
        != ENTRA_DELEGATED_ADMIN_CONSENT_REQUIRED_SCOPE
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
        or client_id
        != identities["calling_client_service_principal_object_id"]
        or resource_id != identities["api_service_principal_object_id"]
        or client_id == identities["calling_client_application_id"]
        or resource_id == identities["api_application_id"]
    ):
        raise EntraDelegatedAdminConsentReadinessError(
            "delegated admin-consent desired state does not match approved evidence"
        )

    return EntraDelegatedAdminConsentReadinessReceipt(
        receipt_type=ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE,
        schema_version=ENTRA_DELEGATED_ADMIN_CONSENT_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE,
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
        client_service_principal_object_id_sha256=_identity_sha256(
            "client_service_principal_object_id",
            client_id,
        ),
        resource_service_principal_object_id_sha256=_identity_sha256(
            "resource_service_principal_object_id",
            resource_id,
        ),
        api_delegated_scope_id_sha256=_identity_sha256(
            "api_delegated_scope_id",
            scope_id,
        ),
        delegated_scope_value_sha256=_identity_sha256(
            "delegated_scope_value",
            grant.scope,
        ),
        delegated_grant_relationship_sha256=_identity_sha256(
            "delegated_grant_relationship",
            identities["tenant_id"],
            client_id,
            resource_id,
            grant.consent_type,
            "null",
            grant.scope,
        ),
        desired_grant_count=1,
        desired_scope_count=1,
        configuration_bound=True,
        api_registration_bound=True,
        calling_client_registration_bound=True,
        approved_inventory_digest_bound=True,
        client_service_principal_bound=True,
        resource_service_principal_bound=True,
        application_ids_not_used_as_principal_ids=True,
        tenant_wide_consent_type_validated=True,
        null_principal_id_validated=True,
        exact_delegated_scope_validated=True,
        single_scope_validated=True,
        normalized_oauth2_permission_grant_desired_shape_validated=True,
        provider_generated_grant_id_excluded_from_desired_state=True,
        ready_to_post_payload=False,
        offline_desired_state_validated=True,
        provider_io_performed=False,
        provider_state_checked=False,
        source_authenticity_checked=False,
        live_service_principal_inventory_checked=False,
        delegated_permission_grant_checked=False,
        exact_existing_grant_count_checked=False,
        duplicate_or_overlapping_grants_checked=False,
        admin_consent_checked=False,
        admin_consent_effectiveness_checked=False,
        consent_propagation_checked=False,
        operator_identity_checked=False,
        operator_role_checked=False,
        operator_authorization_checked=False,
        graph_permission_grant_checked=False,
        tenant_policy_checked=False,
        user_assignment_checked=False,
        user_flow_checked=False,
        conditional_access_checked=False,
        runtime_pkce_s256_checked=False,
        real_signed_token_scope_checked=False,
        grant_creation_performed=False,
        grant_update_performed=False,
        grant_deletion_performed=False,
        application_mutation_performed=False,
        service_principal_mutation_performed=False,
        activation_ready=False,
    )


def render_entra_delegated_admin_consent_readiness_receipt(
    receipt: EntraDelegatedAdminConsentReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized desired-state evidence."""

    if type(receipt) is not EntraDelegatedAdminConsentReadinessReceipt:
        raise TypeError("Entra delegated admin-consent receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_TYPE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_RECEIPT_TYPE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_REQUIRED_SCOPE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_SCHEMA_VERSION",
    "ENTRA_DELEGATED_ADMIN_CONSENT_SCOPE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_SOURCE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_TYPE",
    "MAX_ENTRA_DELEGATED_ADMIN_CONSENT_DOCUMENT_BYTES",
    "EntraDelegatedAdminConsentReadinessError",
    "EntraDelegatedAdminConsentReadinessReceipt",
    "load_entra_delegated_admin_consent_readiness",
    "render_entra_delegated_admin_consent_readiness_receipt",
]
