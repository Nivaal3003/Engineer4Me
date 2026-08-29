"""Offline Entra application and service-principal inventory projection.

The contract is deliberately pure and fail closed.  It validates one strict
caller-supplied projection against already reviewed Engineer4Me registration
documents.  It does not read files or environment variables, contact Microsoft
Graph, inspect a tenant, open a database session, mutate provider resources, or
turn local input into live-provider evidence.
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

from app.security.authentication_entra_api_registration_readiness import (
    entra_api_registration_receipt_matches_identity,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    entra_calling_client_registration_receipt_matches_identity,
    load_entra_calling_client_registration_readiness,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    render_authentication_readiness_preview,
)
from app.security.identity_models import SecurityModel


ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_application_service_principal_inventory_readiness"
)
ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE = "engineer4me_microsoft_entra_application_service_principal_inventory_readiness_receipt"
ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCHEMA_VERSION = 1
ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCOPE = (
    "offline_identity_inventory_projection_only"
)
ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE = "microsoft_graph_v1_0"
MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_BYTES = 16_384
MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_NESTING_DEPTH = 8
MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_CONTAINERS = 128
_SHA256_HEX_LENGTH = 64


class EntraApplicationServicePrincipalInventoryReadinessError(ValueError):
    """Sanitized rejection of an untrusted local inventory projection."""


class EntraApplicationInventoryEntry(SecurityModel):
    role: Literal["api", "calling_client"]
    application_id: UUID
    application_object_id: UUID


class EntraServicePrincipalInventoryEntry(SecurityModel):
    role: Literal["api", "calling_client"]
    service_principal_object_id: UUID
    application_id: UUID
    application_owner_organization_id: UUID
    service_principal_type: Literal["Application"]
    account_enabled: Literal[True]
    disabled_by_microsoft_status: Literal[None, "NotDisabled"]


class EntraApplicationServicePrincipalInventory(SecurityModel):
    tenant_id: UUID
    applications: tuple[EntraApplicationInventoryEntry, ...] = Field(
        min_length=2,
        max_length=2,
    )
    service_principals: tuple[EntraServicePrincipalInventoryEntry, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @model_validator(mode="after")
    def validate_inventory(self) -> "EntraApplicationServicePrincipalInventory":
        expected_roles = ("api", "calling_client")
        if tuple(entry.role for entry in self.applications) != expected_roles:
            raise ValueError("application inventory roles must be canonical")
        if tuple(entry.role for entry in self.service_principals) != expected_roles:
            raise ValueError("service-principal inventory roles must be canonical")

        application_ids = {
            entry.role: entry.application_id for entry in self.applications
        }
        for entry in self.service_principals:
            if (
                entry.application_id != application_ids[entry.role]
                or entry.application_owner_organization_id != self.tenant_id
            ):
                raise ValueError(
                    "service-principal inventory must match its application and tenant"
                )

        identifiers = (
            self.tenant_id,
            *(entry.application_id for entry in self.applications),
            *(entry.application_object_id for entry in self.applications),
            *(entry.service_principal_object_id for entry in self.service_principals),
        )
        if any(value.int == 0 for value in identifiers):
            raise ValueError("inventory identifiers must be nonzero")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("inventory identifiers must be distinct")
        return self


class EntraApplicationServicePrincipalInventoryDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_application_service_principal_inventory_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["microsoft_graph_v1_0"]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    approved_calling_client_registration_document_sha256: str
    inventory: EntraApplicationServicePrincipalInventory

    @model_validator(mode="after")
    def validate_digests(
        self,
    ) -> "EntraApplicationServicePrincipalInventoryDocument":
        digests = (
            self.approved_configuration_sha256,
            self.approved_api_registration_document_sha256,
            self.approved_calling_client_registration_document_sha256,
        )
        if any(not _is_lower_sha256(value) for value in digests):
            raise ValueError("approved digests must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraApplicationServicePrincipalInventoryReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    inventory_document_sha256: str
    tenant_id_sha256: str
    api_application_id_sha256: str
    api_application_object_id_sha256: str
    api_delegated_scope_id_sha256: str
    api_service_principal_object_id_sha256: str
    api_application_service_principal_relationship_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    calling_client_service_principal_object_id_sha256: str
    calling_client_application_service_principal_relationship_sha256: str
    application_count: int
    service_principal_count: int
    enabled_service_principal_count: int
    not_disabled_service_principal_count: int
    configuration_bound: bool
    api_registration_bound: bool
    calling_client_registration_bound: bool
    application_identity_projection_validated: bool
    service_principal_identity_projection_validated: bool
    application_service_principal_relationships_validated: bool
    tenant_ownership_projection_validated: bool
    service_principal_type_projection_validated: bool
    account_enabled_projection_validated: bool
    microsoft_disablement_projection_validated: bool
    local_projection_validated: bool
    provider_io_performed: bool
    provider_state_checked: bool
    live_inventory_checked: bool
    source_authenticity_checked: bool
    provider_ownership_checked: bool
    owner_tenant_membership_checked: bool
    tenant_external_status_checked: bool
    application_credential_inventory_checked: bool
    service_principal_credential_inventory_checked: bool
    service_principal_assignment_required_checked: bool
    service_principal_lock_checked: bool
    claims_policy_assignments_checked: bool
    delegated_permission_grant_checked: bool
    admin_consent_checked: bool
    user_flow_checked: bool
    conditional_access_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_azpacr_public_client_checked: bool
    real_signed_token_checked: bool
    redirect_endpoint_ownership_checked: bool
    redirect_tls_checked: bool
    open_redirect_behavior_checked: bool
    application_creation_performed: bool
    service_principal_creation_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = (
            self.configuration_sha256,
            self.api_registration_document_sha256,
            self.calling_client_registration_document_sha256,
            self.inventory_document_sha256,
            self.tenant_id_sha256,
            self.api_application_id_sha256,
            self.api_application_object_id_sha256,
            self.api_delegated_scope_id_sha256,
            self.api_service_principal_object_id_sha256,
            self.api_application_service_principal_relationship_sha256,
            self.calling_client_application_id_sha256,
            self.calling_client_application_object_id_sha256,
            self.calling_client_service_principal_object_id_sha256,
            self.calling_client_application_service_principal_relationship_sha256,
        )
        validated_flags = (
            self.configuration_bound,
            self.api_registration_bound,
            self.calling_client_registration_bound,
            self.application_identity_projection_validated,
            self.service_principal_identity_projection_validated,
            self.application_service_principal_relationships_validated,
            self.tenant_ownership_projection_validated,
            self.service_principal_type_projection_validated,
            self.account_enabled_projection_validated,
            self.microsoft_disablement_projection_validated,
            self.local_projection_validated,
        )
        deferred_flags = (
            self.provider_io_performed,
            self.provider_state_checked,
            self.live_inventory_checked,
            self.source_authenticity_checked,
            self.provider_ownership_checked,
            self.owner_tenant_membership_checked,
            self.tenant_external_status_checked,
            self.application_credential_inventory_checked,
            self.service_principal_credential_inventory_checked,
            self.service_principal_assignment_required_checked,
            self.service_principal_lock_checked,
            self.claims_policy_assignments_checked,
            self.delegated_permission_grant_checked,
            self.admin_consent_checked,
            self.user_flow_checked,
            self.conditional_access_checked,
            self.runtime_pkce_s256_checked,
            self.runtime_azpacr_public_client_checked,
            self.real_signed_token_checked,
            self.redirect_endpoint_ownership_checked,
            self.redirect_tls_checked,
            self.open_redirect_behavior_checked,
            self.application_creation_performed,
            self.service_principal_creation_performed,
            self.activation_ready,
        )
        if (
            self.receipt_type
            != ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCHEMA_VERSION
            or self.source != ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE
            or any(not _is_lower_sha256(value) for value in digests)
            or type(self.application_count) is not int
            or self.application_count != 2
            or type(self.service_principal_count) is not int
            or self.service_principal_count != 2
            or type(self.enabled_service_principal_count) is not int
            or self.enabled_service_principal_count != 2
            or type(self.not_disabled_service_principal_count) is not int
            or self.not_disabled_service_principal_count != 2
            or any(value is not True for value in validated_flags)
            or any(value is not False for value in deferred_flags)
        ):
            raise ValueError(
                "Entra application/service-principal inventory receipt is invalid"
            )


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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraApplicationServicePrincipalInventoryReadinessError(
                "Entra inventory document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise EntraApplicationServicePrincipalInventoryReadinessError(
        "Entra inventory document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document contains a non-finite number"
        )
    return parsed


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_NESTING_DEPTH:
                raise EntraApplicationServicePrincipalInventoryReadinessError(
                    "Entra inventory document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_NESTING_DEPTH:
                raise EntraApplicationServicePrincipalInventoryReadinessError(
                    "Entra inventory document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_CONTAINERS:
            raise EntraApplicationServicePrincipalInventoryReadinessError(
                "Entra inventory document exceeds the structure limit"
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
    if (
        type(parsed.get("document_type")) is not str
        or type(parsed.get("schema_version")) is not int
        or type(parsed.get("source")) is not str
        or type(parsed.get("approved_configuration_sha256")) is not str
        or type(parsed.get("approved_api_registration_document_sha256")) is not str
        or type(parsed.get("approved_calling_client_registration_document_sha256"))
        is not str
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document failed contract validation"
        )
    inventory = parsed.get("inventory")
    if not isinstance(inventory, dict):
        return
    if not _is_canonical_uuid_text(inventory.get("tenant_id")):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document failed contract validation"
        )
    applications = inventory.get("applications")
    service_principals = inventory.get("service_principals")
    if not isinstance(applications, list) or any(
        not isinstance(entry, dict)
        or not _is_canonical_uuid_text(entry.get("application_id"))
        or not _is_canonical_uuid_text(entry.get("application_object_id"))
        for entry in applications
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document failed contract validation"
        )
    if not isinstance(service_principals, list) or any(
        not isinstance(entry, dict)
        or not _is_canonical_uuid_text(entry.get("service_principal_object_id"))
        or not _is_canonical_uuid_text(entry.get("application_id"))
        or not _is_canonical_uuid_text(entry.get("application_owner_organization_id"))
        or type(entry.get("account_enabled")) is not bool
        or (
            entry.get("disabled_by_microsoft_status") is not None
            and type(entry.get("disabled_by_microsoft_status")) is not str
        )
        for entry in service_principals
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document failed contract validation"
        )


def _identity_sha256(label: str, *values: str) -> str:
    framed = ("engineer4me-step207-v1", label, str(len(values)), *values)
    material = "".join(f"{len(value)}:{value}" for value in framed).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def load_entra_application_service_principal_inventory_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
) -> EntraApplicationServicePrincipalInventoryReadinessReceipt:
    """Bind one local identity projection to accepted registration evidence."""

    if not isinstance(document, bytes):
        raise TypeError("Entra inventory document must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication readiness preview is required")
    if not isinstance(api_registration_document, bytes):
        raise TypeError("accepted Entra API registration document must be bytes")
    if not isinstance(calling_client_registration_document, bytes):
        raise TypeError("accepted Entra calling-client document must be bytes")
    if not _is_lower_sha256(accepted_api_registration_document_sha256):
        raise TypeError("accepted Entra API registration digest is required")
    if not _is_lower_sha256(accepted_calling_client_registration_document_sha256):
        raise TypeError("accepted Entra calling-client digest is required")
    try:
        render_authentication_readiness_preview(authentication_preview)
    except (TypeError, ValueError):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "prerequisite readiness evidence is not locally validated"
        ) from None
    try:
        api_receipt = load_entra_api_registration_readiness(
            document=api_registration_document,
            authentication_preview=authentication_preview,
        )
        client_receipt = load_entra_calling_client_registration_readiness(
            document=calling_client_registration_document,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
        )
    except (TypeError, ValueError):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "accepted registration evidence is not locally validated"
        ) from None
    if not hmac.compare_digest(
        api_receipt.registration_document_sha256,
        accepted_api_registration_document_sha256,
    ) or not hmac.compare_digest(
        client_receipt.client_registration_document_sha256,
        accepted_calling_client_registration_document_sha256,
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "registration documents do not match their accepted digests"
        )
    if not document:
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document is empty"
        )
    if len(document) > MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_BYTES:
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except EntraApplicationServicePrincipalInventoryReadinessError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document root must be an object"
        )
    _require_bounded_structure(parsed)
    _require_exact_scalar_inputs(parsed)
    try:
        canonical_document = _canonical_bytes(parsed)
        validated = (
            EntraApplicationServicePrincipalInventoryDocument.model_validate_json(
                canonical_document
            )
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory document failed contract validation"
        ) from None

    inventory = validated.inventory
    applications = {entry.role: entry for entry in inventory.applications}
    principals = {entry.role: entry for entry in inventory.service_principals}
    api_application = applications["api"]
    client_application = applications["calling_client"]
    api_principal = principals["api"]
    client_principal = principals["calling_client"]
    if (
        authentication_preview.token_profile != "microsoft_entra_v2"
        or authentication_preview.microsoft_entra_tenant_id is None
        or authentication_preview.microsoft_entra_api_application_id is None
        or authentication_preview.microsoft_entra_calling_client_application_id is None
        or authentication_preview.microsoft_entra_required_delegated_scope
        != "access_as_user"
        or authentication_preview.microsoft_entra_required_azpacr != "0"
        or not hmac.compare_digest(
            validated.approved_configuration_sha256,
            authentication_preview.configuration_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_api_registration_document_sha256,
            accepted_api_registration_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_calling_client_registration_document_sha256,
            accepted_calling_client_registration_document_sha256,
        )
        or str(inventory.tenant_id) != authentication_preview.microsoft_entra_tenant_id
        or str(api_application.application_id)
        != authentication_preview.microsoft_entra_api_application_id
        or str(client_application.application_id)
        != authentication_preview.microsoft_entra_calling_client_application_id
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory does not match authentication readiness"
        )

    api_scope_id = _api_delegated_scope_id(api_registration_document)
    registration_owner_ids = _registration_owner_ids(
        api_registration_document,
        calling_client_registration_document,
    )
    projected_identifiers = (
        inventory.tenant_id,
        api_application.application_id,
        api_application.application_object_id,
        api_principal.service_principal_object_id,
        client_application.application_id,
        client_application.application_object_id,
        client_principal.service_principal_object_id,
    )
    if (
        api_scope_id is None
        or registration_owner_ids is None
        or api_scope_id in projected_identifiers
        or any(
            owner_id == api_scope_id or owner_id in projected_identifiers
            for owner_id in registration_owner_ids
        )
        or not entra_api_registration_receipt_matches_identity(
            api_receipt,
            tenant_id=inventory.tenant_id,
            api_application_id=api_application.application_id,
            api_application_object_id=api_application.application_object_id,
            delegated_scope_id=api_scope_id,
        )
        or not entra_calling_client_registration_receipt_matches_identity(
            client_receipt,
            tenant_id=inventory.tenant_id,
            api_application_id=api_application.application_id,
            api_application_object_id=api_application.application_object_id,
            api_delegated_scope_id=api_scope_id,
            calling_client_application_id=client_application.application_id,
            calling_client_application_object_id=(
                client_application.application_object_id
            ),
        )
    ):
        raise EntraApplicationServicePrincipalInventoryReadinessError(
            "Entra inventory identities do not match registration evidence"
        )

    return EntraApplicationServicePrincipalInventoryReadinessReceipt(
        receipt_type=(ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE),
        schema_version=(ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCHEMA_VERSION),
        source=validated.source,
        configuration_sha256=authentication_preview.configuration_sha256,
        api_registration_document_sha256=(api_receipt.registration_document_sha256),
        calling_client_registration_document_sha256=(
            client_receipt.client_registration_document_sha256
        ),
        inventory_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        tenant_id_sha256=_identity_sha256("tenant_id", str(inventory.tenant_id)),
        api_application_id_sha256=_identity_sha256(
            "api_application_id", str(api_application.application_id)
        ),
        api_application_object_id_sha256=_identity_sha256(
            "api_application_object_id", str(api_application.application_object_id)
        ),
        api_delegated_scope_id_sha256=_identity_sha256(
            "api_delegated_scope_id",
            str(api_scope_id),
        ),
        api_service_principal_object_id_sha256=_identity_sha256(
            "api_service_principal_object_id",
            str(api_principal.service_principal_object_id),
        ),
        api_application_service_principal_relationship_sha256=_identity_sha256(
            "api_application_service_principal_relationship",
            str(inventory.tenant_id),
            str(api_application.application_id),
            str(api_application.application_object_id),
            str(api_principal.service_principal_object_id),
        ),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            str(client_application.application_id),
        ),
        calling_client_application_object_id_sha256=_identity_sha256(
            "calling_client_application_object_id",
            str(client_application.application_object_id),
        ),
        calling_client_service_principal_object_id_sha256=_identity_sha256(
            "calling_client_service_principal_object_id",
            str(client_principal.service_principal_object_id),
        ),
        calling_client_application_service_principal_relationship_sha256=(
            _identity_sha256(
                "calling_client_application_service_principal_relationship",
                str(inventory.tenant_id),
                str(client_application.application_id),
                str(client_application.application_object_id),
                str(client_principal.service_principal_object_id),
            )
        ),
        application_count=2,
        service_principal_count=2,
        enabled_service_principal_count=2,
        not_disabled_service_principal_count=2,
        configuration_bound=True,
        api_registration_bound=True,
        calling_client_registration_bound=True,
        application_identity_projection_validated=True,
        service_principal_identity_projection_validated=True,
        application_service_principal_relationships_validated=True,
        tenant_ownership_projection_validated=True,
        service_principal_type_projection_validated=True,
        account_enabled_projection_validated=True,
        microsoft_disablement_projection_validated=True,
        local_projection_validated=True,
        provider_io_performed=False,
        provider_state_checked=False,
        live_inventory_checked=False,
        source_authenticity_checked=False,
        provider_ownership_checked=False,
        owner_tenant_membership_checked=False,
        tenant_external_status_checked=False,
        application_credential_inventory_checked=False,
        service_principal_credential_inventory_checked=False,
        service_principal_assignment_required_checked=False,
        service_principal_lock_checked=False,
        claims_policy_assignments_checked=False,
        delegated_permission_grant_checked=False,
        admin_consent_checked=False,
        user_flow_checked=False,
        conditional_access_checked=False,
        runtime_pkce_s256_checked=False,
        runtime_azpacr_public_client_checked=False,
        real_signed_token_checked=False,
        redirect_endpoint_ownership_checked=False,
        redirect_tls_checked=False,
        open_redirect_behavior_checked=False,
        application_creation_performed=False,
        service_principal_creation_performed=False,
        activation_ready=False,
    )


def _api_delegated_scope_id(document: bytes) -> UUID | None:
    """Recover a public prerequisite identity after its strict loader succeeds."""

    try:
        parsed = json.loads(document.decode("utf-8"))
        value = parsed["registration"]["delegated_scopes"][0]["scope_id"]
    except (KeyError, IndexError, TypeError, UnicodeDecodeError, ValueError):
        return None
    if not _is_canonical_uuid_text(value):
        return None
    return UUID(value)


def _registration_owner_ids(*documents: bytes) -> frozenset[UUID] | None:
    """Recover owner identities only after both strict prerequisite loads."""

    owners: set[UUID] = set()
    for document in documents:
        try:
            parsed = json.loads(document.decode("utf-8"))
            values = parsed["registration"]["owner_object_ids"]
        except (KeyError, TypeError, UnicodeDecodeError, ValueError):
            return None
        if not isinstance(values, list) or not values or any(
            not _is_canonical_uuid_text(value) for value in values
        ):
            return None
        owners.update(UUID(value) for value in values)
    return frozenset(owners)


def render_entra_application_service_principal_inventory_readiness_receipt(
    receipt: EntraApplicationServicePrincipalInventoryReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized local projection evidence."""

    if type(receipt) is not EntraApplicationServicePrincipalInventoryReadinessReceipt:
        raise TypeError("Entra application/service-principal receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__}
        | {"validation_scope": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCOPE},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE",
    "ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_RECEIPT_TYPE",
    "ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCHEMA_VERSION",
    "ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SCOPE",
    "ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE",
    "MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_BYTES",
    "MAX_ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_NESTING_DEPTH",
    "EntraApplicationServicePrincipalInventoryReadinessError",
    "EntraApplicationServicePrincipalInventoryReadinessReceipt",
    "load_entra_application_service_principal_inventory_readiness",
    "render_entra_application_service_principal_inventory_readiness_receipt",
]
