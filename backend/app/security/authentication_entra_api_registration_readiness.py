"""Offline desired-state contract for one Microsoft Entra External ID API app.

The contract validates explicit public registration metadata only. It does not
read files or environment variables, call Microsoft Graph, contact a provider,
open a database session, mutate an application, or establish live readiness.
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

from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    render_authentication_readiness_preview,
)
from app.security.identity_models import SecurityModel


ENTRA_API_REGISTRATION_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_api_registration_readiness"
)
ENTRA_API_REGISTRATION_SCHEMA_VERSION = 1
ENTRA_API_REGISTRATION_SCOPE = "offline_desired_state_only"
ENTRA_API_REGISTRATION_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_api_registration_readiness_receipt"
)
MAX_ENTRA_API_REGISTRATION_DOCUMENT_BYTES = 16_384
MAX_ENTRA_API_REGISTRATION_NESTING_DEPTH = 8
MAX_ENTRA_API_REGISTRATION_CONTAINERS = 256
_SHA256_HEX_LENGTH = 64


class EntraAPIRegistrationReadinessError(ValueError):
    """Sanitized rejection of untrusted registration desired state."""


class EntraDelegatedScope(SecurityModel):
    scope_id: UUID
    value: Literal["access_as_user"]
    consent: Literal["admins_only"]
    enabled: Literal[True]
    admin_consent_display_name: Literal[
        "Access Engineer4Me as the signed-in user"
    ]
    admin_consent_description: Literal[
        "Allow this application to access Engineer4Me as the signed-in user."
    ]
    user_consent_display_name: None
    user_consent_description: None


class EntraAPIRegistration(SecurityModel):
    tenant_id: UUID
    api_application_id: UUID
    application_object_id: UUID
    display_name: Literal["Engineer4Me API"]
    description: None
    notes: None
    marketing_url: None
    privacy_statement_url: None
    support_url: None
    terms_of_service_url: None
    logo_configured: Literal[False]
    owner_object_ids: tuple[UUID, ...] = Field(min_length=1, max_length=5)
    sign_in_audience: Literal["AzureADMyOrg"]
    requested_access_token_version: Literal[2]
    accept_mapped_claims: Literal[False]
    identifier_uris: tuple[str, ...] = Field(min_length=1, max_length=1)
    delegated_scopes: tuple[EntraDelegatedScope, ...] = Field(
        min_length=1,
        max_length=1,
    )
    web_redirect_uris: tuple[str, ...] = Field(max_length=0)
    spa_redirect_uris: tuple[str, ...] = Field(max_length=0)
    public_client_redirect_uris: tuple[str, ...] = Field(max_length=0)
    implicit_access_token_enabled: Literal[False]
    implicit_id_token_enabled: Literal[False]
    public_client_fallback_enabled: Literal[False]
    password_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    key_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    federated_identity_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    app_role_ids: tuple[UUID, ...] = Field(max_length=0)
    preauthorized_client_application_ids: tuple[UUID, ...] = Field(max_length=0)
    known_client_application_ids: tuple[UUID, ...] = Field(max_length=0)
    required_resource_application_ids: tuple[UUID, ...] = Field(max_length=0)
    optional_claims_configured: Literal[False]
    group_membership_claims_configured: Literal[False]
    token_encryption_key_configured: Literal[False]
    add_in_ids: tuple[UUID, ...] = Field(max_length=0)
    home_page_url: None
    logout_url: None

    @model_validator(mode="after")
    def validate_registration(self) -> "EntraAPIRegistration":
        expected_identifier_uri = f"api://{self.api_application_id}"
        if self.identifier_uris != (expected_identifier_uri,):
            raise ValueError("API identifier URI must match the application ID")
        owner_ids = tuple(self.owner_object_ids)
        if len(owner_ids) != len(set(owner_ids)):
            raise ValueError("owner object IDs must be unique")
        if owner_ids != tuple(sorted(owner_ids, key=str)):
            raise ValueError("owner object IDs must be sorted")
        all_ids = (
            self.tenant_id,
            self.api_application_id,
            self.application_object_id,
            self.delegated_scopes[0].scope_id,
            *owner_ids,
        )
        if any(value.int == 0 for value in all_ids):
            raise ValueError("registration identifiers must be nonzero")
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("registration identifiers must be distinct")
        return self


class EntraAPIRegistrationDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_api_registration_readiness"
    ]
    schema_version: Literal[1]
    approved_configuration_sha256: str
    registration: EntraAPIRegistration

    @model_validator(mode="after")
    def validate_digest(self) -> "EntraAPIRegistrationDocument":
        value = self.approved_configuration_sha256
        if (
            type(value) is not str
            or len(value) != _SHA256_HEX_LENGTH
            or value != value.lower()
        ):
            raise ValueError("configuration digest must be lowercase SHA-256")
        try:
            int(value, 16)
        except ValueError:
            raise ValueError("configuration digest must be lowercase SHA-256") from None
        return self


@dataclass(frozen=True, slots=True)
class EntraAPIRegistrationReadinessReceipt:
    receipt_type: str
    schema_version: int
    configuration_sha256: str
    registration_document_sha256: str
    tenant_id_sha256: str
    api_application_id_sha256: str
    application_object_id_sha256: str
    display_name_sha256: str
    owner_object_ids_sha256: str
    owner_count: int
    delegated_scope_id_sha256: str
    identifier_uri_sha256: str
    sign_in_audience: str
    requested_access_token_version: int
    delegated_scope_value: str
    delegated_scope_consent: str
    delegated_scope_enabled: bool
    accept_mapped_claims: bool
    desired_redirect_uri_count: int
    desired_password_key_credential_count: int
    desired_federated_identity_credential_count: int
    desired_app_role_count: int
    desired_preauthorized_client_count: int
    desired_known_client_count: int
    desired_required_resource_count: int
    desired_optional_claims_configured: bool
    desired_group_membership_claims_configured: bool
    desired_token_encryption_key_configured: bool
    desired_add_in_count: int
    configuration_bound: bool
    provider_state_checked: bool
    live_registration_checked: bool
    live_application_exists_checked: bool
    admin_consent_checked: bool
    calling_client_registration_checked: bool
    user_flow_checked: bool
    runtime_scope_enforcement: bool
    delegated_token_enforcement: bool
    roleless_app_token_rejection: bool
    calling_client_identity_checked: bool
    azp_checked: bool
    service_principal_checked: bool
    service_principal_assignment_required_checked: bool
    service_principal_lock_checked: bool
    claims_policy_assignments_checked: bool
    provider_ownership_checked: bool
    owner_tenant_membership_checked: bool
    application_creation_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = (
            self.configuration_sha256,
            self.registration_document_sha256,
            self.tenant_id_sha256,
            self.api_application_id_sha256,
            self.application_object_id_sha256,
            self.display_name_sha256,
            self.owner_object_ids_sha256,
            self.delegated_scope_id_sha256,
            self.identifier_uri_sha256,
        )
        if (
            self.receipt_type != ENTRA_API_REGISTRATION_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_API_REGISTRATION_SCHEMA_VERSION
            or any(
                type(value) is not str
                or len(value) != _SHA256_HEX_LENGTH
                or value != value.lower()
                for value in digests
            )
            or any(not _is_hex_digest(value) for value in digests)
            or self.sign_in_audience != "AzureADMyOrg"
            or type(self.requested_access_token_version) is not int
            or self.requested_access_token_version != 2
            or self.delegated_scope_value != "access_as_user"
            or self.delegated_scope_consent != "admins_only"
            or self.delegated_scope_enabled is not True
            or self.accept_mapped_claims is not False
            or type(self.owner_count) is not int
            or self.owner_count < 1
            or self.owner_count > 5
            or type(self.desired_redirect_uri_count) is not int
            or self.desired_redirect_uri_count != 0
            or type(self.desired_password_key_credential_count) is not int
            or self.desired_password_key_credential_count != 0
            or type(self.desired_federated_identity_credential_count) is not int
            or self.desired_federated_identity_credential_count != 0
            or type(self.desired_app_role_count) is not int
            or self.desired_app_role_count != 0
            or type(self.desired_preauthorized_client_count) is not int
            or self.desired_preauthorized_client_count != 0
            or type(self.desired_known_client_count) is not int
            or self.desired_known_client_count != 0
            or type(self.desired_required_resource_count) is not int
            or self.desired_required_resource_count != 0
            or self.desired_optional_claims_configured is not False
            or self.desired_group_membership_claims_configured is not False
            or self.desired_token_encryption_key_configured is not False
            or type(self.desired_add_in_count) is not int
            or self.desired_add_in_count != 0
            or self.configuration_bound is not True
            or self.provider_state_checked is not False
            or self.live_registration_checked is not False
            or self.live_application_exists_checked is not False
            or self.admin_consent_checked is not False
            or self.calling_client_registration_checked is not False
            or self.user_flow_checked is not False
            or self.runtime_scope_enforcement is not False
            or self.delegated_token_enforcement is not False
            or self.roleless_app_token_rejection is not False
            or self.calling_client_identity_checked is not False
            or self.azp_checked is not False
            or self.service_principal_checked is not False
            or self.service_principal_assignment_required_checked is not False
            or self.service_principal_lock_checked is not False
            or self.claims_policy_assignments_checked is not False
            or self.provider_ownership_checked is not False
            or self.owner_tenant_membership_checked is not False
            or self.application_creation_performed is not False
            or self.activation_ready is not False
        ):
            raise ValueError("Entra API registration readiness receipt is invalid")


def _is_hex_digest(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraAPIRegistrationReadinessError(
                "Entra API registration document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise EntraAPIRegistrationReadinessError(
        "Entra API registration document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document contains a non-finite number"
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
            if depth > MAX_ENTRA_API_REGISTRATION_NESTING_DEPTH:
                raise EntraAPIRegistrationReadinessError(
                    "Entra API registration document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_API_REGISTRATION_NESTING_DEPTH:
                raise EntraAPIRegistrationReadinessError(
                    "Entra API registration document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_API_REGISTRATION_CONTAINERS:
            raise EntraAPIRegistrationReadinessError(
                "Entra API registration document exceeds the structure limit"
            )


def _require_canonical_uuid_text(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return str(parsed) == value


def _require_canonical_uuid_inputs(parsed: dict[str, Any]) -> None:
    registration = parsed.get("registration")
    if not isinstance(registration, dict):
        return
    scalar_fields = (
        "tenant_id",
        "api_application_id",
        "application_object_id",
    )
    if any(
        not _require_canonical_uuid_text(registration.get(field))
        for field in scalar_fields
    ):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document failed contract validation"
        )
    owner_ids = registration.get("owner_object_ids")
    if not isinstance(owner_ids, list) or any(
        not _require_canonical_uuid_text(value) for value in owner_ids
    ):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document failed contract validation"
        )
    scopes = registration.get("delegated_scopes")
    if not isinstance(scopes, list) or any(
        not isinstance(scope, dict)
        or not _require_canonical_uuid_text(scope.get("scope_id"))
        for scope in scopes
    ):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document failed contract validation"
        )
    for field in (
        "password_credential_ids",
        "key_credential_ids",
        "app_role_ids",
        "preauthorized_client_application_ids",
        "known_client_application_ids",
        "required_resource_application_ids",
        "federated_identity_credential_ids",
        "add_in_ids",
    ):
        values = registration.get(field)
        if not isinstance(values, list) or any(
            not _require_canonical_uuid_text(value) for value in values
        ):
            raise EntraAPIRegistrationReadinessError(
                "Entra API registration document failed contract validation"
            )


def _identity_sha256(label: str, *values: str) -> str:
    framed = (
        "engineer4me-step202-v1",
        label,
        str(len(values)),
        *values,
    )
    material = "".join(f"{len(value)}:{value}" for value in framed).encode(
        "utf-8"
    )
    return hashlib.sha256(material).hexdigest()


def load_entra_api_registration_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
) -> EntraAPIRegistrationReadinessReceipt:
    """Bind strict desired state to one already validated Step 201 preview."""

    if not isinstance(document, bytes):
        raise TypeError("Entra API registration document must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication readiness preview is required")
    try:
        render_authentication_readiness_preview(authentication_preview)
    except (TypeError, ValueError):
        raise EntraAPIRegistrationReadinessError(
            "authentication readiness preview is not locally validated"
        ) from None
    if not document:
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document is empty"
        )
    if len(document) > MAX_ENTRA_API_REGISTRATION_DOCUMENT_BYTES:
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except EntraAPIRegistrationReadinessError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document root must be an object"
        )
    _require_bounded_structure(parsed)
    _require_canonical_uuid_inputs(parsed)
    try:
        canonical_document = _canonical_bytes(parsed)
        validated = EntraAPIRegistrationDocument.model_validate_json(
            canonical_document
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document failed contract validation"
        ) from None

    registration = validated.registration
    scope = registration.delegated_scopes[0]
    if (
        authentication_preview.token_profile != "microsoft_entra_v2"
        or authentication_preview.microsoft_entra_tenant_id is None
        or authentication_preview.microsoft_entra_api_application_id is None
        or authentication_preview.microsoft_entra_required_delegated_scope
        != scope.value
        or authentication_preview.audience
        != authentication_preview.microsoft_entra_api_application_id
        or not hmac.compare_digest(
            validated.approved_configuration_sha256,
            authentication_preview.configuration_sha256,
        )
        or str(registration.tenant_id)
        != authentication_preview.microsoft_entra_tenant_id
        or str(registration.api_application_id)
        != authentication_preview.microsoft_entra_api_application_id
    ):
        raise EntraAPIRegistrationReadinessError(
            "Entra API registration document does not match authentication readiness"
        )

    sorted_owner_ids = tuple(
        sorted(str(value) for value in registration.owner_object_ids)
    )
    return EntraAPIRegistrationReadinessReceipt(
        receipt_type=ENTRA_API_REGISTRATION_RECEIPT_TYPE,
        schema_version=ENTRA_API_REGISTRATION_SCHEMA_VERSION,
        configuration_sha256=authentication_preview.configuration_sha256,
        registration_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        tenant_id_sha256=_identity_sha256(
            "tenant_id",
            str(registration.tenant_id),
        ),
        api_application_id_sha256=_identity_sha256(
            "api_application_id",
            str(registration.api_application_id)
        ),
        application_object_id_sha256=_identity_sha256(
            "application_object_id",
            str(registration.application_object_id)
        ),
        display_name_sha256=_identity_sha256(
            "display_name",
            registration.display_name,
        ),
        owner_object_ids_sha256=_identity_sha256(
            "owner_object_ids",
            str(len(sorted_owner_ids)),
            *sorted_owner_ids,
        ),
        owner_count=len(registration.owner_object_ids),
        delegated_scope_id_sha256=_identity_sha256(
            "delegated_scope_id",
            str(scope.scope_id),
        ),
        identifier_uri_sha256=_identity_sha256(
            "identifier_uri",
            registration.identifier_uris[0],
        ),
        sign_in_audience=registration.sign_in_audience,
        requested_access_token_version=registration.requested_access_token_version,
        delegated_scope_value=scope.value,
        delegated_scope_consent=scope.consent,
        delegated_scope_enabled=scope.enabled,
        accept_mapped_claims=registration.accept_mapped_claims,
        desired_redirect_uri_count=0,
        desired_password_key_credential_count=0,
        desired_federated_identity_credential_count=0,
        desired_app_role_count=0,
        desired_preauthorized_client_count=0,
        desired_known_client_count=0,
        desired_required_resource_count=0,
        desired_optional_claims_configured=False,
        desired_group_membership_claims_configured=False,
        desired_token_encryption_key_configured=False,
        desired_add_in_count=0,
        configuration_bound=True,
        provider_state_checked=False,
        live_registration_checked=False,
        live_application_exists_checked=False,
        admin_consent_checked=False,
        calling_client_registration_checked=False,
        user_flow_checked=False,
        runtime_scope_enforcement=False,
        delegated_token_enforcement=False,
        roleless_app_token_rejection=False,
        calling_client_identity_checked=False,
        azp_checked=False,
        service_principal_checked=False,
        service_principal_assignment_required_checked=False,
        service_principal_lock_checked=False,
        claims_policy_assignments_checked=False,
        provider_ownership_checked=False,
        owner_tenant_membership_checked=False,
        application_creation_performed=False,
        activation_ready=False,
    )


def entra_api_registration_receipt_matches_identity(
    receipt: EntraAPIRegistrationReadinessReceipt,
    *,
    tenant_id: UUID,
    api_application_id: UUID,
    api_application_object_id: UUID,
    delegated_scope_id: UUID,
) -> bool:
    """Match raw reviewed UUIDs without exposing them in the API receipt."""

    if (
        type(receipt) is not EntraAPIRegistrationReadinessReceipt
        or type(tenant_id) is not UUID
        or type(api_application_id) is not UUID
        or type(api_application_object_id) is not UUID
        or type(delegated_scope_id) is not UUID
        or tenant_id.int == 0
        or api_application_id.int == 0
        or api_application_object_id.int == 0
        or delegated_scope_id.int == 0
    ):
        return False
    try:
        receipt.__post_init__()
    except ValueError:
        return False
    return (
        hmac.compare_digest(
            receipt.tenant_id_sha256,
            _identity_sha256("tenant_id", str(tenant_id)),
        )
        and hmac.compare_digest(
            receipt.api_application_id_sha256,
            _identity_sha256("api_application_id", str(api_application_id)),
        )
        and hmac.compare_digest(
            receipt.application_object_id_sha256,
            _identity_sha256(
                "application_object_id",
                str(api_application_object_id),
            ),
        )
        and hmac.compare_digest(
            receipt.delegated_scope_id_sha256,
            _identity_sha256("delegated_scope_id", str(delegated_scope_id)),
        )
    )


def render_entra_api_registration_readiness_receipt(
    receipt: EntraAPIRegistrationReadinessReceipt,
) -> str:
    """Render one canonical privacy-minimised non-live readiness receipt."""

    if type(receipt) is not EntraAPIRegistrationReadinessReceipt:
        raise TypeError("Entra API registration readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {
            "accept_mapped_claims": receipt.accept_mapped_claims,
            "activation_ready": receipt.activation_ready,
            "admin_consent_checked": receipt.admin_consent_checked,
            "api_application_id_sha256": receipt.api_application_id_sha256,
            "application_creation_performed": (
                receipt.application_creation_performed
            ),
            "application_object_id_sha256": receipt.application_object_id_sha256,
            "azp_checked": receipt.azp_checked,
            "calling_client_identity_checked": (
                receipt.calling_client_identity_checked
            ),
            "calling_client_registration_checked": (
                receipt.calling_client_registration_checked
            ),
            "claims_policy_assignments_checked": (
                receipt.claims_policy_assignments_checked
            ),
            "configuration_bound": receipt.configuration_bound,
            "configuration_sha256": receipt.configuration_sha256,
            "delegated_scope_consent": receipt.delegated_scope_consent,
            "delegated_scope_enabled": receipt.delegated_scope_enabled,
            "delegated_scope_id_sha256": receipt.delegated_scope_id_sha256,
            "delegated_scope_value": receipt.delegated_scope_value,
            "delegated_token_enforcement": receipt.delegated_token_enforcement,
            "desired_add_in_count": receipt.desired_add_in_count,
            "desired_app_role_count": receipt.desired_app_role_count,
            "desired_federated_identity_credential_count": (
                receipt.desired_federated_identity_credential_count
            ),
            "desired_group_membership_claims_configured": (
                receipt.desired_group_membership_claims_configured
            ),
            "desired_known_client_count": receipt.desired_known_client_count,
            "desired_optional_claims_configured": (
                receipt.desired_optional_claims_configured
            ),
            "desired_password_key_credential_count": (
                receipt.desired_password_key_credential_count
            ),
            "desired_preauthorized_client_count": (
                receipt.desired_preauthorized_client_count
            ),
            "desired_redirect_uri_count": receipt.desired_redirect_uri_count,
            "desired_required_resource_count": (
                receipt.desired_required_resource_count
            ),
            "desired_token_encryption_key_configured": (
                receipt.desired_token_encryption_key_configured
            ),
            "display_name_sha256": receipt.display_name_sha256,
            "identifier_uri_sha256": receipt.identifier_uri_sha256,
            "live_application_exists_checked": (
                receipt.live_application_exists_checked
            ),
            "live_registration_checked": receipt.live_registration_checked,
            "owner_count": receipt.owner_count,
            "owner_object_ids_sha256": receipt.owner_object_ids_sha256,
            "owner_tenant_membership_checked": (
                receipt.owner_tenant_membership_checked
            ),
            "provider_ownership_checked": receipt.provider_ownership_checked,
            "provider_state_checked": receipt.provider_state_checked,
            "receipt_type": receipt.receipt_type,
            "registration_document_sha256": receipt.registration_document_sha256,
            "requested_access_token_version": (
                receipt.requested_access_token_version
            ),
            "roleless_app_token_rejection": receipt.roleless_app_token_rejection,
            "runtime_scope_enforcement": receipt.runtime_scope_enforcement,
            "schema_version": receipt.schema_version,
            "service_principal_assignment_required_checked": (
                receipt.service_principal_assignment_required_checked
            ),
            "service_principal_checked": receipt.service_principal_checked,
            "service_principal_lock_checked": (
                receipt.service_principal_lock_checked
            ),
            "sign_in_audience": receipt.sign_in_audience,
            "tenant_id_sha256": receipt.tenant_id_sha256,
            "user_flow_checked": receipt.user_flow_checked,
            "validation_scope": ENTRA_API_REGISTRATION_SCOPE,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_API_REGISTRATION_DOCUMENT_TYPE",
    "ENTRA_API_REGISTRATION_RECEIPT_TYPE",
    "ENTRA_API_REGISTRATION_SCHEMA_VERSION",
    "ENTRA_API_REGISTRATION_SCOPE",
    "MAX_ENTRA_API_REGISTRATION_DOCUMENT_BYTES",
    "MAX_ENTRA_API_REGISTRATION_NESTING_DEPTH",
    "EntraAPIRegistrationReadinessError",
    "EntraAPIRegistrationReadinessReceipt",
    "entra_api_registration_receipt_matches_identity",
    "load_entra_api_registration_readiness",
    "render_entra_api_registration_readiness_receipt",
]
