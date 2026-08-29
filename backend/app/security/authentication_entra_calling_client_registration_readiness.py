"""Offline desired-state contract for the immediate Entra browser SPA client.

The contract is pure and fail closed.  It validates explicit public
registration metadata and binds it to already validated Engineer4Me
authentication and API-registration evidence.  It does not read files or
environment variables, contact Microsoft Graph, inspect a tenant, open a
database session, mutate an application, or establish live readiness.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import Field, ValidationError, model_validator

from app.security.authentication_entra_api_registration_readiness import (
    entra_api_registration_receipt_matches_identity,
    load_entra_api_registration_readiness,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    render_authentication_readiness_preview,
)
from app.security.identity_models import SecurityModel


ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_registration_readiness"
)
ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_registration_readiness_receipt"
)
ENTRA_CALLING_CLIENT_REGISTRATION_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_REGISTRATION_SCOPE = "offline_spa_desired_state_only"
ENTRA_CALLING_CLIENT_ARCHITECTURE = "public_browser_spa_pkce"
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_BYTES = 24_576
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_NESTING_DEPTH = 8
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_CONTAINERS = 256
MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS = 3
_SHA256_HEX_LENGTH = 64
_EXPECTED_RUNTIME_OIDC_SCOPES = ("offline_access", "openid", "profile")
_UNSUPPORTED_ENTRA_REDIRECT_CHARACTERS = frozenset("!$'(),;")
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class EntraCallingClientRegistrationReadinessError(ValueError):
    """Sanitized rejection of untrusted calling-client desired state."""


class EntraCallingClientRequiredResourceAccess(SecurityModel):
    resource_application_id: UUID
    delegated_scope_id: UUID
    permission_type: Literal["Scope"]
    scope_value: Literal["access_as_user"]


class EntraCallingClientRegistration(SecurityModel):
    tenant_id: UUID
    api_application_id: UUID
    api_application_object_id: UUID
    api_delegated_scope_id: UUID
    calling_client_application_id: UUID
    calling_client_application_object_id: UUID
    display_name: Literal["Engineer4Me Web"]
    description: None
    notes: None
    marketing_url: None
    privacy_statement_url: None
    support_url: None
    terms_of_service_url: None
    desired_logo_configured: Literal[False]
    owner_object_ids: tuple[UUID, ...] = Field(min_length=2, max_length=5)
    desired_sign_in_audience: Literal["AzureADMyOrg"]
    desired_client_architecture: Literal["public_browser_spa_pkce"]
    desired_browser_flow: Literal["authorization_code_pkce"]
    desired_pkce_method: Literal["S256"]
    desired_client_authentication_method: Literal["none"]
    desired_authorization_code_flow_enabled: Literal[True]
    desired_pkce_required: Literal[True]
    spa_redirect_uris: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS,
    )
    web_redirect_uris: tuple[str, ...] = Field(max_length=0)
    public_client_redirect_uris: tuple[str, ...] = Field(max_length=0)
    desired_implicit_access_token_enabled: Literal[False]
    desired_implicit_id_token_enabled: Literal[False]
    desired_public_client_fallback_enabled: Literal[False]
    desired_native_authentication_apis_enabled: Literal["none"]
    desired_device_only_auth_supported: Literal[False]
    desired_device_code_flow_enabled: Literal[False]
    desired_resource_owner_password_flow_enabled: Literal[False]
    desired_client_credentials_flow_enabled: Literal[False]
    desired_on_behalf_of_flow_enabled: Literal[False]
    password_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    key_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    federated_identity_credential_ids: tuple[UUID, ...] = Field(max_length=0)
    required_resource_access: tuple[
        EntraCallingClientRequiredResourceAccess,
        ...,
    ] = Field(min_length=1, max_length=1)
    microsoft_graph_permission_ids: tuple[UUID, ...] = Field(max_length=0)
    identifier_uris: tuple[str, ...] = Field(max_length=0)
    exposed_delegated_scope_ids: tuple[UUID, ...] = Field(max_length=0)
    app_role_ids: tuple[UUID, ...] = Field(max_length=0)
    preauthorized_client_application_ids: tuple[UUID, ...] = Field(max_length=0)
    known_client_application_ids: tuple[UUID, ...] = Field(max_length=0)
    desired_optional_claims_configured: Literal[False]
    desired_group_membership_claims_configured: Literal[False]
    desired_token_encryption_key_configured: Literal[False]
    desired_api_accept_mapped_claims: Literal[False]
    desired_oauth2_required_post_response: Literal[False]
    add_in_ids: tuple[UUID, ...] = Field(max_length=0)
    desired_runtime_oidc_scopes: tuple[str, ...] = Field(min_length=3, max_length=3)
    desired_runtime_api_scope: str
    home_page_url: None
    logout_url: None

    @model_validator(mode="after")
    def validate_registration(self) -> "EntraCallingClientRegistration":
        owners = tuple(self.owner_object_ids)
        if len(owners) != len(set(owners)):
            raise ValueError("owner object IDs must be unique")
        if owners != tuple(sorted(owners, key=str)):
            raise ValueError("owner object IDs must be sorted")

        identifiers = (
            self.tenant_id,
            self.api_application_id,
            self.api_application_object_id,
            self.api_delegated_scope_id,
            self.calling_client_application_id,
            self.calling_client_application_object_id,
            *owners,
        )
        if any(value.int == 0 for value in identifiers):
            raise ValueError("calling-client identifiers must be nonzero")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("calling-client identifiers must be distinct")

        access = self.required_resource_access[0]
        if (
            access.resource_application_id != self.api_application_id
            or access.delegated_scope_id != self.api_delegated_scope_id
        ):
            raise ValueError("required API access must match the protected API")

        redirect_uris = tuple(self.spa_redirect_uris)
        if len(redirect_uris) != len(set(redirect_uris)):
            raise ValueError("SPA redirect URIs must be unique")
        if redirect_uris != tuple(sorted(redirect_uris)):
            raise ValueError("SPA redirect URIs must be sorted")
        if any(not _is_canonical_production_spa_redirect_uri(uri) for uri in redirect_uris):
            raise ValueError("SPA redirect URI is not canonical HTTPS")

        if self.desired_runtime_oidc_scopes != _EXPECTED_RUNTIME_OIDC_SCOPES:
            raise ValueError("runtime OIDC scopes must match the approved minimum")
        expected_api_scope = f"api://{self.api_application_id}/access_as_user"
        if self.desired_runtime_api_scope != expected_api_scope:
            raise ValueError("runtime API scope must match the protected API")
        return self


class EntraCallingClientRegistrationDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_registration_readiness"
    ]
    schema_version: Literal[1]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    registration: EntraCallingClientRegistration

    @model_validator(mode="after")
    def validate_digests(self) -> "EntraCallingClientRegistrationDocument":
        if not _is_lower_sha256(self.approved_configuration_sha256):
            raise ValueError("configuration digest must be lowercase SHA-256")
        if not _is_lower_sha256(self.approved_api_registration_document_sha256):
            raise ValueError("API registration digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientRegistrationReadinessReceipt:
    receipt_type: str
    schema_version: int
    configuration_sha256: str
    api_registration_document_sha256: str
    client_registration_document_sha256: str
    tenant_id_sha256: str
    api_application_id_sha256: str
    api_application_object_id_sha256: str
    api_delegated_scope_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    display_name_sha256: str
    owner_object_ids_sha256: str
    spa_redirect_uris_sha256: str
    desired_runtime_oidc_scopes_sha256: str
    desired_runtime_api_scope_sha256: str
    required_resource_access_sha256: str
    desired_owner_count: int
    desired_spa_redirect_uri_count: int
    desired_required_resource_access_count: int
    desired_microsoft_graph_permission_count: int
    desired_password_credential_count: int
    desired_key_credential_count: int
    desired_federated_identity_credential_count: int
    desired_exposed_delegated_scope_count: int
    desired_app_role_count: int
    desired_web_redirect_uri_count: int
    desired_public_client_redirect_uri_count: int
    desired_identifier_uri_count: int
    desired_preauthorized_client_count: int
    desired_known_client_count: int
    desired_add_in_count: int
    desired_info_url_count: int
    desired_runtime_oidc_scope_count: int
    desired_client_architecture: str
    desired_browser_flow: str
    desired_pkce_method: str
    desired_client_authentication_method: str
    desired_sign_in_audience: str
    desired_authorization_code_flow_enabled: bool
    desired_pkce_required: bool
    desired_implicit_access_token_enabled: bool
    desired_implicit_id_token_enabled: bool
    desired_public_client_fallback_enabled: bool
    desired_native_authentication_apis_enabled: str
    desired_device_only_auth_supported: bool
    desired_device_code_flow_enabled: bool
    desired_resource_owner_password_flow_enabled: bool
    desired_client_credentials_flow_enabled: bool
    desired_on_behalf_of_flow_enabled: bool
    desired_client_secret_allowed: bool
    desired_logo_configured: bool
    desired_optional_claims_configured: bool
    desired_group_membership_claims_configured: bool
    desired_token_encryption_key_configured: bool
    desired_api_accept_mapped_claims: bool
    desired_oauth2_required_post_response: bool
    desired_offline_access: bool
    desired_permission_type: str
    desired_delegated_scope_value: str
    desired_delegated_scope_consent: str
    configuration_bound: bool
    api_registration_bound: bool
    required_resource_access_bound: bool
    desired_state_validated: bool
    desired_spa_platform_configured: bool
    redirect_uri_syntax_validated: bool
    provider_state_checked: bool
    live_registration_checked: bool
    live_application_exists_checked: bool
    delegated_permission_grant_checked: bool
    admin_consent_checked: bool
    service_principal_checked: bool
    user_flow_checked: bool
    provider_ownership_checked: bool
    owner_tenant_membership_checked: bool
    tenant_external_status_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_azpacr_public_client_checked: bool
    redirect_endpoint_ownership_checked: bool
    redirect_tls_checked: bool
    open_redirect_behavior_checked: bool
    application_creation_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = (
            self.configuration_sha256,
            self.api_registration_document_sha256,
            self.client_registration_document_sha256,
            self.tenant_id_sha256,
            self.api_application_id_sha256,
            self.api_application_object_id_sha256,
            self.api_delegated_scope_id_sha256,
            self.calling_client_application_id_sha256,
            self.calling_client_application_object_id_sha256,
            self.display_name_sha256,
            self.owner_object_ids_sha256,
            self.spa_redirect_uris_sha256,
            self.desired_runtime_oidc_scopes_sha256,
            self.desired_runtime_api_scope_sha256,
            self.required_resource_access_sha256,
        )
        zero_counts = (
            self.desired_microsoft_graph_permission_count,
            self.desired_password_credential_count,
            self.desired_key_credential_count,
            self.desired_federated_identity_credential_count,
            self.desired_exposed_delegated_scope_count,
            self.desired_app_role_count,
            self.desired_web_redirect_uri_count,
            self.desired_public_client_redirect_uri_count,
            self.desired_identifier_uri_count,
            self.desired_preauthorized_client_count,
            self.desired_known_client_count,
            self.desired_add_in_count,
            self.desired_info_url_count,
        )
        if (
            self.receipt_type != ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_CALLING_CLIENT_REGISTRATION_SCHEMA_VERSION
            or any(not _is_lower_sha256(value) for value in digests)
            or type(self.desired_owner_count) is not int
            or self.desired_owner_count < 2
            or self.desired_owner_count > 5
            or type(self.desired_spa_redirect_uri_count) is not int
            or self.desired_spa_redirect_uri_count < 1
            or self.desired_spa_redirect_uri_count > MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS
            or type(self.desired_required_resource_access_count) is not int
            or self.desired_required_resource_access_count != 1
            or type(self.desired_runtime_oidc_scope_count) is not int
            or self.desired_runtime_oidc_scope_count != 3
            or any(type(value) is not int or value != 0 for value in zero_counts)
            or self.desired_client_architecture != ENTRA_CALLING_CLIENT_ARCHITECTURE
            or self.desired_browser_flow != "authorization_code_pkce"
            or self.desired_pkce_method != "S256"
            or self.desired_client_authentication_method != "none"
            or self.desired_sign_in_audience != "AzureADMyOrg"
            or self.desired_authorization_code_flow_enabled is not True
            or self.desired_pkce_required is not True
            or self.desired_implicit_access_token_enabled is not False
            or self.desired_implicit_id_token_enabled is not False
            or self.desired_public_client_fallback_enabled is not False
            or self.desired_native_authentication_apis_enabled != "none"
            or self.desired_device_only_auth_supported is not False
            or self.desired_device_code_flow_enabled is not False
            or self.desired_resource_owner_password_flow_enabled is not False
            or self.desired_client_credentials_flow_enabled is not False
            or self.desired_on_behalf_of_flow_enabled is not False
            or self.desired_client_secret_allowed is not False
            or self.desired_logo_configured is not False
            or self.desired_optional_claims_configured is not False
            or self.desired_group_membership_claims_configured is not False
            or self.desired_token_encryption_key_configured is not False
            or self.desired_api_accept_mapped_claims is not False
            or self.desired_oauth2_required_post_response is not False
            or self.desired_offline_access is not True
            or self.desired_permission_type != "Scope"
            or self.desired_delegated_scope_value != "access_as_user"
            or self.desired_delegated_scope_consent != "admins_only"
            or self.configuration_bound is not True
            or self.api_registration_bound is not True
            or self.required_resource_access_bound is not True
            or self.desired_state_validated is not True
            or self.desired_spa_platform_configured is not True
            or self.redirect_uri_syntax_validated is not True
            or self.provider_state_checked is not False
            or self.live_registration_checked is not False
            or self.live_application_exists_checked is not False
            or self.delegated_permission_grant_checked is not False
            or self.admin_consent_checked is not False
            or self.service_principal_checked is not False
            or self.user_flow_checked is not False
            or self.provider_ownership_checked is not False
            or self.owner_tenant_membership_checked is not False
            or self.tenant_external_status_checked is not False
            or self.runtime_pkce_s256_checked is not False
            or self.runtime_azpacr_public_client_checked is not False
            or self.redirect_endpoint_ownership_checked is not False
            or self.redirect_tls_checked is not False
            or self.open_redirect_behavior_checked is not False
            or self.application_creation_performed is not False
            or self.activation_ready is not False
        ):
            raise ValueError("Entra calling-client registration receipt is invalid")


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


def _is_canonical_production_spa_redirect_uri(value: object) -> bool:
    if type(value) is not str or len(value) > 256 or not value:
        return False
    if any(
        character == "\\"
        or character == "%"
        or character in _UNSUPPORTED_ENTRA_REDIRECT_CHARACTERS
        or character.isspace()
        or ord(character) < 0x20
        or ord(character) > 0x7E
        for character in value
    ):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or "*" in value
        or _DNS_NAME.fullmatch(hostname) is None
        or any(label.startswith("xn--") for label in hostname.split("."))
        or parsed.netloc != hostname
        or not parsed.path.startswith("/")
        or parsed.path in {"", "/"}
        or "//" in parsed.path
        or any(segment in {".", ".."} for segment in parsed.path.split("/"))
    ):
        return False
    return urlunsplit(("https", hostname, parsed.path, "", "")) == value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraCallingClientRegistrationReadinessError(
                "Entra calling-client registration document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise EntraCallingClientRegistrationReadinessError(
        "Entra calling-client registration document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document contains a non-finite number"
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
            if depth > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_NESTING_DEPTH:
                raise EntraCallingClientRegistrationReadinessError(
                    "Entra calling-client registration document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_NESTING_DEPTH:
                raise EntraCallingClientRegistrationReadinessError(
                    "Entra calling-client registration document exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_CONTAINERS:
            raise EntraCallingClientRegistrationReadinessError(
                "Entra calling-client registration document exceeds the structure limit"
            )


def _is_canonical_uuid_text(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _require_canonical_uuid_inputs(parsed: dict[str, Any]) -> None:
    registration = parsed.get("registration")
    if not isinstance(registration, dict):
        return
    for field in (
        "tenant_id",
        "api_application_id",
        "api_application_object_id",
        "api_delegated_scope_id",
        "calling_client_application_id",
        "calling_client_application_object_id",
    ):
        if not _is_canonical_uuid_text(registration.get(field)):
            raise EntraCallingClientRegistrationReadinessError(
                "Entra calling-client registration document failed contract validation"
            )
    for field in (
        "owner_object_ids",
        "password_credential_ids",
        "key_credential_ids",
        "federated_identity_credential_ids",
        "microsoft_graph_permission_ids",
        "exposed_delegated_scope_ids",
        "app_role_ids",
        "preauthorized_client_application_ids",
        "known_client_application_ids",
        "add_in_ids",
    ):
        values = registration.get(field)
        if not isinstance(values, list) or any(
            not _is_canonical_uuid_text(value) for value in values
        ):
            raise EntraCallingClientRegistrationReadinessError(
                "Entra calling-client registration document failed contract validation"
            )
    access_values = registration.get("required_resource_access")
    if not isinstance(access_values, list) or any(
        not isinstance(access, dict)
        or not _is_canonical_uuid_text(access.get("resource_application_id"))
        or not _is_canonical_uuid_text(access.get("delegated_scope_id"))
        for access in access_values
    ):
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document failed contract validation"
        )


def _require_exact_boolean_inputs(parsed: dict[str, Any]) -> None:
    registration = parsed.get("registration")
    if not isinstance(registration, dict):
        return
    for field in (
        "desired_logo_configured",
        "desired_authorization_code_flow_enabled",
        "desired_pkce_required",
        "desired_implicit_access_token_enabled",
        "desired_implicit_id_token_enabled",
        "desired_public_client_fallback_enabled",
        "desired_device_only_auth_supported",
        "desired_device_code_flow_enabled",
        "desired_resource_owner_password_flow_enabled",
        "desired_client_credentials_flow_enabled",
        "desired_on_behalf_of_flow_enabled",
        "desired_optional_claims_configured",
        "desired_group_membership_claims_configured",
        "desired_token_encryption_key_configured",
        "desired_api_accept_mapped_claims",
        "desired_oauth2_required_post_response",
    ):
        if type(registration.get(field)) is not bool:
            raise EntraCallingClientRegistrationReadinessError(
                "Entra calling-client registration document failed contract validation"
            )


def _identity_sha256(label: str, *values: str) -> str:
    framed = ("engineer4me-step205-v1", label, str(len(values)), *values)
    material = "".join(f"{len(value)}:{value}" for value in framed).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def load_entra_calling_client_registration_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
) -> EntraCallingClientRegistrationReadinessReceipt:
    """Bind one strict SPA desired state to Step 202 and Step 204 evidence."""

    if not isinstance(document, bytes):
        raise TypeError("Entra calling-client registration document must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication readiness preview is required")
    if not isinstance(api_registration_document, bytes):
        raise TypeError("accepted Entra API registration document must be bytes")
    if not _is_lower_sha256(accepted_api_registration_document_sha256):
        raise TypeError("accepted Entra API registration digest is required")
    try:
        render_authentication_readiness_preview(authentication_preview)
    except (TypeError, ValueError):
        raise EntraCallingClientRegistrationReadinessError(
            "prerequisite readiness evidence is not locally validated"
        ) from None
    try:
        api_registration_receipt = load_entra_api_registration_readiness(
            document=api_registration_document,
            authentication_preview=authentication_preview,
        )
    except (TypeError, ValueError):
        raise EntraCallingClientRegistrationReadinessError(
            "accepted API registration document is not locally validated"
        ) from None
    if not hmac.compare_digest(
        api_registration_receipt.registration_document_sha256,
        accepted_api_registration_document_sha256,
    ):
        raise EntraCallingClientRegistrationReadinessError(
            "API registration document does not match the accepted digest"
        )
    if not document:
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document is empty"
        )
    if len(document) > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_BYTES:
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except EntraCallingClientRegistrationReadinessError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document root must be an object"
        )
    _require_bounded_structure(parsed)
    _require_canonical_uuid_inputs(parsed)
    _require_exact_boolean_inputs(parsed)
    try:
        canonical_document = _canonical_bytes(parsed)
        validated = EntraCallingClientRegistrationDocument.model_validate_json(
            canonical_document
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraCallingClientRegistrationReadinessError(
            "Entra calling-client registration document failed contract validation"
        ) from None

    registration = validated.registration
    access = registration.required_resource_access[0]
    if (
        authentication_preview.token_profile != "microsoft_entra_v2"
        or authentication_preview.microsoft_entra_tenant_id is None
        or authentication_preview.microsoft_entra_api_application_id is None
        or authentication_preview.microsoft_entra_required_delegated_scope
        != "access_as_user"
        or authentication_preview.microsoft_entra_calling_client_application_id
        is None
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
        or str(registration.calling_client_application_id)
        != authentication_preview.microsoft_entra_calling_client_application_id
    ):
        raise EntraCallingClientRegistrationReadinessError(
            "calling-client registration does not match authentication readiness"
        )
    if (
        not hmac.compare_digest(
            api_registration_receipt.configuration_sha256,
            authentication_preview.configuration_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_api_registration_document_sha256,
            accepted_api_registration_document_sha256,
        )
        or not entra_api_registration_receipt_matches_identity(
            api_registration_receipt,
            tenant_id=registration.tenant_id,
            api_application_id=registration.api_application_id,
            api_application_object_id=registration.api_application_object_id,
            delegated_scope_id=registration.api_delegated_scope_id,
        )
        or access.scope_value != api_registration_receipt.delegated_scope_value
        or api_registration_receipt.delegated_scope_consent != "admins_only"
        or api_registration_receipt.delegated_scope_enabled is not True
    ):
        raise EntraCallingClientRegistrationReadinessError(
            "calling-client registration does not match API registration readiness"
        )

    owners = tuple(sorted(str(value) for value in registration.owner_object_ids))
    redirect_uris = tuple(registration.spa_redirect_uris)
    return EntraCallingClientRegistrationReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_REGISTRATION_SCHEMA_VERSION,
        configuration_sha256=authentication_preview.configuration_sha256,
        api_registration_document_sha256=(
            api_registration_receipt.registration_document_sha256
        ),
        client_registration_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=_identity_sha256("tenant_id", str(registration.tenant_id)),
        api_application_id_sha256=_identity_sha256(
            "api_application_id",
            str(registration.api_application_id),
        ),
        api_application_object_id_sha256=_identity_sha256(
            "api_application_object_id",
            str(registration.api_application_object_id),
        ),
        api_delegated_scope_id_sha256=_identity_sha256(
            "api_delegated_scope_id",
            str(registration.api_delegated_scope_id),
        ),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            str(registration.calling_client_application_id),
        ),
        calling_client_application_object_id_sha256=_identity_sha256(
            "calling_client_application_object_id",
            str(registration.calling_client_application_object_id),
        ),
        display_name_sha256=_identity_sha256(
            "display_name",
            registration.display_name,
        ),
        owner_object_ids_sha256=_identity_sha256(
            "owner_object_ids",
            str(len(owners)),
            *owners,
        ),
        spa_redirect_uris_sha256=_identity_sha256(
            "spa_redirect_uris",
            str(len(redirect_uris)),
            *redirect_uris,
        ),
        desired_runtime_oidc_scopes_sha256=_identity_sha256(
            "desired_runtime_oidc_scopes",
            *registration.desired_runtime_oidc_scopes,
        ),
        desired_runtime_api_scope_sha256=_identity_sha256(
            "desired_runtime_api_scope",
            registration.desired_runtime_api_scope,
        ),
        required_resource_access_sha256=_identity_sha256(
            "required_resource_access",
            str(access.resource_application_id),
            str(access.delegated_scope_id),
            access.permission_type,
            access.scope_value,
        ),
        desired_owner_count=len(owners),
        desired_spa_redirect_uri_count=len(redirect_uris),
        desired_required_resource_access_count=1,
        desired_microsoft_graph_permission_count=0,
        desired_password_credential_count=0,
        desired_key_credential_count=0,
        desired_federated_identity_credential_count=0,
        desired_exposed_delegated_scope_count=0,
        desired_app_role_count=0,
        desired_web_redirect_uri_count=0,
        desired_public_client_redirect_uri_count=0,
        desired_identifier_uri_count=0,
        desired_preauthorized_client_count=0,
        desired_known_client_count=0,
        desired_add_in_count=0,
        desired_info_url_count=0,
        desired_runtime_oidc_scope_count=3,
        desired_client_architecture=registration.desired_client_architecture,
        desired_browser_flow=registration.desired_browser_flow,
        desired_pkce_method=registration.desired_pkce_method,
        desired_client_authentication_method=(
            registration.desired_client_authentication_method
        ),
        desired_sign_in_audience=registration.desired_sign_in_audience,
        desired_authorization_code_flow_enabled=True,
        desired_pkce_required=True,
        desired_implicit_access_token_enabled=False,
        desired_implicit_id_token_enabled=False,
        desired_public_client_fallback_enabled=False,
        desired_native_authentication_apis_enabled="none",
        desired_device_only_auth_supported=False,
        desired_device_code_flow_enabled=False,
        desired_resource_owner_password_flow_enabled=False,
        desired_client_credentials_flow_enabled=False,
        desired_on_behalf_of_flow_enabled=False,
        desired_client_secret_allowed=False,
        desired_logo_configured=False,
        desired_optional_claims_configured=False,
        desired_group_membership_claims_configured=False,
        desired_token_encryption_key_configured=False,
        desired_api_accept_mapped_claims=False,
        desired_oauth2_required_post_response=False,
        desired_offline_access=True,
        desired_permission_type=access.permission_type,
        desired_delegated_scope_value=access.scope_value,
        desired_delegated_scope_consent=(
            api_registration_receipt.delegated_scope_consent
        ),
        configuration_bound=True,
        api_registration_bound=True,
        required_resource_access_bound=True,
        desired_state_validated=True,
        desired_spa_platform_configured=True,
        redirect_uri_syntax_validated=True,
        provider_state_checked=False,
        live_registration_checked=False,
        live_application_exists_checked=False,
        delegated_permission_grant_checked=False,
        admin_consent_checked=False,
        service_principal_checked=False,
        user_flow_checked=False,
        provider_ownership_checked=False,
        owner_tenant_membership_checked=False,
        tenant_external_status_checked=False,
        runtime_pkce_s256_checked=False,
        runtime_azpacr_public_client_checked=False,
        redirect_endpoint_ownership_checked=False,
        redirect_tls_checked=False,
        open_redirect_behavior_checked=False,
        application_creation_performed=False,
        activation_ready=False,
    )


def entra_calling_client_registration_receipt_matches_identity(
    receipt: EntraCallingClientRegistrationReadinessReceipt,
    *,
    tenant_id: UUID,
    api_application_id: UUID,
    api_application_object_id: UUID,
    api_delegated_scope_id: UUID,
    calling_client_application_id: UUID,
    calling_client_application_object_id: UUID,
) -> bool:
    """Match reviewed UUIDs without exposing them in the client receipt."""

    identifiers = (
        tenant_id,
        api_application_id,
        api_application_object_id,
        api_delegated_scope_id,
        calling_client_application_id,
        calling_client_application_object_id,
    )
    if (
        type(receipt) is not EntraCallingClientRegistrationReadinessReceipt
        or any(type(value) is not UUID or value.int == 0 for value in identifiers)
        or len(identifiers) != len(set(identifiers))
    ):
        return False
    try:
        receipt.__post_init__()
    except ValueError:
        return False
    matches = (
        hmac.compare_digest(
            receipt.tenant_id_sha256,
            _identity_sha256("tenant_id", str(tenant_id)),
        ),
        hmac.compare_digest(
            receipt.api_application_id_sha256,
            _identity_sha256("api_application_id", str(api_application_id)),
        ),
        hmac.compare_digest(
            receipt.api_application_object_id_sha256,
            _identity_sha256(
                "api_application_object_id",
                str(api_application_object_id),
            ),
        ),
        hmac.compare_digest(
            receipt.api_delegated_scope_id_sha256,
            _identity_sha256(
                "api_delegated_scope_id",
                str(api_delegated_scope_id),
            ),
        ),
        hmac.compare_digest(
            receipt.calling_client_application_id_sha256,
            _identity_sha256(
                "calling_client_application_id",
                str(calling_client_application_id),
            ),
        ),
        hmac.compare_digest(
            receipt.calling_client_application_object_id_sha256,
            _identity_sha256(
                "calling_client_application_object_id",
                str(calling_client_application_object_id),
            ),
        )
    )
    return all(matches)


def render_entra_calling_client_registration_readiness_receipt(
    receipt: EntraCallingClientRegistrationReadinessReceipt,
) -> str:
    """Render one canonical privacy-minimized non-live readiness receipt."""

    if type(receipt) is not EntraCallingClientRegistrationReadinessReceipt:
        raise TypeError("Entra calling-client registration receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {
            "activation_ready": receipt.activation_ready,
            "admin_consent_checked": receipt.admin_consent_checked,
            "api_application_id_sha256": receipt.api_application_id_sha256,
            "api_application_object_id_sha256": (
                receipt.api_application_object_id_sha256
            ),
            "api_delegated_scope_id_sha256": (
                receipt.api_delegated_scope_id_sha256
            ),
            "desired_client_credentials_flow_enabled": (
                receipt.desired_client_credentials_flow_enabled
            ),
            "api_registration_bound": receipt.api_registration_bound,
            "api_registration_document_sha256": (
                receipt.api_registration_document_sha256
            ),
            "desired_app_role_count": receipt.desired_app_role_count,
            "desired_add_in_count": receipt.desired_add_in_count,
            "desired_api_accept_mapped_claims": (
                receipt.desired_api_accept_mapped_claims
            ),
            "application_creation_performed": (
                receipt.application_creation_performed
            ),
            "calling_client_application_object_id_sha256": (
                receipt.calling_client_application_object_id_sha256
            ),
            "desired_authorization_code_flow_enabled": (
                receipt.desired_authorization_code_flow_enabled
            ),
            "calling_client_application_id_sha256": (
                receipt.calling_client_application_id_sha256
            ),
            "desired_client_architecture": receipt.desired_client_architecture,
            "desired_browser_flow": receipt.desired_browser_flow,
            "desired_client_authentication_method": (
                receipt.desired_client_authentication_method
            ),
            "desired_pkce_method": receipt.desired_pkce_method,
            "client_registration_document_sha256": (
                receipt.client_registration_document_sha256
            ),
            "desired_client_secret_allowed": receipt.desired_client_secret_allowed,
            "configuration_bound": receipt.configuration_bound,
            "configuration_sha256": receipt.configuration_sha256,
            "desired_state_validated": receipt.desired_state_validated,
            "display_name_sha256": receipt.display_name_sha256,
            "delegated_permission_grant_checked": (
                receipt.delegated_permission_grant_checked
            ),
            "desired_device_code_flow_enabled": receipt.desired_device_code_flow_enabled,
            "desired_device_only_auth_supported": receipt.desired_device_only_auth_supported,
            "desired_delegated_scope_consent": (
                receipt.desired_delegated_scope_consent
            ),
            "desired_delegated_scope_value": (
                receipt.desired_delegated_scope_value
            ),
            "desired_exposed_delegated_scope_count": (
                receipt.desired_exposed_delegated_scope_count
            ),
            "desired_federated_identity_credential_count": (
                receipt.desired_federated_identity_credential_count
            ),
            "desired_implicit_access_token_enabled": (
                receipt.desired_implicit_access_token_enabled
            ),
            "desired_implicit_id_token_enabled": receipt.desired_implicit_id_token_enabled,
            "desired_identifier_uri_count": receipt.desired_identifier_uri_count,
            "desired_info_url_count": receipt.desired_info_url_count,
            "desired_key_credential_count": receipt.desired_key_credential_count,
            "desired_known_client_count": receipt.desired_known_client_count,
            "desired_logo_configured": receipt.desired_logo_configured,
            "live_application_exists_checked": (
                receipt.live_application_exists_checked
            ),
            "live_registration_checked": receipt.live_registration_checked,
            "desired_microsoft_graph_permission_count": (
                receipt.desired_microsoft_graph_permission_count
            ),
            "desired_native_authentication_apis_enabled": (
                receipt.desired_native_authentication_apis_enabled
            ),
            "desired_on_behalf_of_flow_enabled": receipt.desired_on_behalf_of_flow_enabled,
            "desired_oauth2_required_post_response": (
                receipt.desired_oauth2_required_post_response
            ),
            "desired_offline_access": receipt.desired_offline_access,
            "desired_optional_claims_configured": (
                receipt.desired_optional_claims_configured
            ),
            "open_redirect_behavior_checked": (
                receipt.open_redirect_behavior_checked
            ),
            "desired_owner_count": receipt.desired_owner_count,
            "owner_object_ids_sha256": receipt.owner_object_ids_sha256,
            "owner_tenant_membership_checked": (
                receipt.owner_tenant_membership_checked
            ),
            "desired_password_credential_count": receipt.desired_password_credential_count,
            "desired_permission_type": receipt.desired_permission_type,
            "desired_pkce_required": receipt.desired_pkce_required,
            "desired_preauthorized_client_count": (
                receipt.desired_preauthorized_client_count
            ),
            "provider_ownership_checked": receipt.provider_ownership_checked,
            "provider_state_checked": receipt.provider_state_checked,
            "desired_public_client_fallback_enabled": (
                receipt.desired_public_client_fallback_enabled
            ),
            "desired_public_client_redirect_uri_count": (
                receipt.desired_public_client_redirect_uri_count
            ),
            "receipt_type": receipt.receipt_type,
            "redirect_endpoint_ownership_checked": (
                receipt.redirect_endpoint_ownership_checked
            ),
            "redirect_tls_checked": receipt.redirect_tls_checked,
            "redirect_uri_syntax_validated": (
                receipt.redirect_uri_syntax_validated
            ),
            "required_resource_access_bound": (
                receipt.required_resource_access_bound
            ),
            "desired_required_resource_access_count": (
                receipt.desired_required_resource_access_count
            ),
            "required_resource_access_sha256": (
                receipt.required_resource_access_sha256
            ),
            "desired_runtime_api_scope_sha256": receipt.desired_runtime_api_scope_sha256,
            "runtime_azpacr_public_client_checked": (
                receipt.runtime_azpacr_public_client_checked
            ),
            "desired_runtime_oidc_scopes_sha256": receipt.desired_runtime_oidc_scopes_sha256,
            "desired_runtime_oidc_scope_count": (
                receipt.desired_runtime_oidc_scope_count
            ),
            "runtime_pkce_s256_checked": receipt.runtime_pkce_s256_checked,
            "schema_version": receipt.schema_version,
            "service_principal_checked": receipt.service_principal_checked,
            "desired_sign_in_audience": receipt.desired_sign_in_audience,
            "desired_spa_platform_configured": receipt.desired_spa_platform_configured,
            "desired_spa_redirect_uri_count": receipt.desired_spa_redirect_uri_count,
            "desired_group_membership_claims_configured": (
                receipt.desired_group_membership_claims_configured
            ),
            "desired_token_encryption_key_configured": (
                receipt.desired_token_encryption_key_configured
            ),
            "desired_web_redirect_uri_count": receipt.desired_web_redirect_uri_count,
            "spa_redirect_uris_sha256": receipt.spa_redirect_uris_sha256,
            "tenant_id_sha256": receipt.tenant_id_sha256,
            "tenant_external_status_checked": (
                receipt.tenant_external_status_checked
            ),
            "user_flow_checked": receipt.user_flow_checked,
            "desired_resource_owner_password_flow_enabled": (
                receipt.desired_resource_owner_password_flow_enabled
            ),
            "validation_scope": ENTRA_CALLING_CLIENT_REGISTRATION_SCOPE,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_ARCHITECTURE",
    "ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_REGISTRATION_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_REGISTRATION_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_REGISTRATION_SCOPE",
    "MAX_ENTRA_CALLING_CLIENT_REDIRECT_URIS",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_BYTES",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_NESTING_DEPTH",
    "EntraCallingClientRegistrationReadinessError",
    "EntraCallingClientRegistrationReadinessReceipt",
    "entra_calling_client_registration_receipt_matches_identity",
    "load_entra_calling_client_registration_readiness",
    "render_entra_calling_client_registration_readiness_receipt",
]
