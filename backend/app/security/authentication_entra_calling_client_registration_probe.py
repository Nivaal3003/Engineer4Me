"""Controlled Graph proof of the reviewed calling-client SPA registration.

The probe revalidates the exact Step 205 calling-client registration and the
Step 207 application/service-principal inventory before constructing three
ordered Microsoft Graph v1.0 GETs for one application object: the selected
application entity, its selected owner IDs, and its selected federated identity
credential IDs.  It compares bounded responses with the approved local state.

This is not a complete Microsoft Graph application manifest.  In particular,
runtime authorization-code/PKCE behavior, redirect endpoint control, tenant
context, token/operator facts, service-principal settings, policies, freshness,
and concurrent provider mutation remain outside this proof.

Only responses sealed by the module-owned HTTPS loader can confer live-provider
evidence.  Public response objects and injected or rebound HTTP openers remain
synthetic evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from uuid import UUID

from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    EntraApplicationServicePrincipalInventoryReadinessError,
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
)
from app.security.authentication_entra_calling_client_registration_graph_http_loader import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS,
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES,
    BoundedHTTPSEntraCallingClientRegistrationGraphLoader,
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphResponse,
    EntraCallingClientRegistrationGraphTransport,
    entra_calling_client_registration_graph_url,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    EntraCallingClientRegistrationReadinessError,
    load_entra_calling_client_registration_readiness,
    render_entra_calling_client_registration_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    render_authentication_readiness_preview,
)
from app.security.identity_models import SecurityModel
from pydantic import Field, ValidationError, model_validator

ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_registration_graph_probe_receipt"
)
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE = (
    "controlled_read_only_graph_calling_client_spa_registration_proof"
)
ENTRA_GRAPH_API_VERSION = "v1.0"
ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION = "Application.Read.All"
ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID = (
    "c79f8feb-a9db-4090-85f9-90d820caa0eb"
)
ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS = (
    "non_admin_member_target_application_owner"
)
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TOTAL_RESPONSE_BYTES = (
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES
    + MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES
    + MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES
)
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_NESTING_DEPTH = 10
MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_CONTAINERS = 256
_SHA256_HEX_LENGTH = 64


class EntraCallingClientRegistrationGraphProbeError(ValueError):
    """Sanitized rejection of invalid prerequisites or provider evidence."""


@dataclass(frozen=True, slots=True)
class EntraCallingClientRegistrationGraphAuthorizationContract:
    """Declared operator intent; never evidence about the supplied token."""

    permission_type: Literal["delegated_work_school"]
    permission_name: str
    permission_id: str
    consent_requirement: Literal["admin"]
    credential_origin: Literal["out_of_band_operator"]
    access_basis: Literal["non_admin_member_target_application_owner"]

    def __post_init__(self) -> None:
        if (
            self.permission_type != "delegated_work_school"
            or self.permission_name != ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION
            or self.permission_id
            != ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID
            or self.consent_requirement != "admin"
            or self.credential_origin != "out_of_band_operator"
            or self.access_basis != ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS
        ):
            raise ValueError("Microsoft Graph authorization contract is invalid")


class _SpaApplication(SecurityModel):
    odata_type: Literal["#microsoft.graph.spaApplication"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    redirect_uris: tuple[str, ...] = Field(
        alias="redirectUris", min_length=1, max_length=3
    )


class _ImplicitGrantSettings(SecurityModel):
    odata_type: Literal["#microsoft.graph.implicitGrantSettings"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    enable_access_token_issuance: Literal[False] = Field(
        alias="enableAccessTokenIssuance"
    )
    enable_id_token_issuance: Literal[False] = Field(alias="enableIdTokenIssuance")


class _WebApplication(SecurityModel):
    odata_type: Literal["#microsoft.graph.webApplication"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    home_page_url: None = Field(alias="homePageUrl")
    logout_url: None = Field(alias="logoutUrl")
    redirect_uris: tuple[str, ...] = Field(alias="redirectUris", max_length=0)
    implicit_grant_settings: _ImplicitGrantSettings = Field(
        alias="implicitGrantSettings"
    )


class _PublicClientApplication(SecurityModel):
    odata_type: Literal["#microsoft.graph.publicClientApplication"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    redirect_uris: tuple[str, ...] = Field(alias="redirectUris", max_length=0)


class _ResourceAccess(SecurityModel):
    odata_type: Literal["#microsoft.graph.resourceAccess"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    id: UUID
    type: Literal["Scope"]


class _RequiredResourceAccess(SecurityModel):
    odata_type: Literal["#microsoft.graph.requiredResourceAccess"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    resource_app_id: UUID = Field(alias="resourceAppId")
    resource_access: tuple[_ResourceAccess, ...] = Field(
        alias="resourceAccess",
        min_length=1,
        max_length=1,
    )


class _ApiApplication(SecurityModel):
    odata_type: Literal["#microsoft.graph.apiApplication"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    accept_mapped_claims: Literal[False] | None = Field(alias="acceptMappedClaims")
    known_client_applications: tuple[UUID, ...] = Field(
        alias="knownClientApplications",
        max_length=0,
    )
    oauth2_permission_scopes: tuple[object, ...] = Field(
        alias="oauth2PermissionScopes",
        max_length=0,
    )
    pre_authorized_applications: tuple[object, ...] = Field(
        alias="preAuthorizedApplications",
        max_length=0,
    )
    requested_access_token_version: Literal[1, 2] | None = Field(
        alias="requestedAccessTokenVersion"
    )


class _InformationalUrl(SecurityModel):
    odata_type: Literal["#microsoft.graph.informationalUrl"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    logo_url: None = Field(alias="logoUrl")
    marketing_url: None = Field(alias="marketingUrl")
    privacy_statement_url: None = Field(alias="privacyStatementUrl")
    support_url: None = Field(alias="supportUrl")
    terms_of_service_url: None = Field(alias="termsOfServiceUrl")


class _CallingClientApplicationResponse(SecurityModel):
    odata_context: str | None = Field(default=None, alias="@odata.context")
    odata_type: Literal["#microsoft.graph.application"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    id: UUID
    app_id: UUID = Field(alias="appId")
    deleted_date_time: None = Field(alias="deletedDateTime")
    disabled_by_microsoft_status: Literal["NotDisabled"] | None = Field(
        alias="disabledByMicrosoftStatus"
    )
    display_name: Literal["Engineer4Me Web"] = Field(alias="displayName")
    description: None
    notes: None
    sign_in_audience: Literal["AzureADMyOrg"] = Field(alias="signInAudience")
    spa: _SpaApplication
    web: _WebApplication
    public_client: _PublicClientApplication = Field(alias="publicClient")
    is_fallback_public_client: Literal[False] | None = Field(
        alias="isFallbackPublicClient"
    )
    is_device_only_auth_supported: Literal[False] | None = Field(
        alias="isDeviceOnlyAuthSupported"
    )
    native_authentication_apis_enabled: Literal["none"] = Field(
        alias="nativeAuthenticationApisEnabled"
    )
    oauth2_required_post_response: Literal[False] = Field(
        alias="oauth2RequiredPostResponse"
    )
    password_credentials: tuple[object, ...] = Field(
        alias="passwordCredentials",
        max_length=0,
    )
    key_credentials: tuple[object, ...] = Field(alias="keyCredentials", max_length=0)
    required_resource_access: tuple[_RequiredResourceAccess, ...] = Field(
        alias="requiredResourceAccess",
        min_length=1,
        max_length=1,
    )
    identifier_uris: tuple[str, ...] = Field(alias="identifierUris", max_length=0)
    app_roles: tuple[object, ...] = Field(alias="appRoles", max_length=0)
    api: _ApiApplication
    optional_claims: None = Field(alias="optionalClaims")
    group_membership_claims: Literal["None"] | None = Field(
        alias="groupMembershipClaims"
    )
    token_encryption_key_id: None = Field(alias="tokenEncryptionKeyId")
    add_ins: tuple[object, ...] = Field(alias="addIns", max_length=0)
    info: _InformationalUrl

    @model_validator(mode="after")
    def validate_context(self) -> _CallingClientApplicationResponse:
        if self.odata_context is not None and self.odata_context != (
            f"{ENTRA_GRAPH_BASE_URL}/$metadata#applications("
            f"{ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT})/$entity"
        ):
            raise ValueError("application OData context is invalid")
        return self


class _OwnerEntry(SecurityModel):
    odata_type: (
        Literal[
            "#microsoft.graph.user",
            "#microsoft.graph.servicePrincipal",
        ]
        | None
    ) = Field(default=None, alias="@odata.type")
    id: UUID


class _OwnerCollectionResponse(SecurityModel):
    odata_context: str | None = Field(default=None, alias="@odata.context")
    value: tuple[_OwnerEntry, ...] = Field(min_length=2, max_length=5)

    @model_validator(mode="after")
    def validate_context(self) -> _OwnerCollectionResponse:
        if self.odata_context is not None and self.odata_context not in {
            f"{ENTRA_GRAPH_BASE_URL}/$metadata#directoryObjects(id)",
            f"{ENTRA_GRAPH_BASE_URL}/$metadata#directoryObjects",
        }:
            raise ValueError("owner OData context is invalid")
        return self


class _FederatedIdentityCredentialCollectionResponse(SecurityModel):
    odata_context: str | None = Field(default=None, alias="@odata.context")
    value: tuple[object, ...] = Field(max_length=0)


@dataclass(frozen=True, slots=True)
class EntraCallingClientRegistrationGraphProbeReceipt:
    receipt_type: str
    schema_version: int
    validation_scope: str
    graph_api_version: str
    authorization_permission_type: str
    authorization_permission_name: str
    authorization_permission_id: str
    authorization_consent_requirement: str
    authorization_credential_origin: str
    authorization_access_basis: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    offline_calling_client_receipt_sha256: str
    offline_inventory_receipt_sha256: str
    expected_graph_subset_sha256: str
    request_plan_sha256: str
    application_response_sha256: str
    owners_response_sha256: str
    federated_identity_credentials_response_sha256: str
    tenant_id_sha256: str
    api_application_id_sha256: str
    api_application_object_id_sha256: str
    api_delegated_scope_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    owner_object_ids_sha256: str
    spa_redirect_uris_sha256: str
    required_resource_access_sha256: str
    registration_security_surfaces_sha256: str
    request_count: int
    response_count: int
    application_response_bytes: int
    owners_response_bytes: int
    federated_identity_credentials_response_bytes: int
    total_response_bytes: int
    desired_spa_redirect_uri_count: int
    response_owner_count: int
    desired_required_resource_access_count: int
    response_password_credential_count: int
    response_key_credential_count: int
    response_federated_identity_credential_count: int
    response_identifier_uri_count: int
    response_app_role_count: int
    response_oauth2_permission_scope_count: int
    response_preauthorized_application_count: int
    response_known_client_application_count: int
    response_add_in_count: int
    response_web_redirect_uri_count: int
    response_public_client_redirect_uri_count: int
    response_info_url_count: int
    api_requested_access_token_version: int | None
    fallback_public_client_wire_form: str
    device_only_auth_wire_form: str
    accept_mapped_claims_wire_form: str
    group_membership_claims_wire_form: str
    configuration_bound: bool
    api_registration_revalidated: bool
    calling_client_registration_revalidated: bool
    calling_client_registration_digest_bound: bool
    inventory_projection_revalidated: bool
    approved_inventory_digest_bound: bool
    application_object_inventory_mapping_validated: bool
    exact_three_get_request_plan_validated: bool
    sequential_request_order_validated: bool
    same_application_object_id_in_all_requests_validated: bool
    graph_global_v1_endpoint_validated: bool
    read_only_methods_validated: bool
    exact_select_projections_validated: bool
    no_request_body_validated: bool
    no_proxy_redirect_retry_compression_validated: bool
    no_batch_or_paging_validated: bool
    response_bounds_validated: bool
    response_json_integrity_validated: bool
    response_schema_validated: bool
    application_identity_validated: bool
    derived_agent_identity_blueprint_wire_type_rejected: bool
    application_not_deleted_validated: bool
    microsoft_disablement_status_validated: bool
    profile_fields_validated: bool
    single_tenant_audience_validated: bool
    exact_spa_redirects_validated: bool
    spa_redirect_wire_order_normalized: bool
    empty_web_redirects_validated: bool
    empty_public_client_redirects_validated: bool
    implicit_grant_disabled_validated: bool
    fallback_public_client_disabled_validated: bool
    device_only_auth_disabled_validated: bool
    native_authentication_apis_disabled_validated: bool
    oauth2_post_response_disabled_validated: bool
    password_credentials_empty_validated: bool
    key_credentials_empty_validated: bool
    exact_required_resource_access_validated: bool
    identifier_uris_empty_validated: bool
    app_roles_empty_validated: bool
    exposed_delegated_scopes_empty_validated: bool
    preauthorized_applications_empty_validated: bool
    known_client_applications_empty_validated: bool
    optional_claims_empty_validated: bool
    group_membership_claims_empty_validated: bool
    token_encryption_key_empty_validated: bool
    add_ins_empty_validated: bool
    information_urls_and_logo_empty_validated: bool
    exact_owner_set_validated: bool
    owner_wire_order_normalized: bool
    federated_identity_credentials_empty_validated: bool
    collection_paging_and_count_rejected: bool
    least_privilege_delegated_permission_contract_validated: bool
    non_admin_owner_access_intent_validated: bool
    application_permission_contract_rejected: bool
    synthetic_transport_used: bool
    live_https_transport_attested: bool
    provider_io_performed: bool
    provider_state_checked: bool
    source_authenticity_checked: bool
    live_application_registration_checked: bool
    live_spa_redirect_registration_checked: bool
    live_owner_inventory_checked: bool
    live_federated_identity_credential_inventory_checked: bool
    authorization_token_claims_checked: bool
    actual_token_type_checked: bool
    app_only_token_checked: bool
    work_school_account_checked: bool
    token_tenant_checked: bool
    token_graph_audience_checked: bool
    token_application_read_all_permission_checked: bool
    token_application_read_all_admin_consent_checked: bool
    delegated_operator_identity_checked: bool
    delegated_operator_member_status_checked: bool
    delegated_operator_owner_relationship_checked: bool
    delegated_operator_role_checked: bool
    delegated_operator_authorization_checked: bool
    provider_tenant_ownership_checked: bool
    tenant_external_status_checked: bool
    owner_tenant_membership_checked: bool
    owner_account_status_checked: bool
    owner_object_types_fully_checked: bool
    owner_review_freshness_checked: bool
    api_requested_access_token_version_approved_state_checked: bool
    redirect_dns_control_checked: bool
    redirect_endpoint_tls_checked: bool
    redirect_endpoint_reachability_checked: bool
    redirect_cors_checked: bool
    redirect_content_security_policy_checked: bool
    open_redirect_behavior_checked: bool
    runtime_authorization_code_flow_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_state_checked: bool
    runtime_nonce_checked: bool
    runtime_redirect_uri_match_checked: bool
    runtime_browser_origin_checked: bool
    runtime_no_client_secret_checked: bool
    runtime_oidc_scopes_requested_checked: bool
    runtime_api_scope_requested_checked: bool
    live_delegated_consent_grant_checked: bool
    service_principal_configuration_checked: bool
    service_principal_assignment_required_checked: bool
    application_tags_checked: bool
    request_signature_verification_checked: bool
    saml_metadata_checked: bool
    service_management_reference_checked: bool
    service_principal_lock_checked: bool
    application_template_checked: bool
    claims_policy_assignments_checked: bool
    conditional_access_checked: bool
    user_flow_checked: bool
    user_flow_application_association_checked: bool
    response_freshness_checked: bool
    atomic_provider_snapshot_checked: bool
    concurrent_provider_mutation_checked: bool
    real_signed_api_token_checked: bool
    application_mutation_performed: bool
    owner_mutation_performed: bool
    federated_identity_credential_mutation_performed: bool
    service_principal_mutation_performed: bool
    receipt_self_authenticating: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digest_values = tuple(
            getattr(self, field)
            for field in self.__dataclass_fields__
            if field.endswith("_sha256")
        )
        structural_true = tuple(
            getattr(self, field) for field in _STRUCTURAL_TRUE_FIELDS
        )
        deferred_false = tuple(getattr(self, field) for field in _DEFERRED_FALSE_FIELDS)
        live = self.live_https_transport_attested
        if (
            self.receipt_type
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCHEMA_VERSION
            or self.validation_scope
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE
            or self.graph_api_version != ENTRA_GRAPH_API_VERSION
            or self.authorization_permission_type != "delegated_work_school"
            or self.authorization_permission_name
            != ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION
            or self.authorization_permission_id
            != ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID
            or self.authorization_consent_requirement != "admin"
            or self.authorization_credential_origin != "out_of_band_operator"
            or self.authorization_access_basis
            != ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS
            or any(not _is_lower_sha256(value) for value in digest_values)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or type(self.request_count) is not int
            or self.request_count
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT
            or type(self.response_count) is not int
            or self.response_count != 3
            or type(self.application_response_bytes) is not int
            or not 1
            <= self.application_response_bytes
            <= MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES
            or type(self.owners_response_bytes) is not int
            or not 1
            <= self.owners_response_bytes
            <= MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES
            or type(self.federated_identity_credentials_response_bytes) is not int
            or not 1
            <= self.federated_identity_credentials_response_bytes
            <= MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES
            or type(self.total_response_bytes) is not int
            or self.total_response_bytes
            != self.application_response_bytes
            + self.owners_response_bytes
            + self.federated_identity_credentials_response_bytes
            or self.total_response_bytes
            > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TOTAL_RESPONSE_BYTES
            or type(self.desired_spa_redirect_uri_count) is not int
            or not 1 <= self.desired_spa_redirect_uri_count <= 3
            or type(self.response_owner_count) is not int
            or not 2 <= self.response_owner_count <= 5
            or type(self.desired_required_resource_access_count) is not int
            or self.desired_required_resource_access_count != 1
            or any(
                type(getattr(self, field)) is not int or getattr(self, field) != 0
                for field in _ZERO_COUNT_FIELDS
            )
            or self.api_requested_access_token_version not in {None, 1, 2}
            or (
                self.api_requested_access_token_version is not None
                and type(self.api_requested_access_token_version) is not int
            )
            or self.fallback_public_client_wire_form not in {"false", "null"}
            or self.device_only_auth_wire_form not in {"false", "null"}
            or self.accept_mapped_claims_wire_form not in {"false", "null"}
            or self.group_membership_claims_wire_form not in {"None", "null"}
            or any(value is not True for value in structural_true)
            or type(live) is not bool
            or self.synthetic_transport_used is not (not live)
            or self.provider_io_performed is not live
            or self.provider_state_checked is not live
            or self.source_authenticity_checked is not live
            or self.live_application_registration_checked is not live
            or self.live_spa_redirect_registration_checked is not live
            or self.live_owner_inventory_checked is not live
            or self.live_federated_identity_credential_inventory_checked is not live
            or any(value is not False for value in deferred_false)
        ):
            raise ValueError("Microsoft Graph calling-client probe receipt is invalid")


_STRUCTURAL_TRUE_FIELDS = (
    "configuration_bound",
    "api_registration_revalidated",
    "calling_client_registration_revalidated",
    "calling_client_registration_digest_bound",
    "inventory_projection_revalidated",
    "approved_inventory_digest_bound",
    "application_object_inventory_mapping_validated",
    "exact_three_get_request_plan_validated",
    "sequential_request_order_validated",
    "same_application_object_id_in_all_requests_validated",
    "graph_global_v1_endpoint_validated",
    "read_only_methods_validated",
    "exact_select_projections_validated",
    "no_request_body_validated",
    "no_proxy_redirect_retry_compression_validated",
    "no_batch_or_paging_validated",
    "response_bounds_validated",
    "response_json_integrity_validated",
    "response_schema_validated",
    "application_identity_validated",
    "derived_agent_identity_blueprint_wire_type_rejected",
    "application_not_deleted_validated",
    "microsoft_disablement_status_validated",
    "profile_fields_validated",
    "single_tenant_audience_validated",
    "exact_spa_redirects_validated",
    "spa_redirect_wire_order_normalized",
    "empty_web_redirects_validated",
    "empty_public_client_redirects_validated",
    "implicit_grant_disabled_validated",
    "fallback_public_client_disabled_validated",
    "device_only_auth_disabled_validated",
    "native_authentication_apis_disabled_validated",
    "oauth2_post_response_disabled_validated",
    "password_credentials_empty_validated",
    "key_credentials_empty_validated",
    "exact_required_resource_access_validated",
    "identifier_uris_empty_validated",
    "app_roles_empty_validated",
    "exposed_delegated_scopes_empty_validated",
    "preauthorized_applications_empty_validated",
    "known_client_applications_empty_validated",
    "optional_claims_empty_validated",
    "group_membership_claims_empty_validated",
    "token_encryption_key_empty_validated",
    "add_ins_empty_validated",
    "information_urls_and_logo_empty_validated",
    "exact_owner_set_validated",
    "owner_wire_order_normalized",
    "federated_identity_credentials_empty_validated",
    "collection_paging_and_count_rejected",
    "least_privilege_delegated_permission_contract_validated",
    "non_admin_owner_access_intent_validated",
    "application_permission_contract_rejected",
)

_DEFERRED_FALSE_FIELDS = (
    "authorization_token_claims_checked",
    "actual_token_type_checked",
    "app_only_token_checked",
    "work_school_account_checked",
    "token_tenant_checked",
    "token_graph_audience_checked",
    "token_application_read_all_permission_checked",
    "token_application_read_all_admin_consent_checked",
    "delegated_operator_identity_checked",
    "delegated_operator_member_status_checked",
    "delegated_operator_owner_relationship_checked",
    "delegated_operator_role_checked",
    "delegated_operator_authorization_checked",
    "provider_tenant_ownership_checked",
    "tenant_external_status_checked",
    "owner_tenant_membership_checked",
    "owner_account_status_checked",
    "owner_object_types_fully_checked",
    "owner_review_freshness_checked",
    "api_requested_access_token_version_approved_state_checked",
    "redirect_dns_control_checked",
    "redirect_endpoint_tls_checked",
    "redirect_endpoint_reachability_checked",
    "redirect_cors_checked",
    "redirect_content_security_policy_checked",
    "open_redirect_behavior_checked",
    "runtime_authorization_code_flow_checked",
    "runtime_pkce_s256_checked",
    "runtime_state_checked",
    "runtime_nonce_checked",
    "runtime_redirect_uri_match_checked",
    "runtime_browser_origin_checked",
    "runtime_no_client_secret_checked",
    "runtime_oidc_scopes_requested_checked",
    "runtime_api_scope_requested_checked",
    "live_delegated_consent_grant_checked",
    "service_principal_configuration_checked",
    "service_principal_assignment_required_checked",
    "application_tags_checked",
    "request_signature_verification_checked",
    "saml_metadata_checked",
    "service_management_reference_checked",
    "service_principal_lock_checked",
    "application_template_checked",
    "claims_policy_assignments_checked",
    "conditional_access_checked",
    "user_flow_checked",
    "user_flow_application_association_checked",
    "response_freshness_checked",
    "atomic_provider_snapshot_checked",
    "concurrent_provider_mutation_checked",
    "real_signed_api_token_checked",
    "application_mutation_performed",
    "owner_mutation_performed",
    "federated_identity_credential_mutation_performed",
    "service_principal_mutation_performed",
    "receipt_self_authenticating",
    "activation_ready",
)

_ZERO_COUNT_FIELDS = (
    "response_password_credential_count",
    "response_key_credential_count",
    "response_federated_identity_credential_count",
    "response_identifier_uri_count",
    "response_app_role_count",
    "response_oauth2_permission_scope_count",
    "response_preauthorized_application_count",
    "response_known_client_application_count",
    "response_add_in_count",
    "response_web_redirect_uri_count",
    "response_public_client_redirect_uri_count",
    "response_info_url_count",
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


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed_sha256(namespace: str, label: str, *values: bytes | str) -> str:
    encoded = [
        value.encode("utf-8") if isinstance(value, str) else value
        for value in (namespace, label, str(len(values)), *values)
    ]
    material = b"".join(
        str(len(value)).encode("ascii") + b":" + value for value in encoded
    )
    return hashlib.sha256(material).hexdigest()


def _evidence_sha256(label: str, *values: bytes | str) -> str:
    return _framed_sha256("engineer4me-step213-evidence-v1", label, *values)


def _identity_sha256(label: str, *values: str) -> str:
    return _framed_sha256("engineer4me-step213-identity-v1", label, *values)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraCallingClientRegistrationGraphProbeError(
                "Microsoft Graph response contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise EntraCallingClientRegistrationGraphProbeError(
        "Microsoft Graph response contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph response contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if (
                depth
                > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_NESTING_DEPTH
            ):
                raise EntraCallingClientRegistrationGraphProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if (
                depth
                > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_NESTING_DEPTH
            ):
                raise EntraCallingClientRegistrationGraphProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_CONTAINERS:
            raise EntraCallingClientRegistrationGraphProbeError(
                "Microsoft Graph response exceeds the structure limit"
            )


def _reject_explicit_null_metadata(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if any(
                key in current and current[key] is None
                for key in ("@odata.context", "@odata.type")
            ):
                raise EntraCallingClientRegistrationGraphProbeError(
                    "Microsoft Graph metadata cannot be explicitly null"
                )
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


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
    response: EntraCallingClientRegistrationGraphResponse,
    request: EntraCallingClientRegistrationGraphRequest,
) -> dict[str, Any]:
    if type(response) is not EntraCallingClientRegistrationGraphResponse:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph transport returned an invalid response"
        )
    try:
        response.validate()
    except ValueError:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph transport returned an invalid response"
        ) from None
    if (
        response.status_code != 200
        or response.final_url != request.url
        or not _content_type_is_json(response.content_type)
        or not response.body
        or len(response.body) > request.maximum_response_bytes
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph response failed the transport contract"
        )
    try:
        decoded = response.body.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph response must be UTF-8 JSON"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
    except EntraCallingClientRegistrationGraphProbeError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph response is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph response root must be an object"
        )
    _require_bounded_structure(parsed)
    _reject_explicit_null_metadata(parsed)
    return parsed


def _load_public_inputs(
    *,
    calling_client_registration_document: bytes,
    inventory_document: bytes,
) -> dict[str, Any]:
    """Recover public identities only after strict prerequisite reruns."""

    try:
        registration = json.loads(calling_client_registration_document.decode("utf-8"))[
            "registration"
        ]
        inventory = json.loads(inventory_document.decode("utf-8"))["inventory"]
        application = next(
            entry
            for entry in inventory["applications"]
            if entry["role"] == "calling_client"
        )
        inputs = {
            "tenant_id": registration["tenant_id"],
            "api_application_id": registration["api_application_id"],
            "api_application_object_id": registration["api_application_object_id"],
            "api_delegated_scope_id": registration["api_delegated_scope_id"],
            "calling_client_application_id": registration[
                "calling_client_application_id"
            ],
            "calling_client_application_object_id": registration[
                "calling_client_application_object_id"
            ],
            "display_name": registration["display_name"],
            "owner_object_ids": tuple(registration["owner_object_ids"]),
            "spa_redirect_uris": tuple(registration["spa_redirect_uris"]),
            "inventory_calling_client_application_id": application["application_id"],
            "inventory_calling_client_application_object_id": application[
                "application_object_id"
            ],
        }
    except (KeyError, StopIteration, TypeError, UnicodeDecodeError, ValueError):
        raise EntraCallingClientRegistrationGraphProbeError(
            "approved calling-client identities are invalid"
        ) from None
    identifiers = (
        inputs["tenant_id"],
        inputs["api_application_id"],
        inputs["api_application_object_id"],
        inputs["api_delegated_scope_id"],
        inputs["calling_client_application_id"],
        inputs["calling_client_application_object_id"],
        *inputs["owner_object_ids"],
    )
    if (
        any(not _canonical_uuid(value) for value in identifiers)
        or inputs["display_name"] != "Engineer4Me Web"
        or not 2 <= len(inputs["owner_object_ids"]) <= 5
        or len(set(inputs["owner_object_ids"])) != len(inputs["owner_object_ids"])
        or tuple(sorted(inputs["owner_object_ids"])) != inputs["owner_object_ids"]
        or not 1 <= len(inputs["spa_redirect_uris"]) <= 3
        or tuple(sorted(inputs["spa_redirect_uris"])) != inputs["spa_redirect_uris"]
        or inputs["inventory_calling_client_application_id"]
        != inputs["calling_client_application_id"]
        or inputs["inventory_calling_client_application_object_id"]
        != inputs["calling_client_application_object_id"]
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "approved calling-client identities do not match"
        )
    return inputs


def _request_plan(
    application_object_id: str,
) -> tuple[
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphRequest,
]:
    definitions = (
        (
            1,
            "calling_client_application",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES,
        ),
        (
            2,
            "owners",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES,
        ),
        (
            3,
            "federated_identity_credentials",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES,
        ),
    )
    return tuple(
        EntraCallingClientRegistrationGraphRequest(
            sequence=sequence,
            resource=resource,
            method="GET",
            url=entra_calling_client_registration_graph_url(
                application_object_id=application_object_id,
                resource=resource,
            ),
            headers=(("Accept", "application/json"), ("Accept-Encoding", "identity")),
            body=None,
            timeout_seconds=ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS,
            maximum_response_bytes=maximum_response_bytes,
            follow_redirects=False,
            maximum_retries=0,
            proxy_allowed=False,
        )
        for sequence, resource, maximum_response_bytes in definitions
    )


def _validate_application_response(
    parsed: dict[str, Any],
    *,
    inputs: dict[str, Any],
) -> _CallingClientApplicationResponse:
    try:
        raw_uuid_values = (
            parsed["id"],
            parsed["appId"],
            parsed["requiredResourceAccess"][0]["resourceAppId"],
            parsed["requiredResourceAccess"][0]["resourceAccess"][0]["id"],
        )
    except (KeyError, IndexError, TypeError):
        raw_uuid_values = ()
    if len(raw_uuid_values) != 4 or any(
        not _canonical_uuid(value) for value in raw_uuid_values
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph application UUIDs are not canonical"
        )
    try:
        raw_requested_access_token_version = parsed["api"][
            "requestedAccessTokenVersion"
        ]
    except (KeyError, TypeError):
        raw_requested_access_token_version = object()
    if raw_requested_access_token_version is not None and (
        type(raw_requested_access_token_version) is not int
        or raw_requested_access_token_version not in {1, 2}
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph requested access-token version is invalid"
        )
    try:
        model = _CallingClientApplicationResponse.model_validate_json(
            _canonical_bytes(parsed)
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph application response failed schema validation"
        ) from None
    access = model.required_resource_access[0]
    resource_access = access.resource_access[0]
    redirect_uris = tuple(model.spa.redirect_uris)
    normalized_redirect_uris = tuple(sorted(redirect_uris))
    if (
        str(model.id) != inputs["calling_client_application_object_id"]
        or str(model.app_id) != inputs["calling_client_application_id"]
        or len(set(redirect_uris)) != len(redirect_uris)
        or normalized_redirect_uris != inputs["spa_redirect_uris"]
        or access.resource_app_id != UUID(inputs["api_application_id"])
        or resource_access.id != UUID(inputs["api_delegated_scope_id"])
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph application does not match approved registration"
        )
    return model


def _validate_owners_response(
    parsed: dict[str, Any],
    *,
    owner_object_ids: tuple[str, ...],
) -> _OwnerCollectionResponse:
    raw_entries = parsed.get("value")
    if not isinstance(raw_entries, list) or any(
        not isinstance(entry, dict) or not _canonical_uuid(entry.get("id"))
        for entry in raw_entries
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph owner UUIDs are not canonical"
        )
    try:
        model = _OwnerCollectionResponse.model_validate_json(_canonical_bytes(parsed))
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph owner response failed schema validation"
        ) from None
    actual = tuple(sorted(str(entry.id) for entry in model.value))
    if len(set(actual)) != len(actual) or actual != owner_object_ids:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph owners do not match approved registration"
        )
    return model


def _validate_federated_identity_credentials_response(
    parsed: dict[str, Any],
    *,
    application_object_id: str,
) -> _FederatedIdentityCredentialCollectionResponse:
    try:
        model = _FederatedIdentityCredentialCollectionResponse.model_validate_json(
            _canonical_bytes(parsed)
        )
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph federated-credential response failed schema validation"
        ) from None
    metadata_origins = (
        "https://graph.microsoft.com",
        ENTRA_GRAPH_BASE_URL,
    )
    valid_contexts = {
        f"{origin}/$metadata#federatedIdentityCredentials{suffix}"
        for origin in metadata_origins
        for suffix in ("", "(id)")
    } | {
        (
            f"{origin}/$metadata#applications('{application_object_id}')/"
            f"federatedIdentityCredentials{suffix}"
        )
        for origin in metadata_origins
        for suffix in ("", "(id)")
    }
    if model.odata_context is not None and model.odata_context not in valid_contexts:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph federated-credential OData context is invalid"
        )
    return model


def _run_entra_calling_client_registration_graph_probe(
    *,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    transport: EntraCallingClientRegistrationGraphTransport,
    _live_transport_expected: bool,
) -> EntraCallingClientRegistrationGraphProbeReceipt:
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication readiness preview is required")
    for value, message in (
        (api_registration_document, "accepted API registration document must be bytes"),
        (
            calling_client_registration_document,
            "accepted calling-client registration document must be bytes",
        ),
        (inventory_document, "approved inventory document must be bytes"),
    ):
        if not isinstance(value, bytes):
            raise TypeError(message)
    for value, message in (
        (
            accepted_api_registration_document_sha256,
            "accepted API registration digest is required",
        ),
        (
            accepted_calling_client_registration_document_sha256,
            "accepted calling-client registration digest is required",
        ),
        (approved_inventory_document_sha256, "approved inventory digest is required"),
    ):
        if not _is_lower_sha256(value):
            raise TypeError(message)
    if (
        type(authorization)
        is not EntraCallingClientRegistrationGraphAuthorizationContract
    ):
        raise TypeError("Microsoft Graph calling-client authorization is required")
    try:
        authorization.__post_init__()
    except ValueError:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph calling-client authorization is invalid"
        ) from None
    if not callable(transport):
        raise TypeError(
            "an explicit Microsoft Graph calling-client transport is required"
        )
    if type(_live_transport_expected) is not bool:
        raise TypeError(
            "private Microsoft Graph calling-client transport mode is required"
        )

    try:
        render_authentication_readiness_preview(authentication_preview)
        client_receipt = load_entra_calling_client_registration_readiness(
            document=calling_client_registration_document,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
        )
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
        EntraCallingClientRegistrationReadinessError,
        EntraApplicationServicePrincipalInventoryReadinessError,
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "approved calling-client prerequisites are not valid"
        ) from None
    if not hmac.compare_digest(
        client_receipt.client_registration_document_sha256,
        accepted_calling_client_registration_document_sha256,
    ) or not hmac.compare_digest(
        inventory_receipt.inventory_document_sha256,
        approved_inventory_document_sha256,
    ):
        raise EntraCallingClientRegistrationGraphProbeError(
            "calling-client prerequisites do not match approved digests"
        )

    inputs = _load_public_inputs(
        calling_client_registration_document=calling_client_registration_document,
        inventory_document=inventory_document,
    )
    requests = _request_plan(inputs["calling_client_application_object_id"])
    transport_failed = False
    try:
        response_set = transport(requests)
    except Exception:  # noqa: BLE001 - injected transport is untrusted
        transport_failed = True
        response_set = None
    if transport_failed:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph calling-client transport failed"
        )
    if type(response_set) is not tuple or len(response_set) != 3:
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph transport returned an invalid response set"
        )

    parsed_responses: list[dict[str, Any]] = []
    responses: list[EntraCallingClientRegistrationGraphResponse] = []
    for request, response in zip(requests, response_set, strict=True):
        parsed = _parse_response_json(response, request)
        if _live_transport_expected and not response.live_https_attested:
            raise EntraCallingClientRegistrationGraphProbeError(
                "live Microsoft Graph calling-client provenance is not attested"
            )
        if not _live_transport_expected and response.live_https_attested:
            raise EntraCallingClientRegistrationGraphProbeError(
                "attested responses are not accepted by synthetic validation"
            )
        parsed_responses.append(parsed)
        responses.append(response)

    application = _validate_application_response(parsed_responses[0], inputs=inputs)
    owners = _validate_owners_response(
        parsed_responses[1],
        owner_object_ids=inputs["owner_object_ids"],
    )
    _validate_federated_identity_credentials_response(
        parsed_responses[2],
        application_object_id=inputs["calling_client_application_object_id"],
    )

    request_material = _canonical_bytes(
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
    expected_subset = _canonical_bytes(
        {
            "calling_client_application_id": inputs["calling_client_application_id"],
            "calling_client_application_object_id": inputs[
                "calling_client_application_object_id"
            ],
            "display_name": inputs["display_name"],
            "owner_object_ids": inputs["owner_object_ids"],
            "spa_redirect_uris": inputs["spa_redirect_uris"],
            "api_application_id": inputs["api_application_id"],
            "api_delegated_scope_id": inputs["api_delegated_scope_id"],
            "zero_security_surfaces": (
                "web_redirects",
                "public_client_redirects",
                "implicit_grants",
                "password_credentials",
                "key_credentials",
                "federated_identity_credentials",
                "identifier_uris",
                "app_roles",
                "oauth2_permission_scopes",
                "preauthorized_applications",
                "known_client_applications",
                "optional_claims",
                "token_encryption_key",
                "add_ins",
                "information_urls",
                "logo",
            ),
        }
    )
    owner_ids = tuple(sorted(str(entry.id) for entry in owners.value))
    redirect_uris = tuple(sorted(application.spa.redirect_uris))
    access = application.required_resource_access[0]
    resource_access = access.resource_access[0]
    live = _live_transport_expected
    return EntraCallingClientRegistrationGraphProbeReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCHEMA_VERSION,
        validation_scope=ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE,
        graph_api_version=ENTRA_GRAPH_API_VERSION,
        authorization_permission_type=authorization.permission_type,
        authorization_permission_name=authorization.permission_name,
        authorization_permission_id=authorization.permission_id,
        authorization_consent_requirement=authorization.consent_requirement,
        authorization_credential_origin=authorization.credential_origin,
        authorization_access_basis=authorization.access_basis,
        configuration_sha256=authentication_preview.configuration_sha256,
        api_registration_document_sha256=(
            inventory_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            client_receipt.client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        inventory_document_sha256=inventory_receipt.inventory_document_sha256,
        offline_calling_client_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_registration_readiness_receipt(
                client_receipt
            ).encode("utf-8")
        ).hexdigest(),
        offline_inventory_receipt_sha256=hashlib.sha256(
            render_entra_application_service_principal_inventory_readiness_receipt(
                inventory_receipt
            ).encode("utf-8")
        ).hexdigest(),
        expected_graph_subset_sha256=_evidence_sha256(
            "expected_graph_subset",
            expected_subset,
        ),
        request_plan_sha256=_evidence_sha256("request_plan", request_material),
        application_response_sha256=_evidence_sha256(
            "application_response_bytes",
            responses[0].body,
        ),
        owners_response_sha256=_evidence_sha256(
            "owners_response_bytes",
            responses[1].body,
        ),
        federated_identity_credentials_response_sha256=_evidence_sha256(
            "federated_identity_credentials_response_bytes",
            responses[2].body,
        ),
        tenant_id_sha256=_identity_sha256("tenant_id", inputs["tenant_id"]),
        api_application_id_sha256=_identity_sha256(
            "api_application_id",
            inputs["api_application_id"],
        ),
        api_application_object_id_sha256=_identity_sha256(
            "api_application_object_id",
            inputs["api_application_object_id"],
        ),
        api_delegated_scope_id_sha256=_identity_sha256(
            "api_delegated_scope_id",
            inputs["api_delegated_scope_id"],
        ),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            inputs["calling_client_application_id"],
        ),
        calling_client_application_object_id_sha256=_identity_sha256(
            "calling_client_application_object_id",
            inputs["calling_client_application_object_id"],
        ),
        owner_object_ids_sha256=_identity_sha256(
            "owner_object_ids",
            str(len(owner_ids)),
            *owner_ids,
        ),
        spa_redirect_uris_sha256=_identity_sha256(
            "spa_redirect_uris",
            str(len(redirect_uris)),
            *redirect_uris,
        ),
        required_resource_access_sha256=_identity_sha256(
            "required_resource_access",
            str(access.resource_app_id),
            str(resource_access.id),
            resource_access.type,
        ),
        registration_security_surfaces_sha256=_identity_sha256(
            "registration_security_surfaces",
            inputs["calling_client_application_id"],
            inputs["calling_client_application_object_id"],
            str(len(redirect_uris)),
            *redirect_uris,
            str(len(owner_ids)),
            *owner_ids,
            str(access.resource_app_id),
            str(resource_access.id),
            resource_access.type,
        ),
        request_count=len(requests),
        response_count=len(responses),
        application_response_bytes=len(responses[0].body),
        owners_response_bytes=len(responses[1].body),
        federated_identity_credentials_response_bytes=len(responses[2].body),
        total_response_bytes=sum(len(response.body) for response in responses),
        desired_spa_redirect_uri_count=len(redirect_uris),
        response_owner_count=len(owner_ids),
        desired_required_resource_access_count=1,
        response_password_credential_count=0,
        response_key_credential_count=0,
        response_federated_identity_credential_count=0,
        response_identifier_uri_count=0,
        response_app_role_count=0,
        response_oauth2_permission_scope_count=0,
        response_preauthorized_application_count=0,
        response_known_client_application_count=0,
        response_add_in_count=0,
        response_web_redirect_uri_count=0,
        response_public_client_redirect_uri_count=0,
        response_info_url_count=0,
        api_requested_access_token_version=(
            application.api.requested_access_token_version
        ),
        fallback_public_client_wire_form=(
            "null" if application.is_fallback_public_client is None else "false"
        ),
        device_only_auth_wire_form=(
            "null" if application.is_device_only_auth_supported is None else "false"
        ),
        accept_mapped_claims_wire_form=(
            "null" if application.api.accept_mapped_claims is None else "false"
        ),
        group_membership_claims_wire_form=(
            "null" if application.group_membership_claims is None else "None"
        ),
        **{field: True for field in _STRUCTURAL_TRUE_FIELDS},
        synthetic_transport_used=not live,
        live_https_transport_attested=live,
        provider_io_performed=live,
        provider_state_checked=live,
        source_authenticity_checked=live,
        live_application_registration_checked=live,
        live_spa_redirect_registration_checked=live,
        live_owner_inventory_checked=live,
        live_federated_identity_credential_inventory_checked=live,
        **{field: False for field in _DEFERRED_FALSE_FIELDS},
    )


def validate_entra_calling_client_registration_graph_probe(
    *,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    transport: EntraCallingClientRegistrationGraphTransport,
) -> EntraCallingClientRegistrationGraphProbeReceipt:
    """Validate deterministic responses; never emit live-provider evidence."""

    failed = False
    invalid_call = False
    interrupted = False
    terminated = False
    receipt = None
    try:
        receipt = _run_entra_calling_client_registration_graph_probe(
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
    except KeyboardInterrupt:
        interrupted = True
    except SystemExit:
        terminated = True
    except TypeError:
        invalid_call = True
    except BaseException:  # noqa: BLE001 - public sanitizing boundary
        failed = True
    finally:
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
        authorization = None
        transport = None
    if interrupted:
        receipt = None
        raise KeyboardInterrupt("Microsoft Graph calling-client probe interrupted")
    if terminated:
        receipt = None
        raise SystemExit("Microsoft Graph calling-client probe terminated")
    if invalid_call:
        receipt = None
        raise TypeError("Microsoft Graph calling-client probe inputs are invalid")
    if failed:
        receipt = None
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph calling-client probe failed"
        )
    return receipt


def probe_live_entra_calling_client_registration_graph(
    *,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    delegated_access_token: str,
) -> EntraCallingClientRegistrationGraphProbeReceipt:
    """Perform the sealed three-read HTTPS proof with one opaque token.

    The reads are sequential and non-atomic.  The first or second GET can
    complete before a later failure.  Such a failure emits no receipt and
    performs no provider mutation.
    """

    loader = None
    receipt = None
    failed = False
    invalid_call = False
    interrupted = False
    terminated = False
    try:
        loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
            delegated_access_token=delegated_access_token
        )
        delegated_access_token = None
        receipt = _run_entra_calling_client_registration_graph_probe(
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
            calling_client_registration_document=(calling_client_registration_document),
            accepted_calling_client_registration_document_sha256=(
                accepted_calling_client_registration_document_sha256
            ),
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
            authorization=authorization,
            transport=loader,
            _live_transport_expected=True,
        )
    except KeyboardInterrupt:
        interrupted = True
    except SystemExit:
        terminated = True
    except TypeError:
        invalid_call = True
    except BaseException:  # noqa: BLE001 - public sanitizing boundary
        failed = True
    finally:
        close_interrupted = False
        close_terminated = False
        close_failed = False
        if loader is not None:
            try:
                loader.close()
            except KeyboardInterrupt:
                close_interrupted = True
            except SystemExit:
                close_terminated = True
            except BaseException:  # noqa: BLE001
                close_failed = True
        interrupted = interrupted or close_interrupted
        terminated = terminated or close_terminated
        failed = failed or close_failed
        loader = None
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
        authorization = None
        delegated_access_token = None
    if interrupted:
        receipt = None
        raise KeyboardInterrupt("Microsoft Graph calling-client probe interrupted")
    if terminated:
        receipt = None
        raise SystemExit("Microsoft Graph calling-client probe terminated")
    if invalid_call:
        receipt = None
        raise TypeError("Microsoft Graph calling-client probe inputs are invalid")
    if failed:
        receipt = None
        raise EntraCallingClientRegistrationGraphProbeError(
            "Microsoft Graph calling-client probe failed"
        )
    return receipt


def render_entra_calling_client_registration_graph_probe_receipt(
    receipt: EntraCallingClientRegistrationGraphProbeReceipt,
) -> str:
    """Render canonical privacy-minimized proof evidence."""

    if type(receipt) is not EntraCallingClientRegistrationGraphProbeReceipt:
        raise TypeError("Microsoft Graph calling-client probe receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE",
    "ENTRA_GRAPH_API_VERSION",
    "ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID",
    "ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION",
    "ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_CONTAINERS",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_RESPONSE_NESTING_DEPTH",
    "MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TOTAL_RESPONSE_BYTES",
    "EntraCallingClientRegistrationGraphAuthorizationContract",
    "EntraCallingClientRegistrationGraphProbeError",
    "EntraCallingClientRegistrationGraphProbeReceipt",
    "probe_live_entra_calling_client_registration_graph",
    "render_entra_calling_client_registration_graph_probe_receipt",
    "validate_entra_calling_client_registration_graph_probe",
]
