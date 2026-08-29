"""Offline Microsoft Entra calling-client MSAL Browser integration readiness.

The contract reruns the complete Step 216 source-document chain and derives a
privacy-minimized future MSAL Browser integration profile.  It performs no
filesystem, package-manager, registry, browser, OAuth, DNS, TLS, HTTP, Graph,
Entra, environment, database, or process I/O and never claims installation or
runtime activation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import model_validator

from app.security.authentication_entra_calling_client_pkce_runtime_readiness import (
    load_entra_calling_client_pkce_runtime_readiness,
    render_entra_calling_client_pkce_runtime_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel

ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_readiness"
)
ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_readiness_receipt"
)
ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_MSAL_BROWSER_SOURCE = (
    "engineer4me_reviewed_msal_browser_v5_integration_security_profile"
)
ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE = (
    "offline_msal_browser_package_and_integration_desired_state_only"
)
ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE = (
    "engineer4me_entra_spa_msal_browser_v5_integration_controls_v1"
)

MSAL_BROWSER_PACKAGE_NAME = "@azure/msal-browser"
MSAL_BROWSER_REVIEWED_VERSION = "5.17.3"
MSAL_BROWSER_REVIEW_DATE = "2026-08-15"
MSAL_BROWSER_SUPPORTED_MAJOR = 5
MSAL_BROWSER_CONSUMPTION = "package_manager_and_bundler"
MSAL_BROWSER_APPLICATION_TYPE = "standard_public_client_application"
MSAL_BROWSER_INTERACTION_TYPE = "redirect_only"
MSAL_BROWSER_PROTOCOL_MODE = "AAD"
MSAL_BROWSER_CACHE_LOCATION = "sessionStorage"
MSAL_BROWSER_REDIRECT_HANDLER = "handleRedirectPromise"
MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT = "/auth/msal-redirect-bridge.js"
MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH = "@azure/msal-browser/redirect-bridge"
MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT = "broadcastResponseToMainFrame"
MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT = 1
MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS = 100
MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_BYTES = 4_096
MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_NESTING_DEPTH = 2
MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTAINERS = 8
_SHA256_HEX_LENGTH = 64
_UUID_TEXT = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


class EntraCallingClientMSALBrowserReadinessError(ValueError):
    """Sanitized failure at the offline MSAL Browser readiness boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientMSALBrowserDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_msal_browser_v5_integration_security_profile"]
    approved_pkce_runtime_control_document_sha256: str
    control_profile: Literal[
        "engineer4me_entra_spa_msal_browser_v5_integration_controls_v1"
    ]

    @model_validator(mode="after")
    def validate_digest(self) -> EntraCallingClientMSALBrowserDocument:
        if not _is_lower_sha256(self.approved_pkce_runtime_control_document_sha256):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALBrowserReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    control_profile: str
    package_name: str
    reviewed_package_version: str
    package_review_date: str
    package_consumption: str
    application_type: str
    interaction_type: str
    protocol_mode: str
    cache_location: str
    redirect_handler: str
    redirect_bridge_script: str
    redirect_bridge_package_subpath: str
    redirect_bridge_export: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    approved_redirect_endpoint_control_document_sha256: str
    redirect_endpoint_control_document_sha256: str
    approved_pkce_runtime_control_document_sha256: str
    pkce_runtime_control_document_sha256: str
    offline_pkce_runtime_readiness_receipt_sha256: str
    msal_browser_control_document_sha256: str
    tenant_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    api_application_id_sha256: str
    api_delegated_scope_id_sha256: str
    spa_redirect_uris_sha256: str
    authority_origin_sha256: str
    authority_sha256: str
    known_authorities_sha256: str
    msal_package_selection_profile_sha256: str
    msal_configuration_profile_sha256: str
    redirect_bridge_profile_sha256: str
    initialization_profile_sha256: str
    csp_and_endpoint_transition_profile_sha256: str
    reviewed_package_major: int
    desired_direct_dependency_count: int
    desired_redirect_endpoint_count: int
    known_authority_count: int
    current_callback_csp_directive_count: int
    required_transition_csp_directive_count: int
    reviewed_token_post_retry_count: int
    reviewed_token_post_retry_backoff_milliseconds: int
    step216_source_chain_revalidated: bool
    approved_pkce_runtime_digest_bound: bool
    exact_identity_projection_validated: bool
    exact_redirect_set_derived: bool
    exact_authority_derived_from_approved_issuer: bool
    reviewed_core_package_candidate_declared: bool
    reviewed_supported_major_declared: bool
    reviewed_candidate_release_retry_behavior_declared: bool
    step216_no_retry_conflict_detected: bool
    exact_version_specifier_required: bool
    semver_range_and_latest_tag_rejected: bool
    package_manager_and_bundler_required: bool
    cdn_consumption_rejected: bool
    complete_dependency_lock_required: bool
    lockfile_integrity_required: bool
    version_revalidation_before_install_required: bool
    standard_public_client_application_required: bool
    nested_application_authentication_rejected: bool
    redirect_interaction_only_required: bool
    popup_interaction_rejected: bool
    asynchronous_initialization_required: bool
    initialization_before_other_msal_apis_required: bool
    handle_redirect_promise_required: bool
    redirect_handling_before_account_or_token_use_required: bool
    exact_client_id_binding_required: bool
    exact_tenant_specific_authority_required: bool
    exact_known_authority_required: bool
    exact_registered_redirect_selection_required: bool
    aad_protocol_mode_required: bool
    session_storage_cache_required: bool
    deprecated_temporary_cache_override_rejected: bool
    deprecated_cookie_auth_state_rejected: bool
    pii_logging_forbidden: bool
    raw_token_and_account_logging_forbidden: bool
    dedicated_redirect_bridge_document_required: bool
    same_origin_external_bridge_script_required: bool
    redirect_bridge_inline_script_rejected: bool
    redirect_bridge_router_and_business_logic_rejected: bool
    redirect_bridge_package_subpath_required: bool
    broadcast_response_to_main_frame_required: bool
    redirect_bridge_coop_headers_forbidden: bool
    callback_document_transition_required: bool
    successor_endpoint_proof_required: bool
    step216_csp_gap_remains_blocking: bool
    offline_integration_constraints_validated: bool
    package_registry_metadata_checked: bool
    package_version_current_checked: bool
    package_tarball_downloaded: bool
    package_tarball_integrity_checked: bool
    package_signature_or_provenance_checked: bool
    package_license_source_checked: bool
    package_security_advisories_checked: bool
    reviewed_candidate_approved_for_integration: bool
    reviewed_candidate_compatible_with_step216: bool
    package_selection_ready: bool
    package_manager_selected: bool
    package_registry_or_mirror_selected: bool
    dependency_lockfile_created: bool
    dependency_lockfile_integrity_checked: bool
    transitive_dependency_graph_checked: bool
    frontend_source_tree_present_checked: bool
    frontend_framework_selected: bool
    frontend_build_tool_selected: bool
    msal_react_selected: bool
    msal_angular_selected: bool
    package_installed: bool
    installed_package_version_checked: bool
    production_bundle_contains_reviewed_package: bool
    production_bundle_integrity_checked: bool
    source_map_exposure_checked: bool
    msal_configuration_implemented: bool
    msal_initialization_executed: bool
    redirect_handler_executed: bool
    dedicated_redirect_bridge_deployed: bool
    redirect_bridge_script_integrity_checked: bool
    revised_csp_deployed: bool
    revised_callback_endpoint_reproved: bool
    browser_csp_enforcement_checked: bool
    authorization_server_discovery_checked: bool
    token_endpoint_cors_checked: bool
    runtime_redirect_uri_match_checked: bool
    runtime_browser_origin_checked: bool
    runtime_no_client_secret_checked: bool
    runtime_oidc_scopes_requested_checked: bool
    runtime_api_scope_requested_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_state_checked: bool
    runtime_nonce_checked: bool
    authorization_response_received: bool
    authorization_code_redeemed: bool
    id_token_validated: bool
    access_token_validated: bool
    real_engineer4me_api_call_checked: bool
    real_customer_user_journey_checked: bool
    live_user_flow_association_checked: bool
    live_delegated_consent_checked: bool
    provider_policy_checked: bool
    conditional_access_checked: bool
    mfa_checked: bool
    terms_of_use_checked: bool
    provider_io_performed: bool
    browser_io_performed: bool
    network_io_performed: bool
    filesystem_io_performed: bool
    package_manager_process_performed: bool
    application_configuration_mutation_performed: bool
    identity_provider_configuration_mutation_performed: bool
    endpoint_configuration_mutation_performed: bool
    receipt_self_authenticating: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = tuple(
            getattr(self, field)
            for field in self.__dataclass_fields__
            if field.endswith("_sha256")
        )
        strings = tuple(getattr(self, field) for field in _PUBLIC_STRING_FIELDS)
        counts = tuple(getattr(self, field) for field in _COUNT_FIELDS)
        structural = tuple(getattr(self, field) for field in _STRUCTURAL_TRUE_FIELDS)
        deferred = tuple(getattr(self, field) for field in _DEFERRED_FALSE_FIELDS)
        if (
            any(type(value) is not str for value in strings)
            or self.receipt_type != ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_MSAL_BROWSER_SOURCE
            or self.validation_scope != ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE
            or self.control_profile != ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE
            or self.package_name != MSAL_BROWSER_PACKAGE_NAME
            or self.reviewed_package_version != MSAL_BROWSER_REVIEWED_VERSION
            or self.package_review_date != MSAL_BROWSER_REVIEW_DATE
            or self.package_consumption != MSAL_BROWSER_CONSUMPTION
            or self.application_type != MSAL_BROWSER_APPLICATION_TYPE
            or self.interaction_type != MSAL_BROWSER_INTERACTION_TYPE
            or self.protocol_mode != MSAL_BROWSER_PROTOCOL_MODE
            or self.cache_location != MSAL_BROWSER_CACHE_LOCATION
            or self.redirect_handler != MSAL_BROWSER_REDIRECT_HANDLER
            or self.redirect_bridge_script != MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT
            or self.redirect_bridge_package_subpath
            != MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH
            or self.redirect_bridge_export != MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_redirect_endpoint_control_document_sha256,
                self.redirect_endpoint_control_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_pkce_runtime_control_document_sha256,
                self.pkce_runtime_control_document_sha256,
            )
            or any(type(value) is not int for value in counts)
            or self.reviewed_package_major != MSAL_BROWSER_SUPPORTED_MAJOR
            or self.desired_direct_dependency_count != 1
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or self.known_authority_count != 1
            or self.current_callback_csp_directive_count != 6
            or self.required_transition_csp_directive_count != 7
            or self.reviewed_token_post_retry_count
            != MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
            or self.reviewed_token_post_retry_backoff_milliseconds
            != MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS
            or any(value is not True for value in structural)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra MSAL Browser readiness receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "control_profile",
    "package_name",
    "reviewed_package_version",
    "package_review_date",
    "package_consumption",
    "application_type",
    "interaction_type",
    "protocol_mode",
    "cache_location",
    "redirect_handler",
    "redirect_bridge_script",
    "redirect_bridge_package_subpath",
    "redirect_bridge_export",
)

_COUNT_FIELDS = (
    "reviewed_package_major",
    "desired_direct_dependency_count",
    "desired_redirect_endpoint_count",
    "known_authority_count",
    "current_callback_csp_directive_count",
    "required_transition_csp_directive_count",
    "reviewed_token_post_retry_count",
    "reviewed_token_post_retry_backoff_milliseconds",
)

_STRUCTURAL_TRUE_FIELDS = (
    "step216_source_chain_revalidated",
    "approved_pkce_runtime_digest_bound",
    "exact_identity_projection_validated",
    "exact_redirect_set_derived",
    "exact_authority_derived_from_approved_issuer",
    "reviewed_core_package_candidate_declared",
    "reviewed_supported_major_declared",
    "reviewed_candidate_release_retry_behavior_declared",
    "step216_no_retry_conflict_detected",
    "exact_version_specifier_required",
    "semver_range_and_latest_tag_rejected",
    "package_manager_and_bundler_required",
    "cdn_consumption_rejected",
    "complete_dependency_lock_required",
    "lockfile_integrity_required",
    "version_revalidation_before_install_required",
    "standard_public_client_application_required",
    "nested_application_authentication_rejected",
    "redirect_interaction_only_required",
    "popup_interaction_rejected",
    "asynchronous_initialization_required",
    "initialization_before_other_msal_apis_required",
    "handle_redirect_promise_required",
    "redirect_handling_before_account_or_token_use_required",
    "exact_client_id_binding_required",
    "exact_tenant_specific_authority_required",
    "exact_known_authority_required",
    "exact_registered_redirect_selection_required",
    "aad_protocol_mode_required",
    "session_storage_cache_required",
    "deprecated_temporary_cache_override_rejected",
    "deprecated_cookie_auth_state_rejected",
    "pii_logging_forbidden",
    "raw_token_and_account_logging_forbidden",
    "dedicated_redirect_bridge_document_required",
    "same_origin_external_bridge_script_required",
    "redirect_bridge_inline_script_rejected",
    "redirect_bridge_router_and_business_logic_rejected",
    "redirect_bridge_package_subpath_required",
    "broadcast_response_to_main_frame_required",
    "redirect_bridge_coop_headers_forbidden",
    "callback_document_transition_required",
    "successor_endpoint_proof_required",
    "step216_csp_gap_remains_blocking",
    "offline_integration_constraints_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "package_registry_metadata_checked",
    "package_version_current_checked",
    "package_tarball_downloaded",
    "package_tarball_integrity_checked",
    "package_signature_or_provenance_checked",
    "package_license_source_checked",
    "package_security_advisories_checked",
    "reviewed_candidate_approved_for_integration",
    "reviewed_candidate_compatible_with_step216",
    "package_selection_ready",
    "package_manager_selected",
    "package_registry_or_mirror_selected",
    "dependency_lockfile_created",
    "dependency_lockfile_integrity_checked",
    "transitive_dependency_graph_checked",
    "frontend_source_tree_present_checked",
    "frontend_framework_selected",
    "frontend_build_tool_selected",
    "msal_react_selected",
    "msal_angular_selected",
    "package_installed",
    "installed_package_version_checked",
    "production_bundle_contains_reviewed_package",
    "production_bundle_integrity_checked",
    "source_map_exposure_checked",
    "msal_configuration_implemented",
    "msal_initialization_executed",
    "redirect_handler_executed",
    "dedicated_redirect_bridge_deployed",
    "redirect_bridge_script_integrity_checked",
    "revised_csp_deployed",
    "revised_callback_endpoint_reproved",
    "browser_csp_enforcement_checked",
    "authorization_server_discovery_checked",
    "token_endpoint_cors_checked",
    "runtime_redirect_uri_match_checked",
    "runtime_browser_origin_checked",
    "runtime_no_client_secret_checked",
    "runtime_oidc_scopes_requested_checked",
    "runtime_api_scope_requested_checked",
    "runtime_pkce_s256_checked",
    "runtime_state_checked",
    "runtime_nonce_checked",
    "authorization_response_received",
    "authorization_code_redeemed",
    "id_token_validated",
    "access_token_validated",
    "real_engineer4me_api_call_checked",
    "real_customer_user_journey_checked",
    "live_user_flow_association_checked",
    "live_delegated_consent_checked",
    "provider_policy_checked",
    "conditional_access_checked",
    "mfa_checked",
    "terms_of_use_checked",
    "provider_io_performed",
    "browser_io_performed",
    "network_io_performed",
    "filesystem_io_performed",
    "package_manager_process_performed",
    "application_configuration_mutation_performed",
    "identity_provider_configuration_mutation_performed",
    "endpoint_configuration_mutation_performed",
    "receipt_self_authenticating",
    "activation_ready",
)


def _is_lower_sha256(value: object) -> bool:
    return bool(
        type(value) is str
        and re.fullmatch(rf"[0-9a-f]{{{_SHA256_HEX_LENGTH}}}", value) is not None
    )


def _is_canonical_uuid(value: object) -> bool:
    return bool(type(value) is str and _UUID_TEXT.fullmatch(value) is not None)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed_sha256(label: str, *values: bytes | str) -> str:
    digest = hashlib.sha256()
    for value in ("engineer4me-step217-v1", label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise ValueError("non-finite number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise ValueError("non-finite number")
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTAINERS:
            raise ValueError("structure limit")


def _require_exact_document_scalars(parsed: dict[str, Any]) -> None:
    expected = {
        "document_type",
        "schema_version",
        "source",
        "approved_pkce_runtime_control_document_sha256",
        "control_profile",
    }
    if (
        set(parsed) != expected
        or any(
            type(parsed.get(field)) is not str
            for field in expected - {"schema_version"}
        )
        or type(parsed.get("schema_version")) is not int
    ):
        raise ValueError("document contract")


def _validated_projection(
    *,
    authentication_preview: AuthenticationReadinessPreview,
    calling_client_registration_document: bytes,
) -> dict[str, object]:
    try:
        registration = json.loads(calling_client_registration_document.decode("utf-8"))[
            "registration"
        ]
        tenant_id = registration["tenant_id"]
        api_application_id = registration["api_application_id"]
        api_scope_id = registration["api_delegated_scope_id"]
        calling_client_application_id = registration["calling_client_application_id"]
        calling_client_object_id = registration["calling_client_application_object_id"]
        redirect_uris = tuple(registration["spa_redirect_uris"])
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise ValueError("validated registration projection unavailable") from None
    if (
        any(
            not _is_canonical_uuid(value)
            for value in (
                tenant_id,
                api_application_id,
                api_scope_id,
                calling_client_application_id,
                calling_client_object_id,
            )
        )
        or redirect_uris != tuple(sorted(redirect_uris))
        or len(redirect_uris) != len(set(redirect_uris))
        or not 1 <= len(redirect_uris) <= 3
        or registration["desired_browser_flow"] != "authorization_code_pkce"
        or registration["desired_pkce_method"] != "S256"
        or registration["desired_client_authentication_method"] != "none"
        or authentication_preview.microsoft_entra_tenant_id != tenant_id
        or authentication_preview.microsoft_entra_api_application_id
        != api_application_id
        or authentication_preview.microsoft_entra_calling_client_application_id
        != calling_client_application_id
    ):
        raise ValueError("validated registration projection mismatch")
    issuer = authentication_preview.issuer
    try:
        parsed = urlsplit(issuer)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("approved issuer is invalid") from None
    if (
        type(issuer) is not str
        or parsed.scheme != "https"
        or type(hostname) is not str
        or hostname != hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc != hostname
        or parsed.path != f"/{tenant_id}/v2.0"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("approved issuer cannot derive a canonical authority")
    origin = f"https://{hostname}"
    return {
        "tenant_id": tenant_id,
        "api_application_id": api_application_id,
        "api_scope_id": api_scope_id,
        "calling_client_application_id": calling_client_application_id,
        "calling_client_object_id": calling_client_object_id,
        "redirect_uris": redirect_uris,
        "authority_origin": origin,
        "authority_hostname": hostname,
        "authority": f"{origin}/{tenant_id}",
    }


def _package_selection_profile() -> bytes:
    return _canonical_bytes(
        {
            "package": MSAL_BROWSER_PACKAGE_NAME,
            "reviewed_candidate_version": MSAL_BROWSER_REVIEWED_VERSION,
            "review_date": MSAL_BROWSER_REVIEW_DATE,
            "exact_version_specifier": MSAL_BROWSER_REVIEWED_VERSION,
            "allowed_consumption": MSAL_BROWSER_CONSUMPTION,
            "cdn_allowed": False,
            "semver_range_allowed": False,
            "latest_tag_allowed": False,
            "package_manager_selection_checked": False,
            "registry_or_mirror_selection_checked": False,
            "full_dependency_lock_required": True,
            "lockfile_integrity_required": True,
            "version_revalidation_before_install_required": True,
            "reviewed_token_post_transport_retry_count": (
                MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
            ),
            "reviewed_token_post_transport_retry_backoff_milliseconds": (
                MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS
            ),
            "step216_required_token_post_retry_count": 0,
            "step216_retry_compatible": False,
            "candidate_approved_for_integration": False,
            "framework_wrapper": "none_until_frontend_framework_selected",
        }
    )


def _msal_configuration_profile(projection: dict[str, object]) -> bytes:
    return _canonical_bytes(
        {
            "application_type": MSAL_BROWSER_APPLICATION_TYPE,
            "auth": {
                "clientId": projection["calling_client_application_id"],
                "authority": projection["authority"],
                "knownAuthorities": [projection["authority_hostname"]],
                "permittedRedirectUris": list(projection["redirect_uris"]),
                "redirectUriSelection": "exact_registered_value_per_request",
                "postLogoutRedirectUri": "not_selected",
            },
            "cache": {
                "cacheLocation": MSAL_BROWSER_CACHE_LOCATION,
                "temporaryCacheLocationOverrideAllowed": False,
                "storeAuthStateInCookie": False,
                "secureCookiesConfigured": False,
            },
            "system": {
                "protocolMode": MSAL_BROWSER_PROTOCOL_MODE,
                "allowRedirectInIframe": False,
                "piiLoggingEnabled": False,
                "nestedApplicationAuthenticationAllowed": False,
            },
            "runtimeImplementationChecked": False,
        }
    )


def _redirect_bridge_profile(projection: dict[str, object]) -> bytes:
    return _canonical_bytes(
        {
            "redirectUris": list(projection["redirect_uris"]),
            "dedicatedDocumentRequired": True,
            "externalBridgeScript": MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT,
            "packageSubpath": MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH,
            "requiredExport": MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT,
            "scriptMustBeSameOriginRootRelative": True,
            "inlineScriptAllowed": False,
            "routerAllowed": False,
            "businessLogicAllowed": False,
            "additionalJavaScriptAllowed": False,
            "crossOriginOpenerPolicyHeaderAllowed": False,
            "crossOriginOpenerPolicyReportOnlyHeaderAllowed": False,
            "callbackDocumentTransitionRequired": True,
            "successorEndpointProofRequired": True,
            "deployed": False,
        }
    )


def _initialization_profile() -> bytes:
    return _canonical_bytes(
        {
            "applicationType": MSAL_BROWSER_APPLICATION_TYPE,
            "initializeMustResolveBeforeOtherApis": True,
            "interactionType": MSAL_BROWSER_INTERACTION_TYPE,
            "popupApisAllowed": False,
            "redirectHandler": MSAL_BROWSER_REDIRECT_HANDLER,
            "redirectHandlerBeforeAccountOrTokenUse": True,
            "rawRedirectHashOverrideAllowed": False,
            "rawTokenOrAccountLoggingAllowed": False,
            "executed": False,
        }
    )


def _csp_and_endpoint_transition_profile(projection: dict[str, object]) -> bytes:
    return _canonical_bytes(
        {
            "step216CurrentDirectiveCount": 6,
            "tokenExchangeIntermediateDirectiveCount": 7,
            "authorityOrigin": projection["authority_origin"],
            "connectSrcRequired": ["'self'", projection["authority_origin"]],
            "crossOriginOpenerPolicyHeaderAllowedOnRedirectBridge": False,
            "redirectBridgeDocumentChangeRequired": True,
            "finalApiOriginPolicyChecked": False,
            "deploymentChecked": False,
            "successorEndpointProofChecked": False,
        }
    )


def _load_internal(
    *,
    document: bytes,
    pkce_runtime_control_document: bytes,
    approved_pkce_runtime_control_document_sha256: str,
    redirect_endpoint_control_document: bytes,
    approved_redirect_endpoint_control_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientMSALBrowserReadinessReceipt:
    byte_inputs = (
        document,
        pkce_runtime_control_document,
        redirect_endpoint_control_document,
        api_registration_document,
        calling_client_registration_document,
        inventory_document,
    )
    digest_inputs = (
        approved_pkce_runtime_control_document_sha256,
        approved_redirect_endpoint_control_document_sha256,
        accepted_api_registration_document_sha256,
        accepted_calling_client_registration_document_sha256,
        approved_inventory_document_sha256,
    )
    if any(type(value) is not bytes for value in byte_inputs):
        raise _ArgumentTypeError("documents must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise _ArgumentTypeError("authentication preview is required")
    if any(not _is_lower_sha256(value) for value in digest_inputs):
        raise _ArgumentTypeError("approved digests are required")

    pkce_receipt = load_entra_calling_client_pkce_runtime_readiness(
        document=pkce_runtime_control_document,
        redirect_endpoint_control_document=redirect_endpoint_control_document,
        approved_redirect_endpoint_control_document_sha256=(
            approved_redirect_endpoint_control_document_sha256
        ),
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
    if not hmac.compare_digest(
        pkce_receipt.pkce_runtime_control_document_sha256,
        approved_pkce_runtime_control_document_sha256,
    ):
        raise ValueError("PKCE runtime-control digest mismatch")

    if (
        not document
        or len(document) > MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_BYTES
    ):
        raise ValueError("document byte boundary")
    parsed = json.loads(
        document.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )
    if not isinstance(parsed, dict):
        raise ValueError("document root")  # noqa: TRY004 - untrusted JSON shape
    _require_bounded_structure(parsed)
    _require_exact_document_scalars(parsed)
    canonical_document = _canonical_bytes(parsed)
    validated = EntraCallingClientMSALBrowserDocument.model_validate_json(
        canonical_document
    )
    if not hmac.compare_digest(
        validated.approved_pkce_runtime_control_document_sha256,
        approved_pkce_runtime_control_document_sha256,
    ):
        raise ValueError("approved evidence mismatch")

    projection = _validated_projection(
        authentication_preview=authentication_preview,
        calling_client_registration_document=calling_client_registration_document,
    )
    package_profile = _package_selection_profile()
    config_profile = _msal_configuration_profile(projection)
    bridge_profile = _redirect_bridge_profile(projection)
    initialization_profile = _initialization_profile()
    transition_profile = _csp_and_endpoint_transition_profile(projection)
    true_values = {field: True for field in _STRUCTURAL_TRUE_FIELDS}
    false_values = {field: False for field in _DEFERRED_FALSE_FIELDS}
    return EntraCallingClientMSALBrowserReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE,
        control_profile=validated.control_profile,
        package_name=MSAL_BROWSER_PACKAGE_NAME,
        reviewed_package_version=MSAL_BROWSER_REVIEWED_VERSION,
        package_review_date=MSAL_BROWSER_REVIEW_DATE,
        package_consumption=MSAL_BROWSER_CONSUMPTION,
        application_type=MSAL_BROWSER_APPLICATION_TYPE,
        interaction_type=MSAL_BROWSER_INTERACTION_TYPE,
        protocol_mode=MSAL_BROWSER_PROTOCOL_MODE,
        cache_location=MSAL_BROWSER_CACHE_LOCATION,
        redirect_handler=MSAL_BROWSER_REDIRECT_HANDLER,
        redirect_bridge_script=MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT,
        redirect_bridge_package_subpath=MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH,
        redirect_bridge_export=MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT,
        configuration_sha256=pkce_receipt.configuration_sha256,
        api_registration_document_sha256=pkce_receipt.api_registration_document_sha256,
        calling_client_registration_document_sha256=(
            pkce_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=(
            pkce_receipt.approved_inventory_document_sha256
        ),
        inventory_document_sha256=pkce_receipt.inventory_document_sha256,
        approved_redirect_endpoint_control_document_sha256=(
            pkce_receipt.approved_redirect_endpoint_control_document_sha256
        ),
        redirect_endpoint_control_document_sha256=(
            pkce_receipt.redirect_endpoint_control_document_sha256
        ),
        approved_pkce_runtime_control_document_sha256=(
            approved_pkce_runtime_control_document_sha256
        ),
        pkce_runtime_control_document_sha256=(
            pkce_receipt.pkce_runtime_control_document_sha256
        ),
        offline_pkce_runtime_readiness_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_pkce_runtime_readiness_receipt(
                pkce_receipt
            ).encode("utf-8")
        ).hexdigest(),
        msal_browser_control_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=_framed_sha256("tenant_id", str(projection["tenant_id"])),
        calling_client_application_id_sha256=_framed_sha256(
            "calling_client_application_id",
            str(projection["calling_client_application_id"]),
        ),
        calling_client_application_object_id_sha256=_framed_sha256(
            "calling_client_application_object_id",
            str(projection["calling_client_object_id"]),
        ),
        api_application_id_sha256=_framed_sha256(
            "api_application_id", str(projection["api_application_id"])
        ),
        api_delegated_scope_id_sha256=_framed_sha256(
            "api_delegated_scope_id", str(projection["api_scope_id"])
        ),
        spa_redirect_uris_sha256=_framed_sha256(
            "spa_redirect_uris",
            str(len(projection["redirect_uris"])),
            *projection["redirect_uris"],
        ),
        authority_origin_sha256=_framed_sha256(
            "authority_origin", str(projection["authority_origin"])
        ),
        authority_sha256=_framed_sha256("authority", str(projection["authority"])),
        known_authorities_sha256=_framed_sha256(
            "known_authorities", str(projection["authority_hostname"])
        ),
        msal_package_selection_profile_sha256=_framed_sha256(
            "msal_package_selection_profile", package_profile
        ),
        msal_configuration_profile_sha256=_framed_sha256(
            "msal_configuration_profile", config_profile
        ),
        redirect_bridge_profile_sha256=_framed_sha256(
            "redirect_bridge_profile", bridge_profile
        ),
        initialization_profile_sha256=_framed_sha256(
            "initialization_profile", initialization_profile
        ),
        csp_and_endpoint_transition_profile_sha256=_framed_sha256(
            "csp_and_endpoint_transition_profile", transition_profile
        ),
        reviewed_package_major=MSAL_BROWSER_SUPPORTED_MAJOR,
        desired_direct_dependency_count=1,
        desired_redirect_endpoint_count=len(projection["redirect_uris"]),
        known_authority_count=1,
        current_callback_csp_directive_count=6,
        required_transition_csp_directive_count=7,
        reviewed_token_post_retry_count=(MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT),
        reviewed_token_post_retry_backoff_milliseconds=(
            MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS
        ),
        **true_values,
        **false_values,
    )


def _scrub_exception_graph(error: BaseException) -> tuple[bool, bool]:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    interrupted = False
    terminated = False
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted = interrupted or isinstance(current, KeyboardInterrupt)
        terminated = terminated or isinstance(current, SystemExit)
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        try:
            children = current.exceptions
        except (AttributeError, TypeError):
            children = ()
        if type(children) is tuple:
            pending.extend(
                child for child in children if isinstance(child, BaseException)
            )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001,S110  # pragma: no cover
            pass
    return interrupted, terminated


def load_entra_calling_client_msal_browser_readiness(
    *,
    document: bytes,
    pkce_runtime_control_document: bytes,
    approved_pkce_runtime_control_document_sha256: str,
    redirect_endpoint_control_document: bytes,
    approved_redirect_endpoint_control_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientMSALBrowserReadinessReceipt:
    """Validate the offline MSAL Browser plan without package or provider I/O."""

    result = None
    error = None
    invalid_call = False
    failed = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document=document,
            pkce_runtime_control_document=pkce_runtime_control_document,
            approved_pkce_runtime_control_document_sha256=(
                approved_pkce_runtime_control_document_sha256
            ),
            redirect_endpoint_control_document=redirect_endpoint_control_document,
            approved_redirect_endpoint_control_document_sha256=(
                approved_redirect_endpoint_control_document_sha256
            ),
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
    except _ArgumentTypeError as caught:
        error = caught
        invalid_call = True
    except BaseException as caught:  # noqa: BLE001 - sanitize public boundary
        error = caught
        failed = True
    finally:
        if error is not None:
            interrupted, terminated = _scrub_exception_graph(error)
        error = None
        document = None
        pkce_runtime_control_document = None
        approved_pkce_runtime_control_document_sha256 = None
        redirect_endpoint_control_document = None
        approved_redirect_endpoint_control_document_sha256 = None
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
    if interrupted:
        result = None
        raise KeyboardInterrupt("Entra MSAL Browser readiness interrupted")
    if terminated:
        result = None
        raise SystemExit("Entra MSAL Browser readiness terminated")
    if invalid_call:
        result = None
        raise TypeError("Entra MSAL Browser readiness inputs are invalid")
    if failed or result is None:
        result = None
        raise EntraCallingClientMSALBrowserReadinessError(
            "Entra MSAL Browser readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_browser_readiness_receipt(
    receipt: EntraCallingClientMSALBrowserReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized structural readiness evidence."""

    if type(receipt) is not EntraCallingClientMSALBrowserReadinessReceipt:
        raise TypeError("Entra MSAL Browser readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_CONTROL_PROFILE",
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_SCOPE",
    "ENTRA_CALLING_CLIENT_MSAL_BROWSER_SOURCE",
    "MAX_ENTRA_CALLING_CLIENT_MSAL_BROWSER_DOCUMENT_BYTES",
    "MSAL_BROWSER_APPLICATION_TYPE",
    "MSAL_BROWSER_CACHE_LOCATION",
    "MSAL_BROWSER_CONSUMPTION",
    "MSAL_BROWSER_INTERACTION_TYPE",
    "MSAL_BROWSER_PACKAGE_NAME",
    "MSAL_BROWSER_PROTOCOL_MODE",
    "MSAL_BROWSER_REDIRECT_BRIDGE_EXPORT",
    "MSAL_BROWSER_REDIRECT_BRIDGE_PACKAGE_SUBPATH",
    "MSAL_BROWSER_REDIRECT_BRIDGE_SCRIPT",
    "MSAL_BROWSER_REDIRECT_HANDLER",
    "MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS",
    "MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT",
    "MSAL_BROWSER_REVIEWED_VERSION",
    "MSAL_BROWSER_REVIEW_DATE",
    "MSAL_BROWSER_SUPPORTED_MAJOR",
    "EntraCallingClientMSALBrowserReadinessError",
    "EntraCallingClientMSALBrowserReadinessReceipt",
    "load_entra_calling_client_msal_browser_readiness",
    "render_entra_calling_client_msal_browser_readiness_receipt",
]
