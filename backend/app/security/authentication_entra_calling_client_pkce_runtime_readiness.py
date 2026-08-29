"""Offline Microsoft Entra SPA authorization-code/PKCE runtime readiness.

The contract re-runs the complete Step 214 redirect-control source chain, then
derives a privacy-minimized future authorization transaction plan from the
approved tenant, calling-client registration, API scope, and redirect URIs.
It performs no browser, OAuth, DNS, TLS, HTTP, Microsoft Graph, filesystem,
environment, database, or process I/O.

Step 215 intentionally proves an exact six-directive callback CSP with no
cross-origin ``connect-src``.  A browser token exchange therefore requires a
separately approved CSP transition and a new endpoint proof.  This module
records that fail-closed dependency and never claims runtime activation.
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

from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    load_entra_calling_client_redirect_endpoint_readiness,
    render_entra_calling_client_redirect_endpoint_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel

ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_spa_pkce_runtime_readiness"
)
ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_spa_pkce_runtime_readiness_receipt"
)
ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SOURCE = (
    "engineer4me_reviewed_spa_authorization_code_pkce_runtime_security_profile"
)
ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE = (
    "offline_spa_authorization_code_pkce_runtime_security_desired_state_only"
)
ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE = (
    "engineer4me_entra_spa_authorization_code_pkce_runtime_controls_v1"
)

FUTURE_AUTHORIZATION_RESPONSE_TYPE = "code"
FUTURE_AUTHORIZATION_RESPONSE_MODE = "query"
FUTURE_TOKEN_GRANT_TYPE = "authorization_code"
FUTURE_PKCE_METHOD = "S256"
FUTURE_TRANSACTION_STORAGE = "sessionStorage"
FUTURE_AUTHORIZATION_NAVIGATION_MODE = "top_level_same_window"
FUTURE_TOKEN_REQUEST_METHOD = "POST"
FUTURE_TOKEN_REQUEST_CONTENT_TYPE = "application/x-www-form-urlencoded"
FUTURE_TOKEN_FETCH_CREDENTIALS_MODE = "omit"
FUTURE_TOKEN_FETCH_REDIRECT_MODE = "error"
FUTURE_TOKEN_FETCH_CACHE_MODE = "no-store"
FUTURE_OIDC_SCOPE_ORDER = ("openid", "profile", "offline_access")
FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS = 256
FUTURE_STATE_MINIMUM_ENTROPY_BITS = 128
FUTURE_NONCE_MINIMUM_ENTROPY_BITS = 128
FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH = 43
FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH = 128
FUTURE_STATE_MAXIMUM_LENGTH = 512
FUTURE_NONCE_MAXIMUM_LENGTH = 512
FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS = 600
FUTURE_CALLBACK_QUERY_MAXIMUM_BYTES = 16_384
FUTURE_AUTHORIZATION_CODE_MAXIMUM_BYTES = 8_192
FUTURE_TOKEN_REQUEST_MAXIMUM_BYTES = 16_384
FUTURE_TOKEN_RESPONSE_MAXIMUM_BYTES = 65_536
MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_BYTES = 4_096
MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_NESTING_DEPTH = 2
MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTAINERS = 8
_SHA256_HEX_LENGTH = 64
_UUID_TEXT = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


class EntraCallingClientPKCERuntimeReadinessError(ValueError):
    """Sanitized failure at the offline PKCE readiness boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientPKCERuntimeDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_spa_pkce_runtime_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_reviewed_spa_authorization_code_pkce_runtime_security_profile"
    ]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    approved_calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    approved_redirect_endpoint_control_document_sha256: str
    control_profile: Literal[
        "engineer4me_entra_spa_authorization_code_pkce_runtime_controls_v1"
    ]

    @model_validator(mode="after")
    def validate_digests(self) -> EntraCallingClientPKCERuntimeDocument:
        if any(
            not _is_lower_sha256(value)
            for value in (
                self.approved_configuration_sha256,
                self.approved_api_registration_document_sha256,
                self.approved_calling_client_registration_document_sha256,
                self.approved_inventory_document_sha256,
                self.approved_redirect_endpoint_control_document_sha256,
            )
        ):
            raise ValueError("approved digests must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientPKCERuntimeReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    control_profile: str
    authorization_response_type: str
    authorization_response_mode: str
    token_grant_type: str
    pkce_method: str
    transaction_storage: str
    authorization_navigation_mode: str
    token_request_method: str
    token_request_content_type: str
    token_fetch_credentials_mode: str
    token_fetch_redirect_mode: str
    token_fetch_cache_mode: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    approved_redirect_endpoint_control_document_sha256: str
    redirect_endpoint_control_document_sha256: str
    offline_redirect_readiness_receipt_sha256: str
    pkce_runtime_control_document_sha256: str
    tenant_id_sha256: str
    api_application_id_sha256: str
    api_delegated_scope_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    spa_redirect_uris_sha256: str
    authorization_server_origin_sha256: str
    authorization_endpoint_sha256: str
    token_endpoint_sha256: str
    oidc_scope_set_sha256: str
    api_scope_sha256: str
    complete_scope_set_sha256: str
    authorization_request_template_sha256: str
    token_request_template_sha256: str
    callback_validation_profile_sha256: str
    transaction_storage_profile_sha256: str
    runtime_csp_transition_profile_sha256: str
    desired_redirect_endpoint_count: int
    desired_oidc_scope_count: int
    desired_api_scope_count: int
    desired_total_scope_count: int
    pkce_verifier_minimum_entropy_bits: int
    state_minimum_entropy_bits: int
    nonce_minimum_entropy_bits: int
    pkce_verifier_minimum_length: int
    pkce_verifier_maximum_length: int
    state_maximum_length: int
    nonce_maximum_length: int
    transaction_maximum_age_seconds: int
    callback_query_maximum_bytes: int
    authorization_code_maximum_bytes: int
    token_request_maximum_bytes: int
    token_response_maximum_bytes: int
    configuration_bound: bool
    api_registration_bound: bool
    calling_client_registration_bound: bool
    approved_inventory_digest_bound: bool
    approved_redirect_control_digest_bound: bool
    step214_source_chain_revalidated: bool
    exact_identity_projection_validated: bool
    redirect_uris_derived_from_approved_registration: bool
    tenant_specific_authority_derived_from_approved_issuer: bool
    exact_authorization_endpoint_plan_derived: bool
    exact_token_endpoint_plan_derived: bool
    authorization_code_only_required: bool
    implicit_and_hybrid_responses_rejected: bool
    exact_query_response_mode_required: bool
    exact_approved_scope_set_required: bool
    pkce_s256_required: bool
    plain_pkce_rejected: bool
    per_attempt_cryptographic_randomness_required: bool
    minimum_verifier_state_nonce_entropy_required: bool
    pkce_base64url_without_padding_required: bool
    state_and_nonce_opaque_library_values_required: bool
    normalized_required_parameter_subsets_only: bool
    verifier_excluded_from_authorization_request_required: bool
    state_and_nonce_authorization_binding_required: bool
    session_storage_only_required: bool
    transaction_single_use_required: bool
    transaction_expiry_required: bool
    callback_exact_state_match_required: bool
    callback_code_or_error_exclusivity_required: bool
    callback_query_cleanup_required: bool
    sensitive_value_logging_forbidden: bool
    exact_form_encoded_token_post_required: bool
    same_redirect_uri_for_authorize_and_token_required: bool
    browser_origin_header_required: bool
    public_client_secret_and_assertion_forbidden: bool
    token_fetch_cookie_credentials_forbidden: bool
    token_fetch_redirect_and_retry_forbidden: bool
    token_fetch_no_store_required: bool
    supported_microsoft_authentication_library_required: bool
    step215_six_directive_csp_token_exchange_gap_recorded: bool
    runtime_connect_src_transition_required: bool
    endpoint_reproof_after_csp_transition_required: bool
    offline_desired_state_validated: bool
    successor_live_endpoint_proof_completed: bool
    supported_library_package_selected: bool
    supported_library_version_checked: bool
    supported_library_source_integrity_checked: bool
    runtime_csp_transition_deployed: bool
    runtime_csp_transition_endpoint_reproved: bool
    authorization_server_discovery_checked: bool
    authorization_server_reachability_checked: bool
    authorization_server_tls_checked: bool
    authorization_server_hostname_ownership_checked: bool
    external_tenant_classification_checked: bool
    live_user_flow_association_checked: bool
    live_delegated_consent_checked: bool
    runtime_csp_browser_enforcement_checked: bool
    engineer4me_api_origin_csp_policy_checked: bool
    exact_runtime_wire_query_checked: bool
    exact_runtime_wire_form_checked: bool
    runtime_csprng_checked: bool
    runtime_unique_verifier_checked: bool
    runtime_unique_state_checked: bool
    runtime_unique_nonce_checked: bool
    browser_session_storage_isolation_checked: bool
    browser_storage_cleanup_checked: bool
    authorization_navigation_checked: bool
    runtime_redirect_uri_match_checked: bool
    runtime_browser_origin_checked: bool
    runtime_no_client_secret_checked: bool
    runtime_oidc_scopes_requested_checked: bool
    runtime_api_scope_requested_checked: bool
    service_worker_behavior_checked: bool
    browser_extension_behavior_checked: bool
    customer_user_flow_checked: bool
    authorization_response_received: bool
    callback_query_bounds_checked: bool
    callback_state_match_checked: bool
    callback_replay_rejected: bool
    callback_error_sanitization_checked: bool
    callback_history_cleanup_checked: bool
    token_endpoint_cors_checked: bool
    browser_origin_checked: bool
    authorization_code_redeemed: bool
    pkce_verifier_accepted: bool
    token_response_received: bool
    token_response_bounds_checked: bool
    id_token_signature_checked: bool
    id_token_issuer_checked: bool
    id_token_audience_checked: bool
    id_token_nonce_checked: bool
    access_token_signature_checked: bool
    access_token_issuer_checked: bool
    access_token_audience_checked: bool
    access_token_scope_checked: bool
    access_token_calling_client_checked: bool
    refresh_token_rotation_checked: bool
    refresh_token_storage_checked: bool
    real_engineer4me_api_call_checked: bool
    real_customer_user_journey_checked: bool
    provider_policy_checked: bool
    conditional_access_checked: bool
    mfa_checked: bool
    terms_of_use_checked: bool
    provider_io_performed: bool
    browser_io_performed: bool
    network_io_performed: bool
    application_configuration_mutation_performed: bool
    identity_provider_configuration_mutation_performed: bool
    endpoint_configuration_mutation_performed: bool
    read_operation_side_effects_checked: bool
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
            or self.receipt_type != ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SOURCE
            or self.validation_scope != ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE
            or self.control_profile != ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE
            or self.authorization_response_type != FUTURE_AUTHORIZATION_RESPONSE_TYPE
            or self.authorization_response_mode != FUTURE_AUTHORIZATION_RESPONSE_MODE
            or self.token_grant_type != FUTURE_TOKEN_GRANT_TYPE
            or self.pkce_method != FUTURE_PKCE_METHOD
            or self.transaction_storage != FUTURE_TRANSACTION_STORAGE
            or self.authorization_navigation_mode
            != FUTURE_AUTHORIZATION_NAVIGATION_MODE
            or self.token_request_method != FUTURE_TOKEN_REQUEST_METHOD
            or self.token_request_content_type != FUTURE_TOKEN_REQUEST_CONTENT_TYPE
            or self.token_fetch_credentials_mode != FUTURE_TOKEN_FETCH_CREDENTIALS_MODE
            or self.token_fetch_redirect_mode != FUTURE_TOKEN_FETCH_REDIRECT_MODE
            or self.token_fetch_cache_mode != FUTURE_TOKEN_FETCH_CACHE_MODE
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_redirect_endpoint_control_document_sha256,
                self.redirect_endpoint_control_document_sha256,
            )
            or any(type(value) is not int for value in counts)
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or self.desired_oidc_scope_count != 3
            or self.desired_api_scope_count != 1
            or self.desired_total_scope_count != 4
            or self.pkce_verifier_minimum_entropy_bits
            != FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS
            or self.state_minimum_entropy_bits != FUTURE_STATE_MINIMUM_ENTROPY_BITS
            or self.nonce_minimum_entropy_bits != FUTURE_NONCE_MINIMUM_ENTROPY_BITS
            or self.pkce_verifier_minimum_length != FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH
            or self.pkce_verifier_maximum_length != FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH
            or self.state_maximum_length != FUTURE_STATE_MAXIMUM_LENGTH
            or self.nonce_maximum_length != FUTURE_NONCE_MAXIMUM_LENGTH
            or self.transaction_maximum_age_seconds
            != FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS
            or self.callback_query_maximum_bytes != FUTURE_CALLBACK_QUERY_MAXIMUM_BYTES
            or self.authorization_code_maximum_bytes
            != FUTURE_AUTHORIZATION_CODE_MAXIMUM_BYTES
            or self.token_request_maximum_bytes != FUTURE_TOKEN_REQUEST_MAXIMUM_BYTES
            or self.token_response_maximum_bytes != FUTURE_TOKEN_RESPONSE_MAXIMUM_BYTES
            or any(value is not True for value in structural)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra SPA PKCE runtime readiness receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "control_profile",
    "authorization_response_type",
    "authorization_response_mode",
    "token_grant_type",
    "pkce_method",
    "transaction_storage",
    "authorization_navigation_mode",
    "token_request_method",
    "token_request_content_type",
    "token_fetch_credentials_mode",
    "token_fetch_redirect_mode",
    "token_fetch_cache_mode",
)

_COUNT_FIELDS = (
    "desired_redirect_endpoint_count",
    "desired_oidc_scope_count",
    "desired_api_scope_count",
    "desired_total_scope_count",
    "pkce_verifier_minimum_entropy_bits",
    "state_minimum_entropy_bits",
    "nonce_minimum_entropy_bits",
    "pkce_verifier_minimum_length",
    "pkce_verifier_maximum_length",
    "state_maximum_length",
    "nonce_maximum_length",
    "transaction_maximum_age_seconds",
    "callback_query_maximum_bytes",
    "authorization_code_maximum_bytes",
    "token_request_maximum_bytes",
    "token_response_maximum_bytes",
)

_STRUCTURAL_TRUE_FIELDS = (
    "configuration_bound",
    "api_registration_bound",
    "calling_client_registration_bound",
    "approved_inventory_digest_bound",
    "approved_redirect_control_digest_bound",
    "step214_source_chain_revalidated",
    "exact_identity_projection_validated",
    "redirect_uris_derived_from_approved_registration",
    "tenant_specific_authority_derived_from_approved_issuer",
    "exact_authorization_endpoint_plan_derived",
    "exact_token_endpoint_plan_derived",
    "authorization_code_only_required",
    "implicit_and_hybrid_responses_rejected",
    "exact_query_response_mode_required",
    "exact_approved_scope_set_required",
    "pkce_s256_required",
    "plain_pkce_rejected",
    "per_attempt_cryptographic_randomness_required",
    "minimum_verifier_state_nonce_entropy_required",
    "pkce_base64url_without_padding_required",
    "state_and_nonce_opaque_library_values_required",
    "normalized_required_parameter_subsets_only",
    "verifier_excluded_from_authorization_request_required",
    "state_and_nonce_authorization_binding_required",
    "session_storage_only_required",
    "transaction_single_use_required",
    "transaction_expiry_required",
    "callback_exact_state_match_required",
    "callback_code_or_error_exclusivity_required",
    "callback_query_cleanup_required",
    "sensitive_value_logging_forbidden",
    "exact_form_encoded_token_post_required",
    "same_redirect_uri_for_authorize_and_token_required",
    "browser_origin_header_required",
    "public_client_secret_and_assertion_forbidden",
    "token_fetch_cookie_credentials_forbidden",
    "token_fetch_redirect_and_retry_forbidden",
    "token_fetch_no_store_required",
    "supported_microsoft_authentication_library_required",
    "step215_six_directive_csp_token_exchange_gap_recorded",
    "runtime_connect_src_transition_required",
    "endpoint_reproof_after_csp_transition_required",
    "offline_desired_state_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "successor_live_endpoint_proof_completed",
    "supported_library_package_selected",
    "supported_library_version_checked",
    "supported_library_source_integrity_checked",
    "runtime_csp_transition_deployed",
    "runtime_csp_transition_endpoint_reproved",
    "authorization_server_discovery_checked",
    "authorization_server_reachability_checked",
    "authorization_server_tls_checked",
    "authorization_server_hostname_ownership_checked",
    "external_tenant_classification_checked",
    "live_user_flow_association_checked",
    "live_delegated_consent_checked",
    "runtime_csp_browser_enforcement_checked",
    "engineer4me_api_origin_csp_policy_checked",
    "exact_runtime_wire_query_checked",
    "exact_runtime_wire_form_checked",
    "runtime_csprng_checked",
    "runtime_unique_verifier_checked",
    "runtime_unique_state_checked",
    "runtime_unique_nonce_checked",
    "browser_session_storage_isolation_checked",
    "browser_storage_cleanup_checked",
    "authorization_navigation_checked",
    "runtime_redirect_uri_match_checked",
    "runtime_browser_origin_checked",
    "runtime_no_client_secret_checked",
    "runtime_oidc_scopes_requested_checked",
    "runtime_api_scope_requested_checked",
    "service_worker_behavior_checked",
    "browser_extension_behavior_checked",
    "customer_user_flow_checked",
    "authorization_response_received",
    "callback_query_bounds_checked",
    "callback_state_match_checked",
    "callback_replay_rejected",
    "callback_error_sanitization_checked",
    "callback_history_cleanup_checked",
    "token_endpoint_cors_checked",
    "browser_origin_checked",
    "authorization_code_redeemed",
    "pkce_verifier_accepted",
    "token_response_received",
    "token_response_bounds_checked",
    "id_token_signature_checked",
    "id_token_issuer_checked",
    "id_token_audience_checked",
    "id_token_nonce_checked",
    "access_token_signature_checked",
    "access_token_issuer_checked",
    "access_token_audience_checked",
    "access_token_scope_checked",
    "access_token_calling_client_checked",
    "refresh_token_rotation_checked",
    "refresh_token_storage_checked",
    "real_engineer4me_api_call_checked",
    "real_customer_user_journey_checked",
    "provider_policy_checked",
    "conditional_access_checked",
    "mfa_checked",
    "terms_of_use_checked",
    "provider_io_performed",
    "browser_io_performed",
    "network_io_performed",
    "application_configuration_mutation_performed",
    "identity_provider_configuration_mutation_performed",
    "endpoint_configuration_mutation_performed",
    "read_operation_side_effects_checked",
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
    for value in ("engineer4me-step216-v1", label, str(len(values)), *values):
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
            if depth > MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTAINERS:
            raise ValueError("structure limit")


def _require_exact_document_scalars(parsed: dict[str, Any]) -> None:
    expected = {
        "document_type",
        "schema_version",
        "source",
        "approved_configuration_sha256",
        "approved_api_registration_document_sha256",
        "approved_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
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
        oidc_scopes = tuple(registration["desired_runtime_oidc_scopes"])
        api_scope = registration["desired_runtime_api_scope"]
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
        or oidc_scopes != ("offline_access", "openid", "profile")
        or api_scope != f"api://{api_application_id}/access_as_user"
        or registration["desired_browser_flow"] != "authorization_code_pkce"
        or registration["desired_pkce_method"] != "S256"
        or registration["desired_client_authentication_method"] != "none"
        or registration["desired_authorization_code_flow_enabled"] is not True
        or registration["desired_pkce_required"] is not True
        or registration["desired_implicit_access_token_enabled"] is not False
        or registration["desired_implicit_id_token_enabled"] is not False
        or authentication_preview.microsoft_entra_tenant_id != tenant_id
        or authentication_preview.microsoft_entra_api_application_id
        != api_application_id
        or authentication_preview.microsoft_entra_calling_client_application_id
        != calling_client_application_id
        or authentication_preview.microsoft_entra_required_delegated_scope
        != "access_as_user"
    ):
        raise ValueError("validated registration projection mismatch")

    issuer = authentication_preview.issuer
    try:
        parsed_issuer = urlsplit(issuer)
        hostname = parsed_issuer.hostname
        port = parsed_issuer.port
    except ValueError:
        raise ValueError("approved issuer is invalid") from None
    if (
        type(issuer) is not str
        or parsed_issuer.scheme != "https"
        or type(hostname) is not str
        or hostname != hostname.lower()
        or parsed_issuer.username is not None
        or parsed_issuer.password is not None
        or port is not None
        or parsed_issuer.netloc != hostname
        or parsed_issuer.path != f"/{tenant_id}/v2.0"
        or parsed_issuer.query
        or parsed_issuer.fragment
    ):
        raise ValueError("approved issuer cannot derive a canonical authority")
    origin = f"https://{hostname}"
    authority = f"{origin}/{tenant_id}"
    return {
        "tenant_id": tenant_id,
        "api_application_id": api_application_id,
        "api_scope_id": api_scope_id,
        "calling_client_application_id": calling_client_application_id,
        "calling_client_object_id": calling_client_object_id,
        "redirect_uris": redirect_uris,
        "oidc_scopes": FUTURE_OIDC_SCOPE_ORDER,
        "api_scope": api_scope,
        "origin": origin,
        "authorization_endpoint": f"{authority}/oauth2/v2.0/authorize",
        "token_endpoint": f"{authority}/oauth2/v2.0/token",
    }


def _authorization_request_template(projection: dict[str, object]) -> bytes:
    requests = []
    for redirect_uri in projection["redirect_uris"]:
        requests.append(
            {
                "endpoint": projection["authorization_endpoint"],
                "navigation": FUTURE_AUTHORIZATION_NAVIGATION_MODE,
                "projection": "required_application_parameter_subset_not_wire_payload",
                "supported_library_managed_parameters_may_be_added": True,
                "parameters": [
                    ["client_id", projection["calling_client_application_id"]],
                    ["response_type", FUTURE_AUTHORIZATION_RESPONSE_TYPE],
                    ["redirect_uri", redirect_uri],
                    ["response_mode", FUTURE_AUTHORIZATION_RESPONSE_MODE],
                    [
                        "scope",
                        " ".join(
                            (*FUTURE_OIDC_SCOPE_ORDER, str(projection["api_scope"]))
                        ),
                    ],
                    ["code_challenge", "<S256_BASE64URL_SHA256_OF_VERIFIER>"],
                    ["code_challenge_method", FUTURE_PKCE_METHOD],
                    ["state", "<UNIQUE_OPAQUE_SUPPORTED_LIBRARY_STATE>"],
                    ["nonce", "<UNIQUE_OPAQUE_SUPPORTED_LIBRARY_NONCE>"],
                ],
                "forbidden_parameters": [
                    "client_secret",
                    "client_assertion",
                    "client_assertion_type",
                    "code_verifier",
                    "id_token_hint",
                    "login_hint",
                    "domain_hint",
                    "request",
                    "request_uri",
                ],
            }
        )
    return _canonical_bytes(requests)


def _token_request_template(projection: dict[str, object]) -> bytes:
    requests = []
    scope = " ".join((*FUTURE_OIDC_SCOPE_ORDER, str(projection["api_scope"])))
    for redirect_uri in projection["redirect_uris"]:
        requests.append(
            {
                "endpoint": projection["token_endpoint"],
                "method": FUTURE_TOKEN_REQUEST_METHOD,
                "content_type": FUTURE_TOKEN_REQUEST_CONTENT_TYPE,
                "projection": "required_application_parameter_subset_not_wire_payload",
                "supported_library_managed_parameters_may_be_added": True,
                "browser_origin": urlsplit(redirect_uri).scheme
                + "://"
                + str(urlsplit(redirect_uri).hostname),
                "fetch": {
                    "credentials": FUTURE_TOKEN_FETCH_CREDENTIALS_MODE,
                    "redirect": FUTURE_TOKEN_FETCH_REDIRECT_MODE,
                    "cache": FUTURE_TOKEN_FETCH_CACHE_MODE,
                    "retry_count": 0,
                },
                "form_fields": [
                    ["client_id", projection["calling_client_application_id"]],
                    ["grant_type", FUTURE_TOKEN_GRANT_TYPE],
                    ["code", "<ONE_TIME_AUTHORIZATION_CODE>"],
                    ["redirect_uri", redirect_uri],
                    ["scope", scope],
                    ["code_verifier", "<ONE_TIME_PKCE_VERIFIER>"],
                ],
                "forbidden_fields": [
                    "client_secret",
                    "client_assertion",
                    "client_assertion_type",
                    "password",
                    "refresh_token",
                ],
                "authorization_header": None,
                "cookie": None,
                "maximum_request_bytes": FUTURE_TOKEN_REQUEST_MAXIMUM_BYTES,
                "maximum_response_bytes": FUTURE_TOKEN_RESPONSE_MAXIMUM_BYTES,
            }
        )
    return _canonical_bytes(requests)


def _callback_validation_profile() -> bytes:
    return _canonical_bytes(
        {
            "maximum_query_bytes": FUTURE_CALLBACK_QUERY_MAXIMUM_BYTES,
            "maximum_authorization_code_bytes": (
                FUTURE_AUTHORIZATION_CODE_MAXIMUM_BYTES
            ),
            "response_exclusivity": "exactly_one_of_code_or_error",
            "state": "required_exact_single_use_unexpired_match",
            "nonce": "required_and_later_bound_to_validated_id_token",
            "query_cleanup": "history_replace_before_application_navigation",
            "raw_error_display": False,
            "raw_value_logging": False,
            "provider_parameter_parsing": (
                "supported_microsoft_authentication_library_required"
            ),
        }
    )


def _transaction_storage_profile() -> bytes:
    return _canonical_bytes(
        {
            "storage": FUTURE_TRANSACTION_STORAGE,
            "maximum_age_seconds": FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS,
            "single_use": True,
            "cleanup_on_success": True,
            "cleanup_on_error": True,
            "cleanup_on_expiry": True,
            "local_storage_allowed": False,
            "cookie_storage_allowed": False,
            "url_storage_allowed": False,
            "logged_values_allowed": False,
            "values": {
                "code_verifier": {
                    "minimum_entropy_bits": (FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS),
                    "encoding": "base64url_without_padding",
                    "minimum_length": FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH,
                    "maximum_length": FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH,
                },
                "state": {
                    "minimum_entropy_bits": FUTURE_STATE_MINIMUM_ENTROPY_BITS,
                    "encoding": "opaque_supported_library_serialization",
                    "maximum_length": FUTURE_STATE_MAXIMUM_LENGTH,
                },
                "nonce": {
                    "minimum_entropy_bits": FUTURE_NONCE_MINIMUM_ENTROPY_BITS,
                    "encoding": "opaque_supported_library_serialization",
                    "maximum_length": FUTURE_NONCE_MAXIMUM_LENGTH,
                },
            },
        }
    )


def _runtime_csp_transition_profile(projection: dict[str, object]) -> bytes:
    return _canonical_bytes(
        {
            "reason": "browser_token_endpoint_exchange_requires_cross_origin_connect",
            "step215_current_exact_directive_count": 6,
            "step215_current_connect_src_present": False,
            "token_exchange_intermediate_exact_directives": {
                "default-src": ["'self'"],
                "script-src": ["'self'"],
                "connect-src": ["'self'", projection["origin"]],
                "base-uri": ["'none'"],
                "object-src": ["'none'"],
                "frame-ancestors": ["'none'"],
                "form-action": ["'none'"],
            },
            "deployment_checked": False,
            "endpoint_reproof_required": True,
            "engineer4me_api_origin_policy_checked": False,
        }
    )


def _load_internal(
    *,
    document: bytes,
    redirect_endpoint_control_document: bytes,
    approved_redirect_endpoint_control_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientPKCERuntimeReadinessReceipt:
    byte_inputs = (
        document,
        redirect_endpoint_control_document,
        api_registration_document,
        calling_client_registration_document,
        inventory_document,
    )
    digest_inputs = (
        approved_redirect_endpoint_control_document_sha256,
        accepted_api_registration_document_sha256,
        accepted_calling_client_registration_document_sha256,
        approved_inventory_document_sha256,
    )
    if any(not isinstance(value, bytes) for value in byte_inputs):
        raise _ArgumentTypeError("documents must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise _ArgumentTypeError("authentication preview is required")
    if any(not _is_lower_sha256(value) for value in digest_inputs):
        raise _ArgumentTypeError("approved digests are required")

    redirect_receipt = load_entra_calling_client_redirect_endpoint_readiness(
        document=redirect_endpoint_control_document,
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
        redirect_receipt.redirect_endpoint_control_document_sha256,
        approved_redirect_endpoint_control_document_sha256,
    ):
        raise ValueError("redirect-control digest mismatch")

    if (
        not document
        or len(document) > MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_BYTES
    ):
        raise ValueError("document byte boundary")
    decoded = document.decode("utf-8")
    parsed = json.loads(
        decoded,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )
    if not isinstance(parsed, dict):
        raise ValueError("document root")  # noqa: TRY004 - untrusted JSON shape
    _require_bounded_structure(parsed)
    _require_exact_document_scalars(parsed)
    canonical_document = _canonical_bytes(parsed)
    validated = EntraCallingClientPKCERuntimeDocument.model_validate_json(
        canonical_document
    )
    if (
        not hmac.compare_digest(
            validated.approved_configuration_sha256,
            redirect_receipt.configuration_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_api_registration_document_sha256,
            redirect_receipt.api_registration_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_calling_client_registration_document_sha256,
            redirect_receipt.calling_client_registration_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_inventory_document_sha256,
            approved_inventory_document_sha256,
        )
        or not hmac.compare_digest(
            validated.approved_redirect_endpoint_control_document_sha256,
            approved_redirect_endpoint_control_document_sha256,
        )
    ):
        raise ValueError("approved evidence mismatch")

    projection = _validated_projection(
        authentication_preview=authentication_preview,
        calling_client_registration_document=calling_client_registration_document,
    )
    authorization_template = _authorization_request_template(projection)
    token_template = _token_request_template(projection)
    callback_profile = _callback_validation_profile()
    storage_profile = _transaction_storage_profile()
    csp_transition = _runtime_csp_transition_profile(projection)
    complete_scopes = (*FUTURE_OIDC_SCOPE_ORDER, str(projection["api_scope"]))
    true_values = {field: True for field in _STRUCTURAL_TRUE_FIELDS}
    false_values = {field: False for field in _DEFERRED_FALSE_FIELDS}
    return EntraCallingClientPKCERuntimeReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE,
        control_profile=validated.control_profile,
        authorization_response_type=FUTURE_AUTHORIZATION_RESPONSE_TYPE,
        authorization_response_mode=FUTURE_AUTHORIZATION_RESPONSE_MODE,
        token_grant_type=FUTURE_TOKEN_GRANT_TYPE,
        pkce_method=FUTURE_PKCE_METHOD,
        transaction_storage=FUTURE_TRANSACTION_STORAGE,
        authorization_navigation_mode=FUTURE_AUTHORIZATION_NAVIGATION_MODE,
        token_request_method=FUTURE_TOKEN_REQUEST_METHOD,
        token_request_content_type=FUTURE_TOKEN_REQUEST_CONTENT_TYPE,
        token_fetch_credentials_mode=FUTURE_TOKEN_FETCH_CREDENTIALS_MODE,
        token_fetch_redirect_mode=FUTURE_TOKEN_FETCH_REDIRECT_MODE,
        token_fetch_cache_mode=FUTURE_TOKEN_FETCH_CACHE_MODE,
        configuration_sha256=redirect_receipt.configuration_sha256,
        api_registration_document_sha256=(
            redirect_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            redirect_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        inventory_document_sha256=redirect_receipt.inventory_document_sha256,
        approved_redirect_endpoint_control_document_sha256=(
            approved_redirect_endpoint_control_document_sha256
        ),
        redirect_endpoint_control_document_sha256=(
            redirect_receipt.redirect_endpoint_control_document_sha256
        ),
        offline_redirect_readiness_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_redirect_endpoint_readiness_receipt(
                redirect_receipt
            ).encode("utf-8")
        ).hexdigest(),
        pkce_runtime_control_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=_framed_sha256("tenant_id", str(projection["tenant_id"])),
        api_application_id_sha256=_framed_sha256(
            "api_application_id", str(projection["api_application_id"])
        ),
        api_delegated_scope_id_sha256=_framed_sha256(
            "api_delegated_scope_id", str(projection["api_scope_id"])
        ),
        calling_client_application_id_sha256=_framed_sha256(
            "calling_client_application_id",
            str(projection["calling_client_application_id"]),
        ),
        calling_client_application_object_id_sha256=_framed_sha256(
            "calling_client_application_object_id",
            str(projection["calling_client_object_id"]),
        ),
        spa_redirect_uris_sha256=_framed_sha256(
            "spa_redirect_uris",
            str(len(projection["redirect_uris"])),
            *projection["redirect_uris"],
        ),
        authorization_server_origin_sha256=_framed_sha256(
            "authorization_server_origin", str(projection["origin"])
        ),
        authorization_endpoint_sha256=_framed_sha256(
            "authorization_endpoint", str(projection["authorization_endpoint"])
        ),
        token_endpoint_sha256=_framed_sha256(
            "token_endpoint", str(projection["token_endpoint"])
        ),
        oidc_scope_set_sha256=_framed_sha256(
            "oidc_scope_set", *FUTURE_OIDC_SCOPE_ORDER
        ),
        api_scope_sha256=_framed_sha256("api_scope", str(projection["api_scope"])),
        complete_scope_set_sha256=_framed_sha256(
            "complete_scope_set", *complete_scopes
        ),
        authorization_request_template_sha256=_framed_sha256(
            "authorization_request_template", authorization_template
        ),
        token_request_template_sha256=_framed_sha256(
            "token_request_template", token_template
        ),
        callback_validation_profile_sha256=_framed_sha256(
            "callback_validation_profile", callback_profile
        ),
        transaction_storage_profile_sha256=_framed_sha256(
            "transaction_storage_profile", storage_profile
        ),
        runtime_csp_transition_profile_sha256=_framed_sha256(
            "runtime_csp_transition_profile", csp_transition
        ),
        desired_redirect_endpoint_count=len(projection["redirect_uris"]),
        desired_oidc_scope_count=3,
        desired_api_scope_count=1,
        desired_total_scope_count=4,
        pkce_verifier_minimum_entropy_bits=(FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS),
        state_minimum_entropy_bits=FUTURE_STATE_MINIMUM_ENTROPY_BITS,
        nonce_minimum_entropy_bits=FUTURE_NONCE_MINIMUM_ENTROPY_BITS,
        pkce_verifier_minimum_length=FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH,
        pkce_verifier_maximum_length=FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH,
        state_maximum_length=FUTURE_STATE_MAXIMUM_LENGTH,
        nonce_maximum_length=FUTURE_NONCE_MAXIMUM_LENGTH,
        transaction_maximum_age_seconds=FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS,
        callback_query_maximum_bytes=FUTURE_CALLBACK_QUERY_MAXIMUM_BYTES,
        authorization_code_maximum_bytes=FUTURE_AUTHORIZATION_CODE_MAXIMUM_BYTES,
        token_request_maximum_bytes=FUTURE_TOKEN_REQUEST_MAXIMUM_BYTES,
        token_response_maximum_bytes=FUTURE_TOKEN_RESPONSE_MAXIMUM_BYTES,
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


def load_entra_calling_client_pkce_runtime_readiness(
    *,
    document: bytes,
    redirect_endpoint_control_document: bytes,
    approved_redirect_endpoint_control_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientPKCERuntimeReadinessReceipt:
    """Validate the offline runtime plan without provider or browser I/O."""

    result = None
    error = None
    invalid_call = False
    failed = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document=document,
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
        raise KeyboardInterrupt("Entra SPA PKCE runtime readiness interrupted")
    if terminated:
        result = None
        raise SystemExit("Entra SPA PKCE runtime readiness terminated")
    if invalid_call:
        result = None
        raise TypeError("Entra SPA PKCE runtime readiness inputs are invalid")
    if failed or result is None:
        result = None
        raise EntraCallingClientPKCERuntimeReadinessError(
            "Entra SPA PKCE runtime readiness validation failed"
        )
    return result


def render_entra_calling_client_pkce_runtime_readiness_receipt(
    receipt: EntraCallingClientPKCERuntimeReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized structural readiness evidence."""

    if type(receipt) is not EntraCallingClientPKCERuntimeReadinessReceipt:
        raise TypeError("Entra SPA PKCE runtime readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_CONTROL_PROFILE",
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SCOPE",
    "ENTRA_CALLING_CLIENT_PKCE_RUNTIME_SOURCE",
    "FUTURE_AUTHORIZATION_CODE_MAXIMUM_BYTES",
    "FUTURE_AUTHORIZATION_NAVIGATION_MODE",
    "FUTURE_AUTHORIZATION_RESPONSE_MODE",
    "FUTURE_AUTHORIZATION_RESPONSE_TYPE",
    "FUTURE_CALLBACK_QUERY_MAXIMUM_BYTES",
    "FUTURE_NONCE_MAXIMUM_LENGTH",
    "FUTURE_NONCE_MINIMUM_ENTROPY_BITS",
    "FUTURE_OIDC_SCOPE_ORDER",
    "FUTURE_PKCE_METHOD",
    "FUTURE_PKCE_VERIFIER_MAXIMUM_LENGTH",
    "FUTURE_PKCE_VERIFIER_MINIMUM_ENTROPY_BITS",
    "FUTURE_PKCE_VERIFIER_MINIMUM_LENGTH",
    "FUTURE_STATE_MAXIMUM_LENGTH",
    "FUTURE_STATE_MINIMUM_ENTROPY_BITS",
    "FUTURE_TOKEN_FETCH_CACHE_MODE",
    "FUTURE_TOKEN_FETCH_CREDENTIALS_MODE",
    "FUTURE_TOKEN_FETCH_REDIRECT_MODE",
    "FUTURE_TOKEN_GRANT_TYPE",
    "FUTURE_TOKEN_REQUEST_CONTENT_TYPE",
    "FUTURE_TOKEN_REQUEST_MAXIMUM_BYTES",
    "FUTURE_TOKEN_REQUEST_METHOD",
    "FUTURE_TOKEN_RESPONSE_MAXIMUM_BYTES",
    "FUTURE_TRANSACTION_MAXIMUM_AGE_SECONDS",
    "FUTURE_TRANSACTION_STORAGE",
    "MAX_ENTRA_CALLING_CLIENT_PKCE_RUNTIME_DOCUMENT_BYTES",
    "EntraCallingClientPKCERuntimeReadinessError",
    "EntraCallingClientPKCERuntimeReadinessReceipt",
    "load_entra_calling_client_pkce_runtime_readiness",
    "render_entra_calling_client_pkce_runtime_readiness_receipt",
]
