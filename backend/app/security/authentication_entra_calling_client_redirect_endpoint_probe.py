"""Controlled DNS/TLS/HTTP proof for approved Entra SPA redirect endpoints.

The proof validates the Step 214 offline source chain before any I/O, performs
the Step 213 exact calling-client Graph proof as the first live operation, and
only then executes the derived redirect-endpoint plan.  No receipt or URI list
is accepted as provenance.  Synthetic transports exercise the same structural
checks but can never confer live evidence.

This module never starts an OAuth/OIDC journey, follows a redirect, executes
JavaScript, renders a browser document, redeems a code, or invokes a
configuration-write or mutation-capable configuration method.  Incidental
effects of reads, such as provider logging, caching, or rate limiting, are
unobserved and are not claimed absent.
"""

from __future__ import annotations

import codecs
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urlsplit

from app.security.authentication_entra_calling_client_redirect_endpoint_http_loader import (
    ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST,
    ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS,
    BoundedHTTPSEntraCallingClientRedirectEndpointLoader,
    EntraCallingClientRedirectEndpointDNSObservation,
    EntraCallingClientRedirectEndpointRequest,
    EntraCallingClientRedirectEndpointResponse,
    EntraCallingClientRedirectEndpointTransport,
    EntraCallingClientRedirectEndpointTransportResult,
)
from app.security.authentication_entra_calling_client_redirect_endpoint_readiness import (
    ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE,
    FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET,
    FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE,
    FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE,
    FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN,
    FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS,
    FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT,
    FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
    FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
    FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET,
    FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES,
    FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD,
    EntraCallingClientRedirectEndpointReadinessReceipt,
    load_entra_calling_client_redirect_endpoint_readiness,
    render_entra_calling_client_redirect_endpoint_readiness_receipt,
)
from app.security.authentication_entra_calling_client_registration_graph_http_loader import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT,
    EntraCallingClientRegistrationGraphTransport,
)
from app.security.authentication_entra_calling_client_registration_probe import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE,
    ENTRA_GRAPH_API_VERSION,
    ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID,
    ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION,
    ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS,
    EntraCallingClientRegistrationGraphAuthorizationContract,
    EntraCallingClientRegistrationGraphProbeReceipt,
    probe_live_entra_calling_client_registration_graph,
    render_entra_calling_client_registration_graph_probe_receipt,
    validate_entra_calling_client_registration_graph_probe,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)

ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_redirect_endpoint_probe_receipt"
)
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE = (
    "controlled_live_dns_tls_http_spa_redirect_endpoint_security_control_proof"
)
_SHA256_HEX_LENGTH = 64
_HEADER_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CACHE_VALUE_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_URL_SCALAR_ATTRIBUTES = frozenset(
    {
        "action",
        "archive",
        "background",
        "cite",
        "classid",
        "codebase",
        "data",
        "dynsrc",
        "formaction",
        "href",
        "icon",
        "longdesc",
        "lowsrc",
        "manifest",
        "poster",
        "profile",
        "src",
        "usemap",
    }
)
_FORBIDDEN_HTML_ELEMENTS = frozenset(
    {
        "animate",
        "animatemotion",
        "animatetransform",
        "applet",
        "base",
        "discard",
        "embed",
        "form",
        "frame",
        "frameset",
        "iframe",
        "math",
        "object",
        "set",
        "style",
        "svg",
    }
)
_FORBIDDEN_RESPONSE_HEADERS = frozenset(
    {
        "access-control-allow-credentials",
        "access-control-allow-origin",
        "alt-svc",
        "content-encoding",
        "content-location",
        "content-security-policy-report-only",
        "cross-origin-embedder-policy-report-only",
        "cross-origin-opener-policy-report-only",
        "document-policy-report-only",
        "link",
        "location",
        "nel",
        "refresh",
        "report-to",
        "reporting-endpoints",
        "set-cookie",
    }
)
_EXACT_CSP = {
    "base-uri": ("'none'",),
    "default-src": ("'self'",),
    "form-action": ("'none'",),
    "frame-ancestors": ("'none'",),
    "object-src": ("'none'",),
    "script-src": ("'self'",),
}
_MAX_HTML_URL_ATTRIBUTE_BYTES = 2_048
_MAX_HTML_URL_LIST_ITEMS = 32


class EntraCallingClientRedirectEndpointProbeError(ValueError):
    """Sanitized rejection of invalid prerequisites or endpoint evidence."""


@dataclass(frozen=True, slots=True)
class EntraCallingClientRedirectEndpointProbeReceipt:
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
    request_method: str
    minimum_tls_version: str
    expected_media_type: str
    expected_charset: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    redirect_endpoint_control_document_sha256: str
    enforced_response_header_profile_sha256: str
    step214_preflight_receipt_sha256: str
    step213_registration_probe_receipt_sha256: str
    request_plan_sha256: str
    dns_observation_sha256: str
    selected_address_set_sha256: str
    tls_observation_sha256: str
    response_security_projection_sha256: str
    baseline_response_set_sha256: str
    hostile_origin_response_set_sha256: str
    bounded_vector_response_set_sha256: str
    all_response_body_set_sha256: str
    tenant_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    calling_client_service_principal_object_id_sha256: str
    spa_redirect_uris_sha256: str
    redirect_hostnames_sha256: str
    step213_graph_request_plan_count: int
    desired_redirect_endpoint_count: int
    desired_distinct_hostname_count: int
    sealed_dns_resolution_call_count: int
    resolved_address_count: int
    selected_address_count: int
    endpoint_requests_per_endpoint: int
    total_endpoint_request_count: int
    response_count: int
    sealed_tcp_connection_count: int
    sealed_tls_handshake_count: int
    baseline_response_count: int
    hostile_origin_response_count: int
    open_redirect_vector_count: int
    open_redirect_vector_response_count: int
    total_header_bytes: int
    total_body_bytes: int
    max_header_bytes: int
    max_body_bytes: int
    hsts_minimum_max_age_seconds: int
    endpoint_network_operation_timeout_seconds: float
    configuration_bound: bool
    api_registration_revalidated: bool
    calling_client_registration_revalidated: bool
    inventory_projection_revalidated: bool
    approved_inventory_digest_bound: bool
    step214_preflight_validated: bool
    step213_registration_prerequisite_rerun: bool
    fixed_control_profile_bound: bool
    step215_enforced_response_header_profile_bound: bool
    redirects_derived_from_approved_registration: bool
    exact_sorted_unique_redirect_set_validated: bool
    exact_sorted_unique_hostname_set_validated: bool
    complete_request_plan_prevalidated: bool
    step213_before_endpoint_io_enforced: bool
    all_host_resolution_barrier_required: bool
    one_resolution_call_per_hostname_required: bool
    all_returned_addresses_public_required: bool
    deterministic_one_address_per_hostname_selected: bool
    selected_address_scope_only_declared: bool
    fresh_connection_per_request_required: bool
    selected_preresolved_peer_required: bool
    original_hostname_sni_certificate_host_required: bool
    sequential_exact_ten_get_plan_validated: bool
    no_body_authorization_cookie_proxy_redirect_retry_compression_validated: bool
    endpoint_network_remaining_time_required: bool
    tls_key_logging_disabled_required: bool
    alpn_none_or_http_1_1_required: bool
    strict_http_1_1_200_required: bool
    http_1_1_wire_validated: bool
    response_framing_validated: bool
    response_bounds_validated: bool
    text_html_utf8_validated: bool
    required_security_headers_validated: bool
    forbidden_response_headers_absent_validated: bool
    exact_csp_validated: bool
    static_html_baseline_validated: bool
    hostile_origin_plan_validated: bool
    bounded_vector_plan_validated: bool
    variant_body_and_security_projection_match_validated: bool
    privacy_minimized_receipt_validated: bool
    synthetic_transport_used: bool
    step213_live_https_attested: bool
    endpoint_live_https_attested: bool
    sealed_provider_io_performed: bool
    sealed_network_io_performed: bool
    live_registration_checked: bool
    live_spa_redirect_registration_checked: bool
    live_all_host_resolution_barrier_enforced: bool
    live_dns_resolution_checked: bool
    live_all_returned_addresses_public_checked: bool
    live_selected_peer_checked: bool
    live_endpoint_reachability_checked: bool
    live_tls_checked: bool
    live_certificate_chain_checked: bool
    live_hostname_checked: bool
    live_exact_path_checked: bool
    live_status_checked: bool
    live_content_type_checked: bool
    live_response_headers_checked: bool
    live_csp_checked: bool
    live_static_html_checked: bool
    live_hostile_origin_observation_checked: bool
    live_bounded_server_side_vectors_rejected: bool
    live_endpoint_network_remaining_time_checked: bool
    live_tls_key_logging_disabled_checked: bool
    live_alpn_none_or_http_1_1_checked: bool
    dns_wall_clock_timeout_enforced: bool
    dns_cancellation_checked: bool
    dnssec_checked: bool
    resolver_authenticity_checked: bool
    resolver_cache_state_checked: bool
    dns_administrative_control_checked: bool
    unselected_resolved_addresses_tls_checked: bool
    unselected_resolved_addresses_http_checked: bool
    all_resolved_addresses_behavior_checked: bool
    certificate_revocation_checked: bool
    certificate_transparency_checked: bool
    trust_store_provenance_checked: bool
    continuous_availability_checked: bool
    response_freshness_checked: bool
    atomic_provider_endpoint_snapshot_checked: bool
    concurrent_provider_mutation_checked: bool
    broad_application_cors_checked: bool
    entra_token_endpoint_cors_checked: bool
    global_open_redirect_behavior_checked: bool
    client_javascript_navigation_checked: bool
    dom_mutation_checked: bool
    external_same_origin_asset_content_checked: bool
    browser_rendering_checked: bool
    unmodeled_response_header_browser_behavior_checked: bool
    injected_transport_side_effects_checked: bool
    provider_tenant_ownership_checked: bool
    redirect_dns_administrative_ownership_checked: bool
    redirect_legal_ownership_checked: bool
    actual_token_type_checked: bool
    token_permission_checked: bool
    token_tenant_checked: bool
    token_graph_audience_checked: bool
    token_cloud_checked: bool
    token_admin_consent_checked: bool
    work_school_account_checked: bool
    delegated_operator_identity_checked: bool
    delegated_operator_role_checked: bool
    operator_authorization_checked: bool
    runtime_authorization_code_flow_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_state_checked: bool
    runtime_nonce_checked: bool
    runtime_redirect_uri_match_checked: bool
    runtime_browser_origin_checked: bool
    runtime_no_client_secret_checked: bool
    runtime_oidc_scopes_requested_checked: bool
    runtime_api_scope_requested_checked: bool
    runtime_callback_query_handling_checked: bool
    runtime_token_redemption_checked: bool
    service_worker_behavior_checked: bool
    browser_extension_behavior_checked: bool
    real_customer_user_journey_checked: bool
    real_signed_api_token_checked: bool
    application_configuration_mutation_performed: bool
    dns_configuration_mutation_performed: bool
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
        structural = tuple(getattr(self, field) for field in _STRUCTURAL_TRUE_FIELDS)
        deferred = tuple(getattr(self, field) for field in _DEFERRED_FALSE_FIELDS)
        dynamic = tuple(getattr(self, field) for field in _DYNAMIC_LIVE_FIELDS)
        live = self.step213_live_https_attested
        if (
            any(
                type(getattr(self, field)) is not str for field in _PUBLIC_STRING_FIELDS
            )
            or self.receipt_type
            != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCHEMA_VERSION
            or self.validation_scope
            != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE
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
            or self.request_method != FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD
            or self.minimum_tls_version != FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION
            or self.expected_media_type != FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE
            or self.expected_charset != FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.enforced_response_header_profile_sha256,
                _evidence_sha256(
                    "enforced_response_header_profile",
                    _canonical_bytes(sorted(_FORBIDDEN_RESPONSE_HEADERS)),
                ),
            )
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or any(type(getattr(self, field)) is not int for field in _COUNT_FIELDS)
            or type(self.step213_graph_request_plan_count) is not int
            or self.step213_graph_request_plan_count
            != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT
            or type(self.desired_redirect_endpoint_count) is not int
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or type(self.desired_distinct_hostname_count) is not int
            or not 1
            <= self.desired_distinct_hostname_count
            <= self.desired_redirect_endpoint_count
            or self.sealed_dns_resolution_call_count
            != (self.desired_distinct_hostname_count if live else 0)
            or type(self.resolved_address_count) is not int
            or not self.desired_distinct_hostname_count
            <= self.resolved_address_count
            <= self.desired_distinct_hostname_count
            * ENTRA_REDIRECT_ENDPOINT_MAX_RESOLVED_ADDRESSES_PER_HOST
            or self.selected_address_count != self.desired_distinct_hostname_count
            or self.endpoint_requests_per_endpoint
            != FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            or self.total_endpoint_request_count
            != self.desired_redirect_endpoint_count
            * FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            or self.response_count != self.total_endpoint_request_count
            or self.sealed_tcp_connection_count
            != (self.total_endpoint_request_count if live else 0)
            or self.sealed_tls_handshake_count
            != (self.total_endpoint_request_count if live else 0)
            or self.baseline_response_count != self.desired_redirect_endpoint_count
            or self.hostile_origin_response_count
            != self.desired_redirect_endpoint_count
            or self.open_redirect_vector_count
            != len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
            or self.open_redirect_vector_response_count
            != self.desired_redirect_endpoint_count
            * len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
            or type(self.total_header_bytes) is not int
            or not self.response_count
            <= self.total_header_bytes
            <= self.response_count * FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
            or type(self.total_body_bytes) is not int
            or not self.response_count
            <= self.total_body_bytes
            <= self.response_count * FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES
            or self.max_header_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
            or self.max_body_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES
            or self.hsts_minimum_max_age_seconds
            != FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS
            or type(self.endpoint_network_operation_timeout_seconds) is not float
            or self.endpoint_network_operation_timeout_seconds
            != ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS
            or any(value is not True for value in structural)
            or type(live) is not bool
            or self.synthetic_transport_used is not (not live)
            or any(value is not live for value in dynamic)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra redirect endpoint probe receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "validation_scope",
    "graph_api_version",
    "authorization_permission_type",
    "authorization_permission_name",
    "authorization_permission_id",
    "authorization_consent_requirement",
    "authorization_credential_origin",
    "authorization_access_basis",
    "request_method",
    "minimum_tls_version",
    "expected_media_type",
    "expected_charset",
)

_COUNT_FIELDS = (
    "step213_graph_request_plan_count",
    "desired_redirect_endpoint_count",
    "desired_distinct_hostname_count",
    "sealed_dns_resolution_call_count",
    "resolved_address_count",
    "selected_address_count",
    "endpoint_requests_per_endpoint",
    "total_endpoint_request_count",
    "response_count",
    "sealed_tcp_connection_count",
    "sealed_tls_handshake_count",
    "baseline_response_count",
    "hostile_origin_response_count",
    "open_redirect_vector_count",
    "open_redirect_vector_response_count",
    "total_header_bytes",
    "total_body_bytes",
    "max_header_bytes",
    "max_body_bytes",
    "hsts_minimum_max_age_seconds",
)

_STRUCTURAL_TRUE_FIELDS = (
    "configuration_bound",
    "api_registration_revalidated",
    "calling_client_registration_revalidated",
    "inventory_projection_revalidated",
    "approved_inventory_digest_bound",
    "step214_preflight_validated",
    "step213_registration_prerequisite_rerun",
    "fixed_control_profile_bound",
    "step215_enforced_response_header_profile_bound",
    "redirects_derived_from_approved_registration",
    "exact_sorted_unique_redirect_set_validated",
    "exact_sorted_unique_hostname_set_validated",
    "complete_request_plan_prevalidated",
    "step213_before_endpoint_io_enforced",
    "all_host_resolution_barrier_required",
    "one_resolution_call_per_hostname_required",
    "all_returned_addresses_public_required",
    "deterministic_one_address_per_hostname_selected",
    "selected_address_scope_only_declared",
    "fresh_connection_per_request_required",
    "selected_preresolved_peer_required",
    "original_hostname_sni_certificate_host_required",
    "sequential_exact_ten_get_plan_validated",
    "no_body_authorization_cookie_proxy_redirect_retry_compression_validated",
    "endpoint_network_remaining_time_required",
    "tls_key_logging_disabled_required",
    "alpn_none_or_http_1_1_required",
    "strict_http_1_1_200_required",
    "response_bounds_validated",
    "text_html_utf8_validated",
    "required_security_headers_validated",
    "forbidden_response_headers_absent_validated",
    "exact_csp_validated",
    "static_html_baseline_validated",
    "hostile_origin_plan_validated",
    "bounded_vector_plan_validated",
    "variant_body_and_security_projection_match_validated",
    "privacy_minimized_receipt_validated",
)

_DYNAMIC_LIVE_FIELDS = (
    "step213_live_https_attested",
    "endpoint_live_https_attested",
    "sealed_provider_io_performed",
    "sealed_network_io_performed",
    "live_registration_checked",
    "live_spa_redirect_registration_checked",
    "live_all_host_resolution_barrier_enforced",
    "live_dns_resolution_checked",
    "live_all_returned_addresses_public_checked",
    "live_selected_peer_checked",
    "live_endpoint_reachability_checked",
    "live_tls_checked",
    "live_certificate_chain_checked",
    "live_hostname_checked",
    "live_exact_path_checked",
    "live_status_checked",
    "live_content_type_checked",
    "live_response_headers_checked",
    "live_csp_checked",
    "live_static_html_checked",
    "live_hostile_origin_observation_checked",
    "live_bounded_server_side_vectors_rejected",
    "live_endpoint_network_remaining_time_checked",
    "live_tls_key_logging_disabled_checked",
    "live_alpn_none_or_http_1_1_checked",
    "http_1_1_wire_validated",
    "response_framing_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "dns_wall_clock_timeout_enforced",
    "dns_cancellation_checked",
    "dnssec_checked",
    "resolver_authenticity_checked",
    "resolver_cache_state_checked",
    "dns_administrative_control_checked",
    "unselected_resolved_addresses_tls_checked",
    "unselected_resolved_addresses_http_checked",
    "all_resolved_addresses_behavior_checked",
    "certificate_revocation_checked",
    "certificate_transparency_checked",
    "trust_store_provenance_checked",
    "continuous_availability_checked",
    "response_freshness_checked",
    "atomic_provider_endpoint_snapshot_checked",
    "concurrent_provider_mutation_checked",
    "broad_application_cors_checked",
    "entra_token_endpoint_cors_checked",
    "global_open_redirect_behavior_checked",
    "client_javascript_navigation_checked",
    "dom_mutation_checked",
    "external_same_origin_asset_content_checked",
    "browser_rendering_checked",
    "unmodeled_response_header_browser_behavior_checked",
    "injected_transport_side_effects_checked",
    "provider_tenant_ownership_checked",
    "redirect_dns_administrative_ownership_checked",
    "redirect_legal_ownership_checked",
    "actual_token_type_checked",
    "token_permission_checked",
    "token_tenant_checked",
    "token_graph_audience_checked",
    "token_cloud_checked",
    "token_admin_consent_checked",
    "work_school_account_checked",
    "delegated_operator_identity_checked",
    "delegated_operator_role_checked",
    "operator_authorization_checked",
    "runtime_authorization_code_flow_checked",
    "runtime_pkce_s256_checked",
    "runtime_state_checked",
    "runtime_nonce_checked",
    "runtime_redirect_uri_match_checked",
    "runtime_browser_origin_checked",
    "runtime_no_client_secret_checked",
    "runtime_oidc_scopes_requested_checked",
    "runtime_api_scope_requested_checked",
    "runtime_callback_query_handling_checked",
    "runtime_token_redemption_checked",
    "service_worker_behavior_checked",
    "browser_extension_behavior_checked",
    "real_customer_user_journey_checked",
    "real_signed_api_token_checked",
    "application_configuration_mutation_performed",
    "dns_configuration_mutation_performed",
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


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed_sha256(namespace: str, label: str, *values: bytes | str) -> str:
    digest = hashlib.sha256()
    for value in (namespace, label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _evidence_sha256(label: str, *values: bytes | str) -> str:
    return _framed_sha256("engineer4me-step215-evidence-v1", label, *values)


def _identity_sha256(label: str, *values: str) -> str:
    return _framed_sha256("engineer4me-step215-identity-v1", label, *values)


def _step213_identity_sha256(label: str, *values: str) -> str:
    encoded = [
        value.encode("utf-8")
        for value in (
            "engineer4me-step213-identity-v1",
            label,
            str(len(values)),
            *values,
        )
    ]
    material = b"".join(
        str(len(value)).encode("ascii") + b":" + value for value in encoded
    )
    return hashlib.sha256(material).hexdigest()


def _step214_evidence_sha256(label: str, value: bytes) -> str:
    digest = hashlib.sha256()
    for item in ("engineer4me-step214-v1", label, "1", value):
        encoded = item if isinstance(item, bytes) else item.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _scrub_exception_graph(error: BaseException) -> tuple[bool, bool]:
    pending = [error]
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
        for attribute in ("__context__", "__cause__"):
            try:
                linked = BaseException.__getattribute__(current, attribute)
            except BaseException:  # noqa: BLE001  # pragma: no cover
                linked = None
            if isinstance(linked, BaseException):
                pending.append(linked)
        try:
            children = BaseException.__getattribute__(current, "exceptions")
        except BaseException:  # noqa: BLE001
            children = ()
        if type(children) is tuple:
            pending.extend(
                child for child in children if isinstance(child, BaseException)
            )
        try:
            notes = BaseException.__getattribute__(current, "__notes__")
            if isinstance(notes, list):
                notes.clear()
        except BaseException:  # noqa: BLE001,S110
            pass
        try:
            namespace = BaseException.__getattribute__(current, "__dict__")
            if isinstance(namespace, dict):
                namespace.clear()
        except BaseException:  # noqa: BLE001,S110  # pragma: no cover
            pass
        for attribute, value in (
            ("args", ()),
            ("__traceback__", None),
            ("__context__", None),
            ("__cause__", None),
            ("__suppress_context__", True),
        ):
            try:
                BaseException.__setattr__(current, attribute, value)
            except BaseException:  # noqa: BLE001,S110  # pragma: no cover
                pass
    return interrupted, terminated


class _StaticCallbackHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_depth = 0

    @staticmethod
    def _safe_url(value: object) -> bool:
        if (
            type(value) is not str
            or not value
            or len(value.encode("utf-8", errors="ignore"))
            > _MAX_HTML_URL_ATTRIBUTE_BYTES
            or value.startswith("//")
        ):
            return False
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            return False
        if (
            not value.startswith("/")
            or "//" in value
            or "\\" in value
            or "%" in value
            or any(
                character.isspace() or ord(character) < 0x20 or ord(character) > 0x7E
                for character in value
            )
        ):
            return False
        split = urlsplit(value)
        return bool(
            not split.scheme
            and not split.netloc
            and not any(segment in {".", ".."} for segment in split.path.split("/"))
        )

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.casefold()
        local_tag = normalized_tag.rsplit(":", 1)[-1]
        if local_tag in _FORBIDDEN_HTML_ELEMENTS:
            raise ValueError("forbidden callback element")
        names = [name.casefold() for name, _ in attrs]
        if len(names) != len(set(names)):
            raise ValueError("duplicate callback attribute")
        values = {name.casefold(): value for name, value in attrs}
        local_names = [name.rsplit(":", 1)[-1] for name in names]
        if any(name.startswith("on") for name in local_names):
            raise ValueError("inline event handler")
        if (
            "attributionsrc" in local_names
            or "base" in local_names
            or "referrerpolicy" in local_names
            or "style" in local_names
        ):
            raise ValueError("callback origin/referrer override")
        if any(
            type(value) is str and "url(" in value.casefold()
            for value in values.values()
        ):
            raise ValueError("callback CSS URL form")
        if (
            local_tag == "meta"
            and (values.get("http-equiv") or "").strip().casefold() == "refresh"
        ):
            raise ValueError("meta refresh")
        if (
            local_tag == "meta"
            and (values.get("name") or "").strip().casefold() == "referrer"
        ):
            raise ValueError("meta referrer override")
        for name, value in values.items():
            local_name = name.rsplit(":", 1)[-1]
            if local_name == "ping":
                candidates = value.split() if type(value) is str else []
                if not 1 <= len(candidates) <= _MAX_HTML_URL_LIST_ITEMS or any(
                    not self._safe_url(item) for item in candidates
                ):
                    raise ValueError("unsafe ping URL")
            elif local_name in {"imagesrcset", "srcset"}:
                if type(value) is not str or not value:
                    raise ValueError("unsafe srcset URL")
                candidates = [entry.strip() for entry in value.split(",")]
                if not 1 <= len(candidates) <= _MAX_HTML_URL_LIST_ITEMS:
                    raise ValueError("unsafe srcset URL")
                for candidate in candidates:
                    parts = candidate.split()
                    if (
                        not 1 <= len(parts) <= 2
                        or not self._safe_url(parts[0])
                        or (
                            len(parts) == 2
                            and re.fullmatch(
                                r"(?:[1-9][0-9]*w|(?:[1-9][0-9]*)(?:\.[0-9]+)?x)",
                                parts[1],
                            )
                            is None
                        )
                    ):
                        raise ValueError("unsafe srcset URL")
            elif local_name in _URL_SCALAR_ATTRIBUTES and not self._safe_url(value):
                raise ValueError("unsafe callback URL")
        if local_tag == "script":
            if names.count("src") != 1 or not self._safe_url(values.get("src")):
                raise ValueError("inline callback script")
            self.script_depth += 1

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        local_tag = tag.casefold().rsplit(":", 1)[-1]
        if local_tag in _FORBIDDEN_HTML_ELEMENTS:
            raise ValueError("forbidden callback element")
        if local_tag == "script":
            if self.script_depth < 1:
                raise ValueError("unbalanced callback script")
            self.script_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.script_depth and data.strip():
            raise ValueError("inline callback script")

    def handle_comment(self, data: str) -> None:
        if self.script_depth and data.strip():
            raise ValueError("inline callback script")

    def close(self) -> None:
        super().close()
        if self.script_depth:
            raise ValueError("unclosed callback script")


def _validate_callback_html(body: bytes) -> None:
    if not body or body.startswith(codecs.BOM_UTF8):
        raise ValueError("callback document is empty or has a BOM")
    decoded = body.decode("utf-8", errors="strict")
    if decoded.startswith("\ufeff"):
        raise ValueError("callback document has a BOM")
    parser = _StaticCallbackHTMLParser()
    parser.feed(decoded)
    parser.close()


def _header_map(
    response: EntraCallingClientRedirectEndpointResponse,
) -> dict[str, str]:
    response.validate()
    headers = dict(response.headers)
    if len(headers) != len(response.headers):
        raise ValueError("duplicate response header")
    if any(name in headers for name in _FORBIDDEN_RESPONSE_HEADERS):
        raise ValueError("forbidden response header")
    return headers


def _content_type(value: str | None) -> str:
    if (
        type(value) is not str
        or re.fullmatch(
            r'\s*text/html\s*;\s*charset\s*=\s*(?:utf-8|"utf-8")\s*',
            value,
            flags=re.IGNORECASE,
        )
        is None
    ):
        raise ValueError("invalid callback content type")
    return "text/html;charset=utf-8"


def _hsts(value: str | None) -> tuple[tuple[str, str | None], ...]:
    if type(value) is not str:
        raise ValueError("missing HSTS")
    directives: dict[str, str | None] = {}
    for raw in value.split(";"):
        raw = raw.strip()
        if not raw:
            raise ValueError("empty HSTS directive")
        parts = raw.split("=", 1)
        name = parts[0].strip().casefold()
        item = parts[1].strip() if len(parts) == 2 else None
        if name in directives or name not in {
            "max-age",
            "includesubdomains",
            "preload",
        }:
            raise ValueError("invalid HSTS directive")
        if name == "max-age":
            if item is None or not item.isascii() or not item.isdecimal():
                raise ValueError("invalid HSTS max-age")
            if len(item) > 1 and item.startswith("0"):
                raise ValueError("noncanonical HSTS max-age")
            if int(item) < FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS:
                raise ValueError("insufficient HSTS max-age")
        elif item is not None:
            raise ValueError("invalid valueless HSTS directive")
        directives[name] = item
    if "max-age" not in directives:
        raise ValueError("missing HSTS max-age")
    return tuple(sorted(directives.items()))


def _cache_control(value: str | None) -> tuple[tuple[str, str | None], ...]:
    if type(value) is not str:
        raise ValueError("missing cache control")
    directives: dict[str, str | None] = {}
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            raise ValueError("empty cache directive")
        parts = raw.split("=", 1)
        name = parts[0].strip().casefold()
        item = parts[1].strip() if len(parts) == 2 else None
        if _HEADER_TOKEN.fullmatch(name) is None or name in directives:
            raise ValueError("invalid cache directive")
        if item is not None:
            valid_quoted = (
                len(item) >= 2
                and item.startswith('"')
                and item.endswith('"')
                and all(0x20 <= ord(character) <= 0x7E for character in item[1:-1])
                and "\\" not in item[1:-1]
                and '"' not in item[1:-1]
            )
            if _CACHE_VALUE_TOKEN.fullmatch(item) is None and not valid_quoted:
                raise ValueError("invalid cache directive value")
        directives[name] = item
    if directives.get("no-store", object()) is not None:
        raise ValueError("no-store is required")
    return tuple(sorted(directives.items()))


def _csp(value: str | None) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if type(value) is not str:
        raise ValueError("missing CSP")
    raw_directives = value.split(";")
    if raw_directives and not raw_directives[-1].strip():
        raw_directives.pop()
    directives: dict[str, tuple[str, ...]] = {}
    for raw in raw_directives:
        parts = raw.split()
        if len(parts) < 2:
            raise ValueError("invalid CSP directive")
        name = parts[0].casefold()
        sources = tuple(item.casefold() for item in parts[1:])
        if name in directives:
            raise ValueError("duplicate CSP directive")
        directives[name] = sources
    if directives != _EXACT_CSP:
        raise ValueError("CSP does not match the exact callback baseline")
    return tuple(sorted(directives.items()))


def _security_projection(
    response: EntraCallingClientRedirectEndpointResponse,
) -> bytes:
    headers = _header_map(response)
    if response.status_code != FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE:
        raise ValueError("callback status is not accepted")
    content_type = _content_type(headers.get("content-type"))
    hsts = _hsts(headers.get("strict-transport-security"))
    referrer = headers.get("referrer-policy", "").strip().casefold()
    if referrer != "no-referrer":
        raise ValueError("callback referrer policy is not accepted")
    cache = _cache_control(headers.get("cache-control"))
    content_type_options = headers.get("x-content-type-options", "").strip().casefold()
    if content_type_options != "nosniff":
        raise ValueError("callback content-type options are not accepted")
    csp = _csp(headers.get("content-security-policy"))
    _validate_callback_html(response.body)
    return _canonical_bytes(
        {
            "status": response.status_code,
            "content_type": content_type,
            "strict_transport_security": hsts,
            "referrer_policy": referrer,
            "cache_control": cache,
            "x_content_type_options": content_type_options,
            "content_security_policy": csp,
            "forbidden_headers_absent": True,
        }
    )


def _projection_from_documents(
    calling_client_registration_document: bytes,
    inventory_document: bytes,
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...]]:
    registration = json.loads(calling_client_registration_document.decode("utf-8"))[
        "registration"
    ]
    inventory = json.loads(inventory_document.decode("utf-8"))["inventory"]
    principal = next(
        value
        for value in inventory["service_principals"]
        if value["role"] == "calling_client"
    )
    identities = {
        "tenant_id": registration["tenant_id"],
        "calling_client_application_id": registration["calling_client_application_id"],
        "calling_client_application_object_id": registration[
            "calling_client_application_object_id"
        ],
        "calling_client_service_principal_object_id": principal[
            "service_principal_object_id"
        ],
    }
    redirect_uris = tuple(registration["spa_redirect_uris"])
    hostnames = tuple(sorted({urlsplit(uri).hostname for uri in redirect_uris}))
    if (
        not 1 <= len(redirect_uris) <= 3
        or redirect_uris != tuple(sorted(set(redirect_uris)))
        or any(hostname is None for hostname in hostnames)
        or principal["application_id"] != identities["calling_client_application_id"]
        or principal["application_owner_organization_id"] != identities["tenant_id"]
    ):
        raise ValueError("approved endpoint projection is invalid")
    return identities, redirect_uris, hostnames


def _request_plan(
    redirect_uris: tuple[str, ...],
) -> tuple[EntraCallingClientRedirectEndpointRequest, ...]:
    requests: list[EntraCallingClientRedirectEndpointRequest] = []
    for endpoint_sequence, redirect_uri in enumerate(redirect_uris, start=1):
        hostname = urlsplit(redirect_uri).hostname
        definitions: list[tuple[str, str | None, str, tuple[tuple[str, str], ...]]] = [
            (
                "baseline",
                None,
                redirect_uri,
                (("Accept", "text/html"), ("Accept-Encoding", "identity")),
            ),
            (
                "hostile_origin",
                None,
                redirect_uri,
                (
                    ("Accept", "text/html"),
                    ("Accept-Encoding", "identity"),
                    ("Origin", FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN),
                ),
            ),
        ]
        target = quote(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET, safe="")
        definitions.extend(
            (
                "bounded_open_redirect_vector",
                vector,
                f"{redirect_uri}?{vector}={target}",
                (("Accept", "text/html"), ("Accept-Encoding", "identity")),
            )
            for vector in FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
        )
        for within_sequence, (kind, vector, url, headers) in enumerate(
            definitions,
            start=1,
        ):
            requests.append(
                EntraCallingClientRedirectEndpointRequest(
                    sequence=len(requests) + 1,
                    endpoint_sequence=endpoint_sequence,
                    request_sequence_for_endpoint=within_sequence,
                    kind=kind,
                    vector_name=vector,
                    redirect_uri=redirect_uri,
                    method="GET",
                    url=url,
                    hostname=hostname,
                    port=443,
                    headers=headers,
                    body=None,
                    total_timeout_seconds=(
                        ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS
                    ),
                    maximum_header_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
                    maximum_body_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
                    follow_redirects=False,
                    maximum_retries=0,
                    proxy_allowed=False,
                    compression_allowed=False,
                )
            )
    return tuple(requests)


def _step214_plan_material(
    requests: tuple[EntraCallingClientRedirectEndpointRequest, ...],
) -> bytes:
    return _canonical_bytes(
        [
            {
                "sequence": request.sequence,
                "kind": request.kind,
                **(
                    {"vector_name": request.vector_name}
                    if request.vector_name is not None
                    else {}
                ),
                "method": "GET",
                "url": request.url,
                "port": 443,
                "headers": [list(item) for item in request.headers],
                "body": None,
                "authorization": None,
                "cookie": None,
                "proxy": False,
                "follow_redirects": False,
                "retries": 0,
                "compression": False,
            }
            for request in requests
        ]
    )


def _prepare(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
) -> dict[str, Any]:
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication preview is required")
    if any(
        type(value) is not bytes
        for value in (
            document,
            api_registration_document,
            calling_client_registration_document,
            inventory_document,
        )
    ):
        raise TypeError("approved source documents must be bytes")
    if any(
        not _is_lower_sha256(value)
        for value in (
            accepted_api_registration_document_sha256,
            accepted_calling_client_registration_document_sha256,
            approved_inventory_document_sha256,
        )
    ):
        raise TypeError("approved source-document digests are required")
    if (
        type(authorization)
        is not EntraCallingClientRegistrationGraphAuthorizationContract
    ):
        raise TypeError("Step 213 authorization contract is required")
    authorization.__post_init__()
    readiness = load_entra_calling_client_redirect_endpoint_readiness(
        document=document,
        authentication_preview=authentication_preview,
        api_registration_document=api_registration_document,
        accepted_api_registration_document_sha256=accepted_api_registration_document_sha256,
        calling_client_registration_document=calling_client_registration_document,
        accepted_calling_client_registration_document_sha256=(
            accepted_calling_client_registration_document_sha256
        ),
        inventory_document=inventory_document,
        approved_inventory_document_sha256=approved_inventory_document_sha256,
    )
    if type(readiness) is not EntraCallingClientRedirectEndpointReadinessReceipt:
        raise ValueError("Step 214 readiness is invalid")
    readiness.__post_init__()
    identities, redirect_uris, hostnames = _projection_from_documents(
        calling_client_registration_document,
        inventory_document,
    )
    requests = _request_plan(redirect_uris)
    if (
        readiness.control_profile
        != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE
        or readiness.desired_redirect_endpoint_count != len(redirect_uris)
        or readiness.desired_distinct_hostname_count != len(hostnames)
        or readiness.future_total_https_request_count != len(requests)
        or not hmac.compare_digest(
            readiness.future_endpoint_request_plan_sha256,
            _step214_evidence_sha256(
                "future_endpoint_request_plan",
                _step214_plan_material(requests),
            ),
        )
    ):
        raise ValueError("Step 214 readiness plan does not match")
    return {
        "readiness": readiness,
        "readiness_rendered": render_entra_calling_client_redirect_endpoint_readiness_receipt(
            readiness
        ),
        "identities": identities,
        "redirect_uris": redirect_uris,
        "hostnames": hostnames,
        "requests": requests,
    }


def _validate_registration_receipt(
    receipt: EntraCallingClientRegistrationGraphProbeReceipt,
    *,
    prepared: dict[str, Any],
    live: bool,
) -> str:
    if type(receipt) is not EntraCallingClientRegistrationGraphProbeReceipt:
        raise ValueError("Step 213 registration receipt is invalid")
    receipt.__post_init__()
    readiness = prepared["readiness"]
    identities = prepared["identities"]
    redirect_uris = prepared["redirect_uris"]
    if (
        receipt.receipt_type
        != ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE
        or receipt.live_https_transport_attested is not live
        or receipt.provider_io_performed is not live
        or receipt.live_spa_redirect_registration_checked is not live
        or not hmac.compare_digest(
            receipt.configuration_sha256,
            readiness.configuration_sha256,
        )
        or not hmac.compare_digest(
            receipt.api_registration_document_sha256,
            readiness.api_registration_document_sha256,
        )
        or not hmac.compare_digest(
            receipt.calling_client_registration_document_sha256,
            readiness.calling_client_registration_document_sha256,
        )
        or not hmac.compare_digest(
            receipt.inventory_document_sha256,
            readiness.inventory_document_sha256,
        )
        or not hmac.compare_digest(
            receipt.tenant_id_sha256,
            _step213_identity_sha256("tenant_id", identities["tenant_id"]),
        )
        or not hmac.compare_digest(
            receipt.calling_client_application_id_sha256,
            _step213_identity_sha256(
                "calling_client_application_id",
                identities["calling_client_application_id"],
            ),
        )
        or not hmac.compare_digest(
            receipt.calling_client_application_object_id_sha256,
            _step213_identity_sha256(
                "calling_client_application_object_id",
                identities["calling_client_application_object_id"],
            ),
        )
        or not hmac.compare_digest(
            receipt.spa_redirect_uris_sha256,
            _step213_identity_sha256(
                "spa_redirect_uris",
                str(len(redirect_uris)),
                *redirect_uris,
            ),
        )
    ):
        raise ValueError("Step 213 registration proof does not match Step 214")
    return render_entra_calling_client_registration_graph_probe_receipt(receipt)


def _request_material(
    requests: tuple[EntraCallingClientRedirectEndpointRequest, ...],
) -> bytes:
    return _canonical_bytes(
        [
            {field: getattr(request, field) for field in request.__dataclass_fields__}
            for request in requests
        ]
    )


def _evaluate(
    *,
    prepared: dict[str, Any],
    registration_rendered: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    transport: EntraCallingClientRedirectEndpointTransport,
    live: bool,
) -> EntraCallingClientRedirectEndpointProbeReceipt:
    if not callable(transport):
        raise TypeError("redirect endpoint transport is required")
    requests = prepared["requests"]
    result = transport(requests)
    if type(result) is not EntraCallingClientRedirectEndpointTransportResult:
        raise ValueError("redirect endpoint transport result is invalid")
    result.validate()
    if result.live_https_attested is not live:
        raise ValueError("redirect endpoint transport provenance is invalid")
    hostnames = prepared["hostnames"]
    observations = result.dns_observations
    for observation in observations:
        if type(observation) is not EntraCallingClientRedirectEndpointDNSObservation:
            raise ValueError("redirect endpoint DNS observation type is invalid")
        observation.__post_init__()
    if tuple(value.hostname for value in observations) != hostnames:
        raise ValueError("redirect endpoint DNS observations do not match")
    by_hostname: dict[str, EntraCallingClientRedirectEndpointDNSObservation] = {
        value.hostname: value for value in observations
    }
    if len(by_hostname) != len(hostnames):
        raise ValueError("redirect endpoint DNS observations are not unique")
    responses = result.responses
    if len(responses) != len(requests):
        raise ValueError("redirect endpoint response count does not match")
    projections: list[bytes] = []
    for request, response in zip(requests, responses, strict=True):
        response.validate()
        if (
            response.live_https_attested is not live
            or response.request_url != request.url
            or response.final_url != request.url
            or response.connected_address
            != by_hostname[request.hostname].resolved_addresses[0]
            or response.tls_version not in {"TLSv1.2", "TLSv1.3"}
            or (live and not response.connected_peer_preresolved)
            or (live and not response.certificate_chain_verified)
            or (live and not response.hostname_verified)
        ):
            raise ValueError("redirect endpoint response binding is invalid")
        projections.append(_security_projection(response))
    for endpoint_index in range(len(prepared["redirect_uris"])):
        start = endpoint_index * FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        baseline_body = responses[start].body
        baseline_projection = projections[start]
        for index in range(
            start + 1, start + FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        ):
            if not hmac.compare_digest(
                responses[index].body, baseline_body
            ) or not hmac.compare_digest(projections[index], baseline_projection):
                raise ValueError("redirect endpoint variant differs from baseline")

    readiness = prepared["readiness"]
    identities = prepared["identities"]
    redirect_uris = prepared["redirect_uris"]
    selected = tuple(
        (observation.hostname, observation.resolved_addresses[0])
        for observation in observations
    )
    dns_material = _canonical_bytes(
        [
            {
                "hostname": value.hostname,
                "resolved_addresses": value.resolved_addresses,
                "resolver_call_count": value.resolver_call_count,
            }
            for value in observations
        ]
    )
    tls_material = _canonical_bytes(
        [
            {
                "request_sequence": request.sequence,
                "hostname": request.hostname,
                "connected_address": response.connected_address,
                "tls_version": response.tls_version,
                "live_attested": response.live_https_attested,
            }
            for request, response in zip(requests, responses, strict=True)
        ]
    )
    baseline_bodies = tuple(
        responses[index].body
        for index in range(
            0, len(responses), FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        )
    )
    hostile_bodies = tuple(
        responses[index].body
        for index in range(
            1, len(responses), FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        )
    )
    vector_bodies = tuple(
        response.body
        for index, response in enumerate(responses)
        if index % FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT >= 2
    )
    return EntraCallingClientRedirectEndpointProbeReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCHEMA_VERSION,
        validation_scope=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE,
        graph_api_version=ENTRA_GRAPH_API_VERSION,
        authorization_permission_type=authorization.permission_type,
        authorization_permission_name=authorization.permission_name,
        authorization_permission_id=authorization.permission_id,
        authorization_consent_requirement=authorization.consent_requirement,
        authorization_credential_origin=authorization.credential_origin,
        authorization_access_basis=authorization.access_basis,
        request_method=FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD,
        minimum_tls_version=FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION,
        expected_media_type=FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE,
        expected_charset=FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET,
        configuration_sha256=readiness.configuration_sha256,
        api_registration_document_sha256=readiness.api_registration_document_sha256,
        calling_client_registration_document_sha256=(
            readiness.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=(
            readiness.approved_inventory_document_sha256
        ),
        inventory_document_sha256=readiness.inventory_document_sha256,
        redirect_endpoint_control_document_sha256=(
            readiness.redirect_endpoint_control_document_sha256
        ),
        enforced_response_header_profile_sha256=_evidence_sha256(
            "enforced_response_header_profile",
            _canonical_bytes(sorted(_FORBIDDEN_RESPONSE_HEADERS)),
        ),
        step214_preflight_receipt_sha256=hashlib.sha256(
            prepared["readiness_rendered"].encode("utf-8")
        ).hexdigest(),
        step213_registration_probe_receipt_sha256=hashlib.sha256(
            registration_rendered.encode("utf-8")
        ).hexdigest(),
        request_plan_sha256=_evidence_sha256(
            "request_plan", _request_material(requests)
        ),
        dns_observation_sha256=_evidence_sha256("dns_observation", dns_material),
        selected_address_set_sha256=_evidence_sha256(
            "selected_address_set", _canonical_bytes(selected)
        ),
        tls_observation_sha256=_evidence_sha256("tls_observation", tls_material),
        response_security_projection_sha256=_evidence_sha256(
            "response_security_projection", *projections
        ),
        baseline_response_set_sha256=_evidence_sha256(
            "baseline_response_set", *baseline_bodies
        ),
        hostile_origin_response_set_sha256=_evidence_sha256(
            "hostile_origin_response_set", *hostile_bodies
        ),
        bounded_vector_response_set_sha256=_evidence_sha256(
            "bounded_vector_response_set", *vector_bodies
        ),
        all_response_body_set_sha256=_evidence_sha256(
            "all_response_body_set", *(response.body for response in responses)
        ),
        tenant_id_sha256=_identity_sha256("tenant_id", identities["tenant_id"]),
        calling_client_application_id_sha256=_identity_sha256(
            "calling_client_application_id",
            identities["calling_client_application_id"],
        ),
        calling_client_application_object_id_sha256=_identity_sha256(
            "calling_client_application_object_id",
            identities["calling_client_application_object_id"],
        ),
        calling_client_service_principal_object_id_sha256=_identity_sha256(
            "calling_client_service_principal_object_id",
            identities["calling_client_service_principal_object_id"],
        ),
        spa_redirect_uris_sha256=_identity_sha256(
            "spa_redirect_uris", str(len(redirect_uris)), *redirect_uris
        ),
        redirect_hostnames_sha256=_identity_sha256(
            "redirect_hostnames", str(len(hostnames)), *hostnames
        ),
        step213_graph_request_plan_count=(
            ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT
        ),
        desired_redirect_endpoint_count=len(redirect_uris),
        desired_distinct_hostname_count=len(hostnames),
        sealed_dns_resolution_call_count=(
            sum(value.resolver_call_count for value in observations) if live else 0
        ),
        resolved_address_count=sum(
            len(value.resolved_addresses) for value in observations
        ),
        selected_address_count=len(selected),
        endpoint_requests_per_endpoint=FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT,
        total_endpoint_request_count=len(requests),
        response_count=len(responses),
        sealed_tcp_connection_count=len(responses) if live else 0,
        sealed_tls_handshake_count=len(responses) if live else 0,
        baseline_response_count=len(redirect_uris),
        hostile_origin_response_count=len(redirect_uris),
        open_redirect_vector_count=len(
            FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
        ),
        open_redirect_vector_response_count=(
            len(redirect_uris)
            * len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
        ),
        total_header_bytes=sum(value.header_bytes for value in responses),
        total_body_bytes=sum(len(value.body) for value in responses),
        max_header_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
        max_body_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
        hsts_minimum_max_age_seconds=(
            FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS
        ),
        endpoint_network_operation_timeout_seconds=(
            ENTRA_REDIRECT_ENDPOINT_TOTAL_REQUEST_TIMEOUT_SECONDS
        ),
        **{field: True for field in _STRUCTURAL_TRUE_FIELDS},
        synthetic_transport_used=not live,
        **{field: live for field in _DYNAMIC_LIVE_FIELDS},
        **{field: False for field in _DEFERRED_FALSE_FIELDS},
    )


_MODULE_OWNED_STEP213_VALIDATE = validate_entra_calling_client_registration_graph_probe
_MODULE_OWNED_STEP213_LIVE = probe_live_entra_calling_client_registration_graph
_MODULE_OWNED_ENDPOINT_LOADER = BoundedHTTPSEntraCallingClientRedirectEndpointLoader


def _public_boundary(
    operation: Any,
    values_to_clear: list[Any],
) -> EntraCallingClientRedirectEndpointProbeReceipt:
    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    failed = False
    try:
        result = operation()
    except KeyboardInterrupt as caught:
        error = caught
        interrupted = True
    except SystemExit as caught:
        error = caught
        terminated = True
    except TypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001 - sanitize public boundary
        error = caught
        failed = True
    finally:
        if error is not None:
            nested_interrupted, nested_terminated = _scrub_exception_graph(error)
            interrupted = interrupted or nested_interrupted
            terminated = terminated or nested_terminated
        error = None
        operation = None
        for index in range(len(values_to_clear)):
            values_to_clear[index] = None
        values_to_clear = []
    if interrupted:
        result = None
        raise KeyboardInterrupt("Entra redirect endpoint probe interrupted")
    if terminated:
        result = None
        raise SystemExit("Entra redirect endpoint probe terminated")
    if invalid:
        result = None
        raise TypeError("Entra redirect endpoint probe inputs are invalid")
    if failed or result is None:
        result = None
        raise EntraCallingClientRedirectEndpointProbeError(
            "Entra redirect endpoint probe failed"
        )
    return result


def validate_entra_calling_client_redirect_endpoint_probe(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    calling_client_registration_transport: EntraCallingClientRegistrationGraphTransport,
    endpoint_transport: EntraCallingClientRedirectEndpointTransport,
) -> EntraCallingClientRedirectEndpointProbeReceipt:
    """Validate deterministic Graph/endpoint responses as synthetic evidence."""

    values = [
        document,
        authentication_preview,
        api_registration_document,
        accepted_api_registration_document_sha256,
        calling_client_registration_document,
        accepted_calling_client_registration_document_sha256,
        inventory_document,
        approved_inventory_document_sha256,
        authorization,
        calling_client_registration_transport,
        endpoint_transport,
    ]

    def operation() -> EntraCallingClientRedirectEndpointProbeReceipt:
        prepared = _prepare(
            document=document,
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
        )
        registration = _MODULE_OWNED_STEP213_VALIDATE(
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
            transport=calling_client_registration_transport,
        )
        registration_rendered = _validate_registration_receipt(
            registration,
            prepared=prepared,
            live=False,
        )
        return _evaluate(
            prepared=prepared,
            registration_rendered=registration_rendered,
            authorization=authorization,
            transport=endpoint_transport,
            live=False,
        )

    try:
        return _public_boundary(operation, values)
    finally:
        document = None
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
        authorization = None
        calling_client_registration_transport = None
        endpoint_transport = None


def probe_live_entra_calling_client_redirect_endpoint(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraCallingClientRegistrationGraphAuthorizationContract,
    delegated_access_token: str,
) -> EntraCallingClientRedirectEndpointProbeReceipt:
    """Run the sealed Step 213 proof, then the sealed endpoint transport."""

    values = [
        document,
        authentication_preview,
        api_registration_document,
        accepted_api_registration_document_sha256,
        calling_client_registration_document,
        accepted_calling_client_registration_document_sha256,
        inventory_document,
        approved_inventory_document_sha256,
        authorization,
        delegated_access_token,
    ]

    def operation() -> EntraCallingClientRedirectEndpointProbeReceipt:
        nonlocal delegated_access_token
        prepared = _prepare(
            document=document,
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
        )
        registration = _MODULE_OWNED_STEP213_LIVE(
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
            delegated_access_token=delegated_access_token,
        )
        delegated_access_token = None
        values[-1] = None
        registration_rendered = _validate_registration_receipt(
            registration,
            prepared=prepared,
            live=True,
        )
        loader = _MODULE_OWNED_ENDPOINT_LOADER()
        try:
            return _evaluate(
                prepared=prepared,
                registration_rendered=registration_rendered,
                authorization=authorization,
                transport=loader,
                live=True,
            )
        finally:
            loader.close()

    try:
        return _public_boundary(operation, values)
    finally:
        document = None
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
        authorization = None
        delegated_access_token = None


def render_entra_calling_client_redirect_endpoint_probe_receipt(
    receipt: EntraCallingClientRedirectEndpointProbeReceipt,
) -> str:
    """Render canonical privacy-minimized endpoint proof evidence."""

    if type(receipt) is not EntraCallingClientRedirectEndpointProbeReceipt:
        raise TypeError("Entra redirect endpoint probe receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_PROBE_SCOPE",
    "EntraCallingClientRedirectEndpointProbeError",
    "EntraCallingClientRedirectEndpointProbeReceipt",
    "probe_live_entra_calling_client_redirect_endpoint",
    "render_entra_calling_client_redirect_endpoint_probe_receipt",
    "validate_entra_calling_client_redirect_endpoint_probe",
]
