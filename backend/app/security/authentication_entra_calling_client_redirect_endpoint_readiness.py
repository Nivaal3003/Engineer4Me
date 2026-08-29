"""Offline security-control readiness for Entra SPA redirect endpoints.

This contract re-runs the approved Step 207 inventory projection (which in
turn re-runs the Step 205 calling-client, API-registration, and configuration
contracts), then derives the exact one-to-three approved SPA redirect URIs.
The Step 214 document deliberately carries no redirect list: callers cannot
replace or independently re-state the approved targets.

The fixed profile describes a future, bounded server-side observation plan.
It performs no DNS, TLS, HTTP, browser, provider, filesystem, environment,
database, or process I/O and makes no live endpoint or ownership claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from pydantic import model_validator

from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel

ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_redirect_endpoint_"
    "security_control_readiness"
)
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_redirect_endpoint_"
    "security_control_readiness_receipt"
)
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE = (
    "engineer4me_reviewed_redirect_endpoint_security_control_profile"
)
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE = (
    "offline_spa_redirect_endpoint_security_control_desired_state_only"
)
ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE = (
    "engineer4me_entra_spa_redirect_endpoint_security_controls_v1"
)
MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_BYTES = 4_096
MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_NESTING_DEPTH = 2
MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTAINERS = 8

FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD = "GET"
FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION = "1.2"
FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE = "text/html"
FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET = "utf-8"
FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE = 200
FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES = 16_384
FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES = 262_144
FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS = 31_536_000
FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN = "https://attacker.invalid"
FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET = "https://attacker.invalid/steal"
FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES = (
    "continue",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "returnUrl",
    "target",
    "url",
)
FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT = 10
_SHA256_HEX_LENGTH = 64


class EntraCallingClientRedirectEndpointReadinessError(ValueError):
    """Sanitized rejection of an invalid local endpoint-control document."""


class _ArgumentTypeError(TypeError):
    """Private marker for public argument preflight failures."""


class EntraCallingClientRedirectEndpointDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_redirect_endpoint_"
        "security_control_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_redirect_endpoint_security_control_profile"]
    approved_configuration_sha256: str
    approved_api_registration_document_sha256: str
    approved_calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    control_profile: Literal[
        "engineer4me_entra_spa_redirect_endpoint_security_controls_v1"
    ]

    @model_validator(mode="after")
    def validate_digests(self) -> EntraCallingClientRedirectEndpointDocument:
        if any(
            not _is_lower_sha256(value)
            for value in (
                self.approved_configuration_sha256,
                self.approved_api_registration_document_sha256,
                self.approved_calling_client_registration_document_sha256,
                self.approved_inventory_document_sha256,
            )
        ):
            raise ValueError("approved digests must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientRedirectEndpointReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    control_profile: str
    future_request_method: str
    future_minimum_tls_version: str
    future_expected_media_type: str
    future_expected_charset: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    offline_inventory_receipt_sha256: str
    redirect_endpoint_control_document_sha256: str
    tenant_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    calling_client_service_principal_object_id_sha256: str
    calling_client_service_principal_app_id_mapping_sha256: str
    spa_redirect_uris_sha256: str
    redirect_hostnames_sha256: str
    future_endpoint_request_plan_sha256: str
    future_security_header_profile_sha256: str
    future_content_security_policy_profile_sha256: str
    future_html_profile_sha256: str
    future_open_redirect_vector_plan_sha256: str
    desired_redirect_endpoint_count: int
    desired_distinct_hostname_count: int
    future_dns_resolution_call_count: int
    future_https_request_count_per_endpoint: int
    future_total_https_request_count: int
    future_open_redirect_vector_count: int
    future_expected_status_code: int
    future_max_header_bytes: int
    future_max_body_bytes: int
    future_hsts_minimum_max_age_seconds: int
    configuration_bound: bool
    api_registration_bound: bool
    calling_client_registration_bound: bool
    approved_inventory_digest_bound: bool
    offline_inventory_revalidated: bool
    calling_client_identity_mapping_validated: bool
    redirect_uris_derived_from_approved_registration: bool
    exact_sorted_unique_redirect_uri_set_validated: bool
    canonical_production_https_redirects_validated: bool
    exact_case_sensitive_target_paths_required: bool
    fixed_control_profile_validated: bool
    all_targets_prevalidated_before_io_required: bool
    sequential_bounded_requests_required: bool
    get_only_required: bool
    no_request_body_required: bool
    no_authorization_header_required: bool
    no_cookie_required: bool
    no_proxy_required: bool
    no_redirect_following_required: bool
    no_retry_required: bool
    no_compression_required: bool
    public_resolved_addresses_only_required: bool
    connected_peer_public_and_preresolved_required: bool
    tls_minimum_1_2_required: bool
    tls_chain_validation_required: bool
    tls_hostname_validation_required: bool
    exact_final_url_required: bool
    direct_200_required: bool
    text_html_utf8_required: bool
    header_bound_required: bool
    body_bound_required: bool
    location_header_absent_required: bool
    set_cookie_header_absent_required: bool
    content_encoding_header_absent_required: bool
    acao_header_absent_required: bool
    acac_header_absent_required: bool
    hsts_minimum_required: bool
    referrer_policy_no_referrer_required: bool
    cache_control_no_store_required: bool
    x_content_type_options_nosniff_required: bool
    csp_baseline_required: bool
    safe_callback_html_baseline_required: bool
    hostile_origin_probe_required: bool
    exact_open_redirect_vector_plan_required: bool
    variant_response_matches_baseline_required: bool
    step213_live_registration_rerun_required: bool
    endpoint_controls_before_runtime_pkce_required: bool
    offline_desired_state_validated: bool
    provider_io_performed: bool
    network_io_performed: bool
    dns_resolution_checked: bool
    dns_public_address_checked: bool
    connected_peer_address_checked: bool
    redirect_dns_control_checked: bool
    redirect_dns_administrative_ownership_checked: bool
    redirect_legal_ownership_checked: bool
    redirect_endpoint_reachability_checked: bool
    redirect_endpoint_tls_checked: bool
    redirect_endpoint_certificate_chain_checked: bool
    redirect_endpoint_hostname_checked: bool
    redirect_exact_path_deployment_checked: bool
    redirect_response_status_checked: bool
    redirect_response_content_type_checked: bool
    redirect_response_headers_checked: bool
    redirect_hsts_checked: bool
    redirect_referrer_policy_checked: bool
    redirect_cache_control_checked: bool
    redirect_content_security_policy_checked: bool
    redirect_html_security_checked: bool
    redirect_hostile_origin_behavior_checked: bool
    redirect_application_cors_checked: bool
    entra_token_endpoint_cors_checked: bool
    bounded_server_side_redirect_vectors_rejected: bool
    open_redirect_behavior_checked: bool
    step213_live_registration_checked: bool
    live_spa_redirect_registration_checked: bool
    provider_tenant_ownership_checked: bool
    runtime_authorization_code_flow_checked: bool
    runtime_pkce_s256_checked: bool
    runtime_state_checked: bool
    runtime_nonce_checked: bool
    runtime_redirect_uri_match_checked: bool
    runtime_browser_origin_checked: bool
    runtime_no_client_secret_checked: bool
    runtime_oidc_scopes_requested_checked: bool
    runtime_api_scope_requested_checked: bool
    real_customer_user_journey_checked: bool
    real_signed_api_token_checked: bool
    application_mutation_performed: bool
    dns_mutation_performed: bool
    endpoint_mutation_performed: bool
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
        if (
            any(
                type(getattr(self, field)) is not str for field in _PUBLIC_STRING_FIELDS
            )
            or self.receipt_type != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE
            or self.validation_scope != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE
            or self.control_profile
            != ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE
            or self.future_request_method != FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD
            or self.future_minimum_tls_version
            != FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION
            or self.future_expected_media_type
            != FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE
            or self.future_expected_charset != FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or type(self.desired_redirect_endpoint_count) is not int
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or type(self.desired_distinct_hostname_count) is not int
            or not 1
            <= self.desired_distinct_hostname_count
            <= self.desired_redirect_endpoint_count
            or type(self.future_dns_resolution_call_count) is not int
            or self.future_dns_resolution_call_count
            != self.desired_distinct_hostname_count
            or type(self.future_https_request_count_per_endpoint) is not int
            or self.future_https_request_count_per_endpoint
            != FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            or FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            != 2 + len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
            or type(self.future_total_https_request_count) is not int
            or self.future_total_https_request_count
            != self.desired_redirect_endpoint_count
            * FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
            or type(self.future_open_redirect_vector_count) is not int
            or self.future_open_redirect_vector_count
            != len(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES)
            or type(self.future_expected_status_code) is not int
            or self.future_expected_status_code
            != FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE
            or type(self.future_max_header_bytes) is not int
            or self.future_max_header_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES
            or type(self.future_max_body_bytes) is not int
            or self.future_max_body_bytes != FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES
            or type(self.future_hsts_minimum_max_age_seconds) is not int
            or self.future_hsts_minimum_max_age_seconds
            != FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS
            or any(value is not True for value in structural)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra redirect endpoint readiness receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "control_profile",
    "future_request_method",
    "future_minimum_tls_version",
    "future_expected_media_type",
    "future_expected_charset",
)


_STRUCTURAL_TRUE_FIELDS = (
    "configuration_bound",
    "api_registration_bound",
    "calling_client_registration_bound",
    "approved_inventory_digest_bound",
    "offline_inventory_revalidated",
    "calling_client_identity_mapping_validated",
    "redirect_uris_derived_from_approved_registration",
    "exact_sorted_unique_redirect_uri_set_validated",
    "canonical_production_https_redirects_validated",
    "exact_case_sensitive_target_paths_required",
    "fixed_control_profile_validated",
    "all_targets_prevalidated_before_io_required",
    "sequential_bounded_requests_required",
    "get_only_required",
    "no_request_body_required",
    "no_authorization_header_required",
    "no_cookie_required",
    "no_proxy_required",
    "no_redirect_following_required",
    "no_retry_required",
    "no_compression_required",
    "public_resolved_addresses_only_required",
    "connected_peer_public_and_preresolved_required",
    "tls_minimum_1_2_required",
    "tls_chain_validation_required",
    "tls_hostname_validation_required",
    "exact_final_url_required",
    "direct_200_required",
    "text_html_utf8_required",
    "header_bound_required",
    "body_bound_required",
    "location_header_absent_required",
    "set_cookie_header_absent_required",
    "content_encoding_header_absent_required",
    "acao_header_absent_required",
    "acac_header_absent_required",
    "hsts_minimum_required",
    "referrer_policy_no_referrer_required",
    "cache_control_no_store_required",
    "x_content_type_options_nosniff_required",
    "csp_baseline_required",
    "safe_callback_html_baseline_required",
    "hostile_origin_probe_required",
    "exact_open_redirect_vector_plan_required",
    "variant_response_matches_baseline_required",
    "step213_live_registration_rerun_required",
    "endpoint_controls_before_runtime_pkce_required",
    "offline_desired_state_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "provider_io_performed",
    "network_io_performed",
    "dns_resolution_checked",
    "dns_public_address_checked",
    "connected_peer_address_checked",
    "redirect_dns_control_checked",
    "redirect_dns_administrative_ownership_checked",
    "redirect_legal_ownership_checked",
    "redirect_endpoint_reachability_checked",
    "redirect_endpoint_tls_checked",
    "redirect_endpoint_certificate_chain_checked",
    "redirect_endpoint_hostname_checked",
    "redirect_exact_path_deployment_checked",
    "redirect_response_status_checked",
    "redirect_response_content_type_checked",
    "redirect_response_headers_checked",
    "redirect_hsts_checked",
    "redirect_referrer_policy_checked",
    "redirect_cache_control_checked",
    "redirect_content_security_policy_checked",
    "redirect_html_security_checked",
    "redirect_hostile_origin_behavior_checked",
    "redirect_application_cors_checked",
    "entra_token_endpoint_cors_checked",
    "bounded_server_side_redirect_vectors_rejected",
    "open_redirect_behavior_checked",
    "step213_live_registration_checked",
    "live_spa_redirect_registration_checked",
    "provider_tenant_ownership_checked",
    "runtime_authorization_code_flow_checked",
    "runtime_pkce_s256_checked",
    "runtime_state_checked",
    "runtime_nonce_checked",
    "runtime_redirect_uri_match_checked",
    "runtime_browser_origin_checked",
    "runtime_no_client_secret_checked",
    "runtime_oidc_scopes_requested_checked",
    "runtime_api_scope_requested_checked",
    "real_customer_user_journey_checked",
    "real_signed_api_token_checked",
    "application_mutation_performed",
    "dns_mutation_performed",
    "endpoint_mutation_performed",
    "receipt_self_authenticating",
    "activation_ready",
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
    for value in ("engineer4me-step214-v1", label, str(len(values)), *values):
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
            if depth > MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTAINERS:
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
    calling_client_registration_document: bytes,
    inventory_document: bytes,
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...]]:
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
        principal = next(
            entry
            for entry in inventory["service_principals"]
            if entry["role"] == "calling_client"
        )
        values = {
            "tenant_id": registration["tenant_id"],
            "calling_client_application_id": registration[
                "calling_client_application_id"
            ],
            "calling_client_application_object_id": registration[
                "calling_client_application_object_id"
            ],
            "calling_client_service_principal_object_id": principal[
                "service_principal_object_id"
            ],
        }
        redirect_uris = tuple(registration["spa_redirect_uris"])
        hostnames = tuple(sorted({urlsplit(uri).hostname for uri in redirect_uris}))
    except (KeyError, StopIteration, TypeError, UnicodeDecodeError, ValueError):
        raise ValueError("validated projection unavailable") from None
    if (
        application["application_id"] != values["calling_client_application_id"]
        or application["application_object_id"]
        != values["calling_client_application_object_id"]
        or principal["application_id"] != values["calling_client_application_id"]
        or principal["application_owner_organization_id"] != values["tenant_id"]
        or not 1 <= len(redirect_uris) <= 3
        or redirect_uris != tuple(sorted(redirect_uris))
        or len(redirect_uris) != len(set(redirect_uris))
        or not 1 <= len(hostnames) <= len(redirect_uris)
        or any(hostname is None for hostname in hostnames)
    ):
        raise ValueError("validated projection mismatch")
    return values, redirect_uris, hostnames


def _future_request_plan(redirect_uris: tuple[str, ...]) -> bytes:
    target = quote(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET, safe="")
    plan: list[dict[str, object]] = []
    sequence = 0
    for redirect_uri in redirect_uris:
        sequence += 1
        baseline: dict[str, object] = {
            "sequence": sequence,
            "kind": "baseline",
            "method": "GET",
            "url": redirect_uri,
            "port": 443,
            "headers": [["Accept", "text/html"], ["Accept-Encoding", "identity"]],
            "body": None,
            "authorization": None,
            "cookie": None,
            "proxy": False,
            "follow_redirects": False,
            "retries": 0,
            "compression": False,
        }
        plan.append(baseline)
        sequence += 1
        plan.append(
            {
                **baseline,
                "sequence": sequence,
                "kind": "hostile_origin",
                "headers": [
                    ["Accept", "text/html"],
                    ["Accept-Encoding", "identity"],
                    ["Origin", FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN],
                ],
            }
        )
        for vector_name in FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES:
            sequence += 1
            plan.append(
                {
                    **baseline,
                    "sequence": sequence,
                    "kind": "bounded_open_redirect_vector",
                    "vector_name": vector_name,
                    "url": f"{redirect_uri}?{vector_name}={target}",
                }
            )
    return _canonical_bytes(plan)


def _security_header_profile() -> bytes:
    return _canonical_bytes(
        {
            "forbidden_response_headers": [
                "location",
                "set-cookie",
                "content-encoding",
                "access-control-allow-origin",
                "access-control-allow-credentials",
            ],
            "strict_transport_security": {
                "required": True,
                "minimum_max_age_seconds": 31_536_000,
            },
            "referrer-policy": "no-referrer",
            "cache-control_required_directive": "no-store",
            "x-content-type-options": "nosniff",
        }
    )


def _content_security_policy_profile() -> bytes:
    return _canonical_bytes(
        {
            "required_directives": {
                "base-uri": ["'none'"],
                "object-src": ["'none'"],
                "frame-ancestors": ["'none'"],
                "form-action": ["'none'"],
                "default-src": ["'self'"],
                "script-src": ["'self'"],
            },
            "forbidden_source_expressions": [
                "*",
                "http:",
                "https:",
                "data:",
                "blob:",
                "filesystem:",
                "'unsafe-inline'",
                "'unsafe-eval'",
                "'unsafe-hashes'",
            ],
            "forbidden_reporting_directives": ["report-uri", "report-to"],
        }
    )


def _html_profile() -> bytes:
    return _canonical_bytes(
        {
            "forbidden_elements": ["base", "form", "iframe", "object", "embed"],
            "forbidden_behaviors": [
                "meta_refresh",
                "inline_script",
                "inline_event_handler",
            ],
            "analysis_scope": "static HTML URL-bearing attributes only",
            "allowed_static_url_bearing_attributes": (
                "same-origin root-relative paths only"
            ),
            "all_other_static_url_forms_forbidden": True,
            "forbidden_static_url_forms": [
                "cross-origin",
                "protocol-relative",
                "javascript:",
                "data:",
                "blob:",
                "filesystem:",
            ],
        }
    )


def _open_redirect_vector_plan() -> bytes:
    return _canonical_bytes(
        {
            "ordered_names": list(FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES),
            "target": FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET,
            "claim_boundary": "bounded_server_side_vector_set_only",
        }
    )


def _load_internal(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientRedirectEndpointReadinessReceipt:
    if not isinstance(document, bytes):
        raise _ArgumentTypeError("document must be bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise _ArgumentTypeError("authentication preview is required")
    if not isinstance(api_registration_document, bytes):
        raise _ArgumentTypeError("API registration document must be bytes")
    if not isinstance(calling_client_registration_document, bytes):
        raise _ArgumentTypeError("calling-client registration document must be bytes")
    if not isinstance(inventory_document, bytes):
        raise _ArgumentTypeError("inventory document must be bytes")
    if not _is_lower_sha256(accepted_api_registration_document_sha256):
        raise _ArgumentTypeError("accepted API digest is required")
    if not _is_lower_sha256(accepted_calling_client_registration_document_sha256):
        raise _ArgumentTypeError("accepted calling-client digest is required")
    if not _is_lower_sha256(approved_inventory_document_sha256):
        raise _ArgumentTypeError("approved inventory digest is required")

    inventory_receipt = load_entra_application_service_principal_inventory_readiness(
        document=inventory_document,
        authentication_preview=authentication_preview,
        api_registration_document=api_registration_document,
        accepted_api_registration_document_sha256=(
            accepted_api_registration_document_sha256
        ),
        calling_client_registration_document=calling_client_registration_document,
        accepted_calling_client_registration_document_sha256=(
            accepted_calling_client_registration_document_sha256
        ),
    )
    if not hmac.compare_digest(
        inventory_receipt.inventory_document_sha256,
        approved_inventory_document_sha256,
    ):
        raise ValueError("inventory digest mismatch")

    if (
        not document
        or len(document) > MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_BYTES
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
        raise ValueError("document root")  # noqa: TRY004 - untrusted document shape
    _require_bounded_structure(parsed)
    _require_exact_document_scalars(parsed)
    canonical_document = _canonical_bytes(parsed)
    validated = EntraCallingClientRedirectEndpointDocument.model_validate_json(
        canonical_document
    )
    if (
        not hmac.compare_digest(
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
    ):
        raise ValueError("approved evidence mismatch")

    identities, redirect_uris, hostnames = _validated_projection(
        calling_client_registration_document=calling_client_registration_document,
        inventory_document=inventory_document,
    )
    request_plan = _future_request_plan(redirect_uris)
    header_profile = _security_header_profile()
    csp_profile = _content_security_policy_profile()
    html_profile = _html_profile()
    vector_profile = _open_redirect_vector_plan()
    true_values = {field: True for field in _STRUCTURAL_TRUE_FIELDS}
    false_values = {field: False for field in _DEFERRED_FALSE_FIELDS}
    return EntraCallingClientRedirectEndpointReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE,
        control_profile=validated.control_profile,
        future_request_method=FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD,
        future_minimum_tls_version=FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION,
        future_expected_media_type=FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE,
        future_expected_charset=FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET,
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
        redirect_endpoint_control_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=_framed_sha256("tenant_id", identities["tenant_id"]),
        calling_client_application_id_sha256=_framed_sha256(
            "calling_client_application_id",
            identities["calling_client_application_id"],
        ),
        calling_client_application_object_id_sha256=_framed_sha256(
            "calling_client_application_object_id",
            identities["calling_client_application_object_id"],
        ),
        calling_client_service_principal_object_id_sha256=_framed_sha256(
            "calling_client_service_principal_object_id",
            identities["calling_client_service_principal_object_id"],
        ),
        calling_client_service_principal_app_id_mapping_sha256=_framed_sha256(
            "calling_client_service_principal_app_id_mapping",
            identities["tenant_id"],
            identities["calling_client_application_id"],
            identities["calling_client_service_principal_object_id"],
        ),
        spa_redirect_uris_sha256=_framed_sha256(
            "spa_redirect_uris", str(len(redirect_uris)), *redirect_uris
        ),
        redirect_hostnames_sha256=_framed_sha256(
            "redirect_hostnames", str(len(hostnames)), *hostnames
        ),
        future_endpoint_request_plan_sha256=_framed_sha256(
            "future_endpoint_request_plan", request_plan
        ),
        future_security_header_profile_sha256=_framed_sha256(
            "future_security_header_profile", header_profile
        ),
        future_content_security_policy_profile_sha256=_framed_sha256(
            "future_content_security_policy_profile", csp_profile
        ),
        future_html_profile_sha256=_framed_sha256("future_html_profile", html_profile),
        future_open_redirect_vector_plan_sha256=_framed_sha256(
            "future_open_redirect_vector_plan", vector_profile
        ),
        desired_redirect_endpoint_count=len(redirect_uris),
        desired_distinct_hostname_count=len(hostnames),
        future_dns_resolution_call_count=len(hostnames),
        future_https_request_count_per_endpoint=(
            FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        ),
        future_total_https_request_count=(
            len(redirect_uris) * FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT
        ),
        future_open_redirect_vector_count=len(
            FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES
        ),
        future_expected_status_code=FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE,
        future_max_header_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES,
        future_max_body_bytes=FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES,
        future_hsts_minimum_max_age_seconds=(
            FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS
        ),
        **true_values,
        **false_values,
    )


def _scrub_exception_graph(error: BaseException) -> None:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001,S110  # pragma: no cover
            pass


def load_entra_calling_client_redirect_endpoint_readiness(
    *,
    document: bytes,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
) -> EntraCallingClientRedirectEndpointReadinessReceipt:
    """Validate the fixed offline profile without performing any I/O."""

    result = None
    invalid_call = False
    interrupted = False
    terminated = False
    failed = False
    try:
        result = _load_internal(
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
        )
    except KeyboardInterrupt as error:
        _scrub_exception_graph(error)
        interrupted = True
    except SystemExit as error:
        _scrub_exception_graph(error)
        terminated = True
    except _ArgumentTypeError as error:
        _scrub_exception_graph(error)
        invalid_call = True
    except BaseException as error:  # noqa: BLE001 - sanitizing public boundary
        _scrub_exception_graph(error)
        failed = True
    finally:
        document = None
        authentication_preview = None
        api_registration_document = None
        accepted_api_registration_document_sha256 = None
        calling_client_registration_document = None
        accepted_calling_client_registration_document_sha256 = None
        inventory_document = None
        approved_inventory_document_sha256 = None
    if interrupted:
        raise KeyboardInterrupt("Entra redirect endpoint readiness interrupted")
    if terminated:
        raise SystemExit("Entra redirect endpoint readiness terminated")
    if invalid_call:
        raise TypeError("Entra redirect endpoint readiness inputs are invalid")
    if failed or result is None:
        raise EntraCallingClientRedirectEndpointReadinessError(
            "Entra redirect endpoint readiness validation failed"
        )
    return result


def render_entra_calling_client_redirect_endpoint_readiness_receipt(
    receipt: EntraCallingClientRedirectEndpointReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized structural readiness evidence."""

    if type(receipt) is not EntraCallingClientRedirectEndpointReadinessReceipt:
        raise TypeError("Entra redirect endpoint readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTROL_PROFILE",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SCOPE",
    "ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_SOURCE",
    "FUTURE_REDIRECT_ENDPOINT_EXPECTED_CHARSET",
    "FUTURE_REDIRECT_ENDPOINT_EXPECTED_MEDIA_TYPE",
    "FUTURE_REDIRECT_ENDPOINT_EXPECTED_STATUS_CODE",
    "FUTURE_REDIRECT_ENDPOINT_HOSTILE_ORIGIN",
    "FUTURE_REDIRECT_ENDPOINT_HSTS_MINIMUM_MAX_AGE_SECONDS",
    "FUTURE_REDIRECT_ENDPOINT_HTTPS_REQUESTS_PER_ENDPOINT",
    "FUTURE_REDIRECT_ENDPOINT_MAX_BODY_BYTES",
    "FUTURE_REDIRECT_ENDPOINT_MAX_HEADER_BYTES",
    "FUTURE_REDIRECT_ENDPOINT_MINIMUM_TLS_VERSION",
    "FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_TARGET",
    "FUTURE_REDIRECT_ENDPOINT_OPEN_REDIRECT_VECTOR_NAMES",
    "FUTURE_REDIRECT_ENDPOINT_REQUEST_METHOD",
    "MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_CONTAINERS",
    "MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_DOCUMENT_BYTES",
    "MAX_ENTRA_CALLING_CLIENT_REDIRECT_ENDPOINT_NESTING_DEPTH",
    "EntraCallingClientRedirectEndpointReadinessError",
    "EntraCallingClientRedirectEndpointReadinessReceipt",
    "load_entra_calling_client_redirect_endpoint_readiness",
    "render_entra_calling_client_redirect_endpoint_readiness_receipt",
]
