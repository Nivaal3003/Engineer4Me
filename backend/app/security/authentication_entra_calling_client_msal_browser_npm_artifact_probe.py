"""Exact npm metadata and tarball-integrity proof for the MSAL candidate.

The probe reruns the complete Step 218 source chain, consumes one exact ordered
three-response npm plan, verifies registry metadata and the tarball entirely in
memory, and emits privacy-minimized evidence. It never executes or installs the
package and does not approve the retry exception.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import tarfile
from dataclasses import dataclass
from math import isfinite
from pathlib import PurePosixPath
from typing import Any, Literal

from app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness import (
    EntraCallingClientMSALRetryReconciliationReadinessReceipt,
    load_entra_calling_client_msal_retry_reconciliation_readiness,
    render_entra_calling_client_msal_retry_reconciliation_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel
from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_npm_http_loader import (
    MSAL_BROWSER_NPM_PACKAGE_NAME,
    MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION,
    MSAL_BROWSER_NPM_REVIEWED_VERSION,
    NPM_MAX_DIST_TAGS_BYTES,
    NPM_MAX_TARBALL_BYTES,
    NPM_MAX_VERSION_METADATA_BYTES,
    NPM_REGISTRY_ORIGIN,
    NPM_TARBALL_URL,
    BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    EntraCallingClientMSALBrowserNpmHTTPTransport,
    build_entra_calling_client_msal_browser_npm_request_plan,
)

ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_npm_artifact_proof"
)
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_npm_artifact_proof_receipt"
)
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SOURCE = (
    "engineer4me_reviewed_exact_msal_browser_npm_distribution_artifact"
)
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE = (
    "exact_registry_metadata_tarball_integrity_archive_and_exports_subset"
)
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_PROFILE = (
    "engineer4me_msal_browser_5_17_3_npm_artifact_integrity_v1"
)
ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS = (
    "artifact_integrity_proved_but_candidate_stale_and_behavior_unapproved"
)

NPM_INTEGRITY_ALGORITHM = "sha512"
NPM_ARCHIVE_FORMAT = "gzip_compressed_posix_tar"
NPM_LICENSE_IDENTIFIER = "MIT"
MAX_NPM_ARTIFACT_DOCUMENT_BYTES = 4_096
MAX_NPM_JSON_DEPTH = 32
MAX_NPM_JSON_CONTAINERS = 8_192
MAX_NPM_TAR_MEMBERS = 4_096
MAX_NPM_TAR_MEMBER_BYTES = 8_388_608
MAX_NPM_TAR_UNCOMPRESSED_BYTES = 67_108_864
MAX_NPM_PACKAGE_JSON_BYTES = 524_288
MAX_NPM_EXPORT_TARGETS = 128
_SHA256_HEX_LENGTH = 64
_SHA512_HEX_LENGTH = 128
_SHA1_HEX_LENGTH = 40
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SAFE_MEMBER = re.compile(r"package/(?:[A-Za-z0-9._@+-]+/)*[A-Za-z0-9._@+-]+\Z")


class EntraCallingClientMSALBrowserNpmArtifactProbeError(ValueError):
    """Sanitized failure at the exact npm artifact proof boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientMSALBrowserNpmArtifactDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_npm_artifact_proof"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_exact_msal_browser_npm_distribution_artifact"]
    approved_retry_reconciliation_document_sha256: str
    artifact_profile: Literal[
        "engineer4me_msal_browser_5_17_3_npm_artifact_integrity_v1"
    ]

    @model_validator(mode="after")
    def validate_digest(self) -> EntraCallingClientMSALBrowserNpmArtifactDocument:
        if not _is_lower_sha256(self.approved_retry_reconciliation_document_sha256):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    artifact_profile: str
    artifact_status: str
    package_name: str
    reviewed_candidate_version: str
    reviewed_latest_dist_tag_version: str
    registry_origin: str
    integrity_algorithm: str
    archive_format: str
    license_identifier: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    approved_redirect_endpoint_control_document_sha256: str
    redirect_endpoint_control_document_sha256: str
    approved_pkce_runtime_control_document_sha256: str
    pkce_runtime_control_document_sha256: str
    approved_msal_browser_control_document_sha256: str
    msal_browser_control_document_sha256: str
    approved_retry_reconciliation_document_sha256: str
    retry_reconciliation_document_sha256: str
    retry_reconciliation_receipt_sha256: str
    npm_artifact_document_sha256: str
    tenant_id_sha256: str
    calling_client_application_id_sha256: str
    calling_client_application_object_id_sha256: str
    api_application_id_sha256: str
    api_delegated_scope_id_sha256: str
    spa_redirect_uris_sha256: str
    authority_origin_sha256: str
    authority_sha256: str
    known_authorities_sha256: str
    conditional_retry_exception_profile_sha256: str
    distribution_artifact_verification_plan_sha256: str
    response_loss_risk_profile_sha256: str
    package_selection_state_sha256: str
    npm_request_plan_sha256: str
    dist_tags_response_sha256: str
    version_metadata_response_sha256: str
    tarball_sha256: str
    package_metadata_projection_sha256: str
    package_json_sha256: str
    package_exports_sha256: str
    runtime_dependencies_sha256: str
    tar_member_manifest_sha256: str
    license_file_sha256: str
    package_version_relationship_sha256: str
    tarball_sha512: str
    request_plan_count: int
    json_response_count: int
    tarball_response_count: int
    evidence_response_count: int
    sealed_registry_request_count: int
    dist_tags_response_bytes: int
    version_metadata_response_bytes: int
    tarball_response_bytes: int
    total_response_bytes: int
    tar_member_count: int
    regular_file_count: int
    directory_count: int
    total_uncompressed_bytes: int
    export_target_count: int
    runtime_dependency_count: int
    lifecycle_install_script_count: int
    step218_source_chain_revalidated: bool
    approved_retry_reconciliation_digest_bound: bool
    exact_step218_unapproved_exception_state_validated: bool
    step216_zero_retry_requirement_preserved: bool
    exact_three_request_plan_prevalidated: bool
    npm_global_registry_origin_fixed: bool
    unauthenticated_get_only_required: bool
    request_body_forbidden: bool
    proxy_use_forbidden: bool
    redirect_following_forbidden: bool
    retry_forbidden: bool
    response_compression_forbidden: bool
    response_byte_bounds_enforced: bool
    strict_json_duplicate_key_rejection_enforced: bool
    reviewed_latest_dist_tag_exactly_bound: bool
    reviewed_candidate_not_latest_validated: bool
    exact_candidate_metadata_identity_validated: bool
    version_metadata_deprecated_field_absent_validated: bool
    exact_candidate_tarball_url_validated: bool
    sha512_sri_integrity_validated: bool
    legacy_sha1_metadata_consistency_validated: bool
    gzip_tar_archive_parsed_in_memory: bool
    tar_member_paths_canonical_and_safe: bool
    tar_links_and_special_files_rejected: bool
    tar_member_and_size_bounds_enforced: bool
    package_json_identity_validated: bool
    package_license_declaration_validated: bool
    consumer_install_lifecycle_scripts_absent: bool
    package_exports_structurally_validated: bool
    all_export_targets_present_in_archive: bool
    redirect_bridge_export_present: bool
    runtime_dependencies_structurally_validated: bool
    exact_artifact_hashes_emitted: bool
    package_bytes_never_extracted_to_filesystem: bool
    no_package_code_executed: bool
    no_package_install_performed: bool
    partial_response_failure_emits_no_receipt: bool
    candidate_selection_remains_fail_closed: bool
    artifact_subset_structurally_validated: bool
    synthetic_transport_used: bool
    sealed_provider_io_performed: bool
    sealed_network_io_performed: bool
    live_registry_source_attested: bool
    live_tls_certificate_chain_checked: bool
    live_tls_hostname_checked: bool
    live_proxy_bypass_checked: bool
    live_redirect_rejection_checked: bool
    live_retry_disable_checked: bool
    live_dist_tags_checked: bool
    live_version_metadata_checked: bool
    live_tarball_checked: bool
    live_exact_response_relationship_checked: bool
    candidate_is_latest: bool
    registry_state_atomic_snapshot_checked: bool
    registry_state_freshness_guaranteed: bool
    dns_resolution_checked: bool
    dnssec_checked: bool
    connected_ip_public_checked: bool
    certificate_revocation_checked: bool
    certificate_transparency_checked: bool
    npm_registry_ownership_checked: bool
    npm_package_maintainer_identity_checked: bool
    package_publish_authorization_checked: bool
    registry_signature_checked: bool
    registry_provenance_attestation_checked: bool
    source_repository_commit_bound: bool
    source_to_distribution_reproducibility_checked: bool
    package_deprecation_state_freshness_guaranteed: bool
    package_security_advisories_checked: bool
    package_license_terms_legally_reviewed: bool
    full_package_manifest_semantics_checked: bool
    compiled_retry_path_inspected: bool
    exact_retry_trigger_checked: bool
    exact_retry_count_checked: bool
    exact_retry_backoff_checked: bool
    retry_sequentiality_checked: bool
    retry_request_equivalence_checked: bool
    retry_http_response_exclusion_checked: bool
    retry_oauth_error_exclusion_checked: bool
    retry_abort_and_cancellation_checked: bool
    retry_parallelism_absence_checked: bool
    retry_recursion_absence_checked: bool
    retry_telemetry_checked: bool
    response_loss_behavior_checked: bool
    authorization_code_consumption_behavior_checked: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    reviewed_candidate_compatible_with_successor_policy: bool
    package_selection_ready: bool
    dependency_lockfile_created: bool
    dependency_lockfile_integrity_checked: bool
    package_installed: bool
    package_code_executed: bool
    frontend_source_present: bool
    msal_configuration_implemented: bool
    redirect_bridge_deployed: bool
    revised_csp_deployed: bool
    successor_endpoint_reproved: bool
    browser_runtime_checked: bool
    runtime_pkce_s256_checked: bool
    authorization_code_redeemed: bool
    token_validated: bool
    real_engineer4me_api_call_checked: bool
    real_customer_user_journey_checked: bool
    provider_policy_checked: bool
    conditional_access_checked: bool
    mfa_checked: bool
    terms_of_use_checked: bool
    injected_transport_side_effects_checked: bool
    application_configuration_mutation_performed: bool
    identity_provider_configuration_mutation_performed: bool
    registry_configuration_mutation_performed: bool
    receipt_self_authenticating: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        strings = tuple(getattr(self, name) for name in _PUBLIC_STRING_FIELDS)
        counts = tuple(getattr(self, name) for name in _COUNT_FIELDS)
        structural = tuple(getattr(self, name) for name in _STRUCTURAL_TRUE_FIELDS)
        live = tuple(getattr(self, name) for name in _LIVE_FIELDS)
        deferred = tuple(getattr(self, name) for name in _DEFERRED_FALSE_FIELDS)
        expected_live_count = 0 if self.synthetic_transport_used else 3
        if (
            any(type(value) is not str for value in strings)
            or self.receipt_type != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SOURCE
            or self.validation_scope != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE
            or self.artifact_profile != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_PROFILE
            or self.artifact_status != ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS
            or self.package_name != MSAL_BROWSER_NPM_PACKAGE_NAME
            or self.reviewed_candidate_version != MSAL_BROWSER_NPM_REVIEWED_VERSION
            or self.reviewed_latest_dist_tag_version
            != MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION
            or self.registry_origin != NPM_REGISTRY_ORIGIN
            or self.integrity_algorithm != NPM_INTEGRITY_ALGORITHM
            or self.archive_format != NPM_ARCHIVE_FORMAT
            or self.license_identifier != NPM_LICENSE_IDENTIFIER
            or any(not _is_lower_sha256(value) for value in digests)
            or type(self.tarball_sha512) is not str
            or re.fullmatch(rf"[0-9a-f]{{{_SHA512_HEX_LENGTH}}}", self.tarball_sha512)
            is None
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
            or not hmac.compare_digest(
                self.approved_msal_browser_control_document_sha256,
                self.msal_browser_control_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_retry_reconciliation_document_sha256,
                self.retry_reconciliation_document_sha256,
            )
            or any(type(value) is not int for value in counts)
            or self.request_plan_count != 3
            or self.json_response_count != 2
            or self.tarball_response_count != 1
            or self.evidence_response_count != 3
            or self.sealed_registry_request_count != expected_live_count
            or not 1 <= self.dist_tags_response_bytes <= NPM_MAX_DIST_TAGS_BYTES
            or not 1
            <= self.version_metadata_response_bytes
            <= NPM_MAX_VERSION_METADATA_BYTES
            or not 1 <= self.tarball_response_bytes <= NPM_MAX_TARBALL_BYTES
            or self.total_response_bytes
            != self.dist_tags_response_bytes
            + self.version_metadata_response_bytes
            + self.tarball_response_bytes
            or not 2 <= self.tar_member_count <= MAX_NPM_TAR_MEMBERS
            or not 2 <= self.regular_file_count <= self.tar_member_count
            or not 0 <= self.directory_count <= self.tar_member_count
            or self.regular_file_count + self.directory_count != self.tar_member_count
            or not self.regular_file_count
            <= self.total_uncompressed_bytes
            <= MAX_NPM_TAR_UNCOMPRESSED_BYTES
            or not 1 <= self.export_target_count <= MAX_NPM_EXPORT_TARGETS
            or not 0 <= self.runtime_dependency_count <= 256
            or self.lifecycle_install_script_count != 0
            or any(value is not True for value in structural)
            or type(self.synthetic_transport_used) is not bool
            or any(type(value) is not bool for value in live)
            or any(value is not (not self.synthetic_transport_used) for value in live)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("MSAL Browser npm artifact receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "artifact_profile",
    "artifact_status",
    "package_name",
    "reviewed_candidate_version",
    "reviewed_latest_dist_tag_version",
    "registry_origin",
    "integrity_algorithm",
    "archive_format",
    "license_identifier",
)

_COUNT_FIELDS = (
    "request_plan_count",
    "json_response_count",
    "tarball_response_count",
    "evidence_response_count",
    "sealed_registry_request_count",
    "dist_tags_response_bytes",
    "version_metadata_response_bytes",
    "tarball_response_bytes",
    "total_response_bytes",
    "tar_member_count",
    "regular_file_count",
    "directory_count",
    "total_uncompressed_bytes",
    "export_target_count",
    "runtime_dependency_count",
    "lifecycle_install_script_count",
)

_STRUCTURAL_TRUE_FIELDS = (
    "step218_source_chain_revalidated",
    "approved_retry_reconciliation_digest_bound",
    "exact_step218_unapproved_exception_state_validated",
    "step216_zero_retry_requirement_preserved",
    "exact_three_request_plan_prevalidated",
    "npm_global_registry_origin_fixed",
    "unauthenticated_get_only_required",
    "request_body_forbidden",
    "proxy_use_forbidden",
    "redirect_following_forbidden",
    "retry_forbidden",
    "response_compression_forbidden",
    "response_byte_bounds_enforced",
    "strict_json_duplicate_key_rejection_enforced",
    "reviewed_latest_dist_tag_exactly_bound",
    "reviewed_candidate_not_latest_validated",
    "exact_candidate_metadata_identity_validated",
    "version_metadata_deprecated_field_absent_validated",
    "exact_candidate_tarball_url_validated",
    "sha512_sri_integrity_validated",
    "legacy_sha1_metadata_consistency_validated",
    "gzip_tar_archive_parsed_in_memory",
    "tar_member_paths_canonical_and_safe",
    "tar_links_and_special_files_rejected",
    "tar_member_and_size_bounds_enforced",
    "package_json_identity_validated",
    "package_license_declaration_validated",
    "consumer_install_lifecycle_scripts_absent",
    "package_exports_structurally_validated",
    "all_export_targets_present_in_archive",
    "redirect_bridge_export_present",
    "runtime_dependencies_structurally_validated",
    "exact_artifact_hashes_emitted",
    "package_bytes_never_extracted_to_filesystem",
    "no_package_code_executed",
    "no_package_install_performed",
    "partial_response_failure_emits_no_receipt",
    "candidate_selection_remains_fail_closed",
    "artifact_subset_structurally_validated",
)

_LIVE_FIELDS = (
    "sealed_provider_io_performed",
    "sealed_network_io_performed",
    "live_registry_source_attested",
    "live_tls_certificate_chain_checked",
    "live_tls_hostname_checked",
    "live_proxy_bypass_checked",
    "live_redirect_rejection_checked",
    "live_retry_disable_checked",
    "live_dist_tags_checked",
    "live_version_metadata_checked",
    "live_tarball_checked",
    "live_exact_response_relationship_checked",
)

_DEFERRED_FALSE_FIELDS = (
    "candidate_is_latest",
    "registry_state_atomic_snapshot_checked",
    "registry_state_freshness_guaranteed",
    "dns_resolution_checked",
    "dnssec_checked",
    "connected_ip_public_checked",
    "certificate_revocation_checked",
    "certificate_transparency_checked",
    "npm_registry_ownership_checked",
    "npm_package_maintainer_identity_checked",
    "package_publish_authorization_checked",
    "registry_signature_checked",
    "registry_provenance_attestation_checked",
    "source_repository_commit_bound",
    "source_to_distribution_reproducibility_checked",
    "package_deprecation_state_freshness_guaranteed",
    "package_security_advisories_checked",
    "package_license_terms_legally_reviewed",
    "full_package_manifest_semantics_checked",
    "compiled_retry_path_inspected",
    "exact_retry_trigger_checked",
    "exact_retry_count_checked",
    "exact_retry_backoff_checked",
    "retry_sequentiality_checked",
    "retry_request_equivalence_checked",
    "retry_http_response_exclusion_checked",
    "retry_oauth_error_exclusion_checked",
    "retry_abort_and_cancellation_checked",
    "retry_parallelism_absence_checked",
    "retry_recursion_absence_checked",
    "retry_telemetry_checked",
    "response_loss_behavior_checked",
    "authorization_code_consumption_behavior_checked",
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "reviewed_candidate_compatible_with_successor_policy",
    "package_selection_ready",
    "dependency_lockfile_created",
    "dependency_lockfile_integrity_checked",
    "package_installed",
    "package_code_executed",
    "frontend_source_present",
    "msal_configuration_implemented",
    "redirect_bridge_deployed",
    "revised_csp_deployed",
    "successor_endpoint_reproved",
    "browser_runtime_checked",
    "runtime_pkce_s256_checked",
    "authorization_code_redeemed",
    "token_validated",
    "real_engineer4me_api_call_checked",
    "real_customer_user_journey_checked",
    "provider_policy_checked",
    "conditional_access_checked",
    "mfa_checked",
    "terms_of_use_checked",
    "injected_transport_side_effects_checked",
    "application_configuration_mutation_performed",
    "identity_provider_configuration_mutation_performed",
    "registry_configuration_mutation_performed",
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


def _framed_sha256(label: str, *values: bytes | str) -> str:
    digest = hashlib.sha256()
    for value in ("engineer4me-step219-v1", label, str(len(values)), *values):
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


def _parse_json(raw: bytes, *, maximum_bytes: int) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum_bytes:
        raise ValueError("JSON byte boundary")
    parsed = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )
    stack: list[tuple[object, int]] = [(parsed, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_NPM_JSON_DEPTH:
                raise ValueError("JSON depth boundary")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_NPM_JSON_DEPTH:
                raise ValueError("JSON depth boundary")
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_NPM_JSON_CONTAINERS:
            raise ValueError("JSON container boundary")
    return parsed


def _validate_step218_state(
    receipt: EntraCallingClientMSALRetryReconciliationReadinessReceipt,
) -> None:
    receipt.__post_init__()
    if (
        receipt.package_name != MSAL_BROWSER_NPM_PACKAGE_NAME
        or receipt.reviewed_package_version != MSAL_BROWSER_NPM_REVIEWED_VERSION
        or receipt.step216_zero_retry_requirement_preserved is not True
        or receipt.exact_distribution_artifact_proof_required is not True
        or receipt.conditional_exception_approved is not False
        or receipt.step216_zero_retry_superseded is not False
        or receipt.reviewed_candidate_compatible_with_successor_policy is not False
        or receipt.package_selection_ready is not False
        or receipt.activation_ready is not False
    ):
        raise ValueError("Step 218 state mismatch")


def _validate_dist_tags(raw: bytes) -> dict[str, str]:
    parsed = _parse_json(raw, maximum_bytes=NPM_MAX_DIST_TAGS_BYTES)
    if type(parsed) is not dict or not 1 <= len(parsed) <= 64:
        raise ValueError("dist-tags root is invalid")
    normalized: dict[str, str] = {}
    for key, value in parsed.items():
        if (
            type(key) is not str
            or _TAG_NAME.fullmatch(key) is None
            or type(value) is not str
            or len(value) > 64
            or _SEMVER.fullmatch(value) is None
        ):
            raise ValueError("dist-tags entry is invalid")
        normalized[key] = value
    if normalized.get("latest") != MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION:
        raise ValueError("reviewed latest dist-tag changed")
    if normalized["latest"] == MSAL_BROWSER_NPM_REVIEWED_VERSION:
        raise ValueError("reviewed candidate unexpectedly became latest")
    return normalized


def _decode_sha512_integrity(value: object) -> bytes:
    if type(value) is not str or not value.startswith("sha512-") or len(value) > 128:
        raise ValueError("registry integrity is invalid")
    encoded = value[7:]
    decoded = base64.b64decode(encoded, validate=True)
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError("registry integrity is invalid")
    return decoded


def _validate_version_metadata(raw: bytes) -> tuple[dict[str, object], bytes, str]:
    parsed = _parse_json(raw, maximum_bytes=NPM_MAX_VERSION_METADATA_BYTES)
    if type(parsed) is not dict:
        raise ValueError("version metadata root is invalid")
    if (
        parsed.get("name") != MSAL_BROWSER_NPM_PACKAGE_NAME
        or parsed.get("version") != MSAL_BROWSER_NPM_REVIEWED_VERSION
        or parsed.get("license") != NPM_LICENSE_IDENTIFIER
        or "deprecated" in parsed
    ):
        raise ValueError("version metadata identity is invalid")
    dist = parsed.get("dist")
    if type(dist) is not dict:
        raise ValueError("version metadata dist is invalid")
    integrity = dist.get("integrity")
    integrity_bytes = _decode_sha512_integrity(integrity)
    shasum = dist.get("shasum")
    tarball = dist.get("tarball")
    if (
        type(shasum) is not str
        or re.fullmatch(rf"[0-9a-f]{{{_SHA1_HEX_LENGTH}}}", shasum) is None
        or tarball != NPM_TARBALL_URL
    ):
        raise ValueError("version metadata distribution is invalid")
    projection = {
        "name": parsed["name"],
        "version": parsed["version"],
        "license": parsed["license"],
        "dist": {
            "integrityAlgorithm": NPM_INTEGRITY_ALGORITHM,
            "integritySha512": integrity_bytes.hex(),
            "shasum": shasum,
            "tarball": tarball,
        },
        "deprecatedAbsent": True,
    }
    return projection, integrity_bytes, shasum


def _safe_export_target(value: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("./")
        or len(value) > 512
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
        or "//" in value
    ):
        raise ValueError("package export target is invalid")
    relative = value[2:]
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("package export target is invalid")
    canonical = f"package/{path.as_posix()}"
    if _SAFE_MEMBER.fullmatch(canonical) is None:
        raise ValueError("package export target is invalid")
    return canonical


def _collect_export_targets(value: object) -> set[str]:
    targets: set[str] = set()
    stack = [value]
    containers = 0
    while stack:
        current = stack.pop()
        if type(current) is str:
            targets.add(_safe_export_target(current))
        elif type(current) is dict:
            containers += 1
            if containers > 256 or not current:
                raise ValueError("package exports are invalid")
            for key, item in current.items():
                if type(key) is not str or not key or len(key) > 128:
                    raise ValueError("package exports are invalid")
                stack.append(item)
        elif type(current) is list:
            containers += 1
            if containers > 256 or not current or len(current) > 32:
                raise ValueError("package exports are invalid")
            stack.extend(current)
        else:
            raise ValueError("package exports are invalid")
        if len(targets) > MAX_NPM_EXPORT_TARGETS:
            raise ValueError("package export target limit")
    if not targets:
        raise ValueError("package exports contain no targets")
    return targets


def _parse_tarball(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > NPM_MAX_TARBALL_BYTES:
        raise ValueError("tarball byte boundary")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    manifest: list[dict[str, object]] = []
    total_uncompressed = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if not 2 <= len(members) <= MAX_NPM_TAR_MEMBERS:
            raise ValueError("tar member count boundary")
        seen: set[str] = set()
        seen_casefold: set[str] = set()
        for member in members:
            name = member.name
            path = PurePosixPath(name)
            if (
                type(name) is not str
                or not name
                or len(name) > 1024
                or _SAFE_MEMBER.fullmatch(name) is None
                or path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.as_posix() != name
                or name in seen
                or name.casefold() in seen_casefold
                or member.issym()
                or member.islnk()
                or member.isdev()
                or member.isfifo()
                or not (member.isreg() or member.isdir())
                or member.mode & ~0o777
            ):
                raise ValueError("unsafe tar member")
            seen.add(name)
            seen_casefold.add(name.casefold())
            if member.isdir():
                if member.size != 0:
                    raise ValueError("tar directory size is invalid")
                directories.add(name)
                manifest.append({"path": name, "size": 0, "sha256": None})
                continue
            if not 0 <= member.size <= MAX_NPM_TAR_MEMBER_BYTES:
                raise ValueError("tar member size boundary")
            total_uncompressed += member.size
            if total_uncompressed > MAX_NPM_TAR_UNCOMPRESSED_BYTES:
                raise ValueError("tar uncompressed size boundary")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("tar member body is unavailable")
            body = extracted.read(MAX_NPM_TAR_MEMBER_BYTES + 1)
            if type(body) is not bytes or len(body) != member.size:
                raise ValueError("tar member body boundary")
            files[name] = body
            manifest.append(
                {
                    "path": name,
                    "size": member.size,
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            )

    package_json_raw = files.get("package/package.json")
    if (
        package_json_raw is None
        or not package_json_raw
        or len(package_json_raw) > MAX_NPM_PACKAGE_JSON_BYTES
    ):
        raise ValueError("package.json is missing or too large")
    package_json = _parse_json(
        package_json_raw,
        maximum_bytes=MAX_NPM_PACKAGE_JSON_BYTES,
    )
    if type(package_json) is not dict:
        raise ValueError("package.json root is invalid")
    if (
        package_json.get("name") != MSAL_BROWSER_NPM_PACKAGE_NAME
        or package_json.get("version") != MSAL_BROWSER_NPM_REVIEWED_VERSION
        or package_json.get("license") != NPM_LICENSE_IDENTIFIER
    ):
        raise ValueError("package.json identity is invalid")
    scripts = package_json.get("scripts", {})
    if type(scripts) is not dict or any(
        type(key) is not str or type(value) is not str for key, value in scripts.items()
    ):
        raise ValueError("package scripts are invalid")
    install_scripts = {
        key: scripts[key]
        for key in ("preinstall", "install", "postinstall")
        if key in scripts
    }
    if install_scripts:
        raise ValueError("consumer install lifecycle script is present")

    exports = package_json.get("exports")
    if (
        type(exports) is not dict
        or "." not in exports
        or "./redirect-bridge" not in exports
    ):
        raise ValueError("required package exports are absent")
    export_targets = _collect_export_targets(exports)
    if any(target not in files for target in export_targets):
        raise ValueError("package export target is absent from tarball")
    redirect_targets = _collect_export_targets(exports["./redirect-bridge"])
    if not redirect_targets or any(target not in files for target in redirect_targets):
        raise ValueError("redirect bridge export is invalid")

    dependencies = package_json.get("dependencies", {})
    if type(dependencies) is not dict or len(dependencies) > 256:
        raise ValueError("runtime dependencies are invalid")
    if any(
        type(key) is not str
        or not key
        or len(key) > 256
        or type(value) is not str
        or not value
        or len(value) > 256
        for key, value in dependencies.items()
    ):
        raise ValueError("runtime dependencies are invalid")

    license_paths = [
        name
        for name in files
        if name.casefold() in {"package/license", "package/license.txt"}
    ]
    if len(license_paths) != 1 or not files[license_paths[0]]:
        raise ValueError("exact license file is required")
    return {
        "package_json_raw": package_json_raw,
        "exports": exports,
        "dependencies": dependencies,
        "manifest": manifest,
        "license_raw": files[license_paths[0]],
        "member_count": len(manifest),
        "regular_file_count": len(files),
        "directory_count": len(directories),
        "total_uncompressed_bytes": total_uncompressed,
        "export_target_count": len(export_targets),
        "runtime_dependency_count": len(dependencies),
    }


def _validate_document(
    raw: bytes,
) -> tuple[bytes, EntraCallingClientMSALBrowserNpmArtifactDocument]:
    parsed = _parse_json(raw, maximum_bytes=MAX_NPM_ARTIFACT_DOCUMENT_BYTES)
    expected = {
        "document_type",
        "schema_version",
        "source",
        "approved_retry_reconciliation_document_sha256",
        "artifact_profile",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != expected
        or any(
            type(parsed[field]) is not str for field in expected - {"schema_version"}
        )
        or type(parsed["schema_version"]) is not int
    ):
        raise ValueError("artifact document contract is invalid")
    canonical = _canonical_bytes(parsed)
    validated = EntraCallingClientMSALBrowserNpmArtifactDocument.model_validate_json(
        canonical
    )
    return canonical, validated


def _probe_internal(
    *,
    document: bytes,
    retry_reconciliation_document: bytes,
    approved_retry_reconciliation_document_sha256: str,
    msal_browser_control_document: bytes,
    approved_msal_browser_control_document_sha256: str,
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
    transport: EntraCallingClientMSALBrowserNpmHTTPTransport,
    require_live: bool,
) -> EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
    byte_inputs = (
        document,
        retry_reconciliation_document,
        msal_browser_control_document,
        pkce_runtime_control_document,
        redirect_endpoint_control_document,
        api_registration_document,
        calling_client_registration_document,
        inventory_document,
    )
    digest_inputs = (
        approved_retry_reconciliation_document_sha256,
        approved_msal_browser_control_document_sha256,
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
    if not callable(transport) or type(require_live) is not bool:
        raise _ArgumentTypeError("exact transport mode is required")

    reconciliation_receipt = (
        load_entra_calling_client_msal_retry_reconciliation_readiness(
            document=retry_reconciliation_document,
            msal_browser_control_document=msal_browser_control_document,
            approved_msal_browser_control_document_sha256=(
                approved_msal_browser_control_document_sha256
            ),
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
    )
    if not hmac.compare_digest(
        reconciliation_receipt.retry_reconciliation_document_sha256,
        approved_retry_reconciliation_document_sha256,
    ):
        raise ValueError("retry reconciliation digest mismatch")
    _validate_step218_state(reconciliation_receipt)
    canonical_document, validated_document = _validate_document(document)
    if not hmac.compare_digest(
        validated_document.approved_retry_reconciliation_document_sha256,
        approved_retry_reconciliation_document_sha256,
    ):
        raise ValueError("artifact approved evidence mismatch")

    plan = build_entra_calling_client_msal_browser_npm_request_plan()
    responses = transport(plan)
    if type(responses) is not tuple or len(responses) != 3:
        raise ValueError("exact response tuple is required")
    for request, response in zip(plan, responses, strict=True):
        if type(response) is not EntraCallingClientMSALBrowserNpmHTTPResponse:
            raise ValueError("exact response objects are required")
        response.__post_init__()
        if response.request != request:
            raise ValueError("response plan mismatch")
    live_values = tuple(response.live_https_attested for response in responses)
    if not (all(live_values) or not any(live_values)):
        raise ValueError("mixed response provenance")
    live = all(live_values)
    if require_live is not live:
        raise ValueError("response provenance mismatch")

    dist_tags_response, metadata_response, tarball_response = responses
    dist_tags = _validate_dist_tags(dist_tags_response.body)
    metadata_projection, expected_sha512, expected_sha1 = _validate_version_metadata(
        metadata_response.body
    )
    actual_sha512 = hashlib.sha512(tarball_response.body).digest()
    if not hmac.compare_digest(actual_sha512, expected_sha512):
        raise ValueError("tarball SHA-512 integrity mismatch")
    if not hmac.compare_digest(
        hashlib.sha1(tarball_response.body, usedforsecurity=False).hexdigest(),
        expected_sha1,
    ):
        raise ValueError("tarball legacy shasum mismatch")
    tar_projection = _parse_tarball(tarball_response.body)
    request_plan_projection = [
        {
            "sequence": request.sequence,
            "resource": request.resource,
            "method": request.method,
            "url": request.url,
            "accept": request.accept,
            "acceptEncoding": request.accept_encoding,
            "body": None,
        }
        for request in plan
    ]
    version_relationship = {
        "candidate": MSAL_BROWSER_NPM_REVIEWED_VERSION,
        "reviewedLatest": dist_tags["latest"],
        "candidateIsLatest": False,
        "candidateApproved": False,
    }
    true_values = {name: True for name in _STRUCTURAL_TRUE_FIELDS}
    live_values_map = {name: live for name in _LIVE_FIELDS}
    false_values = {name: False for name in _DEFERRED_FALSE_FIELDS}
    total_response_bytes = sum(len(response.body) for response in responses)
    return EntraCallingClientMSALBrowserNpmArtifactProofReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCHEMA_VERSION,
        source=validated_document.source,
        validation_scope=ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE,
        artifact_profile=validated_document.artifact_profile,
        artifact_status=ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS,
        package_name=MSAL_BROWSER_NPM_PACKAGE_NAME,
        reviewed_candidate_version=MSAL_BROWSER_NPM_REVIEWED_VERSION,
        reviewed_latest_dist_tag_version=MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION,
        registry_origin=NPM_REGISTRY_ORIGIN,
        integrity_algorithm=NPM_INTEGRITY_ALGORITHM,
        archive_format=NPM_ARCHIVE_FORMAT,
        license_identifier=NPM_LICENSE_IDENTIFIER,
        configuration_sha256=reconciliation_receipt.configuration_sha256,
        api_registration_document_sha256=(
            reconciliation_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            reconciliation_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=(
            reconciliation_receipt.approved_inventory_document_sha256
        ),
        inventory_document_sha256=reconciliation_receipt.inventory_document_sha256,
        approved_redirect_endpoint_control_document_sha256=(
            reconciliation_receipt.approved_redirect_endpoint_control_document_sha256
        ),
        redirect_endpoint_control_document_sha256=(
            reconciliation_receipt.redirect_endpoint_control_document_sha256
        ),
        approved_pkce_runtime_control_document_sha256=(
            reconciliation_receipt.approved_pkce_runtime_control_document_sha256
        ),
        pkce_runtime_control_document_sha256=(
            reconciliation_receipt.pkce_runtime_control_document_sha256
        ),
        approved_msal_browser_control_document_sha256=(
            reconciliation_receipt.approved_msal_browser_control_document_sha256
        ),
        msal_browser_control_document_sha256=(
            reconciliation_receipt.msal_browser_control_document_sha256
        ),
        approved_retry_reconciliation_document_sha256=(
            approved_retry_reconciliation_document_sha256
        ),
        retry_reconciliation_document_sha256=(
            reconciliation_receipt.retry_reconciliation_document_sha256
        ),
        retry_reconciliation_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
                reconciliation_receipt
            ).encode("utf-8")
        ).hexdigest(),
        npm_artifact_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        tenant_id_sha256=reconciliation_receipt.tenant_id_sha256,
        calling_client_application_id_sha256=(
            reconciliation_receipt.calling_client_application_id_sha256
        ),
        calling_client_application_object_id_sha256=(
            reconciliation_receipt.calling_client_application_object_id_sha256
        ),
        api_application_id_sha256=reconciliation_receipt.api_application_id_sha256,
        api_delegated_scope_id_sha256=(
            reconciliation_receipt.api_delegated_scope_id_sha256
        ),
        spa_redirect_uris_sha256=reconciliation_receipt.spa_redirect_uris_sha256,
        authority_origin_sha256=reconciliation_receipt.authority_origin_sha256,
        authority_sha256=reconciliation_receipt.authority_sha256,
        known_authorities_sha256=reconciliation_receipt.known_authorities_sha256,
        conditional_retry_exception_profile_sha256=(
            reconciliation_receipt.conditional_retry_exception_profile_sha256
        ),
        distribution_artifact_verification_plan_sha256=(
            reconciliation_receipt.distribution_artifact_verification_plan_sha256
        ),
        response_loss_risk_profile_sha256=(
            reconciliation_receipt.response_loss_risk_profile_sha256
        ),
        package_selection_state_sha256=(
            reconciliation_receipt.package_selection_state_sha256
        ),
        npm_request_plan_sha256=_framed_sha256(
            "npm_request_plan", _canonical_bytes(request_plan_projection)
        ),
        dist_tags_response_sha256=hashlib.sha256(dist_tags_response.body).hexdigest(),
        version_metadata_response_sha256=hashlib.sha256(
            metadata_response.body
        ).hexdigest(),
        tarball_sha256=hashlib.sha256(tarball_response.body).hexdigest(),
        package_metadata_projection_sha256=_framed_sha256(
            "package_metadata_projection", _canonical_bytes(metadata_projection)
        ),
        package_json_sha256=hashlib.sha256(
            tar_projection["package_json_raw"]
        ).hexdigest(),
        package_exports_sha256=_framed_sha256(
            "package_exports", _canonical_bytes(tar_projection["exports"])
        ),
        runtime_dependencies_sha256=_framed_sha256(
            "runtime_dependencies", _canonical_bytes(tar_projection["dependencies"])
        ),
        tar_member_manifest_sha256=_framed_sha256(
            "tar_member_manifest", _canonical_bytes(tar_projection["manifest"])
        ),
        license_file_sha256=hashlib.sha256(tar_projection["license_raw"]).hexdigest(),
        package_version_relationship_sha256=_framed_sha256(
            "package_version_relationship", _canonical_bytes(version_relationship)
        ),
        tarball_sha512=actual_sha512.hex(),
        request_plan_count=3,
        json_response_count=2,
        tarball_response_count=1,
        evidence_response_count=3,
        sealed_registry_request_count=3 if live else 0,
        dist_tags_response_bytes=len(dist_tags_response.body),
        version_metadata_response_bytes=len(metadata_response.body),
        tarball_response_bytes=len(tarball_response.body),
        total_response_bytes=total_response_bytes,
        tar_member_count=tar_projection["member_count"],
        regular_file_count=tar_projection["regular_file_count"],
        directory_count=tar_projection["directory_count"],
        total_uncompressed_bytes=tar_projection["total_uncompressed_bytes"],
        export_target_count=tar_projection["export_target_count"],
        runtime_dependency_count=tar_projection["runtime_dependency_count"],
        lifecycle_install_script_count=0,
        **true_values,
        synthetic_transport_used=not live,
        **live_values_map,
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
        children = getattr(current, "exceptions", ())
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


def _public_probe(
    *, require_live: bool, **arguments: object
) -> EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
    result = None
    error = None
    invalid_call = False
    interrupted = False
    terminated = False
    try:
        result = _probe_internal(require_live=require_live, **arguments)
    except _ArgumentTypeError as caught:
        error = caught
        invalid_call = True
    except BaseException as caught:  # noqa: BLE001 - sanitize boundary
        error = caught
    finally:
        if error is not None:
            interrupted, terminated = _scrub_exception_graph(error)
        error = None
        arguments.clear()
        require_live = False
    if interrupted:
        result = None
        raise KeyboardInterrupt("MSAL Browser npm artifact proof interrupted")
    if terminated:
        result = None
        raise SystemExit("MSAL Browser npm artifact proof terminated")
    if invalid_call:
        result = None
        raise TypeError("MSAL Browser npm artifact proof inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALBrowserNpmArtifactProbeError(
            "MSAL Browser npm artifact proof failed"
        )
    return result


def probe_entra_calling_client_msal_browser_npm_artifact(
    *,
    transport: EntraCallingClientMSALBrowserNpmHTTPTransport,
    **arguments: object,
) -> EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
    """Evaluate caller-supplied synthetic artifact evidence only."""

    return _public_probe(
        require_live=False,
        transport=transport,
        **arguments,
    )


def probe_live_entra_calling_client_msal_browser_npm_artifact(
    **arguments: object,
) -> EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
    """Perform the sealed three-read global npm registry proof."""

    loader = BoundedEntraCallingClientMSALBrowserNpmHTTPSLoader()
    try:
        return _public_probe(
            require_live=True,
            transport=loader,
            **arguments,
        )
    finally:
        loader.close()
        loader = None
        arguments.clear()


def render_entra_calling_client_msal_browser_npm_artifact_receipt(
    receipt: EntraCallingClientMSALBrowserNpmArtifactProofReceipt,
) -> str:
    """Render canonical privacy-minimized npm artifact evidence."""

    if type(receipt) is not EntraCallingClientMSALBrowserNpmArtifactProofReceipt:
        raise TypeError("MSAL Browser npm artifact receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_PROFILE",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SOURCE",
    "ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS",
    "MAX_NPM_ARTIFACT_DOCUMENT_BYTES",
    "NPM_ARCHIVE_FORMAT",
    "NPM_INTEGRITY_ALGORITHM",
    "NPM_LICENSE_IDENTIFIER",
    "EntraCallingClientMSALBrowserNpmArtifactProbeError",
    "EntraCallingClientMSALBrowserNpmArtifactProofReceipt",
    "probe_entra_calling_client_msal_browser_npm_artifact",
    "probe_live_entra_calling_client_msal_browser_npm_artifact",
    "render_entra_calling_client_msal_browser_npm_artifact_receipt",
]
