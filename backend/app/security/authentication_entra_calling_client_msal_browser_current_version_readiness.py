"""Offline MSAL Browser current-version and compiled-proof readiness.

This module performs no registry, browser, OAuth, DNS, TLS, HTTP, filesystem,
package-manager, or provider I/O. It reruns the approved Step 218 source chain
and binds a fail-closed plan for proving the current 5.18.0 browser package,
its exact msal-common dependency, and the compiled retry behavior later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness import (
    EntraCallingClientMSALRetryReconciliationReadinessReceipt,
    load_entra_calling_client_msal_retry_reconciliation_readiness,
    render_entra_calling_client_msal_retry_reconciliation_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel

ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_current_version_readiness"
)
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_current_version_readiness_receipt"
)
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SOURCE = (
    "engineer4me_reviewed_msal_browser_5_18_0_transition"
)
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE = (
    "offline_current_version_two_artifact_and_compiled_retry_proof_plan"
)
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_PROFILE = (
    "engineer4me_msal_browser_5_18_0_compiled_retry_proof_readiness_v1"
)
ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS = (
    "current_candidate_declared_but_artifact_behavior_and_selection_unapproved"
)

MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION = "5.17.3"
MSAL_BROWSER_CURRENT_CANDIDATE_VERSION = "5.18.0"
MSAL_COMMON_CURRENT_DEPENDENCY_VERSION = "16.12.0"
MSAL_BROWSER_CURRENT_RELEASE_TAG = "msal-browser-v5.18.0"
MSAL_BROWSER_CURRENT_RELEASE_DATE = "2026-08-04"
MSAL_BROWSER_CURRENT_RELEASE_COMMIT = "5c53ac6"
MSAL_BROWSER_PACKAGE_NAME = "@azure/msal-browser"
MSAL_COMMON_PACKAGE_NAME = "@azure/msal-common"
CURRENT_VERSION_TOKEN_POST_RETRY_COUNT = 1
CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT = 2
CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS = 100
CURRENT_VERSION_ARTIFACT_COUNT = 2
CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT = 10
MAX_MSAL_CURRENT_VERSION_DOCUMENT_BYTES = 4_096
MAX_JSON_DEPTH = 32
MAX_JSON_CONTAINERS = 8_192
_SHA256_HEX_LENGTH = 64


class EntraCallingClientMSALCurrentVersionReadinessError(ValueError):
    """Sanitized current-version readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientMSALCurrentVersionReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_current_version_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_msal_browser_5_18_0_transition"]
    approved_retry_reconciliation_document_sha256: str
    transition_profile: Literal[
        "engineer4me_msal_browser_5_18_0_compiled_retry_proof_readiness_v1"
    ]

    @model_validator(mode="after")
    def validate_digest(
        self,
    ) -> EntraCallingClientMSALCurrentVersionReadinessDocument:
        if not _is_lower_sha256(self.approved_retry_reconciliation_document_sha256):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCurrentVersionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    transition_profile: str
    readiness_status: str
    browser_package_name: str
    common_package_name: str
    previous_reviewed_browser_version: str
    current_candidate_browser_version: str
    current_common_dependency_version: str
    current_release_tag: str
    current_release_date: str
    current_release_commit: str
    behavior_transport_failure_trigger: str
    behavior_retry_execution: str
    behavior_retry_backoff: str
    isolation_network_policy: str
    isolation_filesystem_policy: str
    isolation_process_policy: str
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
    current_version_readiness_document_sha256: str
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
    current_release_metadata_profile_sha256: str
    two_artifact_proof_plan_sha256: str
    isolated_runtime_profile_sha256: str
    compiled_behavior_scenario_plan_sha256: str
    current_candidate_selection_state_sha256: str
    artifact_count: int
    behavior_scenario_count: int
    previous_candidate_retry_count: int
    current_candidate_required_retry_count: int
    current_candidate_maximum_attempt_count: int
    current_candidate_required_backoff_milliseconds: int
    http_response_retry_count: int
    oauth_error_retry_count: int
    abort_or_cancellation_retry_count: int
    desired_redirect_endpoint_count: int
    step218_source_chain_revalidated: bool
    approved_retry_reconciliation_digest_bound: bool
    exact_step218_unapproved_exception_state_validated: bool
    step216_zero_retry_requirement_preserved: bool
    step219_rendered_receipt_not_accepted_as_provenance: bool
    current_release_metadata_profile_declared: bool
    exact_current_browser_version_declared: bool
    exact_current_common_dependency_declared: bool
    browser_and_common_artifacts_both_required: bool
    exact_registry_metadata_and_tarballs_required: bool
    sha512_sri_integrity_required_for_both_artifacts: bool
    safe_in_memory_archive_validation_required: bool
    exact_package_json_identity_required: bool
    exact_dependency_edge_required: bool
    compiled_entrypoint_discovery_required: bool
    compiled_retry_implementation_path_discovery_required: bool
    isolated_supported_node_runtime_required: bool
    exact_node_binary_identity_required: bool
    no_network_during_compiled_execution_required: bool
    ephemeral_filesystem_only_required: bool
    package_lifecycle_scripts_forbidden: bool
    child_process_creation_forbidden_inside_harness: bool
    controlled_fake_transport_required: bool
    real_token_endpoint_forbidden: bool
    real_authorization_code_forbidden: bool
    token_post_transport_failure_only_required: bool
    exactly_one_sequential_retry_required: bool
    exactly_two_total_attempts_maximum_required: bool
    fixed_100_millisecond_backoff_required: bool
    identical_endpoint_method_headers_and_body_required: bool
    http_response_retry_forbidden: bool
    oauth_error_retry_forbidden: bool
    abort_or_cancellation_retry_forbidden: bool
    non_token_request_retry_forbidden: bool
    parallel_retry_forbidden: bool
    recursive_retry_forbidden: bool
    retry_telemetry_count_required: bool
    lost_response_code_consumption_risk_preserved: bool
    current_candidate_transition_plan_validated: bool
    registry_metadata_checked: bool
    current_dist_tag_checked: bool
    current_browser_tarball_downloaded: bool
    current_common_tarball_downloaded: bool
    current_browser_tarball_integrity_checked: bool
    current_common_tarball_integrity_checked: bool
    package_signatures_or_provenance_checked: bool
    package_publish_authorization_checked: bool
    package_maintainer_identity_checked: bool
    source_repository_commit_cryptographically_bound: bool
    source_to_distribution_reproducibility_checked: bool
    package_security_advisories_checked: bool
    package_license_terms_legally_reviewed: bool
    compiled_retry_path_inspected: bool
    exact_retry_trigger_checked: bool
    exact_retry_count_checked: bool
    exact_retry_backoff_checked: bool
    retry_sequentiality_checked: bool
    retry_request_equivalence_checked: bool
    retry_http_response_exclusion_checked: bool
    retry_oauth_error_exclusion_checked: bool
    retry_abort_and_cancellation_checked: bool
    retry_non_token_request_exclusion_checked: bool
    retry_parallelism_absence_checked: bool
    retry_recursion_absence_checked: bool
    retry_telemetry_checked: bool
    response_loss_behavior_checked: bool
    authorization_code_consumption_behavior_checked: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    current_candidate_compatible_with_successor_policy: bool
    current_candidate_selected: bool
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
    provider_io_performed: bool
    browser_io_performed: bool
    network_io_performed: bool
    filesystem_io_performed: bool
    package_manager_process_performed: bool
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
        deferred = tuple(getattr(self, name) for name in _DEFERRED_FALSE_FIELDS)
        if (
            any(type(value) is not str for value in strings)
            or self.receipt_type
            != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SOURCE
            or self.validation_scope != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE
            or self.transition_profile
            != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_PROFILE
            or self.readiness_status != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS
            or self.browser_package_name != MSAL_BROWSER_PACKAGE_NAME
            or self.common_package_name != MSAL_COMMON_PACKAGE_NAME
            or self.previous_reviewed_browser_version
            != MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION
            or self.current_candidate_browser_version
            != MSAL_BROWSER_CURRENT_CANDIDATE_VERSION
            or self.current_common_dependency_version
            != MSAL_COMMON_CURRENT_DEPENDENCY_VERSION
            or self.current_release_tag != MSAL_BROWSER_CURRENT_RELEASE_TAG
            or self.current_release_date != MSAL_BROWSER_CURRENT_RELEASE_DATE
            or self.current_release_commit != MSAL_BROWSER_CURRENT_RELEASE_COMMIT
            or self.behavior_transport_failure_trigger
            != "token_post_transport_rejection_only"
            or self.behavior_retry_execution != "one_sequential_retry_maximum"
            or self.behavior_retry_backoff != "fixed_100_milliseconds"
            or self.isolation_network_policy != "disabled_after_artifact_acquisition"
            or self.isolation_filesystem_policy != "ephemeral_bounded_workspace_only"
            or self.isolation_process_policy != "one_sealed_node_harness_only"
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
            or not hmac.compare_digest(
                self.approved_msal_browser_control_document_sha256,
                self.msal_browser_control_document_sha256,
            )
            or not hmac.compare_digest(
                self.approved_retry_reconciliation_document_sha256,
                self.retry_reconciliation_document_sha256,
            )
            or any(type(value) is not int for value in counts)
            or self.artifact_count != CURRENT_VERSION_ARTIFACT_COUNT
            or self.behavior_scenario_count != CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT
            or self.previous_candidate_retry_count != 1
            or self.current_candidate_required_retry_count
            != CURRENT_VERSION_TOKEN_POST_RETRY_COUNT
            or self.current_candidate_maximum_attempt_count
            != CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT
            or self.current_candidate_required_backoff_milliseconds
            != CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS
            or self.http_response_retry_count != 0
            or self.oauth_error_retry_count != 0
            or self.abort_or_cancellation_retry_count != 0
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or any(value is not True for value in structural)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("MSAL current-version readiness receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "transition_profile",
    "readiness_status",
    "browser_package_name",
    "common_package_name",
    "previous_reviewed_browser_version",
    "current_candidate_browser_version",
    "current_common_dependency_version",
    "current_release_tag",
    "current_release_date",
    "current_release_commit",
    "behavior_transport_failure_trigger",
    "behavior_retry_execution",
    "behavior_retry_backoff",
    "isolation_network_policy",
    "isolation_filesystem_policy",
    "isolation_process_policy",
)

_COUNT_FIELDS = (
    "artifact_count",
    "behavior_scenario_count",
    "previous_candidate_retry_count",
    "current_candidate_required_retry_count",
    "current_candidate_maximum_attempt_count",
    "current_candidate_required_backoff_milliseconds",
    "http_response_retry_count",
    "oauth_error_retry_count",
    "abort_or_cancellation_retry_count",
    "desired_redirect_endpoint_count",
)

_STRUCTURAL_TRUE_FIELDS = (
    "step218_source_chain_revalidated",
    "approved_retry_reconciliation_digest_bound",
    "exact_step218_unapproved_exception_state_validated",
    "step216_zero_retry_requirement_preserved",
    "step219_rendered_receipt_not_accepted_as_provenance",
    "current_release_metadata_profile_declared",
    "exact_current_browser_version_declared",
    "exact_current_common_dependency_declared",
    "browser_and_common_artifacts_both_required",
    "exact_registry_metadata_and_tarballs_required",
    "sha512_sri_integrity_required_for_both_artifacts",
    "safe_in_memory_archive_validation_required",
    "exact_package_json_identity_required",
    "exact_dependency_edge_required",
    "compiled_entrypoint_discovery_required",
    "compiled_retry_implementation_path_discovery_required",
    "isolated_supported_node_runtime_required",
    "exact_node_binary_identity_required",
    "no_network_during_compiled_execution_required",
    "ephemeral_filesystem_only_required",
    "package_lifecycle_scripts_forbidden",
    "child_process_creation_forbidden_inside_harness",
    "controlled_fake_transport_required",
    "real_token_endpoint_forbidden",
    "real_authorization_code_forbidden",
    "token_post_transport_failure_only_required",
    "exactly_one_sequential_retry_required",
    "exactly_two_total_attempts_maximum_required",
    "fixed_100_millisecond_backoff_required",
    "identical_endpoint_method_headers_and_body_required",
    "http_response_retry_forbidden",
    "oauth_error_retry_forbidden",
    "abort_or_cancellation_retry_forbidden",
    "non_token_request_retry_forbidden",
    "parallel_retry_forbidden",
    "recursive_retry_forbidden",
    "retry_telemetry_count_required",
    "lost_response_code_consumption_risk_preserved",
    "current_candidate_transition_plan_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "registry_metadata_checked",
    "current_dist_tag_checked",
    "current_browser_tarball_downloaded",
    "current_common_tarball_downloaded",
    "current_browser_tarball_integrity_checked",
    "current_common_tarball_integrity_checked",
    "package_signatures_or_provenance_checked",
    "package_publish_authorization_checked",
    "package_maintainer_identity_checked",
    "source_repository_commit_cryptographically_bound",
    "source_to_distribution_reproducibility_checked",
    "package_security_advisories_checked",
    "package_license_terms_legally_reviewed",
    "compiled_retry_path_inspected",
    "exact_retry_trigger_checked",
    "exact_retry_count_checked",
    "exact_retry_backoff_checked",
    "retry_sequentiality_checked",
    "retry_request_equivalence_checked",
    "retry_http_response_exclusion_checked",
    "retry_oauth_error_exclusion_checked",
    "retry_abort_and_cancellation_checked",
    "retry_non_token_request_exclusion_checked",
    "retry_parallelism_absence_checked",
    "retry_recursion_absence_checked",
    "retry_telemetry_checked",
    "response_loss_behavior_checked",
    "authorization_code_consumption_behavior_checked",
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "current_candidate_compatible_with_successor_policy",
    "current_candidate_selected",
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
    "provider_io_performed",
    "browser_io_performed",
    "network_io_performed",
    "filesystem_io_performed",
    "package_manager_process_performed",
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
    for value in ("engineer4me-step220-v1", label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _parse_finite_float(value: str) -> float:
    result = float(value)
    if not isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _parse_document(
    raw: bytes,
) -> tuple[bytes, EntraCallingClientMSALCurrentVersionReadinessDocument]:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_MSAL_CURRENT_VERSION_DOCUMENT_BYTES
    ):
        raise _ArgumentTypeError("exact document bytes are required")
    decoded = raw.decode("utf-8")
    parsed = json.loads(
        decoded,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )
    expected = {
        "document_type",
        "schema_version",
        "source",
        "approved_retry_reconciliation_document_sha256",
        "transition_profile",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != expected
        or type(parsed["schema_version"]) is not int
        or any(type(parsed[name]) is not str for name in expected - {"schema_version"})
    ):
        raise ValueError("current-version document contract is invalid")
    pending = [(parsed, 1)]
    containers = 0
    while pending:
        current, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("document depth exceeded")
        if type(current) is dict:
            containers += 1
            pending.extend((value, depth + 1) for value in current.values())
        elif type(current) is list:
            containers += 1
            pending.extend((value, depth + 1) for value in current)
        if containers > MAX_JSON_CONTAINERS:
            raise ValueError("document container limit exceeded")
    canonical = _canonical_bytes(parsed)
    validated = (
        EntraCallingClientMSALCurrentVersionReadinessDocument.model_validate_json(
            canonical
        )
    )
    return canonical, validated


def _validate_step218_state(
    receipt: EntraCallingClientMSALRetryReconciliationReadinessReceipt,
) -> None:
    if type(receipt) is not EntraCallingClientMSALRetryReconciliationReadinessReceipt:
        raise ValueError("exact Step 218 receipt is required")
    render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(receipt)
    if (
        receipt.reviewed_package_version != MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION
        or receipt.reviewed_candidate_token_post_retry_count != 1
        or receipt.conditional_fixed_backoff_milliseconds != 100
        or receipt.conditional_exception_approved
        or receipt.step216_zero_retry_superseded
        or receipt.reviewed_candidate_compatible_with_successor_policy
        or receipt.package_selection_ready
        or receipt.package_installed
        or receipt.activation_ready
    ):
        raise ValueError("Step 218 state is not the exact unapproved baseline")


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


def _load_internal(
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
) -> EntraCallingClientMSALCurrentVersionReadinessReceipt:
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
        raise _ArgumentTypeError("documents must be exact bytes")
    if type(authentication_preview) is not AuthenticationReadinessPreview:
        raise _ArgumentTypeError("authentication preview is required")
    if any(not _is_lower_sha256(value) for value in digest_inputs):
        raise _ArgumentTypeError("approved digests are required")

    prior = load_entra_calling_client_msal_retry_reconciliation_readiness(
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
    if not hmac.compare_digest(
        prior.retry_reconciliation_document_sha256,
        approved_retry_reconciliation_document_sha256,
    ):
        raise ValueError("retry reconciliation digest mismatch")
    _validate_step218_state(prior)
    canonical_document, validated = _parse_document(document)
    if not hmac.compare_digest(
        validated.approved_retry_reconciliation_document_sha256,
        approved_retry_reconciliation_document_sha256,
    ):
        raise ValueError("current-version approved evidence mismatch")

    release_profile = {
        "browserPackage": MSAL_BROWSER_PACKAGE_NAME,
        "browserVersion": MSAL_BROWSER_CURRENT_CANDIDATE_VERSION,
        "commonPackage": MSAL_COMMON_PACKAGE_NAME,
        "commonVersion": MSAL_COMMON_CURRENT_DEPENDENCY_VERSION,
        "releaseTag": MSAL_BROWSER_CURRENT_RELEASE_TAG,
        "releaseDate": MSAL_BROWSER_CURRENT_RELEASE_DATE,
        "releaseCommitShort": MSAL_BROWSER_CURRENT_RELEASE_COMMIT,
        "declaredChanges": [
            "attribute_tokens_support",
            "internal_web_broker_bridge_scaffold_no_callers",
            "msal_common_16_12_0_dependency",
        ],
    }
    artifact_plan = {
        "packages": [
            [MSAL_BROWSER_PACKAGE_NAME, MSAL_BROWSER_CURRENT_CANDIDATE_VERSION],
            [MSAL_COMMON_PACKAGE_NAME, MSAL_COMMON_CURRENT_DEPENDENCY_VERSION],
        ],
        "registry": "https://registry.npmjs.org",
        "proof": [
            "exact_version_metadata",
            "sha512_sri",
            "tarball_sha256_sha512",
            "safe_archive",
            "package_json_identity",
            "exact_dependency_edge",
            "compiled_entrypoint_closure",
        ],
    }
    isolation_profile = {
        "node": "exact_supported_binary_identity_required",
        "networkAfterAcquisition": "disabled",
        "filesystem": "ephemeral_bounded_workspace_only",
        "lifecycleScripts": "forbidden",
        "harnessChildProcesses": "forbidden",
        "transport": "controlled_fake_token_transport",
        "realOAuthInputs": "forbidden",
    }
    behavior_scenarios = [
        "transport_failure_then_success_one_retry_after_100ms",
        "two_transport_failures_two_attempts_then_failure",
        "http_400_response_no_retry",
        "http_429_response_no_retry",
        "http_500_response_no_retry",
        "oauth_error_response_no_retry",
        "abort_or_cancellation_no_retry",
        "non_token_request_no_retry",
        "concurrent_calls_no_cross_talk_or_parallel_retry",
        "retry_telemetry_and_request_equivalence_exact",
    ]
    selection_state = {
        "candidate": MSAL_BROWSER_CURRENT_CANDIDATE_VERSION,
        "artifactProofComplete": False,
        "compiledBehaviorProofComplete": False,
        "conditionalExceptionApproved": False,
        "step216ZeroRetrySuperseded": False,
        "selected": False,
    }
    true_values = {name: True for name in _STRUCTURAL_TRUE_FIELDS}
    false_values = {name: False for name in _DEFERRED_FALSE_FIELDS}
    return EntraCallingClientMSALCurrentVersionReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE,
        transition_profile=validated.transition_profile,
        readiness_status=ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS,
        browser_package_name=MSAL_BROWSER_PACKAGE_NAME,
        common_package_name=MSAL_COMMON_PACKAGE_NAME,
        previous_reviewed_browser_version=MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION,
        current_candidate_browser_version=MSAL_BROWSER_CURRENT_CANDIDATE_VERSION,
        current_common_dependency_version=MSAL_COMMON_CURRENT_DEPENDENCY_VERSION,
        current_release_tag=MSAL_BROWSER_CURRENT_RELEASE_TAG,
        current_release_date=MSAL_BROWSER_CURRENT_RELEASE_DATE,
        current_release_commit=MSAL_BROWSER_CURRENT_RELEASE_COMMIT,
        behavior_transport_failure_trigger="token_post_transport_rejection_only",
        behavior_retry_execution="one_sequential_retry_maximum",
        behavior_retry_backoff="fixed_100_milliseconds",
        isolation_network_policy="disabled_after_artifact_acquisition",
        isolation_filesystem_policy="ephemeral_bounded_workspace_only",
        isolation_process_policy="one_sealed_node_harness_only",
        configuration_sha256=prior.configuration_sha256,
        api_registration_document_sha256=prior.api_registration_document_sha256,
        calling_client_registration_document_sha256=(
            prior.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=prior.approved_inventory_document_sha256,
        inventory_document_sha256=prior.inventory_document_sha256,
        approved_redirect_endpoint_control_document_sha256=(
            prior.approved_redirect_endpoint_control_document_sha256
        ),
        redirect_endpoint_control_document_sha256=(
            prior.redirect_endpoint_control_document_sha256
        ),
        approved_pkce_runtime_control_document_sha256=(
            prior.approved_pkce_runtime_control_document_sha256
        ),
        pkce_runtime_control_document_sha256=prior.pkce_runtime_control_document_sha256,
        approved_msal_browser_control_document_sha256=(
            prior.approved_msal_browser_control_document_sha256
        ),
        msal_browser_control_document_sha256=prior.msal_browser_control_document_sha256,
        approved_retry_reconciliation_document_sha256=(
            approved_retry_reconciliation_document_sha256
        ),
        retry_reconciliation_document_sha256=(
            prior.retry_reconciliation_document_sha256
        ),
        retry_reconciliation_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
                prior
            ).encode("utf-8")
        ).hexdigest(),
        current_version_readiness_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=prior.tenant_id_sha256,
        calling_client_application_id_sha256=(
            prior.calling_client_application_id_sha256
        ),
        calling_client_application_object_id_sha256=(
            prior.calling_client_application_object_id_sha256
        ),
        api_application_id_sha256=prior.api_application_id_sha256,
        api_delegated_scope_id_sha256=prior.api_delegated_scope_id_sha256,
        spa_redirect_uris_sha256=prior.spa_redirect_uris_sha256,
        authority_origin_sha256=prior.authority_origin_sha256,
        authority_sha256=prior.authority_sha256,
        known_authorities_sha256=prior.known_authorities_sha256,
        conditional_retry_exception_profile_sha256=(
            prior.conditional_retry_exception_profile_sha256
        ),
        distribution_artifact_verification_plan_sha256=(
            prior.distribution_artifact_verification_plan_sha256
        ),
        response_loss_risk_profile_sha256=prior.response_loss_risk_profile_sha256,
        package_selection_state_sha256=prior.package_selection_state_sha256,
        current_release_metadata_profile_sha256=_framed_sha256(
            "current_release_metadata", _canonical_bytes(release_profile)
        ),
        two_artifact_proof_plan_sha256=_framed_sha256(
            "two_artifact_proof_plan", _canonical_bytes(artifact_plan)
        ),
        isolated_runtime_profile_sha256=_framed_sha256(
            "isolated_runtime_profile", _canonical_bytes(isolation_profile)
        ),
        compiled_behavior_scenario_plan_sha256=_framed_sha256(
            "compiled_behavior_scenarios", _canonical_bytes(behavior_scenarios)
        ),
        current_candidate_selection_state_sha256=_framed_sha256(
            "current_candidate_selection", _canonical_bytes(selection_state)
        ),
        artifact_count=CURRENT_VERSION_ARTIFACT_COUNT,
        behavior_scenario_count=CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT,
        previous_candidate_retry_count=1,
        current_candidate_required_retry_count=(CURRENT_VERSION_TOKEN_POST_RETRY_COUNT),
        current_candidate_maximum_attempt_count=(
            CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT
        ),
        current_candidate_required_backoff_milliseconds=(
            CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS
        ),
        http_response_retry_count=0,
        oauth_error_retry_count=0,
        abort_or_cancellation_retry_count=0,
        desired_redirect_endpoint_count=prior.desired_redirect_endpoint_count,
        **true_values,
        **false_values,
    )


def load_entra_calling_client_msal_current_version_readiness(
    **arguments: object,
) -> EntraCallingClientMSALCurrentVersionReadinessReceipt:
    """Return one privacy-minimized offline current-version readiness receipt."""

    result = None
    error = None
    invalid_call = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(**arguments)
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
    if interrupted:
        result = None
        raise KeyboardInterrupt("MSAL current-version readiness interrupted")
    if terminated:
        result = None
        raise SystemExit("MSAL current-version readiness terminated")
    if invalid_call:
        result = None
        raise TypeError("MSAL current-version readiness inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALCurrentVersionReadinessError(
            "MSAL current-version readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_current_version_readiness_receipt(
    receipt: EntraCallingClientMSALCurrentVersionReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized readiness evidence."""

    if type(receipt) is not EntraCallingClientMSALCurrentVersionReadinessReceipt:
        raise TypeError("MSAL current-version readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "CURRENT_VERSION_ARTIFACT_COUNT",
    "CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT",
    "CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS",
    "CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT",
    "CURRENT_VERSION_TOKEN_POST_RETRY_COUNT",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_PROFILE",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SOURCE",
    "ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS",
    "MAX_MSAL_CURRENT_VERSION_DOCUMENT_BYTES",
    "MSAL_BROWSER_CURRENT_CANDIDATE_VERSION",
    "MSAL_BROWSER_CURRENT_RELEASE_COMMIT",
    "MSAL_BROWSER_CURRENT_RELEASE_DATE",
    "MSAL_BROWSER_CURRENT_RELEASE_TAG",
    "MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION",
    "MSAL_COMMON_CURRENT_DEPENDENCY_VERSION",
    "EntraCallingClientMSALCurrentVersionReadinessError",
    "EntraCallingClientMSALCurrentVersionReadinessReceipt",
    "load_entra_calling_client_msal_current_version_readiness",
    "render_entra_calling_client_msal_current_version_readiness_receipt",
]
