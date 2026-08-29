"""Offline reconciliation readiness for the MSAL Browser token-POST retry.

The contract reruns the complete Step 217 source-document chain and declares a
narrow successor-policy candidate for independently proving the bounded retry
introduced by MSAL Browser 5.17.3. It performs no package, filesystem, process,
browser, OAuth, provider, DNS, TLS, HTTP, Graph, Entra, database, or other I/O.
The exception is not approved until the exact distributed artifact is proved.
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

from app.security.authentication_entra_calling_client_msal_browser_readiness import (
    MSAL_BROWSER_PACKAGE_NAME,
    MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS,
    MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT,
    MSAL_BROWSER_REVIEWED_VERSION,
    EntraCallingClientMSALBrowserReadinessReceipt,
    load_entra_calling_client_msal_browser_readiness,
    render_entra_calling_client_msal_browser_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel

ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_retry_reconciliation_readiness"
)
ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_retry_reconciliation_readiness_receipt"
ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCHEMA_VERSION = 1
ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SOURCE = (
    "engineer4me_reviewed_msal_browser_bounded_transport_retry_reconciliation"
)
ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE = (
    "offline_conditional_successor_policy_and_artifact_proof_plan_only"
)
ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE = (
    "engineer4me_entra_spa_msal_browser_transport_retry_reconciliation_v1"
)

RECONCILIATION_RETRY_TRIGGER = "token_post_transport_failure_only"
RECONCILIATION_RETRY_EXECUTION = "single_sequential_retry"
RECONCILIATION_RETRY_BACKOFF = "fixed_100_milliseconds"
RECONCILIATION_RESPONSE_AMBIGUITY = "first_response_loss_may_consume_single_use_code"
RECONCILIATION_POLICY_STATUS = "conditional_exception_not_approved"
RECONCILIATION_ARTIFACT_PROOF = "exact_distribution_artifact_required"
STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT = 0
RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT = 1
RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT = 2
RECONCILIATION_FIXED_BACKOFF_MILLISECONDS = 100
RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT = 0
RECONCILIATION_OAUTH_ERROR_RETRY_COUNT = 0
MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_BYTES = 4_096
MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_NESTING_DEPTH = 2
MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_CONTAINERS = 8
_SHA256_HEX_LENGTH = 64


class EntraCallingClientMSALRetryReconciliationReadinessError(ValueError):
    """Sanitized failure at the offline retry-reconciliation boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientMSALRetryReconciliationDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_retry_reconciliation_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_reviewed_msal_browser_bounded_transport_retry_reconciliation"
    ]
    approved_msal_browser_control_document_sha256: str
    reconciliation_profile: Literal[
        "engineer4me_entra_spa_msal_browser_transport_retry_reconciliation_v1"
    ]

    @model_validator(mode="after")
    def validate_digest(
        self,
    ) -> EntraCallingClientMSALRetryReconciliationDocument:
        if not _is_lower_sha256(self.approved_msal_browser_control_document_sha256):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALRetryReconciliationReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    reconciliation_profile: str
    package_name: str
    reviewed_package_version: str
    retry_trigger: str
    retry_execution: str
    retry_backoff: str
    response_ambiguity: str
    policy_status: str
    artifact_proof: str
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
    offline_msal_browser_readiness_receipt_sha256: str
    retry_reconciliation_document_sha256: str
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
    step216_required_token_post_retry_count: int
    reviewed_candidate_token_post_retry_count: int
    conditional_maximum_token_post_retry_count: int
    conditional_maximum_token_post_attempt_count: int
    conditional_fixed_backoff_milliseconds: int
    conditional_http_response_retry_count: int
    conditional_oauth_error_retry_count: int
    desired_redirect_endpoint_count: int
    step217_source_chain_revalidated: bool
    approved_msal_browser_digest_bound: bool
    exact_step217_conflict_state_validated: bool
    step216_zero_retry_requirement_preserved: bool
    reviewed_candidate_single_retry_recorded: bool
    reviewed_candidate_fixed_backoff_recorded: bool
    response_loss_and_code_consumption_ambiguity_acknowledged: bool
    conditional_successor_exception_profile_declared: bool
    token_post_transport_failure_only_required: bool
    exactly_one_sequential_retry_maximum_required: bool
    exactly_two_total_token_post_attempts_maximum_required: bool
    fixed_100_millisecond_backoff_required: bool
    retry_after_http_response_forbidden: bool
    retry_after_oauth_error_forbidden: bool
    parallel_retry_forbidden: bool
    recursive_retry_forbidden: bool
    retry_after_abort_or_cancellation_forbidden: bool
    same_token_endpoint_required: bool
    same_http_post_method_required: bool
    same_normalized_token_parameter_subset_required: bool
    same_authorization_code_required: bool
    same_pkce_verifier_required: bool
    same_redirect_uri_required: bool
    no_client_secret_or_assertion_required: bool
    credentials_omit_required: bool
    redirect_error_mode_required: bool
    cache_no_store_required: bool
    retry_telemetry_count_required: bool
    exact_distribution_artifact_proof_required: bool
    exact_package_version_and_integrity_proof_required: bool
    package_json_and_exports_proof_required: bool
    compiled_retry_path_inspection_required: bool
    retry_behavior_adversarial_test_required: bool
    current_supported_release_revalidation_required: bool
    downgrade_without_independent_review_rejected: bool
    all_other_step216_runtime_controls_preserved: bool
    no_step216_or_step217_source_rewrite_performed: bool
    offline_reconciliation_constraints_validated: bool
    registry_metadata_checked: bool
    package_version_current_checked: bool
    package_tarball_downloaded: bool
    package_tarball_integrity_checked: bool
    package_signature_or_provenance_checked: bool
    package_license_source_checked: bool
    package_security_advisories_checked: bool
    package_json_checked: bool
    package_exports_checked: bool
    redirect_bridge_export_checked: bool
    compiled_distribution_artifact_inspected: bool
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
    retry_configuration_surface_checked: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    reviewed_candidate_compatible_with_successor_policy: bool
    package_selection_ready: bool
    dependency_lockfile_created: bool
    dependency_lockfile_integrity_checked: bool
    package_installed: bool
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
            or self.receipt_type
            != ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version
            != ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCHEMA_VERSION
            or self.source != ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SOURCE
            or self.validation_scope
            != ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE
            or self.reconciliation_profile
            != ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE
            or self.package_name != MSAL_BROWSER_PACKAGE_NAME
            or self.reviewed_package_version != MSAL_BROWSER_REVIEWED_VERSION
            or self.retry_trigger != RECONCILIATION_RETRY_TRIGGER
            or self.retry_execution != RECONCILIATION_RETRY_EXECUTION
            or self.retry_backoff != RECONCILIATION_RETRY_BACKOFF
            or self.response_ambiguity != RECONCILIATION_RESPONSE_AMBIGUITY
            or self.policy_status != RECONCILIATION_POLICY_STATUS
            or self.artifact_proof != RECONCILIATION_ARTIFACT_PROOF
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
            or any(type(value) is not int for value in counts)
            or self.step216_required_token_post_retry_count
            != STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT
            or self.reviewed_candidate_token_post_retry_count
            != MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
            or self.conditional_maximum_token_post_retry_count
            != RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT
            or self.conditional_maximum_token_post_attempt_count
            != RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT
            or self.conditional_fixed_backoff_milliseconds
            != RECONCILIATION_FIXED_BACKOFF_MILLISECONDS
            or self.conditional_http_response_retry_count
            != RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT
            or self.conditional_oauth_error_retry_count
            != RECONCILIATION_OAUTH_ERROR_RETRY_COUNT
            or not 1 <= self.desired_redirect_endpoint_count <= 3
            or any(value is not True for value in structural)
            or any(value is not False for value in deferred)
        ):
            raise ValueError("Entra MSAL retry reconciliation receipt is invalid")


_PUBLIC_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "reconciliation_profile",
    "package_name",
    "reviewed_package_version",
    "retry_trigger",
    "retry_execution",
    "retry_backoff",
    "response_ambiguity",
    "policy_status",
    "artifact_proof",
)

_COUNT_FIELDS = (
    "step216_required_token_post_retry_count",
    "reviewed_candidate_token_post_retry_count",
    "conditional_maximum_token_post_retry_count",
    "conditional_maximum_token_post_attempt_count",
    "conditional_fixed_backoff_milliseconds",
    "conditional_http_response_retry_count",
    "conditional_oauth_error_retry_count",
    "desired_redirect_endpoint_count",
)

_STRUCTURAL_TRUE_FIELDS = (
    "step217_source_chain_revalidated",
    "approved_msal_browser_digest_bound",
    "exact_step217_conflict_state_validated",
    "step216_zero_retry_requirement_preserved",
    "reviewed_candidate_single_retry_recorded",
    "reviewed_candidate_fixed_backoff_recorded",
    "response_loss_and_code_consumption_ambiguity_acknowledged",
    "conditional_successor_exception_profile_declared",
    "token_post_transport_failure_only_required",
    "exactly_one_sequential_retry_maximum_required",
    "exactly_two_total_token_post_attempts_maximum_required",
    "fixed_100_millisecond_backoff_required",
    "retry_after_http_response_forbidden",
    "retry_after_oauth_error_forbidden",
    "parallel_retry_forbidden",
    "recursive_retry_forbidden",
    "retry_after_abort_or_cancellation_forbidden",
    "same_token_endpoint_required",
    "same_http_post_method_required",
    "same_normalized_token_parameter_subset_required",
    "same_authorization_code_required",
    "same_pkce_verifier_required",
    "same_redirect_uri_required",
    "no_client_secret_or_assertion_required",
    "credentials_omit_required",
    "redirect_error_mode_required",
    "cache_no_store_required",
    "retry_telemetry_count_required",
    "exact_distribution_artifact_proof_required",
    "exact_package_version_and_integrity_proof_required",
    "package_json_and_exports_proof_required",
    "compiled_retry_path_inspection_required",
    "retry_behavior_adversarial_test_required",
    "current_supported_release_revalidation_required",
    "downgrade_without_independent_review_rejected",
    "all_other_step216_runtime_controls_preserved",
    "no_step216_or_step217_source_rewrite_performed",
    "offline_reconciliation_constraints_validated",
)

_DEFERRED_FALSE_FIELDS = (
    "registry_metadata_checked",
    "package_version_current_checked",
    "package_tarball_downloaded",
    "package_tarball_integrity_checked",
    "package_signature_or_provenance_checked",
    "package_license_source_checked",
    "package_security_advisories_checked",
    "package_json_checked",
    "package_exports_checked",
    "redirect_bridge_export_checked",
    "compiled_distribution_artifact_inspected",
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
    "retry_configuration_surface_checked",
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "reviewed_candidate_compatible_with_successor_policy",
    "package_selection_ready",
    "dependency_lockfile_created",
    "dependency_lockfile_integrity_checked",
    "package_installed",
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
    "endpoint_configuration_mutation_performed",
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
    for value in ("engineer4me-step218-v1", label, str(len(values)), *values):
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
            if depth > MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_NESTING_DEPTH:
                raise ValueError("nesting limit")
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_CONTAINERS:
            raise ValueError("structure limit")


def _require_exact_document_scalars(parsed: dict[str, Any]) -> None:
    expected = {
        "document_type",
        "schema_version",
        "source",
        "approved_msal_browser_control_document_sha256",
        "reconciliation_profile",
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


def _validate_step217_conflict_state(
    receipt: EntraCallingClientMSALBrowserReadinessReceipt,
) -> None:
    receipt.__post_init__()
    if (
        receipt.package_name != MSAL_BROWSER_PACKAGE_NAME
        or receipt.reviewed_package_version != MSAL_BROWSER_REVIEWED_VERSION
        or receipt.reviewed_token_post_retry_count
        != MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
        or receipt.reviewed_token_post_retry_backoff_milliseconds
        != MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_BACKOFF_MILLISECONDS
        or receipt.step216_no_retry_conflict_detected is not True
        or receipt.reviewed_candidate_approved_for_integration is not False
        or receipt.reviewed_candidate_compatible_with_step216 is not False
        or receipt.package_selection_ready is not False
        or receipt.activation_ready is not False
    ):
        raise ValueError("Step 217 conflict state mismatch")


def _conditional_retry_exception_profile() -> bytes:
    return _canonical_bytes(
        {
            "status": RECONCILIATION_POLICY_STATUS,
            "step216RequiredRetryCount": STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT,
            "conditionalMaximumRetryCount": (
                RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT
            ),
            "conditionalMaximumAttemptCount": (
                RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT
            ),
            "trigger": RECONCILIATION_RETRY_TRIGGER,
            "execution": RECONCILIATION_RETRY_EXECUTION,
            "backoffMilliseconds": RECONCILIATION_FIXED_BACKOFF_MILLISECONDS,
            "httpResponseRetryCount": RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT,
            "oauthErrorRetryCount": RECONCILIATION_OAUTH_ERROR_RETRY_COUNT,
            "parallelRetryAllowed": False,
            "recursiveRetryAllowed": False,
            "retryAfterAbortOrCancellationAllowed": False,
            "sameNormalizedTokenRequestRequired": True,
            "allOtherStep216ControlsPreserved": True,
            "approved": False,
        }
    )


def _distribution_artifact_verification_plan() -> bytes:
    return _canonical_bytes(
        {
            "package": MSAL_BROWSER_PACKAGE_NAME,
            "version": MSAL_BROWSER_REVIEWED_VERSION,
            "exactRegistryMetadataRequired": True,
            "exactTarballRequired": True,
            "registryIntegrityRequired": True,
            "packageJsonRequired": True,
            "exportsRequired": True,
            "redirectBridgeExportRequired": True,
            "compiledRetryPathInspectionRequired": True,
            "adversarialTransportFailureTestsRequired": True,
            "httpAndOauthErrorNoRetryTestsRequired": True,
            "abortAndCancellationNoRetryTestsRequired": True,
            "responseLossAmbiguityTestRequired": True,
            "providerIoPerformed": False,
            "approved": False,
        }
    )


def _response_loss_risk_profile() -> bytes:
    return _canonical_bytes(
        {
            "ambiguity": RECONCILIATION_RESPONSE_AMBIGUITY,
            "firstRequestMayReachTokenEndpoint": True,
            "firstResponseMayBeUnavailableToBrowser": True,
            "authorizationCodeMayAlreadyBeConsumed": True,
            "retryMayReturnInvalidGrant": True,
            "automaticSuccessGuaranteed": False,
            "credentialReplaySafetyEstablished": False,
            "userReauthenticationMayBeRequired": True,
            "riskAccepted": False,
        }
    )


def _package_selection_state() -> bytes:
    return _canonical_bytes(
        {
            "package": MSAL_BROWSER_PACKAGE_NAME,
            "reviewedCandidateVersion": MSAL_BROWSER_REVIEWED_VERSION,
            "downgradeAllowedWithoutReview": False,
            "currentReleaseRevalidationRequired": True,
            "artifactProofRequired": True,
            "conditionalExceptionApproved": False,
            "step216Superseded": False,
            "compatible": False,
            "selectionReady": False,
        }
    )


def _load_internal(
    *,
    document: bytes,
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
) -> EntraCallingClientMSALRetryReconciliationReadinessReceipt:
    byte_inputs = (
        document,
        msal_browser_control_document,
        pkce_runtime_control_document,
        redirect_endpoint_control_document,
        api_registration_document,
        calling_client_registration_document,
        inventory_document,
    )
    digest_inputs = (
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

    msal_receipt = load_entra_calling_client_msal_browser_readiness(
        document=msal_browser_control_document,
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
        msal_receipt.msal_browser_control_document_sha256,
        approved_msal_browser_control_document_sha256,
    ):
        raise ValueError("MSAL Browser control digest mismatch")
    _validate_step217_conflict_state(msal_receipt)

    if (
        not document
        or len(document)
        > MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_BYTES
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
    validated = EntraCallingClientMSALRetryReconciliationDocument.model_validate_json(
        canonical_document
    )
    if not hmac.compare_digest(
        validated.approved_msal_browser_control_document_sha256,
        approved_msal_browser_control_document_sha256,
    ):
        raise ValueError("approved evidence mismatch")

    exception_profile = _conditional_retry_exception_profile()
    artifact_plan = _distribution_artifact_verification_plan()
    risk_profile = _response_loss_risk_profile()
    selection_state = _package_selection_state()
    true_values = {field: True for field in _STRUCTURAL_TRUE_FIELDS}
    false_values = {field: False for field in _DEFERRED_FALSE_FIELDS}
    return EntraCallingClientMSALRetryReconciliationReadinessReceipt(
        receipt_type=ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE,
        schema_version=ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCHEMA_VERSION,
        source=validated.source,
        validation_scope=ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE,
        reconciliation_profile=validated.reconciliation_profile,
        package_name=MSAL_BROWSER_PACKAGE_NAME,
        reviewed_package_version=MSAL_BROWSER_REVIEWED_VERSION,
        retry_trigger=RECONCILIATION_RETRY_TRIGGER,
        retry_execution=RECONCILIATION_RETRY_EXECUTION,
        retry_backoff=RECONCILIATION_RETRY_BACKOFF,
        response_ambiguity=RECONCILIATION_RESPONSE_AMBIGUITY,
        policy_status=RECONCILIATION_POLICY_STATUS,
        artifact_proof=RECONCILIATION_ARTIFACT_PROOF,
        configuration_sha256=msal_receipt.configuration_sha256,
        api_registration_document_sha256=(
            msal_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            msal_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=(
            msal_receipt.approved_inventory_document_sha256
        ),
        inventory_document_sha256=msal_receipt.inventory_document_sha256,
        approved_redirect_endpoint_control_document_sha256=(
            msal_receipt.approved_redirect_endpoint_control_document_sha256
        ),
        redirect_endpoint_control_document_sha256=(
            msal_receipt.redirect_endpoint_control_document_sha256
        ),
        approved_pkce_runtime_control_document_sha256=(
            msal_receipt.approved_pkce_runtime_control_document_sha256
        ),
        pkce_runtime_control_document_sha256=(
            msal_receipt.pkce_runtime_control_document_sha256
        ),
        approved_msal_browser_control_document_sha256=(
            approved_msal_browser_control_document_sha256
        ),
        msal_browser_control_document_sha256=(
            msal_receipt.msal_browser_control_document_sha256
        ),
        offline_msal_browser_readiness_receipt_sha256=hashlib.sha256(
            render_entra_calling_client_msal_browser_readiness_receipt(
                msal_receipt
            ).encode("utf-8")
        ).hexdigest(),
        retry_reconciliation_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=msal_receipt.tenant_id_sha256,
        calling_client_application_id_sha256=(
            msal_receipt.calling_client_application_id_sha256
        ),
        calling_client_application_object_id_sha256=(
            msal_receipt.calling_client_application_object_id_sha256
        ),
        api_application_id_sha256=msal_receipt.api_application_id_sha256,
        api_delegated_scope_id_sha256=msal_receipt.api_delegated_scope_id_sha256,
        spa_redirect_uris_sha256=msal_receipt.spa_redirect_uris_sha256,
        authority_origin_sha256=msal_receipt.authority_origin_sha256,
        authority_sha256=msal_receipt.authority_sha256,
        known_authorities_sha256=msal_receipt.known_authorities_sha256,
        conditional_retry_exception_profile_sha256=_framed_sha256(
            "conditional_retry_exception_profile", exception_profile
        ),
        distribution_artifact_verification_plan_sha256=_framed_sha256(
            "distribution_artifact_verification_plan", artifact_plan
        ),
        response_loss_risk_profile_sha256=_framed_sha256(
            "response_loss_risk_profile", risk_profile
        ),
        package_selection_state_sha256=_framed_sha256(
            "package_selection_state", selection_state
        ),
        step216_required_token_post_retry_count=(
            STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT
        ),
        reviewed_candidate_token_post_retry_count=(
            MSAL_BROWSER_REVIEWED_TOKEN_POST_RETRY_COUNT
        ),
        conditional_maximum_token_post_retry_count=(
            RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT
        ),
        conditional_maximum_token_post_attempt_count=(
            RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT
        ),
        conditional_fixed_backoff_milliseconds=(
            RECONCILIATION_FIXED_BACKOFF_MILLISECONDS
        ),
        conditional_http_response_retry_count=(
            RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT
        ),
        conditional_oauth_error_retry_count=RECONCILIATION_OAUTH_ERROR_RETRY_COUNT,
        desired_redirect_endpoint_count=msal_receipt.desired_redirect_endpoint_count,
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


def load_entra_calling_client_msal_retry_reconciliation_readiness(
    *,
    document: bytes,
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
) -> EntraCallingClientMSALRetryReconciliationReadinessReceipt:
    """Validate the retry reconciliation without package or provider I/O."""

    result = None
    error = None
    invalid_call = False
    failed = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document=document,
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
        msal_browser_control_document = None
        approved_msal_browser_control_document_sha256 = None
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
        raise KeyboardInterrupt("Entra MSAL retry reconciliation interrupted")
    if terminated:
        result = None
        raise SystemExit("Entra MSAL retry reconciliation terminated")
    if invalid_call:
        result = None
        raise TypeError("Entra MSAL retry reconciliation inputs are invalid")
    if failed or result is None:
        result = None
        raise EntraCallingClientMSALRetryReconciliationReadinessError(
            "Entra MSAL retry reconciliation validation failed"
        )
    return result


def render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
    receipt: EntraCallingClientMSALRetryReconciliationReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized retry-reconciliation evidence."""

    if type(receipt) is not EntraCallingClientMSALRetryReconciliationReadinessReceipt:
        raise TypeError("Entra MSAL retry reconciliation receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE",
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE",
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCHEMA_VERSION",
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE",
    "ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SOURCE",
    "MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_BYTES",
    "RECONCILIATION_ARTIFACT_PROOF",
    "RECONCILIATION_FIXED_BACKOFF_MILLISECONDS",
    "RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT",
    "RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT",
    "RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT",
    "RECONCILIATION_OAUTH_ERROR_RETRY_COUNT",
    "RECONCILIATION_POLICY_STATUS",
    "RECONCILIATION_RESPONSE_AMBIGUITY",
    "RECONCILIATION_RETRY_BACKOFF",
    "RECONCILIATION_RETRY_EXECUTION",
    "RECONCILIATION_RETRY_TRIGGER",
    "STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT",
    "EntraCallingClientMSALRetryReconciliationReadinessError",
    "EntraCallingClientMSALRetryReconciliationReadinessReceipt",
    "load_entra_calling_client_msal_retry_reconciliation_readiness",
    "render_entra_calling_client_msal_retry_reconciliation_readiness_receipt",
]
