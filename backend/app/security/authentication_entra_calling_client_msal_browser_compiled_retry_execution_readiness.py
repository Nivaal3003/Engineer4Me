"""Offline exact-artifact and compiled retry execution readiness.

This module performs no filesystem, registry, process, browser, OAuth, DNS,
TLS, HTTP, Graph, Entra, or other provider I/O. It reruns the approved Step
220 source chain and binds exact reviewed MSAL Browser 5.18.0/MSAL Common
16.12.0 artifacts plus a fail-closed successor execution profile.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_current_version_readiness import (
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS,
    MSAL_BROWSER_CURRENT_CANDIDATE_VERSION,
    MSAL_COMMON_CURRENT_DEPENDENCY_VERSION,
    EntraCallingClientMSALCurrentVersionReadinessReceipt,
    load_entra_calling_client_msal_current_version_readiness,
    render_entra_calling_client_msal_current_version_readiness_receipt,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_execution_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_reviewed_msal_browser_5_18_0_dual_artifact_execution_seam"
VALIDATION_SCOPE = "offline_exact_dual_artifact_and_compiled_retry_execution_readiness"
EXECUTION_PROFILE = "engineer4me_msal_browser_5_18_0_compiled_retry_execution_v1"
READINESS_STATUS = (
    "exact_artifacts_and_execution_plan_bound_but_not_acquired_or_executed"
)

BROWSER_PACKAGE_NAME = "@azure/msal-browser"
BROWSER_VERSION = "5.18.0"
BROWSER_TARBALL_URL = (
    "https://registry.npmjs.org/@azure/msal-browser/-/msal-browser-5.18.0.tgz"
)
BROWSER_SRI = "sha512-SPTeHYZghdEdRddJzNjhH+CI5MSQtquNYwGJnYXfOHIBRXCmrWimBS85OhwXpXFIlrCtNTbBPm5mPAWRNEoktA=="
BROWSER_SHASUM = "446b9b42678a220419ef43054fdfc13855a12c2e"
BROWSER_TARBALL_SHA256 = (
    "a596c26b0dd0dffa118dfd1fb494bea3204fb0017efe53d6c055eaaae96d1d83"
)
BROWSER_TARBALL_BYTES = 2_115_481
BROWSER_ARCHIVE_MEMBER_COUNT = 1_136
BROWSER_ARCHIVE_UNCOMPRESSED_BYTES = 12_018_067
BROWSER_PACKAGE_JSON_SHA256 = (
    "cc00bc2ef5f1be431d7f7fdba1a872a165b0b463427bb4f38942ea729730793a"
)

COMMON_PACKAGE_NAME = "@azure/msal-common"
COMMON_VERSION = "16.12.0"
COMMON_TARBALL_URL = (
    "https://registry.npmjs.org/@azure/msal-common/-/msal-common-16.12.0.tgz"
)
COMMON_SRI = "sha512-hgLgfRdbG2AmhXPygebf1KYJEvse86+ZZLWufdiTKaGRYEUqOzHdlf6AS1IiuUCHWbynkgbHc451jSNkbfhWlg=="
COMMON_SHASUM = "5cbd58db91948f92382e8c628f34a57f469d3a74"
COMMON_TARBALL_SHA256 = (
    "d5970eda340baf50398c039c2cdd232156e2799347de6519ebbf7adaf3104387"
)
COMMON_TARBALL_BYTES = 464_089
COMMON_ARCHIVE_MEMBER_COUNT = 662
COMMON_ARCHIVE_UNCOMPRESSED_BYTES = 2_834_778
COMMON_PACKAGE_JSON_SHA256 = (
    "9036bf314224332a79a37f6b564101c6eb0ad70ef90dd6b7bddd3d41c315a1d4"
)

COMPILED_RETRY_ENTRY_PATH = "package/dist/network/FetchClient.mjs"
COMPILED_RETRY_ENTRY_SHA256 = (
    "abf75690801b45b64347873bb5483774aab1b70f1cf261021aa4e6b5181e9704"
)
COMPILED_RETRY_ENTRY_BYTES = 5_560
COMPILED_RETRY_MAXIMUM_RETRIES = 1
COMPILED_RETRY_MAXIMUM_ATTEMPTS = 2
COMPILED_RETRY_BACKOFF_MILLISECONDS = 100
ARTIFACT_COUNT = 2
BEHAVIOR_SCENARIO_COUNT = 10
MAX_DOCUMENT_BYTES = 4_096


class EntraCallingClientMSALCompiledRetryExecutionReadinessError(ValueError):
    """Sanitized Step 221 validation failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


class EntraCallingClientMSALCompiledRetryExecutionReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_execution_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_reviewed_msal_browser_5_18_0_dual_artifact_execution_seam"
    ]
    approved_current_version_readiness_document_sha256: str
    execution_profile: Literal[
        "engineer4me_msal_browser_5_18_0_compiled_retry_execution_v1"
    ]

    @model_validator(mode="after")
    def validate_digest(
        self,
    ) -> EntraCallingClientMSALCompiledRetryExecutionReadinessDocument:
        if not _is_sha256(self.approved_current_version_readiness_document_sha256):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    execution_profile: str
    readiness_status: str
    browser_package_name: str
    browser_version: str
    browser_tarball_url: str
    browser_sri: str
    browser_shasum: str
    common_package_name: str
    common_version: str
    common_tarball_url: str
    common_sri: str
    common_shasum: str
    compiled_retry_entry_path: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    inventory_document_sha256: str
    redirect_endpoint_control_document_sha256: str
    pkce_runtime_control_document_sha256: str
    msal_browser_control_document_sha256: str
    retry_reconciliation_document_sha256: str
    current_version_readiness_document_sha256: str
    current_version_readiness_receipt_sha256: str
    compiled_execution_readiness_document_sha256: str
    tenant_id_sha256: str
    calling_client_application_id_sha256: str
    spa_redirect_uris_sha256: str
    authority_sha256: str
    browser_tarball_sha256: str
    browser_package_json_sha256: str
    common_tarball_sha256: str
    common_package_json_sha256: str
    compiled_retry_entry_sha256: str
    reviewed_dual_artifact_profile_sha256: str
    compiled_execution_profile_sha256: str
    compiled_behavior_matrix_sha256: str
    fail_closed_selection_state_sha256: str
    artifact_count: int
    behavior_scenario_count: int
    browser_tarball_bytes: int
    browser_archive_member_count: int
    browser_archive_uncompressed_bytes: int
    common_tarball_bytes: int
    common_archive_member_count: int
    common_archive_uncompressed_bytes: int
    compiled_retry_entry_bytes: int
    compiled_retry_maximum_retries: int
    compiled_retry_maximum_attempts: int
    compiled_retry_backoff_milliseconds: int
    step220_source_chain_revalidated: bool
    approved_current_version_readiness_digest_bound: bool
    exact_step220_unapproved_state_validated: bool
    exact_browser_artifact_identity_declared: bool
    exact_common_artifact_identity_declared: bool
    exact_browser_common_dependency_edge_required: bool
    exact_sha512_sri_required_for_both_artifacts: bool
    exact_tarball_sha256_required_for_both_artifacts: bool
    exact_package_json_hashes_required: bool
    bounded_safe_archive_closure_required: bool
    exact_compiled_retry_entry_hash_required: bool
    exact_compiled_module_resolution_closure_required: bool
    one_ephemeral_workspace_required: bool
    one_sealed_node_process_required: bool
    lifecycle_scripts_forbidden: bool
    network_disabled_before_compiled_import_required: bool
    controlled_fake_fetch_required: bool
    real_oauth_inputs_forbidden: bool
    transport_failure_only_retry_required: bool
    one_retry_two_attempt_maximum_required: bool
    fixed_100_millisecond_backoff_required: bool
    request_equivalence_required: bool
    response_oauth_abort_non_token_retry_exclusions_required: bool
    concurrency_isolation_required: bool
    telemetry_increment_required: bool
    complete_ten_scenario_matrix_required: bool
    step216_zero_retry_requirement_preserved: bool
    conditional_exception_remains_unapproved: bool
    exact_artifact_execution_plan_validated: bool
    registry_metadata_checked: bool
    browser_tarball_downloaded: bool
    common_tarball_downloaded: bool
    browser_sri_integrity_checked: bool
    common_sri_integrity_checked: bool
    browser_archive_checked: bool
    common_archive_checked: bool
    package_dependency_edge_checked: bool
    compiled_retry_entry_checked: bool
    compiled_module_resolution_checked: bool
    exact_node_binary_identity_checked: bool
    node_process_executed: bool
    compiled_retry_trigger_checked: bool
    compiled_retry_attempt_count_checked: bool
    compiled_retry_backoff_checked: bool
    compiled_request_equivalence_checked: bool
    compiled_exclusion_matrix_checked: bool
    compiled_concurrency_checked: bool
    compiled_telemetry_checked: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    current_candidate_compatible: bool
    current_candidate_selected: bool
    dependency_lockfile_created: bool
    package_installed: bool
    package_code_imported: bool
    filesystem_io_performed: bool
    process_io_performed: bool
    network_io_performed: bool
    registry_io_performed: bool
    browser_io_performed: bool
    provider_io_performed: bool
    runtime_pkce_checked: bool
    token_validated: bool
    real_api_call_checked: bool
    activation_ready: bool
    receipt_self_authenticating: bool

    def __post_init__(self) -> None:
        strings = tuple(getattr(self, name) for name in _STRING_FIELDS)
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        counts = tuple(getattr(self, name) for name in _COUNT_FIELDS)
        if (
            any(type(value) is not str for value in strings)
            or self.receipt_type != RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or self.source != SOURCE
            or self.validation_scope != VALIDATION_SCOPE
            or self.execution_profile != EXECUTION_PROFILE
            or self.readiness_status != READINESS_STATUS
            or self.browser_package_name != BROWSER_PACKAGE_NAME
            or self.browser_version != BROWSER_VERSION
            or self.browser_tarball_url != BROWSER_TARBALL_URL
            or self.browser_sri != BROWSER_SRI
            or self.browser_shasum != BROWSER_SHASUM
            or self.common_package_name != COMMON_PACKAGE_NAME
            or self.common_version != COMMON_VERSION
            or self.common_tarball_url != COMMON_TARBALL_URL
            or self.common_sri != COMMON_SRI
            or self.common_shasum != COMMON_SHASUM
            or self.compiled_retry_entry_path != COMPILED_RETRY_ENTRY_PATH
            or any(not _is_sha256(value) for value in digests)
            or any(type(value) is not int for value in counts)
            or self.artifact_count != ARTIFACT_COUNT
            or self.behavior_scenario_count != BEHAVIOR_SCENARIO_COUNT
            or self.browser_tarball_bytes != BROWSER_TARBALL_BYTES
            or self.browser_archive_member_count != BROWSER_ARCHIVE_MEMBER_COUNT
            or self.browser_archive_uncompressed_bytes
            != BROWSER_ARCHIVE_UNCOMPRESSED_BYTES
            or self.common_tarball_bytes != COMMON_TARBALL_BYTES
            or self.common_archive_member_count != COMMON_ARCHIVE_MEMBER_COUNT
            or self.common_archive_uncompressed_bytes
            != COMMON_ARCHIVE_UNCOMPRESSED_BYTES
            or self.compiled_retry_entry_bytes != COMPILED_RETRY_ENTRY_BYTES
            or self.compiled_retry_maximum_retries != COMPILED_RETRY_MAXIMUM_RETRIES
            or self.compiled_retry_maximum_attempts != COMPILED_RETRY_MAXIMUM_ATTEMPTS
            or self.compiled_retry_backoff_milliseconds
            != COMPILED_RETRY_BACKOFF_MILLISECONDS
            or any(getattr(self, name) is not True for name in _TRUE_FIELDS)
            or any(getattr(self, name) is not False for name in _FALSE_FIELDS)
        ):
            raise ValueError(
                "MSAL compiled retry execution readiness receipt is invalid"
            )


_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "execution_profile",
    "readiness_status",
    "browser_package_name",
    "browser_version",
    "browser_tarball_url",
    "browser_sri",
    "browser_shasum",
    "common_package_name",
    "common_version",
    "common_tarball_url",
    "common_sri",
    "common_shasum",
    "compiled_retry_entry_path",
)
_COUNT_FIELDS = (
    "artifact_count",
    "behavior_scenario_count",
    "browser_tarball_bytes",
    "browser_archive_member_count",
    "browser_archive_uncompressed_bytes",
    "common_tarball_bytes",
    "common_archive_member_count",
    "common_archive_uncompressed_bytes",
    "compiled_retry_entry_bytes",
    "compiled_retry_maximum_retries",
    "compiled_retry_maximum_attempts",
    "compiled_retry_backoff_milliseconds",
)
_TRUE_FIELDS = (
    "step220_source_chain_revalidated",
    "approved_current_version_readiness_digest_bound",
    "exact_step220_unapproved_state_validated",
    "exact_browser_artifact_identity_declared",
    "exact_common_artifact_identity_declared",
    "exact_browser_common_dependency_edge_required",
    "exact_sha512_sri_required_for_both_artifacts",
    "exact_tarball_sha256_required_for_both_artifacts",
    "exact_package_json_hashes_required",
    "bounded_safe_archive_closure_required",
    "exact_compiled_retry_entry_hash_required",
    "exact_compiled_module_resolution_closure_required",
    "one_ephemeral_workspace_required",
    "one_sealed_node_process_required",
    "lifecycle_scripts_forbidden",
    "network_disabled_before_compiled_import_required",
    "controlled_fake_fetch_required",
    "real_oauth_inputs_forbidden",
    "transport_failure_only_retry_required",
    "one_retry_two_attempt_maximum_required",
    "fixed_100_millisecond_backoff_required",
    "request_equivalence_required",
    "response_oauth_abort_non_token_retry_exclusions_required",
    "concurrency_isolation_required",
    "telemetry_increment_required",
    "complete_ten_scenario_matrix_required",
    "step216_zero_retry_requirement_preserved",
    "conditional_exception_remains_unapproved",
    "exact_artifact_execution_plan_validated",
)
_FALSE_FIELDS = (
    "registry_metadata_checked",
    "browser_tarball_downloaded",
    "common_tarball_downloaded",
    "browser_sri_integrity_checked",
    "common_sri_integrity_checked",
    "browser_archive_checked",
    "common_archive_checked",
    "package_dependency_edge_checked",
    "compiled_retry_entry_checked",
    "compiled_module_resolution_checked",
    "exact_node_binary_identity_checked",
    "node_process_executed",
    "compiled_retry_trigger_checked",
    "compiled_retry_attempt_count_checked",
    "compiled_retry_backoff_checked",
    "compiled_request_equivalence_checked",
    "compiled_exclusion_matrix_checked",
    "compiled_concurrency_checked",
    "compiled_telemetry_checked",
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "current_candidate_compatible",
    "current_candidate_selected",
    "dependency_lockfile_created",
    "package_installed",
    "package_code_imported",
    "filesystem_io_performed",
    "process_io_performed",
    "network_io_performed",
    "registry_io_performed",
    "browser_io_performed",
    "provider_io_performed",
    "runtime_pkce_checked",
    "token_validated",
    "real_api_call_checked",
    "activation_ready",
    "receipt_self_authenticating",
)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed(label: str, value: object) -> str:
    digest = hashlib.sha256()
    for part in ("engineer4me-step221-v1", label, _canonical(value)):
        encoded = part if isinstance(part, bytes) else part.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _float(value: str) -> float:
    result = float(value)
    if not isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _parse(
    raw: bytes,
) -> tuple[bytes, EntraCallingClientMSALCompiledRetryExecutionReadinessDocument]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DOCUMENT_BYTES:
        raise _ArgumentTypeError("exact document bytes are required")
    parsed = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=_nonfinite,
        parse_float=_float,
    )
    keys = {
        "document_type",
        "schema_version",
        "source",
        "approved_current_version_readiness_document_sha256",
        "execution_profile",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != keys
        or type(parsed["schema_version"]) is not int
        or any(type(parsed[key]) is not str for key in keys - {"schema_version"})
    ):
        raise ValueError("compiled execution readiness document is invalid")
    canonical = _canonical(parsed)
    return (
        canonical,
        EntraCallingClientMSALCompiledRetryExecutionReadinessDocument.model_validate_json(
            canonical
        ),
    )


def _scrub(error: BaseException) -> tuple[bool, bool]:
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
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        children = getattr(current, "exceptions", ())
        if type(children) is tuple:
            pending.extend(x for x in children if isinstance(x, BaseException))
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001,S110
            pass
    return interrupted, terminated


def _load_internal(
    *, document: bytes, **step220_arguments: object
) -> EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt:
    if type(document) is not bytes:
        raise _ArgumentTypeError("document must be exact bytes")
    current_version_document = step220_arguments.pop(
        "current_version_readiness_document", None
    )
    approved = step220_arguments.pop(
        "approved_current_version_readiness_document_sha256", None
    )
    if type(current_version_document) is not bytes or not _is_sha256(approved):
        raise _ArgumentTypeError("exact Step 220 document evidence is required")
    prior = load_entra_calling_client_msal_current_version_readiness(
        document=current_version_document,
        **step220_arguments
    )
    if type(prior) is not EntraCallingClientMSALCurrentVersionReadinessReceipt:
        raise ValueError("exact Step 220 receipt is required")
    prior_rendered = render_entra_calling_client_msal_current_version_readiness_receipt(
        prior
    )
    if (
        prior.readiness_status != ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS
        or prior.current_candidate_browser_version
        != MSAL_BROWSER_CURRENT_CANDIDATE_VERSION
        or prior.current_common_dependency_version
        != MSAL_COMMON_CURRENT_DEPENDENCY_VERSION
        or prior.conditional_exception_approved
        or prior.step216_zero_retry_superseded
        or prior.current_candidate_selected
        or prior.package_installed
        or prior.package_code_executed
        or prior.activation_ready
    ):
        raise ValueError("Step 220 state is not the exact unapproved baseline")
    canonical_document, validated = _parse(document)
    if (
        not hmac.compare_digest(
            validated.approved_current_version_readiness_document_sha256,
            approved,
        )
        or not hmac.compare_digest(
            prior.current_version_readiness_document_sha256,
            approved,
        )
    ):
        raise ValueError("Step 220 approved evidence mismatch")

    artifacts = [
        {
            "name": BROWSER_PACKAGE_NAME,
            "version": BROWSER_VERSION,
            "tarball": BROWSER_TARBALL_URL,
            "sri": BROWSER_SRI,
            "shasum": BROWSER_SHASUM,
            "sha256": BROWSER_TARBALL_SHA256,
            "bytes": BROWSER_TARBALL_BYTES,
            "members": BROWSER_ARCHIVE_MEMBER_COUNT,
            "uncompressedBytes": BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
            "packageJsonSha256": BROWSER_PACKAGE_JSON_SHA256,
        },
        {
            "name": COMMON_PACKAGE_NAME,
            "version": COMMON_VERSION,
            "tarball": COMMON_TARBALL_URL,
            "sri": COMMON_SRI,
            "shasum": COMMON_SHASUM,
            "sha256": COMMON_TARBALL_SHA256,
            "bytes": COMMON_TARBALL_BYTES,
            "members": COMMON_ARCHIVE_MEMBER_COUNT,
            "uncompressedBytes": COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
            "packageJsonSha256": COMMON_PACKAGE_JSON_SHA256,
        },
    ]
    execution = {
        "entry": COMPILED_RETRY_ENTRY_PATH,
        "entrySha256": COMPILED_RETRY_ENTRY_SHA256,
        "entryBytes": COMPILED_RETRY_ENTRY_BYTES,
        "nodeIdentity": "exact_and_receipt_bound",
        "workspace": "ephemeral_bounded",
        "network": "disabled_before_import",
        "processes": 1,
        "fetch": "controlled_fake_only",
        "realOAuthInputs": False,
    }
    scenarios = [
        "transport_failure_then_success",
        "two_transport_failures",
        "http_400_no_retry",
        "http_429_no_retry",
        "http_500_no_retry",
        "oauth_error_no_retry",
        "abort_no_retry",
        "non_token_request_no_retry",
        "concurrent_isolation",
        "telemetry_and_request_equivalence",
    ]
    selection = {
        "step216ZeroRetrySuperseded": False,
        "exceptionApproved": False,
        "compatible": False,
        "selected": False,
    }
    true_values = {name: True for name in _TRUE_FIELDS}
    false_values = {name: False for name in _FALSE_FIELDS}
    return EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=validated.source,
        validation_scope=VALIDATION_SCOPE,
        execution_profile=validated.execution_profile,
        readiness_status=READINESS_STATUS,
        browser_package_name=BROWSER_PACKAGE_NAME,
        browser_version=BROWSER_VERSION,
        browser_tarball_url=BROWSER_TARBALL_URL,
        browser_sri=BROWSER_SRI,
        browser_shasum=BROWSER_SHASUM,
        common_package_name=COMMON_PACKAGE_NAME,
        common_version=COMMON_VERSION,
        common_tarball_url=COMMON_TARBALL_URL,
        common_sri=COMMON_SRI,
        common_shasum=COMMON_SHASUM,
        compiled_retry_entry_path=COMPILED_RETRY_ENTRY_PATH,
        configuration_sha256=prior.configuration_sha256,
        api_registration_document_sha256=prior.api_registration_document_sha256,
        calling_client_registration_document_sha256=prior.calling_client_registration_document_sha256,
        inventory_document_sha256=prior.inventory_document_sha256,
        redirect_endpoint_control_document_sha256=prior.redirect_endpoint_control_document_sha256,
        pkce_runtime_control_document_sha256=prior.pkce_runtime_control_document_sha256,
        msal_browser_control_document_sha256=prior.msal_browser_control_document_sha256,
        retry_reconciliation_document_sha256=prior.retry_reconciliation_document_sha256,
        current_version_readiness_document_sha256=prior.current_version_readiness_document_sha256,
        current_version_readiness_receipt_sha256=hashlib.sha256(
            prior_rendered.encode("utf-8")
        ).hexdigest(),
        compiled_execution_readiness_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        tenant_id_sha256=prior.tenant_id_sha256,
        calling_client_application_id_sha256=prior.calling_client_application_id_sha256,
        spa_redirect_uris_sha256=prior.spa_redirect_uris_sha256,
        authority_sha256=prior.authority_sha256,
        browser_tarball_sha256=BROWSER_TARBALL_SHA256,
        browser_package_json_sha256=BROWSER_PACKAGE_JSON_SHA256,
        common_tarball_sha256=COMMON_TARBALL_SHA256,
        common_package_json_sha256=COMMON_PACKAGE_JSON_SHA256,
        compiled_retry_entry_sha256=COMPILED_RETRY_ENTRY_SHA256,
        reviewed_dual_artifact_profile_sha256=_framed("artifacts", artifacts),
        compiled_execution_profile_sha256=_framed("execution", execution),
        compiled_behavior_matrix_sha256=_framed("scenarios", scenarios),
        fail_closed_selection_state_sha256=_framed("selection", selection),
        artifact_count=ARTIFACT_COUNT,
        behavior_scenario_count=BEHAVIOR_SCENARIO_COUNT,
        browser_tarball_bytes=BROWSER_TARBALL_BYTES,
        browser_archive_member_count=BROWSER_ARCHIVE_MEMBER_COUNT,
        browser_archive_uncompressed_bytes=BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
        common_tarball_bytes=COMMON_TARBALL_BYTES,
        common_archive_member_count=COMMON_ARCHIVE_MEMBER_COUNT,
        common_archive_uncompressed_bytes=COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
        compiled_retry_entry_bytes=COMPILED_RETRY_ENTRY_BYTES,
        compiled_retry_maximum_retries=COMPILED_RETRY_MAXIMUM_RETRIES,
        compiled_retry_maximum_attempts=COMPILED_RETRY_MAXIMUM_ATTEMPTS,
        compiled_retry_backoff_milliseconds=COMPILED_RETRY_BACKOFF_MILLISECONDS,
        **true_values,
        **false_values,
    )


def load_entra_calling_client_msal_compiled_retry_execution_readiness(
    **arguments: object,
) -> EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt:
    """Return one sanitized offline Step 221 readiness receipt."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(**arguments)
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
        arguments.clear()
    if interrupted:
        raise KeyboardInterrupt("MSAL compiled retry execution readiness interrupted")
    if terminated:
        raise SystemExit("MSAL compiled retry execution readiness terminated")
    if invalid:
        raise TypeError("MSAL compiled retry execution readiness inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALCompiledRetryExecutionReadinessError(
            "MSAL compiled retry execution readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt(
    receipt: EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized readiness evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt
    ):
        raise TypeError("exact MSAL compiled retry readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "BEHAVIOR_SCENARIO_COUNT",
    "BROWSER_ARCHIVE_MEMBER_COUNT",
    "BROWSER_PACKAGE_NAME",
    "BROWSER_TARBALL_SHA256",
    "BROWSER_VERSION",
    "COMMON_ARCHIVE_MEMBER_COUNT",
    "COMMON_PACKAGE_NAME",
    "COMMON_TARBALL_SHA256",
    "COMMON_VERSION",
    "COMPILED_RETRY_ENTRY_PATH",
    "COMPILED_RETRY_ENTRY_SHA256",
    "DOCUMENT_TYPE",
    "EXECUTION_PROFILE",
    "READINESS_STATUS",
    "RECEIPT_TYPE",
    "SOURCE",
    "VALIDATION_SCOPE",
    "EntraCallingClientMSALCompiledRetryExecutionReadinessError",
    "EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt",
    "load_entra_calling_client_msal_compiled_retry_execution_readiness",
    "render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt",
]
