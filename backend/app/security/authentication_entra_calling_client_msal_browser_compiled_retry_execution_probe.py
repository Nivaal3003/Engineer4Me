"""Controlled dual-artifact and sealed Node compiled-retry execution proof.

The live path reruns Step 222, performs four exact read-only npm GETs, validates
both immutable archives, extracts only validated regular files to one temporary
workspace, and executes the frozen harness in one permission-restricted Node
process. The observed retry conflict never approves an exception or selection.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness import (
    BEHAVIOR_SCENARIO_COUNT,
    BROWSER_ARCHIVE_MEMBER_COUNT,
    BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
    BROWSER_PACKAGE_JSON_SHA256,
    BROWSER_PACKAGE_NAME,
    BROWSER_SHASUM,
    BROWSER_SRI,
    BROWSER_TARBALL_BYTES,
    BROWSER_TARBALL_SHA256,
    BROWSER_VERSION,
    COMMON_ARCHIVE_MEMBER_COUNT,
    COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
    COMMON_PACKAGE_JSON_SHA256,
    COMMON_PACKAGE_NAME,
    COMMON_SHASUM,
    COMMON_SRI,
    COMMON_TARBALL_BYTES,
    COMMON_TARBALL_SHA256,
    COMMON_VERSION,
    COMPILED_RETRY_ENTRY_BYTES,
    COMPILED_RETRY_ENTRY_PATH,
    COMPILED_RETRY_ENTRY_SHA256,
)
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_harness_readiness import (
    HARNESS_BYTES,
    HARNESS_SCENARIO_COUNT,
    HARNESS_SHA256,
    EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt,
    load_entra_calling_client_msal_compiled_retry_harness_readiness,
    render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_harness_readiness import (
    STATUS as STEP222_STATUS,
)
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_live_loader import (
    BROWSER_TARBALL_URL,
    COMMON_TARBALL_URL,
    NPM_REGISTRY_ORIGIN,
    BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader,
    EntraCallingClientMSALCompiledRetryLiveHTTPResponse,
    build_entra_calling_client_msal_compiled_retry_live_request_plan,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_execution_proof"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_msal_browser_5_18_0_dual_artifact_node_execution"
SCOPE = "exact_dual_artifact_integrity_and_permission_restricted_compiled_execution"
PROFILE = "engineer4me_msal_browser_5_18_0_sealed_compiled_retry_execution_v1"
STATUS = "proof_contract_validated_live_attestation_correlated_separately"
NODE_VERSION = "v24.19.0"
RUNNER_FILE_NAME = (
    "authentication_entra_calling_client_msal_browser_compiled_retry_sealed_runner.mjs"
)
RUNNER_SHA256 = "3fd4ee6630be84a0bec2c6b51417f5418daded62b64cd7dc7dc862e28722012c"
RUNNER_BYTES = 1_375
MAX_DOCUMENT_BYTES = 4_096
MAX_JSON_BYTES = 524_288
MAX_JSON_DEPTH = 32
MAX_TAR_MEMBERS = 4_096
MAX_TAR_FILE_BYTES = 16_777_216
MAX_TAR_UNCOMPRESSED_BYTES = 67_108_864
MAX_STDOUT_BYTES = 65_536
MAX_STDERR_BYTES = 4_096
MAX_NODE_EXECUTABLE_BYTES = 268_435_456
NODE_TIMEOUT_SECONDS = 20
OBSERVED_FAKE_FETCH_CALL_COUNT = 15
OBSERVED_NON_TOKEN_POST_ATTEMPTS = 2
_SAFE_MEMBER = re.compile(r"package/(?:[A-Za-z0-9._@+-]+/)*[A-Za-z0-9._@+-]+\Z")


class EntraCallingClientMSALCompiledRetryExecutionProbeError(ValueError):
    """Sanitized failure at the Step 223 proof boundary."""


class _ArgumentTypeError(TypeError):
    """Private marker for public input misuse."""


class EntraCallingClientMSALCompiledRetryExecutionDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_execution_proof"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_controlled_msal_browser_5_18_0_dual_artifact_node_execution"
    ]
    approved_harness_readiness_document_sha256: str
    expected_node_version: Literal["v24.19.0"]
    approved_node_executable_sha256: str
    execution_profile: Literal[
        "engineer4me_msal_browser_5_18_0_sealed_compiled_retry_execution_v1"
    ]

    @model_validator(mode="after")
    def validate_digests(
        self,
    ) -> EntraCallingClientMSALCompiledRetryExecutionDocument:
        if not _is_sha256(
            self.approved_harness_readiness_document_sha256
        ) or not _is_sha256(self.approved_node_executable_sha256):
            raise ValueError("approved digests must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryArtifactEvidence:
    browser_tarball_sha256: str
    browser_tarball_bytes: int
    browser_archive_member_count: int
    browser_archive_uncompressed_bytes: int
    browser_package_json_sha256: str
    common_tarball_sha256: str
    common_tarball_bytes: int
    common_archive_member_count: int
    common_archive_uncompressed_bytes: int
    common_package_json_sha256: str
    compiled_retry_entry_sha256: str
    compiled_retry_entry_bytes: int
    browser_metadata_response_sha256: str
    common_metadata_response_sha256: str

    def __post_init__(self) -> None:
        expected = {
            "browser_tarball_sha256": BROWSER_TARBALL_SHA256,
            "browser_tarball_bytes": BROWSER_TARBALL_BYTES,
            "browser_archive_member_count": BROWSER_ARCHIVE_MEMBER_COUNT,
            "browser_archive_uncompressed_bytes": BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
            "browser_package_json_sha256": BROWSER_PACKAGE_JSON_SHA256,
            "common_tarball_sha256": COMMON_TARBALL_SHA256,
            "common_tarball_bytes": COMMON_TARBALL_BYTES,
            "common_archive_member_count": COMMON_ARCHIVE_MEMBER_COUNT,
            "common_archive_uncompressed_bytes": COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
            "common_package_json_sha256": COMMON_PACKAGE_JSON_SHA256,
            "compiled_retry_entry_sha256": COMPILED_RETRY_ENTRY_SHA256,
            "compiled_retry_entry_bytes": COMPILED_RETRY_ENTRY_BYTES,
        }
        for name, value in expected.items():
            actual = getattr(self, name)
            if type(actual) is not type(value) or actual != value:
                raise ValueError("compiled retry artifact evidence is invalid")
        if not _is_sha256(self.browser_metadata_response_sha256) or not _is_sha256(
            self.common_metadata_response_sha256
        ):
            raise ValueError("compiled retry metadata evidence is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryExecutionEvidence:
    node_version: str
    node_executable_sha256: str
    stdout: bytes
    stderr: bytes
    exit_code: int

    def __post_init__(self) -> None:
        if (
            type(self.node_version) is not str
            or self.node_version != NODE_VERSION
            or not _is_sha256(self.node_executable_sha256)
            or type(self.stdout) is not bytes
            or not 1 <= len(self.stdout) <= MAX_STDOUT_BYTES
            or type(self.stderr) is not bytes
            or len(self.stderr) > MAX_STDERR_BYTES
            or self.stderr
            or type(self.exit_code) is not int
            or self.exit_code != 0
        ):
            raise ValueError("compiled retry execution evidence is invalid")


class EntraCallingClientMSALCompiledRetryArtifactTransport(Protocol):
    def __call__(self) -> EntraCallingClientMSALCompiledRetryArtifactEvidence: ...


class EntraCallingClientMSALCompiledRetryExecutionTransport(Protocol):
    def __call__(
        self,
        artifact_evidence: EntraCallingClientMSALCompiledRetryArtifactEvidence,
        harness: bytes,
        runner: bytes,
    ) -> EntraCallingClientMSALCompiledRetryExecutionEvidence: ...


@dataclass(slots=True)
class _VerifiedLiveArtifacts:
    evidence: EntraCallingClientMSALCompiledRetryArtifactEvidence
    browser_tarball: bytes
    common_tarball: bytes


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryExecutionProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    execution_profile: str
    proof_status: str
    node_version: str
    browser_package_name: str
    browser_version: str
    common_package_name: str
    common_version: str
    registry_origin: str
    compiled_scope_finding: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    inventory_document_sha256: str
    harness_readiness_document_sha256: str
    harness_readiness_receipt_sha256: str
    execution_proof_document_sha256: str
    browser_tarball_sha256: str
    browser_package_json_sha256: str
    common_tarball_sha256: str
    common_package_json_sha256: str
    compiled_retry_entry_sha256: str
    harness_sha256: str
    runner_sha256: str
    node_executable_sha256: str
    browser_metadata_response_sha256: str
    common_metadata_response_sha256: str
    request_plan_sha256: str
    artifact_evidence_sha256: str
    harness_stdout_sha256: str
    harness_scenario_projection_sha256: str
    permission_profile_sha256: str
    fail_closed_selection_state_sha256: str
    artifact_count: int
    request_plan_count: int
    harness_scenario_count: int
    observed_fake_fetch_call_count: int
    observed_non_token_post_attempts: int
    sealed_registry_request_count: int
    sealed_node_process_count: int
    browser_tarball_bytes: int
    browser_archive_member_count: int
    browser_archive_uncompressed_bytes: int
    common_tarball_bytes: int
    common_archive_member_count: int
    common_archive_uncompressed_bytes: int
    compiled_retry_entry_bytes: int
    harness_bytes: int
    runner_bytes: int
    step222_source_chain_revalidated: bool
    approved_step222_document_digest_bound: bool
    exact_step222_fail_closed_state_validated: bool
    exact_harness_bytes_bound: bool
    exact_runner_bytes_bound: bool
    exact_dual_artifact_identity_required: bool
    exact_four_request_plan_prevalidated: bool
    unauthenticated_get_only_required: bool
    request_body_forbidden: bool
    proxy_redirect_retry_compression_forbidden: bool
    archive_paths_and_types_fail_closed: bool
    browser_common_dependency_edge_required: bool
    compiled_retry_entry_identity_required: bool
    one_ephemeral_workspace_required: bool
    one_sealed_node_process_required: bool
    node_permission_model_required: bool
    network_child_worker_write_addon_wasi_permissions_forbidden: bool
    inspector_and_ffi_permissions_forbidden: bool
    lifecycle_scripts_forbidden: bool
    fake_fetch_and_synthetic_oauth_values_required: bool
    exact_ten_scenario_matrix_required: bool
    non_token_two_attempt_conflict_declared: bool
    step216_zero_retry_requirement_preserved: bool
    conditional_exception_remains_unapproved: bool
    proof_contract_validated: bool
    synthetic_evidence_used: bool
    live_registry_source_attested: bool
    live_browser_artifact_verified: bool
    live_common_artifact_verified: bool
    live_archive_closure_checked: bool
    live_dependency_edge_checked: bool
    live_compiled_entry_checked: bool
    live_ephemeral_extraction_performed: bool
    live_node_executable_hash_checked: bool
    live_node_version_checked: bool
    live_node_permission_profile_checked: bool
    live_harness_process_executed: bool
    live_retry_trigger_checked: bool
    live_retry_count_checked: bool
    live_retry_backoff_checked: bool
    live_response_exclusions_checked: bool
    live_abort_exclusion_checked: bool
    live_non_token_scope_checked: bool
    live_concurrency_checked: bool
    live_telemetry_checked: bool
    live_request_equivalence_checked: bool
    live_non_token_two_attempt_conflict_observed: bool
    live_proof_complete: bool
    sealed_registry_io_performed: bool
    sealed_ephemeral_filesystem_io_performed: bool
    sealed_node_process_io_performed: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    candidate_compatible: bool
    candidate_selected: bool
    dependency_lockfile_created: bool
    package_installed: bool
    browser_oauth_provider_io_performed: bool
    real_oauth_inputs_processed: bool
    runtime_pkce_checked: bool
    token_validated: bool
    real_api_call_checked: bool
    activation_ready: bool
    receipt_self_authenticating: bool
    registry_snapshot_atomicity_checked: bool
    registry_freshness_guaranteed: bool
    registry_signature_checked: bool
    registry_provenance_attestation_checked: bool
    node_binary_publisher_provenance_checked: bool
    malicious_code_isolation_guaranteed: bool
    node_process_memory_bound_checked: bool
    node_process_output_generation_bound_checked: bool
    read_operation_side_effects_checked: bool
    injected_transport_side_effects_checked: bool

    def __post_init__(self) -> None:
        if (
            any(
                type(getattr(self, name)) is not str or not getattr(self, name)
                for name in _STRING_FIELDS
            )
            or self.receipt_type != RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or self.source != SOURCE
            or self.validation_scope != SCOPE
            or self.execution_profile != PROFILE
            or self.proof_status != STATUS
            or self.node_version != NODE_VERSION
            or self.browser_package_name != BROWSER_PACKAGE_NAME
            or self.browser_version != BROWSER_VERSION
            or self.common_package_name != COMMON_PACKAGE_NAME
            or self.common_version != COMMON_VERSION
            or self.registry_origin != NPM_REGISTRY_ORIGIN
            or self.compiled_scope_finding
            != "sendPostRequestAsync_retries_non_abort_transport_failure_for_any_post_url"
            or self.browser_tarball_sha256 != BROWSER_TARBALL_SHA256
            or self.browser_package_json_sha256 != BROWSER_PACKAGE_JSON_SHA256
            or self.common_tarball_sha256 != COMMON_TARBALL_SHA256
            or self.common_package_json_sha256 != COMMON_PACKAGE_JSON_SHA256
            or self.compiled_retry_entry_sha256 != COMPILED_RETRY_ENTRY_SHA256
            or self.harness_sha256 != HARNESS_SHA256
            or self.runner_sha256 != RUNNER_SHA256
            or any(
                not _is_sha256(getattr(self, name))
                for name in self.__dataclass_fields__
                if name.endswith("_sha256")
            )
            or any(type(getattr(self, name)) is not int for name in _COUNT_FIELDS)
            or self.artifact_count != 2
            or self.request_plan_count != 4
            or self.harness_scenario_count != 10
            or self.observed_fake_fetch_call_count != OBSERVED_FAKE_FETCH_CALL_COUNT
            or self.observed_non_token_post_attempts != OBSERVED_NON_TOKEN_POST_ATTEMPTS
            or self.browser_tarball_bytes != BROWSER_TARBALL_BYTES
            or self.browser_archive_member_count != BROWSER_ARCHIVE_MEMBER_COUNT
            or self.browser_archive_uncompressed_bytes
            != BROWSER_ARCHIVE_UNCOMPRESSED_BYTES
            or self.common_tarball_bytes != COMMON_TARBALL_BYTES
            or self.common_archive_member_count != COMMON_ARCHIVE_MEMBER_COUNT
            or self.common_archive_uncompressed_bytes
            != COMMON_ARCHIVE_UNCOMPRESSED_BYTES
            or self.compiled_retry_entry_bytes != COMPILED_RETRY_ENTRY_BYTES
            or self.harness_bytes != HARNESS_BYTES
            or self.runner_bytes != RUNNER_BYTES
            or any(getattr(self, name) is not True for name in _TRUE_FIELDS)
            or any(getattr(self, name) is not False for name in _FALSE_FIELDS)
            or any(type(getattr(self, name)) is not bool for name in _DYNAMIC_FIELDS)
            or self.synthetic_evidence_used == self.live_proof_complete
            or self.sealed_registry_request_count
            != (0 if self.synthetic_evidence_used else 4)
            or self.sealed_node_process_count
            != (0 if self.synthetic_evidence_used else 1)
            or any(
                getattr(self, name) is not self.live_proof_complete
                for name in _LIVE_FIELDS
            )
        ):
            raise ValueError("compiled retry execution proof receipt is invalid")


_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "execution_profile",
    "proof_status",
    "node_version",
    "browser_package_name",
    "browser_version",
    "common_package_name",
    "common_version",
    "registry_origin",
    "compiled_scope_finding",
)
_COUNT_FIELDS = (
    "artifact_count",
    "request_plan_count",
    "harness_scenario_count",
    "observed_fake_fetch_call_count",
    "observed_non_token_post_attempts",
    "sealed_registry_request_count",
    "sealed_node_process_count",
    "browser_tarball_bytes",
    "browser_archive_member_count",
    "browser_archive_uncompressed_bytes",
    "common_tarball_bytes",
    "common_archive_member_count",
    "common_archive_uncompressed_bytes",
    "compiled_retry_entry_bytes",
    "harness_bytes",
    "runner_bytes",
)
_TRUE_FIELDS = (
    "step222_source_chain_revalidated",
    "approved_step222_document_digest_bound",
    "exact_step222_fail_closed_state_validated",
    "exact_harness_bytes_bound",
    "exact_runner_bytes_bound",
    "exact_dual_artifact_identity_required",
    "exact_four_request_plan_prevalidated",
    "unauthenticated_get_only_required",
    "request_body_forbidden",
    "proxy_redirect_retry_compression_forbidden",
    "archive_paths_and_types_fail_closed",
    "browser_common_dependency_edge_required",
    "compiled_retry_entry_identity_required",
    "one_ephemeral_workspace_required",
    "one_sealed_node_process_required",
    "node_permission_model_required",
    "network_child_worker_write_addon_wasi_permissions_forbidden",
    "inspector_and_ffi_permissions_forbidden",
    "lifecycle_scripts_forbidden",
    "fake_fetch_and_synthetic_oauth_values_required",
    "exact_ten_scenario_matrix_required",
    "non_token_two_attempt_conflict_declared",
    "step216_zero_retry_requirement_preserved",
    "conditional_exception_remains_unapproved",
    "proof_contract_validated",
)
_LIVE_FIELDS = (
    "live_registry_source_attested",
    "live_browser_artifact_verified",
    "live_common_artifact_verified",
    "live_archive_closure_checked",
    "live_dependency_edge_checked",
    "live_compiled_entry_checked",
    "live_ephemeral_extraction_performed",
    "live_node_executable_hash_checked",
    "live_node_version_checked",
    "live_node_permission_profile_checked",
    "live_harness_process_executed",
    "live_retry_trigger_checked",
    "live_retry_count_checked",
    "live_retry_backoff_checked",
    "live_response_exclusions_checked",
    "live_abort_exclusion_checked",
    "live_non_token_scope_checked",
    "live_concurrency_checked",
    "live_telemetry_checked",
    "live_request_equivalence_checked",
    "live_non_token_two_attempt_conflict_observed",
    "live_proof_complete",
    "sealed_registry_io_performed",
    "sealed_ephemeral_filesystem_io_performed",
    "sealed_node_process_io_performed",
)
_DYNAMIC_FIELDS = ("synthetic_evidence_used", *_LIVE_FIELDS)
_FALSE_FIELDS = (
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "candidate_compatible",
    "candidate_selected",
    "dependency_lockfile_created",
    "package_installed",
    "browser_oauth_provider_io_performed",
    "real_oauth_inputs_processed",
    "runtime_pkce_checked",
    "token_validated",
    "real_api_call_checked",
    "activation_ready",
    "receipt_self_authenticating",
    "registry_snapshot_atomicity_checked",
    "registry_freshness_guaranteed",
    "registry_signature_checked",
    "registry_provenance_attestation_checked",
    "node_binary_publisher_provenance_checked",
    "malicious_code_isolation_guaranteed",
    "node_process_memory_bound_checked",
    "node_process_output_generation_bound_checked",
    "read_operation_side_effects_checked",
    "injected_transport_side_effects_checked",
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
    ).encode()


def _framed(label: str, value: object) -> str:
    digest = hashlib.sha256()
    for part in ("engineer4me-step223-v1", label, _canonical(value)):
        encoded = part if isinstance(part, bytes) else part.encode()
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


def _json_depth(value: object, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON depth exceeded")
    if type(value) is dict:
        return max(
            (_json_depth(item, depth + 1) for item in value.values()), default=depth
        )
    if type(value) is list:
        return max((_json_depth(item, depth + 1) for item in value), default=depth)
    if type(value) not in (str, int, float, bool, type(None)):
        raise ValueError("JSON value type is invalid")
    if type(value) is float and not isfinite(value):
        raise ValueError("non-finite JSON value")
    return depth


def _parse_json(raw: bytes, limit: int) -> object:
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise ValueError("bounded JSON bytes are required")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )
    _json_depth(value)
    return value


def _parse_document(
    raw: bytes,
) -> tuple[bytes, EntraCallingClientMSALCompiledRetryExecutionDocument]:
    if type(raw) is not bytes:
        raise _ArgumentTypeError("exact execution proof document bytes are required")
    if not 1 <= len(raw) <= MAX_DOCUMENT_BYTES:
        raise ValueError("bounded execution proof document bytes are required")
    parsed = _parse_json(raw, MAX_DOCUMENT_BYTES)
    keys = {
        "document_type",
        "schema_version",
        "source",
        "approved_harness_readiness_document_sha256",
        "expected_node_version",
        "approved_node_executable_sha256",
        "execution_profile",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != keys
        or type(parsed["schema_version"]) is not int
        or any(type(parsed[key]) is not str for key in keys - {"schema_version"})
    ):
        raise ValueError("compiled retry execution proof document is invalid")
    canonical = _canonical(parsed)
    return (
        canonical,
        EntraCallingClientMSALCompiledRetryExecutionDocument.model_validate_json(
            canonical
        ),
    )


def _metadata_projection(
    raw: bytes, package: str, version: str, tarball: str
) -> dict[str, str]:
    value = _parse_json(raw, MAX_JSON_BYTES)
    if type(value) is not dict or type(value.get("dist")) is not dict:
        raise ValueError("npm metadata root is invalid")
    dist = value["dist"]
    projection = {
        "name": value.get("name"),
        "version": value.get("version"),
        "tarball": dist.get("tarball"),
        "integrity": dist.get("integrity"),
        "shasum": dist.get("shasum"),
    }
    expected = {
        "name": package,
        "version": version,
        "tarball": tarball,
        "integrity": BROWSER_SRI if package == BROWSER_PACKAGE_NAME else COMMON_SRI,
        "shasum": BROWSER_SHASUM if package == BROWSER_PACKAGE_NAME else COMMON_SHASUM,
    }
    if (
        any(type(item) is not str for item in projection.values())
        or projection != expected
    ):
        raise ValueError("npm metadata projection changed")
    return projection


def _verify_tarball(
    *,
    raw: bytes,
    package: str,
    version: str,
    expected_sha256: str,
    expected_bytes: int,
    expected_sri: str,
    expected_shasum: str,
    expected_members: int,
    expected_uncompressed: int,
    expected_package_json_sha256: str,
) -> tuple[dict[str, tarfile.TarInfo], bytes, bytes | None]:
    if type(raw) is not bytes or len(raw) != expected_bytes:
        raise ValueError("npm tarball byte count changed")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("npm tarball SHA-256 changed")
    sha512 = base64.b64encode(hashlib.sha512(raw).digest()).decode()
    if f"sha512-{sha512}" != expected_sri:
        raise ValueError("npm tarball SRI changed")
    if hashlib.sha1(raw).hexdigest() != expected_shasum:
        raise ValueError("npm legacy shasum changed")
    members: dict[str, tarfile.TarInfo] = {}
    casefolded: set[str] = set()
    package_json = None
    compiled_entry = None
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        infos = archive.getmembers()
        if len(infos) != expected_members or len(infos) > MAX_TAR_MEMBERS:
            raise ValueError("npm archive member count changed")
        for info in infos:
            name = info.name
            path = PurePosixPath(name)
            if (
                type(name) is not str
                or _SAFE_MEMBER.fullmatch(name) is None
                or path.is_absolute()
                or ".." in path.parts
                or name in members
                or name.casefold() in casefolded
                or not (info.isdir() or info.isreg())
                or info.size < 0
                or info.size > MAX_TAR_FILE_BYTES
            ):
                raise ValueError("npm archive member is unsafe")
            members[name] = info
            casefolded.add(name.casefold())
            if info.isreg():
                total += info.size
                if total > MAX_TAR_UNCOMPRESSED_BYTES:
                    raise ValueError("npm archive uncompressed bound exceeded")
                if name in {"package/package.json", COMPILED_RETRY_ENTRY_PATH}:
                    stream = archive.extractfile(info)
                    if stream is None:
                        raise ValueError("npm archive file cannot be read")
                    content = stream.read(info.size + 1)
                    if len(content) != info.size:
                        raise ValueError("npm archive file length changed")
                    if name == "package/package.json":
                        package_json = content
                    else:
                        compiled_entry = content
    if total != expected_uncompressed or package_json is None:
        raise ValueError("npm archive closure changed")
    if hashlib.sha256(package_json).hexdigest() != expected_package_json_sha256:
        raise ValueError("npm package manifest changed")
    manifest = _parse_json(package_json, MAX_JSON_BYTES)
    if (
        type(manifest) is not dict
        or manifest.get("name") != package
        or manifest.get("version") != version
        or manifest.get("license") != "MIT"
    ):
        raise ValueError("npm package identity changed")
    scripts = manifest.get("scripts", {})
    if type(scripts) is not dict or any(
        name in scripts for name in ("preinstall", "install", "postinstall")
    ):
        raise ValueError("npm lifecycle script boundary changed")
    if package == BROWSER_PACKAGE_NAME:
        dependencies = manifest.get("dependencies")
        if (
            type(dependencies) is not dict
            or dependencies.get(COMMON_PACKAGE_NAME) != COMMON_VERSION
        ):
            raise ValueError("browser/common dependency edge changed")
        if (
            compiled_entry is None
            or len(compiled_entry) != COMPILED_RETRY_ENTRY_BYTES
            or hashlib.sha256(compiled_entry).hexdigest() != COMPILED_RETRY_ENTRY_SHA256
        ):
            raise ValueError("compiled retry entry changed")
    elif compiled_entry is not None:
        raise ValueError("unexpected compiled entry projection")
    return members, package_json, compiled_entry


def _artifact_evidence(
    browser_metadata: bytes,
    common_metadata: bytes,
) -> EntraCallingClientMSALCompiledRetryArtifactEvidence:
    return EntraCallingClientMSALCompiledRetryArtifactEvidence(
        browser_tarball_sha256=BROWSER_TARBALL_SHA256,
        browser_tarball_bytes=BROWSER_TARBALL_BYTES,
        browser_archive_member_count=BROWSER_ARCHIVE_MEMBER_COUNT,
        browser_archive_uncompressed_bytes=BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
        browser_package_json_sha256=BROWSER_PACKAGE_JSON_SHA256,
        common_tarball_sha256=COMMON_TARBALL_SHA256,
        common_tarball_bytes=COMMON_TARBALL_BYTES,
        common_archive_member_count=COMMON_ARCHIVE_MEMBER_COUNT,
        common_archive_uncompressed_bytes=COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
        common_package_json_sha256=COMMON_PACKAGE_JSON_SHA256,
        compiled_retry_entry_sha256=COMPILED_RETRY_ENTRY_SHA256,
        compiled_retry_entry_bytes=COMPILED_RETRY_ENTRY_BYTES,
        browser_metadata_response_sha256=hashlib.sha256(browser_metadata).hexdigest(),
        common_metadata_response_sha256=hashlib.sha256(common_metadata).hexdigest(),
    )


def _verify_live_responses(
    responses: object,
) -> _VerifiedLiveArtifacts:
    if type(responses) is not tuple or len(responses) != 4:
        raise ValueError("exact four live responses are required")
    if any(
        type(response) is not EntraCallingClientMSALCompiledRetryLiveHTTPResponse
        for response in responses
    ):
        raise ValueError("exact live response objects are required")
    if not all(response.live_https_attested for response in responses):
        raise ValueError("sealed live responses are required")
    browser_metadata, browser_tarball, common_metadata, common_tarball = (
        response.body for response in responses
    )
    _metadata_projection(
        browser_metadata,
        BROWSER_PACKAGE_NAME,
        BROWSER_VERSION,
        BROWSER_TARBALL_URL,
    )
    _metadata_projection(
        common_metadata,
        COMMON_PACKAGE_NAME,
        COMMON_VERSION,
        COMMON_TARBALL_URL,
    )
    _verify_tarball(
        raw=browser_tarball,
        package=BROWSER_PACKAGE_NAME,
        version=BROWSER_VERSION,
        expected_sha256=BROWSER_TARBALL_SHA256,
        expected_bytes=BROWSER_TARBALL_BYTES,
        expected_sri=BROWSER_SRI,
        expected_shasum=BROWSER_SHASUM,
        expected_members=BROWSER_ARCHIVE_MEMBER_COUNT,
        expected_uncompressed=BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
        expected_package_json_sha256=BROWSER_PACKAGE_JSON_SHA256,
    )
    _verify_tarball(
        raw=common_tarball,
        package=COMMON_PACKAGE_NAME,
        version=COMMON_VERSION,
        expected_sha256=COMMON_TARBALL_SHA256,
        expected_bytes=COMMON_TARBALL_BYTES,
        expected_sri=COMMON_SRI,
        expected_shasum=COMMON_SHASUM,
        expected_members=COMMON_ARCHIVE_MEMBER_COUNT,
        expected_uncompressed=COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
        expected_package_json_sha256=COMMON_PACKAGE_JSON_SHA256,
    )
    return _VerifiedLiveArtifacts(
        evidence=_artifact_evidence(browser_metadata, common_metadata),
        browser_tarball=browser_tarball,
        common_tarball=common_tarball,
    )


def _extract_validated_tarball(raw: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for info in archive.getmembers():
            relative = PurePosixPath(info.name).relative_to("package")
            target = destination.joinpath(*relative.parts)
            if info.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(info)
            if stream is None:
                raise ValueError("validated archive file cannot be read")
            content = stream.read(info.size + 1)
            if len(content) != info.size:
                raise ValueError("validated archive file changed")
            target.write_bytes(content)


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _validate_node_executable(
    node_executable_path: object,
    approved_node_executable_sha256: str,
) -> str:
    if type(node_executable_path) is not str:
        raise _ArgumentTypeError("canonical absolute Node executable path is required")
    if not node_executable_path or not os.path.isabs(node_executable_path):
        raise ValueError("canonical absolute Node executable path is required")
    try:
        metadata = os.lstat(node_executable_path)
    except (OSError, ValueError):
        raise ValueError("Node executable is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError("Node executable is not a canonical executable regular file")
    canonical = os.path.realpath(node_executable_path)
    if os.path.normcase(canonical) != os.path.normcase(node_executable_path):
        raise ValueError("canonical absolute Node executable path is required")
    node = Path(node_executable_path)
    if os.name == "nt":
        if node.suffix.lower() != ".exe":
            raise ValueError(
                "Node executable is not a canonical executable regular file"
            )
    elif not os.access(node, os.X_OK):
        raise ValueError("Node executable is not a canonical executable regular file")
    size = metadata.st_size
    if type(size) is not int or not 1 <= size <= MAX_NODE_EXECUTABLE_BYTES:
        raise ValueError("Node executable size is invalid")
    digest = hashlib.sha256()
    total = 0
    with node.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            total += len(chunk)
            if total > MAX_NODE_EXECUTABLE_BYTES:
                raise ValueError("Node executable size exceeded")
            digest.update(chunk)
    if total != size or digest.hexdigest() != approved_node_executable_sha256:
        raise ValueError("Node executable digest changed")
    return node_executable_path


def _sealed_execute(
    *,
    artifacts: _VerifiedLiveArtifacts,
    harness: bytes,
    runner: bytes,
    node_executable_path: str,
    approved_node_executable_sha256: str,
) -> EntraCallingClientMSALCompiledRetryExecutionEvidence:
    node_executable_path = _validate_node_executable(
        node_executable_path,
        approved_node_executable_sha256,
    )
    with tempfile.TemporaryDirectory(prefix="e4m-step223-") as temporary:
        workspace = Path(temporary)
        home = workspace / "home"
        home.mkdir()
        browser = workspace / "node_modules" / "@azure" / "msal-browser"
        common = workspace / "node_modules" / "@azure" / "msal-common"
        browser.mkdir(parents=True)
        common.mkdir(parents=True)
        _extract_validated_tarball(artifacts.browser_tarball, browser)
        _extract_validated_tarball(artifacts.common_tarball, common)
        harness_path = workspace / "harness.mjs"
        runner_path = workspace / "runner.mjs"
        harness_path.write_bytes(harness)
        runner_path.write_bytes(runner)
        entry_path = browser / "dist" / "network" / "FetchClient.mjs"
        if (
            not entry_path.is_file()
            or hashlib.sha256(entry_path.read_bytes()).hexdigest()
            != COMPILED_RETRY_ENTRY_SHA256
        ):
            raise ValueError("extracted compiled retry entry changed")
        environment = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TMP": str(workspace),
            "TEMP": str(workspace),
            "NO_COLOR": "1",
        }
        if os.name == "nt":
            system_root = os.environ.get("SystemRoot")
            if type(system_root) is not str or not os.path.isabs(system_root):
                raise ValueError("Windows system root is unavailable")
            environment["SystemRoot"] = system_root
        command = [
            node_executable_path,
            "--permission",
            f"--allow-fs-read={workspace}",
            str(runner_path),
            str(harness_path),
            str(entry_path),
            HARNESS_SHA256,
        ]
        completed = subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=NODE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
        evidence = EntraCallingClientMSALCompiledRetryExecutionEvidence(
            node_version=NODE_VERSION,
            node_executable_sha256=approved_node_executable_sha256,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )
    return evidence


def _scenario_projection(
    stdout: bytes, approved_node_sha256: str
) -> tuple[dict[str, object], str]:
    if type(stdout) is not bytes or not 1 <= len(stdout) <= MAX_STDOUT_BYTES:
        raise ValueError("bounded harness stdout is required")
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("harness stdout is not UTF-8") from error
    lines = text.splitlines()
    if len(lines) != 2 or not all(lines):
        raise ValueError("harness stdout must contain exactly two JSON records")
    runner_record = _parse_json(lines[0].encode(), MAX_STDOUT_BYTES)
    harness_record = _parse_json(lines[1].encode(), MAX_STDOUT_BYTES)
    permissions = {
        "network": False,
        "childProcess": False,
        "worker": False,
        "fileSystemWrite": False,
        "addons": False,
        "wasi": False,
        "inspector": False,
        "ffi": False,
    }
    if runner_record != {
        "runnerSchemaVersion": 1,
        "nodeVersion": NODE_VERSION,
        "harnessSha256": HARNESS_SHA256,
        "permissions": permissions,
    }:
        raise ValueError("sealed runner record changed")
    if (
        type(harness_record) is not dict
        or set(harness_record) != {"schemaVersion", "scenarioCount", "scenarios"}
        or harness_record["schemaVersion"] != 1
        or type(harness_record["scenarioCount"]) is not int
        or harness_record["scenarioCount"] != BEHAVIOR_SCENARIO_COUNT
        or type(harness_record["scenarios"]) is not list
        or len(harness_record["scenarios"]) != BEHAVIOR_SCENARIO_COUNT
    ):
        raise ValueError("harness record schema changed")
    by_name: dict[str, dict[str, object]] = {}
    for scenario in harness_record["scenarios"]:
        if type(scenario) is not dict or type(scenario.get("name")) is not str:
            raise ValueError("harness scenario schema changed")
        name = scenario["name"]
        if name in by_name:
            raise ValueError("duplicate harness scenario")
        by_name[name] = scenario
    expected_names = {
        "transport_failure_then_success",
        "two_transport_failures",
        "http_400_no_retry",
        "http_429_no_retry",
        "http_500_no_retry",
        "oauth_error_no_retry",
        "abort_no_retry",
        "non_token_transport_failure",
        "concurrent_isolation",
        "telemetry_and_request_equivalence",
    }
    if set(by_name) != expected_names:
        raise ValueError("harness scenario inventory changed")
    retry_names = {
        "transport_failure_then_success",
        "two_transport_failures",
        "non_token_transport_failure",
    }
    no_retry_names = {
        "http_400_no_retry",
        "http_429_no_retry",
        "http_500_no_retry",
        "oauth_error_no_retry",
        "abort_no_retry",
    }
    standard_keys = {
        "name",
        "attemptCount",
        "elapsedBetweenAttemptsMilliseconds",
        "requestEquivalent",
        "status",
        "errorName",
        "telemetry",
    }
    expected_telemetry = [
        {
            "value": {"fetchRetryCount": 1},
            "correlationId": "00000000-0000-4000-8000-000000000222",
        }
    ]
    for name in retry_names:
        scenario = by_name[name]
        elapsed = scenario.get("elapsedBetweenAttemptsMilliseconds")
        if (
            set(scenario) != standard_keys
            or type(scenario.get("attemptCount")) is not int
            or scenario["attemptCount"] != 2
            or type(elapsed) is not int
            or not 90 <= elapsed <= 10_000
            or scenario.get("requestEquivalent") is not True
            or scenario.get("telemetry") != expected_telemetry
        ):
            raise ValueError("retry scenario changed")
    for name in no_retry_names:
        scenario = by_name[name]
        if (
            set(scenario) != standard_keys
            or type(scenario.get("attemptCount")) is not int
            or scenario["attemptCount"] != 1
            or scenario.get("elapsedBetweenAttemptsMilliseconds") is not None
            or scenario.get("requestEquivalent") is not True
            or scenario.get("telemetry") != []
        ):
            raise ValueError("no-retry scenario changed")
    expected_statuses = {
        "transport_failure_then_success": 200,
        "http_400_no_retry": 400,
        "http_429_no_retry": 429,
        "http_500_no_retry": 500,
        "oauth_error_no_retry": 400,
        "non_token_transport_failure": 200,
    }
    for name, status in expected_statuses.items():
        if (
            type(by_name[name].get("status")) is not int
            or by_name[name]["status"] != status
        ):
            raise ValueError("harness HTTP status changed")
    expected_errors = {
        "transport_failure_then_success": None,
        "two_transport_failures": "NetworkError",
        "http_400_no_retry": None,
        "http_429_no_retry": None,
        "http_500_no_retry": None,
        "oauth_error_no_retry": None,
        "abort_no_retry": "NetworkError",
        "non_token_transport_failure": None,
    }
    if any(
        by_name[name].get("errorName") != error
        for name, error in expected_errors.items()
    ):
        raise ValueError("harness error result changed")
    if (
        by_name["two_transport_failures"].get("status") is not None
        or by_name["abort_no_retry"].get("status") is not None
    ):
        raise ValueError("harness transport failure status changed")
    concurrent = by_name["concurrent_isolation"]
    if (
        set(concurrent)
        != {
            "name",
            "attemptCount",
            "perRequestAttempts",
            "elapsedMilliseconds",
            "statuses",
        }
        or type(concurrent.get("attemptCount")) is not int
        or concurrent["attemptCount"] != 4
        or concurrent.get("perRequestAttempts") != [2, 2]
        or concurrent.get("statuses") != [200, 200]
        or type(concurrent.get("elapsedMilliseconds")) is not int
        or not 90 <= concurrent["elapsedMilliseconds"] <= 10_000
    ):
        raise ValueError("harness concurrency scenario changed")
    telemetry = by_name["telemetry_and_request_equivalence"]
    if (
        set(telemetry) != {"name", "attemptCount", "requestEquivalent", "telemetry"}
        or type(telemetry.get("attemptCount")) is not int
        or telemetry["attemptCount"] != 2
        or telemetry.get("requestEquivalent") is not True
        or telemetry.get("telemetry") != expected_telemetry
    ):
        raise ValueError("harness telemetry scenario changed")
    projection = {
        "nodeVersion": NODE_VERSION,
        "nodeExecutableSha256": approved_node_sha256,
        "permissions": permissions,
        "scenarioNames": sorted(expected_names),
        "fakeFetchCalls": OBSERVED_FAKE_FETCH_CALL_COUNT,
        "nonTokenPostAttempts": OBSERVED_NON_TOKEN_POST_ATTEMPTS,
        "retryBackoffRangeMilliseconds": [90, 10_000],
        "selectionApproved": False,
    }
    return projection, hashlib.sha256(stdout).hexdigest()


def _artifact_projection(
    evidence: EntraCallingClientMSALCompiledRetryArtifactEvidence,
) -> dict[str, object]:
    evidence.__post_init__()
    return {name: getattr(evidence, name) for name in evidence.__dataclass_fields__}


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
        interrupted |= isinstance(current, KeyboardInterrupt)
        terminated |= isinstance(current, SystemExit)
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
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
        except BaseException:  # noqa: BLE001,S110
            pass
    return interrupted, terminated


def _load_internal(
    *,
    document: bytes,
    harness: bytes,
    runner: bytes,
    node_executable_path: str | None = None,
    artifact_transport: EntraCallingClientMSALCompiledRetryArtifactTransport
    | None = None,
    execution_transport: EntraCallingClientMSALCompiledRetryExecutionTransport
    | None = None,
    **step222_arguments: object,
) -> EntraCallingClientMSALCompiledRetryExecutionProofReceipt:
    if (
        type(document) is not bytes
        or type(harness) is not bytes
        or type(runner) is not bytes
    ):
        raise _ArgumentTypeError(
            "exact document, harness, and runner bytes are required"
        )
    injected = artifact_transport is not None or execution_transport is not None
    if injected != (artifact_transport is not None and execution_transport is not None):
        raise _ArgumentTypeError(
            "artifact and execution transports must be supplied together"
        )
    if injected and node_executable_path is not None:
        raise _ArgumentTypeError("synthetic execution cannot accept a Node path")
    if not injected and type(node_executable_path) is not str:
        raise _ArgumentTypeError("sealed execution requires a Node path")
    if artifact_transport is not None and not isinstance(artifact_transport, Callable):
        raise _ArgumentTypeError("artifact transport must be callable")
    if execution_transport is not None and not isinstance(
        execution_transport, Callable
    ):
        raise _ArgumentTypeError("execution transport must be callable")
    prior_document = step222_arguments.pop("harness_readiness_document", None)
    approved = step222_arguments.pop("approved_harness_readiness_document_sha256", None)
    if type(prior_document) is not bytes or not _is_sha256(approved):
        raise _ArgumentTypeError("exact Step 222 evidence is required")
    prior = load_entra_calling_client_msal_compiled_retry_harness_readiness(
        document=prior_document,
        harness=harness,
        **step222_arguments,
    )
    if type(prior) is not EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt:
        raise ValueError("exact Step 222 receipt is required")
    prior_rendered = (
        render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt(prior)
    )
    if (
        prior.readiness_status != STEP222_STATUS
        or prior.harness_readiness_document_sha256 != approved
        or prior.conditional_exception_approved
        or prior.step216_zero_retry_superseded
        or prior.candidate_compatible
        or prior.candidate_selected
        or prior.harness_executed_by_contract
        or prior.activation_ready
    ):
        raise ValueError("Step 222 state is not the exact fail-closed baseline")
    canonical_document, validated = _parse_document(document)
    if (
        validated.approved_harness_readiness_document_sha256 != approved
        or len(harness) != HARNESS_BYTES
        or hashlib.sha256(harness).hexdigest() != HARNESS_SHA256
        or len(runner) != RUNNER_BYTES
        or hashlib.sha256(runner).hexdigest() != RUNNER_SHA256
    ):
        raise ValueError("Step 222, harness, or runner evidence changed")
    if not injected:
        node_executable_path = _validate_node_executable(
            node_executable_path,
            validated.approved_node_executable_sha256,
        )
    plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
    live_artifacts = None
    if injected:
        artifact_evidence = artifact_transport()
        if (
            type(artifact_evidence)
            is not EntraCallingClientMSALCompiledRetryArtifactEvidence
        ):
            raise ValueError("exact synthetic artifact evidence is required")
        artifact_evidence.__post_init__()
        execution_evidence = execution_transport(artifact_evidence, harness, runner)
    else:
        responses = BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader().load(
            plan
        )
        live_artifacts = _verify_live_responses(responses)
        artifact_evidence = live_artifacts.evidence
        execution_evidence = _sealed_execute(
            artifacts=live_artifacts,
            harness=harness,
            runner=runner,
            node_executable_path=node_executable_path,
            approved_node_executable_sha256=validated.approved_node_executable_sha256,
        )
    if (
        type(execution_evidence)
        is not EntraCallingClientMSALCompiledRetryExecutionEvidence
    ):
        raise ValueError("exact execution evidence is required")
    execution_evidence.__post_init__()
    if (
        execution_evidence.node_executable_sha256
        != validated.approved_node_executable_sha256
    ):
        raise ValueError("approved Node executable evidence mismatch")
    scenario_projection, stdout_sha256 = _scenario_projection(
        execution_evidence.stdout,
        validated.approved_node_executable_sha256,
    )
    artifact_projection = _artifact_projection(artifact_evidence)
    permission_profile = {
        "permissionFlag": True,
        "fileSystemRead": "ephemeral_workspace_only",
        "network": False,
        "childProcess": False,
        "worker": False,
        "fileSystemWrite": False,
        "addons": False,
        "wasi": False,
        "inspector": False,
        "ffi": False,
        "realOAuthInputs": False,
    }
    selection = {
        "step216ZeroRetrySuperseded": False,
        "exceptionApproved": False,
        "compatible": False,
        "selected": False,
    }
    request_projection = [
        {
            "sequence": request.sequence,
            "resource": request.resource,
            "method": request.method,
            "url": request.url,
            "accept": request.accept,
            "acceptEncoding": request.accept_encoding,
            "connection": request.connection,
            "userAgent": request.user_agent,
            "authorization": None,
            "body": None,
        }
        for request in plan
    ]
    live = not injected
    receipt = EntraCallingClientMSALCompiledRetryExecutionProofReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        execution_profile=PROFILE,
        proof_status=STATUS,
        node_version=NODE_VERSION,
        browser_package_name=BROWSER_PACKAGE_NAME,
        browser_version=BROWSER_VERSION,
        common_package_name=COMMON_PACKAGE_NAME,
        common_version=COMMON_VERSION,
        registry_origin=NPM_REGISTRY_ORIGIN,
        compiled_scope_finding="sendPostRequestAsync_retries_non_abort_transport_failure_for_any_post_url",
        configuration_sha256=prior.configuration_sha256,
        api_registration_document_sha256=prior.api_registration_document_sha256,
        calling_client_registration_document_sha256=prior.calling_client_registration_document_sha256,
        inventory_document_sha256=prior.inventory_document_sha256,
        harness_readiness_document_sha256=prior.harness_readiness_document_sha256,
        harness_readiness_receipt_sha256=hashlib.sha256(
            prior_rendered.encode()
        ).hexdigest(),
        execution_proof_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        browser_tarball_sha256=BROWSER_TARBALL_SHA256,
        browser_package_json_sha256=BROWSER_PACKAGE_JSON_SHA256,
        common_tarball_sha256=COMMON_TARBALL_SHA256,
        common_package_json_sha256=COMMON_PACKAGE_JSON_SHA256,
        compiled_retry_entry_sha256=COMPILED_RETRY_ENTRY_SHA256,
        harness_sha256=HARNESS_SHA256,
        runner_sha256=RUNNER_SHA256,
        node_executable_sha256=validated.approved_node_executable_sha256,
        browser_metadata_response_sha256=artifact_evidence.browser_metadata_response_sha256,
        common_metadata_response_sha256=artifact_evidence.common_metadata_response_sha256,
        request_plan_sha256=_framed("request_plan", request_projection),
        artifact_evidence_sha256=_framed("artifacts", artifact_projection),
        harness_stdout_sha256=stdout_sha256,
        harness_scenario_projection_sha256=_framed("scenarios", scenario_projection),
        permission_profile_sha256=_framed("permissions", permission_profile),
        fail_closed_selection_state_sha256=_framed("selection", selection),
        artifact_count=2,
        request_plan_count=4,
        harness_scenario_count=HARNESS_SCENARIO_COUNT,
        observed_fake_fetch_call_count=OBSERVED_FAKE_FETCH_CALL_COUNT,
        observed_non_token_post_attempts=OBSERVED_NON_TOKEN_POST_ATTEMPTS,
        sealed_registry_request_count=4 if live else 0,
        sealed_node_process_count=1 if live else 0,
        browser_tarball_bytes=BROWSER_TARBALL_BYTES,
        browser_archive_member_count=BROWSER_ARCHIVE_MEMBER_COUNT,
        browser_archive_uncompressed_bytes=BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
        common_tarball_bytes=COMMON_TARBALL_BYTES,
        common_archive_member_count=COMMON_ARCHIVE_MEMBER_COUNT,
        common_archive_uncompressed_bytes=COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
        compiled_retry_entry_bytes=COMPILED_RETRY_ENTRY_BYTES,
        harness_bytes=HARNESS_BYTES,
        runner_bytes=RUNNER_BYTES,
        **{name: True for name in _TRUE_FIELDS},
        synthetic_evidence_used=injected,
        **{name: live for name in _LIVE_FIELDS},
        **{name: False for name in _FALSE_FIELDS},
    )
    if live_artifacts is not None:
        live_artifacts.browser_tarball = b""
        live_artifacts.common_tarball = b""
    return receipt


def load_entra_calling_client_msal_compiled_retry_execution_proof(
    **arguments: object,
) -> EntraCallingClientMSALCompiledRetryExecutionProofReceipt:
    """Return one sanitized Step 223 proof receipt."""

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
        raise KeyboardInterrupt("compiled retry execution proof interrupted")
    if terminated:
        raise SystemExit("compiled retry execution proof terminated")
    if invalid:
        raise TypeError("compiled retry execution proof inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALCompiledRetryExecutionProbeError(
            "compiled retry execution proof failed"
        )
    return result


def render_entra_calling_client_msal_compiled_retry_execution_proof_receipt(
    receipt: EntraCallingClientMSALCompiledRetryExecutionProofReceipt,
) -> str:
    """Render canonical Step 223 evidence."""

    if type(receipt) is not EntraCallingClientMSALCompiledRetryExecutionProofReceipt:
        raise TypeError("exact compiled retry execution proof receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "DOCUMENT_TYPE",
    "NODE_VERSION",
    "PROFILE",
    "RECEIPT_TYPE",
    "RUNNER_BYTES",
    "RUNNER_FILE_NAME",
    "RUNNER_SHA256",
    "SOURCE",
    "STATUS",
    "EntraCallingClientMSALCompiledRetryArtifactEvidence",
    "EntraCallingClientMSALCompiledRetryArtifactTransport",
    "EntraCallingClientMSALCompiledRetryExecutionDocument",
    "EntraCallingClientMSALCompiledRetryExecutionEvidence",
    "EntraCallingClientMSALCompiledRetryExecutionProbeError",
    "EntraCallingClientMSALCompiledRetryExecutionProofReceipt",
    "EntraCallingClientMSALCompiledRetryExecutionTransport",
    "load_entra_calling_client_msal_compiled_retry_execution_proof",
    "render_entra_calling_client_msal_compiled_retry_execution_proof_receipt",
]
