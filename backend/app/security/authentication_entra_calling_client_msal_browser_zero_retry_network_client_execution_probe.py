"""Controlled local Node execution proof for the exact zero-retry adapter."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from builtins import BaseExceptionGroup
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    ADAPTER_BYTES,
    ADAPTER_PATH,
    ADAPTER_SHA256,
    EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt,
    load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness,
    render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_execution_proof"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_local_permission_restricted_zero_retry_execution"
SCOPE = "exact_adapter_permission_restricted_node_fake_fetch_execution"
PROFILE = "engineer4me_msal_browser_zero_retry_network_client_execution_v1"
STATUS = "execution_projection_validated_sealed_attestation_correlated_separately"
NODE_VERSION = "v24.19.0"
HARNESS_FILE_NAME = (
    "authentication_entra_calling_client_msal_browser_"
    "zero_retry_network_client_execution_harness.mjs"
)
HARNESS_SHA256 = "8122b8ecfdde5b1a5478bcb7a354db6820abb44f6373c1899e075eb8c0991090"
HARNESS_BYTES = 7_882
RUNNER_FILE_NAME = (
    "authentication_entra_calling_client_msal_browser_"
    "zero_retry_network_client_execution_runner.mjs"
)
RUNNER_SHA256 = "9ed7e79f407636e2ae09201603f6a0e92c70d6269e909679f485292b76d433b2"
RUNNER_BYTES = 2_149
SCENARIO_COUNT = 15
OBSERVED_FETCH_CALL_COUNT = 12
SINGLE_ATTEMPT_SCENARIO_COUNT = 10
PRE_FETCH_REJECTION_COUNT = 4
REQUEST_TIMEOUT_MILLISECONDS = 10_000
MAXIMUM_RESPONSE_BYTES = 1_048_576
MAX_DOCUMENT_BYTES = 4_096
MAX_STDOUT_BYTES = 65_536
MAX_STDERR_BYTES = 4_096
MAX_NODE_EXECUTABLE_BYTES = 536_870_912
NODE_TIMEOUT_SECONDS = 30
SCENARIO_PROJECTION_SHA256 = (
    "04cf275e585820f147d2541a0cca7777b914d9c9320bcf67392dee31ddf2fa7b"
)
PERMISSION_PROFILE_SHA256 = (
    "9b54227c034c22da43adaaea263176dec09eec213e324082e5455354f669a5d8"
)
FAIL_CLOSED_SELECTION_STATE_SHA256 = (
    "d42d4d5e4d1862fc5a8904c6e336cf1d6dad2cb22b61bd93ca61ed2b2e296700"
)


class EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError(ValueError):
    """Sanitized Step 228 execution-proof failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step228-v1\x00" + domain.encode() + b"\x00" + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALZeroRetryNetworkClientExecutionDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_execution_proof"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_controlled_local_permission_restricted_zero_retry_execution"
    ]
    approved_step227_implementation_document_sha256: str
    expected_node_version: Literal["v24.19.0"]
    approved_node_executable_sha256: str
    execution_profile: Literal[
        "engineer4me_msal_browser_zero_retry_network_client_execution_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_types(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("execution-proof document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step227_implementation_document_sha256": str,
            "expected_node_version": str,
            "approved_node_executable_sha256": str,
            "execution_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("execution-proof document keys are not exact")
        if any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("execution-proof document field types are not exact")
        return value

    @model_validator(mode="after")
    def validate_digests(
        self,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionDocument:
        if not _is_sha256(
            self.approved_step227_implementation_document_sha256
        ) or not _is_sha256(self.approved_node_executable_sha256):
            raise ValueError("execution-proof approved digests are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence:
    node_version: str
    node_executable_sha256: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    _sealed_attestation: object = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.node_version) is not str
            or self.node_version != NODE_VERSION
            or not _is_sha256(self.node_executable_sha256)
            or type(self.stdout) is not bytes
            or not 1 <= len(self.stdout) <= MAX_STDOUT_BYTES
            or type(self.stderr) is not bytes
            or self.stderr
            or len(self.stderr) > MAX_STDERR_BYTES
            or type(self.exit_code) is not int
            or self.exit_code != 0
        ):
            raise ValueError("zero-retry execution evidence is invalid")


def _build_attestation_helpers() -> tuple[
    Callable[
        [EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence],
        EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence,
    ],
    Callable[[EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence], bool],
]:
    token = object()

    def attest(
        evidence: EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence:
        object.__setattr__(evidence, "_sealed_attestation", token)
        return evidence

    def is_attested(
        evidence: EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence,
    ) -> bool:
        return evidence._sealed_attestation is token

    return attest, is_attested


_attest_sealed_evidence, _is_sealed_evidence = _build_attestation_helpers()


class EntraCallingClientMSALZeroRetryNetworkClientExecutionTransport(Protocol):
    def __call__(
        self,
        adapter: bytes,
        harness: bytes,
        runner: bytes,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence: ...


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    execution_profile: str
    proof_status: str
    node_version: str
    adapter_path: str
    harness_file_name: str
    runner_file_name: str
    execution_proof_document_sha256: str
    step227_implementation_document_sha256: str
    step227_receipt_sha256: str
    adapter_sha256: str
    harness_sha256: str
    runner_sha256: str
    node_executable_sha256: str
    stdout_sha256: str
    scenario_projection_sha256: str
    permission_profile_sha256: str
    fail_closed_selection_state_sha256: str
    adapter_bytes: int
    harness_bytes: int
    runner_bytes: int
    scenario_count: int
    observed_fetch_call_count: int
    single_attempt_scenario_count: int
    pre_fetch_rejection_count: int
    request_timeout_milliseconds: int
    maximum_response_bytes: int
    step227_source_chain_rerun: bool
    step227_rendered_receipt_accepted_as_provenance: bool
    exact_adapter_harness_and_runner_bound: bool
    exact_node_version_and_executable_digest_bound: bool
    exact_scenario_matrix_validated: bool
    successful_post_one_attempt_validated: bool
    successful_get_one_attempt_validated: bool
    transport_failure_zero_retry_validated: bool
    abort_failure_zero_retry_validated: bool
    timeout_abort_zero_retry_validated: bool
    invalid_json_zero_retry_validated: bool
    http_and_oauth_response_zero_retry_validated: bool
    target_and_header_prefetch_rejection_validated: bool
    oversized_and_duplicate_header_failure_validated: bool
    concurrent_calls_one_attempt_each_validated: bool
    exact_fetch_option_projection_validated: bool
    sanitized_error_projection_validated: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    offline_execution_projection_validated: bool
    synthetic_execution_evidence: bool
    sealed_node_execution_performed: bool
    sealed_node_executable_attested: bool
    sealed_permission_profile_enforced: bool
    global_fetch_disabled_by_sealed_runner: bool
    sealed_filesystem_write_permission_absent: bool
    sealed_child_process_permission_absent: bool
    temporary_filesystem_io_performed: bool
    local_node_process_performed: bool
    injected_transport_side_effects_checked: bool
    browser_runtime_checked: bool
    token_endpoint_cors_checked: bool
    msal_runtime_compatibility_approved: bool
    frontend_import_graph_checked: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    real_oauth_values_processed: bool
    runtime_pkce_or_token_exchange_executed: bool
    sealed_provider_or_external_network_io_performed: bool
    operating_system_network_capability_denied: bool
    sealed_application_configuration_mutation_performed: bool
    sealed_application_activation_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "execution_profile": PROFILE,
            "proof_status": STATUS,
            "node_version": NODE_VERSION,
            "adapter_path": ADAPTER_PATH,
            "harness_file_name": HARNESS_FILE_NAME,
            "runner_file_name": RUNNER_FILE_NAME,
            "adapter_sha256": ADAPTER_SHA256,
            "harness_sha256": HARNESS_SHA256,
            "runner_sha256": RUNNER_SHA256,
            "adapter_bytes": ADAPTER_BYTES,
            "harness_bytes": HARNESS_BYTES,
            "runner_bytes": RUNNER_BYTES,
            "scenario_count": SCENARIO_COUNT,
            "observed_fetch_call_count": OBSERVED_FETCH_CALL_COUNT,
            "single_attempt_scenario_count": SINGLE_ATTEMPT_SCENARIO_COUNT,
            "pre_fetch_rejection_count": PRE_FETCH_REJECTION_COUNT,
            "request_timeout_milliseconds": REQUEST_TIMEOUT_MILLISECONDS,
            "maximum_response_bytes": MAXIMUM_RESPONSE_BYTES,
            "scenario_projection_sha256": SCENARIO_PROJECTION_SHA256,
            "permission_profile_sha256": PERMISSION_PROFILE_SHA256,
            "fail_closed_selection_state_sha256": (FAIL_CLOSED_SELECTION_STATE_SHA256),
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("zero-retry execution-proof constant is invalid")
        for name in (
            "execution_proof_document_sha256",
            "step227_implementation_document_sha256",
            "step227_receipt_sha256",
            "node_executable_sha256",
            "stdout_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("zero-retry execution-proof digest is invalid")
        structural_true = (
            "step227_source_chain_rerun",
            "exact_adapter_harness_and_runner_bound",
            "exact_node_version_and_executable_digest_bound",
            "exact_scenario_matrix_validated",
            "successful_post_one_attempt_validated",
            "successful_get_one_attempt_validated",
            "transport_failure_zero_retry_validated",
            "abort_failure_zero_retry_validated",
            "timeout_abort_zero_retry_validated",
            "invalid_json_zero_retry_validated",
            "http_and_oauth_response_zero_retry_validated",
            "target_and_header_prefetch_rejection_validated",
            "oversized_and_duplicate_header_failure_validated",
            "concurrent_calls_one_attempt_each_validated",
            "exact_fetch_option_projection_validated",
            "sanitized_error_projection_validated",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "offline_execution_projection_validated",
        )
        deferred_false = (
            "step227_rendered_receipt_accepted_as_provenance",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "sealed_provider_or_external_network_io_performed",
            "operating_system_network_capability_denied",
            "sealed_application_configuration_mutation_performed",
            "sealed_application_activation_performed",
        )
        for name in structural_true:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required execution-proof fact is false")
        for name in deferred_false:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred execution-proof fact is true")
        live_names = (
            "sealed_node_execution_performed",
            "sealed_node_executable_attested",
            "sealed_permission_profile_enforced",
            "global_fetch_disabled_by_sealed_runner",
            "sealed_filesystem_write_permission_absent",
            "sealed_child_process_permission_absent",
            "temporary_filesystem_io_performed",
            "local_node_process_performed",
        )
        if type(self.synthetic_execution_evidence) is not bool:
            raise ValueError("synthetic execution mode is invalid")
        expected_live = not self.synthetic_execution_evidence
        for name in live_names:
            if (
                type(getattr(self, name)) is not bool
                or getattr(self, name) is not expected_live
            ):
                raise ValueError("sealed execution attestation correlation is invalid")


def _parse_document(
    value: bytes,
) -> tuple[bytes, EntraCallingClientMSALZeroRetryNetworkClientExecutionDocument]:
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError("execution-proof document size is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("execution-proof document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("execution-proof document JSON is invalid") from None
    document = (
        EntraCallingClientMSALZeroRetryNetworkClientExecutionDocument.model_validate(
            raw
        )
    )
    return _canonical(document.model_dump(mode="json")), document


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _validate_node_executable(path_value: object, approved_sha256: str) -> str:
    if type(path_value) is not str:
        raise _ArgumentTypeError("canonical absolute Node executable path is required")
    if not path_value or not os.path.isabs(path_value):
        raise ValueError("canonical absolute Node executable path is required")
    try:
        metadata = os.lstat(path_value)
    except (OSError, ValueError):
        raise ValueError("Node executable is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError("Node executable must be an executable regular file")
    canonical = os.path.realpath(path_value)
    if os.path.normcase(canonical) != os.path.normcase(path_value):
        raise ValueError("canonical absolute Node executable path is required")
    node = Path(path_value)
    if os.name == "nt":
        if node.suffix.lower() != ".exe":
            raise ValueError("Node executable must be an executable regular file")
    elif not os.access(node, os.X_OK):
        raise ValueError("Node executable must be an executable regular file")
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
    if total != size or digest.hexdigest() != approved_sha256:
        raise ValueError("Node executable digest changed")
    return path_value


def _sealed_execute(
    *,
    adapter: bytes,
    harness: bytes,
    runner: bytes,
    node_executable_path: str,
    approved_node_executable_sha256: str,
) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence:
    node_executable_path = _validate_node_executable(
        node_executable_path, approved_node_executable_sha256
    )
    with tempfile.TemporaryDirectory(prefix="e4m-step228-") as temporary:
        workspace = Path(temporary)
        home = workspace / "home"
        home.mkdir()
        adapter_path = workspace / "adapter.mjs"
        harness_path = workspace / "harness.mjs"
        runner_path = workspace / "runner.mjs"
        adapter_path.write_bytes(adapter)
        harness_path.write_bytes(harness)
        runner_path.write_bytes(runner)
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
        completed = subprocess.run(
            [
                node_executable_path,
                "--permission",
                f"--allow-fs-read={workspace}",
                str(runner_path),
                str(harness_path),
                str(adapter_path),
                HARNESS_SHA256,
                ADAPTER_SHA256,
            ],
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=NODE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
        evidence = _attest_sealed_evidence(
            EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence(
                node_version=NODE_VERSION,
                node_executable_sha256=approved_node_executable_sha256,
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
            )
        )
    return evidence


def _expected_option_projection(method: str) -> dict[str, object]:
    return {
        "cache": "no-store",
        "credentials": "omit",
        "hasAbortSignal": True,
        "method": method,
        "mode": "cors",
        "redirect": "error",
        "referrerPolicy": "no-referrer",
    }


def _scenario_projection(stdout: bytes) -> tuple[dict[str, object], str]:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("execution stdout is not UTF-8") from None
    lines = text.splitlines()
    if len(lines) != 2 or not all(lines):
        raise ValueError("execution stdout must contain exactly two records")
    records = []
    for line in lines:
        if len(line.encode()) > MAX_STDOUT_BYTES:
            raise ValueError("execution stdout record is too large")
        try:
            records.append(json.loads(line, object_pairs_hook=_pairs))
        except (json.JSONDecodeError, ValueError):
            raise ValueError("execution stdout JSON is invalid") from None
    runner, harness = records
    permissions = {
        "childProcess": False,
        "worker": False,
        "fileSystemWrite": False,
        "addons": False,
        "wasi": False,
        "inspector": False,
    }
    if runner != {
        "runnerSchemaVersion": 1,
        "nodeVersion": NODE_VERSION,
        "harnessSha256": HARNESS_SHA256,
        "adapterSha256": ADAPTER_SHA256,
        "permissions": permissions,
        "globalFetchDisabled": True,
        "operatingSystemNetworkCapabilityDenied": False,
    }:
        raise ValueError("sealed runner projection changed")
    if (
        type(harness) is not dict
        or set(harness) != {"schemaVersion", "scenarioCount", "scenarios"}
        or type(harness["schemaVersion"]) is not int
        or harness["schemaVersion"] != 1
        or type(harness["scenarioCount"]) is not int
        or harness["scenarioCount"] != SCENARIO_COUNT
        or type(harness["scenarios"]) is not list
        or len(harness["scenarios"]) != SCENARIO_COUNT
    ):
        raise ValueError("execution harness schema changed")
    by_name: dict[str, dict[str, object]] = {}
    for scenario in harness["scenarios"]:
        if type(scenario) is not dict or type(scenario.get("name")) is not str:
            raise ValueError("execution scenario schema changed")
        if scenario["name"] in by_name:
            raise ValueError("duplicate execution scenario")
        by_name[scenario["name"]] = scenario
    expected_names = {
        "post_success_once",
        "get_success_once",
        "transport_failure_no_retry",
        "abort_failure_no_retry",
        "invalid_json_no_retry",
        "http_400_returned_once",
        "oauth_invalid_grant_returned_once",
        "wrong_post_target_rejected_before_fetch",
        "forbidden_header_rejected_before_fetch",
        "unapproved_get_rejected_before_fetch",
        "get_body_rejected_before_fetch",
        "oversized_response_no_retry",
        "duplicate_response_header_no_retry",
        "timeout_abort_no_retry",
        "concurrent_calls_one_attempt_each",
    }
    if set(by_name) != expected_names:
        raise ValueError("execution scenario names changed")
    post_options = _expected_option_projection("POST")
    get_options = _expected_option_projection("GET")

    def exact(
        name: str,
        attempts: int,
        status: int | None,
        body_kind: str | None,
        error: str | None,
        options: dict[str, object] | None,
    ) -> None:
        if by_name[name] != {
            "name": name,
            "attemptCount": attempts,
            "status": status,
            "bodyKind": body_kind,
            "errorMessage": error,
            "optionProjection": options,
        }:
            raise ValueError("execution scenario result changed")

    exact("post_success_once", 1, 200, "success", None, post_options)
    exact("get_success_once", 1, 200, "success", None, get_options)
    for name in (
        "transport_failure_no_retry",
        "abort_failure_no_retry",
        "invalid_json_no_retry",
        "oversized_response_no_retry",
        "duplicate_response_header_no_retry",
        "timeout_abort_no_retry",
    ):
        exact(name, 1, None, None, "MSAL network request failed", post_options)
    exact("http_400_returned_once", 1, 400, "success", None, post_options)
    exact(
        "oauth_invalid_grant_returned_once",
        1,
        400,
        "oauth_error",
        None,
        post_options,
    )
    prefetch = {
        "wrong_post_target_rejected_before_fetch": (
            "network request target is not approved"
        ),
        "forbidden_header_rejected_before_fetch": "request headers are invalid",
        "unapproved_get_rejected_before_fetch": (
            "network request target is not approved"
        ),
        "get_body_rejected_before_fetch": "GET request body is forbidden",
    }
    for name, error in prefetch.items():
        exact(name, 0, None, None, error, None)
    if by_name["concurrent_calls_one_attempt_each"] != {
        "name": "concurrent_calls_one_attempt_each",
        "attemptCount": 2,
        "perRequestAttempts": [1, 1],
        "statuses": [200, 200],
        "bodyKind": "success",
        "errorMessage": None,
        "optionProjection": None,
    }:
        raise ValueError("concurrent execution scenario changed")
    projection = {
        "runner": runner,
        "scenarios": [by_name[name] for name in sorted(by_name)],
        "counts": {
            "scenarios": SCENARIO_COUNT,
            "fetchCalls": OBSERVED_FETCH_CALL_COUNT,
            "singleAttemptScenarios": SINGLE_ATTEMPT_SCENARIO_COUNT,
            "preFetchRejections": PRE_FETCH_REJECTION_COUNT,
        },
    }
    return projection, hashlib.sha256(stdout).hexdigest()


def _load_internal(
    *,
    document: object,
    step227_document: object,
    step226_document: object,
    adapter: object,
    harness: object,
    runner: object,
    node_executable_path: object = None,
    execution_transport: object = None,
) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt:
    byte_values = (
        document,
        step227_document,
        step226_document,
        adapter,
        harness,
        runner,
    )
    if any(type(value) is not bytes for value in byte_values):
        raise _ArgumentTypeError("exact execution source bytes are required")
    if len({id(value) for value in byte_values}) != len(byte_values):
        raise ValueError("execution source byte objects must be distinct")
    injected = execution_transport is not None
    if injected and node_executable_path is not None:
        raise _ArgumentTypeError("synthetic execution cannot accept a Node path")
    if not injected and type(node_executable_path) is not str:
        raise _ArgumentTypeError("sealed execution requires a Node path")
    if execution_transport is not None and not isinstance(
        execution_transport, Callable
    ):
        raise _ArgumentTypeError("execution transport must be callable")
    prior = load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
        step227_document,
        step226_document,
        adapter,
    )
    if (
        type(prior)
        is not EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt
        or not prior.offline_static_implementation_readiness_validated
        or prior.package_selection_approved
        or prior.node_syntax_checked_by_contract
    ):
        raise ValueError("Step 227 prerequisite state is invalid")
    prior_rendered = render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt(
        prior
    ).encode()
    canonical_document, validated = _parse_document(document)
    if (
        validated.approved_step227_implementation_document_sha256
        != prior.implementation_document_sha256
        or len(adapter) != ADAPTER_BYTES
        or hashlib.sha256(adapter).hexdigest() != ADAPTER_SHA256
        or len(harness) != HARNESS_BYTES
        or hashlib.sha256(harness).hexdigest() != HARNESS_SHA256
        or len(runner) != RUNNER_BYTES
        or hashlib.sha256(runner).hexdigest() != RUNNER_SHA256
    ):
        raise ValueError("execution source identity changed")
    if injected:
        evidence = execution_transport(adapter, harness, runner)
    else:
        evidence = _sealed_execute(
            adapter=adapter,
            harness=harness,
            runner=runner,
            node_executable_path=node_executable_path,
            approved_node_executable_sha256=validated.approved_node_executable_sha256,
        )
    if (
        type(evidence)
        is not EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence
    ):
        raise ValueError("exact execution evidence is required")
    evidence.__post_init__()
    sealed = _is_sealed_evidence(evidence)
    if sealed is injected:
        raise ValueError("execution evidence provenance is invalid")
    if evidence.node_executable_sha256 != validated.approved_node_executable_sha256:
        raise ValueError("approved Node executable evidence mismatch")
    projection, stdout_sha256 = _scenario_projection(evidence.stdout)
    permission_profile = {
        "permissionFlag": True,
        "fileSystemRead": "ephemeral_workspace_only",
        "childProcess": False,
        "worker": False,
        "fileSystemWrite": False,
        "addons": False,
        "wasi": False,
        "inspector": False,
        "globalFetchDisabled": True,
        "operatingSystemNetworkCapabilityDenied": False,
    }
    selection = {
        "step216ZeroRetrySuperseded": False,
        "step225DefaultAccepted": False,
        "compatible": False,
        "selected": False,
        "installed": False,
    }
    structural_true = {
        name: True
        for name in (
            "step227_source_chain_rerun",
            "exact_adapter_harness_and_runner_bound",
            "exact_node_version_and_executable_digest_bound",
            "exact_scenario_matrix_validated",
            "successful_post_one_attempt_validated",
            "successful_get_one_attempt_validated",
            "transport_failure_zero_retry_validated",
            "abort_failure_zero_retry_validated",
            "timeout_abort_zero_retry_validated",
            "invalid_json_zero_retry_validated",
            "http_and_oauth_response_zero_retry_validated",
            "target_and_header_prefetch_rejection_validated",
            "oversized_and_duplicate_header_failure_validated",
            "concurrent_calls_one_attempt_each_validated",
            "exact_fetch_option_projection_validated",
            "sanitized_error_projection_validated",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "offline_execution_projection_validated",
        )
    }
    deferred_false = {
        name: False
        for name in (
            "step227_rendered_receipt_accepted_as_provenance",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "sealed_provider_or_external_network_io_performed",
            "operating_system_network_capability_denied",
            "sealed_application_configuration_mutation_performed",
            "sealed_application_activation_performed",
        )
    }
    live = sealed
    live_values = {
        "synthetic_execution_evidence": injected,
        "sealed_node_execution_performed": live,
        "sealed_node_executable_attested": live,
        "sealed_permission_profile_enforced": live,
        "global_fetch_disabled_by_sealed_runner": live,
        "sealed_filesystem_write_permission_absent": live,
        "sealed_child_process_permission_absent": live,
        "temporary_filesystem_io_performed": live,
        "local_node_process_performed": live,
    }
    return EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        execution_profile=PROFILE,
        proof_status=STATUS,
        node_version=NODE_VERSION,
        adapter_path=ADAPTER_PATH,
        harness_file_name=HARNESS_FILE_NAME,
        runner_file_name=RUNNER_FILE_NAME,
        execution_proof_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        step227_implementation_document_sha256=prior.implementation_document_sha256,
        step227_receipt_sha256=hashlib.sha256(prior_rendered).hexdigest(),
        adapter_sha256=ADAPTER_SHA256,
        harness_sha256=HARNESS_SHA256,
        runner_sha256=RUNNER_SHA256,
        node_executable_sha256=validated.approved_node_executable_sha256,
        stdout_sha256=stdout_sha256,
        scenario_projection_sha256=_framed("scenarios", projection),
        permission_profile_sha256=_framed("permissions", permission_profile),
        fail_closed_selection_state_sha256=_framed("selection", selection),
        adapter_bytes=ADAPTER_BYTES,
        harness_bytes=HARNESS_BYTES,
        runner_bytes=RUNNER_BYTES,
        scenario_count=SCENARIO_COUNT,
        observed_fetch_call_count=OBSERVED_FETCH_CALL_COUNT,
        single_attempt_scenario_count=SINGLE_ATTEMPT_SCENARIO_COUNT,
        pre_fetch_rejection_count=PRE_FETCH_REJECTION_COUNT,
        request_timeout_milliseconds=REQUEST_TIMEOUT_MILLISECONDS,
        maximum_response_bytes=MAXIMUM_RESPONSE_BYTES,
        **structural_true,
        **deferred_false,
        **live_values,
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
        interrupted |= isinstance(current, KeyboardInterrupt)
        terminated |= isinstance(current, SystemExit)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
        except BaseException:  # noqa: BLE001, S110
            pass
    return interrupted, terminated


def prove_entra_calling_client_msal_zero_retry_network_client_execution(
    *,
    document: object,
    step227_document: object,
    step226_document: object,
    adapter: object,
    harness: object,
    runner: object,
    node_executable_path: object = None,
    execution_transport: object = None,
) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt:
    """Validate injected evidence or run one sealed local Node proof."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document=document,
            step227_document=step227_document,
            step226_document=step226_document,
            adapter=adapter,
            harness=harness,
            runner=runner,
            node_executable_path=node_executable_path,
            execution_transport=execution_transport,
        )
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        document = None
        step227_document = None
        step226_document = None
        adapter = None
        harness = None
        runner = None
        node_executable_path = None
        execution_transport = None
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
    if interrupted:
        raise KeyboardInterrupt("MSAL zero-retry execution proof interrupted")
    if terminated:
        raise SystemExit("MSAL zero-retry execution proof terminated")
    if invalid:
        raise TypeError("MSAL zero-retry execution proof input is invalid")
    if result is None:
        raise EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError(
            "MSAL zero-retry execution proof failed"
        )
    return result


def render_entra_calling_client_msal_zero_retry_network_client_execution_receipt(
    receipt: EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt,
) -> str:
    """Render canonical privacy-minimized Step 228 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt
    ):
        raise TypeError("exact zero-retry execution-proof receipt is required")
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
    "HARNESS_BYTES",
    "HARNESS_FILE_NAME",
    "HARNESS_SHA256",
    "NODE_VERSION",
    "PROFILE",
    "RECEIPT_TYPE",
    "RUNNER_BYTES",
    "RUNNER_FILE_NAME",
    "RUNNER_SHA256",
    "SOURCE",
    "STATUS",
    "EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence",
    "EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError",
    "EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt",
    "prove_entra_calling_client_msal_zero_retry_network_client_execution",
    "render_entra_calling_client_msal_zero_retry_network_client_execution_receipt",
]
