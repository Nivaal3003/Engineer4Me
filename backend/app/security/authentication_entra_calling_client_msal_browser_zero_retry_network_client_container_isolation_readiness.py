"""Offline Docker none-network readiness for the exact zero-retry Node proof."""

from __future__ import annotations

import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    HARNESS_BYTES,
    HARNESS_FILE_NAME,
    HARNESS_SHA256,
    NODE_VERSION,
    RUNNER_BYTES,
    RUNNER_FILE_NAME,
    RUNNER_SHA256,
    EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence,
    EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt,
    prove_entra_calling_client_msal_zero_retry_network_client_execution,
    render_entra_calling_client_msal_zero_retry_network_client_execution_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    ADAPTER_BYTES,
    ADAPTER_SHA256,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_zero_retry_container_isolation_readiness"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_reviewed_docker_none_network_execution_isolation_plan"
SCOPE = "offline_exact_container_lifecycle_and_isolation_readiness"
PROFILE = "engineer4me_docker_none_network_zero_retry_node_execution_v1"
STATUS = "container_isolation_plan_bound_but_not_inspected_created_or_executed"
STEP228_PACKAGE_MANIFEST_SHA256 = (
    "525bd42a02b179b5ea5781c6524fe33749d5a43ff6089d29d2de8a7922a3d10e"
)
CONTAINER_RUNTIME = "docker"
CONTAINER_OPERATING_SYSTEM = "linux"
CONTAINER_ARCHITECTURE = "amd64"
CONTAINER_NETWORK_MODE = "none"
CONTAINER_USER = "65532:65532"
CONTAINER_WORKDIR = "/work"
CONTAINER_NODE_PATH = "/usr/local/bin/node"
CONTAINER_MOUNT_TARGET = "/work"
CONTAINER_PIDS_LIMIT = 32
CONTAINER_MEMORY_BYTES = 268_435_456
CONTAINER_MEMORY_SWAP_BYTES = 268_435_456
CONTAINER_CPUS_MILLI = 1_000
CONTAINER_SHM_BYTES = 16_777_216
CONTAINER_STOP_TIMEOUT_SECONDS = 1
CONTAINER_EXECUTION_TIMEOUT_SECONDS = 45
MAXIMUM_STDOUT_BYTES = 65_536
MAXIMUM_STDERR_BYTES = 4_096
MAX_DOCUMENT_BYTES = 4_096


class EntraCallingClientMSALZeroRetryContainerIsolationReadinessError(ValueError):
    """Sanitized Step 229 isolation-readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_image_id(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and _is_sha256(value.removeprefix("sha256:"))
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
        b"Engineer4Me-Step229-v1\x00" + domain.encode() + b"\x00" + _canonical(value)
    ).hexdigest()


def _option(method: str) -> dict[str, object]:
    return {
        "cache": "no-store",
        "credentials": "omit",
        "hasAbortSignal": True,
        "method": method,
        "mode": "cors",
        "redirect": "error",
        "referrerPolicy": "no-referrer",
    }


def _scenario(
    name: str,
    attempts: int,
    status: int | None,
    body_kind: str | None,
    error: str | None,
    options: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "name": name,
        "attemptCount": attempts,
        "status": status,
        "bodyKind": body_kind,
        "errorMessage": error,
        "optionProjection": options,
    }


def _step228_synthetic_stdout() -> bytes:
    post = _option("POST")
    get = _option("GET")
    runner = {
        "runnerSchemaVersion": 1,
        "nodeVersion": NODE_VERSION,
        "harnessSha256": HARNESS_SHA256,
        "adapterSha256": ADAPTER_SHA256,
        "permissions": {
            "childProcess": False,
            "worker": False,
            "fileSystemWrite": False,
            "addons": False,
            "wasi": False,
            "inspector": False,
        },
        "globalFetchDisabled": True,
        "operatingSystemNetworkCapabilityDenied": False,
    }
    scenarios = [
        _scenario("post_success_once", 1, 200, "success", None, post),
        _scenario("get_success_once", 1, 200, "success", None, get),
        _scenario(
            "transport_failure_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "abort_failure_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "invalid_json_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario("http_400_returned_once", 1, 400, "success", None, post),
        _scenario(
            "oauth_invalid_grant_returned_once",
            1,
            400,
            "oauth_error",
            None,
            post,
        ),
        _scenario(
            "wrong_post_target_rejected_before_fetch",
            0,
            None,
            None,
            "network request target is not approved",
            None,
        ),
        _scenario(
            "forbidden_header_rejected_before_fetch",
            0,
            None,
            None,
            "request headers are invalid",
            None,
        ),
        _scenario(
            "unapproved_get_rejected_before_fetch",
            0,
            None,
            None,
            "network request target is not approved",
            None,
        ),
        _scenario(
            "get_body_rejected_before_fetch",
            0,
            None,
            None,
            "GET request body is forbidden",
            None,
        ),
        _scenario(
            "oversized_response_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "duplicate_response_header_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "timeout_abort_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        {
            "name": "concurrent_calls_one_attempt_each",
            "attemptCount": 2,
            "perRequestAttempts": [1, 1],
            "statuses": [200, 200],
            "bodyKind": "success",
            "errorMessage": None,
            "optionProjection": None,
        },
    ]
    harness = {
        "schemaVersion": 1,
        "scenarioCount": 15,
        "scenarios": scenarios,
    }
    return _canonical(runner) + b"\n" + _canonical(harness) + b"\n"


def _profiles(*, image_id: str, node_executable_sha256: str) -> dict[str, str]:
    inspect = {
        "runtime": CONTAINER_RUNTIME,
        "image_reference": image_id,
        "pull": "never",
        "platform": f"{CONTAINER_OPERATING_SYSTEM}/{CONTAINER_ARCHITECTURE}",
        "require_exact_id": True,
        "reject_tag_or_registry_reference": True,
        "config_and_rootfs_review_required_before_create": True,
        "node_path": CONTAINER_NODE_PATH,
        "node_version": NODE_VERSION,
        "node_executable_sha256": node_executable_sha256,
    }
    isolation = {
        "network": CONTAINER_NETWORK_MODE,
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "builtin",
        "user": CONTAINER_USER,
        "privileged": False,
        "healthcheck_disabled": True,
        "devices": [],
        "ports": [],
        "docker_socket_mount": False,
        "host_namespaces": [],
    }
    resources = {
        "pids": CONTAINER_PIDS_LIMIT,
        "memory_bytes": CONTAINER_MEMORY_BYTES,
        "memory_swap_bytes": CONTAINER_MEMORY_SWAP_BYTES,
        "cpus_milli": CONTAINER_CPUS_MILLI,
        "shm_bytes": CONTAINER_SHM_BYTES,
        "stop_timeout_seconds": CONTAINER_STOP_TIMEOUT_SECONDS,
        "execution_timeout_seconds": CONTAINER_EXECUTION_TIMEOUT_SECONDS,
        "stdout_bytes": MAXIMUM_STDOUT_BYTES,
        "stderr_bytes": MAXIMUM_STDERR_BYTES,
    }
    mount = {
        "count": 1,
        "type": "bind",
        "source": "fresh_ephemeral_workspace",
        "target": CONTAINER_MOUNT_TARGET,
        "read_only": True,
        "workspace_mode": "0755",
        "file_mode": "0444",
        "other_mounts": False,
    }
    environment = {
        "HOME": "/nonexistent",
        "USERPROFILE": "/nonexistent",
        "TMP": "/nonexistent",
        "TEMP": "/nonexistent",
        "NO_COLOR": "1",
        "NODE_OPTIONS": "",
        "NODE_USE_ENV_PROXY": "0",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "NO_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "no_proxy": "",
    }
    lifecycle = {
        "order": [
            "prevalidate_all_source_bytes",
            "inspect_exact_local_image",
            "create_container",
            "inspect_applied_container_configuration",
            "start_and_attach_once",
            "remove_container_in_finally",
        ],
        "create_retries": 0,
        "start_retries": 0,
        "container_name": None,
        "restart": "no",
        "auto_remove": False,
        "log_driver": "none",
        "remove_in_finally": True,
        "partial_failure_receipt": False,
    }
    execution = {
        "entrypoint": CONTAINER_NODE_PATH,
        "workdir": CONTAINER_WORKDIR,
        "arguments": [
            "--permission",
            "--allow-fs-read=/work",
            f"/work/{RUNNER_FILE_NAME}",
            f"/work/{HARNESS_FILE_NAME}",
            "/work/authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs",
            HARNESS_SHA256,
            ADAPTER_SHA256,
        ],
        "stdin": "closed",
        "attach": ["stdout", "stderr"],
        "fake_fetch_only": True,
        "real_oauth_values": False,
    }
    return {
        "image_preflight_profile_sha256": _framed("image-preflight", inspect),
        "container_isolation_profile_sha256": _framed("isolation", isolation),
        "container_resource_profile_sha256": _framed("resources", resources),
        "container_mount_profile_sha256": _framed("mount", mount),
        "container_environment_profile_sha256": _framed("environment", environment),
        "container_lifecycle_profile_sha256": _framed("lifecycle", lifecycle),
        "container_execution_profile_sha256": _framed("execution", execution),
    }


class EntraCallingClientMSALZeroRetryContainerIsolationReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_zero_retry_container_isolation_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_docker_none_network_execution_isolation_plan"]
    approved_step228_package_manifest_sha256: str
    approved_step228_execution_document_sha256: str
    approved_container_image_id: str
    expected_container_operating_system: Literal["linux"]
    expected_container_architecture: Literal["amd64"]
    expected_node_path: Literal["/usr/local/bin/node"]
    isolation_profile: Literal[
        "engineer4me_docker_none_network_zero_retry_node_execution_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_types(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("container-isolation document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step228_package_manifest_sha256": str,
            "approved_step228_execution_document_sha256": str,
            "approved_container_image_id": str,
            "expected_container_operating_system": str,
            "expected_container_architecture": str,
            "expected_node_path": str,
            "isolation_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("container-isolation document keys are not exact")
        if any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("container-isolation document types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALZeroRetryContainerIsolationReadinessDocument:
        if (
            self.approved_step228_package_manifest_sha256
            != STEP228_PACKAGE_MANIFEST_SHA256
            or not _is_sha256(self.approved_step228_execution_document_sha256)
            or not _is_image_id(self.approved_container_image_id)
        ):
            raise ValueError("container-isolation approved identities are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    isolation_profile: str
    readiness_status: str
    container_runtime: str
    container_operating_system: str
    container_architecture: str
    container_network_mode: str
    container_user: str
    container_workdir: str
    container_node_path: str
    container_mount_target: str
    approved_step228_package_manifest_sha256: str
    isolation_document_sha256: str
    step228_execution_document_sha256: str
    step228_receipt_sha256: str
    approved_container_image_id: str
    approved_node_executable_sha256: str
    adapter_sha256: str
    harness_sha256: str
    runner_sha256: str
    image_preflight_profile_sha256: str
    container_isolation_profile_sha256: str
    container_resource_profile_sha256: str
    container_mount_profile_sha256: str
    container_environment_profile_sha256: str
    container_lifecycle_profile_sha256: str
    container_execution_profile_sha256: str
    adapter_bytes: int
    harness_bytes: int
    runner_bytes: int
    container_pids_limit: int
    container_memory_bytes: int
    container_memory_swap_bytes: int
    container_cpus_milli: int
    container_shm_bytes: int
    container_stop_timeout_seconds: int
    container_execution_timeout_seconds: int
    maximum_stdout_bytes: int
    maximum_stderr_bytes: int
    step228_source_chain_rerun: bool
    step228_rendered_receipt_accepted_as_provenance: bool
    step228_package_manifest_digest_bound: bool
    step228_execution_document_digest_bound: bool
    exact_adapter_harness_and_runner_bound: bool
    exact_content_addressed_image_required: bool
    registry_tag_execution_reference_forbidden: bool
    image_pull_forbidden: bool
    complete_source_prevalidation_before_daemon_access_required: bool
    image_inspect_before_container_create_required: bool
    image_config_and_rootfs_review_before_create_required: bool
    docker_none_network_required: bool
    read_only_root_filesystem_required: bool
    all_linux_capabilities_dropped_required: bool
    no_new_privileges_required: bool
    builtin_seccomp_required: bool
    non_root_numeric_user_required: bool
    exactly_one_read_only_ephemeral_bind_mount_required: bool
    docker_socket_mount_forbidden: bool
    device_mounts_forbidden: bool
    published_ports_forbidden: bool
    host_namespace_sharing_forbidden: bool
    image_healthcheck_disabled_required: bool
    bounded_resource_profile_required: bool
    exact_environment_override_required: bool
    exact_node_entrypoint_and_arguments_required: bool
    container_config_reinspection_before_start_required: bool
    exactly_one_container_start_required: bool
    container_cleanup_in_finally_required: bool
    zero_docker_operation_retries_required: bool
    node_permission_model_retained_required: bool
    global_fetch_disablement_retained_required: bool
    fake_fetch_only_execution_required: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    offline_container_isolation_readiness_validated: bool
    candidate_docker_daemon_accessed: bool
    container_image_present_checked: bool
    container_image_configuration_checked: bool
    container_rootfs_layers_checked: bool
    node_binary_inside_image_checked: bool
    container_created: bool
    container_configuration_reinspected: bool
    container_started: bool
    container_removed: bool
    os_network_isolation_dynamically_verified: bool
    node_execution_dynamically_observed: bool
    zero_retry_matrix_dynamically_observed_in_container: bool
    docker_engine_version_checked: bool
    docker_desktop_linux_engine_checked: bool
    seccomp_application_dynamically_verified: bool
    resource_limits_dynamically_verified: bool
    injected_transport_side_effects_checked: bool
    browser_runtime_checked: bool
    token_endpoint_cors_checked: bool
    msal_runtime_compatibility_approved: bool
    frontend_import_graph_checked: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    real_oauth_values_processed: bool
    sealed_provider_or_external_network_io_performed: bool
    sealed_application_configuration_mutation_performed: bool
    application_activation_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "isolation_profile": PROFILE,
            "readiness_status": STATUS,
            "container_runtime": CONTAINER_RUNTIME,
            "container_operating_system": CONTAINER_OPERATING_SYSTEM,
            "container_architecture": CONTAINER_ARCHITECTURE,
            "container_network_mode": CONTAINER_NETWORK_MODE,
            "container_user": CONTAINER_USER,
            "container_workdir": CONTAINER_WORKDIR,
            "container_node_path": CONTAINER_NODE_PATH,
            "container_mount_target": CONTAINER_MOUNT_TARGET,
            "approved_step228_package_manifest_sha256": (
                STEP228_PACKAGE_MANIFEST_SHA256
            ),
            "adapter_sha256": ADAPTER_SHA256,
            "harness_sha256": HARNESS_SHA256,
            "runner_sha256": RUNNER_SHA256,
            "adapter_bytes": ADAPTER_BYTES,
            "harness_bytes": HARNESS_BYTES,
            "runner_bytes": RUNNER_BYTES,
            "container_pids_limit": CONTAINER_PIDS_LIMIT,
            "container_memory_bytes": CONTAINER_MEMORY_BYTES,
            "container_memory_swap_bytes": CONTAINER_MEMORY_SWAP_BYTES,
            "container_cpus_milli": CONTAINER_CPUS_MILLI,
            "container_shm_bytes": CONTAINER_SHM_BYTES,
            "container_stop_timeout_seconds": CONTAINER_STOP_TIMEOUT_SECONDS,
            "container_execution_timeout_seconds": (
                CONTAINER_EXECUTION_TIMEOUT_SECONDS
            ),
            "maximum_stdout_bytes": MAXIMUM_STDOUT_BYTES,
            "maximum_stderr_bytes": MAXIMUM_STDERR_BYTES,
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("container-isolation readiness constant is invalid")
        for name in (
            "isolation_document_sha256",
            "step228_execution_document_sha256",
            "step228_receipt_sha256",
            "approved_node_executable_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("container-isolation evidence digest is invalid")
        if not _is_image_id(self.approved_container_image_id):
            raise ValueError("container image ID is invalid")
        for name, expected in _profiles(
            image_id=self.approved_container_image_id,
            node_executable_sha256=self.approved_node_executable_sha256,
        ).items():
            if type(getattr(self, name)) is not str or getattr(self, name) != expected:
                raise ValueError("container-isolation profile digest is invalid")
        true_names = (
            "step228_source_chain_rerun",
            "step228_package_manifest_digest_bound",
            "step228_execution_document_digest_bound",
            "exact_adapter_harness_and_runner_bound",
            "exact_content_addressed_image_required",
            "registry_tag_execution_reference_forbidden",
            "image_pull_forbidden",
            "complete_source_prevalidation_before_daemon_access_required",
            "image_inspect_before_container_create_required",
            "image_config_and_rootfs_review_before_create_required",
            "docker_none_network_required",
            "read_only_root_filesystem_required",
            "all_linux_capabilities_dropped_required",
            "no_new_privileges_required",
            "builtin_seccomp_required",
            "non_root_numeric_user_required",
            "exactly_one_read_only_ephemeral_bind_mount_required",
            "docker_socket_mount_forbidden",
            "device_mounts_forbidden",
            "published_ports_forbidden",
            "host_namespace_sharing_forbidden",
            "image_healthcheck_disabled_required",
            "bounded_resource_profile_required",
            "exact_environment_override_required",
            "exact_node_entrypoint_and_arguments_required",
            "container_config_reinspection_before_start_required",
            "exactly_one_container_start_required",
            "container_cleanup_in_finally_required",
            "zero_docker_operation_retries_required",
            "node_permission_model_retained_required",
            "global_fetch_disablement_retained_required",
            "fake_fetch_only_execution_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "offline_container_isolation_readiness_validated",
        )
        false_names = (
            "step228_rendered_receipt_accepted_as_provenance",
            "candidate_docker_daemon_accessed",
            "container_image_present_checked",
            "container_image_configuration_checked",
            "container_rootfs_layers_checked",
            "node_binary_inside_image_checked",
            "container_created",
            "container_configuration_reinspected",
            "container_started",
            "container_removed",
            "os_network_isolation_dynamically_verified",
            "node_execution_dynamically_observed",
            "zero_retry_matrix_dynamically_observed_in_container",
            "docker_engine_version_checked",
            "docker_desktop_linux_engine_checked",
            "seccomp_application_dynamically_verified",
            "resource_limits_dynamically_verified",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "sealed_provider_or_external_network_io_performed",
            "sealed_application_configuration_mutation_performed",
            "application_activation_performed",
        )
        for name in true_names:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required container-isolation fact is false")
        for name in false_names:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred container-isolation fact is true")


def _parse_document(
    value: bytes,
) -> tuple[bytes, EntraCallingClientMSALZeroRetryContainerIsolationReadinessDocument]:
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError("container-isolation document size is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("container-isolation document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("container-isolation document JSON is invalid") from None
    document = EntraCallingClientMSALZeroRetryContainerIsolationReadinessDocument.model_validate(
        raw
    )
    return _canonical(document.model_dump(mode="json")), document


def _step228_node_digest(document_bytes: bytes) -> str:
    try:
        raw = json.loads(document_bytes.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Step 228 execution document is invalid") from None
    if type(raw) is not dict:
        raise ValueError("Step 228 execution document is invalid")
    digest = raw.get("approved_node_executable_sha256")
    if not _is_sha256(digest):
        raise ValueError("Step 228 Node executable digest is invalid")
    return digest


def _load_internal(
    document_bytes: object,
    step228_execution_document_bytes: object,
    step227_document_bytes: object,
    step226_document_bytes: object,
    adapter_bytes: object,
    harness_bytes: object,
    runner_bytes: object,
) -> EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt:
    values = (
        document_bytes,
        step228_execution_document_bytes,
        step227_document_bytes,
        step226_document_bytes,
        adapter_bytes,
        harness_bytes,
        runner_bytes,
    )
    if any(type(value) is not bytes for value in values):
        raise _ArgumentTypeError("exact container-isolation source bytes are required")
    if len({id(value) for value in values}) != len(values):
        raise ValueError("container-isolation inputs must be distinct byte objects")
    node_digest = _step228_node_digest(step228_execution_document_bytes)

    def transport(
        _adapter: bytes, _harness: bytes, _runner: bytes
    ) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence:
        return EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence(
            node_version=NODE_VERSION,
            node_executable_sha256=node_digest,
            stdout=_step228_synthetic_stdout(),
            stderr=b"",
            exit_code=0,
        )

    prior = prove_entra_calling_client_msal_zero_retry_network_client_execution(
        document=step228_execution_document_bytes,
        step227_document=step227_document_bytes,
        step226_document=step226_document_bytes,
        adapter=adapter_bytes,
        harness=harness_bytes,
        runner=runner_bytes,
        execution_transport=transport,
    )
    if (
        type(prior)
        is not EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt
        or not prior.synthetic_execution_evidence
        or prior.sealed_node_execution_performed
        or prior.operating_system_network_capability_denied
        or prior.package_selection_approved
        or prior.execution_proof_document_sha256
        != hashlib.sha256(step228_execution_document_bytes).hexdigest()
    ):
        raise ValueError("Step 228 prerequisite state is invalid")
    canonical_document, document = _parse_document(document_bytes)
    if canonical_document != document_bytes:
        raise ValueError("container-isolation document is not canonical")
    if (
        hashlib.sha256(step228_execution_document_bytes).hexdigest()
        != document.approved_step228_execution_document_sha256
    ):
        raise ValueError("approved Step 228 execution document changed")
    prior_rendered = (
        render_entra_calling_client_msal_zero_retry_network_client_execution_receipt(
            prior
        ).encode()
    )
    true_values = {
        name: True
        for name in (
            "step228_source_chain_rerun",
            "step228_package_manifest_digest_bound",
            "step228_execution_document_digest_bound",
            "exact_adapter_harness_and_runner_bound",
            "exact_content_addressed_image_required",
            "registry_tag_execution_reference_forbidden",
            "image_pull_forbidden",
            "complete_source_prevalidation_before_daemon_access_required",
            "image_inspect_before_container_create_required",
            "image_config_and_rootfs_review_before_create_required",
            "docker_none_network_required",
            "read_only_root_filesystem_required",
            "all_linux_capabilities_dropped_required",
            "no_new_privileges_required",
            "builtin_seccomp_required",
            "non_root_numeric_user_required",
            "exactly_one_read_only_ephemeral_bind_mount_required",
            "docker_socket_mount_forbidden",
            "device_mounts_forbidden",
            "published_ports_forbidden",
            "host_namespace_sharing_forbidden",
            "image_healthcheck_disabled_required",
            "bounded_resource_profile_required",
            "exact_environment_override_required",
            "exact_node_entrypoint_and_arguments_required",
            "container_config_reinspection_before_start_required",
            "exactly_one_container_start_required",
            "container_cleanup_in_finally_required",
            "zero_docker_operation_retries_required",
            "node_permission_model_retained_required",
            "global_fetch_disablement_retained_required",
            "fake_fetch_only_execution_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "offline_container_isolation_readiness_validated",
        )
    }
    false_values = {
        name: False
        for name in (
            "step228_rendered_receipt_accepted_as_provenance",
            "candidate_docker_daemon_accessed",
            "container_image_present_checked",
            "container_image_configuration_checked",
            "container_rootfs_layers_checked",
            "node_binary_inside_image_checked",
            "container_created",
            "container_configuration_reinspected",
            "container_started",
            "container_removed",
            "os_network_isolation_dynamically_verified",
            "node_execution_dynamically_observed",
            "zero_retry_matrix_dynamically_observed_in_container",
            "docker_engine_version_checked",
            "docker_desktop_linux_engine_checked",
            "seccomp_application_dynamically_verified",
            "resource_limits_dynamically_verified",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "sealed_provider_or_external_network_io_performed",
            "sealed_application_configuration_mutation_performed",
            "application_activation_performed",
        )
    }
    return EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        isolation_profile=PROFILE,
        readiness_status=STATUS,
        container_runtime=CONTAINER_RUNTIME,
        container_operating_system=CONTAINER_OPERATING_SYSTEM,
        container_architecture=CONTAINER_ARCHITECTURE,
        container_network_mode=CONTAINER_NETWORK_MODE,
        container_user=CONTAINER_USER,
        container_workdir=CONTAINER_WORKDIR,
        container_node_path=CONTAINER_NODE_PATH,
        container_mount_target=CONTAINER_MOUNT_TARGET,
        approved_step228_package_manifest_sha256=(STEP228_PACKAGE_MANIFEST_SHA256),
        isolation_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        step228_execution_document_sha256=hashlib.sha256(
            step228_execution_document_bytes
        ).hexdigest(),
        step228_receipt_sha256=hashlib.sha256(prior_rendered).hexdigest(),
        approved_container_image_id=document.approved_container_image_id,
        approved_node_executable_sha256=node_digest,
        adapter_sha256=ADAPTER_SHA256,
        harness_sha256=HARNESS_SHA256,
        runner_sha256=RUNNER_SHA256,
        adapter_bytes=ADAPTER_BYTES,
        harness_bytes=HARNESS_BYTES,
        runner_bytes=RUNNER_BYTES,
        container_pids_limit=CONTAINER_PIDS_LIMIT,
        container_memory_bytes=CONTAINER_MEMORY_BYTES,
        container_memory_swap_bytes=CONTAINER_MEMORY_SWAP_BYTES,
        container_cpus_milli=CONTAINER_CPUS_MILLI,
        container_shm_bytes=CONTAINER_SHM_BYTES,
        container_stop_timeout_seconds=CONTAINER_STOP_TIMEOUT_SECONDS,
        container_execution_timeout_seconds=CONTAINER_EXECUTION_TIMEOUT_SECONDS,
        maximum_stdout_bytes=MAXIMUM_STDOUT_BYTES,
        maximum_stderr_bytes=MAXIMUM_STDERR_BYTES,
        **_profiles(
            image_id=document.approved_container_image_id,
            node_executable_sha256=node_digest,
        ),
        **true_values,
        **false_values,
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


def load_entra_calling_client_msal_zero_retry_container_isolation_readiness(
    document_bytes: object,
    step228_execution_document_bytes: object,
    step227_document_bytes: object,
    step226_document_bytes: object,
    adapter_bytes: object,
    harness_bytes: object,
    runner_bytes: object,
) -> EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt:
    """Return one sanitized offline Step 229 container-isolation receipt."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document_bytes,
            step228_execution_document_bytes,
            step227_document_bytes,
            step226_document_bytes,
            adapter_bytes,
            harness_bytes,
            runner_bytes,
        )
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        document_bytes = None
        step228_execution_document_bytes = None
        step227_document_bytes = None
        step226_document_bytes = None
        adapter_bytes = None
        harness_bytes = None
        runner_bytes = None
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
    if interrupted:
        raise KeyboardInterrupt("MSAL container-isolation readiness interrupted")
    if terminated:
        raise SystemExit("MSAL container-isolation readiness terminated")
    if invalid:
        raise TypeError("MSAL container-isolation readiness input is invalid")
    if result is None:
        raise EntraCallingClientMSALZeroRetryContainerIsolationReadinessError(
            "MSAL container-isolation readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt(
    receipt: EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized Step 229 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt
    ):
        raise TypeError("exact container-isolation readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "CONTAINER_ARCHITECTURE",
    "CONTAINER_NETWORK_MODE",
    "CONTAINER_OPERATING_SYSTEM",
    "CONTAINER_RUNTIME",
    "DOCUMENT_TYPE",
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "STEP228_PACKAGE_MANIFEST_SHA256",
    "EntraCallingClientMSALZeroRetryContainerIsolationReadinessError",
    "EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt",
    "load_entra_calling_client_msal_zero_retry_container_isolation_readiness",
    "render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt",
]
