"""Step 230 controlled Docker none-network zero-retry execution proof."""

from __future__ import annotations

import hashlib
import json
from builtins import BaseExceptionGroup
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_execution_loader import (
    COMMAND_SEQUENCE,
    MAX_IMAGE_BYTES,
    MAX_IMAGE_LAYERS,
    EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
    EntraCallingClientMSALZeroRetryContainerExecutionLoader,
    EntraCallingClientMSALZeroRetryContainerExecutionRequest,
    is_sealed_container_execution_evidence,
    validate_container_execution_evidence,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_isolation_readiness import (
    CONTAINER_ARCHITECTURE,
    CONTAINER_CPUS_MILLI,
    CONTAINER_EXECUTION_TIMEOUT_SECONDS,
    CONTAINER_MEMORY_BYTES,
    CONTAINER_MEMORY_SWAP_BYTES,
    CONTAINER_NETWORK_MODE,
    CONTAINER_OPERATING_SYSTEM,
    CONTAINER_PIDS_LIMIT,
    CONTAINER_SHM_BYTES,
    CONTAINER_USER,
    EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt,
    load_entra_calling_client_msal_zero_retry_container_isolation_readiness,
    render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    NODE_VERSION,
    EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence,
    EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt,
    prove_entra_calling_client_msal_zero_retry_network_client_execution,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_zero_retry_container_execution_proof"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_local_docker_none_network_zero_retry_execution"
SCOPE = "exact_local_image_container_isolation_and_zero_retry_execution"
PROFILE = "engineer4me_docker_none_network_zero_retry_node_execution_proof_v1"
STATUS = "container_execution_proven_or_synthetic_evidence_validated_without_runtime_selection"
STEP229_PACKAGE_MANIFEST_SHA256 = (
    "5f305c67abe65d4827f77bd68933e00275d0dce62dfabf80389101403b9d0b89"
)
MAX_DOCUMENT_BYTES = 4096


class EntraCallingClientMSALZeroRetryContainerExecutionProbeError(ValueError):
    """Sanitized Step 230 proof failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_public_version_token(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(
            character.isascii() and (character.isalnum() or character in ".+-_")
            for character in value
        )
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
        b"Engineer4Me-Step230-v1\x00" + domain.encode() + b"\x00" + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALZeroRetryContainerExecutionProofDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_zero_retry_container_execution_proof"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_controlled_local_docker_none_network_zero_retry_execution"
    ]
    approved_step229_package_manifest_sha256: str
    approved_step229_isolation_document_sha256: str
    approved_docker_executable_sha256: str
    execution_profile: Literal[
        "engineer4me_docker_none_network_zero_retry_node_execution_proof_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_types(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("container execution document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step229_package_manifest_sha256": str,
            "approved_step229_isolation_document_sha256": str,
            "approved_docker_executable_sha256": str,
            "execution_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("container execution document keys are not exact")
        if any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("container execution document types are not exact")
        return value

    @model_validator(mode="after")
    def validate_digests(
        self,
    ) -> EntraCallingClientMSALZeroRetryContainerExecutionProofDocument:
        if (
            self.approved_step229_package_manifest_sha256
            != STEP229_PACKAGE_MANIFEST_SHA256
            or not _is_sha256(self.approved_step229_isolation_document_sha256)
            or not _is_sha256(self.approved_docker_executable_sha256)
        ):
            raise ValueError("container execution approved digests are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    execution_profile: str
    proof_status: str
    docker_server_operating_system: str
    docker_server_architecture: str
    docker_server_version: str
    docker_server_api_version: str
    node_version: str
    container_network_mode: str
    container_user: str
    approved_step229_package_manifest_sha256: str
    execution_document_sha256: str
    step229_isolation_document_sha256: str
    step229_receipt_sha256: str
    docker_cli_sha256: str
    approved_container_image_id: str
    approved_node_executable_sha256: str
    docker_evidence_projection_sha256: str
    public_identity_summary_sha256: str
    image_projection_sha256: str
    container_before_projection_sha256: str
    container_after_projection_sha256: str
    command_sequence_sha256: str
    execution_stdout_sha256: str
    step228_execution_receipt_sha256: str
    image_layer_count: int
    image_size_bytes: int
    planned_docker_command_count: int
    sealed_docker_command_count: int
    container_pids_limit: int
    container_memory_bytes: int
    container_memory_swap_bytes: int
    container_cpus_milli: int
    container_shm_bytes: int
    container_execution_timeout_seconds: int
    step229_source_chain_rerun: bool
    step229_rendered_receipt_accepted_as_provenance: bool
    step229_package_manifest_digest_bound: bool
    step229_isolation_document_digest_bound: bool
    exact_docker_cli_digest_bound: bool
    exact_content_addressed_image_bound: bool
    exact_image_config_and_rootfs_projection_validated: bool
    exact_node_binary_digest_bound: bool
    complete_source_prevalidation_before_candidate_daemon_access: bool
    image_pull_forbidden: bool
    registry_reference_execution_forbidden: bool
    docker_none_network_profile_required: bool
    applied_container_configuration_projection_validated: bool
    exact_node_entrypoint_and_arguments_validated: bool
    read_only_root_and_non_root_user_validated: bool
    capability_and_privilege_controls_validated: bool
    exact_single_read_only_bind_mount_validated: bool
    exact_resource_limits_validated: bool
    image_healthcheck_and_container_logging_disabled: bool
    exactly_one_start_and_zero_retry_sequence_validated: bool
    container_cleanup_success_evidence_required: bool
    exact_step228_zero_retry_stdout_validated: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    synthetic_container_execution_evidence: bool
    sealed_docker_execution_performed: bool
    sealed_candidate_docker_daemon_accessed: bool
    sealed_local_image_inspected: bool
    sealed_container_created: bool
    sealed_container_configuration_reinspected: bool
    sealed_node_binary_attested: bool
    sealed_container_started_once: bool
    sealed_container_removed: bool
    sealed_docker_none_network_applied: bool
    sealed_zero_retry_matrix_observed_in_container: bool
    sealed_temporary_filesystem_io_performed: bool
    sealed_local_container_process_performed: bool
    active_in_container_network_interface_inventory_checked: bool
    active_in_container_dns_denial_checked: bool
    active_in_container_tcp_denial_checked: bool
    loopback_behavior_checked: bool
    docker_daemon_identity_attested: bool
    docker_daemon_trustworthiness_checked: bool
    docker_daemon_background_side_effects_checked: bool
    image_signature_checked: bool
    image_sbom_checked: bool
    image_vulnerability_scan_checked: bool
    image_malware_scan_checked: bool
    container_escape_resistance_checked: bool
    host_kernel_integrity_checked: bool
    injected_transport_side_effects_checked: bool
    browser_runtime_checked: bool
    token_endpoint_cors_checked: bool
    msal_runtime_compatibility_approved: bool
    frontend_import_graph_checked: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    real_oauth_values_processed: bool
    runtime_pkce_or_token_exchange_executed: bool
    sealed_registry_or_provider_request_issued: bool
    sealed_application_configuration_mutation_performed: bool
    application_activation_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "execution_profile": PROFILE,
            "proof_status": STATUS,
            "docker_server_operating_system": CONTAINER_OPERATING_SYSTEM,
            "docker_server_architecture": CONTAINER_ARCHITECTURE,
            "node_version": NODE_VERSION,
            "container_network_mode": CONTAINER_NETWORK_MODE,
            "container_user": CONTAINER_USER,
            "approved_step229_package_manifest_sha256": (
                STEP229_PACKAGE_MANIFEST_SHA256
            ),
            "planned_docker_command_count": len(COMMAND_SEQUENCE),
            "container_pids_limit": CONTAINER_PIDS_LIMIT,
            "container_memory_bytes": CONTAINER_MEMORY_BYTES,
            "container_memory_swap_bytes": CONTAINER_MEMORY_SWAP_BYTES,
            "container_cpus_milli": CONTAINER_CPUS_MILLI,
            "container_shm_bytes": CONTAINER_SHM_BYTES,
            "container_execution_timeout_seconds": (
                CONTAINER_EXECUTION_TIMEOUT_SECONDS
            ),
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("container execution receipt constant is invalid")
        for name in (
            "execution_document_sha256",
            "step229_isolation_document_sha256",
            "step229_receipt_sha256",
            "docker_cli_sha256",
            "approved_node_executable_sha256",
            "docker_evidence_projection_sha256",
            "public_identity_summary_sha256",
            "image_projection_sha256",
            "container_before_projection_sha256",
            "container_after_projection_sha256",
            "command_sequence_sha256",
            "execution_stdout_sha256",
            "step228_execution_receipt_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("container execution evidence digest is invalid")
        if (
            type(self.approved_container_image_id) is not str
            or not self.approved_container_image_id.startswith("sha256:")
            or not _is_sha256(self.approved_container_image_id.removeprefix("sha256:"))
            or not _is_public_version_token(self.docker_server_version, 64)
            or not _is_public_version_token(self.docker_server_api_version, 32)
        ):
            raise ValueError("container execution public identity is invalid")
        if (
            type(self.image_layer_count) is not int
            or not 1 <= self.image_layer_count <= MAX_IMAGE_LAYERS
            or type(self.image_size_bytes) is not int
            or not 1 <= self.image_size_bytes <= MAX_IMAGE_BYTES
        ):
            raise ValueError("container execution image count is invalid")
        expected_public_identity = _framed(
            "public-identity",
            {
                "dockerServerVersion": self.docker_server_version,
                "dockerServerApiVersion": self.docker_server_api_version,
                "dockerCliSha256": self.docker_cli_sha256,
                "imageId": self.approved_container_image_id,
                "nodeExecutableSha256": self.approved_node_executable_sha256,
                "imageLayerCount": self.image_layer_count,
                "imageSizeBytes": self.image_size_bytes,
            },
        )
        if self.public_identity_summary_sha256 != expected_public_identity:
            raise ValueError("container execution public identity digest is invalid")
        live = self.sealed_docker_execution_performed
        if type(live) is not bool:
            raise ValueError("sealed Docker execution flag is invalid")
        if (
            type(self.synthetic_container_execution_evidence) is not bool
            or self.synthetic_container_execution_evidence is live
            or type(self.sealed_docker_command_count) is not int
            or self.sealed_docker_command_count
            != (len(COMMAND_SEQUENCE) if live else 0)
        ):
            raise ValueError("container execution provenance partition is invalid")
        structural_true = (
            "step229_source_chain_rerun",
            "step229_package_manifest_digest_bound",
            "step229_isolation_document_digest_bound",
            "exact_docker_cli_digest_bound",
            "exact_content_addressed_image_bound",
            "exact_image_config_and_rootfs_projection_validated",
            "exact_node_binary_digest_bound",
            "complete_source_prevalidation_before_candidate_daemon_access",
            "image_pull_forbidden",
            "registry_reference_execution_forbidden",
            "docker_none_network_profile_required",
            "applied_container_configuration_projection_validated",
            "exact_node_entrypoint_and_arguments_validated",
            "read_only_root_and_non_root_user_validated",
            "capability_and_privilege_controls_validated",
            "exact_single_read_only_bind_mount_validated",
            "exact_resource_limits_validated",
            "image_healthcheck_and_container_logging_disabled",
            "exactly_one_start_and_zero_retry_sequence_validated",
            "container_cleanup_success_evidence_required",
            "exact_step228_zero_retry_stdout_validated",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
        )
        correlated = (
            "sealed_candidate_docker_daemon_accessed",
            "sealed_local_image_inspected",
            "sealed_container_created",
            "sealed_container_configuration_reinspected",
            "sealed_node_binary_attested",
            "sealed_container_started_once",
            "sealed_container_removed",
            "sealed_docker_none_network_applied",
            "sealed_zero_retry_matrix_observed_in_container",
            "sealed_temporary_filesystem_io_performed",
            "sealed_local_container_process_performed",
        )
        deferred_false = (
            "step229_rendered_receipt_accepted_as_provenance",
            "active_in_container_network_interface_inventory_checked",
            "active_in_container_dns_denial_checked",
            "active_in_container_tcp_denial_checked",
            "loopback_behavior_checked",
            "docker_daemon_identity_attested",
            "docker_daemon_trustworthiness_checked",
            "docker_daemon_background_side_effects_checked",
            "image_signature_checked",
            "image_sbom_checked",
            "image_vulnerability_scan_checked",
            "image_malware_scan_checked",
            "container_escape_resistance_checked",
            "host_kernel_integrity_checked",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "sealed_registry_or_provider_request_issued",
            "sealed_application_configuration_mutation_performed",
            "application_activation_performed",
        )
        for name in structural_true:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required container execution fact is false")
        for name in correlated:
            if type(getattr(self, name)) is not bool or getattr(self, name) is not live:
                raise ValueError("sealed container execution correlation is invalid")
        for name in deferred_false:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred container execution fact is true")


def _parse_document(
    value: bytes,
) -> tuple[bytes, EntraCallingClientMSALZeroRetryContainerExecutionProofDocument]:
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError("container execution document size is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("container execution document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("container execution document JSON is invalid") from None
    document = (
        EntraCallingClientMSALZeroRetryContainerExecutionProofDocument.model_validate(
            raw
        )
    )
    return _canonical(document.model_dump(mode="json")), document


def _validate_actual_step228_stdout(
    *,
    evidence: EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
    step228_document: bytes,
    step227_document: bytes,
    step226_document: bytes,
    adapter: bytes,
    harness: bytes,
    runner: bytes,
) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt:
    def transport(
        _adapter: bytes,
        _harness: bytes,
        _runner: bytes,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence:
        return EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence(
            node_version=NODE_VERSION,
            node_executable_sha256=evidence.node_executable_sha256,
            stdout=evidence.stdout,
            stderr=evidence.stderr,
            exit_code=evidence.exit_code,
        )

    return prove_entra_calling_client_msal_zero_retry_network_client_execution(
        document=step228_document,
        step227_document=step227_document,
        step226_document=step226_document,
        adapter=adapter,
        harness=harness,
        runner=runner,
        execution_transport=transport,
    )


def _load_internal(
    *,
    document: object,
    step229_document: object,
    step228_document: object,
    step227_document: object,
    step226_document: object,
    adapter: object,
    harness: object,
    runner: object,
    docker_executable_path: object = None,
    execution_transport: object = None,
) -> EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt:
    byte_values = (
        document,
        step229_document,
        step228_document,
        step227_document,
        step226_document,
        adapter,
        harness,
        runner,
    )
    if any(type(value) is not bytes for value in byte_values):
        raise _ArgumentTypeError("exact container execution source bytes are required")
    if len({id(value) for value in byte_values}) != len(byte_values):
        raise ValueError("container execution source byte objects must be distinct")
    injected = execution_transport is not None
    if injected and docker_executable_path is not None:
        raise _ArgumentTypeError("synthetic execution cannot accept a Docker path")
    if not injected and type(docker_executable_path) is not str:
        raise _ArgumentTypeError("sealed execution requires a Docker path")
    if injected and not isinstance(execution_transport, Callable):
        raise _ArgumentTypeError("execution transport must be callable")
    prior = load_entra_calling_client_msal_zero_retry_container_isolation_readiness(
        step229_document,
        step228_document,
        step227_document,
        step226_document,
        adapter,
        harness,
        runner,
    )
    if (
        type(prior)
        is not EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt
        or not prior.offline_container_isolation_readiness_validated
        or prior.candidate_docker_daemon_accessed
        or prior.container_created
        or prior.package_selection_approved
    ):
        raise ValueError("Step 229 prerequisite state is invalid")
    prior_rendered = render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt(
        prior
    ).encode()
    canonical_document, validated = _parse_document(document)
    if canonical_document != document:
        raise ValueError("container execution document is not canonical")
    if (
        hashlib.sha256(step229_document).hexdigest()
        != validated.approved_step229_isolation_document_sha256
        or prior.isolation_document_sha256
        != validated.approved_step229_isolation_document_sha256
    ):
        raise ValueError("approved Step 229 isolation document changed")
    request = EntraCallingClientMSALZeroRetryContainerExecutionRequest(
        image_id=prior.approved_container_image_id,
        approved_docker_executable_sha256=(validated.approved_docker_executable_sha256),
        approved_node_executable_sha256=prior.approved_node_executable_sha256,
        adapter=adapter,
        harness=harness,
        runner=runner,
    )
    loader = EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        docker_executable_path=docker_executable_path,
        execution_transport=execution_transport,
    )
    evidence = loader.load(request)
    sealed = is_sealed_container_execution_evidence(evidence)
    if sealed is injected:
        raise ValueError("container execution evidence provenance is invalid")
    if (
        evidence.image_id != prior.approved_container_image_id
        or evidence.docker_cli_sha256 != validated.approved_docker_executable_sha256
        or evidence.node_executable_sha256 != prior.approved_node_executable_sha256
    ):
        raise ValueError("container execution evidence identity changed")
    projection = validate_container_execution_evidence(evidence)
    actual_step228 = _validate_actual_step228_stdout(
        evidence=evidence,
        step228_document=step228_document,
        step227_document=step227_document,
        step226_document=step226_document,
        adapter=adapter,
        harness=harness,
        runner=runner,
    )
    if (
        type(actual_step228)
        is not EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt
        or not actual_step228.synthetic_execution_evidence
        or actual_step228.sealed_node_execution_performed
        or not actual_step228.exact_scenario_matrix_validated
        or actual_step228.package_selection_approved
    ):
        raise ValueError("container zero-retry stdout projection is invalid")
    actual_rendered = json.dumps(
        {
            name: getattr(actual_step228, name)
            for name in actual_step228.__dataclass_fields__
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    structural_true = {
        name: True
        for name in (
            "step229_source_chain_rerun",
            "step229_package_manifest_digest_bound",
            "step229_isolation_document_digest_bound",
            "exact_docker_cli_digest_bound",
            "exact_content_addressed_image_bound",
            "exact_image_config_and_rootfs_projection_validated",
            "exact_node_binary_digest_bound",
            "complete_source_prevalidation_before_candidate_daemon_access",
            "image_pull_forbidden",
            "registry_reference_execution_forbidden",
            "docker_none_network_profile_required",
            "applied_container_configuration_projection_validated",
            "exact_node_entrypoint_and_arguments_validated",
            "read_only_root_and_non_root_user_validated",
            "capability_and_privilege_controls_validated",
            "exact_single_read_only_bind_mount_validated",
            "exact_resource_limits_validated",
            "image_healthcheck_and_container_logging_disabled",
            "exactly_one_start_and_zero_retry_sequence_validated",
            "container_cleanup_success_evidence_required",
            "exact_step228_zero_retry_stdout_validated",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
        )
    }
    live_values = {
        "synthetic_container_execution_evidence": injected,
        "sealed_docker_execution_performed": sealed,
        "sealed_candidate_docker_daemon_accessed": sealed,
        "sealed_local_image_inspected": sealed,
        "sealed_container_created": sealed,
        "sealed_container_configuration_reinspected": sealed,
        "sealed_node_binary_attested": sealed,
        "sealed_container_started_once": sealed,
        "sealed_container_removed": sealed,
        "sealed_docker_none_network_applied": sealed,
        "sealed_zero_retry_matrix_observed_in_container": sealed,
        "sealed_temporary_filesystem_io_performed": sealed,
        "sealed_local_container_process_performed": sealed,
    }
    deferred_false = {
        name: False
        for name in (
            "step229_rendered_receipt_accepted_as_provenance",
            "active_in_container_network_interface_inventory_checked",
            "active_in_container_dns_denial_checked",
            "active_in_container_tcp_denial_checked",
            "loopback_behavior_checked",
            "docker_daemon_identity_attested",
            "docker_daemon_trustworthiness_checked",
            "docker_daemon_background_side_effects_checked",
            "image_signature_checked",
            "image_sbom_checked",
            "image_vulnerability_scan_checked",
            "image_malware_scan_checked",
            "container_escape_resistance_checked",
            "host_kernel_integrity_checked",
            "injected_transport_side_effects_checked",
            "browser_runtime_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "sealed_registry_or_provider_request_issued",
            "sealed_application_configuration_mutation_performed",
            "application_activation_performed",
        )
    }
    image_projection = projection["image"]
    docker_projection = projection["docker"]
    return EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        execution_profile=PROFILE,
        proof_status=STATUS,
        docker_server_operating_system=docker_projection["os"],
        docker_server_architecture=docker_projection["architecture"],
        docker_server_version=docker_projection["version"],
        docker_server_api_version=docker_projection["apiVersion"],
        node_version=NODE_VERSION,
        container_network_mode=CONTAINER_NETWORK_MODE,
        container_user=CONTAINER_USER,
        approved_step229_package_manifest_sha256=(STEP229_PACKAGE_MANIFEST_SHA256),
        execution_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        step229_isolation_document_sha256=prior.isolation_document_sha256,
        step229_receipt_sha256=hashlib.sha256(prior_rendered).hexdigest(),
        docker_cli_sha256=evidence.docker_cli_sha256,
        approved_container_image_id=evidence.image_id,
        approved_node_executable_sha256=evidence.node_executable_sha256,
        docker_evidence_projection_sha256=_framed("evidence", projection),
        public_identity_summary_sha256=_framed(
            "public-identity",
            {
                "dockerServerVersion": docker_projection["version"],
                "dockerServerApiVersion": docker_projection["apiVersion"],
                "dockerCliSha256": evidence.docker_cli_sha256,
                "imageId": evidence.image_id,
                "nodeExecutableSha256": evidence.node_executable_sha256,
                "imageLayerCount": len(image_projection["layers"]),
                "imageSizeBytes": image_projection["size"],
            },
        ),
        image_projection_sha256=_framed("image", image_projection),
        container_before_projection_sha256=_framed("before", projection["before"]),
        container_after_projection_sha256=_framed("after", projection["after"]),
        command_sequence_sha256=_framed("commands", evidence.command_sequence),
        execution_stdout_sha256=hashlib.sha256(evidence.stdout).hexdigest(),
        step228_execution_receipt_sha256=hashlib.sha256(actual_rendered).hexdigest(),
        image_layer_count=len(image_projection["layers"]),
        image_size_bytes=image_projection["size"],
        planned_docker_command_count=len(COMMAND_SEQUENCE),
        sealed_docker_command_count=len(COMMAND_SEQUENCE) if sealed else 0,
        container_pids_limit=CONTAINER_PIDS_LIMIT,
        container_memory_bytes=CONTAINER_MEMORY_BYTES,
        container_memory_swap_bytes=CONTAINER_MEMORY_SWAP_BYTES,
        container_cpus_milli=CONTAINER_CPUS_MILLI,
        container_shm_bytes=CONTAINER_SHM_BYTES,
        container_execution_timeout_seconds=CONTAINER_EXECUTION_TIMEOUT_SECONDS,
        **structural_true,
        **live_values,
        **deferred_false,
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


def prove_entra_calling_client_msal_zero_retry_container_execution(
    *,
    document: object,
    step229_document: object,
    step228_document: object,
    step227_document: object,
    step226_document: object,
    adapter: object,
    harness: object,
    runner: object,
    docker_executable_path: object = None,
    execution_transport: object = None,
) -> EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt:
    """Validate injected evidence or execute one sealed Docker proof."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(
            document=document,
            step229_document=step229_document,
            step228_document=step228_document,
            step227_document=step227_document,
            step226_document=step226_document,
            adapter=adapter,
            harness=harness,
            runner=runner,
            docker_executable_path=docker_executable_path,
            execution_transport=execution_transport,
        )
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        document = None
        step229_document = None
        step228_document = None
        step227_document = None
        step226_document = None
        adapter = None
        harness = None
        runner = None
        docker_executable_path = None
        execution_transport = None
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
    if interrupted:
        raise KeyboardInterrupt("MSAL container execution proof interrupted")
    if terminated:
        raise SystemExit("MSAL container execution proof terminated")
    if invalid:
        raise TypeError("MSAL container execution proof input is invalid")
    if result is None:
        raise EntraCallingClientMSALZeroRetryContainerExecutionProbeError(
            "MSAL container execution proof failed"
        )
    return result


def render_entra_calling_client_msal_zero_retry_container_execution_receipt(
    receipt: EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt,
) -> str:
    """Render canonical privacy-minimized Step 230 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt
    ):
        raise TypeError("exact container execution receipt is required")
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
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "STEP229_PACKAGE_MANIFEST_SHA256",
    "EntraCallingClientMSALZeroRetryContainerExecutionProbeError",
    "EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt",
    "prove_entra_calling_client_msal_zero_retry_container_execution",
    "render_entra_calling_client_msal_zero_retry_container_execution_receipt",
]
