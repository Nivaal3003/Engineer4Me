"""Step 232 bounded frontend-host inventory proof contract.

Only exact synthetic evidence is accepted in this step.  The resulting receipt
validates the future inventory contract but never claims live repository or
frontend-host provenance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_loader import (
    ALLOWED_LOCKFILE_KINDS,
    ALLOWED_PACKAGE_MANAGERS,
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    MAX_CANDIDATE_ROOTS,
    MAX_INSPECTED_FILES,
    MAX_PATH_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_INSPECTED_BYTES,
    MAX_TRACKED_PATHS,
    EntraCallingClientMSALFrontendHostInventoryEvidence,
    validate_entra_calling_client_msal_frontend_host_inventory_evidence,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_"
    "frontend_host_inventory_proof"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_frontend_host_inventory_proof_api"
SCOPE = "exact_step231_state_and_bounded_synthetic_frontend_host_inventory"
PROFILE = "engineer4me_frontend_host_inventory_proof_v1"
STATUS = "synthetic_inventory_validated_live_frontend_host_undetermined"

STEP231_PACKAGE_MANIFEST_SHA256 = (
    "d23f9bb5b1ee336403251404c65c57b5d854c889f5368a1a460e88139a5c8873"
)
STEP231_DEPENDENCY_LOCK_READINESS_SHA256 = (
    "25a22ccba2a5aa6f656fb7a3629d81173af5f7ecfe9daecefec2581cde0b8119"
)
STEP231_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "9ef658e4a2af573ff0a6e42118ec9313686f3abb7e847efdb43df8598bc186ba"
)
ZERO_RETRY_NETWORK_CLIENT_SHA256 = (
    "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
)
MAX_DOCUMENT_BYTES = 4096


class EntraCallingClientMSALFrontendHostInventoryProbeError(ValueError):
    """Sanitized Step 232 proof failure."""


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
    ).encode("utf-8")


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step232-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALFrontendHostInventoryProofDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_inventory_proof"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_controlled_frontend_host_inventory_proof_api"]
    approved_step231_package_manifest_sha256: str
    approved_step231_dependency_lock_readiness_sha256: str
    approved_step231_accepted_state_manifest_sha256: str
    approved_zero_retry_network_client_sha256: str
    approved_branch: Literal["feature/phase-8"]
    approved_head: Literal["89b257fbd72333f17367be0aee82d6157775df33"]
    inventory_profile: Literal["engineer4me_frontend_host_inventory_proof_v1"]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("frontend-host inventory proof document must be exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step231_package_manifest_sha256": str,
            "approved_step231_dependency_lock_readiness_sha256": str,
            "approved_step231_accepted_state_manifest_sha256": str,
            "approved_zero_retry_network_client_sha256": str,
            "approved_branch": str,
            "approved_head": str,
            "inventory_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("frontend-host inventory proof document keys are not exact")
        if any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("frontend-host inventory proof document types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALFrontendHostInventoryProofDocument:
        expected = {
            "approved_step231_package_manifest_sha256": (
                STEP231_PACKAGE_MANIFEST_SHA256
            ),
            "approved_step231_dependency_lock_readiness_sha256": (
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
            ),
            "approved_step231_accepted_state_manifest_sha256": (
                STEP231_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_zero_retry_network_client_sha256": (
                ZERO_RETRY_NETWORK_CLIENT_SHA256
            ),
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected.items()
        ):
            raise ValueError("frontend-host inventory proof identities are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostInventoryProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    inventory_profile: str
    proof_status: str
    approved_branch: str
    approved_head: str
    evidence_provenance: str
    approved_step231_package_manifest_sha256: str
    approved_step231_dependency_lock_readiness_sha256: str
    approved_step231_accepted_state_manifest_sha256: str
    approved_zero_retry_network_client_sha256: str
    proof_document_sha256: str
    evidence_projection_sha256: str
    repository_identity_projection_sha256: str
    candidate_projection_sha256: str
    file_inventory_projection_sha256: str
    policy_limits_sha256: str
    synthetic_tracked_path_count: int
    synthetic_candidate_root_count: int
    synthetic_inventory_file_count: int
    synthetic_inventory_total_bytes: int
    synthetic_package_manager: str
    synthetic_lockfile_kind: str
    max_tracked_paths: int
    max_candidate_roots: int
    max_inspected_files: int
    max_path_bytes: int
    max_single_file_bytes: int
    max_total_inspected_bytes: int
    exact_step231_identities_bound: bool
    exact_branch_and_head_bound: bool
    exact_zero_retry_adapter_digest_bound: bool
    exact_synthetic_evidence_type_required: bool
    synthetic_evidence_validated: bool
    synthetic_and_live_provenance_mutually_exclusive: bool
    git_tracked_projection_required: bool
    canonical_relative_paths_required: bool
    case_collision_rejection_required: bool
    traversal_and_absolute_path_rejection_required: bool
    symlink_and_reparse_rejection_required: bool
    submodule_and_nested_repository_rejection_required: bool
    untracked_content_rejection_required: bool
    sensitive_path_and_environment_content_rejection_required: bool
    single_candidate_root_limit_required: bool
    single_package_manager_and_lockfile_limit_required: bool
    bounded_path_file_and_byte_limits_required: bool
    raw_file_content_omitted_from_receipt: bool
    successor_live_inventory_required: bool
    rendered_receipt_accepted_as_live_provenance: bool
    live_repository_inventory_performed: bool
    live_frontend_host_status_determined: bool
    live_candidate_frontend_host_detected: bool
    candidate_frontend_host_selected: bool
    package_manager_selected: bool
    package_manager_executed: bool
    registry_access_performed: bool
    package_manifest_created_or_modified: bool
    lockfile_created_or_modified: bool
    dependency_installed: bool
    frontend_source_modified: bool
    browser_bundle_built: bool
    browser_runtime_executed: bool
    real_oauth_values_processed: bool
    application_configuration_modified: bool
    application_activated: bool
    operational_write_performed: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    step230_container_proof_boundary_preserved: bool
    step231_dependency_lock_plan_preserved: bool

    def __post_init__(self) -> None:
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "inventory_profile": PROFILE,
            "proof_status": STATUS,
            "approved_branch": APPROVED_BRANCH,
            "approved_head": APPROVED_HEAD,
            "evidence_provenance": EVIDENCE_PROVENANCE,
            "approved_step231_package_manifest_sha256": (
                STEP231_PACKAGE_MANIFEST_SHA256
            ),
            "approved_step231_dependency_lock_readiness_sha256": (
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
            ),
            "approved_step231_accepted_state_manifest_sha256": (
                STEP231_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_zero_retry_network_client_sha256": (
                ZERO_RETRY_NETWORK_CLIENT_SHA256
            ),
            "max_tracked_paths": MAX_TRACKED_PATHS,
            "max_candidate_roots": MAX_CANDIDATE_ROOTS,
            "max_inspected_files": MAX_INSPECTED_FILES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_single_file_bytes": MAX_SINGLE_FILE_BYTES,
            "max_total_inspected_bytes": MAX_TOTAL_INSPECTED_BYTES,
        }
        if any(getattr(self, name) != value for name, value in constants.items()):
            raise ValueError("frontend-host inventory receipt constant is invalid")
        for name in (
            "proof_document_sha256",
            "evidence_projection_sha256",
            "repository_identity_projection_sha256",
            "candidate_projection_sha256",
            "file_inventory_projection_sha256",
            "policy_limits_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("frontend-host inventory receipt digest is invalid")
        integer_fields = (
            "synthetic_tracked_path_count",
            "synthetic_candidate_root_count",
            "synthetic_inventory_file_count",
            "synthetic_inventory_total_bytes",
        )
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 0 for name in integer_fields):
            raise ValueError("frontend-host inventory receipt count is invalid")
        if (
            self.synthetic_tracked_path_count > MAX_TRACKED_PATHS
            or self.synthetic_candidate_root_count > MAX_CANDIDATE_ROOTS
            or self.synthetic_inventory_file_count > MAX_INSPECTED_FILES
            or self.synthetic_inventory_total_bytes > MAX_TOTAL_INSPECTED_BYTES
            or self.synthetic_inventory_file_count > self.synthetic_tracked_path_count
            or self.synthetic_package_manager not in ALLOWED_PACKAGE_MANAGERS
            or self.synthetic_lockfile_kind not in ALLOWED_LOCKFILE_KINDS
            or (
                self.synthetic_candidate_root_count == 0
                and (
                    self.synthetic_package_manager != "none"
                    or self.synthetic_lockfile_kind != "none"
                    or self.synthetic_inventory_file_count != 0
                )
            )
            or (
                self.synthetic_candidate_root_count == 1
                and self.synthetic_package_manager == "none"
            )
        ):
            raise ValueError("frontend-host inventory receipt correlation is invalid")

        required_true = (
            "exact_step231_identities_bound",
            "exact_branch_and_head_bound",
            "exact_zero_retry_adapter_digest_bound",
            "exact_synthetic_evidence_type_required",
            "synthetic_evidence_validated",
            "synthetic_and_live_provenance_mutually_exclusive",
            "git_tracked_projection_required",
            "canonical_relative_paths_required",
            "case_collision_rejection_required",
            "traversal_and_absolute_path_rejection_required",
            "symlink_and_reparse_rejection_required",
            "submodule_and_nested_repository_rejection_required",
            "untracked_content_rejection_required",
            "sensitive_path_and_environment_content_rejection_required",
            "single_candidate_root_limit_required",
            "single_package_manager_and_lockfile_limit_required",
            "bounded_path_file_and_byte_limits_required",
            "raw_file_content_omitted_from_receipt",
            "successor_live_inventory_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "step230_container_proof_boundary_preserved",
            "step231_dependency_lock_plan_preserved",
        )
        required_false = (
            "rendered_receipt_accepted_as_live_provenance",
            "live_repository_inventory_performed",
            "live_frontend_host_status_determined",
            "live_candidate_frontend_host_detected",
            "candidate_frontend_host_selected",
            "package_manager_selected",
            "package_manager_executed",
            "registry_access_performed",
            "package_manifest_created_or_modified",
            "lockfile_created_or_modified",
            "dependency_installed",
            "frontend_source_modified",
            "browser_bundle_built",
            "browser_runtime_executed",
            "real_oauth_values_processed",
            "application_configuration_modified",
            "application_activated",
            "operational_write_performed",
        )
        if any(
            type(getattr(self, name)) is not bool or not getattr(self, name)
            for name in required_true
        ):
            raise ValueError("frontend-host inventory required control is not true")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError("frontend-host inventory deferred control is not false")


def prove_entra_calling_client_msal_frontend_host_inventory(
    document: bytes,
    evidence: EntraCallingClientMSALFrontendHostInventoryEvidence,
) -> EntraCallingClientMSALFrontendHostInventoryProofReceipt:
    """Validate the Step 232 document and exact synthetic inventory evidence."""

    try:
        if type(document) is not bytes:
            raise TypeError("document must be exact bytes")
        if not document or len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError("frontend-host inventory proof document size is invalid")
        parsed = json.loads(document, object_pairs_hook=_pairs)
        model = EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(
            parsed
        )
        validated = validate_entra_calling_client_msal_frontend_host_inventory_evidence(
            evidence
        )
        canonical_document = _canonical(model.model_dump(mode="json"))
        repository_identity = {
            "branch": validated.branch,
            "head": validated.head,
            "repository_root_sha256": validated.repository_root_sha256,
            "tracked_path_count": validated.tracked_path_count,
        }
        candidates = {
            "candidate_roots": validated.candidate_roots,
            "package_manager": validated.package_manager,
            "lockfile_kind": validated.lockfile_kind,
        }
        file_inventory = tuple(
            {
                "path": item.path,
                "role": item.role,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
            }
            for item in validated.files
        )
        evidence_projection = {
            "repository_identity": repository_identity,
            "candidates": candidates,
            "file_inventory": file_inventory,
            "git_tracked_projection_complete": (
                validated.git_tracked_projection_complete
            ),
            "side_effects": {
                "live_repository_accessed": validated.live_repository_accessed,
                "filesystem_io_performed": validated.filesystem_io_performed,
                "git_process_started": validated.git_process_started,
                "package_manager_process_started": (
                    validated.package_manager_process_started
                ),
                "network_io_performed": validated.network_io_performed,
                "repository_mutation_performed": (
                    validated.repository_mutation_performed
                ),
            },
        }
        limits = {
            "max_tracked_paths": MAX_TRACKED_PATHS,
            "max_candidate_roots": MAX_CANDIDATE_ROOTS,
            "max_inspected_files": MAX_INSPECTED_FILES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_single_file_bytes": MAX_SINGLE_FILE_BYTES,
            "max_total_inspected_bytes": MAX_TOTAL_INSPECTED_BYTES,
        }
        return EntraCallingClientMSALFrontendHostInventoryProofReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            inventory_profile=PROFILE,
            proof_status=STATUS,
            approved_branch=APPROVED_BRANCH,
            approved_head=APPROVED_HEAD,
            evidence_provenance=EVIDENCE_PROVENANCE,
            approved_step231_package_manifest_sha256=(
                STEP231_PACKAGE_MANIFEST_SHA256
            ),
            approved_step231_dependency_lock_readiness_sha256=(
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
            ),
            approved_step231_accepted_state_manifest_sha256=(
                STEP231_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            approved_zero_retry_network_client_sha256=(
                ZERO_RETRY_NETWORK_CLIENT_SHA256
            ),
            proof_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            evidence_projection_sha256=_framed(
                "inventory-evidence-projection", evidence_projection
            ),
            repository_identity_projection_sha256=_framed(
                "repository-identity", repository_identity
            ),
            candidate_projection_sha256=_framed("candidate-projection", candidates),
            file_inventory_projection_sha256=_framed(
                "file-inventory", file_inventory
            ),
            policy_limits_sha256=_framed("policy-limits", limits),
            synthetic_tracked_path_count=validated.tracked_path_count,
            synthetic_candidate_root_count=len(validated.candidate_roots),
            synthetic_inventory_file_count=len(validated.files),
            synthetic_inventory_total_bytes=sum(
                item.size_bytes for item in validated.files
            ),
            synthetic_package_manager=validated.package_manager,
            synthetic_lockfile_kind=validated.lockfile_kind,
            max_tracked_paths=MAX_TRACKED_PATHS,
            max_candidate_roots=MAX_CANDIDATE_ROOTS,
            max_inspected_files=MAX_INSPECTED_FILES,
            max_path_bytes=MAX_PATH_BYTES,
            max_single_file_bytes=MAX_SINGLE_FILE_BYTES,
            max_total_inspected_bytes=MAX_TOTAL_INSPECTED_BYTES,
            exact_step231_identities_bound=True,
            exact_branch_and_head_bound=True,
            exact_zero_retry_adapter_digest_bound=True,
            exact_synthetic_evidence_type_required=True,
            synthetic_evidence_validated=True,
            synthetic_and_live_provenance_mutually_exclusive=True,
            git_tracked_projection_required=True,
            canonical_relative_paths_required=True,
            case_collision_rejection_required=True,
            traversal_and_absolute_path_rejection_required=True,
            symlink_and_reparse_rejection_required=True,
            submodule_and_nested_repository_rejection_required=True,
            untracked_content_rejection_required=True,
            sensitive_path_and_environment_content_rejection_required=True,
            single_candidate_root_limit_required=True,
            single_package_manager_and_lockfile_limit_required=True,
            bounded_path_file_and_byte_limits_required=True,
            raw_file_content_omitted_from_receipt=True,
            successor_live_inventory_required=True,
            rendered_receipt_accepted_as_live_provenance=False,
            live_repository_inventory_performed=False,
            live_frontend_host_status_determined=False,
            live_candidate_frontend_host_detected=False,
            candidate_frontend_host_selected=False,
            package_manager_selected=False,
            package_manager_executed=False,
            registry_access_performed=False,
            package_manifest_created_or_modified=False,
            lockfile_created_or_modified=False,
            dependency_installed=False,
            frontend_source_modified=False,
            browser_bundle_built=False,
            browser_runtime_executed=False,
            real_oauth_values_processed=False,
            application_configuration_modified=False,
            application_activated=False,
            operational_write_performed=False,
            step216_zero_retry_policy_preserved=True,
            step225_default_retry_rejection_preserved=True,
            step230_container_proof_boundary_preserved=True,
            step231_dependency_lock_plan_preserved=True,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostInventoryProbeError(
            "frontend-host inventory proof validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_inventory_receipt(
    receipt: EntraCallingClientMSALFrontendHostInventoryProofReceipt,
) -> bytes:
    """Render one exact validated receipt as canonical UTF-8 JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostInventoryProofReceipt:
        raise TypeError("exact frontend-host inventory proof receipt is required")
    receipt.__post_init__()
    return _canonical(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
    )


__all__ = [
    "DOCUMENT_TYPE",
    "MAX_DOCUMENT_BYTES",
    "PROFILE",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SCOPE",
    "SOURCE",
    "STATUS",
    "STEP231_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP231_DEPENDENCY_LOCK_READINESS_SHA256",
    "STEP231_PACKAGE_MANIFEST_SHA256",
    "ZERO_RETRY_NETWORK_CLIENT_SHA256",
    "EntraCallingClientMSALFrontendHostInventoryProbeError",
    "EntraCallingClientMSALFrontendHostInventoryProofDocument",
    "EntraCallingClientMSALFrontendHostInventoryProofReceipt",
    "prove_entra_calling_client_msal_frontend_host_inventory",
    "render_entra_calling_client_msal_frontend_host_inventory_receipt",
]
