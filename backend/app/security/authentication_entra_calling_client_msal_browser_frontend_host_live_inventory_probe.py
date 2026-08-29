"""Step 233 controlled local Git frontend-host inventory proof contract."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_live_inventory_loader import (
    ACCEPTED_OVERLAY_PATH_COUNT,
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    LOCKFILE_MANAGERS,
    MAX_EVIDENCE_DOCUMENT_BYTES,
    STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP232_INVENTORY_LOADER_SHA256,
    STEP232_INVENTORY_PROBE_SHA256,
    STEP232_PACKAGE_MANIFEST_SHA256,
    EntraCallingClientMSALFrontendHostLiveInventoryLoaderError,
    load_entra_calling_client_msal_frontend_host_live_inventory,
)
from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_loader import (
    MAX_CANDIDATE_ROOTS,
    MAX_INSPECTED_FILES,
    MAX_PATH_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_INSPECTED_BYTES,
    MAX_TRACKED_PATHS,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_"
    "frontend_host_live_inventory_proof"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_local_git_frontend_host_inventory"
SCOPE = "exact_step232_state_plus_accepted_head_git_object_inventory"
PROFILE = "engineer4me_frontend_host_live_git_inventory_v2"
STATUS_NO_CANDIDATE = (
    "live_inventory_complete_no_package_manifest_candidate_in_accepted_source"
)
STATUS_SINGLE_CANDIDATE = (
    "live_inventory_complete_single_unselected_package_manifest_candidate"
)
MAX_PROOF_DOCUMENT_BYTES = 4096
MAX_CLI_ENVELOPE_BYTES = MAX_EVIDENCE_DOCUMENT_BYTES + MAX_PROOF_DOCUMENT_BYTES


class EntraCallingClientMSALFrontendHostLiveInventoryProbeError(ValueError):
    """Sanitized Step 233 live inventory proof failure."""


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


class EntraCallingClientMSALFrontendHostLiveInventoryProofDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_live_inventory_proof"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_controlled_local_git_frontend_host_inventory"]
    approved_step232_package_manifest_sha256: str
    approved_step232_accepted_state_manifest_sha256: str
    approved_step232_inventory_loader_sha256: str
    approved_step232_inventory_probe_sha256: str
    approved_branch: Literal["feature/phase-8"]
    approved_head: Literal["89b257fbd72333f17367be0aee82d6157775df33"]
    inventory_profile: Literal["engineer4me_frontend_host_live_git_inventory_v2"]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("frontend-host live inventory document must be exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step232_package_manifest_sha256": str,
            "approved_step232_accepted_state_manifest_sha256": str,
            "approved_step232_inventory_loader_sha256": str,
            "approved_step232_inventory_probe_sha256": str,
            "approved_branch": str,
            "approved_head": str,
            "inventory_profile": str,
        }
        if set(value) != set(expected) or any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("frontend-host live inventory document is not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALFrontendHostLiveInventoryProofDocument:
        expected = {
            "approved_step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
            "approved_step232_accepted_state_manifest_sha256": (
                STEP232_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step232_inventory_loader_sha256": (
                STEP232_INVENTORY_LOADER_SHA256
            ),
            "approved_step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected.items()
        ):
            raise ValueError("frontend-host live inventory identities are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    inventory_profile: str
    proof_status: str
    approved_branch: str
    approved_head: str
    evidence_provenance: str
    approved_step232_package_manifest_sha256: str
    approved_step232_accepted_state_manifest_sha256: str
    approved_step232_inventory_loader_sha256: str
    approved_step232_inventory_probe_sha256: str
    proof_document_sha256: str
    evidence_document_sha256: str
    head_tree_projection_sha256: str
    accepted_overlay_projection_sha256: str
    installer_asserted_combined_source_path_projection_sha256: str
    marker_inventory_projection_sha256: str
    candidate_root_projection_sha256: str
    git_executable_sha256: str
    working_tree_status_projection_sha256: str
    head_tree_path_count: int
    accepted_overlay_path_count: int
    combined_source_path_count: int
    marker_file_count: int
    marker_total_bytes: int
    candidate_root_count: int
    package_manifest_count: int
    dependency_lock_count: int
    observed_package_manager: str
    observed_lockfile_kind: str
    max_head_tree_paths: int
    max_accepted_overlay_paths: int
    max_candidate_roots: int
    max_marker_files: int
    max_path_bytes: int
    max_single_marker_bytes: int
    max_total_marker_bytes: int
    exact_step232_identities_bound: bool
    exact_branch_head_and_tree_bound: bool
    exact_accepted_overlay_bound: bool
    live_repository_inventory_performed: bool
    live_accepted_source_inventory_complete: bool
    before_after_accepted_source_projection_identical: bool
    git_object_reader_used: bool
    git_status_worktree_enumeration_performed: bool
    working_tree_marker_content_read: bool
    tracked_git_symlink_or_gitlink_observed: bool
    raw_path_or_file_content_emitted: bool
    rendered_receipt_is_independent_live_provenance: bool
    live_package_manifest_candidate_status_determined: bool
    no_package_manifest_candidate_identified: bool
    single_unselected_package_manifest_candidate_detected: bool
    qualifying_browser_frontend_host_confirmed: bool
    candidate_frontend_host_selected: bool
    host_decision_or_scaffold_required: bool
    package_manager_selected: bool
    package_manager_executed: bool
    remote_git_or_registry_operation_requested: bool
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
    step232_synthetic_live_provenance_separation_preserved: bool

    def __post_init__(self) -> None:
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "inventory_profile": PROFILE,
            "approved_branch": APPROVED_BRANCH,
            "approved_head": APPROVED_HEAD,
            "evidence_provenance": EVIDENCE_PROVENANCE,
            "approved_step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
            "approved_step232_accepted_state_manifest_sha256": (
                STEP232_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step232_inventory_loader_sha256": (
                STEP232_INVENTORY_LOADER_SHA256
            ),
            "approved_step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
            "accepted_overlay_projection_sha256": STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
            "accepted_overlay_path_count": ACCEPTED_OVERLAY_PATH_COUNT,
            "max_head_tree_paths": MAX_TRACKED_PATHS,
            "max_accepted_overlay_paths": ACCEPTED_OVERLAY_PATH_COUNT,
            "max_candidate_roots": MAX_CANDIDATE_ROOTS,
            "max_marker_files": MAX_INSPECTED_FILES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_single_marker_bytes": MAX_SINGLE_FILE_BYTES,
            "max_total_marker_bytes": MAX_TOTAL_INSPECTED_BYTES,
        }
        if any(getattr(self, name) != value for name, value in constants.items()):
            raise ValueError("frontend-host live inventory receipt constant is invalid")
        for name in (
            "schema_version",
            "accepted_overlay_path_count",
            "max_head_tree_paths",
            "max_accepted_overlay_paths",
            "max_candidate_roots",
            "max_marker_files",
            "max_path_bytes",
            "max_single_marker_bytes",
            "max_total_marker_bytes",
        ):
            if type(getattr(self, name)) is not int:
                raise ValueError("frontend-host live inventory receipt integer is invalid")
        if self.proof_status not in (STATUS_NO_CANDIDATE, STATUS_SINGLE_CANDIDATE):
            raise ValueError("frontend-host live inventory status is invalid")
        for name in (
            "proof_document_sha256",
            "evidence_document_sha256",
            "head_tree_projection_sha256",
            "accepted_overlay_projection_sha256",
            "installer_asserted_combined_source_path_projection_sha256",
            "marker_inventory_projection_sha256",
            "candidate_root_projection_sha256",
            "git_executable_sha256",
            "working_tree_status_projection_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("frontend-host live inventory receipt digest is invalid")
        counts = (
            "head_tree_path_count",
            "combined_source_path_count",
            "marker_file_count",
            "marker_total_bytes",
            "candidate_root_count",
            "package_manifest_count",
            "dependency_lock_count",
        )
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 0 for name in counts):
            raise ValueError("frontend-host live inventory receipt count is invalid")
        if (
            self.head_tree_path_count > MAX_TRACKED_PATHS
            or self.combined_source_path_count
            > MAX_TRACKED_PATHS + ACCEPTED_OVERLAY_PATH_COUNT
            or self.marker_file_count > MAX_INSPECTED_FILES
            or self.marker_total_bytes > MAX_TOTAL_INSPECTED_BYTES
            or self.candidate_root_count > MAX_CANDIDATE_ROOTS
            or self.package_manifest_count != self.candidate_root_count
            or self.dependency_lock_count > 1
            or self.no_package_manifest_candidate_identified
            == self.single_unselected_package_manifest_candidate_detected
            or type(self.no_package_manifest_candidate_identified) is not bool
            or type(self.single_unselected_package_manifest_candidate_detected)
            is not bool
            or self.no_package_manifest_candidate_identified
            != (self.candidate_root_count == 0)
            or self.single_unselected_package_manifest_candidate_detected
            != (self.candidate_root_count == 1)
            or (self.candidate_root_count == 0 and self.proof_status != STATUS_NO_CANDIDATE)
            or (self.candidate_root_count == 1 and self.proof_status != STATUS_SINGLE_CANDIDATE)
            or (
                self.candidate_root_count == 0
                and (
                    self.dependency_lock_count != 0
                    or self.observed_package_manager != "none"
                    or self.observed_lockfile_kind != "none"
                )
            )
            or (
                self.candidate_root_count == 1
                and self.dependency_lock_count == 0
                and (
                    self.observed_package_manager != "unknown"
                    or self.observed_lockfile_kind != "none"
                )
            )
            or (
                self.candidate_root_count == 1
                and self.dependency_lock_count == 1
                and (
                    self.observed_lockfile_kind not in LOCKFILE_MANAGERS
                    or self.observed_package_manager
                    != LOCKFILE_MANAGERS.get(self.observed_lockfile_kind)
                )
            )
        ):
            raise ValueError("frontend-host live inventory receipt correlation is invalid")

        required_true = (
            "exact_step232_identities_bound",
            "exact_branch_head_and_tree_bound",
            "exact_accepted_overlay_bound",
            "live_repository_inventory_performed",
            "live_accepted_source_inventory_complete",
            "before_after_accepted_source_projection_identical",
            "git_object_reader_used",
            "git_status_worktree_enumeration_performed",
            "live_package_manifest_candidate_status_determined",
            "host_decision_or_scaffold_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "step230_container_proof_boundary_preserved",
            "step231_dependency_lock_plan_preserved",
            "step232_synthetic_live_provenance_separation_preserved",
        )
        required_false = (
            "working_tree_marker_content_read",
            "tracked_git_symlink_or_gitlink_observed",
            "raw_path_or_file_content_emitted",
            "rendered_receipt_is_independent_live_provenance",
            "qualifying_browser_frontend_host_confirmed",
            "candidate_frontend_host_selected",
            "package_manager_selected",
            "package_manager_executed",
            "remote_git_or_registry_operation_requested",
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
        if any(type(getattr(self, name)) is not bool or not getattr(self, name) for name in required_true):
            raise ValueError("frontend-host live inventory required control is invalid")
        if any(type(getattr(self, name)) is not bool or getattr(self, name) for name in required_false):
            raise ValueError("frontend-host live inventory deferred control is invalid")


def prove_entra_calling_client_msal_frontend_host_live_inventory(
    document: bytes,
    evidence_document: bytes,
) -> EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt:
    """Bind one exact document to one controlled-installer live projection."""

    try:
        if type(document) is not bytes or not document or len(document) > MAX_PROOF_DOCUMENT_BYTES:
            raise ValueError("frontend-host live inventory proof document size is invalid")
        parsed = json.loads(document, object_pairs_hook=_pairs)
        model = EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
            parsed
        )
        evidence, result = load_entra_calling_client_msal_frontend_host_live_inventory(
            evidence_document
        )
        canonical_document = _canonical(model.model_dump(mode="json"))
        status = (
            STATUS_NO_CANDIDATE
            if result.candidate_root_count == 0
            else STATUS_SINGLE_CANDIDATE
        )
        return EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            inventory_profile=PROFILE,
            proof_status=status,
            approved_branch=APPROVED_BRANCH,
            approved_head=APPROVED_HEAD,
            evidence_provenance=EVIDENCE_PROVENANCE,
            approved_step232_package_manifest_sha256=STEP232_PACKAGE_MANIFEST_SHA256,
            approved_step232_accepted_state_manifest_sha256=(
                STEP232_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            approved_step232_inventory_loader_sha256=STEP232_INVENTORY_LOADER_SHA256,
            approved_step232_inventory_probe_sha256=STEP232_INVENTORY_PROBE_SHA256,
            proof_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            evidence_document_sha256=result.evidence_document_sha256,
            head_tree_projection_sha256=result.head_tree_projection_sha256,
            accepted_overlay_projection_sha256=result.accepted_overlay_projection_sha256,
            installer_asserted_combined_source_path_projection_sha256=(
                result.installer_asserted_combined_source_path_projection_sha256
            ),
            marker_inventory_projection_sha256=result.marker_inventory_projection_sha256,
            candidate_root_projection_sha256=result.candidate_root_projection_sha256,
            git_executable_sha256=result.git_executable_sha256,
            working_tree_status_projection_sha256=(
                result.working_tree_status_projection_sha256
            ),
            head_tree_path_count=result.head_tree_path_count,
            accepted_overlay_path_count=result.accepted_overlay_path_count,
            combined_source_path_count=result.combined_source_path_count,
            marker_file_count=result.marker_file_count,
            marker_total_bytes=result.marker_total_bytes,
            candidate_root_count=result.candidate_root_count,
            package_manifest_count=result.package_manifest_count,
            dependency_lock_count=result.dependency_lock_count,
            observed_package_manager=result.package_manager,
            observed_lockfile_kind=result.lockfile_kind,
            max_head_tree_paths=MAX_TRACKED_PATHS,
            max_accepted_overlay_paths=ACCEPTED_OVERLAY_PATH_COUNT,
            max_candidate_roots=MAX_CANDIDATE_ROOTS,
            max_marker_files=MAX_INSPECTED_FILES,
            max_path_bytes=MAX_PATH_BYTES,
            max_single_marker_bytes=MAX_SINGLE_FILE_BYTES,
            max_total_marker_bytes=MAX_TOTAL_INSPECTED_BYTES,
            exact_step232_identities_bound=True,
            exact_branch_head_and_tree_bound=True,
            exact_accepted_overlay_bound=True,
            live_repository_inventory_performed=evidence.live_repository_accessed,
            live_accepted_source_inventory_complete=True,
            before_after_accepted_source_projection_identical=(
                evidence.before_after_accepted_source_projection_identical
            ),
            git_object_reader_used=(
                evidence.git_object_bytes_read_only_for_allowlisted_markers
            ),
            git_status_worktree_enumeration_performed=(
                evidence.git_status_worktree_enumeration_performed
            ),
            working_tree_marker_content_read=evidence.working_tree_marker_content_read,
            tracked_git_symlink_or_gitlink_observed=(
                evidence.tracked_git_symlink_or_gitlink_observed
            ),
            raw_path_or_file_content_emitted=False,
            rendered_receipt_is_independent_live_provenance=False,
            live_package_manifest_candidate_status_determined=True,
            no_package_manifest_candidate_identified=result.candidate_root_count == 0,
            single_unselected_package_manifest_candidate_detected=(
                result.candidate_root_count == 1
            ),
            qualifying_browser_frontend_host_confirmed=False,
            candidate_frontend_host_selected=False,
            host_decision_or_scaffold_required=True,
            package_manager_selected=False,
            package_manager_executed=False,
            remote_git_or_registry_operation_requested=False,
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
            step232_synthetic_live_provenance_separation_preserved=True,
        )
    except (
        TypeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        EntraCallingClientMSALFrontendHostLiveInventoryLoaderError,
    ) as error:
        raise EntraCallingClientMSALFrontendHostLiveInventoryProbeError(
            "controlled local frontend-host live inventory proof failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_live_inventory_receipt(
    receipt: EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt,
) -> bytes:
    """Render one exact path-free receipt as canonical UTF-8 JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt:
        raise TypeError("exact frontend-host live inventory receipt is required")
    receipt.__post_init__()
    return _canonical(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
    )


def main() -> int:
    """Read one in-memory envelope from stdin and emit one path-free receipt."""

    try:
        envelope_bytes = sys.stdin.buffer.read(MAX_CLI_ENVELOPE_BYTES + 1)
        if not envelope_bytes or len(envelope_bytes) > MAX_CLI_ENVELOPE_BYTES:
            raise ValueError("CLI envelope size is invalid")
        envelope = json.loads(envelope_bytes, object_pairs_hook=_pairs)
        if type(envelope) is not dict or set(envelope) != {"document", "evidence"}:
            raise ValueError("CLI envelope is invalid")
        receipt = prove_entra_calling_client_msal_frontend_host_live_inventory(
            _canonical(envelope["document"]),
            _canonical(envelope["evidence"]),
        )
        sys.stdout.buffer.write(
            render_entra_calling_client_msal_frontend_host_live_inventory_receipt(
                receipt
            )
            + b"\n"
        )
        return 0
    except Exception:
        sys.stderr.write("controlled local frontend-host live inventory CLI failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DOCUMENT_TYPE",
    "MAX_CLI_ENVELOPE_BYTES",
    "MAX_PROOF_DOCUMENT_BYTES",
    "PROFILE",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SCOPE",
    "SOURCE",
    "STATUS_NO_CANDIDATE",
    "STATUS_SINGLE_CANDIDATE",
    "EntraCallingClientMSALFrontendHostLiveInventoryProbeError",
    "EntraCallingClientMSALFrontendHostLiveInventoryProofDocument",
    "EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt",
    "main",
    "prove_entra_calling_client_msal_frontend_host_live_inventory",
    "render_entra_calling_client_msal_frontend_host_live_inventory_receipt",
]
