"""Step 234 offline frontend-host scaffold decision readiness contract.

This module binds the exact accepted Step 233 no-host receipt to a desired-state
decision for one future, dedicated browser-SPA root.  It performs no filesystem,
Git, subprocess, package-manager, browser, configuration, or network operation.
It neither creates nor selects an executable scaffold implementation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_"
    "frontend_host_scaffold_decision_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_offline_frontend_host_scaffold_decision_readiness"
SCOPE = "accepted_step233_no_host_receipt_and_non_materializing_scaffold_plan"
STATUS = "frontend_host_scaffold_decision_plan_validated_creation_remains_blocked"

STEP233_PACKAGE_MANIFEST_SHA256 = (
    "9d03b211b337af98091f9dcccc170495f00b51ddb38c9e4012cce66a67bd09ab"
)
STEP233_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "66ed35cf82aec4cde3d1da4f1fd8320df4b5e8176ae9893427928e6cde20362a"
)
STEP233_LIVE_INVENTORY_LOADER_SHA256 = (
    "84d4462b2e8427fec9fab795abb6415f13839b83a7299df9224c5006ca228e78"
)
STEP233_LIVE_INVENTORY_PROBE_SHA256 = (
    "ef2559bc969d67c4dd2a4868758f6cf64600ba7cff574e7c876dcc5bc14d22b1"
)
STEP233_NO_HOST_RECEIPT_SHA256 = (
    "13cb560199f82d684c14ffdb662db413e7e1d2a43beaa519f9c90b17770edc20"
)
STEP233_INVENTORY_PROFILE = "engineer4me_frontend_host_live_git_inventory_v2"
STEP233_NO_HOST_STATUS = (
    "live_inventory_complete_no_package_manifest_candidate_in_accepted_source"
)
STEP233_PROOF_DOCUMENT_SHA256 = (
    "f108d9c1e6fc2b6f085b2fcaa9066b83ee8a3bdfce3a33cc9dba6456d8361361"
)
STEP233_EVIDENCE_DOCUMENT_SHA256 = (
    "2eb3513efd4cda4bbfab5dee826906280b2448ecdd8ea6178565633174c52063"
)
STEP233_HEAD_TREE_PROJECTION_SHA256 = (
    "bd16c72d7b02c9621acb9776ab3eb6a52cfe08ad1739e21b45e469dd73f4a923"
)
STEP233_COMBINED_SOURCE_PROJECTION_SHA256 = (
    "7425d79f46255bcd28faa370980882eb8de9e819e8c1842054f22917da8e7d1b"
)
STEP233_MARKER_INVENTORY_PROJECTION_SHA256 = (
    "a71e98eac1a0876cb5c199433c4b66310a424b7f4125aafc60c817336a6845b8"
)
STEP233_CANDIDATE_ROOT_PROJECTION_SHA256 = (
    "c11878691b87261506147ba2389aa113f726a5711b132357f2131fd3ee0b1dfe"
)
STEP233_WORKING_TREE_STATUS_PROJECTION_SHA256 = (
    "0ccb21d1581c8dc669f6b88e8a73db296855dd6ee6de80d818890a5943061ccb"
)
STEP233_HEAD_TREE_PATH_COUNT = 268
STEP233_ACCEPTED_OVERLAY_PATH_COUNT = 220
STEP233_COMBINED_SOURCE_PATH_COUNT = 484
STEP233_MARKER_FILE_COUNT = 0
STEP233_CANDIDATE_ROOT_COUNT = 0
STEP233_PACKAGE_MANIFEST_COUNT = 0
STEP233_DEPENDENCY_LOCK_COUNT = 0

STEP231_DEPENDENCY_LOCK_READINESS_SHA256 = (
    "25a22ccba2a5aa6f656fb7a3629d81173af5f7ecfe9daecefec2581cde0b8119"
)
ZERO_RETRY_NETWORK_CLIENT_SHA256 = (
    "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
)
MSAL_BROWSER_PACKAGE = "@azure/msal-browser"
MSAL_BROWSER_VERSION = "5.18.0"
MSAL_COMMON_PACKAGE = "@azure/msal-common"
MSAL_COMMON_VERSION = "16.12.0"
NETWORK_CLIENT_CONFIGURATION_SEAM = "system.networkClient"

SCAFFOLD_TARGET_ROOT = "frontend"
SCAFFOLD_APPLICATION_MODEL = "static_browser_spa"
SCAFFOLD_LANGUAGE = "typescript"
DESIRED_PACKAGE_MANAGER = "npm"
DESIRED_LOCKFILE_NAME = "package-lock.json"
DESIRED_LOCKFILE_VERSION = 3
SCAFFOLD_MODE = "offline_desired_state_only_no_materialization"
FRAMEWORK_SELECTION = "unselected"
BUNDLER_SELECTION = "unselected"
PLANNED_SCAFFOLD_PATHS = (
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/index.html",
    "frontend/tsconfig.json",
    "frontend/src/main.ts",
)
DEFERRED_GATES = (
    "atomic_scaffold_materialization_with_target_containment_collision_case_ambiguity_symlink_reparse_absence_and_race_rechecks",
    "exact_framework_and_bundler_artifact_proof",
    "frozen_npm_lock_generation_and_dependency_tree_validation",
    "deploy_time_public_client_configuration_binding",
    "exact_redirect_uri_and_api_origin_cors_decision",
    "content_security_policy_and_security_header_validation",
    "mobile_first_responsive_and_accessibility_validation",
    "browser_bundle_import_graph_proof",
    "browser_cors_proof",
    "pkce_and_callback_journey_proof",
)
READINESS_DOCUMENT_SHA256 = (
    "275edba62b536bd2849c8e951c23db8a591a119c788d563bf8e77e8a1cf5b321"
)
SCAFFOLD_PLAN_SHA256 = (
    "6e2f30dedf03555d8ae6ff1bf4705328ad0b0f21181f418065ee4195aa404fbb"
)
SECURITY_INTEGRATION_PLAN_SHA256 = (
    "c2ec07fe27dc8937cee4f81e25470073d007bf981333574d84319990b5d452fd"
)
DEFERRED_GATE_PLAN_SHA256 = (
    "1bc72efd3aab404b6574365f5946a7092451d868d2f3595307c91aa2f711526a"
)

MAX_DOCUMENT_BYTES = 4096
MAX_STEP233_RECEIPT_BYTES = 8192

_STEP233_RECEIPT_KEYS = {
    "accepted_overlay_path_count",
    "accepted_overlay_projection_sha256",
    "application_activated",
    "application_configuration_modified",
    "approved_branch",
    "approved_head",
    "approved_step232_accepted_state_manifest_sha256",
    "approved_step232_inventory_loader_sha256",
    "approved_step232_inventory_probe_sha256",
    "approved_step232_package_manifest_sha256",
    "before_after_accepted_source_projection_identical",
    "browser_bundle_built",
    "browser_runtime_executed",
    "candidate_frontend_host_selected",
    "candidate_root_count",
    "candidate_root_projection_sha256",
    "combined_source_path_count",
    "dependency_installed",
    "dependency_lock_count",
    "evidence_document_sha256",
    "evidence_provenance",
    "exact_accepted_overlay_bound",
    "exact_branch_head_and_tree_bound",
    "exact_step232_identities_bound",
    "frontend_source_modified",
    "git_executable_sha256",
    "git_object_reader_used",
    "git_status_worktree_enumeration_performed",
    "head_tree_path_count",
    "head_tree_projection_sha256",
    "host_decision_or_scaffold_required",
    "installer_asserted_combined_source_path_projection_sha256",
    "inventory_profile",
    "live_accepted_source_inventory_complete",
    "live_package_manifest_candidate_status_determined",
    "live_repository_inventory_performed",
    "lockfile_created_or_modified",
    "marker_file_count",
    "marker_inventory_projection_sha256",
    "marker_total_bytes",
    "max_accepted_overlay_paths",
    "max_candidate_roots",
    "max_head_tree_paths",
    "max_marker_files",
    "max_path_bytes",
    "max_single_marker_bytes",
    "max_total_marker_bytes",
    "no_package_manifest_candidate_identified",
    "observed_lockfile_kind",
    "observed_package_manager",
    "operational_write_performed",
    "package_manager_executed",
    "package_manager_selected",
    "package_manifest_count",
    "package_manifest_created_or_modified",
    "proof_document_sha256",
    "proof_status",
    "qualifying_browser_frontend_host_confirmed",
    "raw_path_or_file_content_emitted",
    "real_oauth_values_processed",
    "receipt_type",
    "remote_git_or_registry_operation_requested",
    "rendered_receipt_is_independent_live_provenance",
    "schema_version",
    "single_unselected_package_manifest_candidate_detected",
    "source",
    "step216_zero_retry_policy_preserved",
    "step225_default_retry_rejection_preserved",
    "step230_container_proof_boundary_preserved",
    "step231_dependency_lock_plan_preserved",
    "step232_synthetic_live_provenance_separation_preserved",
    "tracked_git_symlink_or_gitlink_observed",
    "validation_scope",
    "working_tree_marker_content_read",
    "working_tree_status_projection_sha256",
}


class EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError(ValueError):
    """Sanitized Step 234 offline scaffold-decision failure."""


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
        b"Engineer4Me-Step234-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


def _load_step233_no_host_receipt(document: bytes) -> dict[str, object]:
    if type(document) is not bytes or not document or len(document) > MAX_STEP233_RECEIPT_BYTES:
        raise ValueError("Step 233 no-host receipt size is invalid")
    parsed = json.loads(document, object_pairs_hook=_pairs)
    if type(parsed) is not dict or set(parsed) != _STEP233_RECEIPT_KEYS:
        raise ValueError("Step 233 no-host receipt keys are not exact")
    canonical_receipt = _canonical(parsed)
    if hashlib.sha256(canonical_receipt).hexdigest() != STEP233_NO_HOST_RECEIPT_SHA256:
        raise ValueError("Step 233 no-host receipt identity is invalid")

    expected = {
        "receipt_type": (
            "engineer4me_microsoft_entra_calling_client_msal_browser_"
            "frontend_host_live_inventory_proof_receipt"
        ),
        "schema_version": 1,
        "source": "engineer4me_controlled_local_git_frontend_host_inventory",
        "inventory_profile": STEP233_INVENTORY_PROFILE,
        "proof_status": STEP233_NO_HOST_STATUS,
        "proof_document_sha256": STEP233_PROOF_DOCUMENT_SHA256,
        "evidence_document_sha256": STEP233_EVIDENCE_DOCUMENT_SHA256,
        "head_tree_projection_sha256": STEP233_HEAD_TREE_PROJECTION_SHA256,
        "installer_asserted_combined_source_path_projection_sha256": (
            STEP233_COMBINED_SOURCE_PROJECTION_SHA256
        ),
        "marker_inventory_projection_sha256": (
            STEP233_MARKER_INVENTORY_PROJECTION_SHA256
        ),
        "candidate_root_projection_sha256": (
            STEP233_CANDIDATE_ROOT_PROJECTION_SHA256
        ),
        "working_tree_status_projection_sha256": (
            STEP233_WORKING_TREE_STATUS_PROJECTION_SHA256
        ),
        "head_tree_path_count": STEP233_HEAD_TREE_PATH_COUNT,
        "accepted_overlay_path_count": STEP233_ACCEPTED_OVERLAY_PATH_COUNT,
        "combined_source_path_count": STEP233_COMBINED_SOURCE_PATH_COUNT,
        "marker_file_count": STEP233_MARKER_FILE_COUNT,
        "marker_total_bytes": 0,
        "candidate_root_count": STEP233_CANDIDATE_ROOT_COUNT,
        "package_manifest_count": STEP233_PACKAGE_MANIFEST_COUNT,
        "dependency_lock_count": STEP233_DEPENDENCY_LOCK_COUNT,
        "observed_package_manager": "none",
        "observed_lockfile_kind": "none",
        "no_package_manifest_candidate_identified": True,
        "single_unselected_package_manifest_candidate_detected": False,
        "qualifying_browser_frontend_host_confirmed": False,
        "candidate_frontend_host_selected": False,
        "host_decision_or_scaffold_required": True,
        "package_manager_selected": False,
        "package_manager_executed": False,
        "package_manifest_created_or_modified": False,
        "lockfile_created_or_modified": False,
        "dependency_installed": False,
        "frontend_source_modified": False,
        "browser_bundle_built": False,
        "browser_runtime_executed": False,
        "real_oauth_values_processed": False,
        "application_configuration_modified": False,
        "application_activated": False,
        "operational_write_performed": False,
        "rendered_receipt_is_independent_live_provenance": False,
    }
    if any(parsed[name] != value or type(parsed[name]) is not type(value) for name, value in expected.items()):
        raise ValueError("Step 233 no-host receipt correlation is invalid")
    return parsed


class EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessDocument(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_scaffold_decision_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_offline_frontend_host_scaffold_decision_readiness"
    ]
    approved_step233_package_manifest_sha256: str
    approved_step233_accepted_state_manifest_sha256: str
    approved_step233_live_inventory_loader_sha256: str
    approved_step233_live_inventory_probe_sha256: str
    approved_step233_no_host_receipt_sha256: str
    approved_step231_dependency_lock_readiness_sha256: str
    approved_zero_retry_network_client_sha256: str
    approved_step233_inventory_profile: Literal[
        "engineer4me_frontend_host_live_git_inventory_v2"
    ]
    approved_step233_no_host_status: Literal[
        "live_inventory_complete_no_package_manifest_candidate_in_accepted_source"
    ]
    scaffold_target_root: Literal["frontend"]
    scaffold_application_model: Literal["static_browser_spa"]
    scaffold_language: Literal["typescript"]
    desired_package_manager: Literal["npm"]
    desired_lockfile_name: Literal["package-lock.json"]
    desired_lockfile_version: Literal[3]
    scaffold_mode: Literal["offline_desired_state_only_no_materialization"]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("scaffold-decision document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step233_package_manifest_sha256": str,
            "approved_step233_accepted_state_manifest_sha256": str,
            "approved_step233_live_inventory_loader_sha256": str,
            "approved_step233_live_inventory_probe_sha256": str,
            "approved_step233_no_host_receipt_sha256": str,
            "approved_step231_dependency_lock_readiness_sha256": str,
            "approved_zero_retry_network_client_sha256": str,
            "approved_step233_inventory_profile": str,
            "approved_step233_no_host_status": str,
            "scaffold_target_root": str,
            "scaffold_application_model": str,
            "scaffold_language": str,
            "desired_package_manager": str,
            "desired_lockfile_name": str,
            "desired_lockfile_version": int,
            "scaffold_mode": str,
        }
        if set(value) != set(expected) or any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("scaffold-decision document keys or types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessDocument:
        expected = {
            "approved_step233_package_manifest_sha256": (
                STEP233_PACKAGE_MANIFEST_SHA256
            ),
            "approved_step233_accepted_state_manifest_sha256": (
                STEP233_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step233_live_inventory_loader_sha256": (
                STEP233_LIVE_INVENTORY_LOADER_SHA256
            ),
            "approved_step233_live_inventory_probe_sha256": (
                STEP233_LIVE_INVENTORY_PROBE_SHA256
            ),
            "approved_step233_no_host_receipt_sha256": (
                STEP233_NO_HOST_RECEIPT_SHA256
            ),
            "approved_step231_dependency_lock_readiness_sha256": (
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
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
            raise ValueError("scaffold-decision approved identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    approved_step233_package_manifest_sha256: str
    approved_step233_accepted_state_manifest_sha256: str
    approved_step233_live_inventory_loader_sha256: str
    approved_step233_live_inventory_probe_sha256: str
    approved_step233_no_host_receipt_sha256: str
    approved_step231_dependency_lock_readiness_sha256: str
    approved_zero_retry_network_client_sha256: str
    approved_step233_inventory_profile: str
    approved_step233_no_host_status: str
    step233_proof_document_sha256: str
    step233_evidence_document_sha256: str
    step233_head_tree_projection_sha256: str
    step233_combined_source_projection_sha256: str
    step233_marker_inventory_projection_sha256: str
    step233_candidate_root_projection_sha256: str
    step233_working_tree_status_projection_sha256: str
    step233_head_tree_path_count: int
    step233_accepted_overlay_path_count: int
    step233_combined_source_path_count: int
    step233_marker_file_count: int
    step233_candidate_root_count: int
    step233_package_manifest_count: int
    step233_dependency_lock_count: int
    scaffold_target_root: str
    scaffold_application_model: str
    scaffold_language: str
    desired_package_manager: str
    desired_lockfile_name: str
    desired_lockfile_version: int
    scaffold_mode: str
    framework_selection: str
    bundler_selection: str
    planned_scaffold_path_count: int
    deferred_gate_count: int
    msal_browser_package: str
    msal_browser_version: str
    msal_common_package: str
    msal_common_version: str
    network_client_configuration_seam: str
    readiness_document_sha256: str
    scaffold_plan_sha256: str
    security_integration_plan_sha256: str
    deferred_gate_plan_sha256: str
    exact_step233_identities_bound: bool
    exact_step233_no_host_receipt_bound: bool
    accepted_step233_no_host_outcome_bound: bool
    full_step233_installer_execution_remains_live_provenance: bool
    dedicated_scaffold_root_required: bool
    atomic_target_absence_recheck_required: bool
    static_browser_spa_required: bool
    strict_typescript_required: bool
    exact_scaffold_path_allowlist_required: bool
    frozen_npm_lock_required: bool
    exact_msal_versions_required: bool
    zero_retry_network_client_required: bool
    exactly_one_network_client_instance_required: bool
    default_msal_network_client_forbidden: bool
    token_endpoint_post_retry_forbidden: bool
    public_client_pkce_required: bool
    client_secret_forbidden: bool
    deploy_time_public_client_configuration_required: bool
    exact_redirect_uri_match_required: bool
    api_origin_and_cors_decision_required: bool
    csp_and_security_headers_required: bool
    mobile_first_responsive_layout_required: bool
    accessibility_validation_required: bool
    framework_and_bundler_artifact_proof_required: bool
    dependency_integrity_reproof_required: bool
    lifecycle_scripts_disabled_during_future_install: bool
    browser_bundle_import_graph_proof_required: bool
    browser_cors_proof_required: bool
    pkce_and_callback_journey_proof_required: bool
    step233_live_inventory_reexecuted: bool
    rendered_step233_receipt_is_independent_live_provenance: bool
    existing_frontend_host_adopted: bool
    scaffold_root_operationally_selected: bool
    scaffold_target_created: bool
    scaffold_file_written: bool
    package_manifest_created_or_modified: bool
    lockfile_created_or_modified: bool
    operational_package_manager_selection_performed: bool
    package_manager_executed: bool
    registry_or_network_access_performed: bool
    framework_selected: bool
    bundler_selected: bool
    dependency_installed: bool
    frontend_source_modified: bool
    browser_bundle_built: bool
    browser_runtime_executed: bool
    real_oauth_values_processed: bool
    deploy_time_public_client_configuration_applied: bool
    redirect_uri_operationally_selected: bool
    api_origin_and_cors_operationally_selected: bool
    csp_and_security_headers_applied: bool
    responsive_layout_implemented: bool
    accessibility_validation_performed: bool
    application_configuration_modified: bool
    docker_or_compose_modified: bool
    application_activated: bool
    operational_write_performed: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    step230_container_proof_boundary_preserved: bool
    step231_dependency_lock_plan_preserved: bool
    step232_synthetic_live_provenance_separation_preserved: bool
    step233_live_no_host_boundary_preserved: bool

    def __post_init__(self) -> None:
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "approved_step233_package_manifest_sha256": STEP233_PACKAGE_MANIFEST_SHA256,
            "approved_step233_accepted_state_manifest_sha256": (
                STEP233_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step233_live_inventory_loader_sha256": (
                STEP233_LIVE_INVENTORY_LOADER_SHA256
            ),
            "approved_step233_live_inventory_probe_sha256": (
                STEP233_LIVE_INVENTORY_PROBE_SHA256
            ),
            "approved_step233_no_host_receipt_sha256": STEP233_NO_HOST_RECEIPT_SHA256,
            "approved_step231_dependency_lock_readiness_sha256": (
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
            ),
            "approved_zero_retry_network_client_sha256": (
                ZERO_RETRY_NETWORK_CLIENT_SHA256
            ),
            "approved_step233_inventory_profile": STEP233_INVENTORY_PROFILE,
            "approved_step233_no_host_status": STEP233_NO_HOST_STATUS,
            "step233_proof_document_sha256": STEP233_PROOF_DOCUMENT_SHA256,
            "step233_evidence_document_sha256": STEP233_EVIDENCE_DOCUMENT_SHA256,
            "step233_head_tree_projection_sha256": STEP233_HEAD_TREE_PROJECTION_SHA256,
            "step233_combined_source_projection_sha256": (
                STEP233_COMBINED_SOURCE_PROJECTION_SHA256
            ),
            "step233_marker_inventory_projection_sha256": (
                STEP233_MARKER_INVENTORY_PROJECTION_SHA256
            ),
            "step233_candidate_root_projection_sha256": (
                STEP233_CANDIDATE_ROOT_PROJECTION_SHA256
            ),
            "step233_working_tree_status_projection_sha256": (
                STEP233_WORKING_TREE_STATUS_PROJECTION_SHA256
            ),
            "step233_head_tree_path_count": STEP233_HEAD_TREE_PATH_COUNT,
            "step233_accepted_overlay_path_count": STEP233_ACCEPTED_OVERLAY_PATH_COUNT,
            "step233_combined_source_path_count": STEP233_COMBINED_SOURCE_PATH_COUNT,
            "step233_marker_file_count": STEP233_MARKER_FILE_COUNT,
            "step233_candidate_root_count": STEP233_CANDIDATE_ROOT_COUNT,
            "step233_package_manifest_count": STEP233_PACKAGE_MANIFEST_COUNT,
            "step233_dependency_lock_count": STEP233_DEPENDENCY_LOCK_COUNT,
            "scaffold_target_root": SCAFFOLD_TARGET_ROOT,
            "scaffold_application_model": SCAFFOLD_APPLICATION_MODEL,
            "scaffold_language": SCAFFOLD_LANGUAGE,
            "desired_package_manager": DESIRED_PACKAGE_MANAGER,
            "desired_lockfile_name": DESIRED_LOCKFILE_NAME,
            "desired_lockfile_version": DESIRED_LOCKFILE_VERSION,
            "scaffold_mode": SCAFFOLD_MODE,
            "framework_selection": FRAMEWORK_SELECTION,
            "bundler_selection": BUNDLER_SELECTION,
            "planned_scaffold_path_count": len(PLANNED_SCAFFOLD_PATHS),
            "deferred_gate_count": len(DEFERRED_GATES),
            "msal_browser_package": MSAL_BROWSER_PACKAGE,
            "msal_browser_version": MSAL_BROWSER_VERSION,
            "msal_common_package": MSAL_COMMON_PACKAGE,
            "msal_common_version": MSAL_COMMON_VERSION,
            "network_client_configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
        }
        if any(getattr(self, name) != value for name, value in constants.items()):
            raise ValueError("scaffold-decision receipt constant is invalid")
        for name, value in constants.items():
            if type(getattr(self, name)) is not type(value):
                raise ValueError("scaffold-decision receipt constant type is invalid")
        expected_digests = {
            "readiness_document_sha256": READINESS_DOCUMENT_SHA256,
            "scaffold_plan_sha256": SCAFFOLD_PLAN_SHA256,
            "security_integration_plan_sha256": SECURITY_INTEGRATION_PLAN_SHA256,
            "deferred_gate_plan_sha256": DEFERRED_GATE_PLAN_SHA256,
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected_digests.items()
        ):
            raise ValueError("scaffold-decision receipt digest is invalid")

        required_true = (
            "exact_step233_identities_bound",
            "exact_step233_no_host_receipt_bound",
            "accepted_step233_no_host_outcome_bound",
            "full_step233_installer_execution_remains_live_provenance",
            "dedicated_scaffold_root_required",
            "atomic_target_absence_recheck_required",
            "static_browser_spa_required",
            "strict_typescript_required",
            "exact_scaffold_path_allowlist_required",
            "frozen_npm_lock_required",
            "exact_msal_versions_required",
            "zero_retry_network_client_required",
            "exactly_one_network_client_instance_required",
            "default_msal_network_client_forbidden",
            "token_endpoint_post_retry_forbidden",
            "public_client_pkce_required",
            "client_secret_forbidden",
            "deploy_time_public_client_configuration_required",
            "exact_redirect_uri_match_required",
            "api_origin_and_cors_decision_required",
            "csp_and_security_headers_required",
            "mobile_first_responsive_layout_required",
            "accessibility_validation_required",
            "framework_and_bundler_artifact_proof_required",
            "dependency_integrity_reproof_required",
            "lifecycle_scripts_disabled_during_future_install",
            "browser_bundle_import_graph_proof_required",
            "browser_cors_proof_required",
            "pkce_and_callback_journey_proof_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "step230_container_proof_boundary_preserved",
            "step231_dependency_lock_plan_preserved",
            "step232_synthetic_live_provenance_separation_preserved",
            "step233_live_no_host_boundary_preserved",
        )
        required_false = (
            "step233_live_inventory_reexecuted",
            "rendered_step233_receipt_is_independent_live_provenance",
            "existing_frontend_host_adopted",
            "scaffold_root_operationally_selected",
            "scaffold_target_created",
            "scaffold_file_written",
            "package_manifest_created_or_modified",
            "lockfile_created_or_modified",
            "operational_package_manager_selection_performed",
            "package_manager_executed",
            "registry_or_network_access_performed",
            "framework_selected",
            "bundler_selected",
            "dependency_installed",
            "frontend_source_modified",
            "browser_bundle_built",
            "browser_runtime_executed",
            "real_oauth_values_processed",
            "deploy_time_public_client_configuration_applied",
            "redirect_uri_operationally_selected",
            "api_origin_and_cors_operationally_selected",
            "csp_and_security_headers_applied",
            "responsive_layout_implemented",
            "accessibility_validation_performed",
            "application_configuration_modified",
            "docker_or_compose_modified",
            "application_activated",
            "operational_write_performed",
        )
        if any(
            type(getattr(self, name)) is not bool or not getattr(self, name)
            for name in required_true
        ):
            raise ValueError("scaffold-decision required control is invalid")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError("scaffold-decision deferred or mutation control is invalid")


def load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
    document: bytes,
    step233_no_host_receipt: bytes,
) -> EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt:
    """Validate one exact offline decision and its exact Step 233 receipt."""

    try:
        if type(document) is not bytes or not document or len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError("scaffold-decision document size is invalid")
        parsed = json.loads(document, object_pairs_hook=_pairs)
        model = EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessDocument.model_validate(
            parsed
        )
        _load_step233_no_host_receipt(step233_no_host_receipt)
        canonical_document = _canonical(model.model_dump(mode="json"))
        scaffold_plan = {
            "target_root": SCAFFOLD_TARGET_ROOT,
            "application_model": SCAFFOLD_APPLICATION_MODEL,
            "language": SCAFFOLD_LANGUAGE,
            "package_manager": DESIRED_PACKAGE_MANAGER,
            "lockfile_name": DESIRED_LOCKFILE_NAME,
            "lockfile_version": DESIRED_LOCKFILE_VERSION,
            "framework": FRAMEWORK_SELECTION,
            "bundler": BUNDLER_SELECTION,
            "mode": SCAFFOLD_MODE,
            "planned_paths": PLANNED_SCAFFOLD_PATHS,
            "experience_requirements": {
                "mobile_first_responsive_layout": True,
                "accessibility_validation": True,
            },
        }
        security_plan = {
            "dependencies": {
                MSAL_BROWSER_PACKAGE: MSAL_BROWSER_VERSION,
                MSAL_COMMON_PACKAGE: MSAL_COMMON_VERSION,
            },
            "network_client_configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
            "zero_retry_network_client_sha256": ZERO_RETRY_NETWORK_CLIENT_SHA256,
            "network_client_instances": 1,
            "default_network_client_forbidden": True,
            "token_endpoint_post_retries": 0,
            "public_client_pkce_required": True,
            "client_secret_forbidden": True,
            "deploy_time_public_client_configuration_required": True,
            "exact_redirect_uri_match_required": True,
            "api_origin_and_cors_decision_required": True,
            "csp_and_security_headers_required": True,
        }
        return EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            approved_step233_package_manifest_sha256=STEP233_PACKAGE_MANIFEST_SHA256,
            approved_step233_accepted_state_manifest_sha256=(
                STEP233_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            approved_step233_live_inventory_loader_sha256=(
                STEP233_LIVE_INVENTORY_LOADER_SHA256
            ),
            approved_step233_live_inventory_probe_sha256=(
                STEP233_LIVE_INVENTORY_PROBE_SHA256
            ),
            approved_step233_no_host_receipt_sha256=STEP233_NO_HOST_RECEIPT_SHA256,
            approved_step231_dependency_lock_readiness_sha256=(
                STEP231_DEPENDENCY_LOCK_READINESS_SHA256
            ),
            approved_zero_retry_network_client_sha256=(
                ZERO_RETRY_NETWORK_CLIENT_SHA256
            ),
            approved_step233_inventory_profile=STEP233_INVENTORY_PROFILE,
            approved_step233_no_host_status=STEP233_NO_HOST_STATUS,
            step233_proof_document_sha256=STEP233_PROOF_DOCUMENT_SHA256,
            step233_evidence_document_sha256=STEP233_EVIDENCE_DOCUMENT_SHA256,
            step233_head_tree_projection_sha256=STEP233_HEAD_TREE_PROJECTION_SHA256,
            step233_combined_source_projection_sha256=(
                STEP233_COMBINED_SOURCE_PROJECTION_SHA256
            ),
            step233_marker_inventory_projection_sha256=(
                STEP233_MARKER_INVENTORY_PROJECTION_SHA256
            ),
            step233_candidate_root_projection_sha256=(
                STEP233_CANDIDATE_ROOT_PROJECTION_SHA256
            ),
            step233_working_tree_status_projection_sha256=(
                STEP233_WORKING_TREE_STATUS_PROJECTION_SHA256
            ),
            step233_head_tree_path_count=STEP233_HEAD_TREE_PATH_COUNT,
            step233_accepted_overlay_path_count=STEP233_ACCEPTED_OVERLAY_PATH_COUNT,
            step233_combined_source_path_count=STEP233_COMBINED_SOURCE_PATH_COUNT,
            step233_marker_file_count=STEP233_MARKER_FILE_COUNT,
            step233_candidate_root_count=STEP233_CANDIDATE_ROOT_COUNT,
            step233_package_manifest_count=STEP233_PACKAGE_MANIFEST_COUNT,
            step233_dependency_lock_count=STEP233_DEPENDENCY_LOCK_COUNT,
            scaffold_target_root=SCAFFOLD_TARGET_ROOT,
            scaffold_application_model=SCAFFOLD_APPLICATION_MODEL,
            scaffold_language=SCAFFOLD_LANGUAGE,
            desired_package_manager=DESIRED_PACKAGE_MANAGER,
            desired_lockfile_name=DESIRED_LOCKFILE_NAME,
            desired_lockfile_version=DESIRED_LOCKFILE_VERSION,
            scaffold_mode=SCAFFOLD_MODE,
            framework_selection=FRAMEWORK_SELECTION,
            bundler_selection=BUNDLER_SELECTION,
            planned_scaffold_path_count=len(PLANNED_SCAFFOLD_PATHS),
            deferred_gate_count=len(DEFERRED_GATES),
            msal_browser_package=MSAL_BROWSER_PACKAGE,
            msal_browser_version=MSAL_BROWSER_VERSION,
            msal_common_package=MSAL_COMMON_PACKAGE,
            msal_common_version=MSAL_COMMON_VERSION,
            network_client_configuration_seam=NETWORK_CLIENT_CONFIGURATION_SEAM,
            readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            scaffold_plan_sha256=_framed("scaffold-plan", scaffold_plan),
            security_integration_plan_sha256=_framed(
                "security-integration-plan", security_plan
            ),
            deferred_gate_plan_sha256=_framed("deferred-gates", DEFERRED_GATES),
            exact_step233_identities_bound=True,
            exact_step233_no_host_receipt_bound=True,
            accepted_step233_no_host_outcome_bound=True,
            full_step233_installer_execution_remains_live_provenance=True,
            dedicated_scaffold_root_required=True,
            atomic_target_absence_recheck_required=True,
            static_browser_spa_required=True,
            strict_typescript_required=True,
            exact_scaffold_path_allowlist_required=True,
            frozen_npm_lock_required=True,
            exact_msal_versions_required=True,
            zero_retry_network_client_required=True,
            exactly_one_network_client_instance_required=True,
            default_msal_network_client_forbidden=True,
            token_endpoint_post_retry_forbidden=True,
            public_client_pkce_required=True,
            client_secret_forbidden=True,
            deploy_time_public_client_configuration_required=True,
            exact_redirect_uri_match_required=True,
            api_origin_and_cors_decision_required=True,
            csp_and_security_headers_required=True,
            mobile_first_responsive_layout_required=True,
            accessibility_validation_required=True,
            framework_and_bundler_artifact_proof_required=True,
            dependency_integrity_reproof_required=True,
            lifecycle_scripts_disabled_during_future_install=True,
            browser_bundle_import_graph_proof_required=True,
            browser_cors_proof_required=True,
            pkce_and_callback_journey_proof_required=True,
            step233_live_inventory_reexecuted=False,
            rendered_step233_receipt_is_independent_live_provenance=False,
            existing_frontend_host_adopted=False,
            scaffold_root_operationally_selected=False,
            scaffold_target_created=False,
            scaffold_file_written=False,
            package_manifest_created_or_modified=False,
            lockfile_created_or_modified=False,
            operational_package_manager_selection_performed=False,
            package_manager_executed=False,
            registry_or_network_access_performed=False,
            framework_selected=False,
            bundler_selected=False,
            dependency_installed=False,
            frontend_source_modified=False,
            browser_bundle_built=False,
            browser_runtime_executed=False,
            real_oauth_values_processed=False,
            deploy_time_public_client_configuration_applied=False,
            redirect_uri_operationally_selected=False,
            api_origin_and_cors_operationally_selected=False,
            csp_and_security_headers_applied=False,
            responsive_layout_implemented=False,
            accessibility_validation_performed=False,
            application_configuration_modified=False,
            docker_or_compose_modified=False,
            application_activated=False,
            operational_write_performed=False,
            step216_zero_retry_policy_preserved=True,
            step225_default_retry_rejection_preserved=True,
            step230_container_proof_boundary_preserved=True,
            step231_dependency_lock_plan_preserved=True,
            step232_synthetic_live_provenance_separation_preserved=True,
            step233_live_no_host_boundary_preserved=True,
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError(
            "frontend-host scaffold decision readiness validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_scaffold_decision_readiness_receipt(
    receipt: EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt,
) -> bytes:
    """Render only the exact validated Step 234 receipt as canonical JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt:
        raise TypeError("exact frontend-host scaffold-decision receipt is required")
    receipt.__post_init__()
    return _canonical(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
    )


__all__ = [
    "BUNDLER_SELECTION",
    "DEFERRED_GATES",
    "DEFERRED_GATE_PLAN_SHA256",
    "DESIRED_LOCKFILE_NAME",
    "DESIRED_LOCKFILE_VERSION",
    "DESIRED_PACKAGE_MANAGER",
    "DOCUMENT_TYPE",
    "FRAMEWORK_SELECTION",
    "MAX_DOCUMENT_BYTES",
    "MAX_STEP233_RECEIPT_BYTES",
    "MSAL_BROWSER_PACKAGE",
    "MSAL_BROWSER_VERSION",
    "MSAL_COMMON_PACKAGE",
    "MSAL_COMMON_VERSION",
    "NETWORK_CLIENT_CONFIGURATION_SEAM",
    "PLANNED_SCAFFOLD_PATHS",
    "READINESS_DOCUMENT_SHA256",
    "RECEIPT_TYPE",
    "SCAFFOLD_APPLICATION_MODEL",
    "SCAFFOLD_LANGUAGE",
    "SCAFFOLD_MODE",
    "SCAFFOLD_TARGET_ROOT",
    "SCAFFOLD_PLAN_SHA256",
    "SCHEMA_VERSION",
    "SCOPE",
    "SOURCE",
    "STATUS",
    "SECURITY_INTEGRATION_PLAN_SHA256",
    "STEP231_DEPENDENCY_LOCK_READINESS_SHA256",
    "STEP233_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP233_CANDIDATE_ROOT_PROJECTION_SHA256",
    "STEP233_LIVE_INVENTORY_LOADER_SHA256",
    "STEP233_LIVE_INVENTORY_PROBE_SHA256",
    "STEP233_NO_HOST_RECEIPT_SHA256",
    "STEP233_NO_HOST_STATUS",
    "STEP233_PACKAGE_MANIFEST_SHA256",
    "ZERO_RETRY_NETWORK_CLIENT_SHA256",
    "EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessDocument",
    "EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError",
    "EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt",
    "load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness",
    "render_entra_calling_client_msal_frontend_host_scaffold_decision_readiness_receipt",
]
