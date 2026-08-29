"""Step 235 offline browser-SPA architecture-family selection contract.

This module binds the complete exact Step 234 scaffold-decision chain and
selects only non-executable architecture families for a future frontend host.
It performs no filesystem, process, package-manager, registry, browser,
configuration, or network operation.  It creates no scaffold or path allowlist
and deliberately selects no new ecosystem version or package artifact.
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
    "frontend_host_architecture_selection_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_offline_frontend_host_architecture_selection_readiness"
SCOPE = "exact_step234_chain_plus_non_authorizing_architecture_family_selection"
STATUS = (
    "frontend_host_architecture_families_selected_exact_versions_and_"
    "materialization_remain_blocked"
)

STEP234_PACKAGE_MANIFEST_SHA256 = (
    "806d8082896fbba4d1e5b6970b57f5ae6aa0c296012fdadf09e495e11de9327c"
)
STEP234_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "96ef8a3d77043f058036be5b9efa2f250746f9a5155c37fbf94aa75798c6a991"
)
STEP234_SCAFFOLD_DECISION_READINESS_SHA256 = (
    "254680a78772258aadc430aa8fb2539249c4d77c461cf1b8b28fa5f1060fd1d7"
)
STEP234_SCAFFOLD_DECISION_TEST_SHA256 = (
    "49d0c33c441f616b83da5af8a1e9c1a28d796fa6e0cb3c4ab40af2575478ba5b"
)
STEP234_CANONICAL_RECEIPT_SHA256 = (
    "8172f0f2f47b7167fed509769b6bcf465cd4780bcc01bf60dc959c7385198276"
)
STEP234_READINESS_DOCUMENT_SHA256 = (
    "275edba62b536bd2849c8e951c23db8a591a119c788d563bf8e77e8a1cf5b321"
)
STEP234_SCAFFOLD_PLAN_SHA256 = (
    "6e2f30dedf03555d8ae6ff1bf4705328ad0b0f21181f418065ee4195aa404fbb"
)
STEP234_SECURITY_INTEGRATION_PLAN_SHA256 = (
    "c2ec07fe27dc8937cee4f81e25470073d007bf981333574d84319990b5d452fd"
)
STEP234_DEFERRED_GATE_PLAN_SHA256 = (
    "1bc72efd3aab404b6574365f5946a7092451d868d2f3595307c91aa2f711526a"
)
STEP234_STATUS = (
    "frontend_host_scaffold_decision_plan_validated_creation_remains_blocked"
)

STEP234_PROVISIONAL_SCAFFOLD_PATHS = (
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/index.html",
    "frontend/tsconfig.json",
    "frontend/src/main.ts",
)
PATH_PLAN_DISPOSITION = (
    "step234_provisional_five_path_plan_retained_as_non_authorizing_input_"
    "pending_react_vite_allowlist"
)
FINAL_PATH_ALLOWLIST_SELECTION = "unselected"
SCAFFOLD_TARGET_ROOT = "frontend"

RENDERING_MODEL = "client_rendered_static_browser_spa"
UI_FRAMEWORK_FAMILY = "react"
UI_FRAMEWORK_MAJOR_FAMILY = 19
DOM_RENDERER_FAMILY = "react_dom"
DOM_RENDERER_MAJOR_FAMILY = 19
LANGUAGE_FAMILY = "typescript_strict"
BUILD_TOOL_FAMILY = "vite"
BUILD_TOOL_MAJOR_FAMILY = 8
REACT_BUILD_PLUGIN_FAMILY = "@vitejs/plugin-react"
MODULE_FORMAT = "esm"
ROUTING_CAPABILITY = "client_side_browser_history"
ROUTER_SELECTION = "unselected"
NODE_RUNTIME_FAMILY = "node_24_lts"
PACKAGE_MANAGER_FAMILY = "npm"
LOCKFILE_NAME = "package-lock.json"
LOCKFILE_VERSION = 3
AUTHENTICATION_CLIENT_FAMILY = "@azure/msal-browser"
MSAL_REACT_WRAPPER_PACKAGE = "@azure/msal-react"
REACT_AUTH_WRAPPER_DISPOSITION = (
    "forbidden_initial_architecture_unless_separately_reviewed_revision_"
    "supersedes_step235"
)
AUTHENTICATION_CACHE_LOCATION = "sessionStorage"
AUTHENTICATION_INTERACTION_MODEL = "redirect_first"
POPUP_INTERACTION_DISPOSITION = "forbidden_initial_architecture"
PWA_POSTURE = (
    "future_extension_deferred_initial_manifest_service_worker_and_sensitive_cache_forbidden"
)
EXPERIENCE_POSTURE = "mobile_first_responsive"
STYLING_POSTURE = "semantic_html_css_modules_and_custom_property_design_tokens"
ACCESSIBILITY_TARGET = "wcag_2_2_level_aa"
PRIMARY_CONTROL_PRODUCT_TARGET = "44_by_44_css_pixels"
ACCESSIBILITY_AUTOMATION_FAMILY = "axe_core_supporting_checks"
UNIT_TEST_FAMILY = "vitest"
COMPONENT_TEST_FAMILY = "react_testing_library"
END_TO_END_TEST_FAMILY = "playwright"
PUBLIC_RUNTIME_CONFIG_POSTURE = (
    "future_exact_schema_same_origin_json_validated_before_pca_creation"
)

MSAL_BROWSER_PACKAGE = "@azure/msal-browser"
MSAL_BROWSER_VERSION = "5.18.0"
MSAL_COMMON_PACKAGE = "@azure/msal-common"
MSAL_COMMON_VERSION = "16.12.0"
NETWORK_CLIENT_CONFIGURATION_SEAM = "system.networkClient"
ZERO_RETRY_NETWORK_CLIENT_SHA256 = (
    "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
)
FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS = (
    "storeAuthStateInCookie",
    "temporaryCacheLocation",
    "secureCookies",
    "claimsBasedCachingEnabled",
    "cacheMigrationEnabled",
)

DEFERRED_GATES = (
    "controlled_official_registry_compatibility_and_provenance_proof",
    "exact_node_24_lts_patch_and_npm_toolchain_proof",
    "exact_react_react_dom_typescript_vite_plugin_version_selection",
    "exact_router_family_package_and_version_selection",
    "exact_testing_dependency_version_selection",
    "final_scaffold_path_allowlist_selection_and_collision_recheck",
    "lifecycle_script_disabled_exact_lock_generation",
    "static_bundle_import_graph_and_secret_absence_proof",
    "separately_reviewed_pwa_manifest_service_worker_and_cache_extension",
    "mobile_viewport_wcag_2_2_aa_and_cross_browser_validation",
    "redirect_cors_csp_pkce_and_callback_journey_proof",
)

READINESS_DOCUMENT_SHA256 = (
    "10e40546438acece101c6be7490772a47cf159dc19283eb0c9693ed4bbe9d723"
)
ARCHITECTURE_PLAN_SHA256 = (
    "d6ffd2561b069d69f16db836b32f58ff29e5d6fa021559160051035d5b3e8a37"
)
SECURITY_PLAN_SHA256 = (
    "5e1edc9034c672ee81c451641852a20661e4724c80742601ed6d7153c79d3ba8"
)
EXPERIENCE_AND_TEST_PLAN_SHA256 = (
    "cf47c7b86e4dcebcea1ca442c8d463c98cecbe5bb9fd3b22883f0f60c905d5be"
)
DEFERRED_GATE_PLAN_SHA256 = (
    "7253144525f0f93e70d92dd94074aee696389fb54b30bacb1d064caf021e93c7"
)
CANONICAL_RECEIPT_SHA256 = (
    "6b70abd5db7496af97884707a64c52e272c62292de2568aec8adb6a505cf5ee4"
)

MAX_DOCUMENT_BYTES = 8192


class EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError(
    ValueError
):
    """Sanitized Step 235 offline architecture-selection failure."""


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
        b"Engineer4Me-Step235-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessDocument(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_architecture_selection_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_offline_frontend_host_architecture_selection_readiness"
    ]
    approved_step234_package_manifest_sha256: str
    approved_step234_accepted_state_manifest_sha256: str
    approved_step234_scaffold_decision_readiness_sha256: str
    approved_step234_scaffold_decision_test_sha256: str
    approved_step234_canonical_receipt_sha256: str
    approved_step234_readiness_document_sha256: str
    approved_step234_scaffold_plan_sha256: str
    approved_step234_security_integration_plan_sha256: str
    approved_step234_deferred_gate_plan_sha256: str
    approved_step234_status: Literal[
        "frontend_host_scaffold_decision_plan_validated_creation_remains_blocked"
    ]
    scaffold_target_root: Literal["frontend"]
    path_plan_disposition: Literal[
        "step234_provisional_five_path_plan_retained_as_non_authorizing_input_pending_react_vite_allowlist"
    ]
    final_path_allowlist_selection: Literal["unselected"]
    rendering_model: Literal["client_rendered_static_browser_spa"]
    ui_framework_family: Literal["react"]
    ui_framework_major_family: Literal[19]
    dom_renderer_family: Literal["react_dom"]
    dom_renderer_major_family: Literal[19]
    language_family: Literal["typescript_strict"]
    build_tool_family: Literal["vite"]
    build_tool_major_family: Literal[8]
    react_build_plugin_family: Literal["@vitejs/plugin-react"]
    module_format: Literal["esm"]
    routing_capability: Literal["client_side_browser_history"]
    router_selection: Literal["unselected"]
    node_runtime_family: Literal["node_24_lts"]
    package_manager_family: Literal["npm"]
    lockfile_name: Literal["package-lock.json"]
    lockfile_version: Literal[3]
    authentication_client_family: Literal["@azure/msal-browser"]
    react_auth_wrapper_disposition: Literal[
        "forbidden_initial_architecture_unless_separately_reviewed_revision_supersedes_step235"
    ]
    authentication_cache_location: Literal["sessionStorage"]
    authentication_interaction_model: Literal["redirect_first"]
    popup_interaction_disposition: Literal["forbidden_initial_architecture"]
    public_runtime_config_posture: Literal[
        "future_exact_schema_same_origin_json_validated_before_pca_creation"
    ]
    pwa_posture: Literal[
        "future_extension_deferred_initial_manifest_service_worker_and_sensitive_cache_forbidden"
    ]
    experience_posture: Literal["mobile_first_responsive"]
    styling_posture: Literal[
        "semantic_html_css_modules_and_custom_property_design_tokens"
    ]
    accessibility_target: Literal["wcag_2_2_level_aa"]
    primary_control_product_target: Literal["44_by_44_css_pixels"]
    accessibility_automation_family: Literal["axe_core_supporting_checks"]
    unit_test_family: Literal["vitest"]
    component_test_family: Literal["react_testing_library"]
    end_to_end_test_family: Literal["playwright"]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("architecture-selection document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step234_package_manifest_sha256": str,
            "approved_step234_accepted_state_manifest_sha256": str,
            "approved_step234_scaffold_decision_readiness_sha256": str,
            "approved_step234_scaffold_decision_test_sha256": str,
            "approved_step234_canonical_receipt_sha256": str,
            "approved_step234_readiness_document_sha256": str,
            "approved_step234_scaffold_plan_sha256": str,
            "approved_step234_security_integration_plan_sha256": str,
            "approved_step234_deferred_gate_plan_sha256": str,
            "approved_step234_status": str,
            "scaffold_target_root": str,
            "path_plan_disposition": str,
            "final_path_allowlist_selection": str,
            "rendering_model": str,
            "ui_framework_family": str,
            "ui_framework_major_family": int,
            "dom_renderer_family": str,
            "dom_renderer_major_family": int,
            "language_family": str,
            "build_tool_family": str,
            "build_tool_major_family": int,
            "react_build_plugin_family": str,
            "module_format": str,
            "routing_capability": str,
            "router_selection": str,
            "node_runtime_family": str,
            "package_manager_family": str,
            "lockfile_name": str,
            "lockfile_version": int,
            "authentication_client_family": str,
            "react_auth_wrapper_disposition": str,
            "authentication_cache_location": str,
            "authentication_interaction_model": str,
            "popup_interaction_disposition": str,
            "public_runtime_config_posture": str,
            "pwa_posture": str,
            "experience_posture": str,
            "styling_posture": str,
            "accessibility_target": str,
            "primary_control_product_target": str,
            "accessibility_automation_family": str,
            "unit_test_family": str,
            "component_test_family": str,
            "end_to_end_test_family": str,
        }
        if set(value) != set(expected) or any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError(
                "architecture-selection document keys or types are not exact"
            )
        return value

    @model_validator(mode="after")
    def validate_approved_step234_identities(
        self,
    ) -> EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessDocument:
        expected = {
            "approved_step234_package_manifest_sha256": (
                STEP234_PACKAGE_MANIFEST_SHA256
            ),
            "approved_step234_accepted_state_manifest_sha256": (
                STEP234_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step234_scaffold_decision_readiness_sha256": (
                STEP234_SCAFFOLD_DECISION_READINESS_SHA256
            ),
            "approved_step234_scaffold_decision_test_sha256": (
                STEP234_SCAFFOLD_DECISION_TEST_SHA256
            ),
            "approved_step234_canonical_receipt_sha256": (
                STEP234_CANONICAL_RECEIPT_SHA256
            ),
            "approved_step234_readiness_document_sha256": (
                STEP234_READINESS_DOCUMENT_SHA256
            ),
            "approved_step234_scaffold_plan_sha256": STEP234_SCAFFOLD_PLAN_SHA256,
            "approved_step234_security_integration_plan_sha256": (
                STEP234_SECURITY_INTEGRATION_PLAN_SHA256
            ),
            "approved_step234_deferred_gate_plan_sha256": (
                STEP234_DEFERRED_GATE_PLAN_SHA256
            ),
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected.items()
        ):
            raise ValueError("architecture-selection approved identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    approved_step234_package_manifest_sha256: str
    approved_step234_accepted_state_manifest_sha256: str
    approved_step234_scaffold_decision_readiness_sha256: str
    approved_step234_scaffold_decision_test_sha256: str
    approved_step234_canonical_receipt_sha256: str
    approved_step234_readiness_document_sha256: str
    approved_step234_scaffold_plan_sha256: str
    approved_step234_security_integration_plan_sha256: str
    approved_step234_deferred_gate_plan_sha256: str
    approved_step234_status: str
    scaffold_target_root: str
    step234_provisional_path_count: int
    path_plan_disposition: str
    final_path_allowlist_selection: str
    rendering_model: str
    ui_framework_family: str
    ui_framework_major_family: int
    dom_renderer_family: str
    dom_renderer_major_family: int
    language_family: str
    build_tool_family: str
    build_tool_major_family: int
    react_build_plugin_family: str
    module_format: str
    routing_capability: str
    router_selection: str
    node_runtime_family: str
    package_manager_family: str
    lockfile_name: str
    lockfile_version: int
    authentication_client_family: str
    react_auth_wrapper_disposition: str
    authentication_cache_location: str
    authentication_interaction_model: str
    popup_interaction_disposition: str
    public_runtime_config_posture: str
    pwa_posture: str
    experience_posture: str
    styling_posture: str
    accessibility_target: str
    primary_control_product_target: str
    accessibility_automation_family: str
    unit_test_family: str
    component_test_family: str
    end_to_end_test_family: str
    msal_browser_package: str
    msal_browser_version: str
    msal_common_package: str
    msal_common_version: str
    network_client_configuration_seam: str
    forbidden_removed_msal_v5_cache_option_count: int
    deferred_gate_count: int
    readiness_document_sha256: str
    architecture_plan_sha256: str
    security_plan_sha256: str
    experience_and_test_plan_sha256: str
    deferred_gate_plan_sha256: str
    exact_step234_chain_bound: bool
    exact_step234_canonical_receipt_identity_bound: bool
    accepted_step234_blocked_outcome_preserved: bool
    client_rendered_static_spa_family_selected_offline: bool
    react_family_selected_offline: bool
    react_19_major_family_selected_offline: bool
    react_dom_family_selected_offline: bool
    react_dom_19_major_family_selected_offline: bool
    strict_typescript_family_selected_offline: bool
    vite_family_selected_offline: bool
    vite_8_major_family_selected_offline: bool
    official_vite_react_plugin_family_selected_offline: bool
    esm_family_selected_offline: bool
    client_side_browser_history_routing_required: bool
    router_selection_deferred: bool
    static_host_spa_fallback_for_non_asset_routes_required: bool
    spa_fallback_excludes_api_and_static_asset_paths_required: bool
    exact_spa_fallback_successor_proof_required: bool
    node_24_lts_family_selected_offline: bool
    npm_package_lock_v3_policy_preserved: bool
    direct_msal_browser_boundary_preserved: bool
    direct_msal_browser_integration_selected: bool
    msal_react_wrapper_forbidden: bool
    msal_react_requires_separately_reviewed_superseding_revision: bool
    approved_exact_msal_versions_preserved: bool
    msal_authentication_cache_session_storage_required: bool
    local_storage_for_authentication_cache_forbidden: bool
    removed_msal_v5_cache_options_forbidden: bool
    zero_retry_network_client_required: bool
    exactly_one_network_client_instance_required: bool
    exactly_one_public_client_application_instance_required: bool
    default_msal_network_client_forbidden: bool
    custom_or_non_msal_token_persistence_forbidden: bool
    token_endpoint_post_retry_forbidden: bool
    public_client_pkce_required: bool
    client_secret_forbidden: bool
    redirect_first_auth_architecture_selected: bool
    popup_initial_auth_flow_forbidden: bool
    pwa_future_extension_deferred: bool
    web_app_manifest_initially_forbidden: bool
    service_worker_initially_forbidden: bool
    initial_service_worker_caching_of_auth_config_tokens_and_protected_api_responses_forbidden: bool
    separately_reviewed_encrypted_offline_app_data_design_not_precluded: bool
    mobile_first_responsive_required: bool
    semantic_html_required: bool
    css_modules_selected_offline: bool
    custom_property_design_tokens_required: bool
    mobile_first_base_styles_required: bool
    wcag_2_2_level_aa_target_required: bool
    primary_controls_44_by_44_css_pixels_product_target_required: bool
    axe_and_playwright_automation_is_not_conformance_proof: bool
    real_safari_ios_proof_required: bool
    real_device_manual_accessibility_checks_required: bool
    vitest_family_selected_offline: bool
    react_testing_library_family_selected_offline: bool
    axe_core_supporting_checks_family_selected_offline: bool
    playwright_family_selected_offline: bool
    static_dist_production_host_required: bool
    vite_preview_production_host_forbidden: bool
    loopback_only_development_server_required: bool
    permissive_vite_development_cors_forbidden: bool
    public_browser_environment_values_only_required: bool
    vite_public_non_secret_build_metadata_only_required: bool
    vite_auth_and_api_runtime_configuration_forbidden: bool
    same_origin_json_runtime_configuration_required: bool
    exact_runtime_configuration_schema_required: bool
    runtime_configuration_fail_closed_validation_required: bool
    runtime_configuration_validation_before_pca_creation_required: bool
    runtime_configuration_service_worker_cache_forbidden: bool
    exact_runtime_config_path_headers_bytes_values_required_in_successor: bool
    step234_provisional_five_path_plan_bound: bool
    step234_main_ts_not_authorized_for_react_materialization: bool
    step234_provisional_plan_lacked_vite_config: bool
    step234_provisional_paths_non_authorizing: bool
    final_path_allowlist_required_before_materialization: bool
    controlled_registry_compatibility_proof_required: bool
    exact_ecosystem_versions_required_in_successor: bool
    react_and_react_dom_exact_version_parity_required: bool
    toolchain_peer_compatibility_proof_required: bool
    exact_registry_tarball_integrity_required: bool
    registry_signature_and_provenance_status_or_explicit_absence_disposition_required: bool
    registry_engines_deprecations_licenses_and_advisory_status_proof_required: bool
    lifecycle_scripts_disabled_during_future_resolution: bool
    frozen_npm_ci_required_after_lock: bool
    exact_bundle_import_graph_proof_required: bool
    redirect_cors_csp_pkce_journey_proof_required: bool
    architecture_family_selection_authorizes_materialization: bool
    final_scaffold_path_allowlist_selected: bool
    react_exact_version_selected: bool
    react_dom_exact_version_selected: bool
    typescript_exact_version_selected: bool
    typescript_major_version_selected: bool
    vite_exact_version_selected: bool
    vite_plugin_react_exact_version_selected: bool
    node_exact_patch_version_selected: bool
    testing_dependency_exact_versions_selected: bool
    pwa_dependency_exact_versions_selected: bool
    router_family_selected: bool
    router_package_selected: bool
    router_exact_version_selected: bool
    third_party_ui_component_framework_selected: bool
    third_party_css_framework_selected: bool
    third_party_styling_artifact_selected: bool
    ecosystem_artifact_registry_proof_performed: bool
    ecosystem_artifact_downloaded: bool
    ecosystem_artifact_integrity_verified: bool
    runtime_config_path_selected: bool
    runtime_config_schema_selected: bool
    runtime_config_headers_selected: bool
    runtime_config_byte_limit_selected: bool
    runtime_config_values_processed: bool
    runtime_config_fetched: bool
    runtime_config_validated: bool
    public_client_application_created: bool
    axe_or_playwright_claimed_as_conformance_proof: bool
    real_safari_ios_proof_performed: bool
    real_device_manual_accessibility_checks_performed: bool
    scaffold_target_created: bool
    scaffold_file_written: bool
    package_manifest_created_or_modified: bool
    lockfile_created_or_modified: bool
    dependency_tree_resolved: bool
    dependency_installed: bool
    lifecycle_script_executed: bool
    package_manager_executed: bool
    registry_or_network_access_performed: bool
    frontend_source_modified: bool
    web_app_manifest_created: bool
    service_worker_implemented: bool
    service_worker_registered: bool
    service_worker_runtime_cache_configured: bool
    ordinary_http_cache_policy_selected: bool
    protected_response_cached: bool
    browser_bundle_built: bool
    browser_runtime_executed: bool
    popup_auth_flow_executed: bool
    frontend_test_runtime_executed: bool
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
    step234_scaffold_decision_boundary_preserved: bool

    def __post_init__(self) -> None:
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "approved_step234_package_manifest_sha256": STEP234_PACKAGE_MANIFEST_SHA256,
            "approved_step234_accepted_state_manifest_sha256": (
                STEP234_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            "approved_step234_scaffold_decision_readiness_sha256": (
                STEP234_SCAFFOLD_DECISION_READINESS_SHA256
            ),
            "approved_step234_scaffold_decision_test_sha256": (
                STEP234_SCAFFOLD_DECISION_TEST_SHA256
            ),
            "approved_step234_canonical_receipt_sha256": (
                STEP234_CANONICAL_RECEIPT_SHA256
            ),
            "approved_step234_readiness_document_sha256": (
                STEP234_READINESS_DOCUMENT_SHA256
            ),
            "approved_step234_scaffold_plan_sha256": STEP234_SCAFFOLD_PLAN_SHA256,
            "approved_step234_security_integration_plan_sha256": (
                STEP234_SECURITY_INTEGRATION_PLAN_SHA256
            ),
            "approved_step234_deferred_gate_plan_sha256": (
                STEP234_DEFERRED_GATE_PLAN_SHA256
            ),
            "approved_step234_status": STEP234_STATUS,
            "scaffold_target_root": SCAFFOLD_TARGET_ROOT,
            "step234_provisional_path_count": len(STEP234_PROVISIONAL_SCAFFOLD_PATHS),
            "path_plan_disposition": PATH_PLAN_DISPOSITION,
            "final_path_allowlist_selection": FINAL_PATH_ALLOWLIST_SELECTION,
            "rendering_model": RENDERING_MODEL,
            "ui_framework_family": UI_FRAMEWORK_FAMILY,
            "ui_framework_major_family": UI_FRAMEWORK_MAJOR_FAMILY,
            "dom_renderer_family": DOM_RENDERER_FAMILY,
            "dom_renderer_major_family": DOM_RENDERER_MAJOR_FAMILY,
            "language_family": LANGUAGE_FAMILY,
            "build_tool_family": BUILD_TOOL_FAMILY,
            "build_tool_major_family": BUILD_TOOL_MAJOR_FAMILY,
            "react_build_plugin_family": REACT_BUILD_PLUGIN_FAMILY,
            "module_format": MODULE_FORMAT,
            "routing_capability": ROUTING_CAPABILITY,
            "router_selection": ROUTER_SELECTION,
            "node_runtime_family": NODE_RUNTIME_FAMILY,
            "package_manager_family": PACKAGE_MANAGER_FAMILY,
            "lockfile_name": LOCKFILE_NAME,
            "lockfile_version": LOCKFILE_VERSION,
            "authentication_client_family": AUTHENTICATION_CLIENT_FAMILY,
            "react_auth_wrapper_disposition": REACT_AUTH_WRAPPER_DISPOSITION,
            "authentication_cache_location": AUTHENTICATION_CACHE_LOCATION,
            "authentication_interaction_model": AUTHENTICATION_INTERACTION_MODEL,
            "popup_interaction_disposition": POPUP_INTERACTION_DISPOSITION,
            "public_runtime_config_posture": PUBLIC_RUNTIME_CONFIG_POSTURE,
            "pwa_posture": PWA_POSTURE,
            "experience_posture": EXPERIENCE_POSTURE,
            "styling_posture": STYLING_POSTURE,
            "accessibility_target": ACCESSIBILITY_TARGET,
            "primary_control_product_target": PRIMARY_CONTROL_PRODUCT_TARGET,
            "accessibility_automation_family": ACCESSIBILITY_AUTOMATION_FAMILY,
            "unit_test_family": UNIT_TEST_FAMILY,
            "component_test_family": COMPONENT_TEST_FAMILY,
            "end_to_end_test_family": END_TO_END_TEST_FAMILY,
            "msal_browser_package": MSAL_BROWSER_PACKAGE,
            "msal_browser_version": MSAL_BROWSER_VERSION,
            "msal_common_package": MSAL_COMMON_PACKAGE,
            "msal_common_version": MSAL_COMMON_VERSION,
            "network_client_configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
            "forbidden_removed_msal_v5_cache_option_count": len(
                FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS
            ),
            "deferred_gate_count": len(DEFERRED_GATES),
        }
        if any(getattr(self, name) != value for name, value in constants.items()):
            raise ValueError("architecture-selection receipt constant is invalid")
        if any(
            type(getattr(self, name)) is not type(value)
            for name, value in constants.items()
        ):
            raise ValueError("architecture-selection receipt constant type is invalid")

        expected_digests = {
            "readiness_document_sha256": READINESS_DOCUMENT_SHA256,
            "architecture_plan_sha256": ARCHITECTURE_PLAN_SHA256,
            "security_plan_sha256": SECURITY_PLAN_SHA256,
            "experience_and_test_plan_sha256": EXPERIENCE_AND_TEST_PLAN_SHA256,
            "deferred_gate_plan_sha256": DEFERRED_GATE_PLAN_SHA256,
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected_digests.items()
        ):
            raise ValueError("architecture-selection receipt digest is invalid")

        required_true = (
            "exact_step234_chain_bound",
            "exact_step234_canonical_receipt_identity_bound",
            "accepted_step234_blocked_outcome_preserved",
            "client_rendered_static_spa_family_selected_offline",
            "react_family_selected_offline",
            "react_19_major_family_selected_offline",
            "react_dom_family_selected_offline",
            "react_dom_19_major_family_selected_offline",
            "strict_typescript_family_selected_offline",
            "vite_family_selected_offline",
            "vite_8_major_family_selected_offline",
            "official_vite_react_plugin_family_selected_offline",
            "esm_family_selected_offline",
            "client_side_browser_history_routing_required",
            "router_selection_deferred",
            "static_host_spa_fallback_for_non_asset_routes_required",
            "spa_fallback_excludes_api_and_static_asset_paths_required",
            "exact_spa_fallback_successor_proof_required",
            "node_24_lts_family_selected_offline",
            "npm_package_lock_v3_policy_preserved",
            "direct_msal_browser_boundary_preserved",
            "direct_msal_browser_integration_selected",
            "msal_react_wrapper_forbidden",
            "msal_react_requires_separately_reviewed_superseding_revision",
            "approved_exact_msal_versions_preserved",
            "msal_authentication_cache_session_storage_required",
            "local_storage_for_authentication_cache_forbidden",
            "removed_msal_v5_cache_options_forbidden",
            "zero_retry_network_client_required",
            "exactly_one_network_client_instance_required",
            "exactly_one_public_client_application_instance_required",
            "default_msal_network_client_forbidden",
            "custom_or_non_msal_token_persistence_forbidden",
            "token_endpoint_post_retry_forbidden",
            "public_client_pkce_required",
            "client_secret_forbidden",
            "redirect_first_auth_architecture_selected",
            "popup_initial_auth_flow_forbidden",
            "pwa_future_extension_deferred",
            "web_app_manifest_initially_forbidden",
            "service_worker_initially_forbidden",
            "initial_service_worker_caching_of_auth_config_tokens_and_protected_api_responses_forbidden",
            "separately_reviewed_encrypted_offline_app_data_design_not_precluded",
            "mobile_first_responsive_required",
            "semantic_html_required",
            "css_modules_selected_offline",
            "custom_property_design_tokens_required",
            "mobile_first_base_styles_required",
            "wcag_2_2_level_aa_target_required",
            "primary_controls_44_by_44_css_pixels_product_target_required",
            "axe_and_playwright_automation_is_not_conformance_proof",
            "real_safari_ios_proof_required",
            "real_device_manual_accessibility_checks_required",
            "vitest_family_selected_offline",
            "react_testing_library_family_selected_offline",
            "axe_core_supporting_checks_family_selected_offline",
            "playwright_family_selected_offline",
            "static_dist_production_host_required",
            "vite_preview_production_host_forbidden",
            "loopback_only_development_server_required",
            "permissive_vite_development_cors_forbidden",
            "public_browser_environment_values_only_required",
            "vite_public_non_secret_build_metadata_only_required",
            "vite_auth_and_api_runtime_configuration_forbidden",
            "same_origin_json_runtime_configuration_required",
            "exact_runtime_configuration_schema_required",
            "runtime_configuration_fail_closed_validation_required",
            "runtime_configuration_validation_before_pca_creation_required",
            "runtime_configuration_service_worker_cache_forbidden",
            "exact_runtime_config_path_headers_bytes_values_required_in_successor",
            "step234_provisional_five_path_plan_bound",
            "step234_main_ts_not_authorized_for_react_materialization",
            "step234_provisional_plan_lacked_vite_config",
            "step234_provisional_paths_non_authorizing",
            "final_path_allowlist_required_before_materialization",
            "controlled_registry_compatibility_proof_required",
            "exact_ecosystem_versions_required_in_successor",
            "react_and_react_dom_exact_version_parity_required",
            "toolchain_peer_compatibility_proof_required",
            "exact_registry_tarball_integrity_required",
            "registry_signature_and_provenance_status_or_explicit_absence_disposition_required",
            "registry_engines_deprecations_licenses_and_advisory_status_proof_required",
            "lifecycle_scripts_disabled_during_future_resolution",
            "frozen_npm_ci_required_after_lock",
            "exact_bundle_import_graph_proof_required",
            "redirect_cors_csp_pkce_journey_proof_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "step230_container_proof_boundary_preserved",
            "step231_dependency_lock_plan_preserved",
            "step232_synthetic_live_provenance_separation_preserved",
            "step233_live_no_host_boundary_preserved",
            "step234_scaffold_decision_boundary_preserved",
        )
        required_false = (
            "architecture_family_selection_authorizes_materialization",
            "final_scaffold_path_allowlist_selected",
            "react_exact_version_selected",
            "react_dom_exact_version_selected",
            "typescript_exact_version_selected",
            "typescript_major_version_selected",
            "vite_exact_version_selected",
            "vite_plugin_react_exact_version_selected",
            "node_exact_patch_version_selected",
            "testing_dependency_exact_versions_selected",
            "pwa_dependency_exact_versions_selected",
            "router_family_selected",
            "router_package_selected",
            "router_exact_version_selected",
            "third_party_ui_component_framework_selected",
            "third_party_css_framework_selected",
            "third_party_styling_artifact_selected",
            "ecosystem_artifact_registry_proof_performed",
            "ecosystem_artifact_downloaded",
            "ecosystem_artifact_integrity_verified",
            "runtime_config_path_selected",
            "runtime_config_schema_selected",
            "runtime_config_headers_selected",
            "runtime_config_byte_limit_selected",
            "runtime_config_values_processed",
            "runtime_config_fetched",
            "runtime_config_validated",
            "public_client_application_created",
            "axe_or_playwright_claimed_as_conformance_proof",
            "real_safari_ios_proof_performed",
            "real_device_manual_accessibility_checks_performed",
            "scaffold_target_created",
            "scaffold_file_written",
            "package_manifest_created_or_modified",
            "lockfile_created_or_modified",
            "dependency_tree_resolved",
            "dependency_installed",
            "lifecycle_script_executed",
            "package_manager_executed",
            "registry_or_network_access_performed",
            "frontend_source_modified",
            "web_app_manifest_created",
            "service_worker_implemented",
            "service_worker_registered",
            "service_worker_runtime_cache_configured",
            "ordinary_http_cache_policy_selected",
            "protected_response_cached",
            "browser_bundle_built",
            "browser_runtime_executed",
            "popup_auth_flow_executed",
            "frontend_test_runtime_executed",
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
            raise ValueError("architecture-selection required control is invalid")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError(
                "architecture-selection deferred or mutation control is invalid"
            )


def load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
    document: bytes,
) -> EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt:
    """Validate one exact, offline, non-materializing architecture selection."""

    try:
        if type(document) is not bytes or not document or len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError("architecture-selection document size is invalid")
        parsed = json.loads(document, object_pairs_hook=_pairs)
        model = EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessDocument.model_validate(
            parsed
        )
        canonical_document = _canonical(model.model_dump(mode="json"))
        architecture_plan = {
            "target_root": SCAFFOLD_TARGET_ROOT,
            "rendering_model": RENDERING_MODEL,
            "ui_framework_family": UI_FRAMEWORK_FAMILY,
            "ui_framework_major_family": UI_FRAMEWORK_MAJOR_FAMILY,
            "dom_renderer_family": DOM_RENDERER_FAMILY,
            "dom_renderer_major_family": DOM_RENDERER_MAJOR_FAMILY,
            "language_family": LANGUAGE_FAMILY,
            "build_tool_family": BUILD_TOOL_FAMILY,
            "build_tool_major_family": BUILD_TOOL_MAJOR_FAMILY,
            "react_build_plugin_family": REACT_BUILD_PLUGIN_FAMILY,
            "module_format": MODULE_FORMAT,
            "routing": {
                "capability": ROUTING_CAPABILITY,
                "router_selection": ROUTER_SELECTION,
                "static_host_spa_fallback_for_non_asset_routes_required": True,
                "api_and_static_asset_paths_excluded": True,
                "exact_successor_proof_required": True,
            },
            "node_runtime_family": NODE_RUNTIME_FAMILY,
            "package_manager_family": PACKAGE_MANAGER_FAMILY,
            "lockfile": {"name": LOCKFILE_NAME, "version": LOCKFILE_VERSION},
            "path_refinement": {
                "step234_provisional_paths": STEP234_PROVISIONAL_SCAFFOLD_PATHS,
                "disposition": PATH_PLAN_DISPOSITION,
                "final_allowlist": FINAL_PATH_ALLOWLIST_SELECTION,
                "authorizes_materialization": False,
                "react_typescript_entry_surface_requires_future_review": True,
                "vite_configuration_surface_requires_future_review": True,
            },
            "production_posture": {
                "static_dist_host_required": True,
                "vite_preview_forbidden": True,
                "development_server_loopback_only": True,
                "permissive_vite_development_cors_forbidden": True,
            },
            "controlled_registry_evidence": {
                "engine_compatibility_proof_required": True,
                "license_disposition_required": True,
                "deprecation_disposition_required": True,
                "advisory_disposition_required": True,
            },
            "styling": {
                "posture": STYLING_POSTURE,
                "third_party_ui_component_framework": "unselected",
                "third_party_css_framework": "unselected",
                "third_party_styling_artifact": "unselected",
            },
        }
        security_plan = {
            "authentication_client_family": AUTHENTICATION_CLIENT_FAMILY,
            "react_auth_wrapper": {
                "package": MSAL_REACT_WRAPPER_PACKAGE,
                "disposition": REACT_AUTH_WRAPPER_DISPOSITION,
            },
            "interaction": {
                "model": AUTHENTICATION_INTERACTION_MODEL,
                "popup": POPUP_INTERACTION_DISPOSITION,
                "redirect_uri": "unselected",
            },
            "approved_dependencies": {
                MSAL_BROWSER_PACKAGE: MSAL_BROWSER_VERSION,
                MSAL_COMMON_PACKAGE: MSAL_COMMON_VERSION,
            },
            "cache": {
                "location": AUTHENTICATION_CACHE_LOCATION,
                "local_storage_forbidden": True,
                "removed_msal_v5_options_forbidden": (
                    FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS
                ),
            },
            "network_client_configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
            "zero_retry_network_client_sha256": ZERO_RETRY_NETWORK_CLIENT_SHA256,
            "network_client_instances": 1,
            "public_client_application_instances": 1,
            "default_network_client_forbidden": True,
            "application_managed_custom_or_non_msal_auth_token_persistence_forbidden": (
                True
            ),
            "token_endpoint_post_retries": 0,
            "public_client_pkce_required": True,
            "client_secret_forbidden": True,
            "public_browser_environment_values_only": True,
            "runtime_configuration": {
                "posture": PUBLIC_RUNTIME_CONFIG_POSTURE,
                "same_origin_json_required": True,
                "exact_schema_required": True,
                "fail_closed_validation_required": True,
                "validation_before_pca_creation_required": True,
                "service_worker_cache_forbidden": True,
                "vite_auth_or_api_configuration_forbidden": True,
                "path_schema_headers_byte_limit_and_values": "unselected",
            },
        }
        experience_and_test_plan = {
            "pwa_posture": PWA_POSTURE,
            "web_app_manifest_created": False,
            "service_worker_enabled": False,
            "service_worker_sensitive_runtime_cache_configured": False,
            "ordinary_http_cache_policy": "unselected",
            "experience_posture": EXPERIENCE_POSTURE,
            "styling_posture": STYLING_POSTURE,
            "accessibility_target": ACCESSIBILITY_TARGET,
            "primary_control_product_target": PRIMARY_CONTROL_PRODUCT_TARGET,
            "accessibility_automation_family": ACCESSIBILITY_AUTOMATION_FAMILY,
            "automation_is_conformance_proof": False,
            "real_safari_ios_proof_performed": False,
            "real_device_manual_checks_performed": False,
            "test_families": {
                "unit": UNIT_TEST_FAMILY,
                "component": COMPONENT_TEST_FAMILY,
                "end_to_end": END_TO_END_TEST_FAMILY,
            },
        }
        return EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            approved_step234_package_manifest_sha256=STEP234_PACKAGE_MANIFEST_SHA256,
            approved_step234_accepted_state_manifest_sha256=(
                STEP234_ACCEPTED_STATE_MANIFEST_SHA256
            ),
            approved_step234_scaffold_decision_readiness_sha256=(
                STEP234_SCAFFOLD_DECISION_READINESS_SHA256
            ),
            approved_step234_scaffold_decision_test_sha256=(
                STEP234_SCAFFOLD_DECISION_TEST_SHA256
            ),
            approved_step234_canonical_receipt_sha256=(
                STEP234_CANONICAL_RECEIPT_SHA256
            ),
            approved_step234_readiness_document_sha256=(
                STEP234_READINESS_DOCUMENT_SHA256
            ),
            approved_step234_scaffold_plan_sha256=STEP234_SCAFFOLD_PLAN_SHA256,
            approved_step234_security_integration_plan_sha256=(
                STEP234_SECURITY_INTEGRATION_PLAN_SHA256
            ),
            approved_step234_deferred_gate_plan_sha256=(
                STEP234_DEFERRED_GATE_PLAN_SHA256
            ),
            approved_step234_status=STEP234_STATUS,
            scaffold_target_root=SCAFFOLD_TARGET_ROOT,
            step234_provisional_path_count=len(STEP234_PROVISIONAL_SCAFFOLD_PATHS),
            path_plan_disposition=PATH_PLAN_DISPOSITION,
            final_path_allowlist_selection=FINAL_PATH_ALLOWLIST_SELECTION,
            rendering_model=RENDERING_MODEL,
            ui_framework_family=UI_FRAMEWORK_FAMILY,
            ui_framework_major_family=UI_FRAMEWORK_MAJOR_FAMILY,
            dom_renderer_family=DOM_RENDERER_FAMILY,
            dom_renderer_major_family=DOM_RENDERER_MAJOR_FAMILY,
            language_family=LANGUAGE_FAMILY,
            build_tool_family=BUILD_TOOL_FAMILY,
            build_tool_major_family=BUILD_TOOL_MAJOR_FAMILY,
            react_build_plugin_family=REACT_BUILD_PLUGIN_FAMILY,
            module_format=MODULE_FORMAT,
            routing_capability=ROUTING_CAPABILITY,
            router_selection=ROUTER_SELECTION,
            node_runtime_family=NODE_RUNTIME_FAMILY,
            package_manager_family=PACKAGE_MANAGER_FAMILY,
            lockfile_name=LOCKFILE_NAME,
            lockfile_version=LOCKFILE_VERSION,
            authentication_client_family=AUTHENTICATION_CLIENT_FAMILY,
            react_auth_wrapper_disposition=REACT_AUTH_WRAPPER_DISPOSITION,
            authentication_cache_location=AUTHENTICATION_CACHE_LOCATION,
            authentication_interaction_model=AUTHENTICATION_INTERACTION_MODEL,
            popup_interaction_disposition=POPUP_INTERACTION_DISPOSITION,
            public_runtime_config_posture=PUBLIC_RUNTIME_CONFIG_POSTURE,
            pwa_posture=PWA_POSTURE,
            experience_posture=EXPERIENCE_POSTURE,
            styling_posture=STYLING_POSTURE,
            accessibility_target=ACCESSIBILITY_TARGET,
            primary_control_product_target=PRIMARY_CONTROL_PRODUCT_TARGET,
            accessibility_automation_family=ACCESSIBILITY_AUTOMATION_FAMILY,
            unit_test_family=UNIT_TEST_FAMILY,
            component_test_family=COMPONENT_TEST_FAMILY,
            end_to_end_test_family=END_TO_END_TEST_FAMILY,
            msal_browser_package=MSAL_BROWSER_PACKAGE,
            msal_browser_version=MSAL_BROWSER_VERSION,
            msal_common_package=MSAL_COMMON_PACKAGE,
            msal_common_version=MSAL_COMMON_VERSION,
            network_client_configuration_seam=NETWORK_CLIENT_CONFIGURATION_SEAM,
            forbidden_removed_msal_v5_cache_option_count=len(
                FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS
            ),
            deferred_gate_count=len(DEFERRED_GATES),
            readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            architecture_plan_sha256=_framed("architecture-plan", architecture_plan),
            security_plan_sha256=_framed("security-plan", security_plan),
            experience_and_test_plan_sha256=_framed(
                "experience-and-test-plan", experience_and_test_plan
            ),
            deferred_gate_plan_sha256=_framed("deferred-gates", DEFERRED_GATES),
            exact_step234_chain_bound=True,
            exact_step234_canonical_receipt_identity_bound=True,
            accepted_step234_blocked_outcome_preserved=True,
            client_rendered_static_spa_family_selected_offline=True,
            react_family_selected_offline=True,
            react_19_major_family_selected_offline=True,
            react_dom_family_selected_offline=True,
            react_dom_19_major_family_selected_offline=True,
            strict_typescript_family_selected_offline=True,
            vite_family_selected_offline=True,
            vite_8_major_family_selected_offline=True,
            official_vite_react_plugin_family_selected_offline=True,
            esm_family_selected_offline=True,
            client_side_browser_history_routing_required=True,
            router_selection_deferred=True,
            static_host_spa_fallback_for_non_asset_routes_required=True,
            spa_fallback_excludes_api_and_static_asset_paths_required=True,
            exact_spa_fallback_successor_proof_required=True,
            node_24_lts_family_selected_offline=True,
            npm_package_lock_v3_policy_preserved=True,
            direct_msal_browser_boundary_preserved=True,
            direct_msal_browser_integration_selected=True,
            msal_react_wrapper_forbidden=True,
            msal_react_requires_separately_reviewed_superseding_revision=True,
            approved_exact_msal_versions_preserved=True,
            msal_authentication_cache_session_storage_required=True,
            local_storage_for_authentication_cache_forbidden=True,
            removed_msal_v5_cache_options_forbidden=True,
            zero_retry_network_client_required=True,
            exactly_one_network_client_instance_required=True,
            exactly_one_public_client_application_instance_required=True,
            default_msal_network_client_forbidden=True,
            custom_or_non_msal_token_persistence_forbidden=True,
            token_endpoint_post_retry_forbidden=True,
            public_client_pkce_required=True,
            client_secret_forbidden=True,
            redirect_first_auth_architecture_selected=True,
            popup_initial_auth_flow_forbidden=True,
            pwa_future_extension_deferred=True,
            web_app_manifest_initially_forbidden=True,
            service_worker_initially_forbidden=True,
            initial_service_worker_caching_of_auth_config_tokens_and_protected_api_responses_forbidden=True,
            separately_reviewed_encrypted_offline_app_data_design_not_precluded=True,
            mobile_first_responsive_required=True,
            semantic_html_required=True,
            css_modules_selected_offline=True,
            custom_property_design_tokens_required=True,
            mobile_first_base_styles_required=True,
            wcag_2_2_level_aa_target_required=True,
            primary_controls_44_by_44_css_pixels_product_target_required=True,
            axe_and_playwright_automation_is_not_conformance_proof=True,
            real_safari_ios_proof_required=True,
            real_device_manual_accessibility_checks_required=True,
            vitest_family_selected_offline=True,
            react_testing_library_family_selected_offline=True,
            axe_core_supporting_checks_family_selected_offline=True,
            playwright_family_selected_offline=True,
            static_dist_production_host_required=True,
            vite_preview_production_host_forbidden=True,
            loopback_only_development_server_required=True,
            permissive_vite_development_cors_forbidden=True,
            public_browser_environment_values_only_required=True,
            vite_public_non_secret_build_metadata_only_required=True,
            vite_auth_and_api_runtime_configuration_forbidden=True,
            same_origin_json_runtime_configuration_required=True,
            exact_runtime_configuration_schema_required=True,
            runtime_configuration_fail_closed_validation_required=True,
            runtime_configuration_validation_before_pca_creation_required=True,
            runtime_configuration_service_worker_cache_forbidden=True,
            exact_runtime_config_path_headers_bytes_values_required_in_successor=True,
            step234_provisional_five_path_plan_bound=True,
            step234_main_ts_not_authorized_for_react_materialization=True,
            step234_provisional_plan_lacked_vite_config=True,
            step234_provisional_paths_non_authorizing=True,
            final_path_allowlist_required_before_materialization=True,
            controlled_registry_compatibility_proof_required=True,
            exact_ecosystem_versions_required_in_successor=True,
            react_and_react_dom_exact_version_parity_required=True,
            toolchain_peer_compatibility_proof_required=True,
            exact_registry_tarball_integrity_required=True,
            registry_signature_and_provenance_status_or_explicit_absence_disposition_required=True,
            registry_engines_deprecations_licenses_and_advisory_status_proof_required=True,
            lifecycle_scripts_disabled_during_future_resolution=True,
            frozen_npm_ci_required_after_lock=True,
            exact_bundle_import_graph_proof_required=True,
            redirect_cors_csp_pkce_journey_proof_required=True,
            architecture_family_selection_authorizes_materialization=False,
            final_scaffold_path_allowlist_selected=False,
            react_exact_version_selected=False,
            react_dom_exact_version_selected=False,
            typescript_exact_version_selected=False,
            typescript_major_version_selected=False,
            vite_exact_version_selected=False,
            vite_plugin_react_exact_version_selected=False,
            node_exact_patch_version_selected=False,
            testing_dependency_exact_versions_selected=False,
            pwa_dependency_exact_versions_selected=False,
            router_family_selected=False,
            router_package_selected=False,
            router_exact_version_selected=False,
            third_party_ui_component_framework_selected=False,
            third_party_css_framework_selected=False,
            third_party_styling_artifact_selected=False,
            ecosystem_artifact_registry_proof_performed=False,
            ecosystem_artifact_downloaded=False,
            ecosystem_artifact_integrity_verified=False,
            runtime_config_path_selected=False,
            runtime_config_schema_selected=False,
            runtime_config_headers_selected=False,
            runtime_config_byte_limit_selected=False,
            runtime_config_values_processed=False,
            runtime_config_fetched=False,
            runtime_config_validated=False,
            public_client_application_created=False,
            axe_or_playwright_claimed_as_conformance_proof=False,
            real_safari_ios_proof_performed=False,
            real_device_manual_accessibility_checks_performed=False,
            scaffold_target_created=False,
            scaffold_file_written=False,
            package_manifest_created_or_modified=False,
            lockfile_created_or_modified=False,
            dependency_tree_resolved=False,
            dependency_installed=False,
            lifecycle_script_executed=False,
            package_manager_executed=False,
            registry_or_network_access_performed=False,
            frontend_source_modified=False,
            web_app_manifest_created=False,
            service_worker_implemented=False,
            service_worker_registered=False,
            service_worker_runtime_cache_configured=False,
            ordinary_http_cache_policy_selected=False,
            protected_response_cached=False,
            browser_bundle_built=False,
            browser_runtime_executed=False,
            popup_auth_flow_executed=False,
            frontend_test_runtime_executed=False,
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
            step234_scaffold_decision_boundary_preserved=True,
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError(
            "frontend-host architecture selection readiness validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_architecture_selection_readiness_receipt(
    receipt: EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt,
) -> bytes:
    """Render only the exact validated Step 235 receipt as canonical JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt:
        raise TypeError("exact frontend-host architecture-selection receipt is required")
    receipt.__post_init__()
    rendered = _canonical(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
    )
    if hashlib.sha256(rendered).hexdigest() != CANONICAL_RECEIPT_SHA256:
        raise ValueError("architecture-selection receipt identity is invalid")
    return rendered


__all__ = [
    "ACCESSIBILITY_AUTOMATION_FAMILY",
    "ACCESSIBILITY_TARGET",
    "ARCHITECTURE_PLAN_SHA256",
    "AUTHENTICATION_CACHE_LOCATION",
    "AUTHENTICATION_CLIENT_FAMILY",
    "AUTHENTICATION_INTERACTION_MODEL",
    "BUILD_TOOL_FAMILY",
    "BUILD_TOOL_MAJOR_FAMILY",
    "CANONICAL_RECEIPT_SHA256",
    "COMPONENT_TEST_FAMILY",
    "DEFERRED_GATES",
    "DEFERRED_GATE_PLAN_SHA256",
    "DOCUMENT_TYPE",
    "DOM_RENDERER_FAMILY",
    "DOM_RENDERER_MAJOR_FAMILY",
    "END_TO_END_TEST_FAMILY",
    "EXPERIENCE_AND_TEST_PLAN_SHA256",
    "EXPERIENCE_POSTURE",
    "FINAL_PATH_ALLOWLIST_SELECTION",
    "FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS",
    "LANGUAGE_FAMILY",
    "LOCKFILE_NAME",
    "LOCKFILE_VERSION",
    "MAX_DOCUMENT_BYTES",
    "MODULE_FORMAT",
    "MSAL_BROWSER_PACKAGE",
    "MSAL_BROWSER_VERSION",
    "MSAL_COMMON_PACKAGE",
    "MSAL_COMMON_VERSION",
    "MSAL_REACT_WRAPPER_PACKAGE",
    "NETWORK_CLIENT_CONFIGURATION_SEAM",
    "NODE_RUNTIME_FAMILY",
    "PACKAGE_MANAGER_FAMILY",
    "PATH_PLAN_DISPOSITION",
    "POPUP_INTERACTION_DISPOSITION",
    "PRIMARY_CONTROL_PRODUCT_TARGET",
    "PUBLIC_RUNTIME_CONFIG_POSTURE",
    "PWA_POSTURE",
    "REACT_AUTH_WRAPPER_DISPOSITION",
    "REACT_BUILD_PLUGIN_FAMILY",
    "ROUTER_SELECTION",
    "ROUTING_CAPABILITY",
    "READINESS_DOCUMENT_SHA256",
    "RECEIPT_TYPE",
    "RENDERING_MODEL",
    "SCAFFOLD_TARGET_ROOT",
    "SCHEMA_VERSION",
    "SCOPE",
    "SECURITY_PLAN_SHA256",
    "SOURCE",
    "STATUS",
    "STYLING_POSTURE",
    "STEP234_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP234_CANONICAL_RECEIPT_SHA256",
    "STEP234_DEFERRED_GATE_PLAN_SHA256",
    "STEP234_PACKAGE_MANIFEST_SHA256",
    "STEP234_PROVISIONAL_SCAFFOLD_PATHS",
    "STEP234_READINESS_DOCUMENT_SHA256",
    "STEP234_SCAFFOLD_DECISION_READINESS_SHA256",
    "STEP234_SCAFFOLD_DECISION_TEST_SHA256",
    "STEP234_SCAFFOLD_PLAN_SHA256",
    "STEP234_SECURITY_INTEGRATION_PLAN_SHA256",
    "STEP234_STATUS",
    "UI_FRAMEWORK_FAMILY",
    "UI_FRAMEWORK_MAJOR_FAMILY",
    "UNIT_TEST_FAMILY",
    "ZERO_RETRY_NETWORK_CLIENT_SHA256",
    "EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessDocument",
    "EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError",
    "EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt",
    "load_entra_calling_client_msal_frontend_host_architecture_selection_readiness",
    "render_entra_calling_client_msal_frontend_host_architecture_selection_readiness_receipt",
]
