from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import json

import pytest

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_architecture_selection_readiness
    as readiness,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _valid_document() -> dict[str, object]:
    return {
        "document_type": readiness.DOCUMENT_TYPE,
        "schema_version": readiness.SCHEMA_VERSION,
        "source": readiness.SOURCE,
        "approved_step234_package_manifest_sha256": (
            readiness.STEP234_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step234_accepted_state_manifest_sha256": (
            readiness.STEP234_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step234_scaffold_decision_readiness_sha256": (
            readiness.STEP234_SCAFFOLD_DECISION_READINESS_SHA256
        ),
        "approved_step234_scaffold_decision_test_sha256": (
            readiness.STEP234_SCAFFOLD_DECISION_TEST_SHA256
        ),
        "approved_step234_canonical_receipt_sha256": (
            readiness.STEP234_CANONICAL_RECEIPT_SHA256
        ),
        "approved_step234_readiness_document_sha256": (
            readiness.STEP234_READINESS_DOCUMENT_SHA256
        ),
        "approved_step234_scaffold_plan_sha256": (
            readiness.STEP234_SCAFFOLD_PLAN_SHA256
        ),
        "approved_step234_security_integration_plan_sha256": (
            readiness.STEP234_SECURITY_INTEGRATION_PLAN_SHA256
        ),
        "approved_step234_deferred_gate_plan_sha256": (
            readiness.STEP234_DEFERRED_GATE_PLAN_SHA256
        ),
        "approved_step234_status": readiness.STEP234_STATUS,
        "scaffold_target_root": readiness.SCAFFOLD_TARGET_ROOT,
        "path_plan_disposition": readiness.PATH_PLAN_DISPOSITION,
        "final_path_allowlist_selection": (
            readiness.FINAL_PATH_ALLOWLIST_SELECTION
        ),
        "rendering_model": readiness.RENDERING_MODEL,
        "ui_framework_family": readiness.UI_FRAMEWORK_FAMILY,
        "ui_framework_major_family": readiness.UI_FRAMEWORK_MAJOR_FAMILY,
        "dom_renderer_family": readiness.DOM_RENDERER_FAMILY,
        "dom_renderer_major_family": readiness.DOM_RENDERER_MAJOR_FAMILY,
        "language_family": readiness.LANGUAGE_FAMILY,
        "build_tool_family": readiness.BUILD_TOOL_FAMILY,
        "build_tool_major_family": readiness.BUILD_TOOL_MAJOR_FAMILY,
        "react_build_plugin_family": readiness.REACT_BUILD_PLUGIN_FAMILY,
        "module_format": readiness.MODULE_FORMAT,
        "routing_capability": readiness.ROUTING_CAPABILITY,
        "router_selection": readiness.ROUTER_SELECTION,
        "node_runtime_family": readiness.NODE_RUNTIME_FAMILY,
        "package_manager_family": readiness.PACKAGE_MANAGER_FAMILY,
        "lockfile_name": readiness.LOCKFILE_NAME,
        "lockfile_version": readiness.LOCKFILE_VERSION,
        "authentication_client_family": readiness.AUTHENTICATION_CLIENT_FAMILY,
        "react_auth_wrapper_disposition": (
            readiness.REACT_AUTH_WRAPPER_DISPOSITION
        ),
        "authentication_cache_location": (
            readiness.AUTHENTICATION_CACHE_LOCATION
        ),
        "authentication_interaction_model": (
            readiness.AUTHENTICATION_INTERACTION_MODEL
        ),
        "popup_interaction_disposition": readiness.POPUP_INTERACTION_DISPOSITION,
        "public_runtime_config_posture": readiness.PUBLIC_RUNTIME_CONFIG_POSTURE,
        "pwa_posture": readiness.PWA_POSTURE,
        "experience_posture": readiness.EXPERIENCE_POSTURE,
        "styling_posture": readiness.STYLING_POSTURE,
        "accessibility_target": readiness.ACCESSIBILITY_TARGET,
        "primary_control_product_target": (
            readiness.PRIMARY_CONTROL_PRODUCT_TARGET
        ),
        "accessibility_automation_family": (
            readiness.ACCESSIBILITY_AUTOMATION_FAMILY
        ),
        "unit_test_family": readiness.UNIT_TEST_FAMILY,
        "component_test_family": readiness.COMPONENT_TEST_FAMILY,
        "end_to_end_test_family": readiness.END_TO_END_TEST_FAMILY,
    }


def _load() -> readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessReceipt:
    return readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
        _canonical(_valid_document())
    )


def _different(value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + "_changed"
    raise AssertionError(f"unsupported fixture type: {type(value)!r}")


def _wrong_type(value: object) -> object:
    if type(value) is bool:
        return 0
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return 0
    raise AssertionError(f"unsupported fixture type: {type(value)!r}")


TRUE_RECEIPT_CONTROLS = set(
    """
    exact_step234_chain_bound
    exact_step234_canonical_receipt_identity_bound
    accepted_step234_blocked_outcome_preserved
    client_rendered_static_spa_family_selected_offline
    react_family_selected_offline
    react_19_major_family_selected_offline
    react_dom_family_selected_offline
    react_dom_19_major_family_selected_offline
    strict_typescript_family_selected_offline
    vite_family_selected_offline
    vite_8_major_family_selected_offline
    official_vite_react_plugin_family_selected_offline
    esm_family_selected_offline
    client_side_browser_history_routing_required
    router_selection_deferred
    static_host_spa_fallback_for_non_asset_routes_required
    spa_fallback_excludes_api_and_static_asset_paths_required
    exact_spa_fallback_successor_proof_required
    node_24_lts_family_selected_offline
    npm_package_lock_v3_policy_preserved
    direct_msal_browser_boundary_preserved
    direct_msal_browser_integration_selected
    msal_react_wrapper_forbidden
    msal_react_requires_separately_reviewed_superseding_revision
    approved_exact_msal_versions_preserved
    msal_authentication_cache_session_storage_required
    local_storage_for_authentication_cache_forbidden
    removed_msal_v5_cache_options_forbidden
    zero_retry_network_client_required
    exactly_one_network_client_instance_required
    exactly_one_public_client_application_instance_required
    default_msal_network_client_forbidden
    custom_or_non_msal_token_persistence_forbidden
    token_endpoint_post_retry_forbidden
    public_client_pkce_required
    client_secret_forbidden
    redirect_first_auth_architecture_selected
    popup_initial_auth_flow_forbidden
    pwa_future_extension_deferred
    web_app_manifest_initially_forbidden
    service_worker_initially_forbidden
    initial_service_worker_caching_of_auth_config_tokens_and_protected_api_responses_forbidden
    separately_reviewed_encrypted_offline_app_data_design_not_precluded
    mobile_first_responsive_required
    semantic_html_required
    css_modules_selected_offline
    custom_property_design_tokens_required
    mobile_first_base_styles_required
    wcag_2_2_level_aa_target_required
    primary_controls_44_by_44_css_pixels_product_target_required
    axe_and_playwright_automation_is_not_conformance_proof
    real_safari_ios_proof_required
    real_device_manual_accessibility_checks_required
    vitest_family_selected_offline
    react_testing_library_family_selected_offline
    axe_core_supporting_checks_family_selected_offline
    playwright_family_selected_offline
    static_dist_production_host_required
    vite_preview_production_host_forbidden
    loopback_only_development_server_required
    permissive_vite_development_cors_forbidden
    public_browser_environment_values_only_required
    vite_public_non_secret_build_metadata_only_required
    vite_auth_and_api_runtime_configuration_forbidden
    same_origin_json_runtime_configuration_required
    exact_runtime_configuration_schema_required
    runtime_configuration_fail_closed_validation_required
    runtime_configuration_validation_before_pca_creation_required
    runtime_configuration_service_worker_cache_forbidden
    exact_runtime_config_path_headers_bytes_values_required_in_successor
    step234_provisional_five_path_plan_bound
    step234_main_ts_not_authorized_for_react_materialization
    step234_provisional_plan_lacked_vite_config
    step234_provisional_paths_non_authorizing
    final_path_allowlist_required_before_materialization
    controlled_registry_compatibility_proof_required
    exact_ecosystem_versions_required_in_successor
    react_and_react_dom_exact_version_parity_required
    toolchain_peer_compatibility_proof_required
    exact_registry_tarball_integrity_required
    registry_signature_and_provenance_status_or_explicit_absence_disposition_required
    registry_engines_deprecations_licenses_and_advisory_status_proof_required
    lifecycle_scripts_disabled_during_future_resolution
    frozen_npm_ci_required_after_lock
    exact_bundle_import_graph_proof_required
    redirect_cors_csp_pkce_journey_proof_required
    step216_zero_retry_policy_preserved
    step225_default_retry_rejection_preserved
    step230_container_proof_boundary_preserved
    step231_dependency_lock_plan_preserved
    step232_synthetic_live_provenance_separation_preserved
    step233_live_no_host_boundary_preserved
    step234_scaffold_decision_boundary_preserved
    """.split()
)

FALSE_RECEIPT_CONTROLS = set(
    """
    architecture_family_selection_authorizes_materialization
    final_scaffold_path_allowlist_selected
    react_exact_version_selected
    react_dom_exact_version_selected
    typescript_exact_version_selected
    typescript_major_version_selected
    vite_exact_version_selected
    vite_plugin_react_exact_version_selected
    node_exact_patch_version_selected
    testing_dependency_exact_versions_selected
    pwa_dependency_exact_versions_selected
    router_family_selected
    router_package_selected
    router_exact_version_selected
    third_party_ui_component_framework_selected
    third_party_css_framework_selected
    third_party_styling_artifact_selected
    ecosystem_artifact_registry_proof_performed
    ecosystem_artifact_downloaded
    ecosystem_artifact_integrity_verified
    runtime_config_path_selected
    runtime_config_schema_selected
    runtime_config_headers_selected
    runtime_config_byte_limit_selected
    runtime_config_values_processed
    runtime_config_fetched
    runtime_config_validated
    public_client_application_created
    axe_or_playwright_claimed_as_conformance_proof
    real_safari_ios_proof_performed
    real_device_manual_accessibility_checks_performed
    scaffold_target_created
    scaffold_file_written
    package_manifest_created_or_modified
    lockfile_created_or_modified
    dependency_tree_resolved
    dependency_installed
    lifecycle_script_executed
    package_manager_executed
    registry_or_network_access_performed
    frontend_source_modified
    web_app_manifest_created
    service_worker_implemented
    service_worker_registered
    service_worker_runtime_cache_configured
    ordinary_http_cache_policy_selected
    protected_response_cached
    browser_bundle_built
    browser_runtime_executed
    popup_auth_flow_executed
    frontend_test_runtime_executed
    real_oauth_values_processed
    deploy_time_public_client_configuration_applied
    redirect_uri_operationally_selected
    api_origin_and_cors_operationally_selected
    csp_and_security_headers_applied
    responsive_layout_implemented
    accessibility_validation_performed
    application_configuration_modified
    docker_or_compose_modified
    application_activated
    operational_write_performed
    """.split()
)


def test_exact_step234_chain_identities() -> None:
    assert readiness.STEP234_PACKAGE_MANIFEST_SHA256 == (
        "806d8082896fbba4d1e5b6970b57f5ae6aa0c296012fdadf09e495e11de9327c"
    )
    assert readiness.STEP234_ACCEPTED_STATE_MANIFEST_SHA256 == (
        "96ef8a3d77043f058036be5b9efa2f250746f9a5155c37fbf94aa75798c6a991"
    )
    assert readiness.STEP234_SCAFFOLD_DECISION_READINESS_SHA256 == (
        "254680a78772258aadc430aa8fb2539249c4d77c461cf1b8b28fa5f1060fd1d7"
    )
    assert readiness.STEP234_SCAFFOLD_DECISION_TEST_SHA256 == (
        "49d0c33c441f616b83da5af8a1e9c1a28d796fa6e0cb3c4ab40af2575478ba5b"
    )
    assert readiness.STEP234_CANONICAL_RECEIPT_SHA256 == (
        "8172f0f2f47b7167fed509769b6bcf465cd4780bcc01bf60dc959c7385198276"
    )
    assert readiness.STEP234_READINESS_DOCUMENT_SHA256 == (
        "275edba62b536bd2849c8e951c23db8a591a119c788d563bf8e77e8a1cf5b321"
    )
    assert readiness.STEP234_SCAFFOLD_PLAN_SHA256 == (
        "6e2f30dedf03555d8ae6ff1bf4705328ad0b0f21181f418065ee4195aa404fbb"
    )
    assert readiness.STEP234_SECURITY_INTEGRATION_PLAN_SHA256 == (
        "c2ec07fe27dc8937cee4f81e25470073d007bf981333574d84319990b5d452fd"
    )
    assert readiness.STEP234_DEFERRED_GATE_PLAN_SHA256 == (
        "1bc72efd3aab404b6574365f5946a7092451d868d2f3595307c91aa2f711526a"
    )


def test_exact_selected_architecture_families_and_deferred_versions() -> None:
    receipt = _load()
    assert receipt.rendering_model == "client_rendered_static_browser_spa"
    assert (receipt.ui_framework_family, receipt.ui_framework_major_family) == (
        "react",
        19,
    )
    assert (receipt.dom_renderer_family, receipt.dom_renderer_major_family) == (
        "react_dom",
        19,
    )
    assert receipt.react_dom_19_major_family_selected_offline is True
    assert receipt.language_family == "typescript_strict"
    assert (receipt.build_tool_family, receipt.build_tool_major_family) == (
        "vite",
        8,
    )
    assert receipt.react_build_plugin_family == "@vitejs/plugin-react"
    assert receipt.module_format == "esm"
    assert receipt.node_runtime_family == "node_24_lts"
    assert receipt.router_selection == "unselected"
    assert receipt.typescript_major_version_selected is False
    assert receipt.react_exact_version_selected is False
    assert receipt.vite_exact_version_selected is False


def test_vite_development_cors_and_registry_evidence_requirements_are_bound() -> None:
    receipt = _load()
    assert receipt.loopback_only_development_server_required is True
    assert receipt.permissive_vite_development_cors_forbidden is True
    assert (
        receipt.registry_engines_deprecations_licenses_and_advisory_status_proof_required
        is True
    )
    loader_source = inspect.getsource(
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness
    )
    for required_registry_key in (
        "engine_compatibility_proof_required",
        "license_disposition_required",
        "deprecation_disposition_required",
        "advisory_disposition_required",
    ):
        assert f'"{required_registry_key}": True' in loader_source


def test_path_refinement_is_non_authorizing_and_final_allowlist_unselected() -> None:
    receipt = _load()
    assert readiness.STEP234_PROVISIONAL_SCAFFOLD_PATHS == (
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/index.html",
        "frontend/tsconfig.json",
        "frontend/src/main.ts",
    )
    assert receipt.path_plan_disposition == (
        "step234_provisional_five_path_plan_retained_as_non_authorizing_input_"
        "pending_react_vite_allowlist"
    )
    assert receipt.step234_main_ts_not_authorized_for_react_materialization is True
    assert receipt.step234_provisional_plan_lacked_vite_config is True
    assert receipt.final_path_allowlist_selection == "unselected"
    assert receipt.final_scaffold_path_allowlist_selected is False


def test_direct_msal_redirect_first_cache_and_removed_v5_option_contract() -> None:
    receipt = _load()
    assert receipt.authentication_client_family == "@azure/msal-browser"
    assert receipt.react_auth_wrapper_disposition == (
        "forbidden_initial_architecture_unless_separately_reviewed_revision_"
        "supersedes_step235"
    )
    assert receipt.authentication_interaction_model == "redirect_first"
    assert receipt.popup_interaction_disposition == "forbidden_initial_architecture"
    assert receipt.authentication_cache_location == "sessionStorage"
    assert readiness.FORBIDDEN_REMOVED_MSAL_V5_CACHE_OPTIONS == (
        "storeAuthStateInCookie",
        "temporaryCacheLocation",
        "secureCookies",
        "claimsBasedCachingEnabled",
        "cacheMigrationEnabled",
    )
    assert receipt.forbidden_removed_msal_v5_cache_option_count == 5
    assert receipt.direct_msal_browser_integration_selected is True
    assert receipt.msal_react_wrapper_forbidden is True
    assert receipt.exactly_one_public_client_application_instance_required is True
    assert receipt.custom_or_non_msal_token_persistence_forbidden is True
    assert receipt.popup_auth_flow_executed is False
    assert receipt.redirect_uri_operationally_selected is False


def test_runtime_config_pwa_styling_accessibility_and_testing_boundaries() -> None:
    receipt = _load()
    assert receipt.public_runtime_config_posture == (
        "future_exact_schema_same_origin_json_validated_before_pca_creation"
    )
    assert receipt.runtime_config_path_selected is False
    assert receipt.runtime_config_schema_selected is False
    assert receipt.runtime_config_headers_selected is False
    assert receipt.runtime_config_byte_limit_selected is False
    assert receipt.runtime_config_values_processed is False
    assert receipt.public_client_application_created is False
    assert receipt.pwa_posture == (
        "future_extension_deferred_initial_manifest_service_worker_and_"
        "sensitive_cache_forbidden"
    )
    assert receipt.web_app_manifest_created is False
    assert receipt.service_worker_implemented is False
    assert receipt.service_worker_runtime_cache_configured is False
    assert receipt.styling_posture == (
        "semantic_html_css_modules_and_custom_property_design_tokens"
    )
    assert receipt.accessibility_target == "wcag_2_2_level_aa"
    assert receipt.primary_control_product_target == "44_by_44_css_pixels"
    assert receipt.accessibility_automation_family == "axe_core_supporting_checks"
    assert receipt.axe_or_playwright_claimed_as_conformance_proof is False
    assert receipt.real_safari_ios_proof_performed is False
    assert receipt.real_device_manual_accessibility_checks_performed is False
    assert receipt.unit_test_family == "vitest"
    assert receipt.component_test_family == "react_testing_library"
    assert receipt.end_to_end_test_family == "playwright"


def test_receipt_boolean_partition_is_exhaustive_and_exact() -> None:
    receipt = _load()
    boolean_fields = {
        name
        for name in receipt.__dataclass_fields__
        if type(getattr(receipt, name)) is bool
    }
    assert TRUE_RECEIPT_CONTROLS.isdisjoint(FALSE_RECEIPT_CONTROLS)
    assert TRUE_RECEIPT_CONTROLS | FALSE_RECEIPT_CONTROLS == boolean_fields
    assert all(getattr(receipt, name) is True for name in TRUE_RECEIPT_CONTROLS)
    assert all(getattr(receipt, name) is False for name in FALSE_RECEIPT_CONTROLS)


def test_canonical_document_and_plan_identities_are_frozen() -> None:
    receipt = _load()
    assert receipt.readiness_document_sha256 == readiness.READINESS_DOCUMENT_SHA256
    assert receipt.architecture_plan_sha256 == readiness.ARCHITECTURE_PLAN_SHA256
    assert receipt.security_plan_sha256 == readiness.SECURITY_PLAN_SHA256
    assert receipt.experience_and_test_plan_sha256 == (
        readiness.EXPERIENCE_AND_TEST_PLAN_SHA256
    )
    assert receipt.deferred_gate_plan_sha256 == readiness.DEFERRED_GATE_PLAN_SHA256
    assert len(readiness.DEFERRED_GATES) == receipt.deferred_gate_count == 11


def test_render_is_canonical_deterministic_and_identity_bound() -> None:
    first = readiness.render_entra_calling_client_msal_frontend_host_architecture_selection_readiness_receipt(
        _load()
    )
    second = readiness.render_entra_calling_client_msal_frontend_host_architecture_selection_readiness_receipt(
        _load()
    )
    assert first == second
    assert first == _canonical(json.loads(first))
    assert not first.endswith(b"\n")
    assert hashlib.sha256(first).hexdigest() == readiness.CANONICAL_RECEIPT_SHA256
    assert len(json.loads(first)) == len(_load().__dataclass_fields__) == 217


@pytest.mark.parametrize("field_name", sorted(_valid_document()))
def test_each_changed_document_field_fails_closed(field_name: str) -> None:
    document = _valid_document()
    document[field_name] = _different(document[field_name])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
            _canonical(document)
        )


@pytest.mark.parametrize("field_name", sorted(_valid_document()))
def test_each_wrong_document_field_type_fails_closed(field_name: str) -> None:
    document = _valid_document()
    document[field_name] = _wrong_type(document[field_name])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
            _canonical(document)
        )


@pytest.mark.parametrize("field_name", sorted(TRUE_RECEIPT_CONTROLS))
def test_each_required_true_receipt_control_rejects_false(field_name: str) -> None:
    with pytest.raises(ValueError, match="required control"):
        dataclasses.replace(_load(), **{field_name: False})


@pytest.mark.parametrize("field_name", sorted(TRUE_RECEIPT_CONTROLS))
def test_each_required_true_receipt_control_rejects_wrong_type(
    field_name: str,
) -> None:
    with pytest.raises(ValueError, match="required control"):
        dataclasses.replace(_load(), **{field_name: 1})


@pytest.mark.parametrize("field_name", sorted(FALSE_RECEIPT_CONTROLS))
def test_each_required_false_receipt_control_rejects_true(field_name: str) -> None:
    with pytest.raises(ValueError, match="deferred or mutation control"):
        dataclasses.replace(_load(), **{field_name: True})


@pytest.mark.parametrize("field_name", sorted(FALSE_RECEIPT_CONTROLS))
def test_each_required_false_receipt_control_rejects_wrong_type(
    field_name: str,
) -> None:
    with pytest.raises(ValueError, match="deferred or mutation control"):
        dataclasses.replace(_load(), **{field_name: 0})


NON_BOOLEAN_RECEIPT_FIELDS = {
    name
    for name in _load().__dataclass_fields__
    if type(getattr(_load(), name)) is not bool
}


@pytest.mark.parametrize("field_name", sorted(NON_BOOLEAN_RECEIPT_FIELDS))
def test_each_non_boolean_receipt_field_is_identity_bound(field_name: str) -> None:
    receipt = _load()
    with pytest.raises(ValueError):
        dataclasses.replace(
            receipt,
            **{field_name: _different(getattr(receipt, field_name))},
        )


@pytest.mark.parametrize("field_name", sorted(NON_BOOLEAN_RECEIPT_FIELDS))
def test_each_non_boolean_receipt_field_rejects_wrong_type(field_name: str) -> None:
    receipt = _load()
    with pytest.raises(ValueError):
        dataclasses.replace(
            receipt,
            **{field_name: _wrong_type(getattr(receipt, field_name))},
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: {**value, "extra": "forbidden"},
        lambda value: {key: item for key, item in value.items() if key != "source"},
    ],
)
def test_document_key_set_is_exact(mutator: object) -> None:
    document = mutator(_valid_document())  # type: ignore[operator]
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
            _canonical(document)
        )


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"null",
        b"[]",
        b"1",
        b"true",
        b"{",
        b'{"document_type":"first","document_type":"second"}',
        b'{"schema_version":NaN}',
        "not-bytes",
        bytearray(b"{}"),
        memoryview(b"{}"),
        None,
    ],
)
def test_malformed_or_wrong_transport_fails_closed(document: object) -> None:
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(  # type: ignore[arg-type]
            document
        )


def test_oversize_document_fails_closed() -> None:
    document = b"{" + b" " * readiness.MAX_DOCUMENT_BYTES + b"}"
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
            document
        )


def test_failure_message_is_sanitized() -> None:
    secret = "client-secret-must-not-escape"
    document = _valid_document()
    document["source"] = secret
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostArchitectureSelectionReadinessError
    ) as captured:
        readiness.load_entra_calling_client_msal_frontend_host_architecture_selection_readiness(
            _canonical(document)
        )
    assert str(captured.value) == (
        "frontend-host architecture selection readiness validation failed"
    )
    assert secret not in str(captured.value)


def test_receipt_is_frozen_slotted_and_renderer_requires_exact_type() -> None:
    receipt = _load()
    assert dataclasses.is_dataclass(receipt)
    assert receipt.__dataclass_params__.frozen is True
    assert not hasattr(receipt, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.readiness_status = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError, match="exact frontend-host"):
        readiness.render_entra_calling_client_msal_frontend_host_architecture_selection_readiness_receipt(  # type: ignore[arg-type]
            object()
        )


def test_public_exports_are_unique_and_resolve() -> None:
    assert len(readiness.__all__) == len(set(readiness.__all__))
    assert all(hasattr(readiness, name) for name in readiness.__all__)


def test_production_module_has_no_io_process_network_cli_or_dynamic_code_capability() -> None:
    source = inspect.getsource(readiness)
    tree = ast.parse(source)
    forbidden_modules = {
        "asyncio",
        "builtins",
        "http",
        "httpx",
        "importlib",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "tempfile",
        "urllib",
    }
    forbidden_calls = {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
        "input",
        "open",
        "print",
    }
    for node in ast.walk(tree):
        assert not isinstance(node, (ast.AsyncFunctionDef, ast.Await))
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] not in forbidden_modules for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_modules
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_calls
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_calls


def test_no_unapproved_frontend_artifact_or_version_is_selected() -> None:
    assert not hasattr(readiness, "REACT_VERSION")
    assert not hasattr(readiness, "REACT_DOM_VERSION")
    assert not hasattr(readiness, "TYPESCRIPT_VERSION")
    assert not hasattr(readiness, "VITE_VERSION")
    assert not hasattr(readiness, "ROUTER_PACKAGE")
    assert not hasattr(readiness, "ROUTER_VERSION")
    source = inspect.getsource(readiness).lower()
    assert "mock_service_worker" not in source
    assert "http_mock_family" not in source
