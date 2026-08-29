from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import json

import pytest

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_scaffold_decision_readiness
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
        "approved_step233_package_manifest_sha256": (
            readiness.STEP233_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step233_accepted_state_manifest_sha256": (
            readiness.STEP233_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step233_live_inventory_loader_sha256": (
            readiness.STEP233_LIVE_INVENTORY_LOADER_SHA256
        ),
        "approved_step233_live_inventory_probe_sha256": (
            readiness.STEP233_LIVE_INVENTORY_PROBE_SHA256
        ),
        "approved_step233_no_host_receipt_sha256": (
            readiness.STEP233_NO_HOST_RECEIPT_SHA256
        ),
        "approved_step231_dependency_lock_readiness_sha256": (
            readiness.STEP231_DEPENDENCY_LOCK_READINESS_SHA256
        ),
        "approved_zero_retry_network_client_sha256": (
            readiness.ZERO_RETRY_NETWORK_CLIENT_SHA256
        ),
        "approved_step233_inventory_profile": readiness.STEP233_INVENTORY_PROFILE,
        "approved_step233_no_host_status": readiness.STEP233_NO_HOST_STATUS,
        "scaffold_target_root": readiness.SCAFFOLD_TARGET_ROOT,
        "scaffold_application_model": readiness.SCAFFOLD_APPLICATION_MODEL,
        "scaffold_language": readiness.SCAFFOLD_LANGUAGE,
        "desired_package_manager": readiness.DESIRED_PACKAGE_MANAGER,
        "desired_lockfile_name": readiness.DESIRED_LOCKFILE_NAME,
        "desired_lockfile_version": readiness.DESIRED_LOCKFILE_VERSION,
        "scaffold_mode": readiness.SCAFFOLD_MODE,
    }


def _step233_no_host_receipt() -> dict[str, object]:
    return {
        "accepted_overlay_path_count": 220,
        "accepted_overlay_projection_sha256": (
            "bbc241458c79d85cce537fd89d08f2a46beb0728eea0083cdfbaffe7581251bc"
        ),
        "application_activated": False,
        "application_configuration_modified": False,
        "approved_branch": "feature/phase-8",
        "approved_head": "89b257fbd72333f17367be0aee82d6157775df33",
        "approved_step232_accepted_state_manifest_sha256": (
            "bbc241458c79d85cce537fd89d08f2a46beb0728eea0083cdfbaffe7581251bc"
        ),
        "approved_step232_inventory_loader_sha256": (
            "2bbbe6cbff726d86bfdd0f48c978fb02a932ef4d12198e951aa088e8a825a76a"
        ),
        "approved_step232_inventory_probe_sha256": (
            "7cb9d6f4340f0b7be0d1ce16d3a26deb1e1ce34267384c98bda411a28525901b"
        ),
        "approved_step232_package_manifest_sha256": (
            "241edaaf2c07f763ab94fba7ba57bc49ae95fda3201cf13eb1cfdc95d5555e00"
        ),
        "before_after_accepted_source_projection_identical": True,
        "browser_bundle_built": False,
        "browser_runtime_executed": False,
        "candidate_frontend_host_selected": False,
        "candidate_root_count": 0,
        "candidate_root_projection_sha256": (
            "c11878691b87261506147ba2389aa113f726a5711b132357f2131fd3ee0b1dfe"
        ),
        "combined_source_path_count": 484,
        "dependency_installed": False,
        "dependency_lock_count": 0,
        "evidence_document_sha256": (
            "2eb3513efd4cda4bbfab5dee826906280b2448ecdd8ea6178565633174c52063"
        ),
        "evidence_provenance": "controlled_local_git_head_object_inventory",
        "exact_accepted_overlay_bound": True,
        "exact_branch_head_and_tree_bound": True,
        "exact_step232_identities_bound": True,
        "frontend_source_modified": False,
        "git_executable_sha256": (
            "c470d205517c7a53ceca321df16a6e4549fcd52b576ab4d09536d36f26fda5a9"
        ),
        "git_object_reader_used": True,
        "git_status_worktree_enumeration_performed": True,
        "head_tree_path_count": 268,
        "head_tree_projection_sha256": (
            "bd16c72d7b02c9621acb9776ab3eb6a52cfe08ad1739e21b45e469dd73f4a923"
        ),
        "host_decision_or_scaffold_required": True,
        "installer_asserted_combined_source_path_projection_sha256": (
            "7425d79f46255bcd28faa370980882eb8de9e819e8c1842054f22917da8e7d1b"
        ),
        "inventory_profile": "engineer4me_frontend_host_live_git_inventory_v2",
        "live_accepted_source_inventory_complete": True,
        "live_package_manifest_candidate_status_determined": True,
        "live_repository_inventory_performed": True,
        "lockfile_created_or_modified": False,
        "marker_file_count": 0,
        "marker_inventory_projection_sha256": (
            "a71e98eac1a0876cb5c199433c4b66310a424b7f4125aafc60c817336a6845b8"
        ),
        "marker_total_bytes": 0,
        "max_accepted_overlay_paths": 220,
        "max_candidate_roots": 1,
        "max_head_tree_paths": 4096,
        "max_marker_files": 128,
        "max_path_bytes": 512,
        "max_single_marker_bytes": 1_048_576,
        "max_total_marker_bytes": 8_388_608,
        "no_package_manifest_candidate_identified": True,
        "observed_lockfile_kind": "none",
        "observed_package_manager": "none",
        "operational_write_performed": False,
        "package_manager_executed": False,
        "package_manager_selected": False,
        "package_manifest_count": 0,
        "package_manifest_created_or_modified": False,
        "proof_document_sha256": (
            "f108d9c1e6fc2b6f085b2fcaa9066b83ee8a3bdfce3a33cc9dba6456d8361361"
        ),
        "proof_status": (
            "live_inventory_complete_no_package_manifest_candidate_in_accepted_source"
        ),
        "qualifying_browser_frontend_host_confirmed": False,
        "raw_path_or_file_content_emitted": False,
        "real_oauth_values_processed": False,
        "receipt_type": (
            "engineer4me_microsoft_entra_calling_client_msal_browser_"
            "frontend_host_live_inventory_proof_receipt"
        ),
        "remote_git_or_registry_operation_requested": False,
        "rendered_receipt_is_independent_live_provenance": False,
        "schema_version": 1,
        "single_unselected_package_manifest_candidate_detected": False,
        "source": "engineer4me_controlled_local_git_frontend_host_inventory",
        "step216_zero_retry_policy_preserved": True,
        "step225_default_retry_rejection_preserved": True,
        "step230_container_proof_boundary_preserved": True,
        "step231_dependency_lock_plan_preserved": True,
        "step232_synthetic_live_provenance_separation_preserved": True,
        "tracked_git_symlink_or_gitlink_observed": False,
        "validation_scope": "exact_step232_state_plus_accepted_head_git_object_inventory",
        "working_tree_marker_content_read": False,
        "working_tree_status_projection_sha256": (
            "0ccb21d1581c8dc669f6b88e8a73db296855dd6ee6de80d818890a5943061ccb"
        ),
    }


def _load() -> readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt:
    return readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
        _canonical(_valid_document()),
        _canonical(_step233_no_host_receipt()),
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


TRUE_RECEIPT_CONTROLS = {
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
}

FALSE_RECEIPT_CONTROLS = {
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
}


def test_exact_contract_identity_and_desired_state() -> None:
    assert readiness.STATUS == (
        "frontend_host_scaffold_decision_plan_validated_creation_remains_blocked"
    )
    assert readiness.SCAFFOLD_TARGET_ROOT == "frontend"
    assert readiness.SCAFFOLD_APPLICATION_MODEL == "static_browser_spa"
    assert readiness.SCAFFOLD_LANGUAGE == "typescript"
    assert readiness.DESIRED_PACKAGE_MANAGER == "npm"
    assert readiness.DESIRED_LOCKFILE_NAME == "package-lock.json"
    assert readiness.DESIRED_LOCKFILE_VERSION == 3
    assert readiness.FRAMEWORK_SELECTION == "unselected"
    assert readiness.BUNDLER_SELECTION == "unselected"
    assert readiness.PLANNED_SCAFFOLD_PATHS == (
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/index.html",
        "frontend/tsconfig.json",
        "frontend/src/main.ts",
    )
    assert len(readiness.DEFERRED_GATES) == 10
    assert readiness.DEFERRED_GATES[0] == (
        "atomic_scaffold_materialization_with_target_containment_collision_"
        "case_ambiguity_symlink_reparse_absence_and_race_rechecks"
    )


def test_exact_step233_no_host_receipt_fixture_identity() -> None:
    receipt = _step233_no_host_receipt()
    assert len(receipt) == 75
    assert hashlib.sha256(_canonical(receipt)).hexdigest() == (
        readiness.STEP233_NO_HOST_RECEIPT_SHA256
    )
    assert receipt["candidate_root_count"] == 0
    assert receipt["package_manifest_count"] == 0
    assert receipt["marker_file_count"] == 0
    assert receipt["host_decision_or_scaffold_required"] is True
    assert receipt["rendered_receipt_is_independent_live_provenance"] is False


def test_loads_exact_offline_scaffold_decision() -> None:
    receipt = _load()
    assert receipt.readiness_status == readiness.STATUS
    assert receipt.approved_step233_no_host_receipt_sha256 == (
        readiness.STEP233_NO_HOST_RECEIPT_SHA256
    )
    assert receipt.step233_candidate_root_count == 0
    assert receipt.step233_package_manifest_count == 0
    assert receipt.step233_dependency_lock_count == 0
    assert receipt.scaffold_target_root == "frontend"
    assert receipt.planned_scaffold_path_count == 5
    assert receipt.deferred_gate_count == 10
    assert receipt.readiness_document_sha256 == readiness.READINESS_DOCUMENT_SHA256
    assert receipt.scaffold_plan_sha256 == readiness.SCAFFOLD_PLAN_SHA256
    assert receipt.security_integration_plan_sha256 == (
        readiness.SECURITY_INTEGRATION_PLAN_SHA256
    )
    assert receipt.deferred_gate_plan_sha256 == readiness.DEFERRED_GATE_PLAN_SHA256


def test_receipt_boolean_controls_are_exhaustive_and_exact() -> None:
    receipt = _load()
    boolean_fields = {
        field.name
        for field in dataclasses.fields(receipt)
        if type(getattr(receipt, field.name)) is bool
    }
    assert boolean_fields == TRUE_RECEIPT_CONTROLS | FALSE_RECEIPT_CONTROLS
    assert TRUE_RECEIPT_CONTROLS.isdisjoint(FALSE_RECEIPT_CONTROLS)
    assert all(getattr(receipt, name) is True for name in TRUE_RECEIPT_CONTROLS)
    assert all(getattr(receipt, name) is False for name in FALSE_RECEIPT_CONTROLS)


def test_receipt_renders_canonical_exact_json() -> None:
    receipt = _load()
    rendered = readiness.render_entra_calling_client_msal_frontend_host_scaffold_decision_readiness_receipt(
        receipt
    )
    parsed = json.loads(rendered)
    assert rendered == _canonical(parsed)
    assert set(parsed) == {field.name for field in dataclasses.fields(receipt)}
    assert parsed["scaffold_target_root"] == "frontend"
    assert parsed["scaffold_target_created"] is False
    assert parsed["scaffold_root_operationally_selected"] is False


def test_semantically_exact_pretty_step233_receipt_is_accepted() -> None:
    pretty = json.dumps(_step233_no_host_receipt(), indent=2).encode("utf-8") + b"\n"
    receipt = readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
        _canonical(_valid_document()), pretty
    )
    assert receipt.exact_step233_no_host_receipt_bound is True


@pytest.mark.parametrize("key", tuple(_valid_document()))
def test_document_rejects_every_missing_key(key: str) -> None:
    document = _valid_document()
    del document[key]
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(document), _canonical(_step233_no_host_receipt())
        )


@pytest.mark.parametrize("key", tuple(_valid_document()))
def test_document_rejects_every_wrong_type(key: str) -> None:
    document = _valid_document()
    document[key] = _wrong_type(document[key])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(document), _canonical(_step233_no_host_receipt())
        )


@pytest.mark.parametrize("key", tuple(_valid_document()))
def test_document_rejects_every_same_type_value_change(key: str) -> None:
    document = _valid_document()
    document[key] = _different(document[key])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(document), _canonical(_step233_no_host_receipt())
        )


def test_document_rejects_extra_and_duplicate_keys() -> None:
    document = _valid_document()
    document["unexpected"] = "value"
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(document), _canonical(_step233_no_host_receipt())
        )
    duplicate = b'{"schema_version":1,"schema_version":1}'
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            duplicate, _canonical(_step233_no_host_receipt())
        )


@pytest.mark.parametrize("key", tuple(_step233_no_host_receipt()))
def test_step233_receipt_rejects_every_missing_key(key: str) -> None:
    step233 = _step233_no_host_receipt()
    del step233[key]
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(_valid_document()), _canonical(step233)
        )


@pytest.mark.parametrize("key", tuple(_step233_no_host_receipt()))
def test_step233_receipt_rejects_every_wrong_type(key: str) -> None:
    step233 = _step233_no_host_receipt()
    step233[key] = _wrong_type(step233[key])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(_valid_document()), _canonical(step233)
        )


@pytest.mark.parametrize("key", tuple(_step233_no_host_receipt()))
def test_step233_receipt_rejects_every_same_type_value_change(key: str) -> None:
    step233 = _step233_no_host_receipt()
    step233[key] = _different(step233[key])
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(_valid_document()), _canonical(step233)
        )


def test_step233_receipt_rejects_extra_and_duplicate_keys() -> None:
    step233 = _step233_no_host_receipt()
    step233["unexpected"] = False
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(_valid_document()), _canonical(step233)
        )
    duplicate = b'{"candidate_root_count":0,"candidate_root_count":0}'
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ):
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(
            _canonical(_valid_document()), duplicate
        )


@pytest.mark.parametrize(
    ("document", "step233"),
    (
        (bytearray(_canonical(_valid_document())), _canonical(_step233_no_host_receipt())),
        (b"", _canonical(_step233_no_host_receipt())),
        (b"not-json", _canonical(_step233_no_host_receipt())),
        (_canonical([]), _canonical(_step233_no_host_receipt())),
        (b"x" * (readiness.MAX_DOCUMENT_BYTES + 1), _canonical(_step233_no_host_receipt())),
        (_canonical(_valid_document()), bytearray(_canonical(_step233_no_host_receipt()))),
        (_canonical(_valid_document()), b""),
        (_canonical(_valid_document()), b"not-json"),
        (_canonical(_valid_document()), _canonical([])),
        (
            _canonical(_valid_document()),
            b"x" * (readiness.MAX_STEP233_RECEIPT_BYTES + 1),
        ),
    ),
)
def test_loader_rejects_invalid_types_sizes_and_json(
    document: object, step233: object
) -> None:
    with pytest.raises(
        readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessError
    ) as caught:
        readiness.load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness(  # type: ignore[arg-type]
            document, step233
        )
    assert str(caught.value) == (
        "frontend-host scaffold decision readiness validation failed"
    )


@pytest.mark.parametrize(
    "field_name",
    tuple(
        field.name
        for field in dataclasses.fields(
            readiness.EntraCallingClientMSALFrontendHostScaffoldDecisionReadinessReceipt
        )
    ),
)
def test_receipt_rejects_tampering_of_every_field(field_name: str) -> None:
    receipt = _load()
    with pytest.raises(ValueError):
        dataclasses.replace(
            receipt, **{field_name: _different(getattr(receipt, field_name))}
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "readiness_document_sha256",
        "scaffold_plan_sha256",
        "security_integration_plan_sha256",
        "deferred_gate_plan_sha256",
    ),
)
def test_receipt_rejects_alternate_well_formed_computed_digest(
    field_name: str,
) -> None:
    receipt = _load()
    assert getattr(receipt, field_name) != "0" * 64
    with pytest.raises(ValueError):
        dataclasses.replace(receipt, **{field_name: "0" * 64})


def test_renderer_rejects_non_exact_receipt() -> None:
    with pytest.raises(TypeError):
        readiness.render_entra_calling_client_msal_frontend_host_scaffold_decision_readiness_receipt(  # type: ignore[arg-type]
            object()
        )


def test_production_module_has_no_io_process_network_or_cli_capability() -> None:
    source = inspect.getsource(readiness)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "asyncio",
        "http",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "sys",
        "urllib",
    }
    forbidden_calls = {"compile", "eval", "exec", "open", "__import__"}
    forbidden_attributes = {
        "Popen",
        "connect",
        "read_bytes",
        "read_text",
        "run",
        "system",
        "unlink",
        "write_bytes",
        "write_text",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".", 1)[0] not in forbidden_import_roots
                for alias in node.names
            )
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            assert node.module.split(".", 1)[0] not in forbidden_import_roots
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_calls
        if isinstance(node, ast.Attribute):
            assert node.attr not in forbidden_attributes
    assert not hasattr(readiness, "main")


def test_export_surface_is_bounded_and_contains_exact_api() -> None:
    assert all(hasattr(readiness, name) for name in readiness.__all__)
    assert (
        "load_entra_calling_client_msal_frontend_host_scaffold_decision_readiness"
        in readiness.__all__
    )
    assert (
        "render_entra_calling_client_msal_frontend_host_scaffold_decision_readiness_receipt"
        in readiness.__all__
    )
    assert "main" not in readiness.__all__
