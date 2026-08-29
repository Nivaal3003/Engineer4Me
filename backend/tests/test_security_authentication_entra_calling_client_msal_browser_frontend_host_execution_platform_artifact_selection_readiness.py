from __future__ import annotations

import ast
import builtins
import copy
import dataclasses
import hashlib
import inspect
import json
import socket
import subprocess
from dataclasses import replace
from typing import Any

import pytest

import app.security.authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_selection_readiness as readiness
from app.security.authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_selection_readiness import (
    ARCHIVE_ENTRY_REJECTION_RULES,
    ARCHIVE_FORMAT,
    ARCHIVE_ROOT_DIRECTORY,
    AUTOMATIC_APPLICATION_RETRY_COUNT,
    CANONICAL_RECEIPT_SHA256,
    DEFERRED_GATES,
    DOCUMENT_TYPE,
    EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT,
    EXPECTED_NODE_RELEASE_SIGNER_KEY_ID,
    EXCLUDED_ARTIFACT_FAMILIES,
    FORBIDDEN_LAUNCHER_RELATIVE_PATHS,
    MAX_ARCHIVE_COMPRESSION_RATIO,
    MAX_ARCHIVE_DOWNLOAD_BYTES,
    MAX_ARCHIVE_ENTRY_BYTES,
    MAX_ARCHIVE_ENTRY_COUNT,
    MAX_ARCHIVE_EXPANDED_BYTES,
    MAX_AUTHENTICITY_REQUEST_COUNT,
    MAX_DOCUMENT_BYTES,
    NODE_ARCHIVE_FILENAME,
    NODE_ARCHIVE_PUBLISHED_SHA256,
    NODE_ARCHIVE_URL,
    NODE_EXECUTABLE_RELATIVE_PATH,
    NODE_LTS_CODENAME,
    NODE_SHASUMS_ASC_URL,
    NODE_SHASUMS_BODY_SHA256,
    NODE_SHASUMS_SIG_URL,
    NODE_SHASUMS_URL,
    NODE_STANDALONE_EXE_PUBLISHED_SHA256,
    NODE_VERSION,
    NPM_CLI_RELATIVE_PATH,
    NPM_PACKAGE_JSON_RELATIVE_PATH,
    NPM_VERSION,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    SOURCE,
    STATUS,
    STEP237_CANONICAL_RECEIPT_SHA256,
    STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP237_LOCK_GENERATION_PLAN_SHA256,
    STEP237_PACKAGE_MANIFEST_SHA256,
    TARGET_ARCHITECTURE,
    TARGET_OPERATING_SYSTEM,
    TARGET_PLATFORM,
    EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument,
    EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError,
    EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt,
    load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness,
    render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_document,
    render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt,
)


EXPECTED_STEP237_CHAIN = {
    "accepted_state_manifest_bytes": 32_473,
    "accepted_state_manifest_sha256": (
        "9993e24edb671e643e888ab41f1cd79027b09c0f26c9a13aa40d46f98de1be35"
    ),
    "canonical_receipt_sha256": (
        "9e6e30b63e78b3660ae289752d26241b9890d4ec04e4254023b817b6f9cbb5c7"
    ),
    "deferred_gate_plan_sha256": (
        "9846db3a9fcb485b406a857d5f882ea008c05e6c3d6f9fd8d21c3d5c033134aa"
    ),
    "initial_scaffold_allowlist_sha256": (
        "4405f434692da00b1db38236d0d9c2614cd20d59f92b608cbf1f08ac78066bea"
    ),
    "lock_generation_plan_sha256": (
        "987461a9efe9cc9a2533eee00565c9d018dbdc3119796a6988d1a9e6b22fb3db"
    ),
    "mandatory_lock_anchor_plan_sha256": (
        "f06386dd443b78c1023700554935e868f97d0101da5ed5fccc347d97e482631c"
    ),
    "npmrc_bytes_sha256": (
        "bd51c414eeb9453a451af9c7b48389b7baf20f95919eaf69e8059c7c8cdbc334"
    ),
    "npmrc_policy_plan_sha256": (
        "43c2533ff284648f969d237c00c63b88db56fa2f39e87ddd9d8cf9448bdd5743"
    ),
    "package_manifest_bytes_sha256": (
        "ae3f112bccee82debfda9fbdaa51066e6505217200c7177c6dc8d145049e1704"
    ),
    "package_manifest_lock_readiness_sha256": (
        "169686c240c93d454bfda9fbdaa51066f9d151770fc7e3de5c763c024aa25c78"
    ),
    "package_manifest_lock_readiness_test_sha256": (
        "0716527d66716e551347ddd63594e92618e691da2568bf1b594e733abeb5d9a3"
    ),
    "package_manifest_plan_sha256": (
        "06ed6f8c8ce9a135732283de35ebc788b2a29f52505206c095f22e6ad5386aaa"
    ),
    "package_manifest_sha256": (
        "0cacae7e9fe1d28efc7990f3b7fe016bad4bc1ba1d874d472c944364380f5a07"
    ),
    "readiness_document_sha256": (
        "2d62e8767230c7b58c1d3505b5e29bbefe0b43dafa1e5ca95a09a349f5fa75ee"
    ),
    "step235_chain_sha256": (
        "e5febfe9b5a90976cdd181cb8e9057c3e326297681b26e79a64c70485e1fdfe8"
    ),
    "step236_binding_sha256": (
        "6bda563ae1016748b7c3eb8671fd030ff643af65476ce56663a6e05f6a93fda6"
    ),
}

EXPECTED_PROJECTION_DIGESTS = {
    "approved_step237_chain_sha256": (
        "230e1d793b2b230e956486ef802fb249098adecef1f7c2669ffd1ebd693fe834"
    ),
    "execution_platform_selection_sha256": (
        "322cf6c9881a1328a047510a29644df70ff5ebeb4975956fd3291ecd4ee5459f"
    ),
    "artifact_selection_sha256": (
        "8078a1d9871f844798c41ae15ded019a45aa6840e552adfe68759ce8ca070c4f"
    ),
    "authenticity_proof_plan_sha256": (
        "b16334230c7bab2f01422fadd21b6779a96642372972e2b973db2f93f5583c78"
    ),
    "archive_safety_plan_sha256": (
        "772126f4822614f5e6c148dd23383f50d1a541735c1d04cf3d9c6ad3a500db22"
    ),
    "entrypoint_binding_plan_sha256": (
        "141f76059e9fe503d7b2198bfc69111dafe18fedb9c9c397e7cb7edfd950b1d6"
    ),
    "deferred_gate_plan_sha256": (
        "e59ec7bc46ef2e70100542fcc76322c0f6d5a4d7a12b4faf0619a9b95060f4bf"
    ),
    "readiness_document_sha256": (
        "16e0940a97f34eafe7db635ea81da828fe8f55fa793d81538b2767adadefd281"
    ),
}


def _document_bytes() -> bytes:
    return render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_document()


def _document_object() -> dict[str, object]:
    value = json.loads(_document_bytes())
    assert type(value) is dict
    return value


def _receipt() -> EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt:
    return load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
        _document_bytes()
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _leaf_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    if type(value) is dict:
        result: list[tuple[object, ...]] = []
        for key, child in value.items():
            result.extend(_leaf_paths(child, (*path, key)))
        return result
    if type(value) is list:
        result = []
        for index, child in enumerate(value):
            result.extend(_leaf_paths(child, (*path, index)))
        return result
    return [path]


def _container_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    result: list[tuple[object, ...]] = []
    if type(value) in (dict, list):
        if path:
            result.append(path)
        children = value.items() if type(value) is dict else enumerate(value)
        for key, child in children:
            result.extend(_container_paths(child, (*path, key)))
    return result


DOCUMENT_LEAF_PATHS = tuple(_leaf_paths(_document_object()))
DOCUMENT_CONTAINER_PATHS = tuple(_container_paths(_document_object()))
RECEIPT_FIELD_NAMES = tuple(
    field.name
    for field in dataclasses.fields(
        EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt
    )
)


def _get_parent(root: object, path: tuple[object, ...]) -> tuple[object, object]:
    current = root
    for part in path[:-1]:
        current = current[part]  # type: ignore[index]
    return current, path[-1]


def _different(value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + "x"
    if type(value) is list:
        return [*value, None]
    if type(value) is dict:
        return {**value, "unexpected": None}
    raise AssertionError(type(value))


def test_exact_public_constants_and_status() -> None:
    assert DOCUMENT_TYPE.endswith("execution_platform_artifact_selection_readiness")
    assert RECEIPT_TYPE == DOCUMENT_TYPE + "_receipt"
    assert SCHEMA_VERSION == 1
    assert SOURCE == "engineer4me_offline_frontend_execution_platform_artifact_selection_readiness"
    assert STATUS == (
        "offline_windows_x64_portable_toolchain_selected_download_signature_"
        "verification_extraction_execution_and_lock_generation_blocked"
    )
    assert STEP237_PACKAGE_MANIFEST_SHA256 == EXPECTED_STEP237_CHAIN["package_manifest_sha256"]
    assert STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256 == EXPECTED_STEP237_CHAIN["accepted_state_manifest_sha256"]
    assert STEP237_CANONICAL_RECEIPT_SHA256 == EXPECTED_STEP237_CHAIN["canonical_receipt_sha256"]
    assert STEP237_LOCK_GENERATION_PLAN_SHA256 == EXPECTED_STEP237_CHAIN["lock_generation_plan_sha256"]


def test_exact_platform_and_artifact_selection() -> None:
    assert TARGET_PLATFORM == "windows-x64-portable"
    assert TARGET_OPERATING_SYSTEM == "windows"
    assert TARGET_ARCHITECTURE == "x64"
    assert ARCHIVE_FORMAT == "zip"
    assert NODE_VERSION == "24.19.0"
    assert NODE_LTS_CODENAME == "Krypton"
    assert NPM_VERSION == "11.17.0"
    assert NODE_ARCHIVE_FILENAME == "node-v24.19.0-win-x64.zip"
    assert ARCHIVE_ROOT_DIRECTORY == "node-v24.19.0-win-x64"
    assert NODE_ARCHIVE_URL == (
        "https://nodejs.org/dist/v24.19.0/node-v24.19.0-win-x64.zip"
    )
    assert NODE_ARCHIVE_PUBLISHED_SHA256 == "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73"
    assert NODE_STANDALONE_EXE_PUBLISHED_SHA256 == "3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237"


def test_exact_signed_metadata_and_release_key_selection() -> None:
    document = _document_object()
    plan = document["authenticity_proof_plan"]
    assert plan["step236_observed_shasums_body_sha256"] == NODE_SHASUMS_BODY_SHA256
    assert NODE_SHASUMS_URL.endswith("/SHASUMS256.txt")
    assert NODE_SHASUMS_SIG_URL.endswith("/SHASUMS256.txt.sig")
    assert NODE_SHASUMS_ASC_URL.endswith("/SHASUMS256.txt.asc")
    assert EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT == "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"
    assert EXPECTED_NODE_RELEASE_SIGNER_KEY_ID == "20B1A390B168D356"
    assert plan["expected_detached_signature_created_utc"] == "2026-08-03T13:44:56Z"
    assert plan["expected_clearsigned_signature_created_utc"] == "2026-08-03T13:44:34Z"
    assert plan["clearsigned_text_equality_semantics"] == (
        "strict_rfc4880_cleartext_body_recovery_with_dash_unescaping_and_"
        "line_ending_normalization_to_exact_2967_byte_lf_shasums_without_"
        "tool_added_terminal_newline"
    )
    assert plan["keyring"] == {
        "ephemeral_isolated_keyring_required": True,
        "exact_raw_key_bytes": 924,
        "exact_raw_key_sha256": "5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a",
        "exact_release_keys_commit": "7b6eb2d6ab524bb30487f31612cdbeb35ae37533",
        "exact_relative_path": "keys/5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc",
        "exact_url": "https://raw.githubusercontent.com/nodejs/release-keys/7b6eb2d6ab524bb30487f31612cdbeb35ae37533/keys/5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc",
        "material_verified": False,
        "trust_scope": "expected_signer_for_exact_v24_19_0_release_only",
    }
    assert [request["purpose"] for request in plan["requests_in_order"]] == [
        "pinned_release_signer_raw_public_key",
        "signed_checksum_payload",
        "detached_openpgp_binary_signature",
        "clear_signed_openpgp_checksum_payload",
        "selected_portable_node_archive",
    ]
    assert [request["expected_response_bytes"] for request in plan["requests_in_order"]] == [
        924,
        2_967,
        119,
        3_245,
        37_304_352,
    ]


def test_exact_platform_support_gate_is_conditional_and_unproven() -> None:
    host = _document_object()["execution_platform_selection"]["host_validation"]
    assert host["must_be_operating_system"] == "windows"
    assert host["installer_coarse_observation_required"] == {
        "environment_processor_architecture": "AMD64",
        "is_64_bit_operating_system": True,
        "is_64_bit_process": True,
        "os_version_platform": "Win32NT",
    }
    assert host["minimum_node_platform_floor"] == "Windows 10 or Windows Server 2016"
    assert host["require_current_vendor_supported_non_eol_disposition"] is True
    assert host["full_host_support_observation_deferred_to_successor"] is True
    receipt = _receipt()
    assert receipt.contract_module_host_platform_observed is False
    assert receipt.host_compatibility_verified is False
    assert receipt.host_vendor_support_verified is False


def test_exact_safe_zip_bounds_and_rules() -> None:
    plan = _document_object()["archive_safety_plan"]
    assert MAX_ARCHIVE_DOWNLOAD_BYTES == 67_108_864
    assert MAX_ARCHIVE_ENTRY_COUNT == 20_000
    assert MAX_ARCHIVE_EXPANDED_BYTES == 268_435_456
    assert MAX_ARCHIVE_ENTRY_BYTES == 134_217_728
    assert MAX_ARCHIVE_COMPRESSION_RATIO == 200
    assert plan["bounds"] == {
        "maximum_archive_download_bytes": 67_108_864,
        "maximum_compression_ratio": 200,
        "maximum_component_utf8_bytes": 255,
        "maximum_entry_bytes": 134_217_728,
        "maximum_entry_count": 20_000,
        "maximum_expanded_bytes": 268_435_456,
        "maximum_path_depth": 32,
        "maximum_path_utf8_bytes": 1_024,
        "required_root_count": 1,
    }
    assert tuple(plan["rejection_rules"]) == ARCHIVE_ENTRY_REJECTION_RULES
    assert len(ARCHIVE_ENTRY_REJECTION_RULES) == len(set(ARCHIVE_ENTRY_REJECTION_RULES))
    assert {
        "absolute_or_rooted_path",
        "alternate_data_stream_or_colon",
        "backslash_separator",
        "casefold_collision",
        "central_and_local_header_mismatch",
        "crc32_mismatch",
        "directory_traversal_or_dot_segment",
        "dos_reserved_component",
        "file_directory_prefix_collision",
        "hardlink_symlink_reparse_or_special_file",
        "multiple_or_wrong_top_level_root",
        "overlapping_entry_data_ranges",
        "trailing_data_after_end_record",
        "zip64_archive_or_entry",
    } <= set(ARCHIVE_ENTRY_REJECTION_RULES)


def test_exact_entrypoints_forbid_shell_launchers() -> None:
    plan = _document_object()["entrypoint_binding_plan"]
    assert NODE_EXECUTABLE_RELATIVE_PATH == "node-v24.19.0-win-x64/node.exe"
    assert NPM_CLI_RELATIVE_PATH == "node-v24.19.0-win-x64/node_modules/npm/bin/npm-cli.js"
    assert NPM_PACKAGE_JSON_RELATIVE_PATH == "node-v24.19.0-win-x64/node_modules/npm/package.json"
    assert plan["invocation_prefix"] == [
        "verified_absolute_extracted_node_executable",
        "verified_absolute_extracted_npm_cli_js",
    ]
    assert plan["shell_resolution"] == "forbidden"
    assert tuple(plan["forbidden_launchers"]) == FORBIDDEN_LAUNCHER_RELATIVE_PATHS
    assert all(value.endswith(".cmd") for value in FORBIDDEN_LAUNCHER_RELATIVE_PATHS)
    assert plan["version_probe"]["external_deadline_seconds"] == 300


def test_all_excluded_artifact_families_are_exact_and_unique() -> None:
    assert EXCLUDED_ARTIFACT_FAMILIES == tuple(sorted(EXCLUDED_ARTIFACT_FAMILIES))
    assert len(EXCLUDED_ARTIFACT_FAMILIES) == len(set(EXCLUDED_ARTIFACT_FAMILIES)) == 9
    assert {
        "container_image",
        "node_win_x64_msi",
        "standalone_win_x64_node_exe",
        "system_path_node_or_npm",
        "third_party_chocolatey_package",
        "third_party_winget_package",
    } <= set(EXCLUDED_ARTIFACT_FAMILIES)


def test_document_is_exact_canonical_ascii_and_bounded() -> None:
    document = _document_bytes()
    assert type(document) is bytes
    assert document == _canonical(json.loads(document))
    assert document.decode("ascii").encode("ascii") == document
    assert b"\r" not in document
    assert b"\n" not in document
    assert len(document) == 11_396
    assert len(document) < MAX_DOCUMENT_BYTES == 65_536
    assert hashlib.sha256(document).hexdigest() == EXPECTED_PROJECTION_DIGESTS["readiness_document_sha256"]


def test_document_exact_top_level_shape_and_step237_chain() -> None:
    document = _document_object()
    assert set(document) == {
        "approved_step237_chain",
        "archive_safety_plan",
        "artifact_selection",
        "authenticity_proof_plan",
        "deferred_gates",
        "document_type",
        "entrypoint_binding_plan",
        "execution_platform_selection",
        "readiness_status",
        "schema_version",
        "source",
    }
    assert document["approved_step237_chain"] == EXPECTED_STEP237_CHAIN
    assert document["deferred_gates"] == list(DEFERRED_GATES)
    assert len(DEFERRED_GATES) == 14


def test_document_model_accepts_only_exact_projection() -> None:
    model = EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument.model_validate(
        _document_object()
    )
    assert model.model_dump(mode="json") == _document_object()


@pytest.mark.parametrize("path", DOCUMENT_LEAF_PATHS)
def test_every_document_leaf_is_cryptographically_exact(path: tuple[object, ...]) -> None:
    changed = copy.deepcopy(_document_object())
    parent, key = _get_parent(changed, path)
    parent[key] = _different(parent[key])  # type: ignore[index]
    with pytest.raises(EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError):
        load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
            _canonical(changed)
        )
    with pytest.raises((TypeError, ValueError)):
        EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument.model_validate(
            changed
        )


@pytest.mark.parametrize("path", DOCUMENT_CONTAINER_PATHS)
def test_every_document_container_rejects_an_extra_member(path: tuple[object, ...]) -> None:
    changed = copy.deepcopy(_document_object())
    parent, key = _get_parent(changed, path)
    target = parent[key]  # type: ignore[index]
    if type(target) is dict:
        target["unexpected"] = None
    else:
        target.append(None)
    with pytest.raises(EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError):
        load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
            _canonical(changed)
        )


@pytest.mark.parametrize(
    "value",
    [None, "", b"", bytearray(b"{}"), memoryview(b"{}"), {}, [], 1, True],
)
def test_loader_rejects_non_exact_input_types_and_empty_values(value: object) -> None:
    with pytest.raises(EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError) as caught:
        load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(value)  # type: ignore[arg-type]
    assert str(caught.value) == (
        "frontend-host execution-platform artifact selection readiness validation failed"
    )


@pytest.mark.parametrize(
    "position",
    [0, 1, 17, 113, 509, 1024, 2048, 4096, 8192, 10_000, -3, -2, -1],
)
def test_loader_rejects_representative_single_byte_tampering(position: int) -> None:
    changed = bytearray(_document_bytes())
    changed[position] = 32 if changed[position] != 32 else 33
    with pytest.raises(EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError):
        load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
            bytes(changed)
        )


def test_loader_rejects_duplicate_keys_nonfinite_and_non_ascii_documents() -> None:
    invalid_documents = (
        b'{"a":1,"a":1}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'\xff',
        _document_bytes() + b" ",
        b" " + _document_bytes(),
        _document_bytes() + b"\n",
    )
    for document in invalid_documents:
        with pytest.raises(EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError):
            load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
                document
            )


def test_valid_receipt_exact_constants_counts_and_projection_digests() -> None:
    receipt = _receipt()
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.source == SOURCE
    assert receipt.readiness_status == STATUS
    assert receipt.node_archive_published_bytes == 37_304_352
    assert receipt.node_shasums_body_bytes == 2_967
    assert receipt.node_shasums_sig_bytes == 119
    assert receipt.node_shasums_asc_bytes == 3_245
    assert receipt.release_key_bytes == 924
    assert receipt.node_shasums_url == NODE_SHASUMS_URL
    assert receipt.node_shasums_sig_url == NODE_SHASUMS_SIG_URL
    assert receipt.node_shasums_asc_url == NODE_SHASUMS_ASC_URL
    assert receipt.maximum_shasums_response_bytes == 65_536
    assert receipt.maximum_signature_response_bytes == 65_536
    assert receipt.maximum_key_material_bytes == 1_048_576
    assert receipt.artifact_proof_deadline_seconds == 300
    assert receipt.maximum_authenticity_request_count == MAX_AUTHENTICITY_REQUEST_COUNT == 5
    assert receipt.automatic_application_retry_count == AUTOMATIC_APPLICATION_RETRY_COUNT == 0
    for name, expected in EXPECTED_PROJECTION_DIGESTS.items():
        assert getattr(receipt, name) == expected


def test_all_receipt_boolean_controls_are_exact_and_fail_closed() -> None:
    receipt = _receipt()
    fields = dataclasses.fields(receipt)
    boolean_fields = [field.name for field in fields if type(getattr(receipt, field.name)) is bool]
    assert len(boolean_fields) == 68
    false_fields = {
        name for name in boolean_fields if getattr(receipt, name) is False
    }
    assert false_fields == {
        "application_configuration_modified_or_activated",
        "browser_oauth_graph_entra_or_application_endpoint_requested",
        "clearsigned_text_equals_exact_shasums_verified",
        "container_build_platform_selected",
        "contract_module_host_platform_observed",
        "dependency_downloaded_or_installed",
        "docker_restarted_or_rebuilt",
        "ephemeral_keyring_created",
        "frontend_root_created_or_scaffold_written",
        "git_stage_commit_or_push_performed",
        "global_node_install_authorized",
        "host_compatibility_verified",
        "host_vendor_support_verified",
        "lock_generation_authorized_or_performed",
        "lockfile_created_or_modified",
        "node_archive_byte_hash_verified",
        "node_archive_downloaded_or_content_length_proven",
        "node_archive_extracted",
        "node_archive_inventory_inspected",
        "node_executable_or_npm_cli_file_hash_verified",
        "node_or_npm_executed",
        "node_release_keyring_selected_or_persisted",
        "node_release_signer_trust_proven",
        "operational_write_performed",
        "package_manager_or_lifecycle_script_executed",
        "path_registry_or_msi_mutation_authorized",
        "production_platform_selected",
        "published_checksum_candidates_promoted_to_trusted_evidence",
        "release_key_material_verified",
        "shasums_clearsigned_signature_verified",
        "shasums_detached_signature_verified",
        "shasums_or_signature_retrieved",
        "step238_external_request_performed",
    }
    assert all(getattr(receipt, name) is True for name in set(boolean_fields) - false_fields)


@pytest.mark.parametrize("field_name", RECEIPT_FIELD_NAMES)
def test_every_receipt_field_is_enforced_by_post_init(field_name: str) -> None:
    receipt = _receipt()
    with pytest.raises(ValueError):
        replace(receipt, **{field_name: _different(getattr(receipt, field_name))})


def test_receipt_render_is_exact_canonical_and_hash_bound() -> None:
    rendered = render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt(
        _receipt()
    )
    assert type(rendered) is bytes
    assert rendered == _canonical(json.loads(rendered))
    assert hashlib.sha256(rendered).hexdigest() == CANONICAL_RECEIPT_SHA256
    assert len(rendered) == 8_355


@pytest.mark.parametrize("value", [None, object(), {}, _document_object(), b"{}"])
def test_receipt_renderer_rejects_every_non_exact_type(value: object) -> None:
    with pytest.raises(TypeError):
        render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt(value)  # type: ignore[arg-type]


def test_receipt_is_frozen_slotted_and_not_mutable() -> None:
    receipt = _receipt()
    assert not hasattr(receipt, "__dict__")
    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        receipt.node_version = "25.0.0"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        receipt.unexpected = True  # type: ignore[attr-defined]


def test_loader_and_renderer_are_deterministic_across_repetition() -> None:
    documents = [_document_bytes() for _ in range(16)]
    assert len(set(documents)) == 1
    receipts = [_receipt() for _ in range(16)]
    assert len(set(receipts)) == 1
    rendered = [
        render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt(receipt)
        for receipt in receipts
    ]
    assert len(set(rendered)) == 1


def test_module_source_has_no_filesystem_network_archive_or_process_capability() -> None:
    source = inspect.getsource(readiness)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "asyncio",
        "httpx",
        "io",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "tempfile",
        "urllib",
        "zipfile",
    }
    imports: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called_names.add(node.func.id)
    assert not imports & forbidden_import_roots
    assert not called_names & {"open", "exec", "eval", "compile", "__import__"}
    assert "download" not in {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "extract" not in {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_valid_offline_operations_do_not_call_common_io_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        raise AssertionError("I/O surface invoked")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    document = _document_bytes()
    receipt = load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
        document
    )
    rendered = render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt(
        receipt
    )
    assert hashlib.sha256(rendered).hexdigest() == CANONICAL_RECEIPT_SHA256


def test_module_exports_only_the_frozen_public_surface() -> None:
    assert len(readiness.__all__) == len(set(readiness.__all__))
    assert readiness.__all__ == sorted(readiness.__all__)
    assert {
        "CANONICAL_RECEIPT_SHA256",
        "NODE_ARCHIVE_FILENAME",
        "NODE_ARCHIVE_URL",
        "NODE_SHASUMS_SIG_URL",
        "TARGET_PLATFORM",
        "load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness",
        "render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_document",
        "render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt",
    } <= set(readiness.__all__)


def test_no_successor_executor_or_materializer_is_implemented() -> None:
    public_and_private_names = set(vars(readiness))
    forbidden_names = {
        "download_node_archive",
        "extract_node_archive",
        "generate_package_lock",
        "install_node",
        "materialize_frontend",
        "run_node",
        "run_npm",
        "verify_openpgp_signature",
    }
    assert not public_and_private_names & forbidden_names
    receipt = _receipt()
    assert receipt.artifact_selection_is_not_authenticity_or_execution_authorization is True
    assert receipt.node_archive_downloaded_or_content_length_proven is False
    assert receipt.node_archive_extracted is False
    assert receipt.node_or_npm_executed is False
    assert receipt.lock_generation_authorized_or_performed is False
