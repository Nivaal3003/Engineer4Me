"""Pure Step 238 execution-platform and Node.js artifact readiness.

This offline contract binds the exact accepted Step 237 state and selects one
portable Windows-x64 Node.js 24.19.0 distribution artifact for a future,
controlled package-lock-only run.  It also selects fail-closed download,
signature, archive-inspection, extraction, and absolute-entrypoint rules.

The SHASUMS text and published archive checksum candidates are bound to the
Step 236 official metadata proof.  The exact signature, raw-key, and artifact
size identities are separately selected Step 238 official-source research;
none is trusted merely because it is selected.  A successor must verify both
the detached and clear-signed SHASUMS forms with a fresh keyring and then hash
the downloaded bytes.  This module performs only in-memory JSON validation,
canonicalization, and SHA-256 calculation.  It does not inspect the host,
access a network or filesystem, download or extract an archive, execute
Node.js/npm, generate a lockfile, or authorize any write.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_artifact_selection_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = (
    "engineer4me_offline_frontend_execution_platform_artifact_selection_"
    "readiness"
)
SCOPE = (
    "exact_step237_chain_plus_windows_x64_portable_node_npm_artifact_"
    "and_fail_closed_extraction_safety_plan"
)
STATUS = (
    "offline_windows_x64_portable_toolchain_selected_download_signature_"
    "verification_extraction_execution_and_lock_generation_blocked"
)

STEP237_PACKAGE_MANIFEST_SHA256 = (
    "0cacae7e9fe1d28efc7990f3b7fe016bad4bc1ba1d874d472c944364380f5a07"
)
STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "9993e24edb671e643e888ab41f1cd79027b09c0f26c9a13aa40d46f98de1be35"
)
STEP237_FINAL_ACCEPTED_STATE_MANIFEST_BYTES = 32_473
STEP237_PACKAGE_MANIFEST_LOCK_READINESS_SHA256 = (
    "169686c240c93d454bfda9fbdaa51066f9d151770fc7e3de5c763c024aa25c78"
)
STEP237_PACKAGE_MANIFEST_LOCK_READINESS_TEST_SHA256 = (
    "0716527d66716e551347ddd63594e92618e691da2568bf1b594e733abeb5d9a3"
)
STEP237_CANONICAL_RECEIPT_SHA256 = (
    "9e6e30b63e78b3660ae289752d26241b9890d4ec04e4254023b817b6f9cbb5c7"
)
STEP237_READINESS_DOCUMENT_SHA256 = (
    "2d62e8767230c7b58c1d3505b5e29bbefe0b43dafa1e5ca95a09a349f5fa75ee"
)
STEP237_STEP236_BINDING_SHA256 = (
    "6bda563ae1016748b7c3eb8671fd030ff643af65476ce56663a6e05f6a93fda6"
)
STEP237_STEP235_CHAIN_SHA256 = (
    "e5febfe9b5a90976cdd181cb8e9057c3e326297681b26e79a64c70485e1fdfe8"
)
STEP237_PACKAGE_MANIFEST_PLAN_SHA256 = (
    "06ed6f8c8ce9a135732283de35ebc788b2a29f52505206c095f22e6ad5386aaa"
)
STEP237_PACKAGE_MANIFEST_BYTES_SHA256 = (
    "ae3f112bccee82debfda9fbdaa51066e6505217200c7177c6dc8d145049e1704"
)
STEP237_NPMRC_POLICY_PLAN_SHA256 = (
    "43c2533ff284648f969d237c00c63b88db56fa2f39e87ddd9d8cf9448bdd5743"
)
STEP237_NPMRC_BYTES_SHA256 = (
    "bd51c414eeb9453a451af9c7b48389b7baf20f95919eaf69e8059c7c8cdbc334"
)
STEP237_MANDATORY_LOCK_ANCHOR_PLAN_SHA256 = (
    "f06386dd443b78c1023700554935e868f97d0101da5ed5fccc347d97e482631c"
)
STEP237_LOCK_GENERATION_PLAN_SHA256 = (
    "987461a9efe9cc9a2533eee00565c9d018dbdc3119796a6988d1a9e6b22fb3db"
)
STEP237_INITIAL_SCAFFOLD_ALLOWLIST_SHA256 = (
    "4405f434692da00b1db38236d0d9c2614cd20d59f92b608cbf1f08ac78066bea"
)
STEP237_DEFERRED_GATE_PLAN_SHA256 = (
    "9846db3a9fcb485b406a857d5f882ea008c05e6c3d6f9fd8d21c3d5c033134aa"
)

NODE_VERSION = "24.19.0"
NODE_VERSION_TAG = "v24.19.0"
NODE_LTS_CODENAME = "Krypton"
NODE_RELEASE_DATE = "2026-08-03"
NODE_MODULES_VERSION = 137
NPM_VERSION = "11.17.0"
PACKAGE_MANAGER = "npm"
TARGET_PLATFORM = "windows-x64-portable"
TARGET_OPERATING_SYSTEM = "windows"
TARGET_ARCHITECTURE = "x64"
TARGET_PROCESS_ARCHITECTURE = "X64"
ARCHIVE_FORMAT = "zip"
NODE_DISTRIBUTION_ORIGIN = "https://nodejs.org"
NODE_RELEASE_DIRECTORY_URL = "https://nodejs.org/dist/v24.19.0/"
NODE_RELEASE_INDEX_URL = "https://nodejs.org/dist/index.json"
NODE_SHASUMS_URL = (
    "https://nodejs.org/dist/v24.19.0/SHASUMS256.txt"
)
NODE_SHASUMS_ASC_URL = (
    "https://nodejs.org/dist/v24.19.0/SHASUMS256.txt.asc"
)
NODE_SHASUMS_SIG_URL = (
    "https://nodejs.org/dist/v24.19.0/SHASUMS256.txt.sig"
)
NODE_ARCHIVE_FILENAME = "node-v24.19.0-win-x64.zip"
NODE_ARCHIVE_URL = NODE_RELEASE_DIRECTORY_URL + NODE_ARCHIVE_FILENAME
NODE_ARCHIVE_PUBLISHED_BYTES = 37_304_352
NODE_ARCHIVE_PUBLISHED_SHA256 = (
    "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73"
)
NODE_STANDALONE_EXE_PUBLISHED_SHA256 = (
    "3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237"
)
NODE_SHASUMS_BODY_SHA256 = (
    "be0629ee2bcd8e40bb856abdd3407f0762101b76bd60a36b8867f637733631c0"
)
NODE_SHASUMS_BODY_BYTES = 2_967
NODE_SHASUMS_SIG_SHA256 = (
    "801534e2d4c769c087e2e3eec89e879032872357e64e82336f86f03e72ece630"
)
NODE_SHASUMS_SIG_BYTES = 119
NODE_SHASUMS_ASC_SHA256 = (
    "88c7160b8d81c81bbbba7e3bd0bba88917b1e6a2e47e092044f43894a09ceb83"
)
NODE_SHASUMS_ASC_BYTES = 3_245
EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT = (
    "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"
)
EXPECTED_NODE_RELEASE_SIGNER_KEY_ID = "20B1A390B168D356"
EXPECTED_NODE_RELEASE_SIGNATURE_ALGORITHM = "EdDSA-22"
EXPECTED_NODE_RELEASE_SIGNATURE_DIGEST = "SHA256"
EXPECTED_NODE_RELEASE_DETACHED_SIGNATURE_CREATED_UTC = (
    "2026-08-03T13:44:56Z"
)
EXPECTED_NODE_RELEASE_CLEARSIGNED_SIGNATURE_CREATED_UTC = (
    "2026-08-03T13:44:34Z"
)
NODE_RELEASE_KEYS_COMMIT = "7b6eb2d6ab524bb30487f31612cdbeb35ae37533"
NODE_RELEASE_KEY_RELATIVE_PATH = (
    "keys/5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc"
)
NODE_RELEASE_KEY_URL = (
    "https://raw.githubusercontent.com/nodejs/release-keys/"
    "7b6eb2d6ab524bb30487f31612cdbeb35ae37533/keys/"
    "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc"
)
NODE_RELEASE_KEY_BYTES = 924
NODE_RELEASE_KEY_SHA256 = (
    "5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a"
)

ARCHIVE_ROOT_DIRECTORY = "node-v24.19.0-win-x64"
NODE_EXECUTABLE_RELATIVE_PATH = ARCHIVE_ROOT_DIRECTORY + "/node.exe"
NPM_CLI_RELATIVE_PATH = (
    ARCHIVE_ROOT_DIRECTORY + "/node_modules/npm/bin/npm-cli.js"
)
NPM_PACKAGE_JSON_RELATIVE_PATH = (
    ARCHIVE_ROOT_DIRECTORY + "/node_modules/npm/package.json"
)
FORBIDDEN_LAUNCHER_RELATIVE_PATHS = (
    ARCHIVE_ROOT_DIRECTORY + "/corepack.cmd",
    ARCHIVE_ROOT_DIRECTORY + "/npm.cmd",
    ARCHIVE_ROOT_DIRECTORY + "/npx.cmd",
)

MAX_ARCHIVE_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_SHASUMS_RESPONSE_BYTES = 64 * 1024
MAX_SIGNATURE_RESPONSE_BYTES = 64 * 1024
MAX_KEY_MATERIAL_BYTES = 1024 * 1024
MAX_ARCHIVE_ENTRY_COUNT = 20_000
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 200
MAX_ARCHIVE_PATH_UTF8_BYTES = 1_024
MAX_ARCHIVE_COMPONENT_UTF8_BYTES = 255
MAX_ARCHIVE_PATH_DEPTH = 32
EXPECTED_ARCHIVE_ROOT_COUNT = 1
MAX_AUTHENTICITY_REQUEST_COUNT = 5
EXECUTION_DEADLINE_SECONDS = 300
ARTIFACT_PROOF_DEADLINE_SECONDS = 300
AUTOMATIC_APPLICATION_RETRY_COUNT = 0

EXCLUDED_ARTIFACT_FAMILIES = (
    "container_image",
    "node_version_manager",
    "node_win_x64_7z",
    "node_win_x64_msi",
    "package_manager_installed_node",
    "standalone_win_x64_node_exe",
    "system_path_node_or_npm",
    "third_party_chocolatey_package",
    "third_party_winget_package",
)

ARCHIVE_ENTRY_REJECTION_RULES = (
    "absolute_or_rooted_path",
    "alternate_data_stream_or_colon",
    "ancestor_is_non_directory_entry",
    "backslash_separator",
    "casefold_collision",
    "central_and_local_header_mismatch",
    "crc32_mismatch",
    "device_namespace_or_unc_path",
    "directory_traversal_or_dot_segment",
    "dos_reserved_component",
    "duplicate_canonical_path",
    "empty_nul_or_control_character_component",
    "encrypted_entry",
    "entry_count_bound_exceeded",
    "expanded_byte_bound_exceeded",
    "hardlink_symlink_reparse_or_special_file",
    "individual_entry_byte_bound_exceeded",
    "invalid_or_non_ascii_name",
    "file_directory_prefix_collision",
    "multiple_or_wrong_top_level_root",
    "non_store_or_deflate_compression_method",
    "overlapping_entry_data_ranges",
    "path_depth_bound_exceeded",
    "path_length_bound_exceeded",
    "ratio_bound_exceeded",
    "destination_escape_or_existing_path_overwrite",
    "split_or_multidisk_archive",
    "trailing_dot_or_space_component",
    "trailing_data_after_end_record",
    "unicode_normalization_ambiguity",
    "zip64_archive_or_entry",
)

DEFERRED_GATES = (
    "exact_node_release_keyring_revision_bytes_and_sha256_selection",
    "controlled_official_shasums_detached_sig_and_clearsigned_asc_retrieval",
    "both_openpgp_forms_same_expected_signer_and_cleartext_equality_proof",
    "signed_shasums_exact_archive_and_standalone_exe_entry_binding",
    "controlled_exact_portable_zip_download_and_content_length_proof",
    "downloaded_archive_byte_sha256_verification",
    "bounded_complete_zip_inventory_and_rejection_rule_proof",
    "atomic_safe_out_of_repository_extraction",
    "extracted_node_executable_byte_sha256_verification",
    "bundled_npm_package_version_cli_inventory_and_file_hash_proof",
    "verified_absolute_node_plus_npm_cli_entrypoint_version_probe",
    "controlled_isolated_package_lock_only_candidate_generation",
    "complete_lock_graph_integrity_metadata_and_platform_closure",
    "remaining_initial_scaffold_bytes_selection_and_materialization",
)

MAX_DOCUMENT_BYTES = 65_536
CANONICAL_RECEIPT_SHA256 = (
    "ea3320ac9cc9168f3d2b7837ccbcfead8245a5372b6d6dda1a1a2f7b8f352f25"
)


class EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError(
    ValueError
):
    """Sanitized Step 238 offline readiness failure."""


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


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step238-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


def _step237_chain() -> dict[str, object]:
    return {
        "accepted_state_manifest_bytes": (
            STEP237_FINAL_ACCEPTED_STATE_MANIFEST_BYTES
        ),
        "accepted_state_manifest_sha256": (
            STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "canonical_receipt_sha256": STEP237_CANONICAL_RECEIPT_SHA256,
        "deferred_gate_plan_sha256": STEP237_DEFERRED_GATE_PLAN_SHA256,
        "initial_scaffold_allowlist_sha256": (
            STEP237_INITIAL_SCAFFOLD_ALLOWLIST_SHA256
        ),
        "lock_generation_plan_sha256": STEP237_LOCK_GENERATION_PLAN_SHA256,
        "mandatory_lock_anchor_plan_sha256": (
            STEP237_MANDATORY_LOCK_ANCHOR_PLAN_SHA256
        ),
        "npmrc_bytes_sha256": STEP237_NPMRC_BYTES_SHA256,
        "npmrc_policy_plan_sha256": STEP237_NPMRC_POLICY_PLAN_SHA256,
        "package_manifest_bytes_sha256": (
            STEP237_PACKAGE_MANIFEST_BYTES_SHA256
        ),
        "package_manifest_lock_readiness_sha256": (
            STEP237_PACKAGE_MANIFEST_LOCK_READINESS_SHA256
        ),
        "package_manifest_lock_readiness_test_sha256": (
            STEP237_PACKAGE_MANIFEST_LOCK_READINESS_TEST_SHA256
        ),
        "package_manifest_plan_sha256": (
            STEP237_PACKAGE_MANIFEST_PLAN_SHA256
        ),
        "package_manifest_sha256": STEP237_PACKAGE_MANIFEST_SHA256,
        "readiness_document_sha256": STEP237_READINESS_DOCUMENT_SHA256,
        "step235_chain_sha256": STEP237_STEP235_CHAIN_SHA256,
        "step236_binding_sha256": STEP237_STEP236_BINDING_SHA256,
    }


def _execution_platform_selection() -> dict[str, object]:
    return {
        "architecture": TARGET_ARCHITECTURE,
        "archive_format": ARCHIVE_FORMAT,
        "host_validation": {
            "installer_coarse_observation_required": {
                "environment_processor_architecture": "AMD64",
                "is_64_bit_operating_system": True,
                "is_64_bit_process": True,
                "os_version_platform": "Win32NT",
            },
            "minimum_node_platform_floor": "Windows 10 or Windows Server 2016",
            "must_be_operating_system": TARGET_OPERATING_SYSTEM,
            "full_host_support_observation_deferred_to_successor": True,
            "path_runtime_discovery_forbidden": True,
            "require_current_vendor_supported_non_eol_disposition": True,
            "windows_build_display_version_edition_servicing_ltsc_esu_"
            "disposition": "successor_exact_proof_required",
        },
        "operating_system": TARGET_OPERATING_SYSTEM,
        "platform_profile": TARGET_PLATFORM,
        "selection_reason": (
            "portable_non_installer_artifact_for_the_controlled_windows_host_"
            "lock_candidate_only"
        ),
        "unselected_build_and_runtime_platforms": [
            "linux-x64-container-build",
            "production-static-host",
            "browser-runtime",
        ],
    }


def _artifact_selection() -> dict[str, object]:
    return {
        "archive_filename": NODE_ARCHIVE_FILENAME,
        "archive_format": ARCHIVE_FORMAT,
        "archive_root_directory": ARCHIVE_ROOT_DIRECTORY,
        "archive_url": NODE_ARCHIVE_URL,
        "published_archive_bytes": NODE_ARCHIVE_PUBLISHED_BYTES,
        "bundled_npm_version": NPM_VERSION,
        "excluded_artifact_families": list(EXCLUDED_ARTIFACT_FAMILIES),
        "node_lts_codename": NODE_LTS_CODENAME,
        "node_modules_version": NODE_MODULES_VERSION,
        "node_release_date": NODE_RELEASE_DATE,
        "node_version": NODE_VERSION,
        "node_version_tag": NODE_VERSION_TAG,
        "package_manager": PACKAGE_MANAGER,
        "published_archive_sha256_candidate": (
            NODE_ARCHIVE_PUBLISHED_SHA256
        ),
        "published_standalone_exe_sha256_candidate": (
            NODE_STANDALONE_EXE_PUBLISHED_SHA256
        ),
        "selection_kind": "official_portable_zip",
        "trust_state": "selected_untrusted_until_successor_signed_proof",
    }


def _authenticity_proof_plan() -> dict[str, object]:
    return {
        "authorization": "blocked",
        "automatic_application_retry_count": AUTOMATIC_APPLICATION_RETRY_COUNT,
        "expected_signer_fingerprint": (
            EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT
        ),
        "expected_signer_key_id": EXPECTED_NODE_RELEASE_SIGNER_KEY_ID,
        "expected_signature_algorithm": (
            EXPECTED_NODE_RELEASE_SIGNATURE_ALGORITHM
        ),
        "expected_clearsigned_signature_created_utc": (
            EXPECTED_NODE_RELEASE_CLEARSIGNED_SIGNATURE_CREATED_UTC
        ),
        "expected_detached_signature_created_utc": (
            EXPECTED_NODE_RELEASE_DETACHED_SIGNATURE_CREATED_UTC
        ),
        "expected_signature_digest": EXPECTED_NODE_RELEASE_SIGNATURE_DIGEST,
        "clearsigned_text_equality_semantics": (
            "strict_rfc4880_cleartext_body_recovery_with_dash_unescaping_"
            "and_line_ending_normalization_to_exact_2967_byte_lf_shasums_"
            "without_tool_added_terminal_newline"
        ),
        "keyring": {
            "ephemeral_isolated_keyring_required": True,
            "exact_raw_key_bytes": NODE_RELEASE_KEY_BYTES,
            "exact_raw_key_sha256": NODE_RELEASE_KEY_SHA256,
            "exact_release_keys_commit": NODE_RELEASE_KEYS_COMMIT,
            "exact_relative_path": NODE_RELEASE_KEY_RELATIVE_PATH,
            "exact_url": NODE_RELEASE_KEY_URL,
            "material_verified": False,
            "trust_scope": "expected_signer_for_exact_v24_19_0_release_only",
        },
        "network": {
            "allowed_exact_origins": [
                NODE_DISTRIBUTION_ORIGIN,
                "https://raw.githubusercontent.com",
            ],
            "allowed_hosts": ["nodejs.org", "raw.githubusercontent.com"],
            "authorization_cookie_and_credentials": "forbidden",
            "external_deadline_seconds": ARTIFACT_PROOF_DEADLINE_SECONDS,
            "maximum_request_count": MAX_AUTHENTICITY_REQUEST_COUNT,
            "method": "GET",
            "proxy": "forbidden",
            "redirect_count": 0,
            "response_persistence": (
                "archive_only_in_fresh_out_of_repository_temporary_directory"
            ),
        },
        "requests_in_order": [
            {
                "expected_response_bytes": NODE_RELEASE_KEY_BYTES,
                "expected_response_sha256": NODE_RELEASE_KEY_SHA256,
                "maximum_response_bytes": MAX_KEY_MATERIAL_BYTES,
                "purpose": "pinned_release_signer_raw_public_key",
                "url": NODE_RELEASE_KEY_URL,
            },
            {
                "expected_response_bytes": NODE_SHASUMS_BODY_BYTES,
                "expected_response_sha256": NODE_SHASUMS_BODY_SHA256,
                "maximum_response_bytes": MAX_SHASUMS_RESPONSE_BYTES,
                "purpose": "signed_checksum_payload",
                "url": NODE_SHASUMS_URL,
            },
            {
                "expected_response_bytes": NODE_SHASUMS_SIG_BYTES,
                "expected_response_sha256": NODE_SHASUMS_SIG_SHA256,
                "maximum_response_bytes": MAX_SIGNATURE_RESPONSE_BYTES,
                "purpose": "detached_openpgp_binary_signature",
                "url": NODE_SHASUMS_SIG_URL,
            },
            {
                "expected_response_bytes": NODE_SHASUMS_ASC_BYTES,
                "expected_response_sha256": NODE_SHASUMS_ASC_SHA256,
                "maximum_response_bytes": MAX_SIGNATURE_RESPONSE_BYTES,
                "purpose": "clear_signed_openpgp_checksum_payload",
                "url": NODE_SHASUMS_ASC_URL,
            },
            {
                "expected_response_bytes": NODE_ARCHIVE_PUBLISHED_BYTES,
                "expected_response_sha256": NODE_ARCHIVE_PUBLISHED_SHA256,
                "maximum_response_bytes": MAX_ARCHIVE_DOWNLOAD_BYTES,
                "purpose": "selected_portable_node_archive",
                "url": NODE_ARCHIVE_URL,
            },
        ],
        "step236_observed_shasums_body_sha256": NODE_SHASUMS_BODY_SHA256,
        "success_order": [
            "retrieve_and_hash_exact_pinned_raw_release_key",
            "create_fresh_ephemeral_keyring_and_verify_exact_fingerprint",
            "retrieve_exact_shasums_detached_sig_and_clear_signed_asc",
            "verify_both_signatures_and_exact_release_specific_signer",
            "recover_rfc4880_cleartext_with_dash_unescaping_and_normalize_"
            "line_endings_without_tool_added_terminal_newline",
            "require_recovered_cleartext_byte_equal_exact_2967_byte_lf_shasums",
            "parse_unique_exact_archive_and_standalone_exe_entries",
            "require_selected_published_checksum_candidates_match_signed_entries",
            "download_exact_archive_without_redirect_or_retry",
            "require_exact_content_length_within_selected_bound",
            "verify_archive_bytes_against_signed_sha256_before_inspection",
        ],
    }


def _archive_safety_plan() -> dict[str, object]:
    return {
        "authorization": "blocked",
        "bounds": {
            "maximum_archive_download_bytes": MAX_ARCHIVE_DOWNLOAD_BYTES,
            "maximum_compression_ratio": MAX_ARCHIVE_COMPRESSION_RATIO,
            "maximum_entry_bytes": MAX_ARCHIVE_ENTRY_BYTES,
            "maximum_entry_count": MAX_ARCHIVE_ENTRY_COUNT,
            "maximum_expanded_bytes": MAX_ARCHIVE_EXPANDED_BYTES,
            "maximum_path_utf8_bytes": MAX_ARCHIVE_PATH_UTF8_BYTES,
            "maximum_component_utf8_bytes": (
                MAX_ARCHIVE_COMPONENT_UTF8_BYTES
            ),
            "maximum_path_depth": MAX_ARCHIVE_PATH_DEPTH,
            "required_root_count": EXPECTED_ARCHIVE_ROOT_COUNT,
        },
        "destination": {
            "atomic_publish": "required_after_complete_validation",
            "collision_and_reparse_recheck": "required_just_in_time",
            "fresh_empty_directory": True,
            "outside_repository": True,
            "permissions": "current_user_only_where_supported",
        },
        "expected_single_root_directory": ARCHIVE_ROOT_DIRECTORY,
        "inventory_before_extraction": "complete_required",
        "rejection_rules": list(ARCHIVE_ENTRY_REJECTION_RULES),
        "selected_archive_inspected": False,
    }


def _entrypoint_binding_plan() -> dict[str, object]:
    return {
        "authorization": "blocked",
        "forbidden_launchers": list(FORBIDDEN_LAUNCHER_RELATIVE_PATHS),
        "invocation_prefix": [
            "verified_absolute_extracted_node_executable",
            "verified_absolute_extracted_npm_cli_js",
        ],
        "node_executable_relative_path": NODE_EXECUTABLE_RELATIVE_PATH,
        "node_executable_sha256_candidate": (
            NODE_STANDALONE_EXE_PUBLISHED_SHA256
        ),
        "npm_cli_relative_path": NPM_CLI_RELATIVE_PATH,
        "npm_package_json_relative_path": NPM_PACKAGE_JSON_RELATIVE_PATH,
        "npm_package_json_required_version": NPM_VERSION,
        "shell_resolution": "forbidden",
        "step237_lock_generation_plan_sha256": (
            STEP237_LOCK_GENERATION_PLAN_SHA256
        ),
        "version_probe": {
            "expected_node_stdout": "v24.19.0",
            "expected_npm_stdout": "11.17.0",
            "external_deadline_seconds": EXECUTION_DEADLINE_SECONDS,
            "working_directory": "fresh_out_of_repository_temporary_directory",
        },
    }


def _document_projection() -> dict[str, object]:
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "readiness_status": STATUS,
        "approved_step237_chain": _step237_chain(),
        "execution_platform_selection": _execution_platform_selection(),
        "artifact_selection": _artifact_selection(),
        "authenticity_proof_plan": _authenticity_proof_plan(),
        "archive_safety_plan": _archive_safety_plan(),
        "entrypoint_binding_plan": _entrypoint_binding_plan(),
        "deferred_gates": list(DEFERRED_GATES),
    }


def _assert_exact_tree(value: object, expected: object) -> None:
    if type(value) is not type(expected):
        raise ValueError("readiness document value type is not exact")
    if type(expected) is dict:
        if set(value) != set(expected):
            raise ValueError("readiness document object keys are not exact")
        for key in expected:
            _assert_exact_tree(value[key], expected[key])
        return
    if type(expected) is list:
        if len(value) != len(expected):
            raise ValueError("readiness document array length is not exact")
        for actual_item, expected_item in zip(value, expected, strict=True):
            _assert_exact_tree(actual_item, expected_item)
        return
    if value != expected:
        raise ValueError("readiness document value is not exact")


class EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_selection_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_offline_frontend_execution_platform_artifact_selection_readiness"
    ]
    readiness_status: Literal[
        "offline_windows_x64_portable_toolchain_selected_download_signature_verification_extraction_execution_and_lock_generation_blocked"
    ]
    approved_step237_chain: dict[str, Any]
    execution_platform_selection: dict[str, Any]
    artifact_selection: dict[str, Any]
    authenticity_proof_plan: dict[str, Any]
    archive_safety_plan: dict[str, Any]
    entrypoint_binding_plan: dict[str, Any]
    deferred_gates: list[str]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        _assert_exact_tree(value, _document_projection())
        return value

    @model_validator(mode="after")
    def validate_identity_fields(
        self,
    ) -> EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument:
        digest_values = [
            value
            for key, value in self.approved_step237_chain.items()
            if key.endswith("sha256")
        ]
        digest_values.extend(
            [
                self.artifact_selection["published_archive_sha256_candidate"],
                self.artifact_selection[
                    "published_standalone_exe_sha256_candidate"
                ],
                self.authenticity_proof_plan[
                    "step236_observed_shasums_body_sha256"
                ],
                self.entrypoint_binding_plan[
                    "node_executable_sha256_candidate"
                ],
                self.entrypoint_binding_plan[
                    "step237_lock_generation_plan_sha256"
                ],
            ]
        )
        if any(not _is_sha256(value) for value in digest_values):
            raise ValueError("readiness document SHA-256 identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    approved_step237_package_manifest_sha256: str
    approved_step237_final_accepted_state_manifest_sha256: str
    approved_step237_final_accepted_state_manifest_bytes: int
    approved_step237_readiness_module_sha256: str
    approved_step237_readiness_test_sha256: str
    approved_step237_canonical_receipt_sha256: str
    approved_step237_readiness_document_sha256: str
    approved_step237_lock_generation_plan_sha256: str
    target_platform: str
    target_operating_system: str
    target_architecture: str
    archive_format: str
    node_version: str
    node_lts_codename: str
    bundled_npm_version: str
    package_manager: str
    node_archive_filename: str
    node_archive_url: str
    node_archive_published_bytes: int
    node_archive_published_sha256: str
    node_standalone_exe_published_sha256: str
    node_release_date: str
    node_modules_version: int
    node_shasums_body_bytes: int
    node_shasums_body_sha256: str
    node_shasums_url: str
    node_shasums_sig_bytes: int
    node_shasums_sig_sha256: str
    node_shasums_sig_url: str
    node_shasums_asc_bytes: int
    node_shasums_asc_sha256: str
    node_shasums_asc_url: str
    expected_signer_fingerprint: str
    expected_signer_key_id: str
    expected_signature_algorithm: str
    expected_signature_digest: str
    expected_detached_signature_created_utc: str
    expected_clearsigned_signature_created_utc: str
    release_keys_commit: str
    release_key_relative_path: str
    release_key_url: str
    release_key_bytes: int
    release_key_sha256: str
    maximum_archive_download_bytes: int
    maximum_shasums_response_bytes: int
    maximum_signature_response_bytes: int
    maximum_key_material_bytes: int
    maximum_archive_entry_count: int
    maximum_archive_expanded_bytes: int
    maximum_archive_entry_bytes: int
    maximum_archive_compression_ratio: int
    maximum_archive_path_utf8_bytes: int
    maximum_archive_component_utf8_bytes: int
    maximum_archive_path_depth: int
    maximum_authenticity_request_count: int
    automatic_application_retry_count: int
    artifact_proof_deadline_seconds: int
    excluded_artifact_family_count: int
    archive_rejection_rule_count: int
    deferred_gate_count: int
    approved_step237_chain_sha256: str
    execution_platform_selection_sha256: str
    artifact_selection_sha256: str
    authenticity_proof_plan_sha256: str
    archive_safety_plan_sha256: str
    entrypoint_binding_plan_sha256: str
    deferred_gate_plan_sha256: str
    readiness_document_sha256: str
    exact_step237_package_and_final_state_bound: bool
    exact_step237_payload_receipt_document_and_plans_bound: bool
    windows_x64_portable_execution_platform_selected: bool
    exact_official_node_archive_filename_and_url_selected: bool
    exact_node_npm_versions_and_lts_codename_selected: bool
    published_archive_checksum_candidate_bound: bool
    published_standalone_exe_checksum_candidate_bound: bool
    step236_observed_shasums_body_identity_bound: bool
    portable_zip_selected_without_installer_or_system_mutation: bool
    npm_selected_only_as_node_archive_bundled_content: bool
    system_path_and_shell_launcher_resolution_forbidden: bool
    absolute_node_plus_npm_cli_invocation_required: bool
    native_windows_x64_host_recheck_required: bool
    windows_platform_floor_and_current_support_disposition_required: bool
    release_keyring_exact_revision_and_bytes_required: bool
    detached_openpgp_signature_verification_required: bool
    clearsigned_openpgp_signature_and_text_equality_verification_required: bool
    expected_release_signer_fingerprint_required: bool
    signed_unique_shasums_entries_required: bool
    redirect_credentials_proxy_and_application_retries_forbidden: bool
    exact_content_length_and_archive_byte_hash_required: bool
    download_size_request_count_and_response_bounds_selected: bool
    complete_archive_inventory_required_before_extraction: bool
    single_exact_archive_root_required: bool
    traversal_drive_ads_backslash_and_case_collision_rejected: bool
    symlink_reparse_hardlink_and_special_entries_rejected: bool
    zip_bomb_entry_expansion_ratio_path_and_depth_bounds_selected: bool
    fresh_out_of_repository_extraction_required: bool
    collision_and_reparse_recheck_required_just_in_time: bool
    extracted_node_executable_hash_verification_required: bool
    npm_package_version_cli_inventory_and_hash_proof_required: bool
    external_execution_monitor_and_deadline_required: bool
    step237_lock_plan_remains_authoritative_for_future_candidate: bool
    linux_container_build_platform_remains_unselected: bool
    artifact_selection_is_not_authenticity_or_execution_authorization: bool
    step238_external_request_performed: bool
    contract_module_host_platform_observed: bool
    host_compatibility_verified: bool
    host_vendor_support_verified: bool
    container_build_platform_selected: bool
    production_platform_selected: bool
    global_node_install_authorized: bool
    path_registry_or_msi_mutation_authorized: bool
    node_release_keyring_selected_or_persisted: bool
    release_key_material_verified: bool
    ephemeral_keyring_created: bool
    shasums_or_signature_retrieved: bool
    shasums_detached_signature_verified: bool
    shasums_clearsigned_signature_verified: bool
    clearsigned_text_equals_exact_shasums_verified: bool
    node_release_signer_trust_proven: bool
    published_checksum_candidates_promoted_to_trusted_evidence: bool
    node_archive_downloaded_or_content_length_proven: bool
    node_archive_byte_hash_verified: bool
    node_archive_inventory_inspected: bool
    node_archive_extracted: bool
    node_executable_or_npm_cli_file_hash_verified: bool
    node_or_npm_executed: bool
    package_manager_or_lifecycle_script_executed: bool
    lock_generation_authorized_or_performed: bool
    lockfile_created_or_modified: bool
    frontend_root_created_or_scaffold_written: bool
    dependency_downloaded_or_installed: bool
    browser_oauth_graph_entra_or_application_endpoint_requested: bool
    application_configuration_modified_or_activated: bool
    operational_write_performed: bool
    docker_restarted_or_rebuilt: bool
    git_stage_commit_or_push_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "approved_step237_package_manifest_sha256": STEP237_PACKAGE_MANIFEST_SHA256,
            "approved_step237_final_accepted_state_manifest_sha256": STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
            "approved_step237_final_accepted_state_manifest_bytes": STEP237_FINAL_ACCEPTED_STATE_MANIFEST_BYTES,
            "approved_step237_readiness_module_sha256": STEP237_PACKAGE_MANIFEST_LOCK_READINESS_SHA256,
            "approved_step237_readiness_test_sha256": STEP237_PACKAGE_MANIFEST_LOCK_READINESS_TEST_SHA256,
            "approved_step237_canonical_receipt_sha256": STEP237_CANONICAL_RECEIPT_SHA256,
            "approved_step237_readiness_document_sha256": STEP237_READINESS_DOCUMENT_SHA256,
            "approved_step237_lock_generation_plan_sha256": STEP237_LOCK_GENERATION_PLAN_SHA256,
            "target_platform": TARGET_PLATFORM,
            "target_operating_system": TARGET_OPERATING_SYSTEM,
            "target_architecture": TARGET_ARCHITECTURE,
            "archive_format": ARCHIVE_FORMAT,
            "node_version": NODE_VERSION,
            "node_lts_codename": NODE_LTS_CODENAME,
            "bundled_npm_version": NPM_VERSION,
            "package_manager": PACKAGE_MANAGER,
            "node_archive_filename": NODE_ARCHIVE_FILENAME,
            "node_archive_url": NODE_ARCHIVE_URL,
            "node_archive_published_bytes": NODE_ARCHIVE_PUBLISHED_BYTES,
            "node_archive_published_sha256": NODE_ARCHIVE_PUBLISHED_SHA256,
            "node_standalone_exe_published_sha256": NODE_STANDALONE_EXE_PUBLISHED_SHA256,
            "node_release_date": NODE_RELEASE_DATE,
            "node_modules_version": NODE_MODULES_VERSION,
            "node_shasums_body_bytes": NODE_SHASUMS_BODY_BYTES,
            "node_shasums_body_sha256": NODE_SHASUMS_BODY_SHA256,
            "node_shasums_url": NODE_SHASUMS_URL,
            "node_shasums_sig_bytes": NODE_SHASUMS_SIG_BYTES,
            "node_shasums_sig_sha256": NODE_SHASUMS_SIG_SHA256,
            "node_shasums_sig_url": NODE_SHASUMS_SIG_URL,
            "node_shasums_asc_bytes": NODE_SHASUMS_ASC_BYTES,
            "node_shasums_asc_sha256": NODE_SHASUMS_ASC_SHA256,
            "node_shasums_asc_url": NODE_SHASUMS_ASC_URL,
            "expected_signer_fingerprint": EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT,
            "expected_signer_key_id": EXPECTED_NODE_RELEASE_SIGNER_KEY_ID,
            "expected_signature_algorithm": EXPECTED_NODE_RELEASE_SIGNATURE_ALGORITHM,
            "expected_signature_digest": EXPECTED_NODE_RELEASE_SIGNATURE_DIGEST,
            "expected_detached_signature_created_utc": EXPECTED_NODE_RELEASE_DETACHED_SIGNATURE_CREATED_UTC,
            "expected_clearsigned_signature_created_utc": EXPECTED_NODE_RELEASE_CLEARSIGNED_SIGNATURE_CREATED_UTC,
            "release_keys_commit": NODE_RELEASE_KEYS_COMMIT,
            "release_key_relative_path": NODE_RELEASE_KEY_RELATIVE_PATH,
            "release_key_url": NODE_RELEASE_KEY_URL,
            "release_key_bytes": NODE_RELEASE_KEY_BYTES,
            "release_key_sha256": NODE_RELEASE_KEY_SHA256,
            "maximum_archive_download_bytes": MAX_ARCHIVE_DOWNLOAD_BYTES,
            "maximum_shasums_response_bytes": MAX_SHASUMS_RESPONSE_BYTES,
            "maximum_signature_response_bytes": MAX_SIGNATURE_RESPONSE_BYTES,
            "maximum_key_material_bytes": MAX_KEY_MATERIAL_BYTES,
            "maximum_archive_entry_count": MAX_ARCHIVE_ENTRY_COUNT,
            "maximum_archive_expanded_bytes": MAX_ARCHIVE_EXPANDED_BYTES,
            "maximum_archive_entry_bytes": MAX_ARCHIVE_ENTRY_BYTES,
            "maximum_archive_compression_ratio": MAX_ARCHIVE_COMPRESSION_RATIO,
            "maximum_archive_path_utf8_bytes": MAX_ARCHIVE_PATH_UTF8_BYTES,
            "maximum_archive_component_utf8_bytes": MAX_ARCHIVE_COMPONENT_UTF8_BYTES,
            "maximum_archive_path_depth": MAX_ARCHIVE_PATH_DEPTH,
            "maximum_authenticity_request_count": MAX_AUTHENTICITY_REQUEST_COUNT,
            "automatic_application_retry_count": AUTOMATIC_APPLICATION_RETRY_COUNT,
            "artifact_proof_deadline_seconds": ARTIFACT_PROOF_DEADLINE_SECONDS,
            "excluded_artifact_family_count": len(EXCLUDED_ARTIFACT_FAMILIES),
            "archive_rejection_rule_count": len(ARCHIVE_ENTRY_REJECTION_RULES),
            "deferred_gate_count": len(DEFERRED_GATES),
            "approved_step237_chain_sha256": _framed("step237-chain", _step237_chain()),
            "execution_platform_selection_sha256": _framed("execution-platform-selection", _execution_platform_selection()),
            "artifact_selection_sha256": _framed("artifact-selection", _artifact_selection()),
            "authenticity_proof_plan_sha256": _framed("authenticity-proof-plan", _authenticity_proof_plan()),
            "archive_safety_plan_sha256": _framed("archive-safety-plan", _archive_safety_plan()),
            "entrypoint_binding_plan_sha256": _framed("entrypoint-binding-plan", _entrypoint_binding_plan()),
            "deferred_gate_plan_sha256": _framed("deferred-gates", DEFERRED_GATES),
            "readiness_document_sha256": hashlib.sha256(_canonical(_document_projection())).hexdigest(),
        }
        required_true = {
            "exact_step237_package_and_final_state_bound",
            "exact_step237_payload_receipt_document_and_plans_bound",
            "windows_x64_portable_execution_platform_selected",
            "exact_official_node_archive_filename_and_url_selected",
            "exact_node_npm_versions_and_lts_codename_selected",
            "published_archive_checksum_candidate_bound",
            "published_standalone_exe_checksum_candidate_bound",
            "step236_observed_shasums_body_identity_bound",
            "portable_zip_selected_without_installer_or_system_mutation",
            "npm_selected_only_as_node_archive_bundled_content",
            "system_path_and_shell_launcher_resolution_forbidden",
            "absolute_node_plus_npm_cli_invocation_required",
            "native_windows_x64_host_recheck_required",
            "windows_platform_floor_and_current_support_disposition_required",
            "release_keyring_exact_revision_and_bytes_required",
            "detached_openpgp_signature_verification_required",
            "clearsigned_openpgp_signature_and_text_equality_verification_required",
            "expected_release_signer_fingerprint_required",
            "signed_unique_shasums_entries_required",
            "redirect_credentials_proxy_and_application_retries_forbidden",
            "exact_content_length_and_archive_byte_hash_required",
            "download_size_request_count_and_response_bounds_selected",
            "complete_archive_inventory_required_before_extraction",
            "single_exact_archive_root_required",
            "traversal_drive_ads_backslash_and_case_collision_rejected",
            "symlink_reparse_hardlink_and_special_entries_rejected",
            "zip_bomb_entry_expansion_ratio_path_and_depth_bounds_selected",
            "fresh_out_of_repository_extraction_required",
            "collision_and_reparse_recheck_required_just_in_time",
            "extracted_node_executable_hash_verification_required",
            "npm_package_version_cli_inventory_and_hash_proof_required",
            "external_execution_monitor_and_deadline_required",
            "step237_lock_plan_remains_authoritative_for_future_candidate",
            "linux_container_build_platform_remains_unselected",
            "artifact_selection_is_not_authenticity_or_execution_authorization",
        }
        required_false = {
            "step238_external_request_performed",
            "contract_module_host_platform_observed",
            "host_compatibility_verified",
            "host_vendor_support_verified",
            "container_build_platform_selected",
            "production_platform_selected",
            "global_node_install_authorized",
            "path_registry_or_msi_mutation_authorized",
            "node_release_keyring_selected_or_persisted",
            "release_key_material_verified",
            "ephemeral_keyring_created",
            "shasums_or_signature_retrieved",
            "shasums_detached_signature_verified",
            "shasums_clearsigned_signature_verified",
            "clearsigned_text_equals_exact_shasums_verified",
            "node_release_signer_trust_proven",
            "published_checksum_candidates_promoted_to_trusted_evidence",
            "node_archive_downloaded_or_content_length_proven",
            "node_archive_byte_hash_verified",
            "node_archive_inventory_inspected",
            "node_archive_extracted",
            "node_executable_or_npm_cli_file_hash_verified",
            "node_or_npm_executed",
            "package_manager_or_lifecycle_script_executed",
            "lock_generation_authorized_or_performed",
            "lockfile_created_or_modified",
            "frontend_root_created_or_scaffold_written",
            "dependency_downloaded_or_installed",
            "browser_oauth_graph_entra_or_application_endpoint_requested",
            "application_configuration_modified_or_activated",
            "operational_write_performed",
            "docker_restarted_or_rebuilt",
            "git_stage_commit_or_push_performed",
        }
        fields = {field.name for field in dataclasses.fields(self)}
        if fields != set(constants) | required_true | required_false:
            raise ValueError("readiness receipt validation coverage is incomplete")
        if any(
            type(getattr(self, name)) is not type(expected)
            or getattr(self, name) != expected
            for name, expected in constants.items()
        ):
            raise ValueError("readiness receipt constant is invalid")
        if any(
            type(getattr(self, name)) is not bool or not getattr(self, name)
            for name in required_true
        ):
            raise ValueError("readiness receipt required control is invalid")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError("readiness receipt forbidden outcome is invalid")
        if any(
            name.endswith("sha256") and not _is_sha256(getattr(self, name))
            for name in constants
        ):
            raise ValueError("readiness receipt SHA-256 identity is invalid")


def render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_document() -> bytes:
    """Render the one exact Step 238 offline input document in memory."""

    return _canonical(_document_projection())


def load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness(
    document: bytes,
) -> EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt:
    """Validate the exact offline selection and return a blocking receipt."""

    try:
        canonical_document = _canonical(_document_projection())
        if (
            type(document) is not bytes
            or not document
            or len(document) > MAX_DOCUMENT_BYTES
            or document != canonical_document
        ):
            raise ValueError("readiness document bytes are not exact")
        parsed = json.loads(
            document.decode("ascii"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
        model = EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument.model_validate(
            parsed
        )
        if _canonical(model.model_dump(mode="json")) != canonical_document:
            raise ValueError("validated readiness document is not canonical")
        false_controls = {
            "step238_external_request_performed",
            "contract_module_host_platform_observed",
            "host_compatibility_verified",
            "host_vendor_support_verified",
            "container_build_platform_selected",
            "production_platform_selected",
            "global_node_install_authorized",
            "path_registry_or_msi_mutation_authorized",
            "node_release_keyring_selected_or_persisted",
            "release_key_material_verified",
            "ephemeral_keyring_created",
            "shasums_or_signature_retrieved",
            "shasums_detached_signature_verified",
            "shasums_clearsigned_signature_verified",
            "clearsigned_text_equals_exact_shasums_verified",
            "node_release_signer_trust_proven",
            "published_checksum_candidates_promoted_to_trusted_evidence",
            "node_archive_downloaded_or_content_length_proven",
            "node_archive_byte_hash_verified",
            "node_archive_inventory_inspected",
            "node_archive_extracted",
            "node_executable_or_npm_cli_file_hash_verified",
            "node_or_npm_executed",
            "package_manager_or_lifecycle_script_executed",
            "lock_generation_authorized_or_performed",
            "lockfile_created_or_modified",
            "frontend_root_created_or_scaffold_written",
            "dependency_downloaded_or_installed",
            "browser_oauth_graph_entra_or_application_endpoint_requested",
            "application_configuration_modified_or_activated",
            "operational_write_performed",
            "docker_restarted_or_rebuilt",
            "git_stage_commit_or_push_performed",
        }
        receipt_field_names = [
            field.name
            for field in dataclasses.fields(
                EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt
            )
        ]
        control_start = receipt_field_names.index(
            "exact_step237_package_and_final_state_bound"
        )
        true_controls = set(receipt_field_names[control_start:]) - false_controls
        receipt = EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            approved_step237_package_manifest_sha256=STEP237_PACKAGE_MANIFEST_SHA256,
            approved_step237_final_accepted_state_manifest_sha256=STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
            approved_step237_final_accepted_state_manifest_bytes=STEP237_FINAL_ACCEPTED_STATE_MANIFEST_BYTES,
            approved_step237_readiness_module_sha256=STEP237_PACKAGE_MANIFEST_LOCK_READINESS_SHA256,
            approved_step237_readiness_test_sha256=STEP237_PACKAGE_MANIFEST_LOCK_READINESS_TEST_SHA256,
            approved_step237_canonical_receipt_sha256=STEP237_CANONICAL_RECEIPT_SHA256,
            approved_step237_readiness_document_sha256=STEP237_READINESS_DOCUMENT_SHA256,
            approved_step237_lock_generation_plan_sha256=STEP237_LOCK_GENERATION_PLAN_SHA256,
            target_platform=TARGET_PLATFORM,
            target_operating_system=TARGET_OPERATING_SYSTEM,
            target_architecture=TARGET_ARCHITECTURE,
            archive_format=ARCHIVE_FORMAT,
            node_version=NODE_VERSION,
            node_lts_codename=NODE_LTS_CODENAME,
            bundled_npm_version=NPM_VERSION,
            package_manager=PACKAGE_MANAGER,
            node_archive_filename=NODE_ARCHIVE_FILENAME,
            node_archive_url=NODE_ARCHIVE_URL,
            node_archive_published_bytes=NODE_ARCHIVE_PUBLISHED_BYTES,
            node_archive_published_sha256=NODE_ARCHIVE_PUBLISHED_SHA256,
            node_standalone_exe_published_sha256=NODE_STANDALONE_EXE_PUBLISHED_SHA256,
            node_release_date=NODE_RELEASE_DATE,
            node_modules_version=NODE_MODULES_VERSION,
            node_shasums_body_bytes=NODE_SHASUMS_BODY_BYTES,
            node_shasums_body_sha256=NODE_SHASUMS_BODY_SHA256,
            node_shasums_url=NODE_SHASUMS_URL,
            node_shasums_sig_bytes=NODE_SHASUMS_SIG_BYTES,
            node_shasums_sig_sha256=NODE_SHASUMS_SIG_SHA256,
            node_shasums_sig_url=NODE_SHASUMS_SIG_URL,
            node_shasums_asc_bytes=NODE_SHASUMS_ASC_BYTES,
            node_shasums_asc_sha256=NODE_SHASUMS_ASC_SHA256,
            node_shasums_asc_url=NODE_SHASUMS_ASC_URL,
            expected_signer_fingerprint=EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT,
            expected_signer_key_id=EXPECTED_NODE_RELEASE_SIGNER_KEY_ID,
            expected_signature_algorithm=EXPECTED_NODE_RELEASE_SIGNATURE_ALGORITHM,
            expected_signature_digest=EXPECTED_NODE_RELEASE_SIGNATURE_DIGEST,
            expected_detached_signature_created_utc=EXPECTED_NODE_RELEASE_DETACHED_SIGNATURE_CREATED_UTC,
            expected_clearsigned_signature_created_utc=EXPECTED_NODE_RELEASE_CLEARSIGNED_SIGNATURE_CREATED_UTC,
            release_keys_commit=NODE_RELEASE_KEYS_COMMIT,
            release_key_relative_path=NODE_RELEASE_KEY_RELATIVE_PATH,
            release_key_url=NODE_RELEASE_KEY_URL,
            release_key_bytes=NODE_RELEASE_KEY_BYTES,
            release_key_sha256=NODE_RELEASE_KEY_SHA256,
            maximum_archive_download_bytes=MAX_ARCHIVE_DOWNLOAD_BYTES,
            maximum_shasums_response_bytes=MAX_SHASUMS_RESPONSE_BYTES,
            maximum_signature_response_bytes=MAX_SIGNATURE_RESPONSE_BYTES,
            maximum_key_material_bytes=MAX_KEY_MATERIAL_BYTES,
            maximum_archive_entry_count=MAX_ARCHIVE_ENTRY_COUNT,
            maximum_archive_expanded_bytes=MAX_ARCHIVE_EXPANDED_BYTES,
            maximum_archive_entry_bytes=MAX_ARCHIVE_ENTRY_BYTES,
            maximum_archive_compression_ratio=MAX_ARCHIVE_COMPRESSION_RATIO,
            maximum_archive_path_utf8_bytes=MAX_ARCHIVE_PATH_UTF8_BYTES,
            maximum_archive_component_utf8_bytes=MAX_ARCHIVE_COMPONENT_UTF8_BYTES,
            maximum_archive_path_depth=MAX_ARCHIVE_PATH_DEPTH,
            maximum_authenticity_request_count=MAX_AUTHENTICITY_REQUEST_COUNT,
            automatic_application_retry_count=AUTOMATIC_APPLICATION_RETRY_COUNT,
            artifact_proof_deadline_seconds=ARTIFACT_PROOF_DEADLINE_SECONDS,
            excluded_artifact_family_count=len(EXCLUDED_ARTIFACT_FAMILIES),
            archive_rejection_rule_count=len(ARCHIVE_ENTRY_REJECTION_RULES),
            deferred_gate_count=len(DEFERRED_GATES),
            approved_step237_chain_sha256=_framed("step237-chain", _step237_chain()),
            execution_platform_selection_sha256=_framed("execution-platform-selection", _execution_platform_selection()),
            artifact_selection_sha256=_framed("artifact-selection", _artifact_selection()),
            authenticity_proof_plan_sha256=_framed("authenticity-proof-plan", _authenticity_proof_plan()),
            archive_safety_plan_sha256=_framed("archive-safety-plan", _archive_safety_plan()),
            entrypoint_binding_plan_sha256=_framed("entrypoint-binding-plan", _entrypoint_binding_plan()),
            deferred_gate_plan_sha256=_framed("deferred-gates", DEFERRED_GATES),
            readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            **{name: True for name in true_controls},
            **{name: False for name in false_controls},
        )
        receipt.__post_init__()
        return receipt
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError(
            "frontend-host execution-platform artifact selection readiness validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt(
    receipt: EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt,
) -> bytes:
    """Render only an exact validated Step 238 receipt as canonical JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt:
        raise TypeError("exact execution-platform artifact receipt is required")
    receipt.__post_init__()
    rendered = _canonical(
        {
            field.name: getattr(receipt, field.name)
            for field in dataclasses.fields(receipt)
        }
    )
    if hashlib.sha256(rendered).hexdigest() != CANONICAL_RECEIPT_SHA256:
        raise ValueError("execution-platform artifact receipt identity is invalid")
    return rendered


__all__ = [
    "ARCHIVE_ENTRY_REJECTION_RULES",
    "ARCHIVE_FORMAT",
    "ARCHIVE_ROOT_DIRECTORY",
    "ARTIFACT_PROOF_DEADLINE_SECONDS",
    "AUTOMATIC_APPLICATION_RETRY_COUNT",
    "CANONICAL_RECEIPT_SHA256",
    "DEFERRED_GATES",
    "DOCUMENT_TYPE",
    "EXCLUDED_ARTIFACT_FAMILIES",
    "EXPECTED_NODE_RELEASE_SIGNER_FINGERPRINT",
    "EXPECTED_NODE_RELEASE_SIGNER_KEY_ID",
    "EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessDocument",
    "EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessError",
    "EntraCallingClientMSALFrontendHostExecutionPlatformArtifactSelectionReadinessReceipt",
    "FORBIDDEN_LAUNCHER_RELATIVE_PATHS",
    "MAX_ARCHIVE_COMPRESSION_RATIO",
    "MAX_ARCHIVE_DOWNLOAD_BYTES",
    "MAX_ARCHIVE_ENTRY_BYTES",
    "MAX_ARCHIVE_ENTRY_COUNT",
    "MAX_ARCHIVE_EXPANDED_BYTES",
    "MAX_AUTHENTICITY_REQUEST_COUNT",
    "MAX_DOCUMENT_BYTES",
    "NODE_ARCHIVE_FILENAME",
    "NODE_ARCHIVE_PUBLISHED_SHA256",
    "NODE_ARCHIVE_URL",
    "NODE_EXECUTABLE_RELATIVE_PATH",
    "NODE_LTS_CODENAME",
    "NODE_SHASUMS_ASC_URL",
    "NODE_SHASUMS_BODY_SHA256",
    "NODE_SHASUMS_SIG_URL",
    "NODE_SHASUMS_URL",
    "NODE_STANDALONE_EXE_PUBLISHED_SHA256",
    "NODE_VERSION",
    "NPM_CLI_RELATIVE_PATH",
    "NPM_PACKAGE_JSON_RELATIVE_PATH",
    "NPM_VERSION",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SOURCE",
    "STATUS",
    "STEP237_CANONICAL_RECEIPT_SHA256",
    "STEP237_FINAL_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP237_LOCK_GENERATION_PLAN_SHA256",
    "STEP237_PACKAGE_MANIFEST_SHA256",
    "TARGET_ARCHITECTURE",
    "TARGET_OPERATING_SYSTEM",
    "TARGET_PLATFORM",
    "load_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness",
    "render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_document",
    "render_entra_calling_client_msal_frontend_host_execution_platform_artifact_selection_readiness_receipt",
]
