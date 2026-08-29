"""Pure Step 237 frontend package-manifest and lock-generation readiness.

This offline contract binds the accepted Step 236 v1/v2 package identities,
the converged Step 236 state and live receipt, and the Step 235 chain carried by
that receipt.  It selects exact *planned* bytes for ``package.json`` and
``.npmrc`` and an exact initial scaffold path allowlist.  It does not create a
frontend root, write either planned file, invoke Node.js or npm, resolve a
dependency graph, access a registry, or authorize lock generation or scaffold
materialization.

Only in-memory JSON validation, canonicalization, and SHA-256 calculation are
implemented here.  The future executor described by the plan is deliberately
absent.
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
    "package_manifest_lock_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_offline_frontend_package_manifest_lock_readiness"
SCOPE = (
    "exact_step236_chain_plus_offline_exact_package_manifest_npm_policy_"
    "controlled_lock_generation_and_initial_scaffold_plan"
)
STATUS = (
    "exact_frontend_package_manifest_and_controlled_lock_generation_plan_"
    "validated_execution_and_materialization_remain_blocked"
)

STEP236_V1_PACKAGE_MANIFEST_SHA256 = (
    "141d0f78416029c5813949eeb8e8e9d038d367af74e965e8b2cb7ac59f669534"
)
STEP236_V2_PACKAGE_MANIFEST_SHA256 = (
    "848ab0fc9c0f8089a9eb313d8d012f71b8b6e075258a47fc510937d8dffcca43"
)
STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "e3495b2d989ef0d1b13d52bbaf3ef7afbdd711e3004661b03fa7faa204f78e04"
)
STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256 = (
    "e145710941196f408c54f2ef5196480096032ad59229c8997e9d074b8fa985df"
)
STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256 = (
    "c2728927d0fd94ace389204518e2d8daecfc562fd7ade808465fc5d32ec938c2"
)
STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256 = (
    "e0ee0fe928fca390638145f2c61ee052248512159d378f62fde0f105fca5072f"
)
STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256 = (
    "4da7be1d24cf4a1d0f8e91e0bde4db32870586c669a94e0c20e9bba6b9ba8fd0"
)
STEP236_CANONICAL_LIVE_RECEIPT_SHA256 = (
    "218f2360a9502fa83db518e597e8440313aaa0be8dbfea5bd67224964805f179"
)
STEP236_SELECTION_PROFILE = (
    "engineer4me_frontend_ecosystem_exact_tuple_2026_08_19_v1"
)
STEP236_STATUS = (
    "official_registry_selected_metadata_compatible_lock_and_"
    "materialization_remain_blocked"
)

STEP235_PACKAGE_MANIFEST_SHA256 = (
    "ffd92f5353e6e41c545b96d18c390eec2b6354776c08ee45544684a85e4a63f1"
)
STEP235_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "09b211df4fae291a33b3509d83dceebaa1e9742d4995c331324cfdf64e7ed023"
)
STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256 = (
    "7dcf0b63695a5857f878264f19c5c4248cea419c6e2bf66896a266c28dac1e22"
)
STEP235_ARCHITECTURE_SELECTION_TEST_SHA256 = (
    "e6cfa249fad7fd40696cd977971674fad4a52f9e6671f1e82bf561e8f5b8959f"
)
STEP235_CANONICAL_RECEIPT_SHA256 = (
    "6b70abd5db7496af97884707a64c52e272c62292de2568aec8adb6a505cf5ee4"
)
STEP235_READINESS_DOCUMENT_SHA256 = (
    "10e40546438acece101c6be7490772a47cf159dc19283eb0c9693ed4bbe9d723"
)
STEP235_ARCHITECTURE_PLAN_SHA256 = (
    "d6ffd2561b069d69f16db836b32f58ff29e5d6fa021559160051035d5b3e8a37"
)
STEP235_SECURITY_PLAN_SHA256 = (
    "5e1edc9034c672ee81c451641852a20661e4724c80742601ed6d7153c79d3ba8"
)
STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256 = (
    "cf47c7b86e4dcebcea1ca442c8d463c98cecbe5bb9fd3b22883f0f60c905d5be"
)
STEP235_DEFERRED_GATE_PLAN_SHA256 = (
    "7253144525f0f93e70d92dd94074aee696389fb54b30bacb1d064caf021e93c7"
)

STEP236_RECEIPT_COUNTS = (
    ("aggregate_response_bytes", 489_277),
    ("deprecated_package_count", 0),
    ("frontend_ecosystem_metadata_count", 22),
    ("mandatory_transitive_anchor_count", 3),
    ("manifest_direct_package_count", 19),
    ("official_http_request_count", 27),
    ("optional_peer_absence_disposition_count", 23),
    ("peer_relationship_count", 41),
    ("provenance_absence_disposition_count", 8),
    ("provenance_present_count", 15),
    ("registry_package_metadata_count", 23),
    ("selected_metadata_advisory_count", 0),
    ("signature_entry_count", 37),
    ("signature_verified_package_count", 23),
)
STEP236_RECEIPT_PROJECTION_SHA256 = (
    ("advisory_projection_sha256", "1e8313ba0d0cc65dc51e3e98dc99ecc2ad06564d4c6c9f27add5f30a3d8d753d"),
    ("dependency_anchor_projection_sha256", "7e584b0888f38b5d114893250cabdf1b16bb795e8e46ed38bbbc69cc82e94d90"),
    ("engine_compatibility_projection_sha256", "1806b0b566a93c00f68fde4e98fc19971f47aefa29304801be9af7715ec4187d"),
    ("integrity_projection_sha256", "b7aff7790a83b1bf2ceacd280fbd6f11879bd7742b8e34053f44db97c136f1d1"),
    ("license_deprecation_projection_sha256", "116d988b0f464169b50229880e7aa3c286466419d1d84701132ba10f01e1dcd4"),
    ("node_release_projection_sha256", "ee7aa5c11b6ec50e309b8f2ee9e0389a522ae018635d68440d7135a7cb58b542"),
    ("node_shasums_projection_sha256", "7fe50c7ca6f602329c78ccece60f14cf64b37e78b33376daeb1446cbcc610a92"),
    ("official_response_body_set_sha256", "39bb6029ac041382a8cc2cb447096e905b6f3c06f34b6df2567f5179418bf233"),
    ("package_metadata_projection_sha256", "102c88addf77ee93008226a827440a0d0848539f0c1da9ec0bf941dd2b38f58f"),
    ("package_response_body_set_sha256", "f5680f48ba60fc23b46513bbd14a47f848f2b2a88696b67ada1f711668c603f4"),
    ("peer_compatibility_projection_sha256", "795286b1682f29854b3fb34149b0cf64af5e6b78e06ea30bd9ce10fcce00edbd"),
    ("provenance_projection_sha256", "8e6bd6225d324f664f008715520432640c91cb0fc68d066b9f7174dc8374610d"),
    ("selected_package_tuple_sha256", "5a59a95b524576e593c9a3ad62dc80d738f0319fc8efd15bc2884142760afa50"),
    ("signature_projection_sha256", "9133ae256174f9fd2550075cd6d2a5d1380eafbd932edeece0493c71f1d58b69"),
)

NODE_VERSION = "24.19.0"
NPM_VERSION = "11.17.0"
NODE_LTS_CODENAME = "Krypton"
LOCKFILE_VERSION = 3
PACKAGE_MANAGER = "npm"
PACKAGE_MANIFEST_PATH = "frontend/package.json"
NPMRC_PATH = "frontend/.npmrc"
LOCKFILE_PATH = "frontend/package-lock.json"
EXCLUDED_RUNTIME_CONFIG_PATH = "frontend/public/runtime-config.json"
ZERO_RETRY_NETWORK_CLIENT_SHA256 = (
    "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
)

PRODUCTION_DEPENDENCIES = (
    ("@azure/msal-browser", "5.18.0"),
    ("react", "19.2.8"),
    ("react-dom", "19.2.8"),
    ("react-router", "8.3.0"),
)
DEVELOPMENT_DEPENDENCIES = (
    ("@axe-core/playwright", "4.13.0"),
    ("@playwright/test", "1.62.1"),
    ("@testing-library/dom", "10.4.1"),
    ("@testing-library/jest-dom", "7.0.1"),
    ("@testing-library/react", "16.3.2"),
    ("@testing-library/user-event", "14.6.5"),
    ("@types/node", "24.13.3"),
    ("@types/react", "19.2.18"),
    ("@types/react-dom", "19.2.4"),
    ("@vitejs/plugin-react", "6.0.5"),
    ("axe-core", "4.13.0"),
    ("jsdom", "30.0.1"),
    ("typescript", "6.0.2"),
    ("vite", "8.2.1"),
    ("vitest", "4.1.11"),
)
MANUAL_SCRIPTS = (
    ("build", "tsc -b --pretty false && vite build"),
    ("dev", "vite --host 127.0.0.1"),
    ("test", "vitest run --config vitest.config.ts"),
    ("test:e2e", "playwright test --config playwright.config.ts"),
    ("typecheck", "tsc -b --pretty false"),
)
MANDATORY_LOCK_ANCHORS = (
    ("@azure/msal-common", "16.12.0"),
    ("playwright", "1.62.1"),
    ("playwright-core", "1.62.1"),
)
AUTO_LIFECYCLE_HOOK_NAMES = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "publish",
    "postpublish",
    "dependencies",
)

NPMRC_POLICY_LINES = (
    "audit=false",
    "engine-strict=true",
    "fetch-retries=0",
    "fund=false",
    "ignore-scripts=true",
    "lockfile-version=3",
    "package-lock=true",
    "prefer-offline=false",
    "registry=https://registry.npmjs.org/",
    "save-exact=true",
    "strict-peer-deps=true",
    "strict-ssl=true",
    "update-notifier=false",
)

LOCK_GENERATION_ARGV = (
    "install",
    "--package-lock-only",
    "--ignore-scripts",
    "--audit=false",
    "--fund=false",
    "--prefer-offline=false",
    "--save-exact",
    "--engine-strict=true",
    "--strict-peer-deps=true",
    "--fetch-retries=0",
    "--workspaces=false",
)
SCRUBBED_ENVIRONMENT_NAMES = (
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NODE_AUTH_TOKEN",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NO_PROXY",
    "NPM_CONFIG__AUTH",
    "NPM_CONFIG__AUTHTOKEN",
    "NPM_CONFIG_EMAIL",
    "NPM_CONFIG_GLOBALCONFIG",
    "NPM_CONFIG_HTTPS_PROXY",
    "NPM_CONFIG_PASSWORD",
    "NPM_CONFIG_PROXY",
    "NPM_CONFIG_REGISTRY",
    "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_USERNAME",
    "NPM_TOKEN",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "npm_config__auth",
    "npm_config__authtoken",
    "npm_config_email",
    "npm_config_globalconfig",
    "npm_config_https_proxy",
    "npm_config_password",
    "npm_config_proxy",
    "npm_config_registry",
    "npm_config_userconfig",
    "npm_config_username",
)
SCRUBBED_ENVIRONMENT_PREFIXES = ("NPM_CONFIG_", "npm_config_")

INITIAL_SCAFFOLD_PATH_ALLOWLIST = (
    "frontend/.gitignore",
    "frontend/.npmrc",
    "frontend/index.html",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/playwright.config.ts",
    "frontend/tsconfig.json",
    "frontend/tsconfig.app.json",
    "frontend/tsconfig.node.json",
    "frontend/vite.config.ts",
    "frontend/vitest.config.ts",
    "frontend/public/runtime-config.template.json",
    "frontend/src/vite-env.d.ts",
    "frontend/src/main.tsx",
    "frontend/src/App.tsx",
    "frontend/src/App.module.css",
    "frontend/src/auth/createMsalClient.ts",
    "frontend/src/auth/createMsalClient.test.ts",
    "frontend/src/auth/zeroRetryNetworkClient.mjs",
    "frontend/src/auth/zeroRetryNetworkClient.d.ts",
    "frontend/src/config/runtimeConfig.ts",
    "frontend/src/config/runtimeConfig.test.ts",
    "frontend/src/routing/router.tsx",
    "frontend/src/routing/router.test.tsx",
    "frontend/src/pages/HomePage.tsx",
    "frontend/src/pages/NotFoundPage.tsx",
    "frontend/src/styles/global.css",
    "frontend/src/styles/tokens.css",
    "frontend/src/test/setup.ts",
    "frontend/src/test/App.test.tsx",
    "frontend/e2e/accessibility.spec.ts",
    "frontend/e2e/deep-link.spec.ts",
    "frontend/e2e/smoke.spec.ts",
)
SELECTED_EXACT_SCAFFOLD_BYTE_PATHS = (NPMRC_PATH, PACKAGE_MANIFEST_PATH)

DEFERRED_GATES = (
    "exact_node_24_19_0_platform_artifact_checksum_and_signature_proof",
    "verified_absolute_node_binary_and_npm_11_17_0_cli_entrypoint_binding",
    "just_in_time_collision_casefold_symlink_reparse_and_race_recheck",
    "controlled_isolated_lifecycle_disabled_lock_generation_execution",
    "exact_lock_generation_request_response_candidate_graph_and_file_size_bounds_selection",
    "generated_lock_v3_complete_graph_and_exact_root_map_validation",
    "complete_tree_advisory_license_deprecation_lifecycle_and_native_platform_audit",
    "complete_tree_resolved_url_sri_signature_and_provenance_disposition",
    "downloaded_tarball_byte_sri_verification_before_dependency_install",
    "remaining_31_initial_scaffold_file_bytes_selection_and_materialization",
    "runtime_configuration_schema_path_headers_byte_limit_and_value_selection",
    "static_bundle_import_graph_secret_absence_and_browser_journey_proof",
)

MAX_DOCUMENT_BYTES = 65_536
PACKAGE_MANIFEST_FILE_BYTES_SHA256 = (
    "ae3f112bccee82debfda8de49e50446e6505217200c7177c6dc8d145049e1704"
)
NPMRC_FILE_BYTES_SHA256 = (
    "bd51c414eeb9453a451af9c7b48389b7baf20f95919eaf69e8059c7c8cdbc334"
)
CANONICAL_RECEIPT_SHA256 = (
    "9e6e30b63e78b3660ae289752d26241b9890d4ec04e4254023b817b6f9cbb5c7"
)


class EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError(
    ValueError
):
    """Sanitized Step 237 offline readiness failure."""


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
        b"Engineer4Me-Step237-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


def _package_manifest_plan() -> dict[str, object]:
    return {
        "name": "engineer4me-frontend",
        "version": "0.0.0",
        "private": True,
        "type": "module",
        "packageManager": f"npm@{NPM_VERSION}",
        "engines": {"node": NODE_VERSION, "npm": NPM_VERSION},
        "scripts": dict(MANUAL_SCRIPTS),
        "dependencies": dict(PRODUCTION_DEPENDENCIES),
        "devDependencies": dict(DEVELOPMENT_DEPENDENCIES),
    }


def render_planned_frontend_package_manifest_bytes() -> bytes:
    """Return the selected in-memory package.json plan; perform no write."""

    rendered = _canonical(_package_manifest_plan()) + b"\n"
    if (
        len(rendered) != 915
        or hashlib.sha256(rendered).hexdigest()
        != PACKAGE_MANIFEST_FILE_BYTES_SHA256
    ):
        raise ValueError("planned frontend package-manifest identity is invalid")
    return rendered


def render_planned_frontend_npmrc_bytes() -> bytes:
    """Return the selected in-memory .npmrc policy plan; perform no write."""

    rendered = ("\n".join(NPMRC_POLICY_LINES) + "\n").encode("ascii")
    if (
        len(rendered) != 249
        or hashlib.sha256(rendered).hexdigest() != NPMRC_FILE_BYTES_SHA256
    ):
        raise ValueError("planned frontend npm policy identity is invalid")
    return rendered


def _step235_chain() -> dict[str, str]:
    return {
        "accepted_state_manifest_sha256": STEP235_ACCEPTED_STATE_MANIFEST_SHA256,
        "architecture_plan_sha256": STEP235_ARCHITECTURE_PLAN_SHA256,
        "architecture_selection_readiness_sha256": (
            STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256
        ),
        "architecture_selection_test_sha256": (
            STEP235_ARCHITECTURE_SELECTION_TEST_SHA256
        ),
        "canonical_receipt_sha256": STEP235_CANONICAL_RECEIPT_SHA256,
        "deferred_gate_plan_sha256": STEP235_DEFERRED_GATE_PLAN_SHA256,
        "experience_and_test_plan_sha256": (
            STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256
        ),
        "package_manifest_sha256": STEP235_PACKAGE_MANIFEST_SHA256,
        "readiness_document_sha256": STEP235_READINESS_DOCUMENT_SHA256,
        "security_plan_sha256": STEP235_SECURITY_PLAN_SHA256,
    }


def _step236_receipt_binding() -> dict[str, object]:
    return {
        "bundled_npm_version": NPM_VERSION,
        "counts": dict(STEP236_RECEIPT_COUNTS),
        "node_lts_codename": NODE_LTS_CODENAME,
        "node_version": NODE_VERSION,
        "projections": dict(STEP236_RECEIPT_PROJECTION_SHA256),
        "readiness_status": STEP236_STATUS,
        "selection_profile": STEP236_SELECTION_PROFILE,
    }


def _mandatory_lock_anchor_plan() -> list[dict[str, str]]:
    return [
        {
            "disposition": "future_lock_assertion_not_root_direct_dependency",
            "name": name,
            "version": version,
        }
        for name, version in MANDATORY_LOCK_ANCHORS
    ]


def _lock_generation_plan() -> dict[str, object]:
    return {
        "authorization": "blocked",
        "automatic_application_retry_count": 0,
        "argv_after_verified_absolute_entrypoints": list(LOCK_GENERATION_ARGV),
        "bounds": {
            "execution_deadline_seconds": 300,
            "stderr_bytes": 1_048_576,
            "stdout_bytes": 1_048_576,
        },
        "environment": {
            "inheritance": "deny_by_default_minimal_successor_allowlist",
            "scrubbed_exact_names": list(SCRUBBED_ENVIRONMENT_NAMES),
            "scrubbed_prefixes": list(SCRUBBED_ENVIRONMENT_PREFIXES),
            "successor_assignments": {
                "CI": "true",
                "NPM_CONFIG_CACHE": "fresh_out_of_repository_temporary_cache",
                "NPM_CONFIG_GLOBALCONFIG": "sealed_empty_out_of_repository_file",
                "NPM_CONFIG_USERCONFIG": "sealed_exact_step237_npmrc_copy",
            },
        },
        "execution_monitor_required": True,
        "fresh_cache_directory": "required_outside_repository",
        "fresh_working_directory": "required_outside_repository",
        "global_configuration": "sealed_empty",
        "input_file_sha256": {
            ".npmrc": NPMRC_FILE_BYTES_SHA256,
            "package.json": PACKAGE_MANIFEST_FILE_BYTES_SHA256,
        },
        "network_egress": {
            "credentials": "forbidden",
            "host": "registry.npmjs.org",
            "origin": "https://registry.npmjs.org/",
            "proxy": "forbidden",
            "redirect": "forbidden",
            "scope": "official_registry_only",
        },
        "node_executable": {
            "absolute_path": "unselected",
            "future_exact_platform_artifact_proof_required": True,
            "version": NODE_VERSION,
        },
        "npm_cli_entrypoint": {
            "absolute_path": "unselected",
            "future_exact_entrypoint_hash_proof_required": True,
            "version": NPM_VERSION,
        },
        "success_contract": {
            "additional_scaffold_paths_created": 0,
            "complete_transitive_graph_required": True,
            "exit_code": 0,
            "lockfile_version": LOCKFILE_VERSION,
            "node_modules_created": False,
            "root_dependency_maps_exact": True,
            "root_optional_dependencies_absent": True,
            "transitive_optional_and_platform_entries": (
                "allowed_only_with_later_exact_os_cpu_libc_native_and_lifecycle_audit"
            ),
        },
        "unselected_successor_bounds": [
            "maximum_aggregate_response_bytes",
            "maximum_candidate_package_count",
            "maximum_dependency_graph_node_count",
            "maximum_generated_lockfile_bytes",
            "maximum_individual_response_bytes",
            "maximum_network_request_count",
        ],
        "unsupported_source_schemes": [
            "file:",
            "git:",
            "git+",
            "http:",
            "link:",
            "workspace:",
        ],
        "user_configuration": "sealed_exact_step237_npmrc",
    }


def _document_projection() -> dict[str, object]:
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "readiness_status": STATUS,
        "approved_step236_v1_package_manifest_sha256": (
            STEP236_V1_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step236_v2_package_manifest_sha256": (
            STEP236_V2_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step236_final_accepted_state_manifest_sha256": (
            STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step236_ecosystem_compatibility_probe_sha256": (
            STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256
        ),
        "approved_step236_ecosystem_registry_http_loader_sha256": (
            STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256
        ),
        "approved_step236_ecosystem_compatibility_probe_test_sha256": (
            STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256
        ),
        "approved_step236_ecosystem_registry_http_loader_test_sha256": (
            STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256
        ),
        "approved_step236_canonical_live_receipt_sha256": (
            STEP236_CANONICAL_LIVE_RECEIPT_SHA256
        ),
        "step236_receipt_binding": _step236_receipt_binding(),
        "step235_transitive_chain": _step235_chain(),
        "package_manifest_plan": _package_manifest_plan(),
        "package_manifest_bytes_sha256": PACKAGE_MANIFEST_FILE_BYTES_SHA256,
        "npmrc_policy_lines": list(NPMRC_POLICY_LINES),
        "npmrc_bytes_sha256": NPMRC_FILE_BYTES_SHA256,
        "mandatory_lock_anchor_assertions": _mandatory_lock_anchor_plan(),
        "lock_generation_plan": _lock_generation_plan(),
        "initial_scaffold_path_allowlist": list(INITIAL_SCAFFOLD_PATH_ALLOWLIST),
        "selected_exact_scaffold_byte_paths": list(
            SELECTED_EXACT_SCAFFOLD_BYTE_PATHS
        ),
        "excluded_runtime_config_path": EXCLUDED_RUNTIME_CONFIG_PATH,
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


class EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_package_manifest_lock_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_offline_frontend_package_manifest_lock_readiness"
    ]
    readiness_status: Literal[
        "exact_frontend_package_manifest_and_controlled_lock_generation_plan_validated_execution_and_materialization_remain_blocked"
    ]
    approved_step236_v1_package_manifest_sha256: str
    approved_step236_v2_package_manifest_sha256: str
    approved_step236_final_accepted_state_manifest_sha256: str
    approved_step236_ecosystem_compatibility_probe_sha256: str
    approved_step236_ecosystem_registry_http_loader_sha256: str
    approved_step236_ecosystem_compatibility_probe_test_sha256: str
    approved_step236_ecosystem_registry_http_loader_test_sha256: str
    approved_step236_canonical_live_receipt_sha256: str
    step236_receipt_binding: dict[str, Any]
    step235_transitive_chain: dict[str, str]
    package_manifest_plan: dict[str, Any]
    package_manifest_bytes_sha256: str
    npmrc_policy_lines: list[str]
    npmrc_bytes_sha256: str
    mandatory_lock_anchor_assertions: list[dict[str, str]]
    lock_generation_plan: dict[str, Any]
    initial_scaffold_path_allowlist: list[str]
    selected_exact_scaffold_byte_paths: list[str]
    excluded_runtime_config_path: str
    deferred_gates: list[str]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        _assert_exact_tree(value, _document_projection())
        return value

    @model_validator(mode="after")
    def validate_identity_fields(
        self,
    ) -> EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument:
        digest_fields = (
            self.approved_step236_v1_package_manifest_sha256,
            self.approved_step236_v2_package_manifest_sha256,
            self.approved_step236_final_accepted_state_manifest_sha256,
            self.approved_step236_ecosystem_compatibility_probe_sha256,
            self.approved_step236_ecosystem_registry_http_loader_sha256,
            self.approved_step236_ecosystem_compatibility_probe_test_sha256,
            self.approved_step236_ecosystem_registry_http_loader_test_sha256,
            self.approved_step236_canonical_live_receipt_sha256,
            self.package_manifest_bytes_sha256,
            self.npmrc_bytes_sha256,
            *self.step235_transitive_chain.values(),
            *self.step236_receipt_binding["projections"].values(),
        )
        if any(not _is_sha256(value) for value in digest_fields):
            raise ValueError("readiness document SHA-256 identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    approved_step236_v1_package_manifest_sha256: str
    approved_step236_v2_package_manifest_sha256: str
    approved_step236_final_accepted_state_manifest_sha256: str
    approved_step236_ecosystem_compatibility_probe_sha256: str
    approved_step236_ecosystem_registry_http_loader_sha256: str
    approved_step236_ecosystem_compatibility_probe_test_sha256: str
    approved_step236_ecosystem_registry_http_loader_test_sha256: str
    approved_step236_canonical_live_receipt_sha256: str
    approved_step236_selection_profile: str
    approved_step236_status: str
    node_version: str
    bundled_npm_version: str
    node_lts_codename: str
    package_manager: str
    package_manifest_path: str
    npmrc_path: str
    lockfile_path: str
    excluded_runtime_config_path: str
    lockfile_version: int
    production_dependency_count: int
    development_dependency_count: int
    manifest_direct_package_count: int
    mandatory_lock_anchor_count: int
    manual_script_count: int
    automatic_lifecycle_hook_count: int
    initial_scaffold_path_count: int
    selected_exact_scaffold_byte_count: int
    unselected_scaffold_byte_count: int
    package_manifest_file_bytes: int
    npmrc_file_bytes: int
    deferred_gate_count: int
    step236_receipt_binding_sha256: str
    step235_transitive_chain_sha256: str
    package_manifest_plan_sha256: str
    package_manifest_file_bytes_sha256: str
    npmrc_policy_plan_sha256: str
    npmrc_file_bytes_sha256: str
    mandatory_lock_anchor_plan_sha256: str
    lock_generation_plan_sha256: str
    initial_scaffold_allowlist_sha256: str
    deferred_gate_plan_sha256: str
    readiness_document_sha256: str
    exact_step236_v1_package_manifest_bound: bool
    exact_step236_v2_package_manifest_bound: bool
    exact_step236_final_state_bound: bool
    exact_step236_final_four_payloads_bound: bool
    exact_step236_canonical_live_receipt_bound: bool
    exact_step236_projection_counts_status_and_tuple_bound: bool
    exact_step235_chain_transitively_bound: bool
    step236_selected_metadata_not_claimed_as_complete_tree_closure: bool
    package_manifest_exact_logical_object_selected: bool
    package_manifest_exact_lf_bytes_selected: bool
    npmrc_exact_lf_bytes_selected: bool
    package_private_and_esm_required: bool
    node_and_npm_exact_versions_planned: bool
    npm_is_sole_package_manager: bool
    production_dependencies_exact: bool
    development_dependencies_exact: bool
    dependency_versions_have_no_ranges: bool
    mandatory_anchors_are_lock_assertions_not_root_dependencies: bool
    npm_toolchain_is_not_a_dependency: bool
    manual_scripts_present: bool
    automatic_lifecycle_hooks_absent: bool
    ignore_scripts_required_for_future_resolution: bool
    strict_peer_dependencies_required: bool
    configured_application_fetch_retries_zero: bool
    external_execution_monitor_required: bool
    package_lock_v3_required: bool
    exact_root_dependency_maps_required: bool
    transitive_optional_platform_entries_require_later_audit: bool
    final_initial_scaffold_path_allowlist_selected: bool
    selected_paths_ascii_case_sensitive_and_slash_canonical: bool
    parent_directories_implicit_and_not_counted: bool
    actual_runtime_config_path_excluded: bool
    runtime_config_template_must_be_non_operational: bool
    zero_retry_network_client_exact_future_copy_required: bool
    collision_reparse_casefold_and_race_recheck_required_just_in_time: bool
    verified_absolute_node_and_npm_entrypoints_required: bool
    node_platform_artifact_proof_required_before_execution: bool
    full_tree_closure_required_before_install_or_materialization: bool
    request_response_candidate_graph_and_file_size_bounds_deferred: bool
    step237_external_request_performed: bool
    node_platform_artifact_selected: bool
    node_binary_downloaded_or_signature_verified: bool
    node_or_npm_executed: bool
    package_manager_executed: bool
    lock_generation_authorized: bool
    package_manifest_created_or_modified: bool
    npmrc_created_or_modified: bool
    lockfile_created_or_modified: bool
    complete_transitive_dependency_graph_resolved: bool
    complete_tree_advisory_audit_completed: bool
    complete_tree_license_deprecation_audit_completed: bool
    complete_tree_lifecycle_native_platform_audit_completed: bool
    complete_tree_signature_provenance_disposition_completed: bool
    package_tarball_downloaded_or_byte_sri_verified: bool
    dependency_installed: bool
    node_modules_created: bool
    lifecycle_script_executed: bool
    manual_script_executed: bool
    all_scaffold_file_bytes_selected: bool
    lockfile_bytes_selected: bool
    remaining_scaffold_file_bytes_selected: bool
    frontend_root_created: bool
    scaffold_file_written: bool
    scaffold_materialization_authorized: bool
    browser_bundle_built: bool
    frontend_test_or_browser_runtime_executed: bool
    browser_oauth_graph_entra_or_application_endpoint_requested: bool
    application_configuration_modified: bool
    application_activated: bool
    operational_write_performed: bool
    docker_restarted_or_rebuilt: bool
    git_stage_commit_or_push_performed: bool
    all_lock_execution_bounds_selected: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "approved_step236_v1_package_manifest_sha256": STEP236_V1_PACKAGE_MANIFEST_SHA256,
            "approved_step236_v2_package_manifest_sha256": STEP236_V2_PACKAGE_MANIFEST_SHA256,
            "approved_step236_final_accepted_state_manifest_sha256": STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
            "approved_step236_ecosystem_compatibility_probe_sha256": STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256,
            "approved_step236_ecosystem_registry_http_loader_sha256": STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256,
            "approved_step236_ecosystem_compatibility_probe_test_sha256": STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256,
            "approved_step236_ecosystem_registry_http_loader_test_sha256": STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256,
            "approved_step236_canonical_live_receipt_sha256": STEP236_CANONICAL_LIVE_RECEIPT_SHA256,
            "approved_step236_selection_profile": STEP236_SELECTION_PROFILE,
            "approved_step236_status": STEP236_STATUS,
            "node_version": NODE_VERSION,
            "bundled_npm_version": NPM_VERSION,
            "node_lts_codename": NODE_LTS_CODENAME,
            "package_manager": PACKAGE_MANAGER,
            "package_manifest_path": PACKAGE_MANIFEST_PATH,
            "npmrc_path": NPMRC_PATH,
            "lockfile_path": LOCKFILE_PATH,
            "excluded_runtime_config_path": EXCLUDED_RUNTIME_CONFIG_PATH,
            "lockfile_version": LOCKFILE_VERSION,
            "production_dependency_count": len(PRODUCTION_DEPENDENCIES),
            "development_dependency_count": len(DEVELOPMENT_DEPENDENCIES),
            "manifest_direct_package_count": len(PRODUCTION_DEPENDENCIES) + len(DEVELOPMENT_DEPENDENCIES),
            "mandatory_lock_anchor_count": len(MANDATORY_LOCK_ANCHORS),
            "manual_script_count": len(MANUAL_SCRIPTS),
            "automatic_lifecycle_hook_count": 0,
            "initial_scaffold_path_count": len(INITIAL_SCAFFOLD_PATH_ALLOWLIST),
            "selected_exact_scaffold_byte_count": len(SELECTED_EXACT_SCAFFOLD_BYTE_PATHS),
            "unselected_scaffold_byte_count": len(INITIAL_SCAFFOLD_PATH_ALLOWLIST) - len(SELECTED_EXACT_SCAFFOLD_BYTE_PATHS),
            "package_manifest_file_bytes": 915,
            "npmrc_file_bytes": 249,
            "deferred_gate_count": len(DEFERRED_GATES),
            "step236_receipt_binding_sha256": _framed("step236-receipt-binding", _step236_receipt_binding()),
            "step235_transitive_chain_sha256": _framed("step235-transitive-chain", _step235_chain()),
            "package_manifest_plan_sha256": _framed("package-manifest-plan", _package_manifest_plan()),
            "package_manifest_file_bytes_sha256": PACKAGE_MANIFEST_FILE_BYTES_SHA256,
            "npmrc_policy_plan_sha256": _framed("npmrc-policy", NPMRC_POLICY_LINES),
            "npmrc_file_bytes_sha256": NPMRC_FILE_BYTES_SHA256,
            "mandatory_lock_anchor_plan_sha256": _framed("mandatory-lock-anchors", _mandatory_lock_anchor_plan()),
            "lock_generation_plan_sha256": _framed("lock-generation-plan", _lock_generation_plan()),
            "initial_scaffold_allowlist_sha256": _framed("initial-scaffold-allowlist", INITIAL_SCAFFOLD_PATH_ALLOWLIST),
            "deferred_gate_plan_sha256": _framed("deferred-gates", DEFERRED_GATES),
            "readiness_document_sha256": hashlib.sha256(_canonical(_document_projection())).hexdigest(),
        }
        required_true = {
            "exact_step236_v1_package_manifest_bound",
            "exact_step236_v2_package_manifest_bound",
            "exact_step236_final_state_bound",
            "exact_step236_final_four_payloads_bound",
            "exact_step236_canonical_live_receipt_bound",
            "exact_step236_projection_counts_status_and_tuple_bound",
            "exact_step235_chain_transitively_bound",
            "step236_selected_metadata_not_claimed_as_complete_tree_closure",
            "package_manifest_exact_logical_object_selected",
            "package_manifest_exact_lf_bytes_selected",
            "npmrc_exact_lf_bytes_selected",
            "package_private_and_esm_required",
            "node_and_npm_exact_versions_planned",
            "npm_is_sole_package_manager",
            "production_dependencies_exact",
            "development_dependencies_exact",
            "dependency_versions_have_no_ranges",
            "mandatory_anchors_are_lock_assertions_not_root_dependencies",
            "npm_toolchain_is_not_a_dependency",
            "manual_scripts_present",
            "automatic_lifecycle_hooks_absent",
            "ignore_scripts_required_for_future_resolution",
            "strict_peer_dependencies_required",
            "configured_application_fetch_retries_zero",
            "external_execution_monitor_required",
            "package_lock_v3_required",
            "exact_root_dependency_maps_required",
            "transitive_optional_platform_entries_require_later_audit",
            "final_initial_scaffold_path_allowlist_selected",
            "selected_paths_ascii_case_sensitive_and_slash_canonical",
            "parent_directories_implicit_and_not_counted",
            "actual_runtime_config_path_excluded",
            "runtime_config_template_must_be_non_operational",
            "zero_retry_network_client_exact_future_copy_required",
            "collision_reparse_casefold_and_race_recheck_required_just_in_time",
            "verified_absolute_node_and_npm_entrypoints_required",
            "node_platform_artifact_proof_required_before_execution",
            "full_tree_closure_required_before_install_or_materialization",
            "request_response_candidate_graph_and_file_size_bounds_deferred",
        }
        required_false = {
            "step237_external_request_performed",
            "node_platform_artifact_selected",
            "node_binary_downloaded_or_signature_verified",
            "node_or_npm_executed",
            "package_manager_executed",
            "lock_generation_authorized",
            "package_manifest_created_or_modified",
            "npmrc_created_or_modified",
            "lockfile_created_or_modified",
            "complete_transitive_dependency_graph_resolved",
            "complete_tree_advisory_audit_completed",
            "complete_tree_license_deprecation_audit_completed",
            "complete_tree_lifecycle_native_platform_audit_completed",
            "complete_tree_signature_provenance_disposition_completed",
            "package_tarball_downloaded_or_byte_sri_verified",
            "dependency_installed",
            "node_modules_created",
            "lifecycle_script_executed",
            "manual_script_executed",
            "all_scaffold_file_bytes_selected",
            "lockfile_bytes_selected",
            "remaining_scaffold_file_bytes_selected",
            "frontend_root_created",
            "scaffold_file_written",
            "scaffold_materialization_authorized",
            "browser_bundle_built",
            "frontend_test_or_browser_runtime_executed",
            "browser_oauth_graph_entra_or_application_endpoint_requested",
            "application_configuration_modified",
            "application_activated",
            "operational_write_performed",
            "docker_restarted_or_rebuilt",
            "git_stage_commit_or_push_performed",
            "all_lock_execution_bounds_selected",
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
        if any(type(getattr(self, name)) is not bool or not getattr(self, name) for name in required_true):
            raise ValueError("readiness receipt required control is invalid")
        if any(type(getattr(self, name)) is not bool or getattr(self, name) for name in required_false):
            raise ValueError("readiness receipt forbidden outcome is invalid")
        if any(
            name.endswith("sha256") and not _is_sha256(getattr(self, name))
            for name in constants
        ):
            raise ValueError("readiness receipt SHA-256 identity is invalid")


def render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document() -> bytes:
    """Render the one exact offline input document in memory."""

    return _canonical(_document_projection())


def load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(
    document: bytes,
) -> EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt:
    """Validate the exact offline plan and return its non-authorizing receipt."""

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
        model = EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument.model_validate(
            parsed
        )
        if _canonical(model.model_dump(mode="json")) != canonical_document:
            raise ValueError("validated readiness document is not canonical")
        receipt = EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            approved_step236_v1_package_manifest_sha256=STEP236_V1_PACKAGE_MANIFEST_SHA256,
            approved_step236_v2_package_manifest_sha256=STEP236_V2_PACKAGE_MANIFEST_SHA256,
            approved_step236_final_accepted_state_manifest_sha256=STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
            approved_step236_ecosystem_compatibility_probe_sha256=STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256,
            approved_step236_ecosystem_registry_http_loader_sha256=STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256,
            approved_step236_ecosystem_compatibility_probe_test_sha256=STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256,
            approved_step236_ecosystem_registry_http_loader_test_sha256=STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256,
            approved_step236_canonical_live_receipt_sha256=STEP236_CANONICAL_LIVE_RECEIPT_SHA256,
            approved_step236_selection_profile=STEP236_SELECTION_PROFILE,
            approved_step236_status=STEP236_STATUS,
            node_version=NODE_VERSION,
            bundled_npm_version=NPM_VERSION,
            node_lts_codename=NODE_LTS_CODENAME,
            package_manager=PACKAGE_MANAGER,
            package_manifest_path=PACKAGE_MANIFEST_PATH,
            npmrc_path=NPMRC_PATH,
            lockfile_path=LOCKFILE_PATH,
            excluded_runtime_config_path=EXCLUDED_RUNTIME_CONFIG_PATH,
            lockfile_version=LOCKFILE_VERSION,
            production_dependency_count=len(PRODUCTION_DEPENDENCIES),
            development_dependency_count=len(DEVELOPMENT_DEPENDENCIES),
            manifest_direct_package_count=len(PRODUCTION_DEPENDENCIES) + len(DEVELOPMENT_DEPENDENCIES),
            mandatory_lock_anchor_count=len(MANDATORY_LOCK_ANCHORS),
            manual_script_count=len(MANUAL_SCRIPTS),
            automatic_lifecycle_hook_count=0,
            initial_scaffold_path_count=len(INITIAL_SCAFFOLD_PATH_ALLOWLIST),
            selected_exact_scaffold_byte_count=len(SELECTED_EXACT_SCAFFOLD_BYTE_PATHS),
            unselected_scaffold_byte_count=len(INITIAL_SCAFFOLD_PATH_ALLOWLIST) - len(SELECTED_EXACT_SCAFFOLD_BYTE_PATHS),
            package_manifest_file_bytes=915,
            npmrc_file_bytes=249,
            deferred_gate_count=len(DEFERRED_GATES),
            step236_receipt_binding_sha256=_framed("step236-receipt-binding", _step236_receipt_binding()),
            step235_transitive_chain_sha256=_framed("step235-transitive-chain", _step235_chain()),
            package_manifest_plan_sha256=_framed("package-manifest-plan", _package_manifest_plan()),
            package_manifest_file_bytes_sha256=PACKAGE_MANIFEST_FILE_BYTES_SHA256,
            npmrc_policy_plan_sha256=_framed("npmrc-policy", NPMRC_POLICY_LINES),
            npmrc_file_bytes_sha256=NPMRC_FILE_BYTES_SHA256,
            mandatory_lock_anchor_plan_sha256=_framed("mandatory-lock-anchors", _mandatory_lock_anchor_plan()),
            lock_generation_plan_sha256=_framed("lock-generation-plan", _lock_generation_plan()),
            initial_scaffold_allowlist_sha256=_framed("initial-scaffold-allowlist", INITIAL_SCAFFOLD_PATH_ALLOWLIST),
            deferred_gate_plan_sha256=_framed("deferred-gates", DEFERRED_GATES),
            readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            **{name: True for name in (
                "exact_step236_v1_package_manifest_bound", "exact_step236_v2_package_manifest_bound",
                "exact_step236_final_state_bound", "exact_step236_final_four_payloads_bound",
                "exact_step236_canonical_live_receipt_bound", "exact_step236_projection_counts_status_and_tuple_bound",
                "exact_step235_chain_transitively_bound", "step236_selected_metadata_not_claimed_as_complete_tree_closure",
                "package_manifest_exact_logical_object_selected", "package_manifest_exact_lf_bytes_selected",
                "npmrc_exact_lf_bytes_selected", "package_private_and_esm_required", "node_and_npm_exact_versions_planned",
                "npm_is_sole_package_manager", "production_dependencies_exact", "development_dependencies_exact",
                "dependency_versions_have_no_ranges", "mandatory_anchors_are_lock_assertions_not_root_dependencies",
                "npm_toolchain_is_not_a_dependency", "manual_scripts_present", "automatic_lifecycle_hooks_absent",
                "ignore_scripts_required_for_future_resolution", "strict_peer_dependencies_required",
                "configured_application_fetch_retries_zero", "external_execution_monitor_required",
                "package_lock_v3_required", "exact_root_dependency_maps_required",
                "transitive_optional_platform_entries_require_later_audit", "final_initial_scaffold_path_allowlist_selected",
                "selected_paths_ascii_case_sensitive_and_slash_canonical", "parent_directories_implicit_and_not_counted",
                "actual_runtime_config_path_excluded", "runtime_config_template_must_be_non_operational",
                "zero_retry_network_client_exact_future_copy_required", "collision_reparse_casefold_and_race_recheck_required_just_in_time",
                "verified_absolute_node_and_npm_entrypoints_required", "node_platform_artifact_proof_required_before_execution",
                "full_tree_closure_required_before_install_or_materialization",
                "request_response_candidate_graph_and_file_size_bounds_deferred",
            )},
            **{name: False for name in (
                "step237_external_request_performed", "node_platform_artifact_selected",
                "node_binary_downloaded_or_signature_verified", "node_or_npm_executed", "package_manager_executed",
                "lock_generation_authorized", "package_manifest_created_or_modified", "npmrc_created_or_modified",
                "lockfile_created_or_modified", "complete_transitive_dependency_graph_resolved",
                "complete_tree_advisory_audit_completed", "complete_tree_license_deprecation_audit_completed",
                "complete_tree_lifecycle_native_platform_audit_completed", "complete_tree_signature_provenance_disposition_completed",
                "package_tarball_downloaded_or_byte_sri_verified", "dependency_installed", "node_modules_created",
                "lifecycle_script_executed", "manual_script_executed", "all_scaffold_file_bytes_selected",
                "lockfile_bytes_selected", "remaining_scaffold_file_bytes_selected", "frontend_root_created",
                "scaffold_file_written", "scaffold_materialization_authorized", "browser_bundle_built",
                "frontend_test_or_browser_runtime_executed", "browser_oauth_graph_entra_or_application_endpoint_requested",
                "application_configuration_modified", "application_activated", "operational_write_performed",
                "docker_restarted_or_rebuilt", "git_stage_commit_or_push_performed",
                "all_lock_execution_bounds_selected",
            )},
        )
        receipt.__post_init__()
        return receipt
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError(
            "frontend-host package-manifest and lock readiness validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt(
    receipt: EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt,
) -> bytes:
    """Render only the exact validated Step 237 receipt as canonical JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt:
        raise TypeError("exact frontend-host package-manifest lock receipt is required")
    receipt.__post_init__()
    rendered = _canonical(
        {field.name: getattr(receipt, field.name) for field in dataclasses.fields(receipt)}
    )
    if hashlib.sha256(rendered).hexdigest() != CANONICAL_RECEIPT_SHA256:
        raise ValueError("package-manifest lock readiness receipt identity is invalid")
    return rendered


__all__ = [
    "AUTO_LIFECYCLE_HOOK_NAMES",
    "CANONICAL_RECEIPT_SHA256",
    "DEFERRED_GATES",
    "DEVELOPMENT_DEPENDENCIES",
    "DOCUMENT_TYPE",
    "EXCLUDED_RUNTIME_CONFIG_PATH",
    "INITIAL_SCAFFOLD_PATH_ALLOWLIST",
    "LOCKFILE_PATH",
    "LOCKFILE_VERSION",
    "LOCK_GENERATION_ARGV",
    "MANDATORY_LOCK_ANCHORS",
    "MANUAL_SCRIPTS",
    "MAX_DOCUMENT_BYTES",
    "NODE_LTS_CODENAME",
    "NODE_VERSION",
    "NPMRC_FILE_BYTES_SHA256",
    "NPMRC_PATH",
    "NPMRC_POLICY_LINES",
    "NPM_VERSION",
    "PACKAGE_MANIFEST_FILE_BYTES_SHA256",
    "PACKAGE_MANIFEST_PATH",
    "PRODUCTION_DEPENDENCIES",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SELECTED_EXACT_SCAFFOLD_BYTE_PATHS",
    "SOURCE",
    "STATUS",
    "STEP236_CANONICAL_LIVE_RECEIPT_SHA256",
    "STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256",
    "STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256",
    "STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256",
    "STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256",
    "STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP236_RECEIPT_COUNTS",
    "STEP236_RECEIPT_PROJECTION_SHA256",
    "STEP236_SELECTION_PROFILE",
    "STEP236_STATUS",
    "STEP236_V1_PACKAGE_MANIFEST_SHA256",
    "STEP236_V2_PACKAGE_MANIFEST_SHA256",
    "ZERO_RETRY_NETWORK_CLIENT_SHA256",
    "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument",
    "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError",
    "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt",
    "load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness",
    "render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document",
    "render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt",
    "render_planned_frontend_npmrc_bytes",
    "render_planned_frontend_package_manifest_bytes",
]
