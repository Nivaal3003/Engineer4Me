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

import pytest

import app.security.authentication_entra_calling_client_msal_browser_frontend_host_package_manifest_lock_readiness as readiness
from app.security.authentication_entra_calling_client_msal_browser_frontend_host_package_manifest_lock_readiness import (
    AUTO_LIFECYCLE_HOOK_NAMES,
    CANONICAL_RECEIPT_SHA256,
    DEFERRED_GATES,
    DEVELOPMENT_DEPENDENCIES,
    DOCUMENT_TYPE,
    EXCLUDED_RUNTIME_CONFIG_PATH,
    INITIAL_SCAFFOLD_PATH_ALLOWLIST,
    LOCKFILE_PATH,
    LOCKFILE_VERSION,
    LOCK_GENERATION_ARGV,
    MANDATORY_LOCK_ANCHORS,
    MANUAL_SCRIPTS,
    MAX_DOCUMENT_BYTES,
    NODE_LTS_CODENAME,
    NODE_VERSION,
    NPMRC_FILE_BYTES_SHA256,
    NPMRC_PATH,
    NPMRC_POLICY_LINES,
    NPM_VERSION,
    PACKAGE_MANIFEST_FILE_BYTES_SHA256,
    PACKAGE_MANIFEST_PATH,
    PRODUCTION_DEPENDENCIES,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    SELECTED_EXACT_SCAFFOLD_BYTE_PATHS,
    SOURCE,
    STATUS,
    STEP236_CANONICAL_LIVE_RECEIPT_SHA256,
    STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256,
    STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256,
    STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256,
    STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256,
    STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP236_RECEIPT_COUNTS,
    STEP236_RECEIPT_PROJECTION_SHA256,
    STEP236_SELECTION_PROFILE,
    STEP236_STATUS,
    STEP236_V1_PACKAGE_MANIFEST_SHA256,
    STEP236_V2_PACKAGE_MANIFEST_SHA256,
    ZERO_RETRY_NETWORK_CLIENT_SHA256,
    EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument,
    EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError,
    EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt,
    load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness,
    render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document,
    render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt,
    render_planned_frontend_npmrc_bytes,
    render_planned_frontend_package_manifest_bytes,
)


EXPECTED_PRODUCTION_DEPENDENCIES = {
    "@azure/msal-browser": "5.18.0",
    "react": "19.2.8",
    "react-dom": "19.2.8",
    "react-router": "8.3.0",
}
EXPECTED_DEVELOPMENT_DEPENDENCIES = {
    "@axe-core/playwright": "4.13.0",
    "@playwright/test": "1.62.1",
    "@testing-library/dom": "10.4.1",
    "@testing-library/jest-dom": "7.0.1",
    "@testing-library/react": "16.3.2",
    "@testing-library/user-event": "14.6.5",
    "@types/node": "24.13.3",
    "@types/react": "19.2.18",
    "@types/react-dom": "19.2.4",
    "@vitejs/plugin-react": "6.0.5",
    "axe-core": "4.13.0",
    "jsdom": "30.0.1",
    "typescript": "6.0.2",
    "vite": "8.2.1",
    "vitest": "4.1.11",
}
EXPECTED_SCRIPTS = {
    "build": "tsc -b --pretty false && vite build",
    "dev": "vite --host 127.0.0.1",
    "test": "vitest run --config vitest.config.ts",
    "test:e2e": "playwright test --config playwright.config.ts",
    "typecheck": "tsc -b --pretty false",
}
EXPECTED_ANCHORS = {
    "@azure/msal-common": "16.12.0",
    "playwright": "1.62.1",
    "playwright-core": "1.62.1",
}
EXPECTED_NPMRC = (
    b"audit=false\n"
    b"engine-strict=true\n"
    b"fetch-retries=0\n"
    b"fund=false\n"
    b"ignore-scripts=true\n"
    b"lockfile-version=3\n"
    b"package-lock=true\n"
    b"prefer-offline=false\n"
    b"registry=https://registry.npmjs.org/\n"
    b"save-exact=true\n"
    b"strict-peer-deps=true\n"
    b"strict-ssl=true\n"
    b"update-notifier=false\n"
)
EXPECTED_ALLOWLIST = (
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
EXPECTED_PLAN_DIGESTS = {
    "step236_receipt_binding_sha256": "6bda563ae1016748b7c3eb8671fd030ff643af65476ce56663a6e05f6a93fda6",
    "step235_transitive_chain_sha256": "e5febfe9b5a90976cdd181cb8e9057c3e326297681b26e79a64c70485e1fdfe8",
    "package_manifest_plan_sha256": "06ed6f8c8ce9a135732283de35ebc788b2a29f52505206c095f22e6ad5386aaa",
    "package_manifest_file_bytes_sha256": "ae3f112bccee82debfda8de49e50446e6505217200c7177c6dc8d145049e1704",
    "npmrc_policy_plan_sha256": "43c2533ff284648f969d237c00c63b88db56fa2f39e87ddd9d8cf9448bdd5743",
    "npmrc_file_bytes_sha256": "bd51c414eeb9453a451af9c7b48389b7baf20f95919eaf69e8059c7c8cdbc334",
    "mandatory_lock_anchor_plan_sha256": "f06386dd443b78c1023700554935e868f97d0101da5ed5fccc347d97e482631c",
    "lock_generation_plan_sha256": "987461a9efe9cc9a2533eee00565c9d018dbdc3119796a6988d1a9e6b22fb3db",
    "initial_scaffold_allowlist_sha256": "4405f434692da00b1db38236d0d9c2614cd20d59f92b608cbf1f08ac78066bea",
    "deferred_gate_plan_sha256": "9846db3a9fcb485b406a857d5f882ea008c05e6c3d6f9fd8d21c3d5c033134aa",
    "readiness_document_sha256": "2d62e8767230c7b58c1d3505b5e29bbefe0b43dafa1e5ca95a09a349f5fa75ee",
}


def _document_bytes() -> bytes:
    return render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document()


def _document_object() -> dict[str, object]:
    parsed = json.loads(_document_bytes())
    assert type(parsed) is dict
    return parsed


def _receipt() -> EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt:
    return load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(
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


def _replacement(value: object) -> object:
    if type(value) is str:
        return value + "-tampered"
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is list:
        return value + [copy.deepcopy(value[0])] if value else ["tampered"]
    if type(value) is dict:
        changed = copy.deepcopy(value)
        key = next(iter(changed))
        changed[key] = _replacement(changed[key])
        return changed
    raise AssertionError(f"unhandled test value: {type(value)!r}")


def _leaf_paths(value: object, prefix: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    if type(value) is dict:
        return [
            path
            for key, item in value.items()
            for path in _leaf_paths(item, prefix + (key,))
        ]
    if type(value) is list:
        return [
            path
            for index, item in enumerate(value)
            for path in _leaf_paths(item, prefix + (index,))
        ]
    return [prefix]


def _set_path(value: object, path: tuple[object, ...], replacement: object) -> None:
    target = value
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    target[path[-1]] = replacement  # type: ignore[index]


def _get_path(value: object, path: tuple[object, ...]) -> object:
    target = value
    for component in path:
        target = target[component]  # type: ignore[index]
    return target


def _wrong_type(value: object) -> object:
    if type(value) is str:
        return 1
    if type(value) is int:
        return str(value)
    if type(value) is bool:
        return 1
    if type(value) is list:
        return {"wrong": "type"}
    if type(value) is dict:
        return ["wrong", "type"]
    raise AssertionError("unsupported exact-type test value")


def _field_replacement(value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + "0"
    raise AssertionError("receipt fields must be scalar")


def test_exact_step236_and_transitive_step235_identities_are_frozen() -> None:
    assert STEP236_V1_PACKAGE_MANIFEST_SHA256 == "141d0f78416029c5813949eeb8e8e9d038d367af74e965e8b2cb7ac59f669534"
    assert STEP236_V2_PACKAGE_MANIFEST_SHA256 == "848ab0fc9c0f8089a9eb313d8d012f71b8b6e075258a47fc510937d8dffcca43"
    assert STEP236_FINAL_ACCEPTED_STATE_MANIFEST_SHA256 == "e3495b2d989ef0d1b13d52bbaf3ef7afbdd711e3004661b03fa7faa204f78e04"
    assert STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_SHA256 == "e145710941196f408c54f2ef5196480096032ad59229c8997e9d074b8fa985df"
    assert STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_SHA256 == "c2728927d0fd94ace389204518e2d8daecfc562fd7ade808465fc5d32ec938c2"
    assert STEP236_ECOSYSTEM_COMPATIBILITY_PROBE_TEST_SHA256 == "e0ee0fe928fca390638145f2c61ee052248512159d378f62fde0f105fca5072f"
    assert STEP236_ECOSYSTEM_REGISTRY_HTTP_LOADER_TEST_SHA256 == "4da7be1d24cf4a1d0f8e91e0bde4db32870586c669a94e0c20e9bba6b9ba8fd0"
    assert STEP236_CANONICAL_LIVE_RECEIPT_SHA256 == "218f2360a9502fa83db518e597e8440313aaa0be8dbfea5bd67224964805f179"
    document = _document_object()
    assert document["step235_transitive_chain"] == {
        "accepted_state_manifest_sha256": "09b211df4fae291a33b3509d83dceebaa1e9742d4995c331324cfdf64e7ed023",
        "architecture_plan_sha256": "d6ffd2561b069d69f16db836b32f58ff29e5d6fa021559160051035d5b3e8a37",
        "architecture_selection_readiness_sha256": "7dcf0b63695a5857f878264f19c5c4248cea419c6e2bf66896a266c28dac1e22",
        "architecture_selection_test_sha256": "e6cfa249fad7fd40696cd977971674fad4a52f9e6671f1e82bf561e8f5b8959f",
        "canonical_receipt_sha256": "6b70abd5db7496af97884707a64c52e272c62292de2568aec8adb6a505cf5ee4",
        "deferred_gate_plan_sha256": "7253144525f0f93e70d92dd94074aee696389fb54b30bacb1d064caf021e93c7",
        "experience_and_test_plan_sha256": "cf47c7b86e4dcebcea1ca442c8d463c98cecbe5bb9fd3b22883f0f60c905d5be",
        "package_manifest_sha256": "ffd92f5353e6e41c545b96d18c390eec2b6354776c08ee45544684a85e4a63f1",
        "readiness_document_sha256": "10e40546438acece101c6be7490772a47cf159dc19283eb0c9693ed4bbe9d723",
        "security_plan_sha256": "5e1edc9034c672ee81c451641852a20661e4724c80742601ed6d7153c79d3ba8",
    }


def test_step236_receipt_status_counts_and_all_projection_hashes_are_exact() -> None:
    binding = _document_object()["step236_receipt_binding"]
    assert binding == {
        "bundled_npm_version": "11.17.0",
        "counts": dict(STEP236_RECEIPT_COUNTS),
        "node_lts_codename": "Krypton",
        "node_version": "24.19.0",
        "projections": dict(STEP236_RECEIPT_PROJECTION_SHA256),
        "readiness_status": STEP236_STATUS,
        "selection_profile": STEP236_SELECTION_PROFILE,
    }
    assert len(binding["projections"]) == 14
    assert all(len(value) == 64 for value in binding["projections"].values())
    assert binding["counts"]["manifest_direct_package_count"] == 19
    assert binding["counts"]["mandatory_transitive_anchor_count"] == 3
    assert binding["counts"]["official_http_request_count"] == 27
    assert binding["counts"]["selected_metadata_advisory_count"] == 0


def test_planned_package_manifest_has_exact_nine_key_private_esm_object() -> None:
    rendered = render_planned_frontend_package_manifest_bytes()
    assert len(rendered) == 915
    assert rendered.endswith(b"\n")
    assert not rendered.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in rendered
    assert hashlib.sha256(rendered).hexdigest() == PACKAGE_MANIFEST_FILE_BYTES_SHA256
    assert PACKAGE_MANIFEST_FILE_BYTES_SHA256 == "ae3f112bccee82debfda8de49e50446e6505217200c7177c6dc8d145049e1704"
    parsed = json.loads(rendered)
    assert set(parsed) == {
        "name", "version", "private", "type", "packageManager", "engines",
        "scripts", "dependencies", "devDependencies",
    }
    assert len(parsed) == 9
    assert parsed["name"] == "engineer4me-frontend"
    assert parsed["version"] == "0.0.0"
    assert parsed["private"] is True
    assert parsed["type"] == "module"
    assert parsed["packageManager"] == "npm@11.17.0"
    assert parsed["engines"] == {"node": "24.19.0", "npm": "11.17.0"}
    assert rendered == _canonical(parsed) + b"\n"


def test_exact_direct_dependency_maps_have_no_ranges_or_forbidden_root_keys() -> None:
    parsed = json.loads(render_planned_frontend_package_manifest_bytes())
    assert parsed["dependencies"] == EXPECTED_PRODUCTION_DEPENDENCIES
    assert parsed["devDependencies"] == EXPECTED_DEVELOPMENT_DEPENDENCIES
    assert dict(PRODUCTION_DEPENDENCIES) == EXPECTED_PRODUCTION_DEPENDENCIES
    assert dict(DEVELOPMENT_DEPENDENCIES) == EXPECTED_DEVELOPMENT_DEPENDENCIES
    assert len(parsed["dependencies"]) == 4
    assert len(parsed["devDependencies"]) == 15
    assert len(set(parsed["dependencies"]) | set(parsed["devDependencies"])) == 19
    assert all(
        version.count(".") == 2
        and all(part.isdecimal() for part in version.split("."))
        for dependencies in (parsed["dependencies"], parsed["devDependencies"])
        for version in dependencies.values()
    )
    assert not ({"overrides", "resolutions", "workspaces", "optionalDependencies"} & set(parsed))
    assert not (set(EXPECTED_ANCHORS) & set(parsed["dependencies"]))
    assert not (set(EXPECTED_ANCHORS) & set(parsed["devDependencies"]))
    assert "npm" not in parsed["dependencies"] and "npm" not in parsed["devDependencies"]


def test_five_manual_scripts_are_exact_but_auto_lifecycle_hooks_are_absent() -> None:
    scripts = json.loads(render_planned_frontend_package_manifest_bytes())["scripts"]
    assert scripts == EXPECTED_SCRIPTS
    assert dict(MANUAL_SCRIPTS) == EXPECTED_SCRIPTS
    assert len(scripts) == 5
    assert not (set(scripts) & set(AUTO_LIFECYCLE_HOOK_NAMES))
    assert scripts["dev"].endswith("127.0.0.1")
    receipt = _receipt()
    assert receipt.manual_scripts_present is True
    assert receipt.manual_script_executed is False
    assert receipt.automatic_lifecycle_hooks_absent is True
    assert receipt.automatic_lifecycle_hook_count == 0


def test_npmrc_has_exact_thirteen_lf_lines_and_fail_closed_controls() -> None:
    rendered = render_planned_frontend_npmrc_bytes()
    assert rendered == EXPECTED_NPMRC
    assert len(rendered) == 249
    assert rendered.endswith(b"\n") and b"\r" not in rendered
    assert not rendered.startswith(b"\xef\xbb\xbf")
    assert hashlib.sha256(rendered).hexdigest() == NPMRC_FILE_BYTES_SHA256
    assert NPMRC_FILE_BYTES_SHA256 == "bd51c414eeb9453a451af9c7b48389b7baf20f95919eaf69e8059c7c8cdbc334"
    assert tuple(rendered.decode("ascii").splitlines()) == NPMRC_POLICY_LINES
    assert len(NPMRC_POLICY_LINES) == 13
    assert tuple(sorted(NPMRC_POLICY_LINES)) == NPMRC_POLICY_LINES
    assert "ignore-scripts=true" in NPMRC_POLICY_LINES
    assert "strict-peer-deps=true" in NPMRC_POLICY_LINES
    assert "fetch-retries=0" in NPMRC_POLICY_LINES
    assert "registry=https://registry.npmjs.org/" in NPMRC_POLICY_LINES
    assert not any("token" in line.lower() or "auth=" in line.lower() or "proxy=" in line.lower() for line in NPMRC_POLICY_LINES)


def test_three_anchor_assertions_are_exact_and_not_manifest_dependencies() -> None:
    document = _document_object()
    anchors = document["mandatory_lock_anchor_assertions"]
    assert dict(MANDATORY_LOCK_ANCHORS) == EXPECTED_ANCHORS
    assert len(anchors) == 3
    assert {item["name"]: item["version"] for item in anchors} == EXPECTED_ANCHORS
    assert {item["disposition"] for item in anchors} == {
        "future_lock_assertion_not_root_direct_dependency"
    }
    package = document["package_manifest_plan"]
    root_names = set(package["dependencies"]) | set(package["devDependencies"])
    assert not (set(EXPECTED_ANCHORS) & root_names)


def test_lock_generation_plan_is_exact_isolated_bounded_and_unauthorized() -> None:
    plan = _document_object()["lock_generation_plan"]
    assert plan["authorization"] == "blocked"
    assert tuple(plan["argv_after_verified_absolute_entrypoints"]) == LOCK_GENERATION_ARGV
    assert LOCK_GENERATION_ARGV == (
        "install", "--package-lock-only", "--ignore-scripts", "--audit=false",
        "--fund=false", "--prefer-offline=false", "--save-exact",
        "--engine-strict=true", "--strict-peer-deps=true", "--fetch-retries=0",
        "--workspaces=false",
    )
    assert plan["automatic_application_retry_count"] == 0
    assert plan["execution_monitor_required"] is True
    assert plan["bounds"] == {
        "execution_deadline_seconds": 300,
        "stderr_bytes": 1_048_576,
        "stdout_bytes": 1_048_576,
    }
    assert plan["fresh_working_directory"] == "required_outside_repository"
    assert plan["fresh_cache_directory"] == "required_outside_repository"
    assert plan["user_configuration"] == "sealed_exact_step237_npmrc"
    assert plan["global_configuration"] == "sealed_empty"
    assert plan["node_executable"]["absolute_path"] == "unselected"
    assert plan["npm_cli_entrypoint"]["absolute_path"] == "unselected"
    assert plan["node_executable"]["version"] == NODE_VERSION
    assert plan["npm_cli_entrypoint"]["version"] == NPM_VERSION


def test_lock_environment_and_official_registry_egress_are_closed() -> None:
    plan = _document_object()["lock_generation_plan"]
    environment = plan["environment"]
    assert environment["inheritance"] == "deny_by_default_minimal_successor_allowlist"
    assert environment["scrubbed_prefixes"] == ["NPM_CONFIG_", "npm_config_"]
    scrubbed = set(environment["scrubbed_exact_names"])
    assert {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_OPTIONS", "NODE_PATH", "NPM_TOKEN", "NODE_AUTH_TOKEN"} <= scrubbed
    assert environment["successor_assignments"] == {
        "CI": "true",
        "NPM_CONFIG_CACHE": "fresh_out_of_repository_temporary_cache",
        "NPM_CONFIG_GLOBALCONFIG": "sealed_empty_out_of_repository_file",
        "NPM_CONFIG_USERCONFIG": "sealed_exact_step237_npmrc_copy",
    }
    assert plan["network_egress"] == {
        "credentials": "forbidden",
        "host": "registry.npmjs.org",
        "origin": "https://registry.npmjs.org/",
        "proxy": "forbidden",
        "redirect": "forbidden",
        "scope": "official_registry_only",
    }
    assert set(plan["unsupported_source_schemes"]) == {
        "file:", "git:", "git+", "http:", "link:", "workspace:"
    }
    assert len(plan["unsupported_source_schemes"]) == len(set(plan["unsupported_source_schemes"]))
    assert len(environment["scrubbed_exact_names"]) == len(set(environment["scrubbed_exact_names"]))
    assert len(environment["scrubbed_prefixes"]) == len(set(environment["scrubbed_prefixes"]))


def test_variable_network_candidate_graph_and_file_size_bounds_remain_explicitly_deferred() -> None:
    plan = _document_object()["lock_generation_plan"]
    assert plan["unselected_successor_bounds"] == [
        "maximum_aggregate_response_bytes",
        "maximum_candidate_package_count",
        "maximum_dependency_graph_node_count",
        "maximum_generated_lockfile_bytes",
        "maximum_individual_response_bytes",
        "maximum_network_request_count",
    ]
    assert len(plan["unselected_successor_bounds"]) == len(set(plan["unselected_successor_bounds"]))
    receipt = _receipt()
    assert receipt.request_response_candidate_graph_and_file_size_bounds_deferred is True
    assert receipt.all_lock_execution_bounds_selected is False
    assert receipt.lock_generation_authorized is False


def test_future_lock_success_contract_is_v3_exact_root_without_overforbidding_optional_nodes() -> None:
    success = _document_object()["lock_generation_plan"]["success_contract"]
    assert success["exit_code"] == 0
    assert type(success["lockfile_version"]) is int
    assert success["lockfile_version"] == 3 == LOCKFILE_VERSION
    assert success["root_dependency_maps_exact"] is True
    assert success["root_optional_dependencies_absent"] is True
    assert success["complete_transitive_graph_required"] is True
    assert success["node_modules_created"] is False
    assert success["additional_scaffold_paths_created"] == 0
    assert success["transitive_optional_and_platform_entries"] == (
        "allowed_only_with_later_exact_os_cpu_libc_native_and_lifecycle_audit"
    )


def test_initial_scaffold_allowlist_is_exact_safe_and_collision_free() -> None:
    assert INITIAL_SCAFFOLD_PATH_ALLOWLIST == EXPECTED_ALLOWLIST
    assert len(INITIAL_SCAFFOLD_PATH_ALLOWLIST) == 33
    assert len(set(INITIAL_SCAFFOLD_PATH_ALLOWLIST)) == 33
    assert len({path.casefold() for path in INITIAL_SCAFFOLD_PATH_ALLOWLIST}) == 33
    for path in INITIAL_SCAFFOLD_PATH_ALLOWLIST:
        assert path.isascii()
        assert path.startswith("frontend/")
        assert "\\" not in path and "//" not in path and ":" not in path
        assert "/./" not in f"/{path}/" and "/../" not in f"/{path}/"
        assert not path.endswith("/")
    for left in INITIAL_SCAFFOLD_PATH_ALLOWLIST:
        for right in INITIAL_SCAFFOLD_PATH_ALLOWLIST:
            if left != right:
                assert not right.casefold().startswith(left.casefold() + "/")


def test_only_package_json_and_npmrc_bytes_are_selected() -> None:
    assert SELECTED_EXACT_SCAFFOLD_BYTE_PATHS == (
        "frontend/.npmrc", "frontend/package.json"
    )
    assert set(SELECTED_EXACT_SCAFFOLD_BYTE_PATHS) <= set(INITIAL_SCAFFOLD_PATH_ALLOWLIST)
    assert LOCKFILE_PATH in INITIAL_SCAFFOLD_PATH_ALLOWLIST
    assert LOCKFILE_PATH not in SELECTED_EXACT_SCAFFOLD_BYTE_PATHS
    receipt = _receipt()
    assert receipt.initial_scaffold_path_count == 33
    assert receipt.selected_exact_scaffold_byte_count == 2
    assert receipt.unselected_scaffold_byte_count == 31
    assert receipt.final_initial_scaffold_path_allowlist_selected is True
    assert receipt.all_scaffold_file_bytes_selected is False
    assert receipt.lockfile_bytes_selected is False
    assert receipt.remaining_scaffold_file_bytes_selected is False


def test_runtime_config_actual_path_is_excluded_and_template_remains_non_operational() -> None:
    assert EXCLUDED_RUNTIME_CONFIG_PATH == "frontend/public/runtime-config.json"
    assert EXCLUDED_RUNTIME_CONFIG_PATH not in INITIAL_SCAFFOLD_PATH_ALLOWLIST
    assert "frontend/public/runtime-config.template.json" in INITIAL_SCAFFOLD_PATH_ALLOWLIST
    assert "frontend/public/runtime-config.template.json" not in SELECTED_EXACT_SCAFFOLD_BYTE_PATHS
    receipt = _receipt()
    assert receipt.actual_runtime_config_path_excluded is True
    assert receipt.runtime_config_template_must_be_non_operational is True
    assert receipt.frontend_root_created is False
    assert receipt.scaffold_file_written is False


def test_zero_retry_source_identity_and_future_copy_boundary_are_preserved() -> None:
    assert ZERO_RETRY_NETWORK_CLIENT_SHA256 == "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
    assert "frontend/src/auth/zeroRetryNetworkClient.mjs" in INITIAL_SCAFFOLD_PATH_ALLOWLIST
    assert "frontend/src/auth/zeroRetryNetworkClient.d.ts" in INITIAL_SCAFFOLD_PATH_ALLOWLIST
    assert _receipt().zero_retry_network_client_exact_future_copy_required is True


def test_deferred_gates_preserve_complete_tree_and_materialization_boundaries() -> None:
    assert len(DEFERRED_GATES) == 12
    assert len(DEFERRED_GATES) == len(set(DEFERRED_GATES))
    joined = " ".join(DEFERRED_GATES)
    for token in (
        "node_24_19_0_platform_artifact",
        "absolute_node_binary_and_npm_11_17_0_cli",
        "collision_casefold_symlink_reparse_and_race",
        "lock_generation_execution",
        "request_response_candidate_graph_and_file_size_bounds",
        "complete_graph",
        "advisory_license_deprecation_lifecycle_and_native_platform",
        "sri_signature_and_provenance",
        "tarball_byte_sri",
        "remaining_31_initial_scaffold_file_bytes",
        "runtime_configuration",
        "browser_journey",
    ):
        assert token in joined
    receipt = _receipt()
    assert receipt.step236_selected_metadata_not_claimed_as_complete_tree_closure
    assert not receipt.complete_transitive_dependency_graph_resolved
    assert not receipt.complete_tree_advisory_audit_completed
    assert not receipt.complete_tree_license_deprecation_audit_completed
    assert not receipt.complete_tree_lifecycle_native_platform_audit_completed
    assert not receipt.complete_tree_signature_provenance_disposition_completed


def test_exact_document_is_canonical_ascii_bounded_and_validates() -> None:
    document = _document_bytes()
    assert type(document) is bytes
    assert document == _canonical(json.loads(document))
    assert len(document) == 11_439
    assert len(document) < MAX_DOCUMENT_BYTES
    assert document.isascii()
    assert b"\r" not in document and b"\n" not in document
    model = EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument.model_validate(
        json.loads(document)
    )
    assert model.document_type == DOCUMENT_TYPE
    assert model.schema_version == SCHEMA_VERSION
    assert model.source == SOURCE
    assert model.readiness_status == STATUS


def test_success_receipt_has_exact_constants_counts_digests_and_outcomes() -> None:
    receipt = _receipt()
    assert type(receipt) is EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.source == SOURCE
    assert receipt.readiness_status == STATUS == "exact_frontend_package_manifest_and_controlled_lock_generation_plan_validated_execution_and_materialization_remain_blocked"
    assert receipt.approved_step236_selection_profile == STEP236_SELECTION_PROFILE
    assert receipt.approved_step236_status == STEP236_STATUS
    assert receipt.node_version == NODE_VERSION == "24.19.0"
    assert receipt.bundled_npm_version == NPM_VERSION == "11.17.0"
    assert receipt.node_lts_codename == NODE_LTS_CODENAME == "Krypton"
    assert receipt.package_manifest_path == PACKAGE_MANIFEST_PATH
    assert receipt.npmrc_path == NPMRC_PATH
    assert receipt.lockfile_path == LOCKFILE_PATH
    assert receipt.production_dependency_count == 4
    assert receipt.development_dependency_count == 15
    assert receipt.manifest_direct_package_count == 19
    assert receipt.mandatory_lock_anchor_count == 3
    assert receipt.manual_script_count == 5
    assert {name: getattr(receipt, name) for name in EXPECTED_PLAN_DIGESTS} == EXPECTED_PLAN_DIGESTS


def test_canonical_receipt_has_exact_identity_and_all_policy_fields() -> None:
    receipt = _receipt()
    rendered = render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert len(dataclasses.fields(receipt)) == 120
    assert len(parsed) == 120
    assert rendered == _canonical(parsed)
    assert len(rendered) == 6_835
    assert hashlib.sha256(rendered).hexdigest() == CANONICAL_RECEIPT_SHA256
    assert CANONICAL_RECEIPT_SHA256 == "9e6e30b63e78b3660ae289752d26241b9890d4ec04e4254023b817b6f9cbb5c7"
    assert sum(value is True for value in parsed.values()) == 39
    assert sum(value is False for value in parsed.values()) == 34


def test_receipt_explicitly_blocks_every_execution_and_mutation_outcome() -> None:
    receipt = _receipt()
    false_fields = [
        field.name
        for field in dataclasses.fields(receipt)
        if type(getattr(receipt, field.name)) is bool and not getattr(receipt, field.name)
    ]
    assert len(false_fields) == 34
    for required in (
        "step237_external_request_performed", "node_or_npm_executed",
        "package_manager_executed", "lock_generation_authorized",
        "package_manifest_created_or_modified", "npmrc_created_or_modified",
        "lockfile_created_or_modified", "dependency_installed", "node_modules_created",
        "lifecycle_script_executed", "manual_script_executed", "frontend_root_created",
        "scaffold_file_written", "scaffold_materialization_authorized",
        "browser_oauth_graph_entra_or_application_endpoint_requested",
        "application_configuration_modified", "application_activated",
        "operational_write_performed", "docker_restarted_or_rebuilt",
        "git_stage_commit_or_push_performed",
    ):
        assert required in false_fields


@pytest.mark.parametrize("key", sorted(_document_object()))
def test_every_document_top_level_value_rejects_same_type_tamper(key: str) -> None:
    value = _document_object()
    value[key] = _replacement(value[key])
    with pytest.raises(EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError):
        load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(
            _canonical(value)
        )


@pytest.mark.parametrize("key", sorted(_document_object()))
def test_every_document_top_level_key_is_mandatory(key: str) -> None:
    value = _document_object()
    del value[key]
    with pytest.raises(EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError):
        load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(
            _canonical(value)
        )


@pytest.mark.parametrize("key", sorted(_document_object()))
def test_every_document_top_level_type_is_exact(key: str) -> None:
    value = _document_object()
    value[key] = _wrong_type(value[key])
    with pytest.raises(ValueError):
        EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument.model_validate(
            value
        )


NESTED_LEAF_PATHS = tuple(_leaf_paths(_document_object()))


@pytest.mark.parametrize("path", NESTED_LEAF_PATHS, ids=lambda path: "/".join(map(str, path)))
def test_every_document_leaf_rejects_exact_model_tamper(path: tuple[object, ...]) -> None:
    value = _document_object()
    original = _get_path(value, path)
    _set_path(value, path, _replacement(original))
    with pytest.raises(ValueError):
        EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument.model_validate(
            value
        )


def test_document_rejects_extra_key_duplicate_key_noncanonical_and_wrong_transport() -> None:
    extra = _document_object()
    extra["extra"] = False
    invalid_documents: tuple[object, ...] = (
        None,
        "not-bytes",
        bytearray(_document_bytes()),
        b"",
        b"{}",
        b"\xef\xbb\xbf" + _document_bytes(),
        _document_bytes() + b"\n",
        b" " + _document_bytes(),
        _canonical(extra),
        b'{' + b'"document_type":"duplicate",' + _document_bytes()[1:],
        b"{" + b'"nonfinite":NaN}',
        b"x" * (MAX_DOCUMENT_BYTES + 1),
    )
    for document in invalid_documents:
        with pytest.raises(EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError) as error:
            load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(document)  # type: ignore[arg-type]
        assert str(error.value) == "frontend-host package-manifest and lock readiness validation failed"


@pytest.mark.parametrize(
    "field_name",
    [field.name for field in dataclasses.fields(EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt)],
)
def test_every_receipt_field_is_covered_and_rejects_tamper(field_name: str) -> None:
    receipt = _receipt()
    with pytest.raises(ValueError):
        replace(receipt, **{field_name: _field_replacement(getattr(receipt, field_name))})


def test_receipt_renderer_rejects_wrong_type_and_cannot_accept_subclass() -> None:
    for value in (None, {}, dataclasses.asdict(_receipt())):
        with pytest.raises(TypeError):
            render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt(value)  # type: ignore[arg-type]


def test_receipt_rejects_well_formed_but_wrong_sha256_identity() -> None:
    with pytest.raises(ValueError):
        replace(
            _receipt(),
            approved_step236_canonical_live_receipt_sha256="0" * 64,
        )


def test_public_calls_perform_no_filesystem_process_network_or_cli_action(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("I/O, process, network, or CLI capability was used")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "call", forbidden)
    document = render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document()
    receipt = load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness(document)
    assert render_planned_frontend_package_manifest_bytes()
    assert render_planned_frontend_npmrc_bytes()
    assert render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt(receipt)


def test_production_ast_has_no_io_process_network_dynamic_code_or_cli_capability() -> None:
    source = inspect.getsource(readiness)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "asyncio", "http", "httpx", "io", "multiprocessing", "os", "pathlib",
        "requests", "shutil", "socket", "subprocess", "sys", "tempfile", "urllib",
    }
    forbidden_calls = {
        "__import__", "compile", "eval", "exec", "input", "open", "print",
        "Popen", "call", "check_call", "check_output", "connect", "delete",
        "get", "makedirs", "mkdir", "open", "post", "put", "request", "run",
        "stream", "system", "unlink", "urlopen", "write", "write_bytes", "write_text",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] not in forbidden_import_roots for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_import_roots
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_calls
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_calls
    assert 'if __name__ == "__main__"' not in source
    assert "__STEP237_" not in source


def test_module_exports_only_in_memory_contract_surfaces() -> None:
    public_callables = {
        name
        for name in readiness.__all__
        if callable(getattr(readiness, name))
    }
    assert public_callables == {
        "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessDocument",
        "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessError",
        "EntraCallingClientMSALFrontendHostPackageManifestLockReadinessReceipt",
        "load_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness",
        "render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_document",
        "render_entra_calling_client_msal_frontend_host_package_manifest_lock_readiness_receipt",
        "render_planned_frontend_npmrc_bytes",
        "render_planned_frontend_package_manifest_bytes",
    }


def test_contract_contains_no_placeholder_or_claim_of_executed_lock_generation() -> None:
    source = inspect.getsource(readiness)
    assert "__STEP237_" not in source
    assert "TODO" not in source and "FIXME" not in source
    receipt = _receipt()
    assert receipt.lock_generation_authorized is False
    assert receipt.package_manager_executed is False
    assert receipt.lockfile_created_or_modified is False
    assert receipt.step237_external_request_performed is False
