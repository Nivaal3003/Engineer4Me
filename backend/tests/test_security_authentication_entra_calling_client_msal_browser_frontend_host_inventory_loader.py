from __future__ import annotations

import dataclasses

import pytest

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_loader import (
    ALLOWED_FILE_ROLES,
    ALLOWED_LOCKFILE_KINDS,
    ALLOWED_PACKAGE_MANAGERS,
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    EVIDENCE_TYPE,
    MAX_CANDIDATE_ROOTS,
    MAX_INSPECTED_FILES,
    MAX_PATH_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_INSPECTED_BYTES,
    MAX_TRACKED_PATHS,
    SCHEMA_VERSION,
    EntraCallingClientMSALFrontendHostInventoryEvidence,
    EntraCallingClientMSALFrontendHostInventoryFileEvidence,
    EntraCallingClientMSALFrontendHostInventoryLoaderError,
    validate_entra_calling_client_msal_frontend_host_inventory_evidence,
)


def _file(
    path: str = "frontend/package.json",
    role: str = "package_manifest",
    size_bytes: int = 120,
    sha256: str = "1" * 64,
) -> EntraCallingClientMSALFrontendHostInventoryFileEvidence:
    return EntraCallingClientMSALFrontendHostInventoryFileEvidence(
        path=path,
        role=role,  # type: ignore[arg-type]
        size_bytes=size_bytes,
        sha256=sha256,
    )


def _evidence(
    **changes: object,
) -> EntraCallingClientMSALFrontendHostInventoryEvidence:
    values: dict[str, object] = {
        "evidence_type": EVIDENCE_TYPE,
        "schema_version": SCHEMA_VERSION,
        "provenance": EVIDENCE_PROVENANCE,
        "branch": APPROVED_BRANCH,
        "head": APPROVED_HEAD,
        "repository_root_sha256": "2" * 64,
        "tracked_path_count": 300,
        "candidate_roots": ("frontend",),
        "package_manager": "npm",
        "lockfile_kind": "package-lock.json",
        "files": (
            _file(),
            _file(
                "frontend/package-lock.json",
                "dependency_lock",
                240,
                "3" * 64,
            ),
            _file(
                "frontend/src/main.ts",
                "javascript_or_typescript_entrypoint",
                360,
                "4" * 64,
            ),
        ),
        "git_tracked_projection_complete": True,
        "untracked_content_included": False,
        "symlink_or_reparse_point_observed": False,
        "submodule_observed": False,
        "nested_repository_observed": False,
        "git_worktree_indirection_observed": False,
        "case_collision_observed": False,
        "environment_file_content_read": False,
        "secret_value_collected": False,
        "live_repository_accessed": False,
        "filesystem_io_performed": False,
        "git_process_started": False,
        "package_manager_process_started": False,
        "network_io_performed": False,
        "repository_mutation_performed": False,
    }
    values.update(changes)
    return EntraCallingClientMSALFrontendHostInventoryEvidence(**values)  # type: ignore[arg-type]


def _absent() -> EntraCallingClientMSALFrontendHostInventoryEvidence:
    return _evidence(
        candidate_roots=(),
        package_manager="none",
        lockfile_kind="none",
        files=(),
    )


def test_constants_and_limits_are_exact_and_bounded() -> None:
    assert EVIDENCE_TYPE == "engineer4me_frontend_host_inventory_evidence"
    assert EVIDENCE_PROVENANCE == "synthetic_injected_inventory_evidence"
    assert APPROVED_BRANCH == "feature/phase-8"
    assert APPROVED_HEAD == "89b257fbd72333f17367be0aee82d6157775df33"
    assert MAX_TRACKED_PATHS == 4096
    assert MAX_CANDIDATE_ROOTS == 1
    assert MAX_INSPECTED_FILES == 128
    assert MAX_PATH_BYTES == 512
    assert MAX_SINGLE_FILE_BYTES == 1_048_576
    assert MAX_TOTAL_INSPECTED_BYTES == 8_388_608
    assert len(ALLOWED_FILE_ROLES) == len(set(ALLOWED_FILE_ROLES))
    assert ALLOWED_PACKAGE_MANAGERS == (
        "none",
        "npm",
        "pnpm",
        "yarn",
        "bun",
        "unknown",
    )
    assert "package-lock.json" in ALLOWED_LOCKFILE_KINDS


def test_valid_single_npm_host_evidence_is_accepted_unchanged() -> None:
    evidence = _evidence()
    assert validate_entra_calling_client_msal_frontend_host_inventory_evidence(
        evidence
    ) is evidence


def test_valid_absent_host_evidence_is_accepted_without_claiming_live_access() -> None:
    evidence = _absent()
    validated = validate_entra_calling_client_msal_frontend_host_inventory_evidence(
        evidence
    )
    assert validated.candidate_roots == ()
    assert validated.live_repository_accessed is False
    assert validated.filesystem_io_performed is False


def test_repository_root_frontend_representation_is_supported() -> None:
    evidence = _evidence(
        candidate_roots=(".",),
        files=(
            _file("package.json", "package_manifest"),
            _file("package-lock.json", "dependency_lock", 240, "3" * 64),
        ),
    )
    assert evidence.candidate_roots == (".",)


def test_evidence_and_file_records_are_frozen_and_slotted() -> None:
    evidence = _evidence()
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        evidence.package_manager = "yarn"  # type: ignore[misc]
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        evidence.files[0].path = "other/package.json"  # type: ignore[misc]
    assert not hasattr(evidence, "__dict__")
    assert not hasattr(evidence.files[0], "__dict__")


@pytest.mark.parametrize("value", [None, {}, object(), _file()])
def test_public_validator_rejects_non_exact_evidence(value: object) -> None:
    with pytest.raises(
        EntraCallingClientMSALFrontendHostInventoryLoaderError,
        match="frontend-host inventory evidence validation failed",
    ):
        validate_entra_calling_client_msal_frontend_host_inventory_evidence(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/frontend/package.json",
        "frontend/package.json/",
        "frontend//package.json",
        "frontend/../package.json",
        "frontend/./package.json",
        "frontend\\package.json",
        '"frontend/package.json"',
        "frontend/package.json\x00",
        "frontend/package.json\n",
        "frontend/node modules/package.json",
        "frontend/package$.json",
        "frontend/é/package.json",
    ],
)
def test_file_evidence_rejects_noncanonical_path(path: str) -> None:
    with pytest.raises(ValueError, match="file evidence is invalid"):
        _file(path)


@pytest.mark.parametrize(
    "path",
    [
        ".git/package.json",
        "frontend/node_modules/package.json",
        "frontend/.env",
        "frontend/.env.production",
        "frontend/.npmrc",
        "frontend/credentials.json",
        "frontend/client-secret.json",
        "frontend/api_credentials.json",
        "frontend/id_rsa",
    ],
)
def test_file_evidence_rejects_sensitive_or_excluded_path(path: str) -> None:
    with pytest.raises(ValueError, match="file evidence is invalid"):
        _file(path)


@pytest.mark.parametrize(
    ("role", "size_bytes", "sha256"),
    [
        ("unknown_role", 1, "1" * 64),
        ("package_manifest", -1, "1" * 64),
        ("package_manifest", MAX_SINGLE_FILE_BYTES + 1, "1" * 64),
        ("package_manifest", True, "1" * 64),
        ("package_manifest", 1, "A" * 64),
        ("package_manifest", 1, "1" * 63),
    ],
)
def test_file_evidence_rejects_invalid_role_size_or_digest(
    role: str, size_bytes: int, sha256: str
) -> None:
    with pytest.raises(ValueError, match="file evidence is invalid"):
        _file(role=role, size_bytes=size_bytes, sha256=sha256)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("evidence_type", "wrong"),
        ("schema_version", 2),
        ("provenance", "sealed"),
        ("branch", "main"),
        ("head", "0" * 40),
        ("repository_root_sha256", "A" * 64),
        ("tracked_path_count", -1),
        ("tracked_path_count", MAX_TRACKED_PATHS + 1),
        ("candidate_roots", ["frontend"]),
        ("package_manager", "deno"),
        ("lockfile_kind", "deno.lock"),
        ("files", [_file()]),
    ],
)
def test_evidence_rejects_invalid_identity_or_shape(
    name: str, replacement: object
) -> None:
    with pytest.raises(ValueError):
        _evidence(**{name: replacement})


def test_evidence_rejects_multiple_candidate_roots() -> None:
    with pytest.raises(ValueError, match="shape is invalid"):
        _evidence(candidate_roots=("frontend", "web"))


def test_evidence_rejects_duplicate_and_case_colliding_paths() -> None:
    duplicate = (_file(), _file())
    with pytest.raises(ValueError, match="paths collide"):
        _evidence(files=duplicate, lockfile_kind="none")
    collision = (
        _file("frontend/package.json"),
        _file("FRONTEND/PACKAGE.JSON", "workspace_configuration"),
    )
    with pytest.raises(ValueError, match="paths collide"):
        _evidence(files=collision, lockfile_kind="none")


def test_evidence_rejects_file_outside_candidate_root() -> None:
    with pytest.raises(ValueError, match="outside candidate root"):
        _evidence(
            files=(
                _file(),
                _file("other/vite.config.ts", "build_or_bundler_configuration"),
            ),
            lockfile_kind="none",
        )


def test_evidence_rejects_root_without_exact_package_manifest() -> None:
    with pytest.raises(ValueError, match="cardinality"):
        _evidence(
            files=(
                _file(
                    "frontend/vite.config.ts", "build_or_bundler_configuration"
                ),
            ),
            lockfile_kind="none",
        )


def test_evidence_rejects_inconsistent_lockfile_kind_or_cardinality() -> None:
    with pytest.raises(ValueError, match="incomplete"):
        _evidence(files=(_file(),), lockfile_kind="package-lock.json")
    with pytest.raises(ValueError, match="does not match path"):
        _evidence(
            lockfile_kind="yarn.lock",
            files=(
                _file(),
                _file(
                    "frontend/package-lock.json",
                    "dependency_lock",
                    240,
                    "3" * 64,
                ),
            ),
        )


def test_evidence_rejects_absent_host_with_candidate_metadata() -> None:
    with pytest.raises(ValueError, match="absent evidence is inconsistent"):
        _evidence(
            candidate_roots=(),
            package_manager="npm",
            lockfile_kind="none",
            files=(),
        )


def test_evidence_rejects_host_with_none_package_manager() -> None:
    with pytest.raises(ValueError, match="package-manager evidence"):
        _evidence(package_manager="none")


def test_evidence_rejects_tracked_count_less_than_inspected_files() -> None:
    with pytest.raises(ValueError, match="tracked-path count"):
        _evidence(tracked_path_count=2)


def test_evidence_rejects_total_bytes_over_limit() -> None:
    files = tuple(
        _file(
            "frontend/file" + str(index) + ".json",
            "workspace_configuration" if index else "package_manifest",
            MAX_SINGLE_FILE_BYTES,
            f"{index + 1:064x}",
        )
        for index in range(9)
    )
    with pytest.raises(ValueError, match="byte total"):
        _evidence(files=files, lockfile_kind="none")


@pytest.mark.parametrize(
    "name",
    [
        "git_tracked_projection_complete",
        "untracked_content_included",
        "symlink_or_reparse_point_observed",
        "submodule_observed",
        "nested_repository_observed",
        "git_worktree_indirection_observed",
        "case_collision_observed",
        "environment_file_content_read",
        "secret_value_collected",
        "live_repository_accessed",
        "filesystem_io_performed",
        "git_process_started",
        "package_manager_process_started",
        "network_io_performed",
        "repository_mutation_performed",
    ],
)
def test_evidence_rejects_completeness_or_side_effect_boolean_flip(name: str) -> None:
    replacement = False if name == "git_tracked_projection_complete" else True
    with pytest.raises(ValueError):
        _evidence(**{name: replacement})


def test_public_validator_resanitizes_post_construction_tamper() -> None:
    evidence = _evidence()
    object.__setattr__(evidence, "network_io_performed", True)
    with pytest.raises(
        EntraCallingClientMSALFrontendHostInventoryLoaderError,
        match="frontend-host inventory evidence validation failed",
    ):
        validate_entra_calling_client_msal_frontend_host_inventory_evidence(evidence)
