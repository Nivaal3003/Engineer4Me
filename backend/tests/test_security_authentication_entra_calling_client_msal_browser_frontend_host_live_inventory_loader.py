from __future__ import annotations

import dataclasses
import json

import pytest

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_live_inventory_loader import (
    ACCEPTED_OVERLAY_PATH_COUNT,
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    EVIDENCE_TYPE,
    MARKER_BASENAME_ROLES,
    MAX_EVIDENCE_DOCUMENT_BYTES,
    SCHEMA_VERSION,
    STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP232_INVENTORY_LOADER_SHA256,
    STEP232_INVENTORY_PROBE_SHA256,
    STEP232_PACKAGE_MANIFEST_SHA256,
    EntraCallingClientMSALFrontendHostLiveInventoryLoaderError,
    load_entra_calling_client_msal_frontend_host_live_inventory,
)


def _head(
    path: str = "README.md",
    *,
    mode: str = "100644",
    object_type: str = "blob",
    object_id: str = "1" * 40,
) -> dict[str, object]:
    return {
        "mode": mode,
        "object_type": object_type,
        "object_id": object_id,
        "path": path,
    }


def _marker(
    path: str = "frontend/package.json",
    *,
    source_domain: str = "git_head",
    role: str = "package_manifest",
    size_bytes: int = 120,
    sha256: str = "2" * 64,
    object_id: str | None = "1" * 40,
) -> dict[str, object]:
    return {
        "source_domain": source_domain,
        "path": path,
        "role": role,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "object_id": object_id,
    }


def _mapping(*, host: bool = False) -> dict[str, object]:
    head_entries = [_head("frontend/package.json")] if host else [_head()]
    markers = [_marker()] if host else []
    return {
        "evidence_type": EVIDENCE_TYPE,
        "schema_version": SCHEMA_VERSION,
        "provenance": EVIDENCE_PROVENANCE,
        "branch": APPROVED_BRANCH,
        "head": APPROVED_HEAD,
        "head_tree_object_id": "3" * 40,
        "step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
        "accepted_step232_state_manifest_sha256": (
            STEP232_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "step232_inventory_loader_sha256": STEP232_INVENTORY_LOADER_SHA256,
        "step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
        "git_executable_sha256": "4" * 64,
        "working_tree_status_before_sha256": "5" * 64,
        "working_tree_status_after_sha256": "5" * 64,
        "accepted_overlay_path_count": ACCEPTED_OVERLAY_PATH_COUNT,
        "accepted_overlay_projection_sha256": (
            STEP232_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "accepted_overlay_paths_overlapping_head": 0,
        "combined_source_path_count": ACCEPTED_OVERLAY_PATH_COUNT + 1,
        "installer_asserted_combined_source_path_projection_sha256": "6" * 64,
        "head_entries": head_entries,
        "markers": markers,
        "live_repository_accessed": True,
        "filesystem_io_performed": True,
        "git_process_started": True,
        "git_head_projection_complete": True,
        "accepted_overlay_projection_complete": True,
        "before_after_accepted_source_projection_identical": True,
        "git_object_bytes_read_only_for_allowlisted_markers": True,
        "git_status_worktree_enumeration_performed": True,
        "working_tree_marker_content_read": False,
        "tracked_git_symlink_or_gitlink_observed": False,
        "package_manager_process_started": False,
        "remote_git_or_package_network_operation_requested": False,
        "inventory_accepted_source_projection_changed": False,
    }


def _document(mapping: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        _mapping() if mapping is None else mapping,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_constants_bind_the_exact_step232_state_and_policy() -> None:
    assert EVIDENCE_TYPE.endswith("live_git_inventory_evidence")
    assert EVIDENCE_PROVENANCE == "controlled_local_git_head_object_inventory"
    assert APPROVED_BRANCH == "feature/phase-8"
    assert APPROVED_HEAD == "89b257fbd72333f17367be0aee82d6157775df33"
    assert STEP232_PACKAGE_MANIFEST_SHA256 == (
        "241edaaf2c07f763ab94fba7ba57bc49ae95fda3201cf13eb1cfdc95d5555e00"
    )
    assert STEP232_ACCEPTED_STATE_MANIFEST_SHA256 == (
        "bbc241458c79d85cce537fd89d08f2a46beb0728eea0083cdfbaffe7581251bc"
    )
    assert ACCEPTED_OVERLAY_PATH_COUNT == 220
    assert MAX_EVIDENCE_DOCUMENT_BYTES == 2_097_152
    assert MARKER_BASENAME_ROLES["package.json"] == "package_manifest"


def test_loader_accepts_complete_zero_candidate_projection() -> None:
    evidence, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document()
    )
    assert evidence.live_repository_accessed is True
    assert result.head_tree_path_count == 1
    assert result.accepted_overlay_path_count == 220
    assert result.combined_source_path_count == 221
    assert result.candidate_root_count == 0
    assert result.package_manager == "none"
    assert result.lockfile_kind == "none"
    assert result.disposition.endswith("no_package_manifest_candidate_in_accepted_source")


def test_loader_accepts_one_unselected_package_manifest_candidate() -> None:
    _, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document(_mapping(host=True))
    )
    assert result.candidate_roots == ("frontend",)
    assert result.candidate_root_count == 1
    assert result.package_manifest_count == 1
    assert result.marker_file_count == 1
    assert result.package_manager == "unknown"


@pytest.mark.parametrize(
    "path",
    [
        "docs/16_Legal_Compliance/AI Usage Policy.md",
        "docs/Commissioning notes, rev 2.md",
        "docs/R&D=field-test;v2!.md",
        "docs/owner's guide (draft) [2].md",
        "docs/build^tag`x{y}~.txt",
        "docs/100% ready #2.md",
        "docs/safe !#$%&'()+,-.;=@[]^_`{}~ name.txt",
    ],
)
def test_loader_accepts_windows_safe_printable_ascii_paths(path: str) -> None:
    value = _mapping()
    value["head_entries"] = [_head(path)]
    _, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document(value)
    )
    assert result.head_tree_path_count == 1
    assert result.candidate_root_count == 0


def test_loader_accepts_candidate_root_containing_internal_space() -> None:
    value = _mapping(host=True)
    value["head_entries"] = [_head("frontend app/package.json")]
    value["markers"] = [_marker("frontend app/package.json")]
    _, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document(value)
    )
    assert result.candidate_roots == ("frontend app",)
    assert result.package_manifest_count == 1


def test_loader_derives_npm_for_spaced_punctuated_candidate_root() -> None:
    root = "web app & admin #1"
    value = _mapping(host=True)
    value["head_entries"] = [
        _head(f"{root}/package-lock.json", object_id="2" * 40),
        _head(f"{root}/package.json"),
    ]
    value["combined_source_path_count"] = ACCEPTED_OVERLAY_PATH_COUNT + 2
    value["markers"] = [
        _marker(
            f"{root}/package-lock.json",
            role="dependency_lock",
            sha256="7" * 64,
            object_id="2" * 40,
        ),
        _marker(f"{root}/package.json"),
    ]
    _, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document(value)
    )
    assert result.candidate_roots == (root,)
    assert result.package_manager == "npm"
    assert result.lockfile_kind == "package-lock.json"


def test_loader_derives_npm_only_from_one_same_root_lockfile() -> None:
    value = _mapping(host=True)
    value["head_entries"] = [
        _head("frontend/package-lock.json", object_id="2" * 40),
        _head("frontend/package.json"),
    ]
    value["combined_source_path_count"] = ACCEPTED_OVERLAY_PATH_COUNT + 2
    value["markers"] = [
        _marker(
            "frontend/package-lock.json",
            role="dependency_lock",
            sha256="7" * 64,
            object_id="2" * 40,
        ),
        _marker(),
    ]
    _, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document(value)
    )
    assert result.package_manager == "npm"
    assert result.lockfile_kind == "package-lock.json"
    assert result.dependency_lock_count == 1


def test_evidence_and_result_are_frozen_and_slotted() -> None:
    evidence, result = load_entra_calling_client_msal_frontend_host_live_inventory(
        _document()
    )
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        evidence.inventory_accepted_source_projection_changed = True  # type: ignore[misc]
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        result.candidate_root_count = 1  # type: ignore[misc]
    assert not hasattr(evidence, "__dict__")
    assert not hasattr(result, "__dict__")


@pytest.mark.parametrize("value", [None, {}, [], "x", 1, True, bytearray(b"{}")])
def test_loader_rejects_non_exact_or_invalid_documents(value: object) -> None:
    document = value if isinstance(value, (bytes, bytearray)) else json.dumps(value).encode()
    with pytest.raises(
        EntraCallingClientMSALFrontendHostLiveInventoryLoaderError,
        match="controlled local frontend-host live inventory validation failed",
    ):
        load_entra_calling_client_msal_frontend_host_live_inventory(document)  # type: ignore[arg-type]


def test_loader_rejects_oversized_and_duplicate_key_documents() -> None:
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(
            b" " * (MAX_EVIDENCE_DOCUMENT_BYTES + 1)
        )
    duplicate = _document()[:-1] + b',"branch":"feature/phase-8"}'
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(duplicate)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("evidence_type", "wrong"),
        ("schema_version", 2),
        ("schema_version", True),
        ("provenance", "synthetic_injected_inventory_evidence"),
        ("branch", "main"),
        ("head", "0" * 40),
        ("step232_package_manifest_sha256", "0" * 64),
        ("accepted_step232_state_manifest_sha256", "0" * 64),
        ("step232_inventory_loader_sha256", "0" * 64),
        ("step232_inventory_probe_sha256", "0" * 64),
        ("git_executable_sha256", "A" * 64),
        ("accepted_overlay_path_count", 219),
        ("accepted_overlay_projection_sha256", "0" * 64),
        ("combined_source_path_count", 220),
    ],
)
def test_loader_rejects_identity_count_or_digest_tampering(
    name: str, replacement: object
) -> None:
    value = _mapping()
    value[name] = replacement
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


@pytest.mark.parametrize(
    ("path", "mode", "object_type"),
    [
        ("/package.json", "100644", "blob"),
        ("C:/package.json", "100644", "blob"),
        ("frontend//package.json", "100644", "blob"),
        ("frontend/./package.json", "100644", "blob"),
        ("frontend/../package.json", "100644", "blob"),
        ("frontend/package.json/", "100644", "blob"),
        ("frontend\\package.json", "100644", "blob"),
        ('frontend/a"b.txt', "100644", "blob"),
        ("frontend/a:b.txt", "100644", "blob"),
        ("frontend/a*b.txt", "100644", "blob"),
        ("frontend/a?b.txt", "100644", "blob"),
        ("frontend/a<b.txt", "100644", "blob"),
        ("frontend/a>b.txt", "100644", "blob"),
        ("frontend/a|b.txt", "100644", "blob"),
        ("frontend/ leading.txt", "100644", "blob"),
        ("frontend/trailing.txt ", "100644", "blob"),
        ("frontend/trailing.", "100644", "blob"),
        ("frontend/CON.txt", "100644", "blob"),
        ("frontend/COM1 .txt", "100644", "blob"),
        ("frontend/CONIN$.txt", "100644", "blob"),
        ("frontend/caf\u00e9.txt", "100644", "blob"),
        ("frontend/package.json\x00", "100644", "blob"),
        ("frontend/package.json\t", "100644", "blob"),
        ("frontend/package.json\r", "100644", "blob"),
        ("frontend/package.json\n", "100644", "blob"),
        ("frontend/package.json\x7f", "100644", "blob"),
        ("frontend/package.json", "120000", "blob"),
        ("frontend/package.json", "160000", "commit"),
    ],
)
def test_loader_rejects_unsafe_path_symlink_or_gitlink(
    path: str, mode: str, object_type: str
) -> None:
    value = _mapping()
    value["head_entries"] = [
        _head(path, mode=mode, object_type=object_type)
    ]
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


def test_loader_rejects_unsorted_duplicate_and_case_colliding_head_paths() -> None:
    for entries in (
        [_head("b.txt"), _head("a.txt", object_id="2" * 40)],
        [_head(), _head()],
        [_head("Readme.md"), _head("README.md", object_id="2" * 40)],
        [_head("FOO/a.txt"), _head("foo/b.txt", object_id="2" * 40)],
        [_head("foo"), _head("foo/bar.txt", object_id="2" * 40)],
    ):
        value = _mapping()
        value["head_entries"] = entries
        value["combined_source_path_count"] = ACCEPTED_OVERLAY_PATH_COUNT + 2
        with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
            load_entra_calling_client_msal_frontend_host_live_inventory(
                _document(value)
            )


def test_loader_rejects_overlay_overlap_larger_than_head_projection() -> None:
    value = _mapping()
    value["accepted_overlay_paths_overlapping_head"] = 2
    value["combined_source_path_count"] = ACCEPTED_OVERLAY_PATH_COUNT - 1
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


def test_loader_rejects_missing_marker_and_case_spoofed_marker() -> None:
    missing = _mapping(host=True)
    missing["markers"] = []
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(
            _document(missing)
        )
    spoof = _mapping()
    spoof["head_entries"] = [_head("frontend/PACKAGE.JSON")]
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(
            _document(spoof)
        )


def test_loader_rejects_marker_within_node_modules() -> None:
    value = _mapping(host=True)
    value["head_entries"] = [_head("node_modules/package.json")]
    value["markers"] = [_marker("node_modules/package.json")]
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


def test_loader_rejects_fabricated_accepted_overlay_marker() -> None:
    value = _mapping()
    value["markers"] = [
        _marker(source_domain="accepted_overlay", object_id=None)
    ]
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


def test_loader_rejects_multiple_roots_locks_and_orphan_lock() -> None:
    multiple_roots = _mapping(host=True)
    multiple_roots["head_entries"] = [
        _head("frontend/package.json"),
        _head("web/package.json", object_id="2" * 40),
    ]
    multiple_roots["combined_source_path_count"] = ACCEPTED_OVERLAY_PATH_COUNT + 2
    multiple_roots["markers"] = [
        _marker(),
        _marker("web/package.json", sha256="3" * 64, object_id="2" * 40),
    ]
    orphan = _mapping()
    orphan["head_entries"] = [_head("package-lock.json")]
    orphan["markers"] = [
        _marker("package-lock.json", role="dependency_lock")
    ]
    for value in (multiple_roots, orphan):
        with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
            load_entra_calling_client_msal_frontend_host_live_inventory(
                _document(value)
            )


@pytest.mark.parametrize(
    "name",
    [
        "live_repository_accessed",
        "filesystem_io_performed",
        "git_process_started",
        "git_head_projection_complete",
        "accepted_overlay_projection_complete",
        "before_after_accepted_source_projection_identical",
        "git_object_bytes_read_only_for_allowlisted_markers",
        "git_status_worktree_enumeration_performed",
        "working_tree_marker_content_read",
        "tracked_git_symlink_or_gitlink_observed",
        "package_manager_process_started",
        "remote_git_or_package_network_operation_requested",
        "inventory_accepted_source_projection_changed",
    ],
)
def test_loader_rejects_required_or_forbidden_flag_flip(name: str) -> None:
    value = _mapping()
    value[name] = not value[name]
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError):
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))


def test_loader_resanitizes_errors_without_echoing_paths() -> None:
    value = _mapping(host=True)
    value["markers"] = []
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryLoaderError) as captured:
        load_entra_calling_client_msal_frontend_host_live_inventory(_document(value))
    assert captured.value.__cause__ is not None
    assert "frontend/package.json" not in str(captured.value)
