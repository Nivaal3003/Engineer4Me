"""Step 233 controlled local Git-object frontend-host inventory loader.

The loader consumes only the bounded in-memory projection produced by the
reviewed Step 233 installer.  It does not walk the working filesystem, start a
process, execute a package manager, or perform network I/O.  Live provenance
belongs to the complete installer execution, not to a rendered receipt alone.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_loader import (
    MAX_CANDIDATE_ROOTS,
    MAX_INSPECTED_FILES,
    MAX_PATH_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_INSPECTED_BYTES,
    MAX_TRACKED_PATHS,
)

EVIDENCE_TYPE = "engineer4me_frontend_host_live_git_inventory_evidence"
SCHEMA_VERSION = 1
EVIDENCE_PROVENANCE = "controlled_local_git_head_object_inventory"
APPROVED_BRANCH = "feature/phase-8"
APPROVED_HEAD = "89b257fbd72333f17367be0aee82d6157775df33"
STEP232_PACKAGE_MANIFEST_SHA256 = (
    "241edaaf2c07f763ab94fba7ba57bc49ae95fda3201cf13eb1cfdc95d5555e00"
)
STEP232_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "bbc241458c79d85cce537fd89d08f2a46beb0728eea0083cdfbaffe7581251bc"
)
STEP232_INVENTORY_LOADER_SHA256 = (
    "2bbbe6cbff726d86bfdd0f48c978fb02a932ef4d12198e951aa088e8a825a76a"
)
STEP232_INVENTORY_PROBE_SHA256 = (
    "7cb9d6f4340f0b7be0d1ce16d3a26deb1e1ce34267384c98bda411a28525901b"
)
ACCEPTED_OVERLAY_PATH_COUNT = 220
MAX_EVIDENCE_DOCUMENT_BYTES = 2_097_152
WINDOWS_FORBIDDEN_PATH_CHARACTERS = frozenset('<>:"\\|?*')
WINDOWS_RESERVED_PATH_STEMS = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)

MARKER_BASENAME_ROLES: dict[str, str] = {
    "package.json": "package_manifest",
    "package-lock.json": "dependency_lock",
    "npm-shrinkwrap.json": "dependency_lock",
    "pnpm-lock.yaml": "dependency_lock",
    "yarn.lock": "dependency_lock",
    "bun.lock": "dependency_lock",
    "bun.lockb": "dependency_lock",
    "pnpm-workspace.yaml": "workspace_configuration",
    "lerna.json": "workspace_configuration",
    ".nvmrc": "runtime_engine_declaration",
    ".node-version": "runtime_engine_declaration",
    "vite.config.js": "build_or_bundler_configuration",
    "vite.config.mjs": "build_or_bundler_configuration",
    "vite.config.cjs": "build_or_bundler_configuration",
    "vite.config.ts": "build_or_bundler_configuration",
    "vite.config.mts": "build_or_bundler_configuration",
    "vite.config.cts": "build_or_bundler_configuration",
    "webpack.config.js": "build_or_bundler_configuration",
    "webpack.config.cjs": "build_or_bundler_configuration",
    "webpack.config.mjs": "build_or_bundler_configuration",
    "webpack.config.ts": "build_or_bundler_configuration",
    "rollup.config.js": "build_or_bundler_configuration",
    "rollup.config.mjs": "build_or_bundler_configuration",
    "rollup.config.ts": "build_or_bundler_configuration",
    "next.config.js": "build_or_bundler_configuration",
    "next.config.mjs": "build_or_bundler_configuration",
    "next.config.ts": "build_or_bundler_configuration",
    "angular.json": "build_or_bundler_configuration",
    "svelte.config.js": "build_or_bundler_configuration",
    "svelte.config.ts": "build_or_bundler_configuration",
    "astro.config.mjs": "build_or_bundler_configuration",
    "astro.config.ts": "build_or_bundler_configuration",
    "nuxt.config.js": "build_or_bundler_configuration",
    "nuxt.config.ts": "build_or_bundler_configuration",
    "tsconfig.json": "typescript_configuration",
    "index.html": "html_application_shell",
    "manifest.webmanifest": "public_asset_manifest",
}
LOCKFILE_MANAGERS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lock": "bun",
    "bun.lockb": "bun",
}


class EntraCallingClientMSALFrontendHostLiveInventoryLoaderError(ValueError):
    """Sanitized Step 233 live inventory evidence failure."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_object_id(value: object) -> bool:
    return (
        type(value) is str
        and len(value) in (40, 64)
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
        b"Engineer4Me-Step233-v2\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


def _exact_keys(value: object, expected: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError("live inventory object keys are not exact")
    return value


def _is_canonical_source_path(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        return False
    if value.startswith("/") or value.endswith("/") or "//" in value:
        return False
    if any(
        not 32 <= ord(character) <= 126
        or character in WINDOWS_FORBIDDEN_PATH_CHARACTERS
        for character in value
    ):
        return False
    segments = value.split("/")
    if any(
        segment in ("", ".", "..")
        or segment != segment.strip()
        or segment.endswith(".")
        or segment.split(".", 1)[0].rstrip(" .").casefold()
        in WINDOWS_RESERVED_PATH_STEMS
        for segment in segments
    ):
        return False
    return True


def _paths_have_casefold_prefix_collision(paths: tuple[str, ...]) -> bool:
    prefixes: dict[str, str] = {}
    complete_paths = {path.casefold() for path in paths}
    for path in paths:
        segments = path.split("/")
        for length in range(1, len(segments) + 1):
            prefix = "/".join(segments[:length])
            key = prefix.casefold()
            if key in prefixes and prefixes[key] != prefix:
                return True
            if length < len(segments) and key in complete_paths:
                return True
            prefixes[key] = prefix
    return False


def _is_forbidden_marker_path(path: str) -> bool:
    segments = tuple(segment.casefold() for segment in path.split("/"))
    basename = segments[-1]
    return (
        any(segment in (".git", "node_modules") for segment in segments)
        or basename.startswith(".env")
        or "secret" in basename
        or "credential" in basename
    )


def _root(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else "."


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _inside(path: str, root: str) -> bool:
    return root == "." or path.startswith(root + "/")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry:
    mode: str
    object_type: Literal["blob"]
    object_id: str
    path: str


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence:
    source_domain: Literal["git_head"]
    path: str
    role: str
    size_bytes: int
    sha256: str
    object_id: str | None


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostLiveInventoryEvidence:
    evidence_type: str
    schema_version: int
    provenance: str
    branch: str
    head: str
    head_tree_object_id: str
    step232_package_manifest_sha256: str
    accepted_step232_state_manifest_sha256: str
    step232_inventory_loader_sha256: str
    step232_inventory_probe_sha256: str
    git_executable_sha256: str
    working_tree_status_before_sha256: str
    working_tree_status_after_sha256: str
    accepted_overlay_path_count: int
    accepted_overlay_projection_sha256: str
    accepted_overlay_paths_overlapping_head: int
    combined_source_path_count: int
    installer_asserted_combined_source_path_projection_sha256: str
    head_entries: tuple[EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry, ...]
    markers: tuple[EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence, ...]
    live_repository_accessed: bool
    filesystem_io_performed: bool
    git_process_started: bool
    git_head_projection_complete: bool
    accepted_overlay_projection_complete: bool
    before_after_accepted_source_projection_identical: bool
    git_object_bytes_read_only_for_allowlisted_markers: bool
    git_status_worktree_enumeration_performed: bool
    working_tree_marker_content_read: bool
    tracked_git_symlink_or_gitlink_observed: bool
    package_manager_process_started: bool
    remote_git_or_package_network_operation_requested: bool
    inventory_accepted_source_projection_changed: bool


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostLiveInventoryResult:
    evidence_document_sha256: str
    head_tree_projection_sha256: str
    accepted_overlay_projection_sha256: str
    installer_asserted_combined_source_path_projection_sha256: str
    marker_inventory_projection_sha256: str
    candidate_root_projection_sha256: str
    git_executable_sha256: str
    working_tree_status_projection_sha256: str
    head_tree_path_count: int
    accepted_overlay_path_count: int
    combined_source_path_count: int
    marker_file_count: int
    marker_total_bytes: int
    candidate_root_count: int
    package_manifest_count: int
    dependency_lock_count: int
    package_manager: str
    lockfile_kind: str
    disposition: str
    candidate_roots: tuple[str, ...]


_ROOT_KEYS = {
    "evidence_type",
    "schema_version",
    "provenance",
    "branch",
    "head",
    "head_tree_object_id",
    "step232_package_manifest_sha256",
    "accepted_step232_state_manifest_sha256",
    "step232_inventory_loader_sha256",
    "step232_inventory_probe_sha256",
    "git_executable_sha256",
    "working_tree_status_before_sha256",
    "working_tree_status_after_sha256",
    "accepted_overlay_path_count",
    "accepted_overlay_projection_sha256",
    "accepted_overlay_paths_overlapping_head",
    "combined_source_path_count",
    "installer_asserted_combined_source_path_projection_sha256",
    "head_entries",
    "markers",
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
}


def _parse_head_entries(
    value: object,
) -> tuple[EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry, ...]:
    if type(value) is not list or not 0 < len(value) <= MAX_TRACKED_PATHS:
        raise ValueError("live inventory head entry count is invalid")
    entries: list[EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry] = []
    for raw in value:
        item = _exact_keys(raw, {"mode", "object_type", "object_id", "path"})
        if (
            type(item["mode"]) is not str
            or item["mode"] not in ("100644", "100755")
            or item["object_type"] != "blob"
            or not _is_git_object_id(item["object_id"])
            or not _is_canonical_source_path(item["path"])
        ):
            raise ValueError("live inventory head entry is invalid")
        entries.append(
            EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry(
                mode=item["mode"],  # type: ignore[arg-type]
                object_type=item["object_type"],  # type: ignore[arg-type]
                object_id=item["object_id"],  # type: ignore[arg-type]
                path=item["path"],  # type: ignore[arg-type]
            )
        )
    paths = tuple(item.path for item in entries)
    if paths != tuple(sorted(paths)):
        raise ValueError("live inventory head entries are not canonically ordered")
    if (
        len(set(paths)) != len(paths)
        or len({path.casefold() for path in paths}) != len(paths)
        or _paths_have_casefold_prefix_collision(paths)
    ):
        raise ValueError("live inventory head paths collide")
    return tuple(entries)


def _parse_markers(
    value: object,
) -> tuple[EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence, ...]:
    if type(value) is not list or len(value) > MAX_INSPECTED_FILES:
        raise ValueError("live inventory marker count is invalid")
    markers: list[EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence] = []
    for raw in value:
        item = _exact_keys(
            raw,
            {"source_domain", "path", "role", "size_bytes", "sha256", "object_id"},
        )
        if (
            item["source_domain"] != "git_head"
            or type(item["role"]) is not str
            or type(item["size_bytes"]) is not int
            or type(item["size_bytes"]) is bool
            or not 0 <= item["size_bytes"] <= MAX_SINGLE_FILE_BYTES
            or not _is_canonical_source_path(item["path"])
            or _is_forbidden_marker_path(item["path"])
            or not _is_sha256(item["sha256"])
            or not _is_git_object_id(item["object_id"])
        ):
            raise ValueError("live inventory marker evidence is invalid")
        marker = EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence(
            source_domain=item["source_domain"],  # type: ignore[arg-type]
            path=item["path"],  # type: ignore[arg-type]
            role=item["role"],  # type: ignore[arg-type]
            size_bytes=item["size_bytes"],  # type: ignore[arg-type]
            sha256=item["sha256"],  # type: ignore[arg-type]
            object_id=item["object_id"],  # type: ignore[arg-type]
        )
        markers.append(marker)
    paths = tuple(item.path for item in markers)
    if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
        raise ValueError("live inventory markers are not unique and ordered")
    if sum(item.size_bytes for item in markers) > MAX_TOTAL_INSPECTED_BYTES:
        raise ValueError("live inventory marker byte total is invalid")
    return tuple(markers)


def load_entra_calling_client_msal_frontend_host_live_inventory(
    document: bytes,
) -> tuple[
    EntraCallingClientMSALFrontendHostLiveInventoryEvidence,
    EntraCallingClientMSALFrontendHostLiveInventoryResult,
]:
    """Validate one exact controlled-installer Git-object inventory projection."""

    try:
        if type(document) is not bytes or not document or len(document) > MAX_EVIDENCE_DOCUMENT_BYTES:
            raise ValueError("live inventory evidence document size is invalid")
        parsed = _exact_keys(json.loads(document, object_pairs_hook=_pairs), _ROOT_KEYS)
        if type(parsed["schema_version"]) is not int:
            raise ValueError("live inventory schema version type is invalid")
        constants = {
            "evidence_type": EVIDENCE_TYPE,
            "schema_version": SCHEMA_VERSION,
            "provenance": EVIDENCE_PROVENANCE,
            "branch": APPROVED_BRANCH,
            "head": APPROVED_HEAD,
            "step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
            "accepted_step232_state_manifest_sha256": STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
            "step232_inventory_loader_sha256": STEP232_INVENTORY_LOADER_SHA256,
            "step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
        }
        if any(parsed[name] != expected for name, expected in constants.items()):
            raise ValueError("live inventory approved identity is invalid")
        if (
            not _is_git_object_id(parsed["head_tree_object_id"])
            or not _is_sha256(parsed["git_executable_sha256"])
            or not _is_sha256(parsed["working_tree_status_before_sha256"])
            or parsed["working_tree_status_before_sha256"]
            != parsed["working_tree_status_after_sha256"]
        ):
            raise ValueError("live inventory repository identity is invalid")

        required_true = (
            "live_repository_accessed",
            "filesystem_io_performed",
            "git_process_started",
            "git_head_projection_complete",
            "accepted_overlay_projection_complete",
            "before_after_accepted_source_projection_identical",
            "git_object_bytes_read_only_for_allowlisted_markers",
            "git_status_worktree_enumeration_performed",
        )
        required_false = (
            "working_tree_marker_content_read",
            "tracked_git_symlink_or_gitlink_observed",
            "package_manager_process_started",
            "remote_git_or_package_network_operation_requested",
            "inventory_accepted_source_projection_changed",
        )
        if any(type(parsed[name]) is not bool or not parsed[name] for name in required_true):
            raise ValueError("live inventory required evidence flag is invalid")
        if any(type(parsed[name]) is not bool or parsed[name] for name in required_false):
            raise ValueError("live inventory forbidden evidence flag is invalid")

        if (
            type(parsed["accepted_overlay_path_count"]) is not int
            or type(parsed["accepted_overlay_path_count"]) is bool
            or parsed["accepted_overlay_path_count"] != ACCEPTED_OVERLAY_PATH_COUNT
            or parsed["accepted_overlay_projection_sha256"]
            != STEP232_ACCEPTED_STATE_MANIFEST_SHA256
            or type(parsed["accepted_overlay_paths_overlapping_head"]) is not int
            or type(parsed["accepted_overlay_paths_overlapping_head"]) is bool
            or not 0
            <= parsed["accepted_overlay_paths_overlapping_head"]
            <= ACCEPTED_OVERLAY_PATH_COUNT
            or type(parsed["combined_source_path_count"]) is not int
            or type(parsed["combined_source_path_count"]) is bool
            or not _is_sha256(
                parsed["installer_asserted_combined_source_path_projection_sha256"]
            )
        ):
            raise ValueError("live inventory accepted overlay projection is invalid")

        head_entries = _parse_head_entries(parsed["head_entries"])
        markers = _parse_markers(parsed["markers"])
        if parsed["accepted_overlay_paths_overlapping_head"] > len(head_entries):
            raise ValueError("live inventory overlay overlap count is invalid")
        head_by_path = {item.path: item for item in head_entries}
        expected_combined_count = (
            len(head_entries)
            + ACCEPTED_OVERLAY_PATH_COUNT
            - parsed["accepted_overlay_paths_overlapping_head"]
        )
        if (
            parsed["combined_source_path_count"] != expected_combined_count
            or expected_combined_count > MAX_TRACKED_PATHS + ACCEPTED_OVERLAY_PATH_COUNT
        ):
            raise ValueError("live inventory combined path count is invalid")

        expected_markers: list[tuple[str, str]] = []
        marker_casefolds = {name.casefold(): name for name in MARKER_BASENAME_ROLES}
        for path in head_by_path:
            basename = _basename(path)
            if basename.casefold() in marker_casefolds and basename not in MARKER_BASENAME_ROLES:
                raise ValueError("live inventory marker case spoof is invalid")
            role = MARKER_BASENAME_ROLES.get(basename)
            if role is not None:
                expected_markers.append((path, role))
        if tuple(item.path for item in markers) != tuple(path for path, _ in expected_markers):
            raise ValueError("live inventory marker projection is incomplete")

        expected_by_path = dict(expected_markers)
        for marker in markers:
            basename = _basename(marker.path)
            if basename.casefold() in marker_casefolds and basename not in MARKER_BASENAME_ROLES:
                raise ValueError("live inventory marker case spoof is invalid")
            role = MARKER_BASENAME_ROLES.get(basename)
            if role is None or marker.role != role:
                raise ValueError("live inventory marker classification is invalid")
            if (
                marker.path not in expected_by_path
                or marker.object_id != head_by_path[marker.path].object_id
            ):
                raise ValueError("live inventory Git marker identity is invalid")

        package_manifests = tuple(
            item.path for item in markers if item.role == "package_manifest"
        )
        if len(package_manifests) > MAX_CANDIDATE_ROOTS:
            raise ValueError("live inventory candidate root cardinality is invalid")
        candidate_roots = tuple(_root(path) for path in package_manifests)
        dependency_locks = tuple(
            item.path for item in markers if item.role == "dependency_lock"
        )
        if len(dependency_locks) > 1:
            raise ValueError("live inventory lockfile cardinality is invalid")
        if not candidate_roots and dependency_locks:
            raise ValueError("live inventory orphan lockfile is invalid")
        if candidate_roots and any(
            _root(path) != candidate_roots[0] for path in dependency_locks
        ):
            raise ValueError("live inventory lockfile is outside candidate root")
        if any(
            not _inside(item.path, candidate_roots[0])
            for item in markers
            if candidate_roots
            and item.role
            in ("workspace_configuration", "package_manager_marker")
        ):
            raise ValueError("live inventory package marker is outside candidate root")

        lockfile_kind = _basename(dependency_locks[0]) if dependency_locks else "none"
        package_manager = (
            LOCKFILE_MANAGERS[lockfile_kind]
            if dependency_locks
            else ("unknown" if candidate_roots else "none")
        )
        disposition = (
            "live_inventory_complete_no_package_manifest_candidate_in_accepted_source"
            if not candidate_roots
            else "live_inventory_complete_single_unselected_package_manifest_candidate"
        )
        evidence = EntraCallingClientMSALFrontendHostLiveInventoryEvidence(
            **{
                **{name: parsed[name] for name in _ROOT_KEYS if name not in {"head_entries", "markers"}},
                "head_entries": head_entries,
                "markers": markers,
            }
        )  # type: ignore[arg-type]
        result = EntraCallingClientMSALFrontendHostLiveInventoryResult(
            evidence_document_sha256=hashlib.sha256(_canonical(parsed)).hexdigest(),
            head_tree_projection_sha256=_framed(
                "git-head-tree",
                tuple(
                    {
                        "mode": item.mode,
                        "object_type": item.object_type,
                        "object_id": item.object_id,
                        "path": item.path,
                    }
                    for item in head_entries
                ),
            ),
            accepted_overlay_projection_sha256=STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
            installer_asserted_combined_source_path_projection_sha256=parsed[
                "installer_asserted_combined_source_path_projection_sha256"
            ],  # type: ignore[arg-type]
            marker_inventory_projection_sha256=_framed(
                "marker-inventory",
                tuple(
                    {
                        "source_domain": item.source_domain,
                        "path": item.path,
                        "role": item.role,
                        "size_bytes": item.size_bytes,
                        "sha256": item.sha256,
                        "object_id": item.object_id,
                    }
                    for item in markers
                ),
            ),
            candidate_root_projection_sha256=_framed(
                "candidate-roots", candidate_roots
            ),
            git_executable_sha256=parsed["git_executable_sha256"],  # type: ignore[arg-type]
            working_tree_status_projection_sha256=parsed[
                "working_tree_status_before_sha256"
            ],  # type: ignore[arg-type]
            head_tree_path_count=len(head_entries),
            accepted_overlay_path_count=ACCEPTED_OVERLAY_PATH_COUNT,
            combined_source_path_count=parsed["combined_source_path_count"],  # type: ignore[arg-type]
            marker_file_count=len(markers),
            marker_total_bytes=sum(item.size_bytes for item in markers),
            candidate_root_count=len(candidate_roots),
            package_manifest_count=len(package_manifests),
            dependency_lock_count=len(dependency_locks),
            package_manager=package_manager,
            lockfile_kind=lockfile_kind,
            disposition=disposition,
            candidate_roots=candidate_roots,
        )
        return evidence, result
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendHostLiveInventoryLoaderError(
            "controlled local frontend-host live inventory validation failed"
        ) from error


__all__ = [
    "ACCEPTED_OVERLAY_PATH_COUNT",
    "APPROVED_BRANCH",
    "APPROVED_HEAD",
    "EVIDENCE_PROVENANCE",
    "EVIDENCE_TYPE",
    "LOCKFILE_MANAGERS",
    "MARKER_BASENAME_ROLES",
    "MAX_EVIDENCE_DOCUMENT_BYTES",
    "SCHEMA_VERSION",
    "STEP232_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP232_INVENTORY_LOADER_SHA256",
    "STEP232_INVENTORY_PROBE_SHA256",
    "STEP232_PACKAGE_MANIFEST_SHA256",
    "EntraCallingClientMSALFrontendHostLiveInventoryEvidence",
    "EntraCallingClientMSALFrontendHostLiveInventoryHeadEntry",
    "EntraCallingClientMSALFrontendHostLiveInventoryLoaderError",
    "EntraCallingClientMSALFrontendHostLiveInventoryMarkerEvidence",
    "EntraCallingClientMSALFrontendHostLiveInventoryResult",
    "load_entra_calling_client_msal_frontend_host_live_inventory",
]
