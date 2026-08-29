"""Step 232 bounded synthetic frontend-host inventory evidence loader.

The loader validates caller-supplied inventory evidence only.  It deliberately
contains no filesystem, Git, subprocess, package-manager, browser, or network
implementation; a successor step must add and separately approve any live
repository reader.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

EVIDENCE_TYPE = "engineer4me_frontend_host_inventory_evidence"
SCHEMA_VERSION = 1
EVIDENCE_PROVENANCE = "synthetic_injected_inventory_evidence"
APPROVED_BRANCH = "feature/phase-8"
APPROVED_HEAD = "89b257fbd72333f17367be0aee82d6157775df33"

MAX_TRACKED_PATHS = 4096
MAX_CANDIDATE_ROOTS = 1
MAX_INSPECTED_FILES = 128
MAX_PATH_BYTES = 512
MAX_SINGLE_FILE_BYTES = 1_048_576
MAX_TOTAL_INSPECTED_BYTES = 8_388_608

ALLOWED_FILE_ROLES = (
    "package_manifest",
    "dependency_lock",
    "workspace_configuration",
    "package_manager_marker",
    "runtime_engine_declaration",
    "build_or_bundler_configuration",
    "typescript_configuration",
    "html_application_shell",
    "javascript_or_typescript_entrypoint",
    "service_worker_registration",
    "public_asset_manifest",
)
ALLOWED_PACKAGE_MANAGERS = ("none", "npm", "pnpm", "yarn", "bun", "unknown")
ALLOWED_LOCKFILE_KINDS = (
    "none",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "unknown",
)
FORBIDDEN_PATH_SEGMENTS = (".git", "node_modules")
FORBIDDEN_SENSITIVE_BASENAMES = (
    ".npmrc",
    ".yarnrc",
    ".netrc",
    ".pypirc",
    ".git-credentials",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
)


class EntraCallingClientMSALFrontendHostInventoryLoaderError(ValueError):
    """Sanitized Step 232 evidence validation failure."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_canonical_path(value: object, *, allow_repository_root: bool = False) -> bool:
    if type(value) is not str:
        return False
    if allow_repository_root and value == ".":
        return True
    if not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        return False
    if value.startswith("/") or value.endswith("/") or "//" in value or "\\" in value:
        return False
    if value.startswith('"') or value.endswith('"'):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return False
    return all(
        character.isascii()
        and (character.isalnum() or character in "._-@+()[]")
        for segment in segments
        for character in segment
    )


def _is_forbidden_inventory_path(path: str) -> bool:
    segments = tuple(segment.casefold() for segment in path.split("/"))
    basename = segments[-1]
    return (
        any(segment in FORBIDDEN_PATH_SEGMENTS for segment in segments)
        or basename.startswith(".env")
        or basename in FORBIDDEN_SENSITIVE_BASENAMES
        or "secret" in basename
        or "credential" in basename
    )


def _path_in_root(path: str, root: str) -> bool:
    return root == "." or path.startswith(root + "/")


def _root_package_manifest(root: str) -> str:
    return "package.json" if root == "." else root + "/package.json"


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostInventoryFileEvidence:
    path: str
    role: Literal[
        "package_manifest",
        "dependency_lock",
        "workspace_configuration",
        "package_manager_marker",
        "runtime_engine_declaration",
        "build_or_bundler_configuration",
        "typescript_configuration",
        "html_application_shell",
        "javascript_or_typescript_entrypoint",
        "service_worker_registration",
        "public_asset_manifest",
    ]
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            not _is_canonical_path(self.path)
            or _is_forbidden_inventory_path(self.path)
            or type(self.role) is not str
            or self.role not in ALLOWED_FILE_ROLES
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= MAX_SINGLE_FILE_BYTES
            or not _is_sha256(self.sha256)
        ):
            raise ValueError("frontend-host inventory file evidence is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostInventoryEvidence:
    evidence_type: str
    schema_version: int
    provenance: str
    branch: str
    head: str
    repository_root_sha256: str
    tracked_path_count: int
    candidate_roots: tuple[str, ...]
    package_manager: str
    lockfile_kind: str
    files: tuple[EntraCallingClientMSALFrontendHostInventoryFileEvidence, ...]
    git_tracked_projection_complete: bool
    untracked_content_included: bool
    symlink_or_reparse_point_observed: bool
    submodule_observed: bool
    nested_repository_observed: bool
    git_worktree_indirection_observed: bool
    case_collision_observed: bool
    environment_file_content_read: bool
    secret_value_collected: bool
    live_repository_accessed: bool
    filesystem_io_performed: bool
    git_process_started: bool
    package_manager_process_started: bool
    network_io_performed: bool
    repository_mutation_performed: bool

    def __post_init__(self) -> None:
        constants = {
            "evidence_type": EVIDENCE_TYPE,
            "schema_version": SCHEMA_VERSION,
            "provenance": EVIDENCE_PROVENANCE,
            "branch": APPROVED_BRANCH,
            "head": APPROVED_HEAD,
        }
        if any(getattr(self, name) != expected for name, expected in constants.items()):
            raise ValueError("frontend-host inventory evidence identity is invalid")
        if (
            not _is_sha256(self.repository_root_sha256)
            or type(self.tracked_path_count) is not int
            or not 0 <= self.tracked_path_count <= MAX_TRACKED_PATHS
            or type(self.candidate_roots) is not tuple
            or len(self.candidate_roots) > MAX_CANDIDATE_ROOTS
            or type(self.package_manager) is not str
            or self.package_manager not in ALLOWED_PACKAGE_MANAGERS
            or type(self.lockfile_kind) is not str
            or self.lockfile_kind not in ALLOWED_LOCKFILE_KINDS
            or type(self.files) is not tuple
            or len(self.files) > MAX_INSPECTED_FILES
            or any(
                type(item)
                is not EntraCallingClientMSALFrontendHostInventoryFileEvidence
                for item in self.files
            )
        ):
            raise ValueError("frontend-host inventory evidence shape is invalid")

        for root in self.candidate_roots:
            if not _is_canonical_path(root, allow_repository_root=True):
                raise ValueError("frontend-host candidate root is invalid")
        if len(set(self.candidate_roots)) != len(self.candidate_roots) or len(
            {root.casefold() for root in self.candidate_roots}
        ) != len(self.candidate_roots):
            raise ValueError("frontend-host candidate roots collide")

        paths = tuple(item.path for item in self.files)
        if len(set(paths)) != len(paths) or len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("frontend-host inventory paths collide")
        if sum(item.size_bytes for item in self.files) > MAX_TOTAL_INSPECTED_BYTES:
            raise ValueError("frontend-host inventory byte total is invalid")
        if self.tracked_path_count < len(self.files):
            raise ValueError("frontend-host tracked-path count is invalid")

        package_manifests = tuple(
            item.path for item in self.files if item.role == "package_manifest"
        )
        lockfiles = tuple(item.path for item in self.files if item.role == "dependency_lock")
        if len(package_manifests) != len(self.candidate_roots) or len(lockfiles) > 1:
            raise ValueError("frontend-host manifest or lockfile cardinality is invalid")
        for root in self.candidate_roots:
            if _root_package_manifest(root) not in package_manifests:
                raise ValueError("frontend-host root is not derived from package manifest")
        if any(
            not any(_path_in_root(item.path, root) for root in self.candidate_roots)
            for item in self.files
        ):
            raise ValueError("frontend-host inventory path is outside candidate root")

        if not self.candidate_roots:
            if self.files or self.package_manager != "none" or self.lockfile_kind != "none":
                raise ValueError("frontend-host absent evidence is inconsistent")
        else:
            if self.package_manager == "none":
                raise ValueError("frontend-host package-manager evidence is inconsistent")
            if self.lockfile_kind == "none" and lockfiles:
                raise ValueError("frontend-host lockfile evidence is inconsistent")
            if self.lockfile_kind != "none" and len(lockfiles) != 1:
                raise ValueError("frontend-host lockfile evidence is incomplete")
            if lockfiles and lockfiles[0].split("/")[-1] != self.lockfile_kind:
                raise ValueError("frontend-host lockfile kind does not match path")

        required_true = ("git_tracked_projection_complete",)
        required_false = (
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
        )
        if any(
            type(getattr(self, name)) is not bool or not getattr(self, name)
            for name in required_true
        ):
            raise ValueError("frontend-host inventory completeness evidence is invalid")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError("frontend-host inventory side-effect evidence is invalid")


def validate_entra_calling_client_msal_frontend_host_inventory_evidence(
    evidence: EntraCallingClientMSALFrontendHostInventoryEvidence,
) -> EntraCallingClientMSALFrontendHostInventoryEvidence:
    """Return only exact, fully validated synthetic inventory evidence."""

    try:
        if type(evidence) is not EntraCallingClientMSALFrontendHostInventoryEvidence:
            raise TypeError("exact frontend-host inventory evidence is required")
        evidence.__post_init__()
        return evidence
    except (TypeError, ValueError) as error:
        raise EntraCallingClientMSALFrontendHostInventoryLoaderError(
            "frontend-host inventory evidence validation failed"
        ) from error


__all__ = [
    "ALLOWED_FILE_ROLES",
    "ALLOWED_LOCKFILE_KINDS",
    "ALLOWED_PACKAGE_MANAGERS",
    "APPROVED_BRANCH",
    "APPROVED_HEAD",
    "EVIDENCE_PROVENANCE",
    "EVIDENCE_TYPE",
    "MAX_CANDIDATE_ROOTS",
    "MAX_INSPECTED_FILES",
    "MAX_PATH_BYTES",
    "MAX_SINGLE_FILE_BYTES",
    "MAX_TOTAL_INSPECTED_BYTES",
    "MAX_TRACKED_PATHS",
    "SCHEMA_VERSION",
    "EntraCallingClientMSALFrontendHostInventoryEvidence",
    "EntraCallingClientMSALFrontendHostInventoryFileEvidence",
    "EntraCallingClientMSALFrontendHostInventoryLoaderError",
    "validate_entra_calling_client_msal_frontend_host_inventory_evidence",
]
