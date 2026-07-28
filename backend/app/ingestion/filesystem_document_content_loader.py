"""Safe filesystem content loading for document-ingestion jobs.

The processing orchestrator depends only on the storage-neutral
``DocumentContentLoader`` protocol.  This module supplies the first concrete
runtime adapter without coupling orchestration or API code to MinIO.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final

from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
)


_DEFAULT_MAXIMUM_CONTENT_BYTES: Final[int] = 100 * 1024 * 1024


class FilesystemDocumentContentLoaderError(Exception):
    """Base exception for guarded filesystem-content loading failures."""


class DocumentContentPathError(FilesystemDocumentContentLoaderError):
    """Raised when a document source path is missing or unsafe."""


class DocumentContentNotFoundError(FilesystemDocumentContentLoaderError):
    """Raised when a document source cannot be found as a regular file."""


class DocumentContentTooLargeError(FilesystemDocumentContentLoaderError):
    """Raised when a source exceeds the configured in-memory size limit."""


class DocumentContentReadError(FilesystemDocumentContentLoaderError):
    """Raised when source bytes cannot be read consistently."""


@dataclass(frozen=True, slots=True)
class FilesystemDocumentContentLoaderConfig:
    """Runtime controls for the guarded filesystem adapter."""

    root_directory: Path
    maximum_content_bytes: int = _DEFAULT_MAXIMUM_CONTENT_BYTES

    def __post_init__(self) -> None:
        """Validate and canonicalise the configured storage root."""

        raw_root = str(self.root_directory).strip()

        if not raw_root:
            raise ValueError("root_directory cannot be blank.")

        if (
            isinstance(self.maximum_content_bytes, bool)
            or not isinstance(self.maximum_content_bytes, int)
            or self.maximum_content_bytes < 1
        ):
            raise ValueError(
                "maximum_content_bytes must be a positive integer."
            )

        try:
            resolved_root = Path(raw_root).expanduser().resolve(strict=True)
        except FileNotFoundError as error:
            raise ValueError(
                f"Filesystem content root does not exist: {raw_root}"
            ) from error
        except OSError as error:
            raise ValueError(
                f"Filesystem content root cannot be resolved: {raw_root}"
            ) from error

        if not resolved_root.is_dir():
            raise ValueError(
                f"Filesystem content root is not a directory: {raw_root}"
            )

        object.__setattr__(self, "root_directory", resolved_root)


class FilesystemDocumentContentLoader:
    """Load document bytes from a path confined beneath one storage root."""

    def __init__(
        self,
        config: FilesystemDocumentContentLoaderConfig,
    ) -> None:
        """Initialise the adapter with an already validated configuration."""

        if not isinstance(config, FilesystemDocumentContentLoaderConfig):
            raise TypeError(
                "config must be a FilesystemDocumentContentLoaderConfig."
            )

        self._config = config

    @property
    def config(self) -> FilesystemDocumentContentLoaderConfig:
        """Return the immutable loader configuration."""

        return self._config

    @property
    def root_directory(self) -> Path:
        """Return the canonical filesystem content root."""

        return self._config.root_directory

    def load(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> bytes:
        """Return source bytes after confinement and size checks."""

        source_path = self.resolve_source_path(job, document)

        try:
            declared_size = source_path.stat().st_size
        except OSError as error:
            raise DocumentContentReadError(
                f"Unable to inspect source for {self._document_label(job, document)}."
            ) from error

        maximum_size = self._config.maximum_content_bytes

        if declared_size > maximum_size:
            raise DocumentContentTooLargeError(
                f"Source for {self._document_label(job, document)} contains "
                f"{declared_size} bytes; the limit is {maximum_size} bytes."
            )

        try:
            with source_path.open("rb") as source:
                content = source.read(maximum_size + 1)
        except OSError as error:
            raise DocumentContentReadError(
                f"Unable to read source for {self._document_label(job, document)}."
            ) from error

        if len(content) > maximum_size:
            raise DocumentContentTooLargeError(
                f"Source for {self._document_label(job, document)} exceeded "
                f"the {maximum_size}-byte limit while it was being read."
            )

        if len(content) != declared_size:
            raise DocumentContentReadError(
                f"Source for {self._document_label(job, document)} changed "
                "while it was being read."
            )

        return content

    def resolve_source_path(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> Path:
        """Resolve one relative storage key beneath the configured root."""

        source_reference = document.source_path

        if source_reference is None or not source_reference.strip():
            raise DocumentContentPathError(
                f"A source_path is required for "
                f"{self._document_label(job, document)}."
            )

        source_reference = source_reference.strip()

        if any(ord(character) < 32 for character in source_reference):
            raise DocumentContentPathError(
                f"source_path contains control characters for "
                f"{self._document_label(job, document)}."
            )

        windows_path = PureWindowsPath(source_reference)
        normalised_reference = source_reference.replace("\\", "/")
        posix_path = PurePosixPath(normalised_reference)
        path_parts = normalised_reference.split("/")

        if (
            posix_path.is_absolute()
            or windows_path.is_absolute()
            or bool(windows_path.drive)
        ):
            raise DocumentContentPathError(
                f"source_path must be relative for "
                f"{self._document_label(job, document)}."
            )

        if any(part in {"", ".", ".."} for part in path_parts):
            raise DocumentContentPathError(
                f"source_path contains an unsafe path segment for "
                f"{self._document_label(job, document)}."
            )

        unresolved_path = self.root_directory.joinpath(*path_parts)

        try:
            resolved_path = unresolved_path.resolve(strict=True)
        except FileNotFoundError as error:
            raise DocumentContentNotFoundError(
                f"Source was not found for "
                f"{self._document_label(job, document)}."
            ) from error
        except OSError as error:
            raise DocumentContentReadError(
                f"Source path could not be resolved for "
                f"{self._document_label(job, document)}."
            ) from error

        try:
            resolved_path.relative_to(self.root_directory)
        except ValueError as error:
            raise DocumentContentPathError(
                f"source_path escapes the configured content root for "
                f"{self._document_label(job, document)}."
            ) from error

        if not resolved_path.is_file():
            raise DocumentContentNotFoundError(
                f"Source is not a regular file for "
                f"{self._document_label(job, document)}."
            )

        return resolved_path

    @staticmethod
    def _document_label(
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> str:
        """Return a stable diagnostic label without exposing storage paths."""

        return f"job {job.job_id}, document {document.document_id}"


__all__ = [
    "DocumentContentNotFoundError",
    "DocumentContentPathError",
    "DocumentContentReadError",
    "DocumentContentTooLargeError",
    "FilesystemDocumentContentLoader",
    "FilesystemDocumentContentLoaderConfig",
    "FilesystemDocumentContentLoaderError",
]
