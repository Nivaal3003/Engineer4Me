"""Guarded execution coordination for filesystem-backed ingestion jobs.

The filesystem upload service creates authoritative ingestion jobs and the
filesystem processing runtime executes the complete parser and engineering
pipeline. This module supplies the narrow boundary between those components.

It deliberately contains no FastAPI, queue, or background-task concerns. An
HTTP route, worker, scheduler, or command-line task can use the same service.
Before execution begins, the service:

- accepts only jobs created as filesystem-backed API uploads;
- validates the server-owned job and document storage metadata;
- requires every storage reference to match its opaque UUID and shard layout;
- checks that declared document sizes remain within the upload-time bound;
- prevents concurrent execution of the same job in this process; and
- delegates lifecycle changes and document processing to the shared runtime.

The filesystem content loader remains the final authority for path
confinement, file existence, file size, and checksum verification.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any, Final
from uuid import UUID

from app.ingestion.document_processing_orchestrator import (
    DocumentProcessingStateError,
)
from app.ingestion.filesystem_document_processing_runtime import (
    FilesystemDocumentProcessingRuntime,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
    IngestionSourceType,
)


_JOB_UPLOAD_METADATA_ATTRIBUTE: Final[str] = "engineer4me_upload"
_DOCUMENT_STORAGE_ATTRIBUTE: Final[str] = "engineer4me_storage"
_FILESYSTEM_BACKEND: Final[str] = "filesystem"
_SHA256_HEXADECIMAL_LENGTH: Final[int] = 64
_OPAQUE_IDENTIFIER_HEXADECIMAL_LENGTH: Final[int] = 32
_STORAGE_REFERENCE_PART_COUNT: Final[int] = 3
_STORAGE_SHARD_LENGTH: Final[int] = 2


class FilesystemDocumentExecutionError(Exception):
    """Base exception raised by guarded filesystem job execution."""


class FilesystemDocumentExecutionEligibilityError(
    FilesystemDocumentExecutionError
):
    """Raised when a job is not an authoritative filesystem upload."""


class FilesystemDocumentExecutionConflictError(
    FilesystemDocumentExecutionError
):
    """Raised when the same job is already executing in this process."""


class FilesystemDocumentExecutionStateError(
    FilesystemDocumentExecutionError
):
    """Raised when the runtime cannot safely resume a job's current state."""


class FilesystemDocumentExecutionService:
    """Validate and execute jobs through one shared filesystem runtime."""

    def __init__(
        self,
        *,
        runtime: FilesystemDocumentProcessingRuntime,
    ) -> None:
        """Initialise the coordinator with one fully composed runtime."""

        if not isinstance(
            runtime,
            FilesystemDocumentProcessingRuntime,
        ):
            raise TypeError(
                "runtime must be a "
                "FilesystemDocumentProcessingRuntime."
            )

        self._runtime = runtime
        self._execution_lock = RLock()
        self._active_job_ids: set[UUID] = set()

    @property
    def runtime(self) -> FilesystemDocumentProcessingRuntime:
        """Return the complete processing runtime used by this service."""

        return self._runtime

    @property
    def active_job_ids(self) -> frozenset[UUID]:
        """Return a detached snapshot of jobs executing in this process."""

        with self._execution_lock:
            return frozenset(self._active_job_ids)

    def validate_job(self, job: IngestionJob) -> None:
        """Require authoritative upload metadata for every job document."""

        if not isinstance(job, IngestionJob):
            raise TypeError("job must be an IngestionJob.")

        if job.source_type is not IngestionSourceType.API_UPLOAD:
            raise FilesystemDocumentExecutionEligibilityError(
                "Only filesystem-backed API upload jobs may be executed "
                "by this service."
            )

        upload_metadata = self._require_mapping(
            job.metadata.get(_JOB_UPLOAD_METADATA_ATTRIBUTE),
            label=(
                f"Job {job.job_id} does not contain authoritative "
                "filesystem upload metadata."
            ),
        )

        if upload_metadata.get("storage_backend") != _FILESYSTEM_BACKEND:
            raise FilesystemDocumentExecutionEligibilityError(
                f"Job {job.job_id} does not use filesystem upload storage."
            )

        document_count = self._require_positive_integer(
            upload_metadata.get("document_count"),
            label=(
                f"Job {job.job_id} contains invalid upload document-count "
                "metadata."
            ),
        )

        if (
            document_count != len(job.documents)
            or document_count != job.total_document_count
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Job {job.job_id} upload document-count metadata does "
                "not match its registered documents."
            )

        upload_maximum_bytes = self._require_positive_integer(
            upload_metadata.get("maximum_content_bytes"),
            label=(
                f"Job {job.job_id} contains invalid upload size-limit "
                "metadata."
            ),
        )
        runtime_maximum_bytes = (
            self.runtime.config.content_loader_config
            .maximum_content_bytes
        )

        if upload_maximum_bytes > runtime_maximum_bytes:
            raise FilesystemDocumentExecutionEligibilityError(
                f"Job {job.job_id} was accepted with a document-size "
                "limit that exceeds the configured processing limit."
            )

        for document in job.documents:
            self._validate_document(
                job,
                document,
                upload_maximum_bytes=upload_maximum_bytes,
            )

    def process_job(self, job_id: UUID) -> IngestionJob:
        """Validate, exclusively execute, and reconcile one ingestion job."""

        if not isinstance(job_id, UUID):
            raise TypeError("job_id must be a UUID.")

        initial_job = self.runtime.job_service.get(job_id)
        self.validate_job(initial_job)

        if initial_job.terminal:
            return self.runtime.process_job(job_id)

        with self._exclusive_execution(job_id):
            current_job = self.runtime.job_service.get(job_id)
            self.validate_job(current_job)

            try:
                return self.runtime.process_job(job_id)
            except DocumentProcessingStateError as error:
                raise FilesystemDocumentExecutionStateError(
                    f"Filesystem-backed ingestion job {job_id} cannot be "
                    "processed safely from its current state."
                ) from error

    @contextmanager
    def _exclusive_execution(
        self,
        job_id: UUID,
    ) -> Iterator[None]:
        """Acquire and reliably release one in-process execution lease."""

        with self._execution_lock:
            if job_id in self._active_job_ids:
                raise FilesystemDocumentExecutionConflictError(
                    f"Filesystem-backed ingestion job {job_id} is already "
                    "executing."
                )

            self._active_job_ids.add(job_id)

        try:
            yield
        finally:
            with self._execution_lock:
                self._active_job_ids.discard(job_id)

    def _validate_document(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
        *,
        upload_maximum_bytes: int,
    ) -> None:
        """Validate one document's server-owned storage identity."""

        storage_metadata = self._require_mapping(
            document.attributes.get(
                _DOCUMENT_STORAGE_ATTRIBUTE
            ),
            label=(
                f"Document {document.document_id} in job {job.job_id} "
                "does not contain authoritative filesystem storage "
                "metadata."
            ),
        )

        if storage_metadata.get("backend") != _FILESYSTEM_BACKEND:
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "does not use filesystem storage."
            )

        storage_id = self._parse_storage_id(
            storage_metadata.get("storage_id"),
            job=job,
            document=document,
        )
        self._validate_stored_at(
            storage_metadata.get("stored_at"),
            job=job,
            document=document,
        )
        self._validate_storage_reference(
            document.source_path,
            storage_id=storage_id,
            source_name=document.source_name,
            job=job,
            document=document,
        )

        declared_size = document.file_size_bytes

        if (
            isinstance(declared_size, bool)
            or not isinstance(declared_size, int)
            or declared_size < 1
            or declared_size > upload_maximum_bytes
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains invalid authoritative file-size metadata."
            )

        checksum = document.checksum_sha256

        if (
            not isinstance(checksum, str)
            or not self._is_lowercase_hexadecimal(
                checksum,
                length=_SHA256_HEXADECIMAL_LENGTH,
            )
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "does not contain an authoritative SHA-256 checksum."
            )

    @staticmethod
    def _require_mapping(
        value: Any,
        *,
        label: str,
    ) -> Mapping[str, Any]:
        """Return one non-empty string-keyed mapping or reject it."""

        if not isinstance(value, Mapping) or not value:
            raise FilesystemDocumentExecutionEligibilityError(label)

        if any(not isinstance(key, str) for key in value):
            raise FilesystemDocumentExecutionEligibilityError(label)

        return value

    @staticmethod
    def _require_positive_integer(
        value: Any,
        *,
        label: str,
    ) -> int:
        """Return one strict positive integer or reject it."""

        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
        ):
            raise FilesystemDocumentExecutionEligibilityError(label)

        return value

    @staticmethod
    def _parse_storage_id(
        value: Any,
        *,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> UUID:
        """Parse one canonical server-owned UUID string."""

        if not isinstance(value, str):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains invalid filesystem storage identity metadata."
            )

        try:
            storage_id = UUID(value)
        except (ValueError, AttributeError) as error:
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains invalid filesystem storage identity metadata."
            ) from error

        if value != str(storage_id):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains non-canonical filesystem storage identity "
                "metadata."
            )

        return storage_id

    @staticmethod
    def _validate_stored_at(
        value: Any,
        *,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> None:
        """Require one timezone-aware ISO-8601 storage timestamp."""

        if not isinstance(value, str):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains invalid filesystem storage timestamp metadata."
            )

        try:
            stored_at = datetime.fromisoformat(value)
        except ValueError as error:
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains invalid filesystem storage timestamp metadata."
            ) from error

        if (
            stored_at.tzinfo is None
            or stored_at.utcoffset() is None
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains a timezone-naive filesystem storage timestamp."
            )

    @classmethod
    def _validate_storage_reference(
        cls,
        source_path: str | None,
        *,
        storage_id: UUID,
        source_name: str,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> None:
        """Require the exact opaque shard path derived from a storage UUID."""

        if (
            not isinstance(source_path, str)
            or not source_path
            or source_path != source_path.strip()
            or "\\" in source_path
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains an invalid filesystem storage reference."
            )

        reference = PurePosixPath(source_path)
        parts = reference.parts

        if (
            reference.is_absolute()
            or len(parts) != _STORAGE_REFERENCE_PART_COUNT
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains an invalid filesystem storage reference."
            )

        source_suffix = Path(source_name).suffix.lower()
        stored_name = parts[2]
        stored_suffix = Path(stored_name).suffix.lower()
        stored_identifier = stored_name[
            : _OPAQUE_IDENTIFIER_HEXADECIMAL_LENGTH
        ]

        expected_reference = (
            f"{storage_id.hex[:_STORAGE_SHARD_LENGTH]}/"
            f"{storage_id.hex[_STORAGE_SHARD_LENGTH:4]}/"
            f"{storage_id.hex}{source_suffix}"
        )

        if (
            not source_suffix
            or source_suffix != stored_suffix
            or len(stored_identifier)
            != _OPAQUE_IDENTIFIER_HEXADECIMAL_LENGTH
            or not cls._is_lowercase_hexadecimal(
                stored_identifier,
                length=_OPAQUE_IDENTIFIER_HEXADECIMAL_LENGTH,
            )
            or source_path != expected_reference
        ):
            raise FilesystemDocumentExecutionEligibilityError(
                f"Document {document.document_id} in job {job.job_id} "
                "contains a non-canonical filesystem storage reference."
            )

    @staticmethod
    def _is_lowercase_hexadecimal(
        value: str,
        *,
        length: int,
    ) -> bool:
        """Return whether text is exact-length lowercase hexadecimal."""

        if len(value) != length:
            return False

        return all(
            character in "0123456789abcdef"
            for character in value
        )


__all__ = [
    "FilesystemDocumentExecutionConflictError",
    "FilesystemDocumentExecutionEligibilityError",
    "FilesystemDocumentExecutionError",
    "FilesystemDocumentExecutionService",
    "FilesystemDocumentExecutionStateError",
]
