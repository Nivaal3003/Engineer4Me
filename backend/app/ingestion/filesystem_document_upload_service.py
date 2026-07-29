"""Transactional upload coordination for filesystem-backed ingestion.

The secure filesystem storage adapter persists untrusted document streams, and
the ingestion job service registers immutable processing work. This module
coordinates those two operations without depending on FastAPI:

- validates upload batches before creating files;
- stores each stream through ``FilesystemDocumentStorage``;
- derives authoritative document size, checksum, storage key, and timestamps;
- creates a pending single-document or batch ingestion job;
- prevents callers from spoofing server-owned storage metadata; and
- checksum-rolls back every stored file if storage or job submission fails.

HTTP routes, queue consumers, and future offline synchronisation endpoints can
all use this service without duplicating transactional cleanup logic.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Final

from app.ingestion.filesystem_document_storage import (
    DocumentStorageDeleteError,
    FilesystemDocumentStorage,
    FilesystemDocumentStorageError,
    StoredDocument,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
    IngestionJobType,
    IngestionSourceType,
)
from app.ingestion.ingestion_job_service import IngestionJobService


_DEFAULT_MAXIMUM_DOCUMENTS_PER_JOB: Final[int] = 20
_DEFAULT_MAXIMUM_ATTEMPTS: Final[int] = 3
_MAXIMUM_INGESTION_DOCUMENTS: Final[int] = 1_000
_MAXIMUM_ATTEMPTS_LIMIT: Final[int] = 20
_MAXIMUM_SUBMITTED_BY_CHARACTERS: Final[int] = 255
_MAXIMUM_CORRELATION_ID_CHARACTERS: Final[int] = 255
_DOCUMENT_STORAGE_ATTRIBUTE: Final[str] = "engineer4me_storage"
_JOB_UPLOAD_METADATA_ATTRIBUTE: Final[str] = "engineer4me_upload"


class FilesystemDocumentUploadServiceError(Exception):
    """Base exception for upload transaction failures."""


class DocumentUploadValidationError(
    FilesystemDocumentUploadServiceError
):
    """Raised before side effects when upload input is invalid."""


class DocumentUploadStorageError(FilesystemDocumentUploadServiceError):
    """Raised when one or more upload streams cannot be stored."""


class DocumentUploadSubmissionError(
    FilesystemDocumentUploadServiceError
):
    """Raised when stored uploads cannot be registered as an ingestion job."""


class DocumentUploadRollbackError(FilesystemDocumentUploadServiceError):
    """Raised when a failed transaction cannot be fully rolled back."""

    def __init__(
        self,
        *,
        primary_error: Exception,
        rollback_errors: tuple[Exception, ...],
        stored_document_count: int,
    ) -> None:
        """Record failure types without exposing storage keys or checksums."""

        if not isinstance(primary_error, Exception):
            raise TypeError("primary_error must be an Exception.")

        if (
            not isinstance(rollback_errors, tuple)
            or not rollback_errors
            or not all(
                isinstance(error, Exception)
                for error in rollback_errors
            )
        ):
            raise ValueError(
                "rollback_errors must be a non-empty tuple of exceptions."
            )

        if (
            isinstance(stored_document_count, bool)
            or not isinstance(stored_document_count, int)
            or stored_document_count < 1
        ):
            raise ValueError(
                "stored_document_count must be a positive integer."
            )

        self.primary_error = primary_error
        self.rollback_errors = rollback_errors
        self.stored_document_count = stored_document_count
        self.primary_error_type = type(primary_error).__name__
        self.rollback_error_types = tuple(
            type(error).__name__
            for error in rollback_errors
        )

        super().__init__(
            "The upload transaction failed and one or more stored "
            "documents could not be rolled back safely."
        )

    @property
    def rollback_error_count(self) -> int:
        """Return the number of guarded rollback failures."""

        return len(self.rollback_errors)


@dataclass(frozen=True, slots=True)
class FilesystemDocumentUploadServiceConfig:
    """Immutable upload transaction controls."""

    maximum_documents_per_job: int = (
        _DEFAULT_MAXIMUM_DOCUMENTS_PER_JOB
    )
    default_maximum_attempts: int = _DEFAULT_MAXIMUM_ATTEMPTS

    def __post_init__(self) -> None:
        """Validate service bounds against ingestion model constraints."""

        if (
            isinstance(self.maximum_documents_per_job, bool)
            or not isinstance(self.maximum_documents_per_job, int)
            or self.maximum_documents_per_job < 1
            or self.maximum_documents_per_job
            > _MAXIMUM_INGESTION_DOCUMENTS
        ):
            raise ValueError(
                "maximum_documents_per_job must be between 1 and "
                f"{_MAXIMUM_INGESTION_DOCUMENTS}."
            )

        if (
            isinstance(self.default_maximum_attempts, bool)
            or not isinstance(self.default_maximum_attempts, int)
            or self.default_maximum_attempts < 1
            or self.default_maximum_attempts
            > _MAXIMUM_ATTEMPTS_LIMIT
        ):
            raise ValueError(
                "default_maximum_attempts must be between 1 and "
                f"{_MAXIMUM_ATTEMPTS_LIMIT}."
            )


@dataclass(frozen=True, slots=True)
class FilesystemDocumentUpload:
    """One caller-owned binary stream and its untrusted metadata."""

    filename: str
    stream: BinaryIO
    media_type: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject malformed input before storage creates a file."""

        if not isinstance(self.filename, str):
            raise TypeError("filename must be a string.")

        if not self.filename.strip():
            raise DocumentUploadValidationError(
                "Upload filename cannot be blank."
            )

        read_method = getattr(self.stream, "read", None)

        if not callable(read_method):
            raise TypeError(
                "stream must provide a callable read method."
            )

        if (
            self.media_type is not None
            and not isinstance(self.media_type, str)
        ):
            raise TypeError(
                "media_type must be a string when provided."
            )

        prepared_attributes = _copy_mapping(
            self.attributes,
            label="attributes",
        )

        object.__setattr__(
            self,
            "attributes",
            prepared_attributes,
        )


class FilesystemDocumentUploadService:
    """Store upload streams and register one ingestion job atomically."""

    def __init__(
        self,
        *,
        storage: FilesystemDocumentStorage,
        job_service: IngestionJobService,
        config: FilesystemDocumentUploadServiceConfig | None = None,
    ) -> None:
        """Initialise the service with explicit validated dependencies."""

        if not isinstance(storage, FilesystemDocumentStorage):
            raise TypeError(
                "storage must be a FilesystemDocumentStorage."
            )

        if not isinstance(job_service, IngestionJobService):
            raise TypeError(
                "job_service must be an IngestionJobService."
            )

        resolved_config = (
            config
            if config is not None
            else FilesystemDocumentUploadServiceConfig()
        )

        if not isinstance(
            resolved_config,
            FilesystemDocumentUploadServiceConfig,
        ):
            raise TypeError(
                "config must be a "
                "FilesystemDocumentUploadServiceConfig."
            )

        self._storage = storage
        self._job_service = job_service
        self._config = resolved_config

    @property
    def storage(self) -> FilesystemDocumentStorage:
        """Return the guarded storage adapter."""

        return self._storage

    @property
    def job_service(self) -> IngestionJobService:
        """Return the shared ingestion job lifecycle service."""

        return self._job_service

    @property
    def config(self) -> FilesystemDocumentUploadServiceConfig:
        """Return immutable upload transaction controls."""

        return self._config

    def submit_upload(
        self,
        *,
        upload: FilesystemDocumentUpload,
        submitted_by: str,
        correlation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        maximum_attempts: int | None = None,
    ) -> IngestionJob:
        """Store and register one uploaded document."""

        return self.submit_uploads(
            uploads=(upload,),
            submitted_by=submitted_by,
            correlation_id=correlation_id,
            metadata=metadata,
            maximum_attempts=maximum_attempts,
        )

    def submit_uploads(
        self,
        *,
        uploads: Iterable[FilesystemDocumentUpload],
        submitted_by: str,
        correlation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        maximum_attempts: int | None = None,
    ) -> IngestionJob:
        """Store a bounded upload batch and register one pending job."""

        prepared_uploads = self._prepare_uploads(uploads)
        prepared_submitted_by = self._normalise_submitted_by(
            submitted_by
        )
        prepared_correlation_id = self._normalise_correlation_id(
            correlation_id
        )
        prepared_metadata = _copy_mapping(
            metadata,
            label="metadata",
            allow_none=True,
        )
        prepared_maximum_attempts = self._normalise_maximum_attempts(
            maximum_attempts
        )

        prepared_metadata[_JOB_UPLOAD_METADATA_ATTRIBUTE] = {
            "storage_backend": "filesystem",
            "document_count": len(prepared_uploads),
            "maximum_content_bytes": (
                self.storage.config.maximum_content_bytes
            ),
        }

        stored_documents: list[StoredDocument] = []

        try:
            ingestion_documents: list[IngestionDocumentResult] = []

            for upload in prepared_uploads:
                stored = self.storage.store_stream(
                    filename=upload.filename,
                    stream=upload.stream,
                    media_type=upload.media_type,
                )
                stored_documents.append(stored)

                document_attributes = _copy_mapping(
                    upload.attributes,
                    label="upload attributes",
                )
                document_attributes[
                    _DOCUMENT_STORAGE_ATTRIBUTE
                ] = {
                    "backend": "filesystem",
                    "storage_id": str(stored.storage_id),
                    "stored_at": stored.stored_at.isoformat(),
                }

                ingestion_documents.append(
                    IngestionDocumentResult(
                        source_name=stored.source_name,
                        source_path=stored.source_path,
                        media_type=stored.media_type,
                        file_size_bytes=stored.file_size_bytes,
                        checksum_sha256=stored.checksum_sha256,
                        maximum_attempts=(
                            prepared_maximum_attempts
                        ),
                        attributes=document_attributes,
                    )
                )

            job_type = (
                IngestionJobType.SINGLE_DOCUMENT
                if len(ingestion_documents) == 1
                else IngestionJobType.DOCUMENT_BATCH
            )
            job = IngestionJob(
                job_type=job_type,
                source_type=IngestionSourceType.API_UPLOAD,
                submitted_by=prepared_submitted_by,
                correlation_id=prepared_correlation_id,
                documents=ingestion_documents,
                total_document_count=len(ingestion_documents),
                metadata=prepared_metadata,
            )

            return self.job_service.submit(job)
        except Exception as error:
            rollback_errors = self._rollback(stored_documents)

            if rollback_errors:
                raise DocumentUploadRollbackError(
                    primary_error=error,
                    rollback_errors=rollback_errors,
                    stored_document_count=len(stored_documents),
                ) from error

            if isinstance(error, FilesystemDocumentStorageError):
                raise DocumentUploadStorageError(
                    "One or more uploaded documents could not be "
                    "stored safely."
                ) from error

            raise DocumentUploadSubmissionError(
                "Stored upload metadata could not be registered as an "
                "ingestion job."
            ) from error

    def _prepare_uploads(
        self,
        uploads: Iterable[FilesystemDocumentUpload],
    ) -> tuple[FilesystemDocumentUpload, ...]:
        """Materialise and validate a bounded upload collection."""

        if isinstance(
            uploads,
            (str, bytes, bytearray, memoryview),
        ):
            raise TypeError(
                "uploads must be an iterable of "
                "FilesystemDocumentUpload values."
            )

        try:
            prepared = tuple(uploads)
        except TypeError as error:
            raise TypeError(
                "uploads must be an iterable of "
                "FilesystemDocumentUpload values."
            ) from error

        if not prepared:
            raise DocumentUploadValidationError(
                "At least one uploaded document is required."
            )

        if len(prepared) > self.config.maximum_documents_per_job:
            raise DocumentUploadValidationError(
                "Upload batch contains more than the configured "
                f"{self.config.maximum_documents_per_job} documents."
            )

        for upload in prepared:
            if not isinstance(upload, FilesystemDocumentUpload):
                raise TypeError(
                    "uploads must contain only "
                    "FilesystemDocumentUpload values."
                )

        return prepared

    def _normalise_submitted_by(self, value: str) -> str:
        """Return one bounded required submitter identity."""

        if not isinstance(value, str):
            raise TypeError("submitted_by must be a string.")

        cleaned = value.strip()

        if not cleaned:
            raise DocumentUploadValidationError(
                "submitted_by cannot be blank."
            )

        if len(cleaned) > _MAXIMUM_SUBMITTED_BY_CHARACTERS:
            raise DocumentUploadValidationError(
                "submitted_by exceeds the 255-character limit."
            )

        return cleaned

    def _normalise_correlation_id(
        self,
        value: str | None,
    ) -> str | None:
        """Return one optional bounded correlation identifier."""

        if value is None:
            return None

        if not isinstance(value, str):
            raise TypeError(
                "correlation_id must be a string when provided."
            )

        cleaned = value.strip()

        if not cleaned:
            return None

        if len(cleaned) > _MAXIMUM_CORRELATION_ID_CHARACTERS:
            raise DocumentUploadValidationError(
                "correlation_id exceeds the 255-character limit."
            )

        return cleaned

    def _normalise_maximum_attempts(
        self,
        value: int | None,
    ) -> int:
        """Return a valid per-document retry limit."""

        resolved = (
            self.config.default_maximum_attempts
            if value is None
            else value
        )

        if (
            isinstance(resolved, bool)
            or not isinstance(resolved, int)
            or resolved < 1
            or resolved > _MAXIMUM_ATTEMPTS_LIMIT
        ):
            raise DocumentUploadValidationError(
                "maximum_attempts must be between 1 and "
                f"{_MAXIMUM_ATTEMPTS_LIMIT}."
            )

        return resolved

    def _rollback(
        self,
        stored_documents: list[StoredDocument],
    ) -> tuple[Exception, ...]:
        """Checksum-delete stored documents in reverse creation order."""

        rollback_errors: list[Exception] = []

        for stored in reversed(stored_documents):
            try:
                deleted = self.storage.delete(
                    stored.source_path,
                    expected_checksum_sha256=(
                        stored.checksum_sha256
                    ),
                )

                if not deleted:
                    rollback_errors.append(
                        DocumentStorageDeleteError(
                            "A stored document was missing during "
                            "transaction rollback."
                        )
                    )
            except Exception as error:
                rollback_errors.append(error)

        return tuple(rollback_errors)


def _copy_mapping(
    value: Mapping[str, Any] | None,
    *,
    label: str,
    allow_none: bool = False,
) -> dict[str, Any]:
    """Return a detached dictionary for caller-supplied metadata."""

    if value is None:
        if allow_none:
            return {}

        raise TypeError(f"{label} must be a mapping.")

    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping.")

    try:
        prepared = deepcopy(dict(value))
    except Exception as error:
        raise DocumentUploadValidationError(
            f"{label} could not be copied safely."
        ) from error

    if not all(isinstance(key, str) for key in prepared):
        raise DocumentUploadValidationError(
            f"{label} keys must be strings."
        )

    return prepared


__all__ = [
    "DocumentUploadRollbackError",
    "DocumentUploadStorageError",
    "DocumentUploadSubmissionError",
    "DocumentUploadValidationError",
    "FilesystemDocumentUpload",
    "FilesystemDocumentUploadService",
    "FilesystemDocumentUploadServiceConfig",
    "FilesystemDocumentUploadServiceError",
]
