"""Ingestion job and progress models for Engineer4Me.

These models provide the shared contract used by future ingestion services,
background workers, repositories, and REST API endpoints.

An ingestion job may contain one or many engineering documents. Each document
is tracked independently so that one failed document does not invalidate a
successful batch.

The job models intentionally contain no file-processing logic. They describe
state, progress, diagnostics, and controlled transitions only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePath
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from app.engineering.knowledge_models import EngineeringBaseModel


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""

    return datetime.now(UTC)


class IngestionJobError(Exception):
    """Base exception raised by ingestion job state operations."""


class InvalidIngestionJobTransitionError(IngestionJobError):
    """Raised when a job or document transition is not permitted."""


class IngestionJobType(StrEnum):
    """Supported ingestion job scopes."""

    SINGLE_DOCUMENT = "single_document"
    DOCUMENT_BATCH = "document_batch"
    ARCHIVE = "archive"
    DIRECTORY = "directory"


class IngestionJobStatus(StrEnum):
    """Lifecycle status for a complete ingestion job."""

    PENDING = "pending"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IngestionDocumentStatus(StrEnum):
    """Lifecycle status for one document within an ingestion job."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IngestionStage(StrEnum):
    """Current processing stage for a document or ingestion job."""

    WAITING = "waiting"
    VALIDATING = "validating"
    PARSING = "parsing"
    EXTRACTING_METADATA = "extracting_metadata"
    DETECTING_DUPLICATES = "detecting_duplicates"
    EXTRACTING_ENGINEERING_FACTS = "extracting_engineering_facts"
    GENERATING_KNOWLEDGE = "generating_knowledge"
    BUILDING_INDEX = "building_index"
    CONVERTING_KNOWLEDGE = "converting_knowledge"
    REGISTERING_KNOWLEDGE = "registering_knowledge"
    FINALISING = "finalising"
    COMPLETE = "complete"


class IngestionFailureCategory(StrEnum):
    """Normalised failure categories for operational reporting."""

    VALIDATION = "validation"
    UNSUPPORTED_FORMAT = "unsupported_format"
    FILE_ACCESS = "file_access"
    PARSING = "parsing"
    METADATA_EXTRACTION = "metadata_extraction"
    DUPLICATE_DETECTION = "duplicate_detection"
    ENGINEERING_EXTRACTION = "engineering_extraction"
    KNOWLEDGE_GENERATION = "knowledge_generation"
    INDEXING = "indexing"
    CONVERSION = "conversion"
    REPOSITORY_PUBLICATION = "repository_publication"
    CANCELLED = "cancelled"
    INTERNAL = "internal"


class IngestionSourceType(StrEnum):
    """Origin of documents submitted for ingestion."""

    API_UPLOAD = "api_upload"
    LOCAL_FILE = "local_file"
    DIRECTORY_SCAN = "directory_scan"
    ARCHIVE_UPLOAD = "archive_upload"
    OBJECT_STORAGE = "object_storage"
    MANUAL = "manual"
    SYSTEM = "system"


class IngestionDiagnostic(EngineeringBaseModel):
    """Warning or error produced during ingestion."""

    code: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=2_000)
    stage: IngestionStage
    failure_category: IngestionFailureCategory | None = None
    document_id: UUID | None = None
    recoverable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=utc_now)

    @field_validator("code", "message")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        """Normalise required text values."""

        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Value cannot be empty.")

        return cleaned


class IngestionDocumentResult(EngineeringBaseModel):
    """Processing status and result for one submitted document."""

    document_id: UUID = Field(default_factory=uuid4)
    source_name: str = Field(min_length=1, max_length=500)
    source_path: str | None = Field(default=None, max_length=2_000)
    media_type: str | None = Field(default=None, max_length=255)
    file_size_bytes: int | None = Field(default=None, ge=0)
    checksum_sha256: str | None = Field(default=None, max_length=64)

    status: IngestionDocumentStatus = IngestionDocumentStatus.PENDING
    stage: IngestionStage = IngestionStage.WAITING
    progress_percent: int = Field(default=0, ge=0, le=100)

    attempt_count: int = Field(default=0, ge=0)
    maximum_attempts: int = Field(default=3, ge=1, le=20)

    parsed_page_count: int = Field(default=0, ge=0)
    extracted_fact_count: int = Field(default=0, ge=0)
    duplicate_fact_count: int = Field(default=0, ge=0)
    generated_knowledge_count: int = Field(default=0, ge=0)
    registered_knowledge_count: int = Field(default=0, ge=0)
    skipped_knowledge_count: int = Field(default=0, ge=0)
    failed_knowledge_count: int = Field(default=0, ge=0)

    registered_knowledge_ids: list[str] = Field(default_factory=list)
    warnings: list[IngestionDiagnostic] = Field(default_factory=list)
    errors: list[IngestionDiagnostic] = Field(default_factory=list)

    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_name", mode="before")
    @classmethod
    def validate_source_name(cls, value: str) -> str:
        """Normalise and validate the document source name."""

        cleaned = value.strip()

        if not cleaned:
            raise ValueError("source_name cannot be empty.")

        return cleaned

    @field_validator("checksum_sha256")
    @classmethod
    def validate_checksum(cls, value: str | None) -> str | None:
        """Validate an optional SHA-256 checksum."""

        if value is None:
            return None

        cleaned = value.strip().lower()

        if len(cleaned) != 64:
            raise ValueError(
                "checksum_sha256 must contain exactly 64 hexadecimal characters."
            )

        try:
            int(cleaned, 16)
        except ValueError as error:
            raise ValueError(
                "checksum_sha256 must contain only hexadecimal characters."
            ) from error

        return cleaned

    @model_validator(mode="after")
    def validate_document_state(self) -> "IngestionDocumentResult":
        """Validate related status, progress, and timestamp fields."""

        terminal_statuses = {
            IngestionDocumentStatus.COMPLETED,
            IngestionDocumentStatus.SKIPPED,
            IngestionDocumentStatus.FAILED,
            IngestionDocumentStatus.CANCELLED,
        }

        if self.status == IngestionDocumentStatus.COMPLETED:
            if self.progress_percent != 100:
                raise ValueError(
                    "Completed documents must have progress_percent equal to 100."
                )

            if self.stage != IngestionStage.COMPLETE:
                raise ValueError(
                    "Completed documents must use the complete ingestion stage."
                )

        if self.status in terminal_statuses and self.completed_at is None:
            raise ValueError(
                "Terminal document statuses require completed_at."
            )

        if self.status == IngestionDocumentStatus.PROCESSING:
            if self.started_at is None:
                raise ValueError(
                    "Processing documents require started_at."
                )

            if self.stage in {
                IngestionStage.WAITING,
                IngestionStage.COMPLETE,
            }:
                raise ValueError(
                    "Processing documents require an active processing stage."
                )

        if self.attempt_count > self.maximum_attempts:
            raise ValueError(
                "attempt_count cannot exceed maximum_attempts."
            )

        if self.completed_at and self.started_at:
            if self.completed_at < self.started_at:
                raise ValueError(
                    "completed_at cannot be earlier than started_at."
                )

        return self

    @property
    def filename(self) -> str:
        """Return the final filename component of the source."""

        return PurePath(self.source_name).name

    @property
    def terminal(self) -> bool:
        """Return whether document processing has finished."""

        return self.status in {
            IngestionDocumentStatus.COMPLETED,
            IngestionDocumentStatus.SKIPPED,
            IngestionDocumentStatus.FAILED,
            IngestionDocumentStatus.CANCELLED,
        }

    @property
    def retry_available(self) -> bool:
        """Return whether another processing attempt may be made."""

        return (
            self.status == IngestionDocumentStatus.FAILED
            and self.attempt_count < self.maximum_attempts
        )


class IngestionJob(EngineeringBaseModel):
    """Complete ingestion job containing one or more documents."""

    job_id: UUID = Field(default_factory=uuid4)
    job_type: IngestionJobType
    source_type: IngestionSourceType
    status: IngestionJobStatus = IngestionJobStatus.PENDING
    stage: IngestionStage = IngestionStage.WAITING

    submitted_by: str = Field(min_length=1, max_length=255)
    correlation_id: str | None = Field(default=None, max_length=255)

    documents: list[IngestionDocumentResult] = Field(default_factory=list)

    progress_percent: int = Field(default=0, ge=0, le=100)
    current_document_id: UUID | None = None

    total_document_count: int = Field(default=0, ge=0)
    completed_document_count: int = Field(default=0, ge=0)
    skipped_document_count: int = Field(default=0, ge=0)
    failed_document_count: int = Field(default=0, ge=0)
    cancelled_document_count: int = Field(default=0, ge=0)

    warning_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)

    created_at: datetime = Field(default_factory=utc_now)
    queued_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    cancellation_requested: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("submitted_by", mode="before")
    @classmethod
    def validate_submitted_by(cls, value: str) -> str:
        """Normalise the submitting user or system identifier."""

        cleaned = value.strip()

        if not cleaned:
            raise ValueError("submitted_by cannot be empty.")

        return cleaned

    @model_validator(mode="after")
    def validate_job_state(self) -> "IngestionJob":
        """Validate job counts, status, and lifecycle timestamps."""

        document_count = len(self.documents)

        if self.total_document_count != document_count:
            raise ValueError(
                "total_document_count must equal the number of documents."
            )

        outcome_count = (
            self.completed_document_count
            + self.skipped_document_count
            + self.failed_document_count
            + self.cancelled_document_count
        )

        if outcome_count > self.total_document_count:
            raise ValueError(
                "Document outcome counts cannot exceed total_document_count."
            )

        if self.status == IngestionJobStatus.PROCESSING:
            if self.started_at is None:
                raise ValueError(
                    "Processing jobs require started_at."
                )

            if self.stage in {
                IngestionStage.WAITING,
                IngestionStage.COMPLETE,
            }:
                raise ValueError(
                    "Processing jobs require an active processing stage."
                )

        terminal_statuses = {
            IngestionJobStatus.COMPLETED,
            IngestionJobStatus.PARTIALLY_COMPLETED,
            IngestionJobStatus.FAILED,
            IngestionJobStatus.CANCELLED,
        }

        if self.status in terminal_statuses and self.completed_at is None:
            raise ValueError(
                "Terminal job statuses require completed_at."
            )

        if self.status == IngestionJobStatus.COMPLETED:
            if self.progress_percent != 100:
                raise ValueError(
                    "Completed jobs must have progress_percent equal to 100."
                )

            if self.stage != IngestionStage.COMPLETE:
                raise ValueError(
                    "Completed jobs must use the complete ingestion stage."
                )

            if outcome_count != self.total_document_count:
                raise ValueError(
                    "Completed jobs require an outcome for every document."
                )

            if self.failed_document_count or self.cancelled_document_count:
                raise ValueError(
                    "Completed jobs cannot contain failed or cancelled documents."
                )

        if self.completed_at and self.started_at:
            if self.completed_at < self.started_at:
                raise ValueError(
                    "completed_at cannot be earlier than started_at."
                )

        document_ids = [document.document_id for document in self.documents]

        if len(document_ids) != len(set(document_ids)):
            raise ValueError(
                "documents cannot contain duplicate document_id values."
            )

        if (
            self.current_document_id is not None
            and self.current_document_id not in set(document_ids)
        ):
            raise ValueError(
                "current_document_id must identify a document in the job."
            )

        return self

    @property
    def terminal(self) -> bool:
        """Return whether the ingestion job has finished."""

        return self.status in {
            IngestionJobStatus.COMPLETED,
            IngestionJobStatus.PARTIALLY_COMPLETED,
            IngestionJobStatus.FAILED,
            IngestionJobStatus.CANCELLED,
        }

    @property
    def successful_document_count(self) -> int:
        """Return the number of completed and skipped documents."""

        return (
            self.completed_document_count
            + self.skipped_document_count
        )

    @property
    def remaining_document_count(self) -> int:
        """Return the number of documents without a terminal outcome."""

        terminal_count = (
            self.completed_document_count
            + self.skipped_document_count
            + self.failed_document_count
            + self.cancelled_document_count
        )

        return self.total_document_count - terminal_count

    @property
    def registered_knowledge_count(self) -> int:
        """Return the total registered knowledge count for the job."""

        return sum(
            document.registered_knowledge_count
            for document in self.documents
        )


class IngestionJobSummary(EngineeringBaseModel):
    """Compact ingestion job response for lists and monitoring screens."""

    job_id: UUID
    job_type: IngestionJobType
    source_type: IngestionSourceType
    status: IngestionJobStatus
    stage: IngestionStage
    submitted_by: str
    progress_percent: int = Field(ge=0, le=100)
    total_document_count: int = Field(ge=0)
    completed_document_count: int = Field(ge=0)
    skipped_document_count: int = Field(ge=0)
    failed_document_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class IngestionJobStatistics(EngineeringBaseModel):
    """Aggregate ingestion-job statistics."""

    total_jobs: int = Field(default=0, ge=0)
    pending_jobs: int = Field(default=0, ge=0)
    queued_jobs: int = Field(default=0, ge=0)
    processing_jobs: int = Field(default=0, ge=0)
    completed_jobs: int = Field(default=0, ge=0)
    partially_completed_jobs: int = Field(default=0, ge=0)
    failed_jobs: int = Field(default=0, ge=0)
    cancelled_jobs: int = Field(default=0, ge=0)

    total_documents: int = Field(default=0, ge=0)
    completed_documents: int = Field(default=0, ge=0)
    skipped_documents: int = Field(default=0, ge=0)
    failed_documents: int = Field(default=0, ge=0)

    registered_knowledge_count: int = Field(default=0, ge=0)


__all__ = [
    "IngestionDiagnostic",
    "IngestionDocumentResult",
    "IngestionDocumentStatus",
    "IngestionFailureCategory",
    "IngestionJob",
    "IngestionJobError",
    "IngestionJobStatistics",
    "IngestionJobStatus",
    "IngestionJobSummary",
    "IngestionJobType",
    "IngestionSourceType",
    "IngestionStage",
    "InvalidIngestionJobTransitionError",
    "utc_now",
]
