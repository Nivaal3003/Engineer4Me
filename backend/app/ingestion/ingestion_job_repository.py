"""In-memory ingestion job repository for Engineer4Me.

The repository stores validated ingestion jobs independently from the
processing service and REST API.

It provides:

- controlled job creation and replacement;
- immutable read copies;
- status and source filtering;
- chronological pagination;
- cancellation requests;
- aggregate ingestion statistics;
- explicit duplicate and not-found errors.

The in-memory implementation can later be replaced by PostgreSQL without
changing the public service contract.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime
from enum import StrEnum
from threading import RLock
from typing import Iterable
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.engineering.knowledge_models import EngineeringBaseModel
from app.ingestion.ingestion_job_models import (
    IngestionDocumentStatus,
    IngestionJob,
    IngestionJobStatistics,
    IngestionJobStatus,
    IngestionJobSummary,
    IngestionJobType,
    IngestionSourceType,
    utc_now,
)


class IngestionJobRepositoryError(Exception):
    """Base exception raised by the ingestion job repository."""


class IngestionJobNotFoundError(IngestionJobRepositoryError):
    """Raised when an ingestion job cannot be found."""


class DuplicateIngestionJobError(IngestionJobRepositoryError):
    """Raised when a duplicate ingestion job is added."""


class IngestionJobConflictError(IngestionJobRepositoryError):
    """Raised when an ingestion job operation conflicts with its state."""


class IngestionJobSortOrder(StrEnum):
    """Supported ingestion job list ordering."""

    CREATED_ASCENDING = "created_ascending"
    CREATED_DESCENDING = "created_descending"
    UPDATED_ASCENDING = "updated_ascending"
    UPDATED_DESCENDING = "updated_descending"
    PROGRESS_ASCENDING = "progress_ascending"
    PROGRESS_DESCENDING = "progress_descending"


class IngestionJobQuery(EngineeringBaseModel):
    """Filtering and pagination request for ingestion jobs."""

    statuses: list[IngestionJobStatus] = Field(default_factory=list)
    job_types: list[IngestionJobType] = Field(default_factory=list)
    source_types: list[IngestionSourceType] = Field(default_factory=list)
    submitted_by: str | None = Field(default=None, max_length=255)
    correlation_id: str | None = Field(default=None, max_length=255)

    created_from: datetime | None = None
    created_to: datetime | None = None

    include_terminal: bool = True
    cancellation_requested: bool | None = None

    sort_order: IngestionJobSortOrder = (
        IngestionJobSortOrder.CREATED_DESCENDING
    )
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)

    @field_validator(
        "submitted_by",
        "correlation_id",
        mode="before",
    )
    @classmethod
    def normalise_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """Strip optional text filters."""

        if value is None:
            return None

        cleaned = value.strip()

        return cleaned or None

    @model_validator(mode="after")
    def validate_date_range(self) -> "IngestionJobQuery":
        """Ensure the requested date range is chronological."""

        if (
            self.created_from is not None
            and self.created_to is not None
            and self.created_from > self.created_to
        ):
            raise ValueError(
                "created_from cannot be later than created_to."
            )

        return self


class IngestionJobQueryResult(EngineeringBaseModel):
    """Paginated ingestion job query result."""

    jobs: list[IngestionJobSummary] = Field(default_factory=list)
    total_matches: int = Field(default=0, ge=0)
    returned_matches: int = Field(default=0, ge=0)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)

    @model_validator(mode="after")
    def derive_returned_matches(self) -> "IngestionJobQueryResult":
        """Synchronise the returned count with the result collection."""

        object.__setattr__(
            self,
            "returned_matches",
            len(self.jobs),
        )

        return self


class IngestionJobRepository:
    """Thread-safe in-memory repository for ingestion jobs."""

    def __init__(
        self,
        jobs: Iterable[IngestionJob] | None = None,
    ) -> None:
        """Initialise the repository with optional validated jobs."""

        self._jobs: dict[UUID, IngestionJob] = {}
        self._lock = RLock()

        if jobs is not None:
            for job in jobs:
                self.add(job)

    def add(self, job: IngestionJob) -> IngestionJob:
        """Store a new ingestion job.

        Raises:
            DuplicateIngestionJobError: If the identifier already exists.
        """

        prepared = self._prepare_job(job)

        with self._lock:
            if prepared.job_id in self._jobs:
                raise DuplicateIngestionJobError(
                    f"Ingestion job {prepared.job_id} already exists."
                )

            self._jobs[prepared.job_id] = prepared

            return deepcopy(prepared)

    def add_many(
        self,
        jobs: Iterable[IngestionJob],
    ) -> list[IngestionJob]:
        """Store several jobs atomically after validating all identifiers."""

        prepared = [
            self._prepare_job(job)
            for job in jobs
        ]

        identifiers = [job.job_id for job in prepared]

        if len(identifiers) != len(set(identifiers)):
            raise DuplicateIngestionJobError(
                "The submitted jobs contain duplicate job identifiers."
            )

        with self._lock:
            existing = [
                job_id
                for job_id in identifiers
                if job_id in self._jobs
            ]

            if existing:
                formatted = ", ".join(
                    str(job_id)
                    for job_id in existing
                )
                raise DuplicateIngestionJobError(
                    "One or more ingestion jobs already exist: "
                    f"{formatted}."
                )

            for job in prepared:
                self._jobs[job.job_id] = job

            return deepcopy(prepared)

    def get(self, job_id: UUID) -> IngestionJob:
        """Retrieve one ingestion job by identifier."""

        with self._lock:
            job = self._jobs.get(job_id)

            if job is None:
                raise IngestionJobNotFoundError(
                    f"Ingestion job {job_id} was not found."
                )

            return deepcopy(job)

    def exists(self, job_id: UUID) -> bool:
        """Return whether an ingestion job exists."""

        with self._lock:
            return job_id in self._jobs

    def replace(self, job: IngestionJob) -> IngestionJob:
        """Replace an existing ingestion job with a validated version."""

        prepared = self._prepare_job(job)

        with self._lock:
            if prepared.job_id not in self._jobs:
                raise IngestionJobNotFoundError(
                    f"Ingestion job {prepared.job_id} was not found."
                )

            current = self._jobs[prepared.job_id]

            if prepared.created_at != current.created_at:
                raise IngestionJobConflictError(
                    "created_at cannot be changed when replacing a job."
                )

            self._jobs[prepared.job_id] = prepared

            return deepcopy(prepared)

    def upsert(self, job: IngestionJob) -> IngestionJob:
        """Add or replace an ingestion job."""

        prepared = self._prepare_job(job)

        with self._lock:
            current = self._jobs.get(prepared.job_id)

            if (
                current is not None
                and prepared.created_at != current.created_at
            ):
                raise IngestionJobConflictError(
                    "created_at cannot be changed when replacing a job."
                )

            self._jobs[prepared.job_id] = prepared

            return deepcopy(prepared)

    def request_cancellation(
        self,
        job_id: UUID,
        *,
        requested_at: datetime | None = None,
    ) -> IngestionJob:
        """Mark a non-terminal ingestion job for cancellation."""

        timestamp = requested_at or utc_now()

        with self._lock:
            current = self._jobs.get(job_id)

            if current is None:
                raise IngestionJobNotFoundError(
                    f"Ingestion job {job_id} was not found."
                )

            if current.terminal:
                raise IngestionJobConflictError(
                    "Cancellation cannot be requested for a terminal job."
                )

            updated = current.model_copy(
                update={
                    "cancellation_requested": True,
                    "updated_at": timestamp,
                }
            )

            self._jobs[job_id] = updated

            return deepcopy(updated)

    def delete(self, job_id: UUID) -> None:
        """Delete an ingestion job from the repository."""

        with self._lock:
            if job_id not in self._jobs:
                raise IngestionJobNotFoundError(
                    f"Ingestion job {job_id} was not found."
                )

            del self._jobs[job_id]

    def clear(self) -> None:
        """Remove all stored ingestion jobs."""

        with self._lock:
            self._jobs.clear()

    def count(self) -> int:
        """Return the total number of stored jobs."""

        with self._lock:
            return len(self._jobs)

    def list_all(self) -> list[IngestionJob]:
        """Return all jobs ordered by creation time descending."""

        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda job: (
                    job.created_at,
                    str(job.job_id),
                ),
                reverse=True,
            )

            return deepcopy(jobs)

    def search(
        self,
        query: IngestionJobQuery,
    ) -> IngestionJobQueryResult:
        """Filter, order, and paginate ingestion jobs."""

        with self._lock:
            jobs = [
                job
                for job in self._jobs.values()
                if self._matches_query(job, query)
            ]

            ordered = self._sort_jobs(
                jobs,
                query.sort_order,
            )

            total_matches = len(ordered)

            selected = ordered[
                query.offset : query.offset + query.limit
            ]

            summaries = [
                self._build_summary(job)
                for job in selected
            ]

            return IngestionJobQueryResult(
                jobs=summaries,
                total_matches=total_matches,
                offset=query.offset,
                limit=query.limit,
            )

    def statistics(self) -> IngestionJobStatistics:
        """Return aggregate job and document statistics."""

        with self._lock:
            jobs = list(self._jobs.values())

        job_status_counts = Counter(
            job.status
            for job in jobs
        )

        documents = [
            document
            for job in jobs
            for document in job.documents
        ]

        document_status_counts = Counter(
            document.status
            for document in documents
        )

        return IngestionJobStatistics(
            total_jobs=len(jobs),
            pending_jobs=job_status_counts[
                IngestionJobStatus.PENDING
            ],
            queued_jobs=job_status_counts[
                IngestionJobStatus.QUEUED
            ],
            processing_jobs=job_status_counts[
                IngestionJobStatus.PROCESSING
            ],
            completed_jobs=job_status_counts[
                IngestionJobStatus.COMPLETED
            ],
            partially_completed_jobs=job_status_counts[
                IngestionJobStatus.PARTIALLY_COMPLETED
            ],
            failed_jobs=job_status_counts[
                IngestionJobStatus.FAILED
            ],
            cancelled_jobs=job_status_counts[
                IngestionJobStatus.CANCELLED
            ],
            total_documents=len(documents),
            completed_documents=document_status_counts[
                IngestionDocumentStatus.COMPLETED
            ],
            skipped_documents=document_status_counts[
                IngestionDocumentStatus.SKIPPED
            ],
            failed_documents=document_status_counts[
                IngestionDocumentStatus.FAILED
            ],
            registered_knowledge_count=sum(
                job.registered_knowledge_count
                for job in jobs
            ),
        )

    @staticmethod
    def _prepare_job(job: IngestionJob) -> IngestionJob:
        """Return an isolated, fully revalidated job copy."""

        if not isinstance(job, IngestionJob):
            raise TypeError("job must be an IngestionJob instance.")

        return IngestionJob.model_validate(
            job.model_dump()
        )

    @staticmethod
    def _matches_query(
        job: IngestionJob,
        query: IngestionJobQuery,
    ) -> bool:
        """Return whether a job satisfies every query filter."""

        if query.statuses and job.status not in query.statuses:
            return False

        if query.job_types and job.job_type not in query.job_types:
            return False

        if (
            query.source_types
            and job.source_type not in query.source_types
        ):
            return False

        if (
            query.submitted_by is not None
            and job.submitted_by.casefold()
            != query.submitted_by.casefold()
        ):
            return False

        if (
            query.correlation_id is not None
            and (
                job.correlation_id is None
                or job.correlation_id.casefold()
                != query.correlation_id.casefold()
            )
        ):
            return False

        if (
            query.created_from is not None
            and job.created_at < query.created_from
        ):
            return False

        if (
            query.created_to is not None
            and job.created_at > query.created_to
        ):
            return False

        if not query.include_terminal and job.terminal:
            return False

        if (
            query.cancellation_requested is not None
            and job.cancellation_requested
            != query.cancellation_requested
        ):
            return False

        return True

    @staticmethod
    def _sort_jobs(
        jobs: list[IngestionJob],
        sort_order: IngestionJobSortOrder,
    ) -> list[IngestionJob]:
        """Sort jobs using deterministic secondary keys."""

        if sort_order == IngestionJobSortOrder.CREATED_ASCENDING:
            return sorted(
                jobs,
                key=lambda job: (
                    job.created_at,
                    str(job.job_id),
                ),
            )

        if sort_order == IngestionJobSortOrder.UPDATED_ASCENDING:
            return sorted(
                jobs,
                key=lambda job: (
                    job.updated_at,
                    str(job.job_id),
                ),
            )

        if sort_order == IngestionJobSortOrder.UPDATED_DESCENDING:
            return sorted(
                jobs,
                key=lambda job: (
                    job.updated_at,
                    str(job.job_id),
                ),
                reverse=True,
            )

        if sort_order == IngestionJobSortOrder.PROGRESS_ASCENDING:
            return sorted(
                jobs,
                key=lambda job: (
                    job.progress_percent,
                    job.created_at,
                    str(job.job_id),
                ),
            )

        if sort_order == IngestionJobSortOrder.PROGRESS_DESCENDING:
            return sorted(
                jobs,
                key=lambda job: (
                    job.progress_percent,
                    job.created_at,
                    str(job.job_id),
                ),
                reverse=True,
            )

        return sorted(
            jobs,
            key=lambda job: (
                job.created_at,
                str(job.job_id),
            ),
            reverse=True,
        )

    @staticmethod
    def _build_summary(
        job: IngestionJob,
    ) -> IngestionJobSummary:
        """Build a compact immutable monitoring summary."""

        return IngestionJobSummary(
            job_id=job.job_id,
            job_type=job.job_type,
            source_type=job.source_type,
            status=job.status,
            stage=job.stage,
            submitted_by=job.submitted_by,
            progress_percent=job.progress_percent,
            total_document_count=job.total_document_count,
            completed_document_count=job.completed_document_count,
            skipped_document_count=job.skipped_document_count,
            failed_document_count=job.failed_document_count,
            warning_count=job.warning_count,
            error_count=job.error_count,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )


__all__ = [
    "DuplicateIngestionJobError",
    "IngestionJobConflictError",
    "IngestionJobNotFoundError",
    "IngestionJobQuery",
    "IngestionJobQueryResult",
    "IngestionJobRepository",
    "IngestionJobRepositoryError",
    "IngestionJobSortOrder",
]
