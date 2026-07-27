"""Ingestion job lifecycle service for Engineer4Me.

This service coordinates validated ingestion job state changes while keeping
storage responsibilities inside ``IngestionJobRepository``.

Responsibilities include:

- registering new ingestion jobs;
- queueing and starting jobs;
- updating job and document progress;
- requesting and applying cancellation;
- completing, partially completing, or failing jobs;
- retrying eligible failed jobs and documents;
- retrieving summaries and aggregate statistics.

The service deliberately does not invoke the parser, metadata extractor,
engineering extractor, adapter, or publisher. Those integrations belong to
the batch ingestion orchestrator that will use this lifecycle service.
"""

from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Any
from uuid import UUID

from app.ingestion.ingestion_job_models import (
    IngestionDiagnostic,
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionFailureCategory,
    IngestionJob,
    IngestionJobStatistics,
    IngestionJobStatus,
    IngestionStage,
    InvalidIngestionJobTransitionError,
    utc_now,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobConflictError,
    IngestionJobNotFoundError,
    IngestionJobQuery,
    IngestionJobQueryResult,
    IngestionJobRepository,
)


class IngestionJobServiceError(Exception):
    """Base exception raised by the ingestion job lifecycle service."""


class IngestionDocumentNotFoundError(IngestionJobServiceError):
    """Raised when a document is not present in the requested job."""


class IngestionJobCancellationError(IngestionJobServiceError):
    """Raised when a job cannot be cancelled in its current state."""


class IngestionJobRetryError(IngestionJobServiceError):
    """Raised when a job or document is not eligible for retry."""


class IngestionJobService:
    """Manage ingestion job and document lifecycle transitions."""

    def __init__(
        self,
        repository: IngestionJobRepository | None = None,
    ) -> None:
        """Initialise the service with an optional repository."""

        self._repository = repository or IngestionJobRepository()
        self._lock = RLock()

    @property
    def repository(self) -> IngestionJobRepository:
        """Return the configured ingestion job repository."""

        return self._repository

    def submit(self, job: IngestionJob) -> IngestionJob:
        """Register a new pending ingestion job."""

        if job.status != IngestionJobStatus.PENDING:
            raise InvalidIngestionJobTransitionError(
                "A submitted ingestion job must have pending status."
            )

        if job.started_at is not None:
            raise InvalidIngestionJobTransitionError(
                "A pending ingestion job cannot already have started."
            )

        if job.completed_at is not None:
            raise InvalidIngestionJobTransitionError(
                "A pending ingestion job cannot already be completed."
            )

        return self._repository.add(job)

    def get(self, job_id: UUID) -> IngestionJob:
        """Retrieve a complete ingestion job."""

        return self._repository.get(job_id)

    def search(
        self,
        query: IngestionJobQuery,
    ) -> IngestionJobQueryResult:
        """Search ingestion jobs."""

        return self._repository.search(query)

    def statistics(self) -> IngestionJobStatistics:
        """Return aggregate ingestion job statistics."""

        return self._repository.statistics()

    def queue(
        self,
        job_id: UUID,
        *,
        queued_at: datetime | None = None,
    ) -> IngestionJob:
        """Move a pending job into the processing queue."""

        timestamp = queued_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {IngestionJobStatus.PENDING},
                target=IngestionJobStatus.QUEUED,
            )

            updated = self._validated_job_update(
                job,
                status=IngestionJobStatus.QUEUED,
                queued_at=timestamp,
                updated_at=timestamp,
            )

            return self._repository.replace(updated)

    def start(
        self,
        job_id: UUID,
        *,
        stage: IngestionStage = IngestionStage.PARSING,
        started_at: datetime | None = None,
    ) -> IngestionJob:
        """Start a pending or queued ingestion job."""

        timestamp = started_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {
                    IngestionJobStatus.PENDING,
                    IngestionJobStatus.QUEUED,
                },
                target=IngestionJobStatus.PROCESSING,
            )

            if job.cancellation_requested:
                return self._cancel_locked(
                    job,
                    cancelled_at=timestamp,
                )

            updates: dict[str, Any] = {
                "status": IngestionJobStatus.PROCESSING,
                "stage": stage,
                "started_at": timestamp,
                "updated_at": timestamp,
            }

            if job.status == IngestionJobStatus.PENDING:
                updates["queued_at"] = timestamp

            updated = self._validated_job_update(
                job,
                **updates,
            )

            return self._repository.replace(updated)

    def update_progress(
        self,
        job_id: UUID,
        *,
        stage: IngestionStage,
        progress_percent: int,
        current_document_id: UUID | None = None,
        warning_count: int | None = None,
        error_count: int | None = None,
        updated_at: datetime | None = None,
    ) -> IngestionJob:
        """Update the progress of a processing job."""

        timestamp = updated_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            if job.cancellation_requested:
                return self._cancel_locked(
                    job,
                    cancelled_at=timestamp,
                )

            if not 0 <= progress_percent <= 100:
                raise ValueError(
                    "progress_percent must be between 0 and 100."
                )

            if current_document_id is not None:
                self._find_document(
                    job,
                    current_document_id,
                )

            updates: dict[str, Any] = {
                "stage": stage,
                "progress_percent": progress_percent,
                "current_document_id": current_document_id,
                "updated_at": timestamp,
            }

            if warning_count is not None:
                if warning_count < 0:
                    raise ValueError(
                        "warning_count cannot be negative."
                    )
                updates["warning_count"] = warning_count

            if error_count is not None:
                if error_count < 0:
                    raise ValueError(
                        "error_count cannot be negative."
                    )
                updates["error_count"] = error_count

            updated = self._validated_job_update(
                job,
                **updates,
            )

            return self._repository.replace(updated)

    def start_document(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        stage: IngestionStage = IngestionStage.PARSING,
        started_at: datetime | None = None,
    ) -> IngestionJob:
        """Mark one pending document as processing."""

        timestamp = started_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            if job.cancellation_requested:
                return self._cancel_locked(
                    job,
                    cancelled_at=timestamp,
                )

            document = self._find_document(
                job,
                document_id,
            )

            if document.status != IngestionDocumentStatus.PENDING:
                raise InvalidIngestionJobTransitionError(
                    "Only pending or queued documents may be started."
                )

            updated_document = self._validated_document_update(
                document,
                status=IngestionDocumentStatus.PROCESSING,
                stage=stage,
                progress_percent=0,
                attempt_count=document.attempt_count + 1,
                started_at=timestamp,
                completed_at=None,
                updated_at=timestamp,
            )

            return self._replace_document_locked(
                job,
                updated_document,
                current_document_id=document_id,
                stage=stage,
                updated_at=timestamp,
            )
    def update_document_progress(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        stage: IngestionStage,
        progress_percent: int,
        diagnostics: list[IngestionDiagnostic] | None = None,
        warning_count: int | None = None,
        error_count: int | None = None,
        metadata: dict[str, Any] | None = None,
        updated_at: datetime | None = None,
    ) -> IngestionJob:
        """Update the progress and diagnostics of a processing document."""

        timestamp = updated_at or utc_now()

        if not 0 <= progress_percent <= 100:
            raise ValueError(
                "progress_percent must be between 0 and 100."
            )

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            document = self._find_document(job, document_id)

            if document.status != IngestionDocumentStatus.PROCESSING:
                raise InvalidIngestionJobTransitionError(
                    "Document progress can only be updated while processing."
                )

            updates: dict[str, Any] = {
                "stage": stage,
                "progress_percent": progress_percent,
                "updated_at": timestamp,
            }

            if diagnostics is not None:
                warnings, errors = self._classify_diagnostics(diagnostics)
                updates["warnings"] = warnings
                updates["errors"] = errors
            else:
                if warning_count is not None:
                    if warning_count < 0:
                        raise ValueError(
                            "warning_count cannot be negative."
                        )
                    updates["warnings"] = self._count_diagnostics(
                        count=warning_count,
                        stage=stage,
                        warning=True,
                    )

                if error_count is not None:
                    if error_count < 0:
                        raise ValueError(
                            "error_count cannot be negative."
                        )
                    updates["errors"] = self._count_diagnostics(
                        count=error_count,
                        stage=stage,
                        warning=False,
                    )

            if metadata is not None:
                updates["attributes"] = metadata

            updated_document = self._validated_document_update(
                document,
                **updates,
            )

            return self._replace_document_locked(
                job,
                updated_document,
                current_document_id=document_id,
                stage=stage,
                updated_at=timestamp,
            )


    def complete_document(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        registered_knowledge_count: int = 0,
        skipped_knowledge_count: int = 0,
        diagnostics: list[IngestionDiagnostic] | None = None,
        metadata: dict[str, Any] | None = None,
        completed_at: datetime | None = None,
    ) -> IngestionJob:
        """Complete one processing document successfully."""

        timestamp = completed_at or utc_now()

        if registered_knowledge_count < 0:
            raise ValueError(
                "registered_knowledge_count cannot be negative."
            )
        if skipped_knowledge_count < 0:
            raise ValueError(
                "skipped_knowledge_count cannot be negative."
            )

        with self._lock:
            job = self._repository.get(job_id)
            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            document = self._find_document(job, document_id)
            if document.status != IngestionDocumentStatus.PROCESSING:
                raise InvalidIngestionJobTransitionError(
                    "Only a processing document may be completed."
                )

            updates: dict[str, Any] = {
                "status": IngestionDocumentStatus.COMPLETED,
                "stage": IngestionStage.COMPLETE,
                "progress_percent": 100,
                "registered_knowledge_count": registered_knowledge_count,
                "skipped_knowledge_count": skipped_knowledge_count,
                "completed_at": timestamp,
                "updated_at": timestamp,
            }

            if diagnostics is not None:
                warnings, errors = self._classify_diagnostics(diagnostics)
                updates["warnings"] = warnings
                updates["errors"] = errors
            if metadata is not None:
                updates["attributes"] = metadata

            updated_document = self._validated_document_update(
                document,
                **updates,
            )
            return self._replace_document_locked(
                job,
                updated_document,
                current_document_id=None,
                updated_at=timestamp,
            )

    def skip_document(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        diagnostics: list[IngestionDiagnostic] | None = None,
        metadata: dict[str, Any] | None = None,
        completed_at: datetime | None = None,
    ) -> IngestionJob:
        """Mark a pending or processing document as skipped."""

        timestamp = completed_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)
            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            document = self._find_document(job, document_id)
            if document.status not in {
                IngestionDocumentStatus.PENDING,
                IngestionDocumentStatus.PROCESSING,
            }:
                raise InvalidIngestionJobTransitionError(
                    "The document cannot be skipped in its current state."
                )

            updates: dict[str, Any] = {
                "status": IngestionDocumentStatus.SKIPPED,
                "stage": IngestionStage.COMPLETE,
                "progress_percent": 100,
                "completed_at": timestamp,
                "updated_at": timestamp,
            }

            if diagnostics is not None:
                warnings, errors = self._classify_diagnostics(diagnostics)
                updates["warnings"] = warnings
                updates["errors"] = errors
            if metadata is not None:
                updates["attributes"] = metadata

            updated_document = self._validated_document_update(
                document,
                **updates,
            )
            current_document_id = job.current_document_id
            if current_document_id == document_id:
                current_document_id = None

            return self._replace_document_locked(
                job,
                updated_document,
                current_document_id=current_document_id,
                updated_at=timestamp,
            )

    def fail_document(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        diagnostics: list[IngestionDiagnostic] | None = None,
        metadata: dict[str, Any] | None = None,
        completed_at: datetime | None = None,
    ) -> IngestionJob:
        """Mark a pending or processing document as failed."""

        timestamp = completed_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)
            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.PROCESSING,
            )

            document = self._find_document(job, document_id)
            if document.status not in {
                IngestionDocumentStatus.PENDING,
                IngestionDocumentStatus.PROCESSING,
            }:
                raise InvalidIngestionJobTransitionError(
                    "The document cannot fail in its current state."
                )

            updates: dict[str, Any] = {
                "status": IngestionDocumentStatus.FAILED,
                "completed_at": timestamp,
                "updated_at": timestamp,
            }

            if diagnostics is not None:
                updates["warnings"] = []
                updates["errors"] = list(diagnostics)
            if metadata is not None:
                updates["attributes"] = metadata

            updated_document = self._validated_document_update(
                document,
                **updates,
            )
            current_document_id = job.current_document_id
            if current_document_id == document_id:
                current_document_id = None

            return self._replace_document_locked(
                job,
                updated_document,
                current_document_id=current_document_id,
                updated_at=timestamp,
            )

    def request_cancellation(
        self,
        job_id: UUID,
        *,
        requested_at: datetime | None = None,
    ) -> IngestionJob:
        """Request cancellation of a non-terminal job."""

        return self._repository.request_cancellation(
            job_id,
            requested_at=requested_at,
        )

    def apply_cancellation(
        self,
        job_id: UUID,
        *,
        cancelled_at: datetime | None = None,
    ) -> IngestionJob:
        """Move a cancellation-requested job to cancelled status."""

        timestamp = cancelled_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            if not job.cancellation_requested:
                raise IngestionJobCancellationError(
                    "Cancellation has not been requested for this job."
                )

            return self._cancel_locked(
                job,
                cancelled_at=timestamp,
            )

    def complete(
        self,
        job_id: UUID,
        *,
        completed_at: datetime | None = None,
    ) -> IngestionJob:
        """Finalise a processing job from its document outcomes."""

        timestamp = completed_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            self._require_status(
                job,
                {IngestionJobStatus.PROCESSING},
                target=IngestionJobStatus.COMPLETED,
            )

            if job.cancellation_requested:
                return self._cancel_locked(
                    job,
                    cancelled_at=timestamp,
                )

            non_terminal_documents = [
                document
                for document in job.documents
                if not document.terminal
            ]

            if non_terminal_documents:
                raise InvalidIngestionJobTransitionError(
                    "A job cannot be completed while documents remain "
                    "non-terminal."
                )

            completed_count = sum(
                document.status
                == IngestionDocumentStatus.COMPLETED
                for document in job.documents
            )
            skipped_count = sum(
                document.status
                == IngestionDocumentStatus.SKIPPED
                for document in job.documents
            )
            failed_count = sum(
                document.status
                == IngestionDocumentStatus.FAILED
                for document in job.documents
            )

            if failed_count == 0:
                final_status = IngestionJobStatus.COMPLETED
            elif completed_count > 0 or skipped_count > 0:
                final_status = (
                    IngestionJobStatus.PARTIALLY_COMPLETED
                )
            else:
                final_status = IngestionJobStatus.FAILED

            updated = self._validated_job_update(
                job,
                status=final_status,
                stage=IngestionStage.COMPLETE,
                progress_percent=100,
                current_document_id=None,
                completed_document_count=completed_count,
                skipped_document_count=skipped_count,
                failed_document_count=failed_count,
                completed_at=timestamp,
                updated_at=timestamp,
            )

            return self._repository.replace(updated)

    def fail(
        self,
        job_id: UUID,
        *,
        stage: IngestionStage = IngestionStage.FINALISING,
        completed_at: datetime | None = None,
        error_count: int | None = None,
    ) -> IngestionJob:
        """Fail a pending, queued, or processing job."""

        timestamp = completed_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            if job.terminal:
                raise InvalidIngestionJobTransitionError(
                    "A terminal ingestion job cannot be failed again."
                )

            updates: dict[str, Any] = {
                "status": IngestionJobStatus.FAILED,
                "stage": stage,
                "current_document_id": None,
                "completed_at": timestamp,
                "updated_at": timestamp,
            }

            if job.started_at is None:
                updates["started_at"] = timestamp

            if error_count is not None:
                if error_count < 0:
                    raise ValueError(
                        "error_count cannot be negative."
                    )
                updates["error_count"] = error_count

            updated = self._validated_job_update(
                job,
                **updates,
            )

            return self._repository.replace(updated)

    def retry(
        self,
        job_id: UUID,
        *,
        retried_at: datetime | None = None,
    ) -> IngestionJob:
        """Reset a failed or partially completed job for another attempt."""

        timestamp = retried_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)

            if job.status not in {
                IngestionJobStatus.FAILED,
                IngestionJobStatus.PARTIALLY_COMPLETED,
                IngestionJobStatus.CANCELLED,
            }:
                raise IngestionJobRetryError(
                    "Only failed, partially completed, or cancelled jobs "
                    "may be retried."
                )

            documents = [
                self._reset_document_for_retry(
                    document,
                    timestamp=timestamp,
                )
                if document.status
                in {
                    IngestionDocumentStatus.FAILED,
                    IngestionDocumentStatus.CANCELLED,
                }
                else document
                for document in job.documents
            ]

            if all(document.terminal for document in documents):
                raise IngestionJobRetryError(
                    "The job contains no failed or cancelled documents "
                    "eligible for retry."
                )

            updated = self._validated_job_update(
                job,
                status=IngestionJobStatus.PENDING,
                stage=IngestionStage.WAITING,
                documents=documents,
                progress_percent=self._derive_progress(documents),
                current_document_id=None,
                cancellation_requested=False,
                queued_at=None,
                started_at=None,
                completed_at=None,
                completed_document_count=self._count_documents(
                    documents,
                    IngestionDocumentStatus.COMPLETED,
                ),
                skipped_document_count=self._count_documents(
                    documents,
                    IngestionDocumentStatus.SKIPPED,
                ),
                failed_document_count=0,
                updated_at=timestamp,
            )

            return self._repository.replace(updated)

    def retry_document(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        retried_at: datetime | None = None,
    ) -> IngestionJob:
        """Reset one failed document for another attempt."""

        timestamp = retried_at or utc_now()

        with self._lock:
            job = self._repository.get(job_id)
            document = self._find_document(
                job,
                document_id,
            )

            if (
                document.status
                != IngestionDocumentStatus.FAILED
            ):
                raise IngestionJobRetryError(
                    "Only a failed document may be retried."
                )

            updated_document = self._reset_document_for_retry(
                document,
                timestamp=timestamp,
            )

            updated_job = self._replace_document_data(
                job,
                updated_document,
                current_document_id=None,
                updated_at=timestamp,
            )

            if job.terminal:
                updated_job = self._validated_job_update(
                    updated_job,
                    status=IngestionJobStatus.PENDING,
                    stage=IngestionStage.WAITING,
                    cancellation_requested=False,
                    queued_at=None,
                    started_at=None,
                    completed_at=None,
                    updated_at=timestamp,
                )

            return self._repository.replace(updated_job)

    @staticmethod
    def _require_status(
        job: IngestionJob,
        allowed: set[IngestionJobStatus],
        *,
        target: IngestionJobStatus,
    ) -> None:
        """Validate that a job can move towards the target state."""

        if job.status not in allowed:
            allowed_values = ", ".join(
                sorted(status.value for status in allowed)
            )
            raise InvalidIngestionJobTransitionError(
                f"Cannot transition ingestion job from "
                f"{job.status.value} to {target.value}; expected one of "
                f"{allowed_values}."
            )

    @staticmethod
    def _find_document(
        job: IngestionJob,
        document_id: UUID,
    ) -> IngestionDocumentResult:
        """Find a document within a job."""

        for document in job.documents:
            if document.document_id == document_id:
                return document

        raise IngestionDocumentNotFoundError(
            f"Document {document_id} was not found in ingestion job "
            f"{job.job_id}."
        )

    @staticmethod
    def _validated_job_update(
        job: IngestionJob,
        **updates: Any,
    ) -> IngestionJob:
        """Apply updates and fully revalidate an ingestion job."""

        values = job.model_dump()
        values.update(updates)

        return IngestionJob.model_validate(values)

    @staticmethod
    def _classify_diagnostics(
        diagnostics: list[IngestionDiagnostic],
    ) -> tuple[list[IngestionDiagnostic], list[IngestionDiagnostic]]:
        """Separate warning diagnostics from non-recoverable errors."""

        warnings = [
            diagnostic
            for diagnostic in diagnostics
            if diagnostic.failure_category is None
            or diagnostic.recoverable
        ]
        errors = [
            diagnostic
            for diagnostic in diagnostics
            if diagnostic.failure_category is not None
            and not diagnostic.recoverable
        ]
        return warnings, errors

    @staticmethod
    def _count_diagnostics(
        *,
        count: int,
        stage: IngestionStage,
        warning: bool,
    ) -> list[IngestionDiagnostic]:
        """Create deterministic diagnostics for count-only progress updates."""

        prefix = "WARNING" if warning else "ERROR"
        return [
            IngestionDiagnostic(
                code=f"INGESTION_{prefix}_{index + 1}",
                message=f"Ingestion {prefix.lower()} reported.",
                stage=stage,
                failure_category=(
                    None if warning else IngestionFailureCategory.INTERNAL
                ),
                recoverable=warning,
            )
            for index in range(count)
        ]

    @staticmethod
    def _validated_document_update(
        document: IngestionDocumentResult,
        **updates: Any,
    ) -> IngestionDocumentResult:
        """Apply updates and fully revalidate an ingestion document."""

        values = document.model_dump()
        values.update(updates)

        return IngestionDocumentResult.model_validate(values)

    def _replace_document_locked(
        self,
        job: IngestionJob,
        updated_document: IngestionDocumentResult,
        *,
        current_document_id: UUID | None,
        stage: IngestionStage | None = None,
        updated_at: datetime,
    ) -> IngestionJob:
        """Replace one document and persist the recalculated job."""

        updated_job = self._replace_document_data(
            job,
            updated_document,
            current_document_id=current_document_id,
            stage=stage,
            updated_at=updated_at,
        )

        return self._repository.replace(updated_job)

    def _replace_document_data(
        self,
        job: IngestionJob,
        updated_document: IngestionDocumentResult,
        *,
        current_document_id: UUID | None,
        updated_at: datetime,
        stage: IngestionStage | None = None,
    ) -> IngestionJob:
        """Replace a document and recalculate aggregate job fields."""

        documents = [
            updated_document
            if document.document_id
            == updated_document.document_id
            else document
            for document in job.documents
        ]

        updates: dict[str, Any] = {
            "documents": documents,
            "progress_percent": self._derive_progress(documents),
            "current_document_id": current_document_id,
            "completed_document_count": self._count_documents(
                documents,
                IngestionDocumentStatus.COMPLETED,
            ),
            "skipped_document_count": self._count_documents(
                documents,
                IngestionDocumentStatus.SKIPPED,
            ),
            "failed_document_count": self._count_documents(
                documents,
                IngestionDocumentStatus.FAILED,
            ),
            "warning_count": sum(
                len(document.warnings)
                for document in documents
            ),
            "error_count": sum(
                len(document.errors)
                for document in documents
            ),
            "updated_at": updated_at,
        }

        if stage is not None:
            updates["stage"] = stage

        return self._validated_job_update(
            job,
            **updates,
        )

    def _cancel_locked(
        self,
        job: IngestionJob,
        *,
        cancelled_at: datetime,
    ) -> IngestionJob:
        """Cancel a non-terminal job while the service lock is held."""

        if job.terminal:
            raise IngestionJobCancellationError(
                "A terminal ingestion job cannot be cancelled."
            )

        documents = [
            self._cancel_document(
                document,
                cancelled_at=cancelled_at,
            )
            if not document.terminal
            else document
            for document in job.documents
        ]

        updated = self._validated_job_update(
            job,
            status=IngestionJobStatus.CANCELLED,
            stage=IngestionStage.COMPLETE,
            documents=documents,
            progress_percent=self._derive_progress(documents),
            current_document_id=None,
            completed_document_count=self._count_documents(
                documents,
                IngestionDocumentStatus.COMPLETED,
            ),
            skipped_document_count=self._count_documents(
                documents,
                IngestionDocumentStatus.SKIPPED,
            ),
            failed_document_count=self._count_documents(
                documents,
                IngestionDocumentStatus.FAILED,
            ),
            completed_at=cancelled_at,
            updated_at=cancelled_at,
        )

        return self._repository.replace(updated)

    @staticmethod
    def _cancel_document(
        document: IngestionDocumentResult,
        *,
        cancelled_at: datetime,
    ) -> IngestionDocumentResult:
        """Move a non-terminal document to cancelled status."""

        values = document.model_dump()
        values.update(
            {
                "status": IngestionDocumentStatus.CANCELLED,
                "completed_at": cancelled_at,
                "updated_at": cancelled_at,
            }
        )

        return IngestionDocumentResult.model_validate(values)

    @staticmethod
    def _reset_document_for_retry(
        document: IngestionDocumentResult,
        *,
        timestamp: datetime,
    ) -> IngestionDocumentResult:
        """Reset a failed or cancelled document to pending."""

        values = document.model_dump()
        values.update(
            {
                "status": IngestionDocumentStatus.PENDING,
                "stage": IngestionStage.WAITING,
                "progress_percent": 0,
                "started_at": None,
                "completed_at": None,
                "registered_knowledge_count": 0,
                "skipped_knowledge_count": 0,
                "updated_at": timestamp,
            }
        )

        return IngestionDocumentResult.model_validate(values)

    @staticmethod
    def _derive_progress(
        documents: list[IngestionDocumentResult],
    ) -> int:
        """Calculate rounded mean document progress."""

        if not documents:
            return 0

        return round(
            sum(
                document.progress_percent
                for document in documents
            )
            / len(documents)
        )

    @staticmethod
    def _count_documents(
        documents: list[IngestionDocumentResult],
        status: IngestionDocumentStatus,
    ) -> int:
        """Count documents in one lifecycle status."""

        return sum(
            document.status == status
            for document in documents
        )


__all__ = [
    "IngestionDocumentNotFoundError",
    "IngestionJobCancellationError",
    "IngestionJobRetryError",
    "IngestionJobService",
    "IngestionJobServiceError",
    "IngestionJobConflictError",
    "IngestionJobNotFoundError",
]