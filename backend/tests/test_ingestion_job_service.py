"""Tests for the Engineer4Me ingestion job lifecycle service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.ingestion.ingestion_job_models import (
    IngestionDiagnostic,
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
    InvalidIngestionJobTransitionError,
)
from app.ingestion.ingestion_job_repository import (
    DuplicateIngestionJobError,
    IngestionJobNotFoundError,
    IngestionJobQuery,
    IngestionJobRepository,
)
from app.ingestion.ingestion_job_service import (
    IngestionDocumentNotFoundError,
    IngestionJobCancellationError,
    IngestionJobRetryError,
    IngestionJobService,
)


@pytest.fixture
def base_time() -> datetime:
    """Return a stable timezone-aware timestamp."""

    return datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def build_pending_document(
    *,
    source_name: str = "manual.pdf",
) -> IngestionDocumentResult:
    """Build a valid pending document result."""

    return IngestionDocumentResult(
        source_name=source_name,
    )


def build_pending_job(
    *,
    created_at: datetime,
    document_count: int = 1,
) -> IngestionJob:
    """Build a valid pending ingestion job."""

    documents = [
        build_pending_document(
            source_name=f"manual-{index + 1}.pdf",
        )
        for index in range(document_count)
    ]

    return IngestionJob(
        job_type=(
            IngestionJobType.SINGLE_DOCUMENT
            if document_count == 1
            else IngestionJobType.DOCUMENT_BATCH
        ),
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="test-user",
        documents=documents,
        total_document_count=document_count,
        created_at=created_at,
        updated_at=created_at,
    )


def build_processing_job(
    *,
    created_at: datetime,
    document_count: int = 1,
) -> IngestionJob:
    """Build a processing job using the public service transitions."""

    service = IngestionJobService()
    job = build_pending_job(
        created_at=created_at,
        document_count=document_count,
    )

    service.submit(job)
    service.queue(
        job.job_id,
        queued_at=created_at + timedelta(minutes=1),
    )

    return service.start(
        job.job_id,
        started_at=created_at + timedelta(minutes=2),
    )


def prepare_processing_service(
    *,
    created_at: datetime,
    document_count: int = 1,
) -> tuple[IngestionJobService, IngestionJob]:
    """Return a service containing one processing job."""

    service = IngestionJobService()
    job = build_pending_job(
        created_at=created_at,
        document_count=document_count,
    )

    service.submit(job)
    service.queue(
        job.job_id,
        queued_at=created_at + timedelta(minutes=1),
    )
    processing = service.start(
        job.job_id,
        started_at=created_at + timedelta(minutes=2),
    )

    return service, processing


def start_first_document(
    service: IngestionJobService,
    job: IngestionJob,
    *,
    started_at: datetime,
) -> tuple[IngestionJob, IngestionDocumentResult]:
    """Start the first document in a processing job."""

    document = job.documents[0]

    updated_job = service.start_document(
        job.job_id,
        document.document_id,
        started_at=started_at,
    )

    updated_document = next(
        item
        for item in updated_job.documents
        if item.document_id == document.document_id
    )

    return updated_job, updated_document


def test_service_uses_supplied_repository():
    """The service exposes the configured repository."""

    repository = IngestionJobRepository()
    service = IngestionJobService(repository)

    assert service.repository is repository


def test_service_creates_default_repository():
    """A repository is created when none is supplied."""

    service = IngestionJobService()

    assert isinstance(
        service.repository,
        IngestionJobRepository,
    )


def test_submit_registers_pending_job(base_time):
    """Submitting a pending job stores it."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)

    stored = service.submit(job)

    assert stored == job
    assert service.get(job.job_id) == job


def test_submit_rejects_duplicate_job(base_time):
    """Duplicate submitted jobs are rejected."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)

    service.submit(job)

    with pytest.raises(DuplicateIngestionJobError):
        service.submit(job)


def test_submit_rejects_non_pending_job(base_time):
    """Only pending jobs may be submitted."""

    job = build_pending_job(created_at=base_time).model_copy(
        update={
            "status": IngestionJobStatus.QUEUED,
            "queued_at": base_time,
        }
    )

    service = IngestionJobService()

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="must have pending status",
    ):
        service.submit(job)


def test_get_rejects_unknown_job():
    """Unknown job identifiers are rejected."""

    service = IngestionJobService()

    with pytest.raises(IngestionJobNotFoundError):
        service.get(uuid4())


def test_search_delegates_to_repository(base_time):
    """Search returns repository query results."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)
    service.submit(job)

    result = service.search(IngestionJobQuery())

    assert result.total_matches == 1
    assert result.jobs[0].job_id == job.job_id


def test_statistics_delegates_to_repository(base_time):
    """Statistics reflect stored jobs."""

    service = IngestionJobService()
    service.submit(
        build_pending_job(created_at=base_time)
    )

    statistics = service.statistics()

    assert statistics.total_jobs == 1
    assert statistics.pending_jobs == 1


def test_queue_moves_pending_job_to_queued(base_time):
    """Pending jobs may be queued."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)
    service.submit(job)

    queued_at = base_time + timedelta(minutes=1)

    queued = service.queue(
        job.job_id,
        queued_at=queued_at,
    )

    assert queued.status == IngestionJobStatus.QUEUED
    assert queued.queued_at == queued_at
    assert queued.updated_at == queued_at


def test_queue_rejects_non_pending_job(base_time):
    """Only pending jobs may enter the queue."""

    service, processing = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="Cannot transition",
    ):
        service.queue(processing.job_id)


def test_start_moves_queued_job_to_processing(base_time):
    """Queued jobs may begin processing."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)

    service.submit(job)
    service.queue(
        job.job_id,
        queued_at=base_time + timedelta(minutes=1),
    )

    started_at = base_time + timedelta(minutes=2)

    started = service.start(
        job.job_id,
        stage=IngestionStage.PARSING,
        started_at=started_at,
    )

    assert started.status == IngestionJobStatus.PROCESSING
    assert started.stage == IngestionStage.PARSING
    assert started.started_at == started_at


def test_start_allows_direct_start_from_pending(base_time):
    """Pending jobs may start directly without a separate queue call."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)
    service.submit(job)

    started_at = base_time + timedelta(minutes=1)

    started = service.start(
        job.job_id,
        started_at=started_at,
    )

    assert started.status == IngestionJobStatus.PROCESSING
    assert started.queued_at == started_at
    assert started.started_at == started_at


def test_start_applies_existing_cancellation_request(base_time):
    """Starting a cancellation-requested job cancels it."""

    service = IngestionJobService()
    job = build_pending_job(created_at=base_time)

    service.submit(job)
    service.request_cancellation(
        job.job_id,
        requested_at=base_time + timedelta(minutes=1),
    )

    cancelled = service.start(
        job.job_id,
        started_at=base_time + timedelta(minutes=2),
    )

    assert cancelled.status == IngestionJobStatus.CANCELLED
    assert cancelled.documents[0].status == (
        IngestionDocumentStatus.CANCELLED
    )


def test_update_progress_updates_processing_job(base_time):
    """Processing job progress and stage can be updated."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    updated = service.update_progress(
        job.job_id,
        stage=IngestionStage.EXTRACTING_METADATA,
        progress_percent=25,
        warning_count=2,
        error_count=1,
        updated_at=base_time + timedelta(minutes=3),
    )

    assert updated.stage == IngestionStage.EXTRACTING_METADATA
    assert updated.progress_percent == 25
    assert updated.warning_count == 2
    assert updated.error_count == 1


def test_update_progress_rejects_invalid_percentage(base_time):
    """Job progress must remain within the valid range."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        ValueError,
        match="between 0 and 100",
    ):
        service.update_progress(
            job.job_id,
            stage=IngestionStage.PARSING,
            progress_percent=101,
        )


def test_update_progress_rejects_unknown_document(base_time):
    """Current document identifiers must belong to the job."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(IngestionDocumentNotFoundError):
        service.update_progress(
            job.job_id,
            stage=IngestionStage.PARSING,
            progress_percent=10,
            current_document_id=uuid4(),
        )


def test_start_document_moves_document_to_processing(base_time):
    """Pending documents may begin processing."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    started_at = base_time + timedelta(minutes=3)

    updated_job, document = start_first_document(
        service,
        job,
        started_at=started_at,
    )

    assert document.status == IngestionDocumentStatus.PROCESSING
    assert document.stage == IngestionStage.PARSING
    assert document.attempt_count == 1
    assert document.started_at == started_at
    assert updated_job.current_document_id == document.document_id


def test_start_document_rejects_unknown_document(base_time):
    """Unknown document identifiers cannot be started."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(IngestionDocumentNotFoundError):
        service.start_document(
            job.job_id,
            uuid4(),
        )


def test_start_document_rejects_completed_document(base_time):
    """Terminal documents cannot be started again."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.complete_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="pending or queued",
    ):
        service.start_document(
            job.job_id,
            document.document_id,
        )


def test_update_document_progress_updates_fields(base_time):
    """Document progress, diagnostics, and metadata may be updated."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    diagnostic = IngestionDiagnostic(
        message="Manufacturer confidence below preferred threshold.",
    )

    updated = service.update_document_progress(
        job.job_id,
        document.document_id,
        stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
        progress_percent=50,
        diagnostics=[diagnostic],
        warning_count=1,
        metadata={"manufacturer": "Example Manufacturer"},
        updated_at=base_time + timedelta(minutes=4),
    )

    stored_document = updated.documents[0]

    assert stored_document.progress_percent == 50
    assert stored_document.stage == (
        IngestionStage.EXTRACTING_ENGINEERING_FACTS
    )
    assert len(stored_document.warnings) == 1
    assert stored_document.warnings == [diagnostic]
    assert stored_document.errors == []
    assert stored_document.attributes == {
        "manufacturer": "Example Manufacturer"
    }
    assert updated.progress_percent == 50
    assert updated.warning_count == 1


def test_update_document_progress_rejects_pending_document(
    base_time,
):
    """Only processing documents can report progress."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="while processing",
    ):
        service.update_document_progress(
            job.job_id,
            job.documents[0].document_id,
            stage=IngestionStage.PARSING,
            progress_percent=10,
        )


def test_complete_document_records_publication_counts(base_time):
    """Completed documents record knowledge publication outcomes."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    completed = service.complete_document(
        job.job_id,
        document.document_id,
        registered_knowledge_count=4,
        skipped_knowledge_count=1,
        metadata={"published": True},
        completed_at=base_time + timedelta(minutes=4),
    )

    stored_document = completed.documents[0]

    assert stored_document.status == (
        IngestionDocumentStatus.COMPLETED
    )
    assert stored_document.stage == IngestionStage.COMPLETE
    assert stored_document.progress_percent == 100
    assert stored_document.registered_knowledge_count == 4
    assert stored_document.skipped_knowledge_count == 1
    assert completed.completed_document_count == 1
    assert completed.current_document_id is None


def test_complete_document_rejects_negative_counts(base_time):
    """Knowledge counts cannot be negative."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        ValueError,
        match="registered_knowledge_count cannot be negative",
    ):
        service.complete_document(
            job.job_id,
            job.documents[0].document_id,
            registered_knowledge_count=-1,
        )


def test_skip_document_marks_document_terminal(base_time):
    """Pending documents may be skipped during a processing job."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    document = job.documents[0]

    updated = service.skip_document(
        job.job_id,
        document.document_id,
        metadata={"reason": "duplicate"},
        completed_at=base_time + timedelta(minutes=3),
    )

    stored_document = updated.documents[0]

    assert stored_document.status == IngestionDocumentStatus.SKIPPED
    assert stored_document.stage == IngestionStage.COMPLETE
    assert stored_document.progress_percent == 100
    assert updated.skipped_document_count == 1


def test_fail_document_marks_document_failed(base_time):
    """Processing documents may be marked as failed."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    diagnostic = IngestionDiagnostic(
        message="Unable to parse source document.",
    )

    updated = service.fail_document(
        job.job_id,
        document.document_id,
        diagnostics=[diagnostic],
        completed_at=base_time + timedelta(minutes=4),
    )

    stored_document = updated.documents[0]

    assert stored_document.status == IngestionDocumentStatus.FAILED
    assert stored_document.errors == [diagnostic]
    assert updated.failed_document_count == 1
    assert updated.current_document_id is None


def test_request_and_apply_cancellation(base_time):
    """Cancellation requests can be applied to active jobs."""

    service, job = prepare_processing_service(
        created_at=base_time,
        document_count=2,
    )

    requested = service.request_cancellation(
        job.job_id,
        requested_at=base_time + timedelta(minutes=3),
    )

    assert requested.cancellation_requested is True

    cancelled = service.apply_cancellation(
        job.job_id,
        cancelled_at=base_time + timedelta(minutes=4),
    )

    assert cancelled.status == IngestionJobStatus.CANCELLED
    assert cancelled.stage == IngestionStage.COMPLETE
    assert cancelled.completed_at == (
        base_time + timedelta(minutes=4)
    )
    assert all(
        document.status == IngestionDocumentStatus.CANCELLED
        for document in cancelled.documents
    )


def test_apply_cancellation_requires_request(base_time):
    """Cancellation cannot be applied without a request."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        IngestionJobCancellationError,
        match="has not been requested",
    ):
        service.apply_cancellation(job.job_id)


def test_complete_job_with_successful_documents(base_time):
    """A job with only completed documents becomes completed."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.complete_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )

    completed = service.complete(
        job.job_id,
        completed_at=base_time + timedelta(minutes=5),
    )

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.stage == IngestionStage.COMPLETE
    assert completed.progress_percent == 100
    assert completed.completed_document_count == 1


def test_complete_job_with_mixed_outcomes_is_partial(base_time):
    """Mixed successful and failed documents become partially completed."""

    service, job = prepare_processing_service(
        created_at=base_time,
        document_count=2,
    )

    first = job.documents[0]
    second = job.documents[1]

    job = service.start_document(
        job.job_id,
        first.document_id,
        started_at=base_time + timedelta(minutes=3),
    )
    service.complete_document(
        job.job_id,
        first.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )

    service.start_document(
        job.job_id,
        second.document_id,
        started_at=base_time + timedelta(minutes=5),
    )
    service.fail_document(
        job.job_id,
        second.document_id,
        completed_at=base_time + timedelta(minutes=6),
    )

    completed = service.complete(
        job.job_id,
        completed_at=base_time + timedelta(minutes=7),
    )

    assert completed.status == (
        IngestionJobStatus.PARTIALLY_COMPLETED
    )
    assert completed.completed_document_count == 1
    assert completed.failed_document_count == 1


def test_complete_job_with_only_failed_documents_is_failed(
    base_time,
):
    """A job with no successful documents becomes failed."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.fail_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )

    failed = service.complete(
        job.job_id,
        completed_at=base_time + timedelta(minutes=5),
    )

    assert failed.status == IngestionJobStatus.FAILED
    assert failed.failed_document_count == 1


def test_complete_rejects_non_terminal_documents(base_time):
    """Jobs cannot complete while documents remain active."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="documents remain non-terminal",
    ):
        service.complete(job.job_id)


def test_fail_marks_active_job_failed(base_time):
    """Active jobs may be failed explicitly."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    failed_at = base_time + timedelta(minutes=3)

    failed = service.fail(
        job.job_id,
        stage=IngestionStage.FINALISING,
        error_count=3,
        completed_at=failed_at,
    )

    assert failed.status == IngestionJobStatus.FAILED
    assert failed.stage == IngestionStage.FINALISING
    assert failed.error_count == 3
    assert failed.completed_at == failed_at


def test_fail_rejects_terminal_job(base_time):
    """Terminal jobs cannot be failed again."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.fail_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )
    service.complete(
        job.job_id,
        completed_at=base_time + timedelta(minutes=5),
    )

    with pytest.raises(
        InvalidIngestionJobTransitionError,
        match="cannot be failed again",
    ):
        service.fail(job.job_id)


def test_retry_resets_failed_job(base_time):
    """Failed jobs with failed documents may be retried."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.fail_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )
    service.complete(
        job.job_id,
        completed_at=base_time + timedelta(minutes=5),
    )

    retried = service.retry(
        job.job_id,
        retried_at=base_time + timedelta(minutes=6),
    )

    assert retried.status == IngestionJobStatus.PENDING
    assert retried.stage == IngestionStage.WAITING
    assert retried.progress_percent == 0
    assert retried.started_at is None
    assert retried.completed_at is None
    assert retried.failed_document_count == 0
    assert retried.documents[0].status == (
        IngestionDocumentStatus.PENDING
    )
    assert retried.documents[0].attempt_count == 1


def test_retry_rejects_active_job(base_time):
    """Active jobs are not eligible for retry."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        IngestionJobRetryError,
        match="Only failed",
    ):
        service.retry(job.job_id)


def test_retry_document_resets_failed_document(base_time):
    """A failed document may be reset for another attempt."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )
    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    service.fail_document(
        job.job_id,
        document.document_id,
        completed_at=base_time + timedelta(minutes=4),
    )

    retried = service.retry_document(
        job.job_id,
        document.document_id,
        retried_at=base_time + timedelta(minutes=5),
    )

    stored_document = retried.documents[0]

    assert stored_document.status == (
        IngestionDocumentStatus.PENDING
    )
    assert stored_document.stage == IngestionStage.WAITING
    assert stored_document.progress_percent == 0
    assert stored_document.completed_at is None
    assert retried.failed_document_count == 0


def test_retry_document_rejects_non_failed_document(base_time):
    """Only failed documents may be retried."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    with pytest.raises(
        IngestionJobRetryError,
        match="Only a failed document",
    ):
        service.retry_document(
            job.job_id,
            job.documents[0].document_id,
        )


def test_document_progress_recalculates_job_average(base_time):
    """Job progress is the rounded mean of document progress."""

    service, job = prepare_processing_service(
        created_at=base_time,
        document_count=2,
    )

    first = job.documents[0]

    service.start_document(
        job.job_id,
        first.document_id,
        started_at=base_time + timedelta(minutes=3),
    )

    updated = service.update_document_progress(
        job.job_id,
        first.document_id,
        stage=IngestionStage.EXTRACTING_METADATA,
        progress_percent=50,
        updated_at=base_time + timedelta(minutes=4),
    )

    assert updated.progress_percent == 25


def test_document_diagnostics_recalculate_job_counts(base_time):
    """Document warning and error counts roll up to the job."""

    service, job = prepare_processing_service(
        created_at=base_time,
    )

    job, document = start_first_document(
        service,
        job,
        started_at=base_time + timedelta(minutes=3),
    )

    updated = service.update_document_progress(
        job.job_id,
        document.document_id,
        stage=IngestionStage.PARSING,
        progress_percent=20,
        warning_count=2,
        error_count=3,
        updated_at=base_time + timedelta(minutes=4),
    )

    assert updated.warning_count == 2
    assert updated.error_count == 3