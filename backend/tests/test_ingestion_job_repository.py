"""Tests for the Engineer4Me ingestion job repository."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)
from app.ingestion.ingestion_job_repository import (
    DuplicateIngestionJobError,
    IngestionJobConflictError,
    IngestionJobNotFoundError,
    IngestionJobQuery,
    IngestionJobRepository,
    IngestionJobSortOrder,
)


@pytest.fixture
def base_time() -> datetime:
    """Return a stable timezone-aware timestamp."""

    return datetime(2026, 7, 27, 10, 0, tzinfo=UTC)


def build_pending_document(
    *,
    source_name: str = "manual.pdf",
) -> IngestionDocumentResult:
    """Build a valid pending document."""

    return IngestionDocumentResult(
        source_name=source_name,
    )


def build_completed_document(
    *,
    source_name: str = "completed.pdf",
    registered_knowledge_count: int = 2,
    started_at: datetime,
) -> IngestionDocumentResult:
    """Build a valid completed document."""

    return IngestionDocumentResult(
        source_name=source_name,
        status=IngestionDocumentStatus.COMPLETED,
        stage=IngestionStage.COMPLETE,
        progress_percent=100,
        attempt_count=1,
        registered_knowledge_count=registered_knowledge_count,
        started_at=started_at,
        completed_at=started_at + timedelta(minutes=1),
        updated_at=started_at + timedelta(minutes=1),
    )


def build_failed_document(
    *,
    source_name: str = "failed.pdf",
    started_at: datetime,
) -> IngestionDocumentResult:
    """Build a valid failed document."""

    return IngestionDocumentResult(
        source_name=source_name,
        status=IngestionDocumentStatus.FAILED,
        stage=IngestionStage.PARSING,
        progress_percent=30,
        attempt_count=1,
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=30),
        updated_at=started_at + timedelta(seconds=30),
    )


def build_pending_job(
    *,
    created_at: datetime,
    submitted_by: str = "test-user",
    correlation_id: str | None = None,
    source_type: IngestionSourceType = IngestionSourceType.API_UPLOAD,
    job_type: IngestionJobType = IngestionJobType.SINGLE_DOCUMENT,
) -> IngestionJob:
    """Build a valid pending ingestion job."""

    document = build_pending_document()

    return IngestionJob(
        job_type=job_type,
        source_type=source_type,
        submitted_by=submitted_by,
        correlation_id=correlation_id,
        documents=[document],
        total_document_count=1,
        created_at=created_at,
        updated_at=created_at,
    )


def build_processing_job(
    *,
    created_at: datetime,
    progress_percent: int = 50,
) -> IngestionJob:
    """Build a valid processing ingestion job."""

    document = IngestionDocumentResult(
        source_name="processing.pdf",
        status=IngestionDocumentStatus.PROCESSING,
        stage=IngestionStage.EXTRACTING_METADATA,
        progress_percent=progress_percent,
        attempt_count=1,
        started_at=created_at + timedelta(minutes=1),
        updated_at=created_at + timedelta(minutes=2),
    )

    return IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="processor",
        status=IngestionJobStatus.PROCESSING,
        stage=IngestionStage.EXTRACTING_METADATA,
        documents=[document],
        progress_percent=progress_percent,
        current_document_id=document.document_id,
        total_document_count=1,
        created_at=created_at,
        started_at=created_at + timedelta(minutes=1),
        updated_at=created_at + timedelta(minutes=2),
    )


def build_completed_job(
    *,
    created_at: datetime,
    submitted_by: str = "test-user",
    registered_knowledge_count: int = 2,
) -> IngestionJob:
    """Build a valid completed ingestion job."""

    document = build_completed_document(
        started_at=created_at + timedelta(minutes=1),
        registered_knowledge_count=registered_knowledge_count,
    )

    return IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by=submitted_by,
        status=IngestionJobStatus.COMPLETED,
        stage=IngestionStage.COMPLETE,
        documents=[document],
        progress_percent=100,
        total_document_count=1,
        completed_document_count=1,
        created_at=created_at,
        started_at=created_at + timedelta(minutes=1),
        completed_at=created_at + timedelta(minutes=3),
        updated_at=created_at + timedelta(minutes=3),
    )


def build_failed_job(
    *,
    created_at: datetime,
) -> IngestionJob:
    """Build a valid failed ingestion job."""

    document = build_failed_document(
        started_at=created_at + timedelta(minutes=1),
    )

    return IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.LOCAL_FILE,
        submitted_by="worker",
        status=IngestionJobStatus.FAILED,
        stage=IngestionStage.FINALISING,
        documents=[document],
        progress_percent=30,
        total_document_count=1,
        failed_document_count=1,
        error_count=1,
        created_at=created_at,
        started_at=created_at + timedelta(minutes=1),
        completed_at=created_at + timedelta(minutes=3),
        updated_at=created_at + timedelta(minutes=3),
    )


def test_repository_starts_empty():
    """A new repository contains no jobs."""

    repository = IngestionJobRepository()

    assert repository.count() == 0
    assert repository.list_all() == []


def test_repository_accepts_initial_jobs(base_time):
    """Jobs may be supplied when constructing the repository."""

    job = build_pending_job(created_at=base_time)

    repository = IngestionJobRepository([job])

    assert repository.count() == 1
    assert repository.get(job.job_id) == job


def test_add_stores_and_returns_job(base_time):
    """Adding a job stores and returns a validated copy."""

    repository = IngestionJobRepository()
    job = build_pending_job(created_at=base_time)

    stored = repository.add(job)

    assert stored == job
    assert repository.get(job.job_id) == job


def test_add_rejects_non_job_value():
    """Only IngestionJob instances may be stored."""

    repository = IngestionJobRepository()

    with pytest.raises(
        TypeError,
        match="job must be an IngestionJob instance",
    ):
        repository.add("not-a-job")  # type: ignore[arg-type]


def test_add_rejects_duplicate_identifier(base_time):
    """Duplicate job identifiers are rejected."""

    repository = IngestionJobRepository()
    job = build_pending_job(created_at=base_time)

    repository.add(job)

    with pytest.raises(
        DuplicateIngestionJobError,
        match="already exists",
    ):
        repository.add(job)


def test_add_many_stores_all_jobs(base_time):
    """Several jobs can be stored atomically."""

    first = build_pending_job(created_at=base_time)
    second = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository()

    stored = repository.add_many([first, second])

    assert stored == [first, second]
    assert repository.count() == 2


def test_add_many_rejects_duplicate_submitted_identifiers(base_time):
    """Duplicate identifiers within one batch are rejected."""

    job = build_pending_job(created_at=base_time)

    repository = IngestionJobRepository()

    with pytest.raises(
        DuplicateIngestionJobError,
        match="submitted jobs contain duplicate",
    ):
        repository.add_many([job, job])

    assert repository.count() == 0


def test_add_many_is_atomic_when_existing_job_conflicts(base_time):
    """No jobs are stored when one submitted identifier already exists."""

    existing = build_pending_job(created_at=base_time)
    new_job = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository([existing])

    with pytest.raises(
        DuplicateIngestionJobError,
        match="already exist",
    ):
        repository.add_many([new_job, existing])

    assert repository.count() == 1
    assert repository.exists(new_job.job_id) is False


def test_get_raises_for_unknown_job():
    """Unknown job identifiers raise an explicit error."""

    repository = IngestionJobRepository()

    with pytest.raises(
        IngestionJobNotFoundError,
        match="was not found",
    ):
        repository.get(uuid4())


def test_exists_reports_presence(base_time):
    """Existence checks reflect repository contents."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    assert repository.exists(job.job_id) is True
    assert repository.exists(uuid4()) is False


def test_get_returns_defensive_copy(base_time):
    """Retrieved jobs do not expose internal repository state."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    retrieved = repository.get(job.job_id)
    retrieved.metadata["external"] = True

    stored_again = repository.get(job.job_id)

    assert stored_again.metadata == {}


def test_add_isolated_from_original_object(base_time):
    """Changing the original object does not mutate stored state."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository()

    repository.add(job)
    job.metadata["changed"] = True

    stored = repository.get(job.job_id)

    assert stored.metadata == {}


def test_replace_updates_existing_job(base_time):
    """Existing jobs may be replaced while preserving creation time."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    replacement = job.model_copy(
        update={
            "status": IngestionJobStatus.QUEUED,
            "queued_at": base_time + timedelta(minutes=1),
            "updated_at": base_time + timedelta(minutes=1),
        }
    )

    stored = repository.replace(replacement)

    assert stored.status == IngestionJobStatus.QUEUED
    assert repository.get(job.job_id).queued_at is not None


def test_replace_rejects_unknown_job(base_time):
    """Replacing an unknown job raises a not-found error."""

    repository = IngestionJobRepository()
    job = build_pending_job(created_at=base_time)

    with pytest.raises(IngestionJobNotFoundError):
        repository.replace(job)


def test_replace_rejects_changed_created_at(base_time):
    """The original job creation timestamp is immutable."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    replacement = job.model_copy(
        update={
            "created_at": base_time + timedelta(hours=1),
        }
    )

    with pytest.raises(
        IngestionJobConflictError,
        match="created_at cannot be changed",
    ):
        repository.replace(replacement)


def test_upsert_adds_unknown_job(base_time):
    """Upsert creates a job when no current record exists."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository()

    stored = repository.upsert(job)

    assert stored == job
    assert repository.count() == 1


def test_upsert_replaces_existing_job(base_time):
    """Upsert replaces an existing job."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    replacement = job.model_copy(
        update={
            "status": IngestionJobStatus.QUEUED,
            "queued_at": base_time + timedelta(minutes=1),
            "updated_at": base_time + timedelta(minutes=1),
        }
    )

    repository.upsert(replacement)

    assert repository.get(job.job_id).status == IngestionJobStatus.QUEUED


def test_upsert_rejects_changed_created_at(base_time):
    """Upsert cannot rewrite the original creation timestamp."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    changed = job.model_copy(
        update={
            "created_at": base_time + timedelta(days=1),
        }
    )

    with pytest.raises(IngestionJobConflictError):
        repository.upsert(changed)


def test_request_cancellation_marks_pending_job(base_time):
    """Cancellation requests update a non-terminal job."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])
    requested_at = base_time + timedelta(minutes=5)

    updated = repository.request_cancellation(
        job.job_id,
        requested_at=requested_at,
    )

    assert updated.cancellation_requested is True
    assert updated.updated_at == requested_at
    assert repository.get(job.job_id).cancellation_requested is True


def test_request_cancellation_rejects_terminal_job(base_time):
    """Terminal jobs cannot receive cancellation requests."""

    job = build_completed_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    with pytest.raises(
        IngestionJobConflictError,
        match="terminal job",
    ):
        repository.request_cancellation(job.job_id)


def test_request_cancellation_rejects_unknown_job():
    """Cancellation requires an existing job."""

    repository = IngestionJobRepository()

    with pytest.raises(IngestionJobNotFoundError):
        repository.request_cancellation(uuid4())


def test_delete_removes_job(base_time):
    """Deleting a job removes it from storage."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    repository.delete(job.job_id)

    assert repository.count() == 0
    assert repository.exists(job.job_id) is False


def test_delete_rejects_unknown_job():
    """Deleting an unknown job raises a not-found error."""

    repository = IngestionJobRepository()

    with pytest.raises(IngestionJobNotFoundError):
        repository.delete(uuid4())


def test_clear_removes_all_jobs(base_time):
    """Clear empties the repository."""

    jobs = [
        build_pending_job(created_at=base_time),
        build_pending_job(
            created_at=base_time + timedelta(minutes=1),
        ),
    ]
    repository = IngestionJobRepository(jobs)

    repository.clear()

    assert repository.count() == 0


def test_list_all_orders_newest_first(base_time):
    """Job listing is ordered by creation time descending."""

    oldest = build_pending_job(created_at=base_time)
    newest = build_pending_job(
        created_at=base_time + timedelta(hours=1),
    )
    middle = build_pending_job(
        created_at=base_time + timedelta(minutes=30),
    )

    repository = IngestionJobRepository(
        [oldest, newest, middle]
    )

    jobs = repository.list_all()

    assert [job.job_id for job in jobs] == [
        newest.job_id,
        middle.job_id,
        oldest.job_id,
    ]


def test_query_rejects_invalid_date_range(base_time):
    """Query date ranges must be chronological."""

    with pytest.raises(
        ValidationError,
        match="created_from cannot be later",
    ):
        IngestionJobQuery(
            created_from=base_time + timedelta(days=1),
            created_to=base_time,
        )


def test_query_normalises_optional_text():
    """Optional text filters are stripped."""

    query = IngestionJobQuery(
        submitted_by="  test-user  ",
        correlation_id="  batch-001  ",
    )

    assert query.submitted_by == "test-user"
    assert query.correlation_id == "batch-001"


def test_search_filters_by_status(base_time):
    """Search can filter jobs by lifecycle status."""

    pending = build_pending_job(created_at=base_time)
    completed = build_completed_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository(
        [pending, completed]
    )

    result = repository.search(
        IngestionJobQuery(
            statuses=[IngestionJobStatus.COMPLETED],
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == completed.job_id


def test_search_filters_by_job_type_and_source_type(base_time):
    """Search combines job-type and source-type filters."""

    matching = build_pending_job(
        created_at=base_time,
        job_type=IngestionJobType.DOCUMENT_BATCH,
        source_type=IngestionSourceType.DIRECTORY_SCAN,
    )
    other = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository(
        [matching, other]
    )

    result = repository.search(
        IngestionJobQuery(
            job_types=[IngestionJobType.DOCUMENT_BATCH],
            source_types=[IngestionSourceType.DIRECTORY_SCAN],
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == matching.job_id


def test_search_filters_submitted_by_case_insensitively(base_time):
    """Submitter filtering is case-insensitive."""

    matching = build_pending_job(
        created_at=base_time,
        submitted_by="Ingestion-API",
    )
    other = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
        submitted_by="other-user",
    )

    repository = IngestionJobRepository(
        [matching, other]
    )

    result = repository.search(
        IngestionJobQuery(
            submitted_by="ingestion-api",
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == matching.job_id


def test_search_filters_correlation_id_case_insensitively(
    base_time,
):
    """Correlation identifiers are matched case-insensitively."""

    matching = build_pending_job(
        created_at=base_time,
        correlation_id="Batch-ABC",
    )
    other = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
        correlation_id="Batch-XYZ",
    )

    repository = IngestionJobRepository(
        [matching, other]
    )

    result = repository.search(
        IngestionJobQuery(
            correlation_id="batch-abc",
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == matching.job_id


def test_search_filters_creation_range(base_time):
    """Search supports inclusive creation timestamps."""

    before = build_pending_job(
        created_at=base_time,
    )
    matching = build_pending_job(
        created_at=base_time + timedelta(hours=1),
    )
    after = build_pending_job(
        created_at=base_time + timedelta(hours=2),
    )

    repository = IngestionJobRepository(
        [before, matching, after]
    )

    result = repository.search(
        IngestionJobQuery(
            created_from=base_time + timedelta(minutes=30),
            created_to=base_time + timedelta(
                hours=1,
                minutes=30,
            ),
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == matching.job_id


def test_search_can_exclude_terminal_jobs(base_time):
    """Terminal jobs can be excluded from monitoring queries."""

    pending = build_pending_job(created_at=base_time)
    completed = build_completed_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository(
        [pending, completed]
    )

    result = repository.search(
        IngestionJobQuery(
            include_terminal=False,
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == pending.job_id


def test_search_filters_cancellation_requested(base_time):
    """Search can select cancellation-requested jobs."""

    first = build_pending_job(created_at=base_time)
    second = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
    )

    repository = IngestionJobRepository(
        [first, second]
    )
    repository.request_cancellation(first.job_id)

    result = repository.search(
        IngestionJobQuery(
            cancellation_requested=True,
        )
    )

    assert result.total_matches == 1
    assert result.jobs[0].job_id == first.job_id


@pytest.mark.parametrize(
    ("sort_order", "expected_progress"),
    [
        (
            IngestionJobSortOrder.PROGRESS_ASCENDING,
            [10, 50, 90],
        ),
        (
            IngestionJobSortOrder.PROGRESS_DESCENDING,
            [90, 50, 10],
        ),
    ],
)
def test_search_sorts_by_progress(
    base_time,
    sort_order,
    expected_progress,
):
    """Search can order jobs by progress percentage."""

    jobs = [
        build_processing_job(
            created_at=base_time,
            progress_percent=50,
        ),
        build_processing_job(
            created_at=base_time + timedelta(minutes=1),
            progress_percent=10,
        ),
        build_processing_job(
            created_at=base_time + timedelta(minutes=2),
            progress_percent=90,
        ),
    ]

    repository = IngestionJobRepository(jobs)

    result = repository.search(
        IngestionJobQuery(
            sort_order=sort_order,
        )
    )

    assert [
        summary.progress_percent
        for summary in result.jobs
    ] == expected_progress


def test_search_sorts_by_updated_time_ascending(base_time):
    """Search can order jobs by last update time."""

    first = build_pending_job(created_at=base_time)
    second = build_pending_job(
        created_at=base_time + timedelta(minutes=1),
    )

    first = first.model_copy(
        update={
            "updated_at": base_time + timedelta(hours=2),
        }
    )
    second = second.model_copy(
        update={
            "updated_at": base_time + timedelta(hours=1),
        }
    )

    repository = IngestionJobRepository(
        [first, second]
    )

    result = repository.search(
        IngestionJobQuery(
            sort_order=(
                IngestionJobSortOrder.UPDATED_ASCENDING
            ),
        )
    )

    assert [job.job_id for job in result.jobs] == [
        second.job_id,
        first.job_id,
    ]


def test_search_paginates_results(base_time):
    """Search returns the requested page and total match count."""

    jobs = [
        build_pending_job(
            created_at=base_time + timedelta(minutes=index),
        )
        for index in range(5)
    ]

    repository = IngestionJobRepository(jobs)

    result = repository.search(
        IngestionJobQuery(
            sort_order=(
                IngestionJobSortOrder.CREATED_ASCENDING
            ),
            offset=1,
            limit=2,
        )
    )

    assert result.total_matches == 5
    assert result.returned_matches == 2
    assert result.offset == 1
    assert result.limit == 2
    assert [summary.job_id for summary in result.jobs] == [
        jobs[1].job_id,
        jobs[2].job_id,
    ]


def test_search_returns_compact_summaries(base_time):
    """Search results contain monitoring summaries."""

    job = build_pending_job(created_at=base_time)
    repository = IngestionJobRepository([job])

    result = repository.search(IngestionJobQuery())

    summary = result.jobs[0]

    assert summary.job_id == job.job_id
    assert summary.submitted_by == job.submitted_by
    assert summary.total_document_count == 1


def test_statistics_for_empty_repository():
    """Empty repositories return zeroed statistics."""

    statistics = IngestionJobRepository().statistics()

    assert statistics.total_jobs == 0
    assert statistics.total_documents == 0
    assert statistics.registered_knowledge_count == 0


def test_statistics_aggregate_jobs_documents_and_knowledge(
    base_time,
):
    """Statistics aggregate lifecycle and publication outcomes."""

    pending = build_pending_job(created_at=base_time)
    processing = build_processing_job(
        created_at=base_time + timedelta(minutes=1),
    )
    completed = build_completed_job(
        created_at=base_time + timedelta(minutes=2),
        registered_knowledge_count=7,
    )
    failed = build_failed_job(
        created_at=base_time + timedelta(minutes=3),
    )

    repository = IngestionJobRepository(
        [
            pending,
            processing,
            completed,
            failed,
        ]
    )

    statistics = repository.statistics()

    assert statistics.total_jobs == 4
    assert statistics.pending_jobs == 1
    assert statistics.processing_jobs == 1
    assert statistics.completed_jobs == 1
    assert statistics.failed_jobs == 1

    assert statistics.total_documents == 4
    assert statistics.completed_documents == 1
    assert statistics.failed_documents == 1
    assert statistics.registered_knowledge_count == 7
