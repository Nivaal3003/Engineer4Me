"""Tests for Engineer4Me ingestion job and progress models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.ingestion.ingestion_job_models import (
    IngestionDiagnostic,
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionFailureCategory,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)


@pytest.fixture
def now():
    """Return a stable timezone-aware timestamp."""

    return datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


@pytest.fixture
def pending_document():
    """Return a valid pending ingestion document."""

    return IngestionDocumentResult(
        source_name="manuals/PT-100 installation manual.pdf",
        source_path="/uploads/manuals/PT-100 installation manual.pdf",
        media_type="application/pdf",
        file_size_bytes=250_000,
        checksum_sha256="a" * 64,
    )


@pytest.fixture
def completed_document(now):
    """Return a valid completed ingestion document."""

    return IngestionDocumentResult(
        source_name="completed-manual.pdf",
        status=IngestionDocumentStatus.COMPLETED,
        stage=IngestionStage.COMPLETE,
        progress_percent=100,
        attempt_count=1,
        maximum_attempts=3,
        parsed_page_count=24,
        extracted_fact_count=18,
        duplicate_fact_count=2,
        generated_knowledge_count=16,
        registered_knowledge_count=14,
        skipped_knowledge_count=2,
        failed_knowledge_count=0,
        registered_knowledge_ids=[
            "knowledge-001",
            "knowledge-002",
        ],
        started_at=now,
        completed_at=now + timedelta(minutes=2),
        updated_at=now + timedelta(minutes=2),
    )


def test_pending_document_defaults_are_valid(pending_document):
    """New documents start in a valid pending state."""

    assert pending_document.status == IngestionDocumentStatus.PENDING
    assert pending_document.stage == IngestionStage.WAITING
    assert pending_document.progress_percent == 0
    assert pending_document.attempt_count == 0
    assert pending_document.terminal is False
    assert pending_document.retry_available is False
    assert pending_document.filename == "PT-100 installation manual.pdf"


def test_document_checksum_is_normalised():
    """SHA-256 checksums are stored in lowercase form."""

    document = IngestionDocumentResult(
        source_name="manual.pdf",
        checksum_sha256="ABCDEF" * 10 + "ABCD",
    )

    assert document.checksum_sha256 == (
        "abcdef" * 10 + "abcd"
    )


@pytest.mark.parametrize(
    "checksum",
    [
        "abc",
        "g" * 64,
        "a" * 63,
        "a" * 65,
    ],
)
def test_document_rejects_invalid_checksum(checksum):
    """Invalid SHA-256 values are rejected."""

    with pytest.raises(ValidationError):
        IngestionDocumentResult(
            source_name="manual.pdf",
            checksum_sha256=checksum,
        )


def test_document_rejects_blank_source_name():
    """Documents require a meaningful source name."""

    with pytest.raises(
        ValidationError,
        match="source_name cannot be empty",
    ):
        IngestionDocumentResult(source_name="   ")


def test_processing_document_requires_started_at():
    """A processing document must record when work began."""

    with pytest.raises(
        ValidationError,
        match="Processing documents require started_at",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=IngestionDocumentStatus.PROCESSING,
            stage=IngestionStage.PARSING,
            progress_percent=20,
        )


@pytest.mark.parametrize(
    "stage",
    [
        IngestionStage.WAITING,
        IngestionStage.COMPLETE,
    ],
)
def test_processing_document_requires_active_stage(now, stage):
    """Processing cannot use waiting or complete stages."""

    with pytest.raises(
        ValidationError,
        match="active processing stage",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=IngestionDocumentStatus.PROCESSING,
            stage=stage,
            progress_percent=20,
            started_at=now,
        )


def test_completed_document_requires_full_progress(now):
    """Completed documents must report 100 percent progress."""

    with pytest.raises(
        ValidationError,
        match="progress_percent equal to 100",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=IngestionDocumentStatus.COMPLETED,
            stage=IngestionStage.COMPLETE,
            progress_percent=90,
            started_at=now,
            completed_at=now + timedelta(minutes=1),
        )


def test_completed_document_requires_complete_stage(now):
    """Completed documents must use the complete stage."""

    with pytest.raises(
        ValidationError,
        match="complete ingestion stage",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=IngestionDocumentStatus.COMPLETED,
            stage=IngestionStage.FINALISING,
            progress_percent=100,
            started_at=now,
            completed_at=now + timedelta(minutes=1),
        )


@pytest.mark.parametrize(
    "status",
    [
        IngestionDocumentStatus.COMPLETED,
        IngestionDocumentStatus.SKIPPED,
        IngestionDocumentStatus.FAILED,
        IngestionDocumentStatus.CANCELLED,
    ],
)
def test_terminal_document_requires_completed_at(status):
    """Every terminal document status requires a completion timestamp."""

    stage = (
        IngestionStage.COMPLETE
        if status == IngestionDocumentStatus.COMPLETED
        else IngestionStage.FINALISING
    )
    progress = (
        100
        if status == IngestionDocumentStatus.COMPLETED
        else 0
    )

    with pytest.raises(
        ValidationError,
        match="Terminal document statuses require completed_at",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=status,
            stage=stage,
            progress_percent=progress,
        )


def test_document_rejects_attempt_count_above_maximum():
    """Attempt count cannot exceed the configured retry limit."""

    with pytest.raises(
        ValidationError,
        match="attempt_count cannot exceed maximum_attempts",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            attempt_count=4,
            maximum_attempts=3,
        )


def test_document_rejects_completion_before_start(now):
    """Document completion cannot occur before processing starts."""

    with pytest.raises(
        ValidationError,
        match="completed_at cannot be earlier",
    ):
        IngestionDocumentResult(
            source_name="manual.pdf",
            status=IngestionDocumentStatus.FAILED,
            stage=IngestionStage.PARSING,
            started_at=now,
            completed_at=now - timedelta(seconds=1),
        )


def test_failed_document_can_be_retried(now):
    """Failed documents below their attempt limit remain retryable."""

    document = IngestionDocumentResult(
        source_name="manual.pdf",
        status=IngestionDocumentStatus.FAILED,
        stage=IngestionStage.PARSING,
        attempt_count=1,
        maximum_attempts=3,
        started_at=now,
        completed_at=now + timedelta(seconds=30),
    )

    assert document.terminal is True
    assert document.retry_available is True


def test_failed_document_at_attempt_limit_cannot_be_retried(now):
    """Failed documents at their retry limit cannot be retried."""

    document = IngestionDocumentResult(
        source_name="manual.pdf",
        status=IngestionDocumentStatus.FAILED,
        stage=IngestionStage.PARSING,
        attempt_count=3,
        maximum_attempts=3,
        started_at=now,
        completed_at=now + timedelta(seconds=30),
    )

    assert document.retry_available is False


def test_diagnostic_strips_text_and_preserves_details():
    """Diagnostics normalise text and preserve structured context."""

    document_id = uuid4()

    diagnostic = IngestionDiagnostic(
        code="  PARSE-001  ",
        message="  Unable to parse embedded table.  ",
        stage=IngestionStage.PARSING,
        failure_category=IngestionFailureCategory.PARSING,
        document_id=document_id,
        recoverable=True,
        details={"page": 7},
    )

    assert diagnostic.code == "PARSE-001"
    assert diagnostic.message == "Unable to parse embedded table."
    assert diagnostic.document_id == document_id
    assert diagnostic.recoverable is True
    assert diagnostic.details == {"page": 7}


def test_pending_job_defaults_are_valid(pending_document):
    """New jobs start in a valid pending state."""

    job = IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="test-user",
        documents=[pending_document],
        total_document_count=1,
    )

    assert job.status == IngestionJobStatus.PENDING
    assert job.stage == IngestionStage.WAITING
    assert job.progress_percent == 0
    assert job.terminal is False
    assert job.remaining_document_count == 1
    assert job.successful_document_count == 0
    assert job.registered_knowledge_count == 0


def test_job_strips_submitted_by(pending_document):
    """Job submitter identifiers are normalised."""

    job = IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="  ingestion-api  ",
        documents=[pending_document],
        total_document_count=1,
    )

    assert job.submitted_by == "ingestion-api"


def test_job_rejects_blank_submitted_by(pending_document):
    """Jobs require a submitting user or system identifier."""

    with pytest.raises(
        ValidationError,
        match="submitted_by cannot be empty",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="   ",
            documents=[pending_document],
            total_document_count=1,
        )


def test_job_document_count_must_match_documents(pending_document):
    """Declared document count must match the document collection."""

    with pytest.raises(
        ValidationError,
        match="total_document_count must equal",
    ):
        IngestionJob(
            job_type=IngestionJobType.DOCUMENT_BATCH,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=2,
        )


def test_job_rejects_outcomes_above_total(pending_document):
    """Document outcome counts cannot exceed the batch size."""

    with pytest.raises(
        ValidationError,
        match="outcome counts cannot exceed",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=1,
            completed_document_count=1,
            failed_document_count=1,
        )


def test_processing_job_requires_started_at(pending_document):
    """A processing job must record when processing started."""

    with pytest.raises(
        ValidationError,
        match="Processing jobs require started_at",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=1,
            status=IngestionJobStatus.PROCESSING,
            stage=IngestionStage.PARSING,
        )


@pytest.mark.parametrize(
    "stage",
    [
        IngestionStage.WAITING,
        IngestionStage.COMPLETE,
    ],
)
def test_processing_job_requires_active_stage(
    pending_document,
    now,
    stage,
):
    """Processing jobs cannot use waiting or complete stages."""

    with pytest.raises(
        ValidationError,
        match="active processing stage",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=1,
            status=IngestionJobStatus.PROCESSING,
            stage=stage,
            started_at=now,
        )


@pytest.mark.parametrize(
    "status",
    [
        IngestionJobStatus.COMPLETED,
        IngestionJobStatus.PARTIALLY_COMPLETED,
        IngestionJobStatus.FAILED,
        IngestionJobStatus.CANCELLED,
    ],
)
def test_terminal_job_requires_completed_at(
    pending_document,
    status,
):
    """Terminal jobs require a completion timestamp."""

    stage = (
        IngestionStage.COMPLETE
        if status == IngestionJobStatus.COMPLETED
        else IngestionStage.FINALISING
    )
    progress = (
        100
        if status == IngestionJobStatus.COMPLETED
        else 0
    )

    with pytest.raises(
        ValidationError,
        match="Terminal job statuses require completed_at",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=1,
            status=status,
            stage=stage,
            progress_percent=progress,
        )


def test_completed_job_requires_full_progress(
    completed_document,
    now,
):
    """Completed jobs must report 100 percent progress."""

    with pytest.raises(
        ValidationError,
        match="progress_percent equal to 100",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[completed_document],
            total_document_count=1,
            completed_document_count=1,
            status=IngestionJobStatus.COMPLETED,
            stage=IngestionStage.COMPLETE,
            progress_percent=90,
            started_at=now,
            completed_at=now + timedelta(minutes=3),
        )


def test_completed_job_requires_complete_stage(
    completed_document,
    now,
):
    """Completed jobs must use the complete stage."""

    with pytest.raises(
        ValidationError,
        match="complete ingestion stage",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[completed_document],
            total_document_count=1,
            completed_document_count=1,
            status=IngestionJobStatus.COMPLETED,
            stage=IngestionStage.FINALISING,
            progress_percent=100,
            started_at=now,
            completed_at=now + timedelta(minutes=3),
        )


def test_completed_job_requires_outcome_for_every_document(
    completed_document,
    pending_document,
    now,
):
    """A completed batch requires a terminal outcome for every document."""

    with pytest.raises(
        ValidationError,
        match="outcome for every document",
    ):
        IngestionJob(
            job_type=IngestionJobType.DOCUMENT_BATCH,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[
                completed_document,
                pending_document,
            ],
            total_document_count=2,
            completed_document_count=1,
            status=IngestionJobStatus.COMPLETED,
            stage=IngestionStage.COMPLETE,
            progress_percent=100,
            started_at=now,
            completed_at=now + timedelta(minutes=3),
        )


def test_completed_job_rejects_failed_documents(
    completed_document,
    now,
):
    """A fully completed job cannot report failed documents."""

    with pytest.raises(
        ValidationError,
        match="cannot contain failed or cancelled",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[completed_document],
            total_document_count=1,
            failed_document_count=1,
            status=IngestionJobStatus.COMPLETED,
            stage=IngestionStage.COMPLETE,
            progress_percent=100,
            started_at=now,
            completed_at=now + timedelta(minutes=3),
        )


def test_job_rejects_duplicate_document_ids(
    pending_document,
):
    """A job cannot contain the same document identifier twice."""

    duplicate = pending_document.model_copy()

    with pytest.raises(
        ValidationError,
        match="duplicate document_id",
    ):
        IngestionJob(
            job_type=IngestionJobType.DOCUMENT_BATCH,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[
                pending_document,
                duplicate,
            ],
            total_document_count=2,
        )


def test_current_document_must_belong_to_job(
    pending_document,
):
    """Current processing document must be part of the job."""

    with pytest.raises(
        ValidationError,
        match="current_document_id must identify",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[pending_document],
            total_document_count=1,
            current_document_id=uuid4(),
        )


def test_job_rejects_completion_before_start(
    completed_document,
    now,
):
    """Job completion cannot occur before processing starts."""

    with pytest.raises(
        ValidationError,
        match="completed_at cannot be earlier",
    ):
        IngestionJob(
            job_type=IngestionJobType.SINGLE_DOCUMENT,
            source_type=IngestionSourceType.API_UPLOAD,
            submitted_by="test-user",
            documents=[completed_document],
            total_document_count=1,
            completed_document_count=1,
            status=IngestionJobStatus.COMPLETED,
            stage=IngestionStage.COMPLETE,
            progress_percent=100,
            started_at=now,
            completed_at=now - timedelta(seconds=1),
        )


def test_completed_job_aggregate_properties(
    completed_document,
    now,
):
    """Completed jobs calculate remaining and knowledge totals."""

    job = IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="test-user",
        documents=[completed_document],
        total_document_count=1,
        completed_document_count=1,
        status=IngestionJobStatus.COMPLETED,
        stage=IngestionStage.COMPLETE,
        progress_percent=100,
        started_at=now,
        completed_at=now + timedelta(minutes=3),
    )

    assert job.terminal is True
    assert job.successful_document_count == 1
    assert job.remaining_document_count == 0
    assert job.registered_knowledge_count == 14
