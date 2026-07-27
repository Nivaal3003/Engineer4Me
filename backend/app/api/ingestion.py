"""FastAPI routes for document-ingestion job lifecycle management.

The router exposes the ingestion job service through a versioned REST
interface. It supports:

- submitting document-ingestion jobs;
- searching and retrieving jobs;
- viewing ingestion statistics;
- queueing and starting jobs;
- requesting and applying cancellation;
- retrying failed jobs and individual documents.

Binary upload storage and execution of the document-processing pipeline are
deliberately kept outside this router. Those Phase 6 integrations can use the
same service dependency without changing this public API contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ValidationError

from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
    IngestionJobStatistics,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
    InvalidIngestionJobTransitionError,
)
from app.ingestion.ingestion_job_repository import (
    DuplicateIngestionJobError,
    IngestionJobConflictError,
    IngestionJobNotFoundError,
    IngestionJobQuery,
    IngestionJobQueryResult,
    IngestionJobRepository,
    IngestionJobRepositoryError,
    IngestionJobSortOrder,
)
from app.ingestion.ingestion_job_service import (
    IngestionDocumentNotFoundError,
    IngestionJobCancellationError,
    IngestionJobRetryError,
    IngestionJobService,
    IngestionJobServiceError,
)


router = APIRouter(
    prefix="/ingestion",
    tags=["Document Ingestion"],
)


_ingestion_job_repository = IngestionJobRepository()
_ingestion_job_service = IngestionJobService(_ingestion_job_repository)


def get_ingestion_job_service() -> IngestionJobService:
    """Return the shared ingestion job service."""

    return _ingestion_job_service


IngestionJobServiceDependency = Annotated[
    IngestionJobService,
    Depends(get_ingestion_job_service),
]


class IngestionDocumentSubmission(BaseModel):
    """Document metadata supplied when an ingestion job is created."""

    source_name: str = Field(
        min_length=1,
        max_length=500,
        description="Original document name presented to the ingestion system.",
    )
    source_path: str | None = Field(
        default=None,
        max_length=2000,
        description="Resolved storage path or object-storage key, when available.",
    )
    media_type: str | None = Field(
        default=None,
        max_length=255,
        description="Document media type, such as application/pdf.",
    )
    file_size_bytes: int | None = Field(
        default=None,
        ge=0,
        description="Document size in bytes.",
    )
    checksum_sha256: str | None = Field(
        default=None,
        max_length=64,
        description="Lowercase or uppercase SHA-256 checksum.",
    )
    maximum_attempts: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Maximum processing attempts permitted for the document.",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional source, compliance, ownership, or processing metadata."
        ),
    )


class IngestionJobSubmissionRequest(BaseModel):
    """Request body for registering a new ingestion job."""

    job_type: IngestionJobType
    source_type: IngestionSourceType = IngestionSourceType.API_UPLOAD
    submitted_by: str = Field(
        min_length=1,
        max_length=255,
        description="User or system identity that submitted the job.",
    )
    correlation_id: str | None = Field(
        default=None,
        max_length=255,
        description="Optional caller-provided trace or batch identifier.",
    )
    documents: list[IngestionDocumentSubmission] = Field(
        min_length=1,
        max_length=1000,
        description="Documents included in the ingestion job.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Job-level source, compliance, intellectual-property, or workflow "
            "metadata."
        ),
    )


class IngestionJobSearchRequest(BaseModel):
    """Structured search request for ingestion jobs."""

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


class IngestionJobStartRequest(BaseModel):
    """Request body for starting a queued ingestion job."""

    stage: IngestionStage = Field(
        default=IngestionStage.PARSING,
        description="Initial processing stage for the job.",
    )


def _raise_api_error(error: Exception) -> None:
    """Translate ingestion-layer exceptions into HTTP responses."""

    if isinstance(
        error,
        (IngestionJobNotFoundError, IngestionDocumentNotFoundError),
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        (
            DuplicateIngestionJobError,
            IngestionJobConflictError,
            InvalidIngestionJobTransitionError,
            IngestionJobCancellationError,
            IngestionJobRetryError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        (IngestionJobServiceError, IngestionJobRepositoryError),
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    if isinstance(error, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    raise error


@router.get(
    "/statistics",
    response_model=IngestionJobStatistics,
    summary="Get document-ingestion statistics",
)
def get_ingestion_statistics(
    service: IngestionJobServiceDependency,
) -> IngestionJobStatistics:
    """Return aggregate ingestion job and document statistics."""

    try:
        return service.statistics()
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a document-ingestion job",
)
def submit_ingestion_job(
    request: IngestionJobSubmissionRequest,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Register a pending ingestion job and its document metadata."""

    try:
        documents = [
            IngestionDocumentResult(
                source_name=document.source_name,
                source_path=document.source_path,
                media_type=document.media_type,
                file_size_bytes=document.file_size_bytes,
                checksum_sha256=document.checksum_sha256,
                maximum_attempts=document.maximum_attempts,
                attributes=document.attributes,
            )
            for document in request.documents
        ]

        job = IngestionJob(
            job_type=request.job_type,
            source_type=request.source_type,
            submitted_by=request.submitted_by,
            correlation_id=request.correlation_id,
            documents=documents,
            total_document_count=len(documents),
            metadata=request.metadata,
        )

        return service.submit(job)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/search",
    response_model=IngestionJobQueryResult,
    summary="Search document-ingestion jobs",
)
def search_ingestion_jobs(
    request: IngestionJobSearchRequest,
    service: IngestionJobServiceDependency,
) -> IngestionJobQueryResult:
    """Search ingestion jobs using structured filters and pagination."""

    query = IngestionJobQuery(
        statuses=request.statuses,
        job_types=request.job_types,
        source_types=request.source_types,
        submitted_by=request.submitted_by,
        correlation_id=request.correlation_id,
        created_from=request.created_from,
        created_to=request.created_to,
        include_terminal=request.include_terminal,
        cancellation_requested=request.cancellation_requested,
        sort_order=request.sort_order,
        offset=request.offset,
        limit=request.limit,
    )

    try:
        return service.search(query)
    except Exception as error:
        _raise_api_error(error)


@router.get(
    "/jobs/{job_id}",
    response_model=IngestionJob,
    summary="Get a document-ingestion job",
)
def get_ingestion_job(
    job_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Return a job with document progress, diagnostics, and results."""

    try:
        return service.get(job_id)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/queue",
    response_model=IngestionJob,
    summary="Queue a document-ingestion job",
)
def queue_ingestion_job(
    job_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Move a pending job into the processing queue."""

    try:
        return service.queue(job_id)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/start",
    response_model=IngestionJob,
    summary="Start a document-ingestion job",
)
def start_ingestion_job(
    job_id: UUID,
    request: IngestionJobStartRequest,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Start a queued job at the requested processing stage."""

    try:
        return service.start(job_id, stage=request.stage)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/cancellation-request",
    response_model=IngestionJob,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request document-ingestion cancellation",
)
def request_ingestion_job_cancellation(
    job_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Record a cancellation request for cooperative pipeline shutdown."""

    try:
        return service.request_cancellation(job_id)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=IngestionJob,
    summary="Apply document-ingestion cancellation",
)
def cancel_ingestion_job(
    job_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Apply cancellation and finalise eligible documents as cancelled."""

    try:
        return service.apply_cancellation(job_id)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/retry",
    response_model=IngestionJob,
    summary="Retry a document-ingestion job",
)
def retry_ingestion_job(
    job_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Reset an eligible terminal job for another processing attempt."""

    try:
        return service.retry(job_id)
    except Exception as error:
        _raise_api_error(error)


@router.post(
    "/jobs/{job_id}/documents/{document_id}/retry",
    response_model=IngestionJob,
    summary="Retry an ingestion document",
)
def retry_ingestion_document(
    job_id: UUID,
    document_id: UUID,
    service: IngestionJobServiceDependency,
) -> IngestionJob:
    """Reset one eligible document for another processing attempt."""

    try:
        return service.retry_document(job_id, document_id)
    except Exception as error:
        _raise_api_error(error)