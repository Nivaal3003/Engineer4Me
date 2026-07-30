"""HTTP execution boundary for filesystem-backed ingestion jobs.

The multipart upload API persists documents and creates authoritative
ingestion jobs. The filesystem execution service validates and processes
those jobs through the complete PDF, Office, OCR, metadata, engineering, and
knowledge pipeline. This module composes that transport-neutral service into
one explicit synchronous API endpoint.

The execution coordinator is cached process-wide so its in-process job lease
protects concurrent HTTP requests handled by the same application process.
Deployments using multiple application workers must still use an external
queue or distributed lease before enabling concurrent cross-process workers.

The route deliberately:

- accepts only a server-parsed UUID job identifier;
- reuses the shared ingestion lifecycle repository used by upload and status
  routes;
- reuses the guarded upload storage root and authoritative size limit;
- aligns native, image, PDF, and Office parser byte limits with storage;
- returns terminal job state for successful, partial, failed, or cancelled
  processing;
- maps expected eligibility and state failures to stable safe responses; and
- preserves unexpected programmer failures as internal server errors.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.filesystem_document_upload_api import (
    FilesystemDocumentUploadApiConfigurationError,
    get_filesystem_document_storage,
)
from app.api.ingestion import get_ingestion_job_service
from app.ingestion.document_parser import DocumentParserConfig
from app.ingestion.filesystem_document_content_loader import (
    FilesystemDocumentContentLoaderConfig,
)
from app.ingestion.filesystem_document_execution_service import (
    FilesystemDocumentExecutionConflictError,
    FilesystemDocumentExecutionEligibilityError,
    FilesystemDocumentExecutionService,
    FilesystemDocumentExecutionStateError,
)
from app.ingestion.filesystem_document_processing_runtime import (
    FilesystemDocumentProcessingRuntime,
    FilesystemDocumentProcessingRuntimeConfig,
)
from app.ingestion.ingestion_job_models import (
    IngestionJob,
    InvalidIngestionJobTransitionError,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobConflictError,
    IngestionJobNotFoundError,
    IngestionJobRepositoryError,
)
from app.ingestion.ingestion_job_service import IngestionJobServiceError
from app.ingestion.ocr_document_parser import (
    OcrAwareDocumentParserConfig,
)
from app.ingestion.pdf_office_document_parser import (
    PdfOfficeDocumentParserConfig,
)


logger = logging.getLogger(__name__)

_HTTP_UNPROCESSABLE_CONTENT = 422


class FilesystemDocumentExecutionApiConfigurationError(RuntimeError):
    """Raised when the trusted execution runtime cannot be composed."""


@lru_cache(maxsize=1)
def get_filesystem_document_execution_service(
) -> FilesystemDocumentExecutionService:
    """Return the process-wide guarded execution coordinator.

    The upload storage adapter is the authority for both the canonical root
    directory and maximum accepted document size. The processing loader and
    all parser layers inherit those exact values so a document accepted by
    configured upload storage is not rejected later by a stale default byte
    limit.
    """

    try:
        storage = get_filesystem_document_storage()
        maximum_content_bytes = (
            storage.config.maximum_content_bytes
        )

        standard_parser = DocumentParserConfig(
            max_document_size_bytes=maximum_content_bytes,
        )
        ocr_parser = OcrAwareDocumentParserConfig(
            standard_parser=standard_parser,
            maximum_image_bytes=maximum_content_bytes,
        )
        document_parser = PdfOfficeDocumentParserConfig(
            fallback_parser=ocr_parser,
            maximum_document_bytes=maximum_content_bytes,
        )
        runtime_config = FilesystemDocumentProcessingRuntimeConfig(
            content_loader_config=(
                FilesystemDocumentContentLoaderConfig(
                    root_directory=storage.root_directory,
                    maximum_content_bytes=maximum_content_bytes,
                )
            ),
            document_parser=document_parser,
        )
        runtime = FilesystemDocumentProcessingRuntime(
            job_service=get_ingestion_job_service(),
            config=runtime_config,
        )
        return FilesystemDocumentExecutionService(runtime=runtime)
    except FilesystemDocumentUploadApiConfigurationError as error:
        raise FilesystemDocumentExecutionApiConfigurationError(
            "Filesystem document execution storage is unavailable."
        ) from error
    except (OSError, ValueError) as error:
        raise FilesystemDocumentExecutionApiConfigurationError(
            "Filesystem document execution could not be configured."
        ) from error


def get_filesystem_document_execution_service_dependency(
) -> FilesystemDocumentExecutionService:
    """Return the execution coordinator or one safe service response."""

    try:
        return get_filesystem_document_execution_service()
    except FilesystemDocumentExecutionApiConfigurationError as error:
        logger.error(
            "Filesystem document execution configuration is unavailable."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document processing is unavailable.",
        ) from error


FilesystemDocumentExecutionServiceDependency = Annotated[
    FilesystemDocumentExecutionService,
    Depends(
        get_filesystem_document_execution_service_dependency
    ),
]


router = APIRouter(
    prefix="/ingestion",
    tags=["Document Ingestion"],
)


@router.post(
    "/jobs/{job_id}/execute",
    response_model=IngestionJob,
    summary="Execute a filesystem-backed ingestion job",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "The requested ingestion job does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "description": (
                "The job is already executing or cannot safely resume "
                "from its current lifecycle state."
            ),
        },
        _HTTP_UNPROCESSABLE_CONTENT: {
            "description": (
                "The job is not an authoritative filesystem-backed "
                "multipart upload."
            ),
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": (
                "The processing runtime or ingestion repository is "
                "unavailable."
            ),
        },
    },
)
def execute_filesystem_ingestion_job(
    job_id: UUID,
    service: FilesystemDocumentExecutionServiceDependency,
) -> IngestionJob:
    """Synchronously execute one eligible job through the full pipeline."""

    try:
        return service.process_job(job_id)
    except Exception as error:
        _raise_execution_api_error(error)


def _raise_execution_api_error(error: Exception) -> None:
    """Translate expected execution failures into stable safe responses."""

    if isinstance(error, IngestionJobNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested ingestion job was not found.",
        ) from error

    if isinstance(
        error,
        FilesystemDocumentExecutionEligibilityError,
    ):
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=(
                "The ingestion job is not eligible for filesystem "
                "document processing."
            ),
        ) from error

    if isinstance(error, FilesystemDocumentExecutionConflictError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The ingestion job is already being processed.",
        ) from error

    if isinstance(
        error,
        (
            FilesystemDocumentExecutionStateError,
            IngestionJobConflictError,
            InvalidIngestionJobTransitionError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The ingestion job cannot be processed safely from "
                "its current state."
            ),
        ) from error

    if isinstance(
        error,
        (
            IngestionJobRepositoryError,
            IngestionJobServiceError,
        ),
    ):
        logger.error(
            "Filesystem execution repository failure: error=%s",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document processing is unavailable.",
        ) from error

    raise error


__all__ = [
    "FilesystemDocumentExecutionApiConfigurationError",
    "FilesystemDocumentExecutionServiceDependency",
    "execute_filesystem_ingestion_job",
    "get_filesystem_document_execution_service",
    "get_filesystem_document_execution_service_dependency",
    "router",
]
