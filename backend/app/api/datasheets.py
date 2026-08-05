"""Typed Step 110 API for controlled datasheets and exact exports."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, NoReturn
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy.orm import Session

from app.api.calculations import (
    CalculationApiErrorDetail,
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationApiValidationIssue,
)
from app.db.database import get_db
from app.engineering.design.datasheet_models import (
    DatasheetCreateCommand,
    DatasheetRevisionCreate,
)
from app.engineering.design.datasheet_persistence_models import (
    MAX_DATASHEET_LIST_LIMIT,
    DatasheetPage,
    DatasheetRevisionPage,
    PersistedDatasheetRecord,
    PersistedDatasheetRevision,
)
from app.engineering.design.datasheet_registry import (
    DatasheetTemplateRegistryError,
    UnknownDatasheetTemplateError,
    UnknownDatasheetTemplateVersionError,
)
from app.engineering.design.datasheet_service import (
    DatasheetConcurrencyError,
    DatasheetServiceError,
)
from app.engineering.design.xlsx_renderer import (
    DATASHEET_JSON_MEDIA_TYPE,
    DATASHEET_XLSX_MEDIA_TYPE,
    DatasheetExportError,
)
from app.repositories.datasheet_repository import (
    DatasheetNotFoundError,
    DatasheetPersistenceConflictError,
    DatasheetPersistenceCorruptionError,
    DatasheetRepository,
    DatasheetRepositoryError,
    DatasheetRevisionNotFoundError,
)
from app.repositories.design_repository import (
    DesignCaseNotFoundError,
    DesignRepository,
    DesignRepositoryError,
    DesignRevisionNotFoundError,
    EngineeringRunNotFoundError,
)
from app.services.datasheet_persistence_service import (
    DatasheetPersistenceInputError,
    DatasheetPersistenceIntegrityError,
    DatasheetPersistenceService,
    DatasheetPersistenceServiceError,
)


DATASHEET_API_PREFIX = "/api/v1/designs"
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422


class DatasheetExportFormat(StrEnum):
    """Allow-listed export formats; no caller-supplied path or filename."""

    JSON = "json"
    XLSX = "xlsx"


router = APIRouter(tags=["Engineering Datasheets"], route_class=CalculationApiRoute)


def get_datasheet_persistence_service(
    db: Annotated[Session, Depends(get_db)],
) -> DatasheetPersistenceService:
    """Build one request-scoped datasheet and design persistence boundary."""

    return DatasheetPersistenceService(
        repository=DatasheetRepository(db),
        design_repository=DesignRepository(db),
    )


DatasheetServiceDependency = Annotated[
    DatasheetPersistenceService,
    Depends(get_datasheet_persistence_service),
]
PageOffset = Annotated[int, Query(ge=0, le=1_000_000)]
PageLimit = Annotated[int, Query(ge=1, le=MAX_DATASHEET_LIST_LIMIT)]
RevisionNumber = Annotated[int, Path(ge=1, le=100)]


_BAD_REQUEST_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The JSON request body is malformed or ambiguous.",
}
_NOT_FOUND_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The requested design or datasheet record was not found.",
}
_CONFLICT_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "An immutable identity or concurrency guard failed.",
}
_TOO_LARGE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The request exceeds the fixed design transport limit.",
}
_UNPROCESSABLE_RESPONSE = {
    "model": CalculationApiValidationErrorResponse,
    "description": "The datasheet command or export format is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled datasheet service is unavailable.",
}


def _typed_error(
    *,
    status_code: int,
    code: str,
    message: str,
    error: Exception,
) -> NoReturn:
    detail = CalculationApiErrorDetail(code=code, message=message)
    raise HTTPException(
        status_code=status_code,
        detail=detail.model_dump(mode="json"),
    ) from error


def _validation_error(
    *,
    message: str,
    location: tuple[str | int, ...],
    error: Exception,
) -> NoReturn:
    issue = CalculationApiValidationIssue(
        type="datasheet_command_invalid",
        loc=location,
        msg=message,
    )
    raise HTTPException(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        detail=[issue.model_dump(mode="json")],
    ) from error


def _raise_datasheet_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...] = ("body",),
) -> NoReturn:
    if isinstance(error, DesignCaseNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="design_case_not_found",
            message="The requested design case was not found.",
            error=error,
        )
    if isinstance(error, DesignRevisionNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="design_revision_not_found",
            message="The requested design revision was not found.",
            error=error,
        )
    if isinstance(error, DatasheetNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="datasheet_not_found",
            message="The requested datasheet was not found.",
            error=error,
        )
    if isinstance(error, DatasheetRevisionNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="datasheet_revision_not_found",
            message="The requested datasheet revision was not found.",
            error=error,
        )
    if isinstance(error, EngineeringRunNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="engineering_run_not_found",
            message="The requested engineering run was not found.",
            error=error,
        )
    if isinstance(
        error,
        (UnknownDatasheetTemplateError, UnknownDatasheetTemplateVersionError),
    ):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="datasheet_template_not_found",
            message="The exact controlled datasheet template was not found.",
            error=error,
        )
    if isinstance(
        error,
        (DatasheetPersistenceConflictError, DatasheetConcurrencyError),
    ):
        _typed_error(
            status_code=status.HTTP_409_CONFLICT,
            code="datasheet_persistence_conflict",
            message="The datasheet changed or conflicts with immutable history.",
            error=error,
        )
    if isinstance(
        error,
        (
            DatasheetPersistenceInputError,
            DatasheetTemplateRegistryError,
            DatasheetServiceError,
        ),
    ):
        _validation_error(
            message="The datasheet command could not be bound to trusted records.",
            location=location,
            error=error,
        )
    if isinstance(
        error,
        (
            DatasheetPersistenceIntegrityError,
            DatasheetPersistenceCorruptionError,
            DatasheetExportError,
            DatasheetPersistenceServiceError,
            DatasheetRepositoryError,
            DesignRepositoryError,
        ),
    ):
        _typed_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="datasheet_service_unavailable",
            message="Controlled datasheet persistence or export is unavailable.",
            error=error,
        )
    _typed_error(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        code="datasheet_service_unavailable",
        message="Controlled datasheet persistence or export is unavailable.",
        error=error,
    )


@router.post(
    "/designs/{design_case_id}/datasheets",
    response_model=PersistedDatasheetRecord,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="createDesignDatasheet",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def create_design_datasheet(
    design_case_id: UUID,
    command: DatasheetCreateCommand,
    service: DatasheetServiceDependency,
) -> PersistedDatasheetRecord:
    try:
        return service.create(design_case_id, command)
    except Exception as error:  # noqa: BLE001 - fixed translation boundary
        _raise_datasheet_api_error(error)


@router.get(
    "/designs/{design_case_id}/datasheets",
    response_model=DatasheetPage,
    operation_id="listDesignDatasheets",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_design_datasheets(
    design_case_id: UUID,
    service: DatasheetServiceDependency,
    offset: PageOffset = 0,
    limit: PageLimit = 50,
) -> DatasheetPage:
    try:
        return service.list(design_case_id, offset=offset, limit=limit)
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error, location=("query",))


@router.get(
    "/designs/{design_case_id}/datasheets/{datasheet_id}",
    response_model=PersistedDatasheetRecord,
    response_model_exclude_none=False,
    operation_id="getDesignDatasheet",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_design_datasheet(
    design_case_id: UUID,
    datasheet_id: UUID,
    service: DatasheetServiceDependency,
) -> PersistedDatasheetRecord:
    try:
        return service.get(design_case_id, datasheet_id)
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error, location=("path",))


@router.post(
    "/designs/{design_case_id}/datasheets/{datasheet_id}/revisions",
    response_model=PersistedDatasheetRecord,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="reviseDesignDatasheet",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def revise_design_datasheet(
    design_case_id: UUID,
    datasheet_id: UUID,
    command: DatasheetRevisionCreate,
    service: DatasheetServiceDependency,
) -> PersistedDatasheetRecord:
    try:
        return service.revise(design_case_id, datasheet_id, command)
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error)


@router.get(
    "/designs/{design_case_id}/datasheets/{datasheet_id}/revisions",
    response_model=DatasheetRevisionPage,
    operation_id="listDesignDatasheetRevisions",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_design_datasheet_revisions(
    design_case_id: UUID,
    datasheet_id: UUID,
    service: DatasheetServiceDependency,
    offset: PageOffset = 0,
    limit: PageLimit = 50,
) -> DatasheetRevisionPage:
    try:
        return service.list_revisions(
            design_case_id,
            datasheet_id,
            offset=offset,
            limit=limit,
        )
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error, location=("query",))


@router.get(
    "/designs/{design_case_id}/datasheets/{datasheet_id}/revisions/{revision_number}",
    response_model=PersistedDatasheetRevision,
    response_model_exclude_none=False,
    operation_id="getDesignDatasheetRevision",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_design_datasheet_revision(
    design_case_id: UUID,
    datasheet_id: UUID,
    revision_number: RevisionNumber,
    service: DatasheetServiceDependency,
) -> PersistedDatasheetRevision:
    try:
        return service.get_revision(
            design_case_id,
            datasheet_id,
            revision_number,
        )
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error, location=("path", "revision_number"))


@router.get(
    "/designs/{design_case_id}/datasheets/{datasheet_id}/revisions/"
    "{revision_number}/exports/{export_format}",
    response_class=Response,
    operation_id="downloadDesignDatasheetRevision",
    responses={
        status.HTTP_200_OK: {
            "description": "Exact checksummed JSON or XLSX attachment.",
            "content": {
                DATASHEET_JSON_MEDIA_TYPE: {
                    "schema": {"type": "object"},
                },
                DATASHEET_XLSX_MEDIA_TYPE: {
                    "schema": {"type": "string", "format": "binary"},
                },
            },
        },
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def download_design_datasheet_revision(
    design_case_id: UUID,
    datasheet_id: UUID,
    revision_number: RevisionNumber,
    export_format: DatasheetExportFormat,
    service: DatasheetServiceDependency,
) -> Response:
    try:
        if export_format is DatasheetExportFormat.JSON:
            artifact = service.export_json(
                design_case_id,
                datasheet_id,
                revision_number,
            )
        else:
            artifact = service.export_workbook(
                design_case_id,
                datasheet_id,
                revision_number,
            )
        return Response(
            content=artifact.content,
            media_type=artifact.media_type,
            headers={
                "Content-Disposition": (f'attachment; filename="{artifact.filename}"'),
                "ETag": f'"{artifact.checksum_sha256}"',
                "X-Checksum-SHA256": artifact.checksum_sha256,
                "Cache-Control": "private, no-store, max-age=0",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Cross-Origin-Resource-Policy": "same-origin",
            },
        )
    except Exception as error:  # noqa: BLE001
        _raise_datasheet_api_error(error, location=("path", "export_format"))


__all__ = [
    "DATASHEET_API_PREFIX",
    "DatasheetExportFormat",
    "DatasheetServiceDependency",
    "get_datasheet_persistence_service",
    "router",
]
