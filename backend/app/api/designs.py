"""Typed Step 108 API for durable design cases and trusted run records."""

from __future__ import annotations

from typing import Annotated, NoReturn
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.routing import get_route_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.calculations import (
    CalculationApiErrorDetail,
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationApiValidationIssue,
    CalculationRequestBodyLimitMiddleware,
)
from app.db.database import get_db
from app.engineering.calculations.engine import CalculationEvidenceError
from app.engineering.calculations.registry import (
    InvalidMethodLookupError,
    MethodCalculationTypeError,
    UnknownMethodError,
    UnknownMethodVersionError,
)
from app.engineering.design.persistence_models import (
    MAX_DESIGN_LIST_LIMIT,
    MAX_RUN_LIST_LIMIT,
    DesignAnalyzerAssessmentCommand,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignCasePage,
    DesignCaseRecord,
    DesignCaseRevisionCreate,
    DesignCaseRevisionRecord,
    DesignRevisionPage,
    EngineeringRunPage,
    EngineeringRunRecord,
    PersistedAnalyzerAssessment,
    PersistedCalculationExecution,
)
from app.repositories.design_repository import (
    DesignCaseNotFoundError,
    DesignPersistenceConflictError,
    DesignRepository,
    DesignRepositoryError,
    DesignRevisionNotFoundError,
    EngineeringRunNotFoundError,
)
from app.services.analyzer_application_service import (
    AnalyzerApplicationInputError,
    AnalyzerApplicationService,
    AnalyzerApplicationServiceError,
)
from app.services.calculation_service import (
    CalculationEvidenceResolutionError,
    CalculationService,
)
from app.services.design_service import (
    DesignPersistenceInputError,
    DesignPersistenceService,
    DesignPersistenceServiceError,
)
from app.api.analyzers import get_analyzer_application_service
from app.api.calculations import get_calculation_service


DESIGN_API_PREFIX = "/api/v1/designs"
DESIGN_RUN_API_PREFIX = "/api/v1/design-runs"
MAX_DESIGN_REQUEST_BYTES = 1024 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422


class _DesignRequestBodyTooLarge(Exception):
    """Internal streamed-body overflow signal."""


class DesignRequestBodyLimitMiddleware(CalculationRequestBodyLimitMiddleware):
    """Apply a fixed 1 MiB limit to every Step 108 mutating route."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_DESIGN_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=DESIGN_API_PREFIX,
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = get_route_path(scope) if scope["type"] == "http" else ""
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or not (
                path == DESIGN_API_PREFIX
                or path.startswith(f"{DESIGN_API_PREFIX}/")
            )
        ):
            await self._app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if content_length is not None and content_length > self._max_body_bytes:
            await self._send_too_large(scope, receive, send)
            return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self._max_body_bytes:
                    raise _DesignRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _DesignRequestBodyTooLarge:
            if response_started:
                raise
            await self._send_too_large(scope, receive, send)

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        detail = CalculationApiErrorDetail(
            code="design_request_too_large",
            message="The design request exceeds the permitted transport size.",
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    tags=["Engineering Designs"],
    route_class=CalculationApiRoute,
)


def get_design_persistence_service(
    db: Annotated[Session, Depends(get_db)],
    calculation_service: Annotated[
        CalculationService,
        Depends(get_calculation_service),
    ],
    analyzer_service: Annotated[
        AnalyzerApplicationService,
        Depends(get_analyzer_application_service),
    ],
) -> DesignPersistenceService:
    """Build one service around the request-scoped database transaction."""

    return DesignPersistenceService(
        repository=DesignRepository(db),
        calculation_service=calculation_service,
        analyzer_service=analyzer_service,
    )


DesignServiceDependency = Annotated[
    DesignPersistenceService,
    Depends(get_design_persistence_service),
]
PageOffset = Annotated[int, Query(ge=0, le=1_000_000)]
DesignPageLimit = Annotated[
    int,
    Query(ge=1, le=MAX_DESIGN_LIST_LIMIT),
]
RunPageLimit = Annotated[int, Query(ge=1, le=MAX_RUN_LIST_LIMIT)]


_BAD_REQUEST_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The JSON request body is malformed or ambiguous.",
}
_NOT_FOUND_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The requested design record was not found.",
}
_CONFLICT_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "An immutable identity or concurrency guard failed.",
}
_TOO_LARGE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The request exceeds the fixed transport limit.",
}
_UNPROCESSABLE_RESPONSE = {
    "model": CalculationApiValidationErrorResponse,
    "description": "The typed design command is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled design persistence service is unavailable.",
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
    code: str,
    message: str,
    location: tuple[str | int, ...],
    error: Exception,
) -> NoReturn:
    issue = CalculationApiValidationIssue(
        type=code,
        loc=location,
        msg=message,
    )
    raise HTTPException(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        detail=[issue.model_dump(mode="json")],
    ) from error


def _raise_design_api_error(
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
    if isinstance(error, EngineeringRunNotFoundError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="engineering_run_not_found",
            message="The requested engineering run was not found.",
            error=error,
        )
    if isinstance(error, UnknownMethodError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="unknown_method",
            message="The requested calculation method was not found.",
            error=error,
        )
    if isinstance(error, UnknownMethodVersionError):
        _typed_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="unknown_method_version",
            message="The requested calculation method version was not found.",
            error=error,
        )
    if isinstance(error, DesignPersistenceConflictError):
        _typed_error(
            status_code=status.HTTP_409_CONFLICT,
            code="design_persistence_conflict",
            message="The design record changed or conflicts with stored history.",
            error=error,
        )
    if isinstance(
        error,
        (
            DesignPersistenceInputError,
            InvalidMethodLookupError,
            MethodCalculationTypeError,
            CalculationEvidenceError,
            AnalyzerApplicationInputError,
        ),
    ):
        _validation_error(
            code="design_command_invalid",
            message="The design command could not be bound to trusted execution.",
            location=location,
            error=error,
        )
    if isinstance(
        error,
        (
            CalculationEvidenceResolutionError,
            AnalyzerApplicationServiceError,
            DesignPersistenceServiceError,
            DesignRepositoryError,
        ),
    ):
        _typed_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="design_persistence_unavailable",
            message="Design persistence is temporarily unavailable.",
            error=error,
        )
    _typed_error(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        code="design_persistence_unavailable",
        message="Design persistence is temporarily unavailable.",
        error=error,
    )


@router.post(
    "/designs",
    response_model=DesignCaseRecord,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="createDesignCase",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def create_design_case(
    command: DesignCaseCreate,
    service: DesignServiceDependency,
) -> DesignCaseRecord:
    try:
        return service.create_case(command)
    except Exception as error:  # noqa: BLE001 - fixed translation boundary
        _raise_design_api_error(error)


@router.get(
    "/designs",
    response_model=DesignCasePage,
    operation_id="listDesignCases",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE},
)
def list_design_cases(
    service: DesignServiceDependency,
    offset: PageOffset = 0,
    limit: DesignPageLimit = 50,
) -> DesignCasePage:
    try:
        return service.list_cases(offset=offset, limit=limit)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("query",))


@router.get(
    "/designs/{design_case_id}",
    response_model=DesignCaseRecord,
    response_model_exclude_none=False,
    operation_id="getDesignCase",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_design_case(
    design_case_id: UUID,
    service: DesignServiceDependency,
) -> DesignCaseRecord:
    try:
        return service.get_case(design_case_id)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("path", "design_case_id"))


@router.post(
    "/designs/{design_case_id}/revisions",
    response_model=DesignCaseRecord,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="reviseDesignCase",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def revise_design_case(
    design_case_id: UUID,
    command: DesignCaseRevisionCreate,
    service: DesignServiceDependency,
) -> DesignCaseRecord:
    try:
        return service.revise_case(design_case_id, command)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error)


@router.get(
    "/designs/{design_case_id}/revisions",
    response_model=DesignRevisionPage,
    operation_id="listDesignCaseRevisions",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_design_case_revisions(
    design_case_id: UUID,
    service: DesignServiceDependency,
    offset: PageOffset = 0,
    limit: DesignPageLimit = 50,
) -> DesignRevisionPage:
    try:
        return service.list_revisions(
            design_case_id,
            offset=offset,
            limit=limit,
        )
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("query",))


@router.get(
    "/designs/{design_case_id}/revisions/{revision_number}",
    response_model=DesignCaseRevisionRecord,
    response_model_exclude_none=False,
    operation_id="getDesignCaseRevision",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_design_case_revision(
    design_case_id: UUID,
    revision_number: int,
    service: DesignServiceDependency,
) -> DesignCaseRevisionRecord:
    try:
        if not 1 <= revision_number <= 1_000_000:
            raise DesignPersistenceInputError("Revision number is out of range.")
        return service.get_revision(design_case_id, revision_number)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("path", "revision_number"))


@router.post(
    "/designs/{design_case_id}/calculations",
    response_model=PersistedCalculationExecution,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="executeAndPersistDesignCalculation",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def execute_design_calculation(
    design_case_id: UUID,
    command: DesignCalculationExecutionCommand,
    service: DesignServiceDependency,
) -> PersistedCalculationExecution:
    try:
        return service.execute_calculation(design_case_id, command)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error)


@router.post(
    "/designs/{design_case_id}/analyzer-assessments",
    response_model=PersistedAnalyzerAssessment,
    response_model_exclude_none=False,
    status_code=status.HTTP_201_CREATED,
    operation_id="assessAndPersistDesignAnalyzerApplication",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def assess_design_analyzer_application(
    design_case_id: UUID,
    command: DesignAnalyzerAssessmentCommand,
    service: DesignServiceDependency,
) -> PersistedAnalyzerAssessment:
    try:
        return service.assess_analyzer(design_case_id, command)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error)


@router.get(
    "/designs/{design_case_id}/runs",
    response_model=EngineeringRunPage,
    operation_id="listDesignEngineeringRuns",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_design_engineering_runs(
    design_case_id: UUID,
    service: DesignServiceDependency,
    offset: PageOffset = 0,
    limit: RunPageLimit = 50,
) -> EngineeringRunPage:
    try:
        return service.list_runs(
            design_case_id,
            offset=offset,
            limit=limit,
        )
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("query",))


@router.get(
    "/design-runs/{run_id}",
    response_model=EngineeringRunRecord,
    response_model_exclude_none=False,
    operation_id="getEngineeringRun",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_engineering_run(
    run_id: UUID,
    service: DesignServiceDependency,
) -> EngineeringRunRecord:
    try:
        return service.get_run(run_id)
    except Exception as error:  # noqa: BLE001
        _raise_design_api_error(error, location=("path", "run_id"))


__all__ = [
    "DESIGN_API_PREFIX",
    "DESIGN_RUN_API_PREFIX",
    "MAX_DESIGN_REQUEST_BYTES",
    "DesignRequestBodyLimitMiddleware",
    "DesignServiceDependency",
    "get_design_persistence_service",
    "router",
]
