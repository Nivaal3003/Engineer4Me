"""Typed stateless HTTP boundary for the Step 105 pressure-relief workflow.

The router exposes a separate readiness assessment and only the three exact
generic required-area operations.  Both POST routes share a fixed transport
guard and the calculation API's sanitized JSON and query boundary.  This
module performs no persistence, network access, standards execution, device
or orifice selection, manufacturer selection, project approval, or voice
work.
"""

from __future__ import annotations

from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field
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
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.pressure_relief_workflow_models import (
    PRESSURE_RELIEF_API_CATALOGUE,
    PRESSURE_RELIEF_KNOWLEDGE_LINKS,
    PressureReliefExecutionOutcome,
    PressureReliefExecutionRequest,
    PressureReliefKnowledgeLink,
    PressureReliefMethodCatalogueEntry,
    PressureReliefReadinessAssessmentOutcome,
    PressureReliefReadinessAssessmentRequest,
)
from app.services.pressure_relief_service import (
    DEFAULT_PRESSURE_RELIEF_SERVICE,
    PressureReliefService,
    PressureReliefWorkflowInputError,
)

PRESSURE_RELIEF_API_PREFIX = "/api/v1/calculations/pressure-relief"
PRESSURE_RELIEF_CATALOGUE_PATH = f"{PRESSURE_RELIEF_API_PREFIX}/catalogue"
PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH = f"{PRESSURE_RELIEF_API_PREFIX}/knowledge-links"
PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH = (
    f"{PRESSURE_RELIEF_API_PREFIX}/readiness-assessment"
)
PRESSURE_RELIEF_EXECUTION_PATH = f"{PRESSURE_RELIEF_API_PREFIX}/execute"
MAX_PRESSURE_RELIEF_REQUEST_BYTES = 512 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422
_PRESSURE_RELIEF_POST_PATHS = frozenset(
    {
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        PRESSURE_RELIEF_EXECUTION_PATH,
    }
)


class _PressureReliefRequestBodyTooLarge(Exception):
    """Internal non-HTTP signal for streamed pressure-relief overflow."""


class PressureReliefRequestBodyLimitMiddleware(CalculationRequestBodyLimitMiddleware):
    """Apply one fixed 512 KiB guard to both pressure-relief POST routes."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_PRESSURE_RELIEF_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=PRESSURE_RELIEF_EXECUTION_PATH,
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Reject declared and streamed overflow with one fixed response."""

        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or get_route_path(scope) not in _PRESSURE_RELIEF_POST_PATHS
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
                    raise _PressureReliefRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _PressureReliefRequestBodyTooLarge:
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
            code="pressure_relief_request_too_large",
            message=(
                "The pressure-relief request exceeds the permitted transport size."
            ),
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    prefix="/calculations/pressure-relief",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_pressure_relief_service = DEFAULT_PRESSURE_RELIEF_SERVICE


def get_pressure_relief_service() -> PressureReliefService:
    """Return the shared immutable pressure-relief workflow service."""

    return _pressure_relief_service


PressureReliefServiceDependency = Annotated[
    PressureReliefService,
    Depends(get_pressure_relief_service),
]
PressureReliefCatalogueResponse = Annotated[
    tuple[PressureReliefMethodCatalogueEntry, ...],
    Field(min_length=3, max_length=3),
]
PressureReliefKnowledgeLinksResponse = Annotated[
    tuple[PressureReliefKnowledgeLink, ...],
    Field(min_length=2, max_length=2),
]


_BAD_REQUEST_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The JSON request body is malformed or ambiguous.",
}
_TOO_LARGE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The request body exceeds the fixed transport limit.",
}
_UNPROCESSABLE_RESPONSE = {
    "model": CalculationApiValidationErrorResponse,
    "description": "The typed pressure-relief request is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled pressure-relief service is unavailable.",
}


def _fresh_model(
    model_type: type[CalculationModel],
    value: object,
) -> CalculationModel:
    """Return a detached, fully revalidated trusted response model."""

    if not isinstance(value, CalculationModel):
        raise TypeError("pressure-relief responses must be typed models")
    return model_type.model_validate(
        value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
    )


def _raise_pressure_relief_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...],
    translate_input_error: bool = False,
) -> NoReturn:
    """Translate input failures and hide every trusted-boundary failure."""

    if translate_input_error and isinstance(
        error,
        PressureReliefWorkflowInputError,
    ):
        issue = CalculationApiValidationIssue(
            type="pressure_relief_input_error",
            loc=location,
            msg="The pressure-relief request is invalid.",
        )
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=[issue.model_dump(mode="json")],
        ) from error

    detail = CalculationApiErrorDetail(
        code="pressure_relief_service_unavailable",
        message=(
            "Pressure-relief readiness assessment and required-area calculation "
            "are temporarily unavailable."
        ),
    )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=detail.model_dump(mode="json"),
    ) from error


@router.get(
    "/catalogue",
    response_model=PressureReliefCatalogueResponse,
    summary="Get pressure-relief catalogue",
    operation_id="getPressureReliefCatalogue",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_pressure_relief_catalogue(
    service: PressureReliefServiceDependency,
) -> PressureReliefCatalogueResponse:
    """Return detached exact-version executable method metadata."""

    try:
        catalogue = tuple(
            _fresh_model(PressureReliefMethodCatalogueEntry, item)
            for item in service.get_catalogue()
        )
        if catalogue != PRESSURE_RELIEF_API_CATALOGUE:
            raise ValueError("pressure-relief catalogue drift")
        return catalogue
    except Exception as error:  # noqa: BLE001 - sanitize trusted output failures
        _raise_pressure_relief_api_error(error, location=("request",))


@router.get(
    "/knowledge-links",
    response_model=PressureReliefKnowledgeLinksResponse,
    summary="List pressure-relief knowledge links",
    operation_id="listPressureReliefKnowledgeLinks",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_pressure_relief_knowledge_links(
    service: PressureReliefServiceDependency,
) -> PressureReliefKnowledgeLinksResponse:
    """Return inert official metadata without performing network access."""

    try:
        links = tuple(
            _fresh_model(PressureReliefKnowledgeLink, item)
            for item in service.get_knowledge_links()
        )
        if links != PRESSURE_RELIEF_KNOWLEDGE_LINKS:
            raise ValueError("pressure-relief knowledge-link drift")
        return links
    except Exception as error:  # noqa: BLE001 - sanitize trusted output failures
        _raise_pressure_relief_api_error(error, location=("request",))


@router.post(
    "/readiness-assessment",
    response_model=PressureReliefReadinessAssessmentOutcome,
    response_model_exclude_none=False,
    summary="Assess pressure-relief readiness",
    operation_id="assessPressureReliefReadiness",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def assess_pressure_relief_readiness(
    request: PressureReliefReadinessAssessmentRequest,
    service: PressureReliefServiceDependency,
) -> PressureReliefReadinessAssessmentOutcome:
    """Assess one raw readiness request without executing a sizing method."""

    try:
        outcome = service.assess_readiness(request)
        fresh = _fresh_model(PressureReliefReadinessAssessmentOutcome, outcome)
        if (
            not isinstance(fresh, PressureReliefReadinessAssessmentOutcome)
            or fresh.normalized_request != request
        ):
            raise ValueError("pressure-relief readiness response request mismatch")
        return fresh
    except Exception as error:  # noqa: BLE001 - sanitize all service/output failures
        _raise_pressure_relief_api_error(
            error,
            location=("body", "readiness_request"),
            translate_input_error=True,
        )


@router.post(
    "/execute",
    response_model=PressureReliefExecutionOutcome,
    response_model_exclude_none=False,
    summary="Execute an exact pressure-relief calculation",
    operation_id="executePressureReliefCalculation",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def execute_pressure_relief_required_area(
    request: PressureReliefExecutionRequest,
    service: PressureReliefServiceDependency,
) -> PressureReliefExecutionOutcome:
    """Execute one discriminated exact-version generic area operation."""

    try:
        outcome = service.execute(request)
        fresh = _fresh_model(PressureReliefExecutionOutcome, outcome)
        if (
            not isinstance(fresh, PressureReliefExecutionOutcome)
            or fresh.normalized_request != request
        ):
            raise ValueError("pressure-relief execution response request mismatch")
        return fresh
    except Exception as error:  # noqa: BLE001 - sanitize all service/output failures
        _raise_pressure_relief_api_error(
            error,
            location=("body", "operation"),
            translate_input_error=True,
        )


__all__ = [
    "MAX_PRESSURE_RELIEF_REQUEST_BYTES",
    "PRESSURE_RELIEF_API_PREFIX",
    "PRESSURE_RELIEF_CATALOGUE_PATH",
    "PRESSURE_RELIEF_EXECUTION_PATH",
    "PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH",
    "PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH",
    "PressureReliefCatalogueResponse",
    "PressureReliefKnowledgeLinksResponse",
    "PressureReliefRequestBodyLimitMiddleware",
    "PressureReliefServiceDependency",
    "assess_pressure_relief_readiness",
    "execute_pressure_relief_required_area",
    "get_pressure_relief_catalogue",
    "get_pressure_relief_service",
    "list_pressure_relief_knowledge_links",
    "router",
]
