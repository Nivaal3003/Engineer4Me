"""Typed stateless HTTP boundary for the Step 102 control-valve workflow.

The router exposes only the three exact-version calculation operations and one
stateless design-case evaluation.  Both POST routes share a fixed transport
guard and the calculation API's sanitized JSON and query boundary.  This
module performs no persistence, product selection, network access, standards
execution, or voice work.
"""

from __future__ import annotations

from typing import Annotated, NoReturn

from app.api.calculations import (
    CalculationApiErrorDetail,
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationApiValidationIssue,
    CalculationRequestBodyLimitMiddleware,
)
from app.engineering.calculations.control_valve_workflow_models import (
    CONTROL_VALVE_API_CATALOGUE,
    CONTROL_VALVE_KNOWLEDGE_LINKS,
    ControlValveDesignCaseOutcome,
    ControlValveDesignCaseRequest,
    ControlValveExecutionOutcome,
    ControlValveExecutionRequest,
    ControlValveKnowledgeLink,
    ControlValveMethodCatalogueEntry,
)
from app.engineering.calculations.models import CalculationModel
from app.services.control_valve_service import (
    DEFAULT_CONTROL_VALVE_SERVICE,
    ControlValveService,
    ControlValveWorkflowInputError,
)
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field
from starlette.responses import JSONResponse
from starlette.routing import get_route_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CONTROL_VALVE_API_PREFIX = "/api/v1/calculations/control-valves"
CONTROL_VALVE_CATALOGUE_PATH = f"{CONTROL_VALVE_API_PREFIX}/catalogue"
CONTROL_VALVE_KNOWLEDGE_LINKS_PATH = f"{CONTROL_VALVE_API_PREFIX}/knowledge-links"
CONTROL_VALVE_EXECUTION_PATH = f"{CONTROL_VALVE_API_PREFIX}/execute"
CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH = (
    f"{CONTROL_VALVE_API_PREFIX}/design-cases/evaluate"
)
MAX_CONTROL_VALVE_REQUEST_BYTES = 512 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422
_CONTROL_VALVE_POST_PATHS = frozenset(
    {
        CONTROL_VALVE_EXECUTION_PATH,
        CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
    }
)


class _ControlValveRequestBodyTooLarge(Exception):
    """Internal non-HTTP signal for streamed control-valve overflow."""


class ControlValveRequestBodyLimitMiddleware(CalculationRequestBodyLimitMiddleware):
    """Apply one fixed 512 KiB guard to both control-valve POST routes."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_CONTROL_VALVE_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=CONTROL_VALVE_EXECUTION_PATH,
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
            or get_route_path(scope) not in _CONTROL_VALVE_POST_PATHS
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
                    raise _ControlValveRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _ControlValveRequestBodyTooLarge:
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
            code="control_valve_request_too_large",
            message=("The control-valve request exceeds the permitted transport size."),
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    prefix="/calculations/control-valves",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_control_valve_service = DEFAULT_CONTROL_VALVE_SERVICE


def get_control_valve_service() -> ControlValveService:
    """Return the shared immutable control-valve workflow service."""

    return _control_valve_service


ControlValveServiceDependency = Annotated[
    ControlValveService,
    Depends(get_control_valve_service),
]
ControlValveCatalogueResponse = Annotated[
    tuple[ControlValveMethodCatalogueEntry, ...],
    Field(min_length=3, max_length=3),
]
ControlValveKnowledgeLinksResponse = Annotated[
    tuple[ControlValveKnowledgeLink, ...],
    Field(min_length=3, max_length=3),
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
    "description": "The typed control-valve request is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled control-valve service is unavailable.",
}


def _fresh_model(
    model_type: type[CalculationModel],
    value: object,
) -> CalculationModel:
    """Return a detached, fully revalidated trusted response model."""

    if not isinstance(value, CalculationModel):
        raise TypeError("control-valve responses must be typed models")
    return model_type.model_validate(
        value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
    )


def _raise_control_valve_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...],
    translate_input_error: bool = False,
) -> NoReturn:
    """Translate input failures and hide every trusted-boundary failure."""

    if translate_input_error and isinstance(
        error,
        ControlValveWorkflowInputError,
    ):
        issue = CalculationApiValidationIssue(
            type="control_valve_input_error",
            loc=location,
            msg="The control-valve request is invalid.",
        )
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=[issue.model_dump(mode="json")],
        ) from error

    detail = CalculationApiErrorDetail(
        code="control_valve_service_unavailable",
        message=(
            "Control-valve calculation and design-case evaluation are "
            "temporarily unavailable."
        ),
    )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=detail.model_dump(mode="json"),
    ) from error


@router.get(
    "/catalogue",
    response_model=ControlValveCatalogueResponse,
    summary="Get control-valve catalogue",
    operation_id="getControlValveCatalogue",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_control_valve_catalogue(
    service: ControlValveServiceDependency,
) -> ControlValveCatalogueResponse:
    """Return detached exact-version executable method metadata."""

    try:
        catalogue = tuple(
            _fresh_model(ControlValveMethodCatalogueEntry, item)
            for item in service.get_catalogue()
        )
        if catalogue != CONTROL_VALVE_API_CATALOGUE:
            raise ValueError("control-valve catalogue drift")
        return catalogue
    except Exception as error:  # noqa: BLE001 - sanitize trusted output failures
        _raise_control_valve_api_error(error, location=("request",))


@router.get(
    "/knowledge-links",
    response_model=ControlValveKnowledgeLinksResponse,
    summary="List control-valve knowledge links",
    operation_id="listControlValveKnowledgeLinks",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_control_valve_knowledge_links(
    service: ControlValveServiceDependency,
) -> ControlValveKnowledgeLinksResponse:
    """Return inert official metadata without performing network access."""

    try:
        links = tuple(
            _fresh_model(ControlValveKnowledgeLink, item)
            for item in service.get_knowledge_links()
        )
        if links != CONTROL_VALVE_KNOWLEDGE_LINKS:
            raise ValueError("control-valve knowledge-link drift")
        return links
    except Exception as error:  # noqa: BLE001 - sanitize trusted output failures
        _raise_control_valve_api_error(error, location=("request",))


@router.post(
    "/execute",
    response_model=ControlValveExecutionOutcome,
    response_model_exclude_none=False,
    summary="Execute an exact control-valve calculation",
    operation_id="executeControlValveCalculation",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def execute_control_valve_calculation(
    request: ControlValveExecutionRequest,
    service: ControlValveServiceDependency,
) -> ControlValveExecutionOutcome:
    """Execute one discriminated exact-version allow-listed operation."""

    try:
        outcome = service.execute(request)
        fresh = _fresh_model(ControlValveExecutionOutcome, outcome)
        if (
            not isinstance(fresh, ControlValveExecutionOutcome)
            or fresh.normalized_request != request
        ):
            raise ValueError("control-valve response request mismatch")
        return fresh
    except Exception as error:  # noqa: BLE001 - sanitize all service/output failures
        _raise_control_valve_api_error(
            error,
            location=("body", "operation"),
            translate_input_error=True,
        )


@router.post(
    "/design-cases/evaluate",
    response_model=ControlValveDesignCaseOutcome,
    response_model_exclude_none=False,
    summary="Evaluate a stateless control-valve design case",
    operation_id="evaluateControlValveDesignCase",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def evaluate_control_valve_design_case(
    request: ControlValveDesignCaseRequest,
    service: ControlValveServiceDependency,
) -> ControlValveDesignCaseOutcome:
    """Evaluate one raw-input design case without storage or selection."""

    try:
        outcome = service.evaluate_design_case(request)
        fresh = _fresh_model(ControlValveDesignCaseOutcome, outcome)
        if (
            not isinstance(fresh, ControlValveDesignCaseOutcome)
            or fresh.normalized_design_case != request
        ):
            raise ValueError("control-valve design response request mismatch")
        return fresh
    except Exception as error:  # noqa: BLE001 - sanitize all service/output failures
        _raise_control_valve_api_error(
            error,
            location=("body",),
            translate_input_error=True,
        )


__all__ = [
    "CONTROL_VALVE_API_PREFIX",
    "CONTROL_VALVE_CATALOGUE_PATH",
    "CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH",
    "CONTROL_VALVE_EXECUTION_PATH",
    "CONTROL_VALVE_KNOWLEDGE_LINKS_PATH",
    "MAX_CONTROL_VALVE_REQUEST_BYTES",
    "ControlValveCatalogueResponse",
    "ControlValveKnowledgeLinksResponse",
    "ControlValveRequestBodyLimitMiddleware",
    "ControlValveServiceDependency",
    "evaluate_control_valve_design_case",
    "execute_control_valve_calculation",
    "get_control_valve_catalogue",
    "get_control_valve_service",
    "list_control_valve_knowledge_links",
    "router",
]
