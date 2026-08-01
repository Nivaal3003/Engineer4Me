"""Typed HTTP boundary for the Step 99 DP-flow workflow.

The router exposes only allow-listed, exact-version DP-flow operations.  Its
POST routes share one fixed transport guard and the calculation API's
sanitized JSON/query validation boundary.  Stored design cases are immutable
review fixtures addressed by exact identity, revision, and content
fingerprint; this module does not introduce database persistence ahead of the
reviewed Phase 7 persistence step.
"""

from __future__ import annotations

from typing import Annotated
from typing import NoReturn

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from starlette.responses import JSONResponse
from starlette.routing import get_route_path
from starlette.types import ASGIApp
from starlette.types import Message
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from app.api.calculations import CalculationApiErrorDetail
from app.api.calculations import CalculationApiErrorResponse
from app.api.calculations import CalculationApiRoute
from app.api.calculations import CalculationApiValidationErrorResponse
from app.api.calculations import CalculationApiValidationIssue
from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowDesignCaseOutcome,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowDesignCaseRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowExecutionOutcome,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowExecutionRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowKnowledgeLink,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowMethodCatalogueEntry,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowStoredDesignCaseExample,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowStoredDesignCaseReplayRequest,
)
from app.engineering.design.dp_flow_application_models import (
    DPFlowApplicationAssessment,
)
from app.engineering.design.dp_flow_application_models import (
    DPFlowApplicationRequest,
)
from app.services.dp_flow_service import DEFAULT_DP_FLOW_SERVICE
from app.services.dp_flow_service import DPFlowConflictError
from app.services.dp_flow_service import DPFlowInputError
from app.services.dp_flow_service import DPFlowNotFoundError
from app.services.dp_flow_service import DPFlowService
from app.services.dp_flow_service import DPFlowServiceError


DP_FLOW_API_PREFIX = "/api/v1/calculations/dp-flow"
DP_FLOW_CATALOGUE_PATH = f"{DP_FLOW_API_PREFIX}/catalogue"
DP_FLOW_KNOWLEDGE_LINKS_PATH = f"{DP_FLOW_API_PREFIX}/knowledge-links"
DP_FLOW_DESIGN_CASE_EXAMPLES_PATH = (
    f"{DP_FLOW_API_PREFIX}/design-case-examples"
)
DP_FLOW_EXECUTION_PATH = f"{DP_FLOW_API_PREFIX}/execute"
DP_FLOW_APPLICATION_ASSESSMENT_PATH = (
    f"{DP_FLOW_API_PREFIX}/application-assessment"
)
DP_FLOW_DESIGN_CASE_EVALUATION_PATH = (
    f"{DP_FLOW_API_PREFIX}/design-cases/evaluate"
)
DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH = (
    f"{DP_FLOW_API_PREFIX}/design-cases/stored/evaluate"
)
MAX_DP_FLOW_REQUEST_BYTES = 512 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422
_DP_FLOW_POST_PATHS = frozenset(
    {
        DP_FLOW_EXECUTION_PATH,
        DP_FLOW_APPLICATION_ASSESSMENT_PATH,
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
    }
)


class _DPFlowRequestBodyTooLarge(Exception):
    """Internal non-HTTP signal for streamed DP-flow request overflow."""


class DPFlowRequestBodyLimitMiddleware(
    CalculationRequestBodyLimitMiddleware
):
    """Apply one fixed 512 KiB guard to every DP-flow POST route."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_DP_FLOW_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=DP_FLOW_EXECUTION_PATH,
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
            or get_route_path(scope) not in _DP_FLOW_POST_PATHS
        ):
            await self._app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if (
            content_length is not None
            and content_length > self._max_body_bytes
        ):
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
                    raise _DPFlowRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _DPFlowRequestBodyTooLarge:
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
            code="dp_flow_request_too_large",
            message=(
                "The DP-flow request exceeds the permitted transport size."
            ),
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    prefix="/calculations/dp-flow",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_dp_flow_service = DEFAULT_DP_FLOW_SERVICE


def get_dp_flow_service() -> DPFlowService:
    """Return the shared immutable DP-flow workflow service."""

    return _dp_flow_service


DPFlowServiceDependency = Annotated[
    DPFlowService,
    Depends(get_dp_flow_service),
]


_BAD_REQUEST_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The JSON request body is malformed or ambiguous.",
}
_NOT_FOUND_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The exact DP-flow resource was not found.",
}
_CONFLICT_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": (
        "The supplied stored design-case identity, revision, or fingerprint "
        "does not match the immutable reviewed fixture."
    ),
}
_TOO_LARGE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The request body exceeds the fixed transport limit.",
}
_UNPROCESSABLE_RESPONSE = {
    "model": CalculationApiValidationErrorResponse,
    "description": "The typed DP-flow request is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled DP-flow service is unavailable.",
}


def _fresh_model(model_type, value):
    """Return a detached, fully revalidated response model."""

    return model_type.model_validate(
        value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
    )


def _raise_dp_flow_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...],
) -> NoReturn:
    """Translate expected workflow failures without reflecting internals."""

    if isinstance(error, DPFlowNotFoundError):
        _raise_typed_http_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="dp_flow_resource_not_found",
            message="The requested DP-flow resource was not found.",
            error=error,
        )

    if isinstance(error, DPFlowConflictError):
        _raise_typed_http_error(
            status_code=status.HTTP_409_CONFLICT,
            code="dp_flow_resource_conflict",
            message=(
                "The DP-flow resource identity does not match the exact "
                "reviewed revision and fingerprint."
            ),
            error=error,
        )

    if isinstance(error, DPFlowInputError):
        issue = CalculationApiValidationIssue(
            type="dp_flow_input_error",
            loc=location,
            msg="The DP-flow request is invalid.",
        )
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=[issue.model_dump(mode="json")],
        ) from error

    if isinstance(error, DPFlowServiceError):
        _raise_typed_http_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="dp_flow_service_unavailable",
            message=(
                "DP-flow calculation and application assessment are "
                "temporarily unavailable."
            ),
            error=error,
        )

    raise error


def _raise_typed_http_error(
    *,
    status_code: int,
    code: str,
    message: str,
    error: Exception,
) -> NoReturn:
    """Raise one stable typed error without private exception detail."""

    detail = CalculationApiErrorDetail(code=code, message=message)
    raise HTTPException(
        status_code=status_code,
        detail=detail.model_dump(mode="json"),
    ) from error


@router.get(
    "/catalogue",
    response_model=tuple[DPFlowMethodCatalogueEntry, ...],
    summary="Get DP-flow catalogue",
    operation_id="getDPFlowCatalogue",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_dp_flow_catalogue(
    service: DPFlowServiceDependency,
) -> tuple[DPFlowMethodCatalogueEntry, ...]:
    """Return detached exact-version executable and discovery metadata."""

    try:
        return tuple(
            _fresh_model(DPFlowMethodCatalogueEntry, item)
            for item in service.get_catalogue()
        )
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("request",))


@router.get(
    "/knowledge-links",
    response_model=tuple[DPFlowKnowledgeLink, ...],
    summary="List DP-flow knowledge links",
    operation_id="listDPFlowKnowledgeLinks",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_dp_flow_knowledge_links(
    service: DPFlowServiceDependency,
) -> tuple[DPFlowKnowledgeLink, ...]:
    """Return controlled links without treating metadata as executable."""

    try:
        return tuple(
            _fresh_model(DPFlowKnowledgeLink, item)
            for item in service.get_knowledge_links()
        )
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("request",))


@router.get(
    "/design-case-examples",
    response_model=tuple[DPFlowStoredDesignCaseExample, ...],
    summary="List DP-flow design-case examples",
    operation_id="listDPFlowDesignCaseExamples",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_dp_flow_design_case_examples(
    service: DPFlowServiceDependency,
) -> tuple[DPFlowStoredDesignCaseExample, ...]:
    """Return immutable reviewed examples available for exact replay."""

    try:
        return tuple(
            _fresh_model(DPFlowStoredDesignCaseExample, item)
            for item in service.get_design_case_examples()
        )
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("request",))


@router.post(
    "/execute",
    response_model=DPFlowExecutionOutcome,
    response_model_exclude_none=False,
    summary="Execute an exact DP-flow calculation",
    operation_id="executeDPFlowCalculation",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def execute_dp_flow_calculation(
    request: DPFlowExecutionRequest,
    service: DPFlowServiceDependency,
) -> DPFlowExecutionOutcome:
    """Execute one discriminated, exact-version allow-listed operation."""

    try:
        return _fresh_model(DPFlowExecutionOutcome, service.execute(request))
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("body", "operation"))


@router.post(
    "/application-assessment",
    response_model=DPFlowApplicationAssessment,
    response_model_exclude_none=False,
    summary="Assess DP-flow application",
    operation_id="assessDPFlowApplication",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def assess_dp_flow_application(
    request: DPFlowApplicationRequest,
    service: DPFlowServiceDependency,
) -> DPFlowApplicationAssessment:
    """Return deterministic vendor-neutral primary-element scenarios."""

    try:
        return _fresh_model(
            DPFlowApplicationAssessment,
            service.assess_application(request),
        )
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("body",))


@router.post(
    "/design-cases/evaluate",
    response_model=DPFlowDesignCaseOutcome,
    response_model_exclude_none=False,
    summary="Evaluate a stateless DP-flow design case",
    operation_id="evaluateDPFlowDesignCase",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def evaluate_dp_flow_design_case(
    request: DPFlowDesignCaseRequest,
    service: DPFlowServiceDependency,
) -> DPFlowDesignCaseOutcome:
    """Assess and calculate one caller-supplied design case without storage."""

    try:
        return _fresh_model(
            DPFlowDesignCaseOutcome,
            service.evaluate_design_case(request),
        )
    except Exception as error:
        _raise_dp_flow_api_error(error, location=("body",))


@router.post(
    "/design-cases/stored/evaluate",
    response_model=DPFlowDesignCaseOutcome,
    response_model_exclude_none=False,
    summary="Evaluate an exact stored DP-flow design case",
    operation_id="evaluateStoredDPFlowDesignCase",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        status.HTTP_409_CONFLICT: _CONFLICT_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def evaluate_stored_dp_flow_design_case(
    request: DPFlowStoredDesignCaseReplayRequest,
    service: DPFlowServiceDependency,
) -> DPFlowDesignCaseOutcome:
    """Replay one immutable case by exact ID, revision, and fingerprint."""

    try:
        return _fresh_model(
            DPFlowDesignCaseOutcome,
            service.evaluate_stored_design_case(request),
        )
    except Exception as error:
        _raise_dp_flow_api_error(
            error,
            location=("body", "example_id"),
        )


__all__ = [
    "DP_FLOW_API_PREFIX",
    "DP_FLOW_APPLICATION_ASSESSMENT_PATH",
    "DP_FLOW_CATALOGUE_PATH",
    "DP_FLOW_DESIGN_CASE_EVALUATION_PATH",
    "DP_FLOW_DESIGN_CASE_EXAMPLES_PATH",
    "DP_FLOW_EXECUTION_PATH",
    "DP_FLOW_KNOWLEDGE_LINKS_PATH",
    "DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH",
    "DPFlowRequestBodyLimitMiddleware",
    "DPFlowServiceDependency",
    "MAX_DP_FLOW_REQUEST_BYTES",
    "assess_dp_flow_application",
    "evaluate_dp_flow_design_case",
    "evaluate_stored_dp_flow_design_case",
    "execute_dp_flow_calculation",
    "get_dp_flow_catalogue",
    "get_dp_flow_service",
    "list_dp_flow_design_case_examples",
    "list_dp_flow_knowledge_links",
    "router",
]
