"""Typed stateless HTTP boundary for the Step 107 analyzer workflow.

The API exposes the vendor-neutral technology catalogue, five inert internal
knowledge links, immutable illustrative cases, and one assessment operation.
Engineering outcomes such as blocked or insufficient input remain HTTP 200.
No persistence, network access, product selection, or standards execution is
performed.
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
from app.engineering.design.analyzer_assistant import ANALYZER_TECHNOLOGY_CATALOGUE
from app.engineering.design.analyzer_models import (
    AnalyzerApplicationRequest,
    AnalyzerTechnologyDefinition,
)
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    ANALYZER_KNOWLEDGE_LINKS,
    AnalyzerAssessmentEnvelope,
    AnalyzerDesignCaseExample,
    AnalyzerKnowledgeLink,
)
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
    AnalyzerApplicationInputError,
    AnalyzerApplicationService,
    AnalyzerApplicationServiceError,
)

ANALYZER_API_PREFIX = "/api/v1/calculations/analyzers"
ANALYZER_CATALOGUE_PATH = f"{ANALYZER_API_PREFIX}/catalogue"
ANALYZER_KNOWLEDGE_LINKS_PATH = f"{ANALYZER_API_PREFIX}/knowledge-links"
ANALYZER_DESIGN_CASE_EXAMPLES_PATH = f"{ANALYZER_API_PREFIX}/design-case-examples"
ANALYZER_APPLICATION_ASSESSMENT_PATH = f"{ANALYZER_API_PREFIX}/application-assessment"
MAX_ANALYZER_REQUEST_BYTES = 512 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422


class _AnalyzerRequestBodyTooLarge(Exception):
    """Internal non-HTTP signal for streamed analyzer overflow."""


class AnalyzerRequestBodyLimitMiddleware(CalculationRequestBodyLimitMiddleware):
    """Apply one fixed 512 KiB guard to the analyzer assessment route."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_ANALYZER_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=ANALYZER_APPLICATION_ASSESSMENT_PATH,
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or get_route_path(scope) != self._execution_path
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
                    raise _AnalyzerRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _AnalyzerRequestBodyTooLarge:
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
            code="analyzer_request_too_large",
            message="The analyzer request exceeds the permitted transport size.",
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    prefix="/calculations/analyzers",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_analyzer_application_service = DEFAULT_ANALYZER_APPLICATION_SERVICE


def get_analyzer_application_service() -> AnalyzerApplicationService:
    return _analyzer_application_service


AnalyzerApplicationServiceDependency = Annotated[
    AnalyzerApplicationService,
    Depends(get_analyzer_application_service),
]
AnalyzerCatalogueResponse = Annotated[
    tuple[AnalyzerTechnologyDefinition, ...],
    Field(min_length=21, max_length=21),
]
AnalyzerKnowledgeLinksResponse = Annotated[
    tuple[AnalyzerKnowledgeLink, ...],
    Field(min_length=5, max_length=5),
]
AnalyzerDesignCaseExamplesResponse = Annotated[
    tuple[AnalyzerDesignCaseExample, ...],
    Field(min_length=9, max_length=9),
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
    "description": "The typed analyzer application request is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled analyzer application service is unavailable.",
}


def _fresh_model(model_type: type[CalculationModel], value: object):
    if not isinstance(value, CalculationModel):
        raise TypeError("analyzer API responses must be typed models")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def _raise_analyzer_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...],
    translate_input_error: bool = False,
) -> NoReturn:
    if translate_input_error and isinstance(error, AnalyzerApplicationInputError):
        issue = CalculationApiValidationIssue(
            type="analyzer_input_error",
            loc=location,
            msg="The analyzer application request is invalid.",
        )
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=[issue.model_dump(mode="json")],
        ) from error
    detail = CalculationApiErrorDetail(
        code="analyzer_service_unavailable",
        message="Analyzer application assessment is temporarily unavailable.",
    )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=detail.model_dump(mode="json"),
    ) from error


@router.get(
    "/catalogue",
    response_model=AnalyzerCatalogueResponse,
    summary="Get analyzer technology catalogue",
    operation_id="getAnalyzerTechnologyCatalogue",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def get_analyzer_technology_catalogue(
    service: AnalyzerApplicationServiceDependency,
) -> AnalyzerCatalogueResponse:
    try:
        catalogue = tuple(
            _fresh_model(AnalyzerTechnologyDefinition, item)
            for item in service.get_catalogue()
        )
        if catalogue != ANALYZER_TECHNOLOGY_CATALOGUE:
            raise ValueError("analyzer technology catalogue drift")
        return catalogue
    except Exception as error:  # noqa: BLE001 - sanitize trusted failures
        _raise_analyzer_api_error(error, location=("request",))


@router.get(
    "/knowledge-links",
    response_model=AnalyzerKnowledgeLinksResponse,
    summary="List analyzer knowledge links",
    operation_id="listAnalyzerKnowledgeLinks",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_analyzer_knowledge_links(
    service: AnalyzerApplicationServiceDependency,
) -> AnalyzerKnowledgeLinksResponse:
    try:
        links = tuple(
            _fresh_model(AnalyzerKnowledgeLink, item)
            for item in service.get_knowledge_links()
        )
        if links != ANALYZER_KNOWLEDGE_LINKS:
            raise ValueError("analyzer knowledge-link drift")
        return links
    except Exception as error:  # noqa: BLE001 - sanitize trusted failures
        _raise_analyzer_api_error(error, location=("request",))


@router.get(
    "/design-case-examples",
    response_model=AnalyzerDesignCaseExamplesResponse,
    response_model_exclude_none=False,
    summary="List analyzer design-case examples",
    operation_id="listAnalyzerDesignCaseExamples",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def list_analyzer_design_case_examples(
    service: AnalyzerApplicationServiceDependency,
) -> AnalyzerDesignCaseExamplesResponse:
    try:
        examples = tuple(
            _fresh_model(AnalyzerDesignCaseExample, item)
            for item in service.get_design_case_examples()
        )
        if examples != ANALYZER_DESIGN_CASE_EXAMPLES:
            raise ValueError("analyzer design-case example drift")
        return examples
    except Exception as error:  # noqa: BLE001 - sanitize trusted failures
        _raise_analyzer_api_error(error, location=("request",))


@router.post(
    "/application-assessment",
    response_model=AnalyzerAssessmentEnvelope,
    response_model_exclude_none=False,
    summary="Assess analyzer application",
    operation_id="assessAnalyzerApplication",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def assess_analyzer_application(
    request: AnalyzerApplicationRequest,
    service: AnalyzerApplicationServiceDependency,
) -> AnalyzerAssessmentEnvelope:
    try:
        outcome = service.assess(request)
        validated = _fresh_model(AnalyzerAssessmentEnvelope, outcome)
        if validated.assessment.request != request:
            raise ValueError("analyzer API assessment request binding failed")
        return validated
    except (AnalyzerApplicationInputError, AnalyzerApplicationServiceError) as error:
        _raise_analyzer_api_error(
            error,
            location=("body",),
            translate_input_error=True,
        )
    except Exception as error:  # noqa: BLE001 - sanitize trusted failures
        _raise_analyzer_api_error(error, location=("body",))


__all__ = [
    "ANALYZER_API_PREFIX",
    "ANALYZER_APPLICATION_ASSESSMENT_PATH",
    "ANALYZER_CATALOGUE_PATH",
    "ANALYZER_DESIGN_CASE_EXAMPLES_PATH",
    "ANALYZER_KNOWLEDGE_LINKS_PATH",
    "MAX_ANALYZER_REQUEST_BYTES",
    "AnalyzerApplicationServiceDependency",
    "AnalyzerCatalogueResponse",
    "AnalyzerDesignCaseExamplesResponse",
    "AnalyzerKnowledgeLinksResponse",
    "AnalyzerRequestBodyLimitMiddleware",
    "assess_analyzer_application",
    "get_analyzer_application_service",
    "get_analyzer_technology_catalogue",
    "list_analyzer_design_case_examples",
    "list_analyzer_knowledge_links",
    "router",
]
