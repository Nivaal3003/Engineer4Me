"""Typed stateless API for the Step 96 level application wizard.

The route accepts bounded application context and returns explainable,
vendor-neutral technology scenarios.  Structurally valid requests remain HTTP
200 even when additional information or safety review is required; those are
engineering assessment outcomes rather than transport failures.
"""

from __future__ import annotations

from typing import Annotated

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
from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.services.level_application_service import (
    DEFAULT_LEVEL_APPLICATION_SERVICE,
)
from app.services.level_application_service import LevelApplicationService
from app.services.level_application_service import (
    LevelApplicationServiceError,
)


LEVEL_APPLICATION_ASSESSMENT_PATH = (
    "/api/v1/calculations/level/application-assessment"
)
MAX_LEVEL_APPLICATION_REQUEST_BYTES = 2 * 1024 * 1024
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422


class _LevelApplicationRequestBodyTooLarge(Exception):
    """Internal non-HTTP signal for streamed level request overflow."""


class LevelApplicationRequestBodyLimitMiddleware(
    CalculationRequestBodyLimitMiddleware
):
    """Apply a fixed 2 MiB guard only to the level-assessment POST path."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_LEVEL_APPLICATION_REQUEST_BYTES,
    ) -> None:
        super().__init__(
            app,
            max_body_bytes=max_body_bytes,
            execution_path=LEVEL_APPLICATION_ASSESSMENT_PATH,
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
            or get_route_path(scope) != self._execution_path
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
                    raise _LevelApplicationRequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _LevelApplicationRequestBodyTooLarge:
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
            code="level_application_request_too_large",
            message=(
                "The level application request exceeds the permitted "
                "transport size."
            ),
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={"detail": detail.model_dump(mode="json")},
        )
        await response(scope, receive, send)


router = APIRouter(
    prefix="/calculations/level",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_level_application_service = DEFAULT_LEVEL_APPLICATION_SERVICE


def get_level_application_service() -> LevelApplicationService:
    """Return the shared immutable level application service."""

    return _level_application_service


LevelApplicationServiceDependency = Annotated[
    LevelApplicationService,
    Depends(get_level_application_service),
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
    "description": "The typed level application request is invalid.",
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": "The controlled assessment service is unavailable.",
}


@router.post(
    "/application-assessment",
    response_model=LevelApplicationAssessment,
    response_model_exclude_none=False,
    summary="Assess level measurement application",
    operation_id="assessLevelApplication",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: _TOO_LARGE_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def assess_level_application(
    request: LevelApplicationRequest,
    service: LevelApplicationServiceDependency,
) -> LevelApplicationAssessment:
    """Return deterministic, explainable level technology scenarios."""

    try:
        assessment = service.assess(request)
        return LevelApplicationAssessment.model_validate(
            assessment.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except LevelApplicationServiceError as exc:
        detail = CalculationApiErrorDetail(
            code="level_application_service_unavailable",
            message=(
                "Level application assessment is temporarily unavailable."
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail.model_dump(mode="json"),
        ) from exc


__all__ = [
    "LEVEL_APPLICATION_ASSESSMENT_PATH",
    "LevelApplicationRequestBodyLimitMiddleware",
    "LevelApplicationServiceDependency",
    "MAX_LEVEL_APPLICATION_REQUEST_BYTES",
    "assess_level_application",
    "get_level_application_service",
    "router",
]
