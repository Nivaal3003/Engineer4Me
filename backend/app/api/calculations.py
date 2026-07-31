"""Typed HTTP boundary for controlled engineering calculations.

The router exposes deterministic method discovery and stateless execution.
Clients can select only an exact allow-listed method version and can never
submit implementation objects or trusted execution evidence.  Evidence is
resolved by the server-side calculation service before the engine boundary.

Method identifiers are query parameters on exact-lookup routes because the
controlled identifier grammar permits ``/``.  This keeps every valid method
identifier addressable without ambiguous path decoding.
"""

from __future__ import annotations

import json
from typing import Annotated
from typing import NoReturn

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import StrictBool
from pydantic import StrictInt
from pydantic import StringConstraints
from pydantic import model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse
from starlette.responses import Response
from starlette.routing import get_route_path
from starlette.types import ASGIApp
from starlette.types import Message
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from app.engineering.calculations.engine import CalculationEvidenceError
from app.engineering.calculations.method_models import (
    CANONICAL_METHOD_VERSION_PATTERN,
)
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import Identifier
from app.engineering.calculations.models import LongText
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MAX_REFERENCES
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ShortText
from app.engineering.calculations.models import VersionText
from app.engineering.calculations.registry import InvalidMethodLookupError
from app.engineering.calculations.registry import MAX_REGISTERED_METHODS
from app.engineering.calculations.registry import (
    MethodCalculationTypeError,
)
from app.engineering.calculations.registry import UnknownMethodError
from app.engineering.calculations.registry import UnknownMethodVersionError
from app.services.calculation_service import CalculationEvidenceResolutionError
from app.services.calculation_service import CalculationService
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE


MAX_CALCULATION_REQUEST_BYTES = 16 * 1024 * 1024
MAX_CALCULATION_VALIDATION_ISSUES = 64
CALCULATION_EXECUTION_PATH = "/api/v1/calculations/execute"

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,99}$"
_VERSION_PATTERN = rf"^{CANONICAL_METHOD_VERSION_PATTERN}$"
_HTTP_CONTENT_TOO_LARGE = 413
_HTTP_UNPROCESSABLE_CONTENT = 422


class _DuplicateJsonMemberError(ValueError):
    """Internal signal for an ambiguous JSON object representation."""


CanonicalMethodVersion = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=5,
        max_length=64,
        pattern=_VERSION_PATTERN,
    ),
]


class CalculationApiRoute(APIRoute):
    """Route boundary that sanitizes and bounds request validation errors."""

    def get_route_handler(self):
        """Wrap FastAPI validation without changing domain exceptions."""

        route_handler = super().get_route_handler()
        allowed_query_names = frozenset(
            field.alias or field.name
            for field in self.dependant.query_params
        )

        async def sanitized_route_handler(request: Request) -> Response:
            query_error_response = _query_contract_response(
                request,
                allowed_query_names=allowed_query_names,
            )
            if query_error_response is not None:
                return query_error_response

            duplicate_member_response = (
                await _duplicate_json_member_response(request)
            )
            if duplicate_member_response is not None:
                return duplicate_member_response

            try:
                return await route_handler(request)
            except RequestValidationError as error:
                return _request_validation_response(error)
            except StarletteHTTPException as error:
                if (
                    error.status_code == 400
                    and error.detail
                    == "There was an error parsing the body"
                ):
                    return _request_parse_error_response()
                raise

        return sanitized_route_handler


router = APIRouter(
    prefix="/calculations",
    tags=["Engineering Calculations"],
    route_class=CalculationApiRoute,
)


_calculation_service = DEFAULT_CALCULATION_SERVICE


def get_calculation_service() -> CalculationService:
    """Return the shared immutable calculation service."""

    return _calculation_service


CalculationServiceDependency = Annotated[
    CalculationService,
    Depends(get_calculation_service),
]

OptionalCalculationTypeQuery = Annotated[
    str | None,
    Query(
        min_length=2,
        max_length=100,
        pattern=_IDENTIFIER_PATTERN,
        description="Optional exact calculation-type filter.",
    ),
]
MethodIdQuery = Annotated[
    str,
    Query(
        min_length=2,
        max_length=100,
        pattern=_IDENTIFIER_PATTERN,
        description="Permanent exact calculation-method identifier.",
    ),
]
MethodVersionQuery = Annotated[
    str,
    Query(
        min_length=5,
        max_length=64,
        pattern=_VERSION_PATTERN,
        description="Exact canonical semantic method version.",
    ),
]


class CalculationExecutionRequest(CalculationRequest):
    """HTTP execution request with an exact canonical method version."""

    method_version: CanonicalMethodVersion


class CalculationExecutionResult(CalculationResult):
    """HTTP calculation result with an exact canonical method version."""

    method_version: CanonicalMethodVersion


class CalculationMethodMetadata(CalculationMethodDefinition):
    """HTTP method metadata with canonical method-version schemas."""

    method_version: CanonicalMethodVersion
    superseded_by_version: CanonicalMethodVersion | None = None


class CalculationApiErrorDetail(CalculationModel):
    """Stable machine-readable API error detail."""

    code: Identifier
    message: LongText


class CalculationApiErrorResponse(CalculationModel):
    """Stable envelope for translated calculation API errors."""

    detail: CalculationApiErrorDetail


class CalculationApiValidationIssue(BaseModel):
    """One FastAPI-compatible request-validation issue."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    type: str = Field(min_length=1, max_length=100)
    loc: tuple[str | int, ...] = Field(
        min_length=1,
        max_length=16,
    )
    msg: str = Field(min_length=1, max_length=4_000)


class CalculationApiValidationErrorResponse(BaseModel):
    """Envelope shared by framework and translated 422 responses."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    detail: tuple[CalculationApiValidationIssue, ...] = Field(
        min_length=1,
        max_length=MAX_CALCULATION_VALIDATION_ISSUES,
    )


class CalculationMethodSummary(CalculationModel):
    """Compact, bounded discovery representation of one method version."""

    method_id: Identifier
    method_version: CanonicalMethodVersion
    calculation_type: Identifier
    title: ShortText
    lifecycle_status: MethodLifecycleStatus
    engine_compatible: StrictBool
    execution_eligible: StrictBool
    input_count: StrictInt = Field(ge=0, le=MAX_INPUTS)
    option_count: StrictInt = Field(ge=0, le=MAX_OPTIONS)
    reference_count: StrictInt = Field(ge=0, le=MAX_REFERENCES)

    @classmethod
    def from_definition(
        cls,
        definition: CalculationMethodDefinition,
        *,
        engine_version: str,
    ) -> "CalculationMethodSummary":
        """Build one summary without exposing implementation objects."""

        engine_compatible = (
            definition.engine_compatibility.supports(engine_version)
        )
        return cls(
            method_id=definition.method_id,
            method_version=definition.method_version,
            calculation_type=definition.calculation_type,
            title=definition.title,
            lifecycle_status=definition.lifecycle_status,
            engine_compatible=engine_compatible,
            execution_eligible=(
                definition.is_executable and engine_compatible
            ),
            input_count=len(definition.input_specifications),
            option_count=len(definition.option_specifications),
            reference_count=len(definition.references),
        )


class CalculationMethodCatalogue(CalculationModel):
    """Bounded deterministic method-discovery response."""

    engine_version: VersionText
    method_count: StrictInt = Field(
        ge=0,
        le=MAX_REGISTERED_METHODS,
    )
    methods: tuple[CalculationMethodSummary, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REGISTERED_METHODS,
    )

    @model_validator(mode="after")
    def validate_method_count(self) -> "CalculationMethodCatalogue":
        """Keep the declared count synchronized with the payload."""

        if self.method_count != len(self.methods):
            raise ValueError(
                "method_count must equal the number of method summaries."
            )

        return self


class CalculationMethodVersionCatalogue(CalculationModel):
    """Exact bounded versions registered for one method identifier."""

    method_id: Identifier
    version_count: StrictInt = Field(
        ge=1,
        le=MAX_REGISTERED_METHODS,
    )
    versions: tuple[CanonicalMethodVersion, ...] = Field(
        min_length=1,
        max_length=MAX_REGISTERED_METHODS,
    )

    @model_validator(mode="after")
    def validate_versions(
        self,
    ) -> "CalculationMethodVersionCatalogue":
        """Require a count-aligned, unique deterministic version list."""

        if self.version_count != len(self.versions):
            raise ValueError(
                "version_count must equal the number of versions."
            )

        if len(set(self.versions)) != len(self.versions):
            raise ValueError("versions must be unique.")

        if tuple(sorted(self.versions)) != self.versions:
            raise ValueError("versions must use deterministic sorted order.")

        return self


_NOT_FOUND_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": (
        "The exact calculation method or method version is not registered."
    ),
}
_BAD_REQUEST_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": (
        "The calculation request body cannot be decoded, parsed, or "
        "represented unambiguously."
    ),
}
_UNPROCESSABLE_RESPONSE = {
    "model": CalculationApiValidationErrorResponse,
    "description": (
        "The request, lookup, type selection, or evidence links are invalid."
    ),
}
_UNAVAILABLE_RESPONSE = {
    "model": CalculationApiErrorResponse,
    "description": (
        "Server-side trusted evidence resolution is unavailable."
    ),
}


@router.get(
    "/methods",
    response_model=CalculationMethodCatalogue,
    summary="List controlled calculation methods",
    operation_id="listCalculationMethods",
    responses={
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
    },
)
def list_calculation_methods(
    service: CalculationServiceDependency,
    calculation_type: OptionalCalculationTypeQuery = None,
) -> CalculationMethodCatalogue:
    """List compact method metadata in deterministic registry order."""

    try:
        definitions = service.discover_methods(
            calculation_type=calculation_type,
        )
    except Exception as error:
        _raise_calculation_api_error(
            error,
            location=("query", "calculation_type"),
        )

    methods = tuple(
        CalculationMethodSummary.from_definition(
            definition,
            engine_version=service.engine_version,
        )
        for definition in definitions
    )
    return CalculationMethodCatalogue(
        engine_version=service.engine_version,
        method_count=len(methods),
        methods=methods,
    )


@router.get(
    "/methods/versions",
    response_model=CalculationMethodVersionCatalogue,
    summary="List exact calculation method versions",
    operation_id="listCalculationMethodVersions",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
    },
)
def list_calculation_method_versions(
    service: CalculationServiceDependency,
    method_id: MethodIdQuery,
) -> CalculationMethodVersionCatalogue:
    """Return every exact registered version without selecting a latest."""

    try:
        versions = service.available_versions(method_id)
    except Exception as error:
        _raise_calculation_api_error(
            error,
            location=("query", "method_id"),
        )

    return CalculationMethodVersionCatalogue(
        method_id=method_id,
        version_count=len(versions),
        versions=versions,
    )


@router.get(
    "/methods/definition",
    response_model=CalculationMethodMetadata,
    summary="Get exact calculation method metadata",
    operation_id="getCalculationMethodDefinition",
    responses={
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
    },
)
def get_calculation_method_definition(
    service: CalculationServiceDependency,
    method_id: MethodIdQuery,
    method_version: MethodVersionQuery,
    calculation_type: OptionalCalculationTypeQuery = None,
) -> CalculationMethodMetadata:
    """Resolve metadata for one exact method ID and version."""

    try:
        definition = service.get_method(
            method_id,
            method_version,
            calculation_type=calculation_type,
        )
        return CalculationMethodMetadata.model_validate(
            definition.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except Exception as error:
        _raise_calculation_api_error(
            error,
            location=("query", "method_id"),
        )


@router.post(
    "/execute",
    response_model=CalculationExecutionResult,
    summary="Execute an exact controlled calculation method",
    operation_id="executeCalculation",
    responses={
        status.HTTP_400_BAD_REQUEST: _BAD_REQUEST_RESPONSE,
        status.HTTP_404_NOT_FOUND: _NOT_FOUND_RESPONSE,
        _HTTP_CONTENT_TOO_LARGE: {
            "model": CalculationApiErrorResponse,
            "description": (
                "The raw calculation request exceeds the transport limit."
            ),
        },
        _HTTP_UNPROCESSABLE_CONTENT: _UNPROCESSABLE_RESPONSE,
        status.HTTP_503_SERVICE_UNAVAILABLE: _UNAVAILABLE_RESPONSE,
    },
)
def execute_calculation(
    request: CalculationExecutionRequest,
    service: CalculationServiceDependency,
) -> CalculationExecutionResult:
    """Execute one typed request through the server-owned evidence boundary."""

    try:
        result = service.execute(request)
        return CalculationExecutionResult.model_validate(
            result.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except Exception as error:
        _raise_calculation_api_error(
            error,
            location=("body", "method_version"),
            calculation_type_location=("body", "calculation_type"),
        )


def _raise_calculation_api_error(
    error: Exception,
    *,
    location: tuple[str | int, ...],
    calculation_type_location: tuple[str | int, ...] = (
        "query",
        "calculation_type",
    ),
) -> NoReturn:
    """Translate expected domain failures and re-raise unexpected failures."""

    if isinstance(error, UnknownMethodError):
        _raise_typed_http_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="unknown_method",
            message="The requested calculation method was not found.",
            error=error,
        )

    if isinstance(error, UnknownMethodVersionError):
        _raise_typed_http_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="unknown_method_version",
            message=(
                "The requested calculation method version was not found."
            ),
            error=error,
        )

    if isinstance(error, InvalidMethodLookupError):
        _raise_validation_http_error(
            code="invalid_method_lookup",
            message="The calculation method lookup is invalid.",
            location=location,
            error=error,
        )

    if isinstance(error, MethodCalculationTypeError):
        _raise_validation_http_error(
            code="method_calculation_type_mismatch",
            message=(
                "The requested calculation type does not match the method."
            ),
            location=calculation_type_location,
            error=error,
        )

    if isinstance(error, CalculationEvidenceError):
        _raise_validation_http_error(
            code="calculation_evidence_error",
            message=(
                "The request evidence links could not be resolved exactly."
            ),
            location=("body", "reference_ids"),
            error=error,
        )

    if isinstance(error, CalculationEvidenceResolutionError):
        _raise_typed_http_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="calculation_service_unavailable",
            message=(
                "Engineering calculation execution is temporarily "
                "unavailable."
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
    """Raise one stable typed HTTP error without private exception detail."""

    detail = CalculationApiErrorDetail(
        code=code,
        message=message,
    )
    raise HTTPException(
        status_code=status_code,
        detail=detail.model_dump(mode="json"),
    ) from error


def _raise_validation_http_error(
    *,
    code: str,
    message: str,
    location: tuple[str | int, ...],
    error: Exception,
) -> NoReturn:
    """Raise a fixed FastAPI-compatible 422 validation response."""

    issue = CalculationApiValidationIssue(
        type=code,
        loc=location,
        msg=message,
    )
    raise HTTPException(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        detail=[issue.model_dump(mode="json")],
    ) from error


def _request_validation_response(
    error: RequestValidationError,
) -> JSONResponse:
    """Return a bounded fixed response without reflecting rejected input."""

    raw_issues = error.errors()
    if not raw_issues:
        raw_issues = [
            {
                "type": "request_validation_error",
                "loc": ("request",),
            }
        ]
    retained_limit = MAX_CALCULATION_VALIDATION_ISSUES
    truncated = len(raw_issues) > retained_limit
    if truncated:
        retained_limit -= 1

    issues = tuple(
        _sanitized_validation_issue(raw_issue)
        for raw_issue in raw_issues[:retained_limit]
    )
    if truncated:
        issues = (
            *issues,
            CalculationApiValidationIssue(
                type="request_validation_truncated",
                loc=("request",),
                msg=(
                    "Additional invalid request values were omitted from "
                    "this bounded response."
                ),
            ),
        )

    response = CalculationApiValidationErrorResponse(detail=issues)
    return JSONResponse(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        content=response.model_dump(mode="json"),
    )


def _query_contract_response(
    request: Request,
    *,
    allowed_query_names: frozenset[str],
) -> JSONResponse | None:
    """Reject unknown or repeated scalar query keys without reflection."""

    query_names = tuple(
        name
        for name, _value in request.query_params.multi_items()
    )
    issues: list[CalculationApiValidationIssue] = []

    if any(name not in allowed_query_names for name in query_names):
        issues.append(
            CalculationApiValidationIssue(
                type="unexpected_query_parameter",
                loc=("query",),
                msg=(
                    "The request contains an unsupported query parameter."
                ),
            )
        )

    if len(query_names) != len(set(query_names)):
        issues.append(
            CalculationApiValidationIssue(
                type="duplicate_query_parameter",
                loc=("query",),
                msg=(
                    "A scalar query parameter was supplied more than once."
                ),
            )
        )

    if not issues:
        return None

    response = CalculationApiValidationErrorResponse(
        detail=tuple(issues),
    )
    return JSONResponse(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        content=response.model_dump(mode="json"),
    )


def _request_parse_error_response() -> JSONResponse:
    """Return a fixed typed response for low-level body parse failures."""

    response = CalculationApiErrorResponse(
        detail=CalculationApiErrorDetail(
            code="calculation_request_parse_error",
            message=(
                "The calculation request body could not be decoded or "
                "parsed."
            ),
        )
    )
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=response.model_dump(mode="json"),
    )


def _unique_json_object(
    members: list[tuple[str, object]],
) -> dict[str, object]:
    """Build one JSON object only when every member name is unique."""

    result: dict[str, object] = {}
    for name, value in members:
        if name in result:
            raise _DuplicateJsonMemberError
        result[name] = value

    return result


async def _duplicate_json_member_response(
    request: Request,
) -> JSONResponse | None:
    """Reject duplicate JSON names at any nesting level without reflection."""

    if request.method != "POST":
        return None

    media_type = (
        request.headers.get("content-type", "")
        .partition(";")[0]
        .strip()
        .casefold()
    )
    if (
        media_type != "application/json"
        and not media_type.endswith("+json")
    ):
        return None

    try:
        json.loads(
            await request.body(),
            object_pairs_hook=_unique_json_object,
        )
    except _DuplicateJsonMemberError:
        response = CalculationApiErrorResponse(
            detail=CalculationApiErrorDetail(
                code="calculation_request_duplicate_member",
                message=(
                    "The calculation request body contains duplicate "
                    "object members."
                ),
            )
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=response.model_dump(mode="json"),
        )
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        RecursionError,
    ):
        return None

    return None


def _sanitized_validation_issue(
    raw_issue: dict[str, object],
) -> CalculationApiValidationIssue:
    """Reduce one framework issue to stable non-reflective fields."""

    raw_type = raw_issue.get("type")
    issue_type = (
        raw_type
        if isinstance(raw_type, str) and 0 < len(raw_type) <= 100
        else "request_validation_error"
    )
    raw_location = raw_issue.get("loc")
    location_items = (
        tuple(raw_location)
        if isinstance(raw_location, (tuple, list))
        else ("request",)
    )
    if issue_type == "extra_forbidden" and location_items:
        location_items = (
            *location_items[:-1],
            "extra_field",
        )
    location = tuple(
        item
        for item in location_items[:16]
        if (
            isinstance(item, str)
            and 0 < len(item) <= 300
        )
        or (
            isinstance(item, int)
            and not isinstance(item, bool)
            and item >= 0
        )
    )
    if not location:
        location = ("request",)

    return CalculationApiValidationIssue(
        type=issue_type,
        loc=location,
        msg="The request value is invalid.",
    )


class _CalculationRequestBodyTooLarge(HTTPException):
    """Internal 413 signal that survives FastAPI's body parser."""

    def __init__(self) -> None:
        detail = CalculationApiErrorDetail(
            code="calculation_request_too_large",
            message=(
                "The calculation request exceeds the permitted transport "
                "size."
            ),
        )
        super().__init__(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            detail=detail.model_dump(mode="json"),
        )


class CalculationRequestBodyLimitMiddleware:
    """Reject oversized calculation JSON before framework body parsing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_CALCULATION_REQUEST_BYTES,
        execution_path: str = CALCULATION_EXECUTION_PATH,
    ) -> None:
        if (
            isinstance(max_body_bytes, bool)
            or not isinstance(max_body_bytes, int)
            or max_body_bytes < 1
        ):
            raise ValueError("max_body_bytes must be a positive integer.")

        if (
            not isinstance(execution_path, str)
            or not execution_path.startswith("/")
        ):
            raise ValueError("execution_path must be an absolute path.")

        self._app = app
        self._max_body_bytes = max_body_bytes
        self._execution_path = execution_path

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
                    raise _CalculationRequestBodyTooLarge()

            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracked_send)
        except _CalculationRequestBodyTooLarge:
            if response_started:
                raise
            await self._send_too_large(scope, receive, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        """Return one valid non-negative Content-Length when supplied."""

        values = [
            value
            for key, value in scope.get("headers", ())
            if key.lower() == b"content-length"
        ]
        if len(values) != 1:
            return None

        try:
            content_length = int(values[0].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None

        return content_length if content_length >= 0 else None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Send the fixed typed transport-limit response."""

        detail = CalculationApiErrorDetail(
            code="calculation_request_too_large",
            message=(
                "The calculation request exceeds the permitted transport "
                "size."
            ),
        )
        response = JSONResponse(
            status_code=_HTTP_CONTENT_TOO_LARGE,
            content={
                "detail": detail.model_dump(mode="json"),
            },
        )
        await response(scope, receive, send)


__all__ = [
    "CALCULATION_EXECUTION_PATH",
    "CalculationApiErrorDetail",
    "CalculationApiErrorResponse",
    "CalculationApiValidationErrorResponse",
    "CalculationApiValidationIssue",
    "CalculationApiRoute",
    "CalculationExecutionRequest",
    "CalculationExecutionResult",
    "CalculationMethodMetadata",
    "CalculationMethodCatalogue",
    "CalculationMethodSummary",
    "CalculationMethodVersionCatalogue",
    "CalculationRequestBodyLimitMiddleware",
    "CalculationServiceDependency",
    "CanonicalMethodVersion",
    "MAX_CALCULATION_REQUEST_BYTES",
    "MAX_CALCULATION_VALIDATION_ISSUES",
    "execute_calculation",
    "get_calculation_method_definition",
    "get_calculation_service",
    "list_calculation_method_versions",
    "list_calculation_methods",
    "router",
]
