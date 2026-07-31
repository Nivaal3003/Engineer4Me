"""Typed HTTP contract tests for the level application wizard."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import level_applications as api_module
from app.api.calculations import CalculationApiErrorResponse
from app.api.calculations import CalculationApiRoute
from app.api.calculations import CalculationApiValidationErrorResponse
from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.api.level_applications import LEVEL_APPLICATION_ASSESSMENT_PATH
from app.api.level_applications import (
    MAX_LEVEL_APPLICATION_REQUEST_BYTES,
)
from app.api.level_applications import (
    LevelApplicationRequestBodyLimitMiddleware,
)
from app.api.level_applications import assess_level_application
from app.api.level_applications import get_level_application_service
from app.api.level_applications import router
from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_wizard import (
    assess_level_application as run_level_application_wizard,
)
from app.services.level_application_service import (
    DEFAULT_LEVEL_APPLICATION_SERVICE,
)
from app.services.level_application_service import LevelApplicationService
from app.services.level_application_service import (
    LevelApplicationServiceError,
)


class StubLevelApplicationService:
    """Record API calls and return one controlled typed assessment."""

    def __init__(
        self,
        *,
        result: LevelApplicationAssessment | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.result = result or run_level_application_wizard(
            LevelApplicationRequest()
        )
        self.failure = failure
        self.calls: list[LevelApplicationRequest] = []

    def assess(
        self,
        request: LevelApplicationRequest,
    ) -> LevelApplicationAssessment:
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure
        return self.result


def build_client(
    service: StubLevelApplicationService | LevelApplicationService,
    *,
    max_body_bytes: int = MAX_LEVEL_APPLICATION_REQUEST_BYTES,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Build an isolated API with one exact dependency override."""

    application = FastAPI()
    application.add_middleware(
        LevelApplicationRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    application.dependency_overrides[get_level_application_service] = (
        lambda: service
    )
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def assessment() -> LevelApplicationAssessment:
    """Return a deterministic minimal-application assessment."""

    return run_level_application_wizard(LevelApplicationRequest())


@pytest.fixture
def service(
    assessment: LevelApplicationAssessment,
) -> StubLevelApplicationService:
    """Return one successful recording API dependency."""

    return StubLevelApplicationService(result=assessment)


@pytest.fixture
def client(
    service: StubLevelApplicationService,
) -> Iterator[TestClient]:
    """Yield an isolated client and close its resources after each test."""

    with build_client(service) as isolated_client:
        yield isolated_client


def test_default_dependency_is_the_reviewed_service() -> None:
    """The application dependency resolves the immutable default service."""

    assert get_level_application_service() is (
        DEFAULT_LEVEL_APPLICATION_SERVICE
    )


def test_api_reuses_public_calculation_transport_boundaries() -> None:
    """The route and body guard extend only reviewed public API classes."""

    assert issubclass(
        LevelApplicationRequestBodyLimitMiddleware,
        CalculationRequestBodyLimitMiddleware,
    )
    assert len(router.routes) == 1
    assert isinstance(router.routes[0], CalculationApiRoute)


def test_assessment_route_returns_typed_http_200(
    client: TestClient,
    service: StubLevelApplicationService,
    assessment: LevelApplicationAssessment,
) -> None:
    """A valid application request returns the complete typed assessment."""

    response = client.post(LEVEL_APPLICATION_ASSESSMENT_PATH, json={})

    assert response.status_code == 200
    assert response.json() == assessment.model_dump(mode="json")
    validated = LevelApplicationAssessment.model_validate(response.json())
    assert validated == assessment
    assert len(service.calls) == 1
    assert service.calls[0] == LevelApplicationRequest()


def test_incomplete_application_remains_http_200(
    client: TestClient,
    service: StubLevelApplicationService,
) -> None:
    """Unknown facts are an engineering outcome, not a transport failure."""

    response = client.post(LEVEL_APPLICATION_ASSESSMENT_PATH, json={})

    assert response.status_code == 200
    body = response.json()
    assert body["wizard_version"] == "1.0.0"
    assert body["ruleset_version"] == "1.0.0"
    assert body["status"] == "insufficient_input"
    assert body["missing_information"]
    assert body["scenarios"]
    assert len(service.calls) == 1


def test_route_has_no_query_parameter_contract(
    client: TestClient,
    service: StubLevelApplicationService,
) -> None:
    """Unknown and repeated query keys fail before service invocation."""

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH
        + "?secret=SECRET-DO-NOT-REFLECT&secret=again",
        json={},
    )

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    validated = CalculationApiValidationErrorResponse.model_validate(
        response.json()
    )
    assert tuple(issue.type for issue in validated.detail) == (
        "unexpected_query_parameter",
        "duplicate_query_parameter",
    )
    assert service.calls == []


@pytest.mark.parametrize(
    "body",
    (
        b"\xff",
    ),
)
def test_low_level_body_decode_error_is_a_fixed_sanitized_400(
    body: bytes,
    assessment: LevelApplicationAssessment,
) -> None:
    """Decode and parser failures never reflect rejected body content."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "code": "calculation_request_parse_error",
            "message": (
                "The calculation request body could not be decoded or "
                "parsed."
            ),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


@pytest.mark.parametrize(
    "body",
    (
        b'{"measurement":',
        b"{" + (b"9" * 5_000) + b"}",
    ),
)
def test_json_syntax_errors_are_bounded_sanitized_422(
    body: bytes,
    assessment: LevelApplicationAssessment,
) -> None:
    """Framework JSON syntax issues use the shared bounded 422 envelope."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    validated = CalculationApiValidationErrorResponse.model_validate(
        response.json()
    )
    assert len(validated.detail) == 1
    assert validated.detail[0].type == "json_invalid"
    assert validated.detail[0].msg == "The request value is invalid."
    assert service.calls == []


@pytest.mark.parametrize(
    "body",
    (
        b'{"industry":"first","industry":"SECRET-DO-NOT-REFLECT"}',
        (
            b'{"measurement":{"SECRET-DO-NOT-REFLECT":1,'
            b'"SECRET-DO-NOT-REFLECT":2}}'
        ),
    ),
    ids=("top-level", "nested"),
)
def test_duplicate_json_members_are_a_fixed_sanitized_400(
    body: bytes,
    assessment: LevelApplicationAssessment,
) -> None:
    """Ambiguous JSON members fail before validation or assessment."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "code": "calculation_request_duplicate_member",
            "message": (
                "The calculation request body contains duplicate object "
                "members."
            ),
        }
    }
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


@pytest.mark.parametrize(
    "payload",
    (
        None,
        [],
        {"SECRET-DO-NOT-REFLECT": "SECRET-DO-NOT-REFLECT"},
        {"application_notes": False},
        {"supporting_calculation_method_ids": [False]},
    ),
)
def test_invalid_typed_requests_are_sanitized_422(
    payload: Any,
    assessment: LevelApplicationAssessment,
) -> None:
    """Strict invalid values never reach the wizard or echo input values."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        json=payload,
    )

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    assert "input" not in response.text
    validated = CalculationApiValidationErrorResponse.model_validate(
        response.json()
    )
    assert all(
        issue.msg == "The request value is invalid."
        for issue in validated.detail
    )
    assert service.calls == []


@pytest.mark.parametrize("value", ("NaN", "Infinity", "-Infinity"))
def test_non_finite_json_is_a_sanitized_422(
    value: str,
    assessment: LevelApplicationAssessment,
) -> None:
    """Non-standard numeric constants cannot break error serialization."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)
    body = ('{"SECRET-DO-NOT-REFLECT":' + value + "}").encode("ascii")

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert value not in response.text
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_many_validation_errors_are_bounded_and_non_reflective(
    assessment: LevelApplicationAssessment,
) -> None:
    """Adversarial extra fields cannot create an unbounded 422 response."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)
    payload = {
        f"SECRET-DO-NOT-REFLECT-{index}": index
        for index in range(100)
    }

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        json=payload,
    )

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    issues = response.json()["detail"]
    assert len(issues) == 64
    assert issues[-1] == {
        "type": "request_validation_truncated",
        "loc": ["request"],
        "msg": (
            "Additional invalid request values were omitted from this "
            "bounded response."
        ),
    }
    CalculationApiValidationErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_service_unavailability_is_a_fixed_sanitized_503(
    assessment: LevelApplicationAssessment,
) -> None:
    """Service failures expose no implementation or request details."""

    service = StubLevelApplicationService(
        result=assessment,
        failure=LevelApplicationServiceError(),
    )
    client = build_client(service)

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        json={"application_notes": "SECRET-DO-NOT-REFLECT"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "level_application_service_unavailable",
            "message": (
                "Level application assessment is temporarily unavailable."
            ),
        }
    }
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())
    assert len(service.calls) == 1


def test_oversized_content_length_is_rejected_before_parsing(
    assessment: LevelApplicationAssessment,
) -> None:
    """The dedicated transport limit returns its level-specific response."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service, max_body_bytes=128)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": {
            "code": "level_application_request_too_large",
            "message": (
                "The level application request exceeds the permitted "
                "transport size."
            ),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_chunked_oversized_body_is_rejected_during_receive(
    assessment: LevelApplicationAssessment,
) -> None:
    """The limit remains effective without a Content-Length header."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service, max_body_bytes=128)

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    response = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "level_application_request_too_large"
    )
    assert service.calls == []


def test_exact_two_mebibyte_boundary_is_accepted_and_excess_rejected(
    assessment: LevelApplicationAssessment,
) -> None:
    """The frozen 2 MiB transport limit is inclusive at its boundary."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)
    exact_body = b"{}" + (
        b" " * (MAX_LEVEL_APPLICATION_REQUEST_BYTES - 2)
    )

    accepted = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=exact_body,
        headers={"content-type": "application/json"},
    )
    rejected = client.post(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=exact_body + b" ",
        headers={"content-type": "application/json"},
    )

    assert MAX_LEVEL_APPLICATION_REQUEST_BYTES == 2 * 1024 * 1024
    assert accepted.status_code == 200
    assert rejected.status_code == 413
    assert len(service.calls) == 1


def test_body_limit_does_not_apply_to_other_routes(
    assessment: LevelApplicationAssessment,
) -> None:
    """The middleware guard is scoped to one exact POST route path."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service, max_body_bytes=16)

    calculation = client.post(
        "/api/v1/calculations/execute",
        content=b"x" * 128,
    )
    wrong_method = client.put(
        LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=b"x" * 128,
    )

    assert calculation.status_code == 404
    assert wrong_method.status_code == 405
    assert service.calls == []


def test_body_limit_uses_route_path_when_application_is_mounted(
    assessment: LevelApplicationAssessment,
) -> None:
    """An ASGI mount prefix cannot bypass the dedicated transport limit."""

    service = StubLevelApplicationService(result=assessment)
    child = FastAPI()
    child.add_middleware(
        LevelApplicationRequestBodyLimitMiddleware,
        max_body_bytes=128,
    )
    child.include_router(router, prefix="/api/v1")
    child.dependency_overrides[get_level_application_service] = (
        lambda: service
    )
    parent = FastAPI()
    parent.mount("/engineering", child)
    client = TestClient(parent)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        "/engineering" + LEVEL_APPLICATION_ASSESSMENT_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "level_application_request_too_large"
    )
    assert service.calls == []


def test_wrong_methods_are_not_registered(
    client: TestClient,
    service: StubLevelApplicationService,
) -> None:
    """The stateless assessment route accepts POST only."""

    assert client.get(LEVEL_APPLICATION_ASSESSMENT_PATH).status_code == 405
    assert client.put(LEVEL_APPLICATION_ASSESSMENT_PATH).status_code == 405
    assert client.delete(LEVEL_APPLICATION_ASSESSMENT_PATH).status_code == 405
    assert client.patch(LEVEL_APPLICATION_ASSESSMENT_PATH).status_code == 405
    assert service.calls == []


def test_openapi_freezes_typed_request_response_and_errors(
    assessment: LevelApplicationAssessment,
) -> None:
    """OpenAPI advertises one exact operation and all bounded statuses."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)
    document = client.app.openapi()  # type: ignore[union-attr]
    operation = document["paths"][LEVEL_APPLICATION_ASSESSMENT_PATH][
        "post"
    ]

    assert set(document["paths"]) == {LEVEL_APPLICATION_ASSESSMENT_PATH}
    assert operation["summary"] == "Assess level measurement application"
    assert operation["operationId"] == "assessLevelApplication"
    assert operation["tags"] == ["Engineering Calculations"]
    assert set(operation["responses"]) == {
        "200",
        "400",
        "413",
        "422",
        "503",
    }
    assert operation["requestBody"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/LevelApplicationRequest"}
    assert operation["responses"]["200"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/LevelApplicationAssessment"}
    assert operation["responses"]["422"]["content"]["application/json"][
        "schema"
    ] == {
        "$ref": (
            "#/components/schemas/"
            "CalculationApiValidationErrorResponse"
        )
    }


def test_request_and_response_schemas_are_closed_and_vendor_neutral(
    assessment: LevelApplicationAssessment,
) -> None:
    """Transport schemas exclude implementation, execution, and voice data."""

    service = StubLevelApplicationService(result=assessment)
    client = build_client(service)
    document = client.app.openapi()  # type: ignore[union-attr]
    schemas = document["components"]["schemas"]
    request_schema = schemas["LevelApplicationRequest"]
    response_schema = schemas["LevelApplicationAssessment"]
    serialized = str({
        "request": request_schema,
        "response": response_schema,
    }).casefold()

    assert request_schema["additionalProperties"] is False
    assert response_schema["additionalProperties"] is False
    assert "vendor" not in serialized
    assert "implementation" not in serialized
    assert "executor" not in serialized
    assert "voice" not in serialized


def test_handler_revalidates_returned_assessment(
    assessment: LevelApplicationAssessment,
) -> None:
    """The route returns a freshly validated assessment model instance."""

    class IdentityService:
        def assess(
            self,
            request: LevelApplicationRequest,
        ) -> LevelApplicationAssessment:
            del request
            return assessment

    returned = assess_level_application(
        LevelApplicationRequest(),
        IdentityService(),  # type: ignore[arg-type]
    )

    assert returned == assessment
    assert returned is not assessment


@pytest.mark.parametrize("max_body_bytes", (True, 0, -1, 1.5))
def test_body_limit_rejects_invalid_configuration(
    max_body_bytes: Any,
) -> None:
    """The adapter retains the inherited positive-integer invariant."""

    with pytest.raises(ValueError, match="positive integer"):
        LevelApplicationRequestBodyLimitMiddleware(
            FastAPI(),
            max_body_bytes=max_body_bytes,
        )


def test_public_api_exports_are_exact() -> None:
    """Only the reviewed typed level transport boundary is advertised."""

    assert api_module.__all__ == [
        "LEVEL_APPLICATION_ASSESSMENT_PATH",
        "LevelApplicationRequestBodyLimitMiddleware",
        "LevelApplicationServiceDependency",
        "MAX_LEVEL_APPLICATION_REQUEST_BYTES",
        "assess_level_application",
        "get_level_application_service",
        "router",
    ]
