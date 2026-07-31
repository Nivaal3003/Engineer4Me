"""Service-boundary tests for the level application wizard."""

from __future__ import annotations

import ast
import inspect
import sys
from collections.abc import Generator
from typing import Any

import pytest

from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_WIZARD_VERSION,
)
from app.engineering.design.level_application_wizard import (
    assess_level_application,
)
from app.services import level_application_service as service_module
from app.services.level_application_service import (
    DEFAULT_LEVEL_APPLICATION_SERVICE,
)
from app.services.level_application_service import LevelApplicationService
from app.services.level_application_service import (
    LevelApplicationServiceError,
)


class RecordingAssessor:
    """Record the freshly validated request crossing the service boundary."""

    def __init__(
        self,
        *,
        result: LevelApplicationAssessment | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.result = result
        self.failure = failure
        self.calls: list[LevelApplicationRequest] = []

    def __call__(
        self,
        request: LevelApplicationRequest,
    ) -> LevelApplicationAssessment:
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure
        if self.result is not None:
            return self.result
        return assess_level_application(request)


async def async_assessor(
    request: LevelApplicationRequest,
) -> LevelApplicationAssessment:
    """Expose an intentionally prohibited async boundary."""

    return assess_level_application(request)


def generator_assessor(
    request: LevelApplicationRequest,
) -> Generator[LevelApplicationAssessment, None, None]:
    """Expose an intentionally prohibited generator boundary."""

    yield assess_level_application(request)


async def async_generator_assessor(
    request: LevelApplicationRequest,
):
    """Expose an intentionally prohibited async-generator boundary."""

    yield assess_level_application(request)


def no_argument_assessor() -> LevelApplicationAssessment:
    """Expose an intentionally incomplete assessor signature."""

    return assess_level_application(LevelApplicationRequest())


def optional_argument_assessor(
    request: LevelApplicationRequest | None = None,
) -> LevelApplicationAssessment:
    """Expose an intentionally optional assessor argument."""

    return assess_level_application(request or LevelApplicationRequest())


def two_argument_assessor(
    request: LevelApplicationRequest,
    context: object,
) -> LevelApplicationAssessment:
    """Expose an intentionally broad assessor signature."""

    del context
    return assess_level_application(request)


def keyword_only_assessor(
    *,
    request: LevelApplicationRequest,
) -> LevelApplicationAssessment:
    """Expose an intentionally keyword-only assessor signature."""

    return assess_level_application(request)


def variadic_assessor(
    *requests: LevelApplicationRequest,
) -> LevelApplicationAssessment:
    """Expose an intentionally variadic assessor signature."""

    return assess_level_application(requests[0])


def returned_coroutine_assessor(
    request: LevelApplicationRequest,
) -> Any:
    """Return an awaitable from an otherwise synchronous callable."""

    return async_assessor(request)


def returned_generator_assessor(
    request: LevelApplicationRequest,
) -> Any:
    """Return a generator from an otherwise synchronous callable."""

    return generator_assessor(request)


def wrong_result_assessor(
    request: LevelApplicationRequest,
) -> Any:
    """Return a deliberately untyped assessment."""

    del request
    return {"status": "suitable"}


@pytest.fixture
def application_request() -> LevelApplicationRequest:
    """Return the valid all-unknown application boundary."""

    return LevelApplicationRequest()


@pytest.fixture
def assessment(
    application_request: LevelApplicationRequest,
) -> LevelApplicationAssessment:
    """Return one deterministic reviewed wizard result."""

    return assess_level_application(application_request)


def test_default_service_uses_reviewed_wizard(
    application_request: LevelApplicationRequest,
) -> None:
    """The production service delegates to the frozen Step 96 wizard."""

    expected = assess_level_application(application_request)

    actual = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(application_request)

    assert actual == expected
    assert actual is not expected
    assert DEFAULT_LEVEL_APPLICATION_SERVICE.wizard_version == (
        LEVEL_APPLICATION_WIZARD_VERSION
    )


def test_service_revalidates_and_detaches_request(
    application_request: LevelApplicationRequest,
) -> None:
    """An existing request model is never trusted or passed by identity."""

    assessor = RecordingAssessor()
    service = LevelApplicationService(assessor=assessor)

    service.assess(application_request)

    assert len(assessor.calls) == 1
    assert assessor.calls[0] == application_request
    assert assessor.calls[0] is not application_request


def test_service_revalidates_and_detaches_assessment(
    application_request: LevelApplicationRequest,
    assessment: LevelApplicationAssessment,
) -> None:
    """An assessor result is freshly validated before it is returned."""

    assessor = RecordingAssessor(result=assessment)
    service = LevelApplicationService(assessor=assessor)

    returned = service.assess(application_request)

    assert returned == assessment
    assert returned is not assessment


def test_repeated_assessments_are_byte_stable(
    application_request: LevelApplicationRequest,
) -> None:
    """The stateless service preserves deterministic wizard serialization."""

    first = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(application_request)
    second = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(application_request)

    assert first.model_dump_json() == second.model_dump_json()
    assert first.assessment_fingerprint == second.assessment_fingerprint


def test_minimal_request_is_an_engineering_outcome() -> None:
    """Missing application facts stay in the typed assessment boundary."""

    result = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(
        LevelApplicationRequest()
    )

    assert result.status.value == "insufficient_input"
    assert result.missing_information
    assert result.scenarios


def test_constructor_rejects_non_callable() -> None:
    """The injected assessor must be executable through one callable."""

    with pytest.raises(TypeError, match="assessor must be callable"):
        LevelApplicationService(assessor=object())  # type: ignore[arg-type]


def test_constructor_rejects_uninspectable_callable() -> None:
    """A callable without a verifiable signature cannot be injected."""

    with pytest.raises(TypeError, match="inspectable signature"):
        LevelApplicationService(
            assessor=sys.getsizeof,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "assessor",
    (
        async_assessor,
        generator_assessor,
        async_generator_assessor,
    ),
)
def test_constructor_rejects_async_and_generator_assessors(
    assessor: Any,
) -> None:
    """Only a synchronous non-generator dependency may be bound."""

    with pytest.raises(
        TypeError,
        match="synchronous non-generator",
    ):
        LevelApplicationService(assessor=assessor)


@pytest.mark.parametrize(
    "assessor",
    (
        no_argument_assessor,
        optional_argument_assessor,
        two_argument_assessor,
        keyword_only_assessor,
        variadic_assessor,
    ),
)
def test_constructor_rejects_non_exact_signatures(
    assessor: Any,
) -> None:
    """The dependency must accept exactly one required positional request."""

    with pytest.raises(TypeError, match="exactly one request argument"):
        LevelApplicationService(assessor=assessor)


def test_service_is_immutable(
    assessment: LevelApplicationAssessment,
) -> None:
    """A bound assessor cannot be replaced, removed, or shadowed."""

    service = LevelApplicationService(
        assessor=RecordingAssessor(result=assessment)
    )

    with pytest.raises(AttributeError, match="immutable"):
        service._assessor = wrong_result_assessor  # type: ignore[misc]

    with pytest.raises(AttributeError, match="immutable"):
        del service._assessor  # type: ignore[misc]

    with pytest.raises(AttributeError, match="immutable"):
        service.extra = object()  # type: ignore[attr-defined]

    assert not hasattr(service, "__dict__")


def test_request_type_is_enforced_and_failure_is_sanitized() -> None:
    """Mappings cannot bypass the typed application request boundary."""

    service = LevelApplicationService()

    with pytest.raises(LevelApplicationServiceError) as captured:
        service.assess({})  # type: ignore[arg-type]

    assert str(captured.value) == (
        "The level application assessment service is unavailable."
    )
    assert isinstance(captured.value.__cause__, TypeError)


def test_constructed_request_is_freshly_revalidated() -> None:
    """Pydantic construction bypasses cannot cross the service boundary."""

    request = LevelApplicationRequest.model_construct(
        application_notes=object()
    )

    with pytest.raises(LevelApplicationServiceError) as captured:
        DEFAULT_LEVEL_APPLICATION_SERVICE.assess(request)

    assert captured.value.__cause__ is not None


def test_constructed_assessment_is_freshly_revalidated(
    application_request: LevelApplicationRequest,
    assessment: LevelApplicationAssessment,
) -> None:
    """Invalid assessor-owned model copies are rejected after invocation."""

    invalid = assessment.model_copy()
    object.__setattr__(invalid, "assessment_fingerprint", "invalid")
    service = LevelApplicationService(
        assessor=RecordingAssessor(result=invalid)
    )

    with pytest.raises(LevelApplicationServiceError) as captured:
        service.assess(application_request)

    assert captured.value.__cause__ is not None


@pytest.mark.parametrize(
    "assessor",
    (
        returned_coroutine_assessor,
        returned_generator_assessor,
        wrong_result_assessor,
    ),
)
def test_runtime_dependency_contract_failures_are_sanitized(
    application_request: LevelApplicationRequest,
    assessor: Any,
) -> None:
    """Runtime async, generator, and untyped returns fail closed."""

    service = LevelApplicationService(assessor=assessor)

    with pytest.raises(LevelApplicationServiceError) as captured:
        service.assess(application_request)

    assert str(captured.value) == (
        "The level application assessment service is unavailable."
    )
    assert captured.value.__cause__ is not None


def test_assessor_exception_is_sanitized_and_chained(
    application_request: LevelApplicationRequest,
) -> None:
    """Dependency details remain available internally but not in the error."""

    failure = RuntimeError("SECRET-DO-NOT-REFLECT")
    service = LevelApplicationService(
        assessor=RecordingAssessor(failure=failure)
    )

    with pytest.raises(LevelApplicationServiceError) as captured:
        service.assess(application_request)

    assert captured.value.__cause__ is failure
    assert "SECRET-DO-NOT-REFLECT" not in str(captured.value)
    assert captured.value.code == "level_application_service_unavailable"


def test_service_has_no_calculation_or_external_execution_imports() -> None:
    """The wizard service is isolated from methods, I/O, and dynamic code."""

    source = inspect.getsource(service_module)
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert not any(
        module.startswith("app.engineering.calculations")
        for module in imported_modules
    )
    assert imported_modules.isdisjoint(
        {
            "asyncio",
            "builtins",
            "importlib",
            "os",
            "pathlib",
            "socket",
            "subprocess",
            "urllib",
        }
    )
    assert "eval(" not in source
    assert "exec(" not in source


def test_public_service_exports_are_exact() -> None:
    """Only the reviewed service boundary is advertised publicly."""

    assert service_module.__all__ == [
        "DEFAULT_LEVEL_APPLICATION_SERVICE",
        "LevelApplicationAssessor",
        "LevelApplicationService",
        "LevelApplicationServiceError",
    ]
