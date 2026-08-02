"""Focused Step 107 tests for the stateless analyzer application service."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from app.engineering.design.analyzer_assistant import (
    ANALYZER_ASSISTANT_VERSION,
    ANALYZER_RULESET_VERSION,
    ANALYZER_TECHNOLOGY_CATALOGUE,
    ANALYZER_TECHNOLOGY_TAXONOMY_VERSION,
    assess_analyzer_application,
)
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerApplicationAssessment,
    AnalyzerApplicationRequest,
    fingerprint_analyzer_payload,
)
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    ANALYZER_KNOWLEDGE_LINKS,
    ANALYZER_WORKFLOW_VERSION,
    resolve_analyzer_knowledge_links,
    validate_analyzer_design_case_example,
)
from app.services import analyzer_application_service as service_module
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
    AnalyzerApplicationInputError,
    AnalyzerApplicationService,
    AnalyzerApplicationServiceError,
)


class RecordingAssessor:
    """Record the freshly validated request and raw assistant result."""

    def __init__(
        self,
        *,
        result: AnalyzerApplicationAssessment | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.result = result
        self.failure = failure
        self.calls: list[AnalyzerApplicationRequest] = []
        self.returned: list[AnalyzerApplicationAssessment] = []

    def __call__(
        self,
        request: AnalyzerApplicationRequest,
    ) -> AnalyzerApplicationAssessment:
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure
        assessment = self.result or assess_analyzer_application(request)
        self.returned.append(assessment)
        return assessment


class UninspectableAssessor:
    """Callable whose deliberately invalid signature metadata fails closed."""

    @property
    def __signature__(self) -> object:
        raise ValueError("SECRET-UNINSPECTABLE-SIGNATURE")

    def __call__(
        self,
        request: AnalyzerApplicationRequest,
    ) -> AnalyzerApplicationAssessment:
        return assess_analyzer_application(request)


async def async_assessor(
    request: AnalyzerApplicationRequest,
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(request)


def generator_assessor(
    request: AnalyzerApplicationRequest,
) -> Generator[AnalyzerApplicationAssessment]:
    yield assess_analyzer_application(request)


async def async_generator_assessor(
    request: AnalyzerApplicationRequest,
):
    yield assess_analyzer_application(request)


def no_argument_assessor() -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(ANALYZER_DESIGN_CASE_EXAMPLES[0].request)


def optional_argument_assessor(
    request: AnalyzerApplicationRequest | None = None,
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(
        request or ANALYZER_DESIGN_CASE_EXAMPLES[0].request
    )


def two_argument_assessor(
    request: AnalyzerApplicationRequest,
    context: object,
) -> AnalyzerApplicationAssessment:
    del context
    return assess_analyzer_application(request)


def keyword_only_assessor(
    *,
    request: AnalyzerApplicationRequest,
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(request)


def variadic_assessor(
    *requests: AnalyzerApplicationRequest,
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(requests[0])


def returned_coroutine_assessor(request: AnalyzerApplicationRequest) -> Any:
    return async_assessor(request)


def returned_generator_assessor(request: AnalyzerApplicationRequest) -> Any:
    return generator_assessor(request)


def wrong_result_assessor(request: AnalyzerApplicationRequest) -> Any:
    del request
    return {"status": "completed"}


@pytest.fixture
def application_request() -> AnalyzerApplicationRequest:
    return ANALYZER_DESIGN_CASE_EXAMPLES[0].request


@pytest.fixture
def assessment(
    application_request: AnalyzerApplicationRequest,
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(application_request)


def test_default_service_builds_the_reviewed_controlled_envelope(
    application_request: AnalyzerApplicationRequest,
) -> None:
    expected = assess_analyzer_application(application_request)

    outcome = DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(application_request)

    assert outcome.assessment == expected
    assert outcome.assessment is not expected
    assert outcome.assessment.request == application_request
    assert outcome.request_fingerprint == fingerprint_analyzer_payload(
        application_request
    )
    assert outcome.knowledge_links == resolve_analyzer_knowledge_links(expected)
    assert len(outcome.knowledge_links) == 5
    assert outcome.external_knowledge_access_performed is False
    assert outcome.persistence_performed is False
    assert outcome.manufacturer_or_model_selection_performed is False
    assert outcome.standards_conformity_claimed is False
    assert outcome.final_design_approval_granted is False


def test_service_versions_are_exact_and_propagated_to_outcome(
    application_request: AnalyzerApplicationRequest,
) -> None:
    service = AnalyzerApplicationService()
    outcome = service.assess(application_request)

    assert service.workflow_version == ANALYZER_WORKFLOW_VERSION == "1.0.0"
    assert service.assistant_version == ANALYZER_ASSISTANT_VERSION == "1.0.0"
    assert service.ruleset_version == ANALYZER_RULESET_VERSION == "1.0.0"
    assert service.taxonomy_version == ANALYZER_TECHNOLOGY_TAXONOMY_VERSION == "1.0.0"
    assert outcome.workflow_version == service.workflow_version
    assert outcome.model_version == ANALYZER_APPLICATION_MODEL_VERSION == "1.0.0"
    assert outcome.assistant_version == service.assistant_version
    assert outcome.ruleset_version == service.ruleset_version
    assert outcome.taxonomy_version == service.taxonomy_version


def test_service_revalidates_and_detaches_request_and_assessment(
    application_request: AnalyzerApplicationRequest,
) -> None:
    assessor = RecordingAssessor()
    outcome = AnalyzerApplicationService(assessor=assessor).assess(application_request)

    assert len(assessor.calls) == len(assessor.returned) == 1
    assert assessor.calls[0] == application_request
    assert assessor.calls[0] is not application_request
    assert assessor.returned[0] == outcome.assessment
    assert assessor.returned[0] is not outcome.assessment
    assert outcome.assessment.request is not assessor.calls[0]


def test_repeated_envelopes_are_deterministic_and_fully_detached(
    application_request: AnalyzerApplicationRequest,
) -> None:
    first = DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(application_request)
    second = DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(application_request)

    assert first == second
    assert first is not second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.integration_fingerprint == second.integration_fingerprint
    assert first.assessment is not second.assessment
    assert first.assessment.request is not second.assessment.request
    assert all(
        left is not right
        for left, right in zip(
            first.knowledge_links,
            second.knowledge_links,
            strict=True,
        )
    )


def test_parallel_envelopes_are_deterministic_and_isolated(
    application_request: AnalyzerApplicationRequest,
) -> None:
    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = tuple(
            executor.map(
                lambda _: DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(
                    application_request
                ),
                range(24),
            )
        )

    assert all(item == outcomes[0] for item in outcomes)
    assert len({id(item) for item in outcomes}) == len(outcomes)
    assert len({item.integration_fingerprint for item in outcomes}) == 1


def test_discovery_outputs_have_exact_counts_and_controlled_identity() -> None:
    service = AnalyzerApplicationService()
    catalogue = service.get_catalogue()
    links = service.get_knowledge_links()
    examples = service.get_design_case_examples()

    assert len(catalogue) == len(ANALYZER_TECHNOLOGY_CATALOGUE) == 21
    assert len(links) == len(ANALYZER_KNOWLEDGE_LINKS) == 5
    assert len(examples) == len(ANALYZER_DESIGN_CASE_EXAMPLES) == 9
    assert len({item.technology for item in catalogue}) == 21
    assert len({item.reference.reference_id for item in links}) == 5
    assert len({(item.example_id, item.revision) for item in examples}) == 9
    assert all(item.manufacturer_model_selected is False for item in catalogue)
    assert all(item.retrieval_mode == "inert_metadata_only" for item in links)
    assert all(item.illustrative_only is True for item in examples)


def test_discovery_outputs_are_revalidated_and_detached() -> None:
    service = AnalyzerApplicationService()
    first_catalogue = service.get_catalogue()
    second_catalogue = service.get_catalogue()
    first_links = service.get_knowledge_links()
    second_links = service.get_knowledge_links()
    first_examples = service.get_design_case_examples()
    second_examples = service.get_design_case_examples()

    assert first_catalogue == second_catalogue == ANALYZER_TECHNOLOGY_CATALOGUE
    assert first_links == second_links == ANALYZER_KNOWLEDGE_LINKS
    assert first_examples == second_examples == ANALYZER_DESIGN_CASE_EXAMPLES
    for first, second, source in zip(
        first_catalogue,
        second_catalogue,
        ANALYZER_TECHNOLOGY_CATALOGUE,
        strict=True,
    ):
        assert first is not second
        assert first is not source
    for first, second, source in zip(
        first_links,
        second_links,
        ANALYZER_KNOWLEDGE_LINKS,
        strict=True,
    ):
        assert first is not second
        assert first is not source
        assert first.reference is not source.reference
    for first, second, source in zip(
        first_examples,
        second_examples,
        ANALYZER_DESIGN_CASE_EXAMPLES,
        strict=True,
    ):
        assert first is not second
        assert first is not source
        assert first.request is not source.request


def test_design_case_examples_are_rerun_through_injected_assessor() -> None:
    assessor = RecordingAssessor()
    examples = AnalyzerApplicationService(assessor=assessor).get_design_case_examples()

    assert len(assessor.calls) == len(examples) == 9
    assert tuple(assessor.calls) == tuple(item.request for item in examples)
    for example, result in zip(examples, assessor.returned, strict=True):
        independently_validated = validate_analyzer_design_case_example(example)
        assert result == independently_validated
        assert result.status is example.expected_status
        assert result.assessment_fingerprint == example.expected_assessment_fingerprint
        scenarios = {item.technology: item.disposition for item in result.scenarios}
        assert all(
            scenarios[item.technology] is item.disposition
            for item in example.expected_scenarios
        )


def test_assessment_for_another_request_fails_the_binding(
    application_request: AnalyzerApplicationRequest,
) -> None:
    alternate = ANALYZER_DESIGN_CASE_EXAMPLES[1].request
    service = AnalyzerApplicationService(
        assessor=RecordingAssessor(
            result=assess_analyzer_application(alternate),
        )
    )

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        service.assess(application_request)

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert isinstance(captured.value.__cause__, ValueError)
    assert "does not match" not in str(captured.value)


@pytest.mark.parametrize("value", ({}, object()))
def test_untyped_requests_fail_as_sanitized_input_errors(value: object) -> None:
    with pytest.raises(AnalyzerApplicationInputError) as captured:
        DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(  # type: ignore[arg-type]
            value
        )

    assert type(captured.value) is AnalyzerApplicationInputError
    assert captured.value.code == "analyzer_input_error"
    assert str(captured.value) == "The analyzer application request is invalid."
    assert isinstance(captured.value.__cause__, TypeError)


def test_forged_frozen_request_is_freshly_revalidated(
    application_request: AnalyzerApplicationRequest,
) -> None:
    forged = application_request.model_copy()
    object.__setattr__(forged, "request_id", "x")

    with pytest.raises(AnalyzerApplicationInputError) as captured:
        DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(forged)

    assert type(captured.value) is AnalyzerApplicationInputError
    assert captured.value.__cause__ is not None


def test_forged_assessment_is_rejected_after_assessor_invocation(
    application_request: AnalyzerApplicationRequest,
    assessment: AnalyzerApplicationAssessment,
) -> None:
    forged = assessment.model_copy()
    object.__setattr__(forged, "assessment_fingerprint", "0" * 64)
    service = AnalyzerApplicationService(assessor=RecordingAssessor(result=forged))

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        service.assess(application_request)

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert captured.value.__cause__ is not None


@pytest.mark.parametrize(
    ("source_name", "method_name", "field_name", "invalid_value"),
    (
        (
            "ANALYZER_TECHNOLOGY_CATALOGUE",
            "get_catalogue",
            "technology",
            "invented_vendor_product",
        ),
        (
            "ANALYZER_KNOWLEDGE_LINKS",
            "get_knowledge_links",
            "retrieval_mode",
            "external_network",
        ),
        (
            "ANALYZER_DESIGN_CASE_EXAMPLES",
            "get_design_case_examples",
            "request_fingerprint",
            "0" * 64,
        ),
    ),
)
def test_forged_discovery_models_are_freshly_revalidated(
    monkeypatch: pytest.MonkeyPatch,
    source_name: str,
    method_name: str,
    field_name: str,
    invalid_value: object,
) -> None:
    source = getattr(service_module, source_name)
    forged = source[0].model_copy()
    object.__setattr__(forged, field_name, invalid_value)
    monkeypatch.setattr(service_module, source_name, (forged, *source[1:]))

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        getattr(AnalyzerApplicationService(), method_name)()

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert captured.value.code == "analyzer_service_unavailable"


def test_constructor_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="assessor must be callable"):
        AnalyzerApplicationService(assessor=object())  # type: ignore[arg-type]


def test_constructor_rejects_uninspectable_callable_without_reflection() -> None:
    with pytest.raises(TypeError, match="inspectable signature") as captured:
        AnalyzerApplicationService(assessor=UninspectableAssessor())

    assert "SECRET-UNINSPECTABLE-SIGNATURE" not in str(captured.value)
    assert isinstance(captured.value.__cause__, ValueError)


@pytest.mark.parametrize(
    "assessor",
    (async_assessor, generator_assessor, async_generator_assessor),
)
def test_constructor_rejects_async_and_generator_assessors(
    assessor: Any,
) -> None:
    with pytest.raises(TypeError, match="synchronous non-generator"):
        AnalyzerApplicationService(assessor=assessor)


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
def test_constructor_rejects_non_exact_assessor_signatures(
    assessor: Any,
) -> None:
    with pytest.raises(TypeError, match="exactly one request argument"):
        AnalyzerApplicationService(assessor=assessor)


@pytest.mark.parametrize(
    "assessor",
    (
        returned_coroutine_assessor,
        returned_generator_assessor,
        wrong_result_assessor,
    ),
)
def test_runtime_dependency_contract_failures_are_sanitized(
    application_request: AnalyzerApplicationRequest,
    assessor: Any,
) -> None:
    service = AnalyzerApplicationService(assessor=assessor)

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        service.assess(application_request)

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert captured.value.code == "analyzer_service_unavailable"
    assert str(captured.value) == (
        "The controlled analyzer application service is unavailable."
    )
    assert captured.value.__cause__ is not None


def test_assessor_exception_is_sanitized_and_chained(
    application_request: AnalyzerApplicationRequest,
) -> None:
    failure = RuntimeError("SECRET-ASSESSOR-DETAIL")
    service = AnalyzerApplicationService(assessor=RecordingAssessor(failure=failure))

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        service.assess(application_request)

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert captured.value.__cause__ is failure
    assert "SECRET-ASSESSOR-DETAIL" not in str(captured.value)


@pytest.mark.parametrize(
    "method_name",
    ("get_catalogue", "get_knowledge_links", "get_design_case_examples"),
)
def test_discovery_construction_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    def fail_fresh(*args: object, **kwargs: object) -> object:
        raise RuntimeError("SECRET-DISCOVERY-DETAIL")

    monkeypatch.setattr(service_module, "_fresh", fail_fresh)

    with pytest.raises(AnalyzerApplicationServiceError) as captured:
        getattr(AnalyzerApplicationService(), method_name)()

    assert type(captured.value) is AnalyzerApplicationServiceError
    assert "SECRET-DISCOVERY-DETAIL" not in str(captured.value)


def test_service_is_immutable() -> None:
    service = AnalyzerApplicationService()

    with pytest.raises(AttributeError, match="immutable"):
        service._assessor = wrong_result_assessor  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        del service._assessor  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        service.extra = object()  # type: ignore[attr-defined]

    assert not hasattr(service, "__dict__")


def test_service_module_has_no_io_persistence_or_dynamic_execution() -> None:
    tree = ast.parse(inspect.getsource(service_module))
    forbidden_import_roots = {
        "aiohttp",
        "alembic",
        "asyncio",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "socket",
        "sqlalchemy",
        "subprocess",
        "urllib",
    }
    forbidden_calls = {
        "__import__",
        "compile",
        "connect",
        "create_engine",
        "eval",
        "exec",
        "open",
        "save",
        "sessionmaker",
        "urlopen",
        "write",
    }
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id.casefold())
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr.casefold())

    assert not imports & forbidden_import_roots
    assert not calls & forbidden_calls


def test_public_service_exports_are_exact() -> None:
    assert service_module.__all__ == [
        "DEFAULT_ANALYZER_APPLICATION_SERVICE",
        "AnalyzerApplicationAssessor",
        "AnalyzerApplicationInputError",
        "AnalyzerApplicationService",
        "AnalyzerApplicationServiceError",
    ]
