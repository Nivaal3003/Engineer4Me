"""Focused Step 105 tests for the stateless pressure-relief service."""

from __future__ import annotations

import ast
import inspect
from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError

from app.engineering.calculations import pressure_relief as relief
from app.engineering.calculations import pressure_relief_workflow_models as workflow
from app.services import pressure_relief_service as service_module
from app.services.pressure_relief_service import (
    DEFAULT_PRESSURE_RELIEF_SERVICE,
    PressureReliefService,
    PressureReliefServiceError,
    PressureReliefWorkflowInputError,
)
from tests.test_calculation_pressure_relief_workflow import (
    calculate,
    dump,
    execution_request,
    readiness_request,
)


def readiness_assessment_request(
    *,
    complete: bool = True,
) -> workflow.PressureReliefReadinessAssessmentRequest:
    request = (
        readiness_request(relief.PressureReliefFluidPhase.LIQUID)
        if complete
        else relief.PressureReliefReadinessRequest(
            request_id="step105-incomplete-readiness"
        )
    )
    return workflow.PressureReliefReadinessAssessmentRequest(readiness_request=request)


def test_service_is_immutable_and_returns_detached_discovery_metadata() -> None:
    service = PressureReliefService()
    first_catalogue = service.get_catalogue()
    second_catalogue = service.get_catalogue()
    first_links = service.get_knowledge_links()
    second_links = service.get_knowledge_links()

    assert (
        first_catalogue == second_catalogue == (workflow.PRESSURE_RELIEF_API_CATALOGUE)
    )
    assert first_links == second_links == workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS
    assert all(
        first is not source
        for first, source in zip(
            first_catalogue,
            workflow.PRESSURE_RELIEF_API_CATALOGUE,
            strict=True,
        )
    )
    assert all(
        first is not second
        for first, second in zip(
            first_links,
            second_links,
            strict=True,
        )
    )
    with pytest.raises(AttributeError, match="immutable"):
        service.extra = object()  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="immutable"):
        del service._locked
    with pytest.raises(ValidationError):
        first_catalogue[0].standards_conformity_claimed = True  # type: ignore[misc]


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_service_dispatches_all_three_exact_methods_deterministically(
    operation: workflow.PressureReliefOperation,
) -> None:
    request = execution_request(operation)
    expected = calculate(request)

    first = DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request)
    second = DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request)

    assert first == second
    assert first is not second
    assert first.result == expected
    assert first.result is not expected
    assert first.normalized_request == request
    assert first.normalized_request is not request
    assert (
        first.audit.action is workflow.PressureReliefAuditAction.REQUIRED_AREA_EXECUTION
    )
    assert first.audit.operation is operation
    assert first.audit.status == "completed_with_warnings"
    assert first.audit.calculation_performed is True
    assert first.audit.persistence_performed is False
    assert first.audit.network_access_performed is False
    assert first.audit.standards_adapter_execution_count == 0
    assert first.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    assert first.safety_findings[0].code == (
        "preliminary_required_area_not_device_selection"
    )
    assert first.ready_for_device_selection is False
    assert first.device_selected is False
    assert first.orifice_selected is False
    assert first.manufacturer_selection_performed is False
    assert first.standards_conformity_claimed is False
    assert first.final_compliance_claimed is False
    assert first.final_design_approval_granted is False
    assert first.approved_for_project_use is False


@pytest.mark.parametrize("complete", (False, True), ids=("incomplete", "complete"))
def test_readiness_service_returns_valid_blocks_as_safety_leading_outcomes(
    complete: bool,
) -> None:
    request = readiness_assessment_request(complete=complete)
    first = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(request)
    second = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(request)

    assert first == second
    assert first.normalized_request == request
    assert first.result.status == "blocked"
    assert (
        first.disposition
        is workflow.PressureReliefWorkflowDisposition.READINESS_BLOCKED
    )
    assert first.safety_findings
    assert all(item.safety_first for item in first.safety_findings)
    assert first.safety_findings[-1].code == (
        "independent_pressure_systems_review_required"
    )
    source_ids = tuple(
        item.source_finding_id
        for item in first.safety_findings
        if item.source_finding_id is not None
    )
    if complete:
        assert source_ids == (relief.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,)
    else:
        assert len(source_ids) == 7
    assert first.audit.action is workflow.PressureReliefAuditAction.READINESS_ASSESSMENT
    assert first.audit.operation is None
    assert first.audit.calculation_performed is False
    assert first.ready_for_required_area_execution is False
    assert first.approved_for_project_use is False
    assert first.standards_conformity_claimed is False


def test_domain_failure_is_the_sanitized_workflow_input_error() -> None:
    request = execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    values = dump(request)
    values["sizing_input"]["applicability"]["vapor_pressure_absolute_pa"] = 100_000.0
    domain_request = workflow.validate_pressure_relief_execution_request(values)

    with pytest.raises(PressureReliefWorkflowInputError) as captured:
        DEFAULT_PRESSURE_RELIEF_SERVICE.execute(domain_request)

    assert captured.value.code == "pressure_relief_input_error"
    assert str(captured.value) == "The pressure-relief request is invalid."
    assert type(captured.value) is PressureReliefWorkflowInputError


@pytest.mark.parametrize(
    "invalid_request",
    (
        object(),
        {"operation": "manufacturer_selection"},
    ),
)
def test_untyped_or_unregistered_service_requests_fail_closed(
    invalid_request: object,
) -> None:
    with pytest.raises(PressureReliefWorkflowInputError):
        DEFAULT_PRESSURE_RELIEF_SERVICE.execute(  # type: ignore[arg-type]
            invalid_request
        )


def test_public_service_revalidates_a_forged_frozen_request() -> None:
    request = execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    object.__setattr__(request, "method_version", "9.9.9")
    with pytest.raises(PressureReliefWorkflowInputError):
        DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request)


def test_trusted_execution_builder_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_builder(*args: object, **kwargs: object) -> object:
        raise RuntimeError("SECRET-TRUSTED-BUILDER-DETAIL")

    monkeypatch.setattr(
        service_module,
        "build_pressure_relief_execution_outcome",
        fail_builder,
    )
    with pytest.raises(PressureReliefServiceError) as captured:
        PressureReliefService().execute(
            execution_request(workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA)
        )

    assert type(captured.value) is PressureReliefServiceError
    assert captured.value.code == "pressure_relief_service_unavailable"
    assert "SECRET" not in str(captured.value)


def test_result_for_another_operation_is_rejected_as_trusted_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gas_request = execution_request(
        workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA
    )
    gas_result = calculate(gas_request)
    monkeypatch.setattr(
        service_module,
        "_dispatch_required_area",
        lambda request: gas_result,
    )

    with pytest.raises(PressureReliefServiceError) as captured:
        PressureReliefService().execute(
            execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
        )

    assert type(captured.value) is PressureReliefServiceError
    assert not isinstance(captured.value, PressureReliefWorkflowInputError)


def test_readiness_result_for_another_request_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alternate_request = readiness_request(relief.PressureReliefFluidPhase.GAS_VAPOUR)
    alternate_result = relief.assess_pressure_relief_readiness(alternate_request)
    monkeypatch.setattr(
        service_module,
        "assess_pressure_relief_readiness",
        lambda request: alternate_result,
    )

    with pytest.raises(PressureReliefServiceError) as captured:
        PressureReliefService().assess_readiness(readiness_assessment_request())

    assert type(captured.value) is PressureReliefServiceError


def test_discovery_construction_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_fresh(*args: object, **kwargs: object) -> object:
        raise RuntimeError("SECRET-DISCOVERY-DETAIL")

    monkeypatch.setattr(service_module, "_fresh", fail_fresh)
    with pytest.raises(PressureReliefServiceError) as captured:
        PressureReliefService().get_catalogue()
    assert "SECRET" not in str(captured.value)


def test_parallel_calls_are_deterministic_and_return_isolated_models() -> None:
    request = execution_request(
        workflow.PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = tuple(
            executor.map(
                lambda _: DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request),
                range(24),
            )
        )

    assert all(item == outcomes[0] for item in outcomes)
    assert len({id(item) for item in outcomes}) == len(outcomes)
    assert len({item.audit.audit_fingerprint for item in outcomes}) == 1


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
    source = inspect.getsource(service_module).casefold()
    for forbidden in (
        "app.db",
        "app.repositories",
        "manufacturer_service",
        "selection_service",
        "voice",
    ):
        assert forbidden not in source


def test_service_public_exports_are_exact() -> None:
    assert set(service_module.__all__) == {
        "DEFAULT_PRESSURE_RELIEF_SERVICE",
        "PressureReliefService",
        "PressureReliefServiceError",
        "PressureReliefWorkflowInputError",
    }
