"""Focused Step 102 tests for the stateless control-valve service."""

from __future__ import annotations

import app.services.control_valve_service as service_module
import pytest
from app.engineering.calculations.control_valve import (
    ControlValveCalculationError,
    LiquidControlValveSizingResult,
)
from app.engineering.calculations.control_valve_compressible import (
    CompressibleControlValveSizingResult,
)
from app.engineering.calculations.control_valve_installed import (
    InstalledCaseRole,
    InstalledControlValveScreenResult,
)
from app.engineering.calculations.control_valve_workflow_models import (
    CONTROL_VALVE_API_CATALOGUE,
    CONTROL_VALVE_KNOWLEDGE_LINKS,
    ControlValveDesignDisposition,
    ControlValveExecutionOutcome,
    ControlValveOperation,
    ControlValveSafetySeverity,
    installed_sizing_inputs,
)
from app.services.control_valve_service import (
    DEFAULT_CONTROL_VALVE_SERVICE,
    ControlValveService,
    ControlValveServiceError,
    ControlValveWorkflowInputError,
)
from pydantic import ValidationError
from tests.test_calculation_control_valve_workflow import (
    _compressible_request,
    _design_request,
    _installed_request,
    _liquid_request,
)


@pytest.mark.parametrize(
    ("request_factory", "result_type", "operation"),
    (
        (
            _liquid_request,
            LiquidControlValveSizingResult,
            ControlValveOperation.LIQUID_SIZING,
        ),
        (
            _compressible_request,
            CompressibleControlValveSizingResult,
            ControlValveOperation.COMPRESSIBLE_SIZING,
        ),
        (
            _installed_request,
            InstalledControlValveScreenResult,
            ControlValveOperation.INSTALLED_SCREEN,
        ),
    ),
    ids=("liquid", "compressible", "installed"),
)
def test_service_executes_all_exact_reviewed_operations(
    request_factory: object,
    result_type: type[object],
    operation: ControlValveOperation,
) -> None:
    request = request_factory()  # type: ignore[operator]
    first = DEFAULT_CONTROL_VALVE_SERVICE.execute(request)
    second = DEFAULT_CONTROL_VALVE_SERVICE.execute(request)

    assert isinstance(first, ControlValveExecutionOutcome)
    assert isinstance(first.result, result_type)
    assert first.normalized_request == request
    assert first.trace.operation is operation
    assert first.trace.method_id == request.method_id
    assert first.trace.method_version == request.method_version
    assert first == second
    assert first.selection_ready is False
    assert first.manufacturer_selection_performed is False
    assert first.exact_product_selected is False
    assert first.sound_pressure_level_predicted is False
    assert first.standards_conformity_claimed is False
    if operation is ControlValveOperation.INSTALLED_SCREEN:
        assert tuple(first.model_dump(mode="python"))[:2] == (
            "safety_findings",
            "disposition",
        )
        assert first.safety_findings
        assert first.disposition is not None
        assert first.candidate_identity_origin == "caller_supplied"
    elif operation is ControlValveOperation.LIQUID_SIZING:
        assert first.safety_findings == ()
        assert first.disposition is None
        assert first.candidate_identity_origin == "not_applicable"
    else:
        assert first.safety_findings == ()
        assert first.disposition is None
        assert first.candidate_identity_origin == "caller_supplied"


def test_installed_service_calculates_children_server_side_in_fixed_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _installed_request()
    called_case_ids: list[str] = []
    original = service_module._size_input

    def observing_size_input(value: object) -> object:
        called_case_ids.append(value.case_id)  # type: ignore[attr-defined]
        return original(value)  # type: ignore[arg-type]

    monkeypatch.setattr(service_module, "_size_input", observing_size_input)
    outcome = ControlValveService().execute(request)
    assert isinstance(outcome.result, InstalledControlValveScreenResult)

    expected_inputs = installed_sizing_inputs(request)
    assert called_case_ids == ["CASE-MIN", "CASE-NORMAL", "CASE-MAX"]
    assert (
        tuple(
            item.normalized_input for item in outcome.result.normalized_sizing_results
        )
        == expected_inputs
    )
    assert all(
        result.normalized_input is not sizing_input
        for result, sizing_input in zip(
            outcome.result.normalized_sizing_results,
            expected_inputs,
            strict=True,
        )
    )
    assert tuple(item.evidence.role for item in outcome.result.case_results) == (
        InstalledCaseRole.MINIMUM,
        InstalledCaseRole.NORMAL,
        InstalledCaseRole.MAXIMUM,
    )


def test_design_service_is_deterministic_safety_leading_and_never_approves() -> None:
    request = _design_request(blocking=True)
    first = DEFAULT_CONTROL_VALVE_SERVICE.evaluate_design_case(request)
    second = DEFAULT_CONTROL_VALVE_SERVICE.evaluate_design_case(request)
    rendered = first.model_dump(mode="python", round_trip=True)

    assert first == second
    assert tuple(rendered)[:2] == ("safety_findings", "disposition")
    assert first.disposition is ControlValveDesignDisposition.BLOCKED
    assert first.safety_findings[0].severity is ControlValveSafetySeverity.BLOCKING
    assert all(item.safety_first for item in first.safety_findings)
    assert all(not item.project_approval_granted for item in first.safety_findings)
    assert first.selection_ready is False
    assert first.manufacturer_selection_performed is False
    assert first.manufacturer_declared_best is False
    assert first.exact_product_selected is False
    assert first.final_brand_selection == "user_decision_required"
    assert first.approved_for_project_use is False
    assert first.sound_pressure_level_predicted is False
    assert first.standards_conformity_claimed is False


def test_service_instances_are_immutable_and_have_no_mutable_namespace() -> None:
    service = ControlValveService()
    assert not hasattr(service, "__dict__")
    with pytest.raises(AttributeError, match="immutable"):
        service.replacement = object()  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="immutable"):
        del service._locked


def test_catalogue_and_knowledge_boundaries_return_fresh_frozen_models() -> None:
    service = ControlValveService()
    first_catalogue = service.get_catalogue()
    second_catalogue = service.get_catalogue()
    first_links = service.get_knowledge_links()
    second_links = service.get_knowledge_links()

    assert first_catalogue == second_catalogue == CONTROL_VALVE_API_CATALOGUE
    assert first_links == second_links == CONTROL_VALVE_KNOWLEDGE_LINKS
    assert isinstance(first_catalogue, tuple)
    assert isinstance(first_links, tuple)
    assert all(
        first is not source
        for first, source in zip(
            first_catalogue,
            CONTROL_VALVE_API_CATALOGUE,
            strict=True,
        )
    )
    assert all(
        first is not source
        for first, source in zip(
            first_links,
            CONTROL_VALVE_KNOWLEDGE_LINKS,
            strict=True,
        )
    )
    with pytest.raises(ValidationError):
        first_catalogue[0].title = "mutated"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        first_links[0].usage_boundary = "mutated"  # type: ignore[misc]


def test_invalid_request_error_is_typed_and_sanitized() -> None:
    private_marker = "PRIVATE-REQUEST-MARKER"
    with pytest.raises(ControlValveWorkflowInputError) as captured:
        DEFAULT_CONTROL_VALVE_SERVICE.execute(  # type: ignore[arg-type]
            {
                "operation": "liquid_sizing",
                "method_id": private_marker,
                "method_version": "9.9.9",
            }
        )

    assert type(captured.value) is ControlValveWorkflowInputError
    assert captured.value.code == "control_valve_input_error"
    assert str(captured.value) == "The control-valve request is invalid."
    assert private_marker not in str(captured.value)


def test_kernel_domain_failure_is_sanitized_as_input_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_dispatch(request: object) -> object:
        raise ControlValveCalculationError("PRIVATE-KERNEL-MARKER")

    monkeypatch.setattr(service_module, "_dispatch", fail_dispatch)
    with pytest.raises(ControlValveWorkflowInputError) as captured:
        ControlValveService().execute(_liquid_request())
    assert type(captured.value) is ControlValveWorkflowInputError
    assert str(captured.value) == "The control-valve request is invalid."
    assert "PRIVATE-KERNEL-MARKER" not in str(captured.value)


@pytest.mark.parametrize(
    "failure_type",
    (ValueError, TypeError, ValidationError),
    ids=("value-error", "type-error", "pydantic-validation-error"),
)
def test_trusted_dispatch_failures_are_sanitized_as_service_errors(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[Exception],
) -> None:
    private_marker = "PRIVATE-TRUSTED-DISPATCH-MARKER"
    if failure_type is ValidationError:
        request_type = type(_liquid_request())
        invalid_payload = _liquid_request().model_dump(mode="python", round_trip=True)
        invalid_payload["method_id"] = private_marker
        try:
            request_type.model_validate(invalid_payload)
        except ValidationError as error:
            dispatch_failure: Exception = error
        else:  # pragma: no cover - the literal method ID must reject the marker
            raise AssertionError("failed to construct a Pydantic ValidationError")
    else:
        dispatch_failure = failure_type(private_marker)

    def fail_dispatch(request: object) -> object:
        raise dispatch_failure

    monkeypatch.setattr(service_module, "_dispatch", fail_dispatch)
    with pytest.raises(ControlValveServiceError) as captured:
        ControlValveService().execute(_liquid_request())

    assert type(captured.value) is ControlValveServiceError
    assert not isinstance(captured.value, ControlValveWorkflowInputError)
    assert captured.value.code == "control_valve_service_unavailable"
    assert str(captured.value) == (
        "The controlled control-valve service is unavailable."
    )
    assert captured.value.__cause__ is dispatch_failure
    assert private_marker not in str(captured.value)


def test_subnormal_candidate_capacity_is_a_sanitized_input_error() -> None:
    payload = _installed_request().model_dump(mode="python", round_trip=True)
    payload["candidate"]["capacity_curve"][0]["available_cv"] = 5e-324
    with pytest.raises(ControlValveWorkflowInputError) as captured:
        ControlValveService().execute(payload)  # type: ignore[arg-type]
    assert type(captured.value) is ControlValveWorkflowInputError
    assert str(captured.value) == "The control-valve request is invalid."


def test_output_failure_is_service_error_not_input_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_output_fingerprint(*args: object, **kwargs: object) -> str:
        raise RuntimeError("PRIVATE-OUTPUT-MARKER")

    monkeypatch.setattr(
        service_module,
        "build_control_valve_result_fingerprint",
        fail_output_fingerprint,
    )
    with pytest.raises(ControlValveServiceError) as captured:
        ControlValveService().execute(_compressible_request())

    assert type(captured.value) is ControlValveServiceError
    assert not isinstance(captured.value, ControlValveWorkflowInputError)
    assert captured.value.code == "control_valve_service_unavailable"
    assert str(captured.value) == (
        "The controlled control-valve service is unavailable."
    )
    assert "PRIVATE-OUTPUT-MARKER" not in str(captured.value)


def test_design_output_failure_is_service_error_not_input_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_design_fingerprint(*args: object, **kwargs: object) -> str:
        raise RuntimeError("PRIVATE-DESIGN-OUTPUT-MARKER")

    monkeypatch.setattr(
        service_module,
        "build_control_valve_design_case_fingerprint",
        fail_design_fingerprint,
    )
    with pytest.raises(ControlValveServiceError) as captured:
        ControlValveService().evaluate_design_case(_design_request(blocking=True))

    assert type(captured.value) is ControlValveServiceError
    assert not isinstance(captured.value, ControlValveWorkflowInputError)
    assert str(captured.value) == (
        "The controlled control-valve service is unavailable."
    )
    assert "PRIVATE-DESIGN-OUTPUT-MARKER" not in str(captured.value)
