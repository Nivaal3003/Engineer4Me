"""Focused Step 102 tests for typed control-valve workflow contracts."""

from __future__ import annotations

import ast
import inspect
from itertools import permutations
from math import inf, nextafter
from types import MappingProxyType

import app.api.control_valves as control_valve_api_module
import app.engineering.calculations.control_valve_workflow_models as workflow_module
import app.services.control_valve_service as control_valve_service_module
import pytest
from app.engineering.calculations.control_valve import (
    LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    LiquidControlValveSizingInput,
    LiquidControlValveSizingResult,
    build_liquid_control_valve_result_fingerprint_payload,
    fingerprint_control_valve_payload,
    size_liquid_control_valve,
)
from app.engineering.calculations.control_valve_compressible import (
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
    CompressibleControlValveSizingInput,
    CompressibleControlValveSizingResult,
    size_compressible_control_valve,
)
from app.engineering.calculations.control_valve_installed import (
    CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    InstalledCaseRole,
    InstalledControlValveScreenResult,
    evaluate_installed_control_valve_scenarios,
)
from app.engineering.calculations.control_valve_workflow_models import (
    CONTROL_VALVE_API_CATALOGUE,
    CONTROL_VALVE_API_REGISTRY,
    CONTROL_VALVE_CALCULATOR_PACK_VERSION,
    CONTROL_VALVE_KNOWLEDGE_LINKS,
    CONTROL_VALVE_WORKFLOW_VERSION,
    CompressibleControlValveExecutionRequest,
    ControlValveDesignCaseOutcome,
    ControlValveDesignCaseRequest,
    ControlValveDesignDisposition,
    ControlValveExecutionOutcome,
    ControlValveExecutionRequest,
    ControlValveExecutionTrace,
    ControlValveOperatingPointInput,
    ControlValveOperation,
    ControlValveResult,
    ControlValveSafetySeverity,
    InstalledControlValveExecutionRequest,
    LiquidControlValveExecutionRequest,
    build_control_valve_attempt_fingerprint,
    build_control_valve_design_case_fingerprint,
    build_control_valve_input_fingerprint,
    build_control_valve_result_fingerprint,
    build_installed_screen_request,
    derive_control_valve_design_disposition,
    derive_control_valve_safety_findings,
    installed_sizing_inputs,
    validate_control_valve_execution_request,
)
from pydantic import ValidationError
from tests.test_calculation_control_valve import sizing_input as liquid_sizing_input
from tests.test_calculation_control_valve_compressible import (
    sizing_input as compressible_sizing_input,
)
from tests.test_calculation_control_valve_compressible import steam_properties
from tests.test_calculation_control_valve_installed import (
    acoustic_state,
    candidate_from_results,
    exact_node_results,
)


def _liquid_request() -> LiquidControlValveExecutionRequest:
    return LiquidControlValveExecutionRequest(
        operation=ControlValveOperation.LIQUID_SIZING,
        method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        sizing_input=liquid_sizing_input(case_id="WORKFLOW-LIQUID-102"),
    )


def _compressible_request() -> CompressibleControlValveExecutionRequest:
    return CompressibleControlValveExecutionRequest(
        operation=ControlValveOperation.COMPRESSIBLE_SIZING,
        method_id=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        sizing_input=compressible_sizing_input(case_id="WORKFLOW-GAS-102"),
    )


def _installed_request(
    *,
    blocking_travel: bool = False,
    sonic: bool = False,
) -> InstalledControlValveExecutionRequest:
    sizing_results = exact_node_results()
    sizing_inputs = tuple(item.normalized_input for item in sizing_results)
    candidate = candidate_from_results(
        sizing_results,
        minimum_travel=30.0 if blocking_travel else 15.0,
    )

    def operating_point(
        sizing_input: CompressibleControlValveSizingInput,
    ) -> ControlValveOperatingPointInput:
        return ControlValveOperatingPointInput(
            sizing_input=sizing_input,
            downstream_acoustic_state=acoustic_state(
                case_id=sizing_input.case_id,
                density=0.01 if sonic else 8.0,
                speed_of_sound=1.0 if sonic else 350.0,
                diameter=0.01 if sonic else 0.2,
            ),
        )

    return InstalledControlValveExecutionRequest(
        operation=ControlValveOperation.INSTALLED_SCREEN,
        method_id=INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        method_version=CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        screen_id="WORKFLOW-INSTALLED-102",
        candidate=candidate,
        minimum_case=operating_point(sizing_inputs[0]),
        normal_case=operating_point(sizing_inputs[1]),
        maximum_case=operating_point(sizing_inputs[2]),
        candidate_binding_confirmed=True,
        candidate_binding_source_reference=(
            "controlled Step 102 candidate binding record"
        ),
    )


def _size_input(
    value: LiquidControlValveSizingInput | CompressibleControlValveSizingInput,
) -> LiquidControlValveSizingResult | CompressibleControlValveSizingResult:
    if isinstance(value, LiquidControlValveSizingInput):
        return size_liquid_control_valve(value)
    return size_compressible_control_valve(value)


def _calculate_without_service(
    request: ControlValveExecutionRequest,
) -> ControlValveResult:
    if isinstance(request, LiquidControlValveExecutionRequest):
        return size_liquid_control_valve(request.sizing_input)
    if isinstance(request, CompressibleControlValveExecutionRequest):
        return size_compressible_control_valve(request.sizing_input)
    sizing_results = tuple(
        _size_input(item) for item in installed_sizing_inputs(request)
    )
    return evaluate_installed_control_valve_scenarios(
        build_installed_screen_request(request),
        sizing_results,
    )


def _execution_outcome(
    request: ControlValveExecutionRequest,
) -> ControlValveExecutionOutcome:
    normalized = validate_control_valve_execution_request(request)
    operation = ControlValveOperation(normalized.operation)
    metadata = CONTROL_VALVE_API_REGISTRY[operation]
    result = _calculate_without_service(normalized)
    input_fingerprint = build_control_valve_input_fingerprint(normalized)
    result_fingerprint = build_control_valve_result_fingerprint(
        normalized,
        result,
        metadata.knowledge_source_ids,
    )
    trace = ControlValveExecutionTrace(
        operation=operation,
        method_id=metadata.method_id,
        method_version=metadata.method_version,
        calculator_version=result.calculator_version,
        implementation_name=metadata.implementation_name,
        normalized_input_fingerprint=input_fingerprint,
        result_fingerprint=result_fingerprint,
        attempt_fingerprint=build_control_valve_attempt_fingerprint(
            input_fingerprint,
            result_fingerprint,
        ),
        knowledge_source_ids=metadata.knowledge_source_ids,
    )
    if isinstance(result, InstalledControlValveScreenResult):
        findings = derive_control_valve_safety_findings(result)
        disposition = derive_control_valve_design_disposition(findings)
        candidate_identity_origin = "caller_supplied"
    else:
        findings = ()
        disposition = None
        candidate_identity_origin = (
            "not_applicable"
            if isinstance(normalized, LiquidControlValveExecutionRequest)
            else "caller_supplied"
        )
    return ControlValveExecutionOutcome(
        safety_findings=findings,
        disposition=disposition,
        normalized_request=normalized,
        result=result,
        trace=trace,
        candidate_identity_origin=candidate_identity_origin,
    )


def _design_request(*, blocking: bool = True) -> ControlValveDesignCaseRequest:
    return ControlValveDesignCaseRequest(
        design_case_id="CONTROL-VALVE-DESIGN-102",
        revision=1,
        title="Nitrogen control-valve preliminary design",
        service_description=(
            "Controlled nitrogen service with exact minimum, normal, and maximum cases"
        ),
        installed_execution_request=_installed_request(blocking_travel=blocking),
    )


def _design_outcome(*, blocking: bool = True) -> ControlValveDesignCaseOutcome:
    request = _design_request(blocking=blocking)
    calculation = _execution_outcome(request.installed_execution_request)
    assert isinstance(calculation.result, InstalledControlValveScreenResult)
    findings = derive_control_valve_safety_findings(calculation.result)
    disposition = derive_control_valve_design_disposition(findings)
    fingerprint = build_control_valve_design_case_fingerprint(
        request,
        calculation,
        findings,
        disposition,
    )
    return ControlValveDesignCaseOutcome(
        safety_findings=findings,
        disposition=disposition,
        normalized_design_case=request,
        calculation=calculation,
        design_case_fingerprint=fingerprint,
    )


@pytest.mark.parametrize(
    ("request_factory", "result_type"),
    (
        (_liquid_request, LiquidControlValveSizingResult),
        (_compressible_request, CompressibleControlValveSizingResult),
        (_installed_request, InstalledControlValveScreenResult),
    ),
    ids=("liquid", "compressible", "installed"),
)
def test_exact_workflow_requests_execute_valid_reviewed_cases(
    request_factory: object,
    result_type: type[object],
) -> None:
    request = request_factory()  # type: ignore[operator]
    normalized = validate_control_valve_execution_request(request)
    outcome = _execution_outcome(normalized)
    metadata = CONTROL_VALVE_API_REGISTRY[ControlValveOperation(normalized.operation)]

    assert isinstance(outcome.result, result_type)
    assert outcome.trace.workflow_version == CONTROL_VALVE_WORKFLOW_VERSION
    assert (
        outcome.trace.calculator_pack_version == CONTROL_VALVE_CALCULATOR_PACK_VERSION
    )
    assert outcome.trace.method_id == normalized.method_id == metadata.method_id
    assert (
        outcome.trace.method_version
        == normalized.method_version
        == metadata.method_version
    )
    assert outcome.trace.implementation_name == metadata.implementation_name
    if isinstance(outcome.result, InstalledControlValveScreenResult):
        assert tuple(item.evidence.role for item in outcome.result.case_results) == (
            InstalledCaseRole.MINIMUM,
            InstalledCaseRole.NORMAL,
            InstalledCaseRole.MAXIMUM,
        )


def test_catalogue_has_exact_bindings_and_only_inert_knowledge_metadata() -> None:
    expected = {
        ControlValveOperation.LIQUID_SIZING: (
            LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
            LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        ),
        ControlValveOperation.COMPRESSIBLE_SIZING: (
            COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
            COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        ),
        ControlValveOperation.INSTALLED_SCREEN: (
            INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
            CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        ),
    }
    assert isinstance(CONTROL_VALVE_API_REGISTRY, MappingProxyType)
    assert tuple(CONTROL_VALVE_API_REGISTRY) == tuple(ControlValveOperation)
    assert len(CONTROL_VALVE_API_CATALOGUE) == 3
    for operation, (method_id, method_version) in expected.items():
        entry = CONTROL_VALVE_API_REGISTRY[operation]
        assert (entry.method_id, entry.method_version) == (method_id, method_version)
        assert entry.executable is True
        assert entry.knowledge_links_are_inert is True
        assert entry.manufacturer_factors_derived is False
        assert entry.manufacturer_selection_performed is False
        assert entry.standards_conformity_claimed is False
    assert len(CONTROL_VALVE_KNOWLEDGE_LINKS) == 3
    assert all(
        link.retrieval_mode == "inert_metadata_only"
        and link.network_access_performed is False
        and link.approved_as_factor_source is False
        and link.executable is False
        and link.conformity_evidence is False
        and link.standards_conformity_claimed is False
        for link in CONTROL_VALVE_KNOWLEDGE_LINKS
    )


def test_installed_fields_force_minimum_normal_maximum_and_ignore_key_order() -> None:
    request = _installed_request()
    payload = request.model_dump(mode="python", round_trip=True)
    reversed_payload = {key: payload[key] for key in reversed(tuple(payload))}
    normalized = validate_control_valve_execution_request(reversed_payload)
    assert normalized == request
    assert tuple(item.case_id for item in installed_sizing_inputs(normalized)) == (
        "CASE-MIN",
        "CASE-NORMAL",
        "CASE-MAX",
    )
    assert tuple(
        item.role for item in build_installed_screen_request(normalized).operating_cases
    ) == (
        InstalledCaseRole.MINIMUM,
        InstalledCaseRole.NORMAL,
        InstalledCaseRole.MAXIMUM,
    )
    assert build_control_valve_input_fingerprint(normalized) == (
        build_control_valve_input_fingerprint(request)
    )


_CASE_FIELDS = ("minimum_case", "normal_case", "maximum_case")
_PERMUTED_CASE_FIELDS = tuple(
    order for order in permutations(_CASE_FIELDS) if order != _CASE_FIELDS
)


@pytest.mark.parametrize("source_order", _PERMUTED_CASE_FIELDS)
def test_installed_case_value_permutations_fail_closed(
    source_order: tuple[str, str, str],
) -> None:
    payload = _installed_request().model_dump(mode="python", round_trip=True)
    original = {field: payload[field] for field in _CASE_FIELDS}
    for destination, source in zip(_CASE_FIELDS, source_order, strict=True):
        payload[destination] = original[source]
    with pytest.raises(ValidationError, match="flow must increase strictly"):
        validate_control_valve_execution_request(payload)


@pytest.mark.parametrize(
    "request_factory",
    (_liquid_request, _compressible_request, _installed_request),
    ids=("liquid", "compressible", "installed"),
)
@pytest.mark.parametrize(
    ("field", "value"),
    (("method_id", "valve.control.unreviewed"), ("method_version", "9.9.9")),
)
def test_method_and_version_cannot_be_redirected(
    request_factory: object,
    field: str,
    value: str,
) -> None:
    payload = request_factory().model_dump(  # type: ignore[operator]
        mode="python",
        round_trip=True,
    )
    payload[field] = value
    with pytest.raises(ValidationError):
        validate_control_valve_execution_request(payload)


def test_execution_traces_are_deterministic_and_fully_recomputable() -> None:
    request = _installed_request()
    first = _execution_outcome(request)
    second = _execution_outcome(request)
    metadata = CONTROL_VALVE_API_REGISTRY[ControlValveOperation.INSTALLED_SCREEN]
    expected_input = build_control_valve_input_fingerprint(request)
    expected_result = build_control_valve_result_fingerprint(
        request,
        first.result,
        metadata.knowledge_source_ids,
    )

    assert first == second
    assert first.trace.normalized_input_fingerprint == expected_input
    assert first.trace.result_fingerprint == expected_result
    assert first.trace.attempt_fingerprint == build_control_valve_attempt_fingerprint(
        expected_input,
        expected_result,
    )
    assert all(
        len(value) == 64
        for value in (
            first.trace.normalized_input_fingerprint,
            first.trace.result_fingerprint,
            first.trace.attempt_fingerprint,
        )
    )


def test_recomputed_public_hash_cannot_authorize_forged_nested_result() -> None:
    outcome = _execution_outcome(_liquid_request())
    values = outcome.model_dump(mode="python", round_trip=True)
    values["result"]["required_cv"] *= 2.0
    values["result"]["result_fingerprint"] = fingerprint_control_valve_payload(
        build_liquid_control_valve_result_fingerprint_payload(values["result"])
    )
    with pytest.raises(ValidationError):
        ControlValveExecutionOutcome.model_validate(values)


@pytest.mark.parametrize(
    "execution_request",
    (_liquid_request(), _compressible_request()),
    ids=("liquid", "compressible"),
)
def test_recomputed_hashes_cannot_bind_result_for_another_sizing_input(
    execution_request: ControlValveExecutionRequest,
) -> None:
    outcome = _execution_outcome(execution_request)
    if isinstance(execution_request, LiquidControlValveExecutionRequest):
        alternate_input = execution_request.sizing_input.model_copy(
            update={"actual_volumetric_flow_m3_h": 125.0}
        )
    else:
        alternate_input = execution_request.sizing_input.model_copy(
            update={"mass_flow_kg_h": 12_500.0}
        )
    forged_result = _size_input(alternate_input)
    result_fingerprint = build_control_valve_result_fingerprint(
        execution_request,
        forged_result,
        outcome.trace.knowledge_source_ids,
    )
    values = outcome.model_dump(mode="python", round_trip=True)
    values["result"] = forged_result.model_dump(mode="python", round_trip=True)
    values["trace"]["result_fingerprint"] = result_fingerprint
    values["trace"]["attempt_fingerprint"] = (
        build_control_valve_attempt_fingerprint(
            outcome.trace.normalized_input_fingerprint,
            result_fingerprint,
        )
    )

    with pytest.raises(
        ValidationError,
        match="standalone result does not match the canonical request",
    ):
        ControlValveExecutionOutcome.model_validate(values)


def test_recomputed_attempt_hash_cannot_authorize_forged_trace() -> None:
    outcome = _execution_outcome(_compressible_request())
    values = outcome.model_dump(mode="python", round_trip=True)
    forged_result_fingerprint = "f" * 64
    values["trace"]["result_fingerprint"] = forged_result_fingerprint
    values["trace"]["attempt_fingerprint"] = build_control_valve_attempt_fingerprint(
        values["trace"]["normalized_input_fingerprint"],
        forged_result_fingerprint,
    )
    with pytest.raises(ValidationError, match="fingerprints are stale"):
        ControlValveExecutionOutcome.model_validate(values)


def test_caller_cannot_inject_child_results_into_installed_request() -> None:
    values = _installed_request().model_dump(mode="python", round_trip=True)
    values["caller_sizing_results"] = [
        item.model_dump(mode="python", round_trip=True) for item in exact_node_results()
    ]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        validate_control_valve_execution_request(values)


@pytest.mark.parametrize(
    "field",
    ("screen_id", "candidate_binding_source_reference"),
)
def test_installed_traceability_text_rejects_raw_padding(field: str) -> None:
    values = _installed_request().model_dump(mode="python", round_trip=True)
    values[field] = f" {values[field]} "
    with pytest.raises(ValidationError, match="must not be padded"):
        validate_control_valve_execution_request(values)


def test_public_liquid_velocity_limit_upper_bound_is_exact() -> None:
    values = _liquid_request().model_dump(mode="python", round_trip=True)
    values["sizing_input"]["maximum_outlet_velocity"] = {
        "maximum_velocity_m_s": 1.0e6,
        "source_reference": "controlled workflow velocity limit",
        "applicable_conditions": (
            "the exact liquid service and downstream piping arrangement"
        ),
        "supplied_by": "competent piping engineer",
    }

    accepted = validate_control_valve_execution_request(values)
    assert isinstance(accepted, LiquidControlValveExecutionRequest)
    assert accepted.sizing_input.maximum_outlet_velocity is not None
    assert (
        accepted.sizing_input.maximum_outlet_velocity.maximum_velocity_m_s
        == 1.0e6
    )

    values["sizing_input"]["maximum_outlet_velocity"]["maximum_velocity_m_s"] = (
        nextafter(1.0e6, inf)
    )
    with pytest.raises(ValidationError, match="bounded public workflow domain"):
        validate_control_valve_execution_request(values)


@pytest.mark.parametrize(
    ("value", "accepted"),
    (
        (1.0e-12, True),
        (100.0, True),
        (nextafter(1.0e-12, 0.0), False),
        (nextafter(100.0, inf), False),
    ),
    ids=("minimum", "maximum", "below-minimum", "above-maximum"),
)
def test_public_compressibility_factor_bounds_are_exact(
    value: float,
    accepted: bool,
) -> None:
    values = _compressible_request().model_dump(mode="python", round_trip=True)
    values["sizing_input"]["properties"]["compressibility_factor"] = value

    if accepted:
        normalized = validate_control_valve_execution_request(values)
        assert isinstance(normalized, CompressibleControlValveExecutionRequest)
        assert normalized.sizing_input.properties.compressibility_factor == value
    else:
        with pytest.raises(ValidationError, match="bounded public workflow domain"):
            validate_control_valve_execution_request(values)


@pytest.mark.parametrize(
    ("helper_argument", "property_name", "maximum"),
    (
        ("uncertainty_k", "state_uncertainty_k", 1.0e6),
        (
            "pressure_uncertainty_pa",
            "state_pressure_uncertainty_pa",
            1.0e12,
        ),
    ),
    ids=("temperature-uncertainty", "pressure-uncertainty"),
)
def test_public_steam_state_uncertainty_upper_bounds_are_exact(
    helper_argument: str,
    property_name: str,
    maximum: float,
) -> None:
    property_arguments = {helper_argument: maximum}
    sizing = compressible_sizing_input(
        case_id="WORKFLOW-STEAM-BOUND-102",
        p1_pa=475_000.0,
        p2_pa=400_000.0,
        properties=steam_properties(**property_arguments),
    )
    accepted = CompressibleControlValveExecutionRequest(
        operation=ControlValveOperation.COMPRESSIBLE_SIZING,
        method_id=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        sizing_input=sizing,
    )
    assert getattr(accepted.sizing_input.properties, property_name) == maximum

    property_arguments[helper_argument] = nextafter(maximum, inf)
    outside = compressible_sizing_input(
        case_id="WORKFLOW-STEAM-BOUND-102",
        p1_pa=475_000.0,
        p2_pa=400_000.0,
        properties=steam_properties(**property_arguments),
    )
    with pytest.raises(ValidationError, match="bounded public workflow domain"):
        CompressibleControlValveExecutionRequest(
            operation=ControlValveOperation.COMPRESSIBLE_SIZING,
            method_id=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
            method_version=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
            sizing_input=outside,
        )


def test_public_candidate_curve_rejects_subnormal_capacity() -> None:
    values = _installed_request().model_dump(mode="python", round_trip=True)
    values["candidate"]["capacity_curve"][0]["available_cv"] = 5e-324
    with pytest.raises(ValidationError, match="capacity exceeds"):
        validate_control_valve_execution_request(values)


def test_sonic_or_supersonic_downstream_flow_blocks_design_use() -> None:
    outcome = _execution_outcome(_installed_request(sonic=True))
    assert outcome.disposition is ControlValveDesignDisposition.BLOCKED
    sonic = tuple(
        finding
        for finding in outcome.safety_findings
        if finding.code == "downstream_sonic_or_supersonic"
    )
    assert len(sonic) == 3
    assert all(
        finding.severity is ControlValveSafetySeverity.BLOCKING for finding in sonic
    )


def test_installed_safety_findings_have_exact_full_order() -> None:
    outcome = _execution_outcome(
        _installed_request(blocking_travel=True, sonic=True),
    )

    assert tuple(
        (finding.severity, finding.case_role, finding.code, finding.case_id)
        for finding in outcome.safety_findings
    ) == (
        (
            ControlValveSafetySeverity.BLOCKING,
            InstalledCaseRole.MINIMUM,
            "downstream_sonic_or_supersonic",
            "CASE-MIN",
        ),
        (
            ControlValveSafetySeverity.BLOCKING,
            InstalledCaseRole.MINIMUM,
            "travel_window_not_met",
            "CASE-MIN",
        ),
        (
            ControlValveSafetySeverity.BLOCKING,
            InstalledCaseRole.NORMAL,
            "downstream_sonic_or_supersonic",
            "CASE-NORMAL",
        ),
        (
            ControlValveSafetySeverity.BLOCKING,
            InstalledCaseRole.MAXIMUM,
            "downstream_sonic_or_supersonic",
            "CASE-MAX",
        ),
        (
            ControlValveSafetySeverity.REVIEW_REQUIRED,
            None,
            "independent_engineering_review_required",
            None,
        ),
    )


def test_design_outcome_leads_with_typed_ordered_safety_findings() -> None:
    outcome = _design_outcome(blocking=True)
    rendered = outcome.model_dump(mode="python", round_trip=True)
    severity_rank = {
        ControlValveSafetySeverity.BLOCKING: 0,
        ControlValveSafetySeverity.HIGH_PRIORITY: 1,
        ControlValveSafetySeverity.REVIEW_REQUIRED: 2,
    }
    ranks = [severity_rank[item.severity] for item in outcome.safety_findings]

    assert tuple(rendered)[:2] == ("safety_findings", "disposition")
    assert outcome.disposition is ControlValveDesignDisposition.BLOCKED
    assert outcome.safety_findings[0].severity is ControlValveSafetySeverity.BLOCKING
    assert ranks == sorted(ranks)
    assert all(
        finding.safety_first is True and finding.project_approval_granted is False
        for finding in outcome.safety_findings
    )
    assert any(
        finding.case_role is InstalledCaseRole.MINIMUM
        for finding in outcome.safety_findings
    )


@pytest.mark.parametrize("outcome_kind", ("execution", "design"))
def test_outcome_models_reject_reordered_safety_findings(
    outcome_kind: str,
) -> None:
    if outcome_kind == "execution":
        outcome = _execution_outcome(
            _installed_request(blocking_travel=True, sonic=True),
        )
        outcome_model = ControlValveExecutionOutcome
    else:
        outcome = _design_outcome(blocking=True)
        outcome_model = ControlValveDesignCaseOutcome

    values = outcome.model_dump(mode="python", round_trip=True)
    values["safety_findings"] = list(reversed(values["safety_findings"]))
    with pytest.raises(ValidationError):
        outcome_model.model_validate(values)


@pytest.mark.parametrize("forgery", ("finding", "fingerprint"))
def test_design_outcome_rejects_forged_findings_or_fingerprint(
    forgery: str,
) -> None:
    outcome = _design_outcome(blocking=True)
    values = outcome.model_dump(mode="python", round_trip=True)
    if forgery == "finding":
        values["safety_findings"][0]["summary"] = (
            "Forged summary that is long enough to satisfy field validation."
        )
    else:
        values["design_case_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError):
        ControlValveDesignCaseOutcome.model_validate(values)


def test_workflow_outputs_never_claim_approval_product_acoustics_or_conformity() -> (
    None
):
    execution = _execution_outcome(_installed_request())
    design = _design_outcome(blocking=True)

    assert execution.candidate_identity_origin == "caller_supplied"
    assert execution.selection_ready is False
    assert execution.independent_review_required is True
    assert execution.manufacturer_selection_performed is False
    assert execution.exact_product_selected is False
    assert execution.sound_pressure_level_predicted is False
    assert execution.standards_conformity_claimed is False
    assert execution.trace.standards_adapter_execution_count == 0
    assert execution.trace.manufacturer_factors_derived is False
    assert execution.trace.manufacturer_selection_performed is False
    assert execution.trace.standards_conformity_claimed is False

    assert design.candidate_identity_origin == "caller_supplied"
    assert design.selection_ready is False
    assert design.independent_review_required is True
    assert design.manufacturer_selection_performed is False
    assert design.manufacturer_declared_best is False
    assert design.exact_product_selected is False
    assert design.final_brand_selection == "user_decision_required"
    assert design.approved_for_project_use is False
    assert design.sound_pressure_level_predicted is False
    assert design.standards_conformity_claimed is False


def test_step102_modules_have_no_prohibited_coupling_or_dynamic_execution() -> None:
    modules = (
        workflow_module,
        control_valve_service_module,
        control_valve_api_module,
    )
    prohibited_import_roots = {
        "aiohttp",
        "boto3",
        "httpx",
        "psycopg",
        "redis",
        "requests",
        "socket",
        "sqlalchemy",
        "sqlmodel",
        "subprocess",
        "urllib",
    }
    prohibited_coupling_fragments = {
        "database",
        "network",
        "persistence",
        "product",
        "repository",
        "selection",
        "speech",
        "voice",
    }
    prohibited_dynamic_calls = {"eval", "exec", "__import__"}

    for module in modules:
        tree = ast.parse(inspect.getsource(module))
        imported_modules: set[str] = set()
        imported_names: set[str] = set()
        called_names: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
                    imported_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)
                imported_names.update(
                    alias.asname or alias.name for alias in node.names
                )
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_names.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called_names.add(node.func.attr)

        imported_roots = {
            imported.split(".", 1)[0] for imported in imported_modules
        }
        coupling_names = imported_modules | imported_names | called_names
        prohibited_couplings = {
            name
            for name in coupling_names
            if any(
                fragment in name.casefold()
                for fragment in prohibited_coupling_fragments
            )
        }

        assert imported_roots.isdisjoint(prohibited_import_roots), module.__name__
        assert prohibited_couplings == set(), module.__name__
        assert called_names.isdisjoint(prohibited_dynamic_calls), module.__name__
