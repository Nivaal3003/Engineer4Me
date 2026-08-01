"""Focused acceptance tests for Step 101 installed valve screening."""

from __future__ import annotations

import ast
import inspect
from decimal import Decimal
from math import pi
from types import MappingProxyType

import pytest
from pydantic import ValidationError

import app.engineering.calculations as calculation_package
import app.engineering.calculations.control_valve_installed as module
from app.engineering.calculations.control_valve import (
    LiquidControlValvePressureState,
    LiquidControlValveProperties,
    LiquidControlValveSizingInput,
    TraceableLiquidValveFactors,
    ValveInstallationBasis,
    fingerprint_control_valve_payload,
    size_liquid_control_valve,
)
from app.engineering.calculations.control_valve_compressible import (
    CompressibleControlValvePressureState,
    CompressibleControlValveSizingInput,
    CompressibleFlowingProperties,
    TraceableCompressibleValveFactors,
    size_compressible_control_valve,
)
from app.engineering.calculations.control_valve_installed import (
    CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION,
    CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    IEC_60534_2_4_ADAPTER,
    IEC_60534_8_3_ADAPTER,
    INSTALLED_CONTROL_VALVE_DISCOVERY_ENTRIES,
    INSTALLED_CONTROL_VALVE_METHOD_IMPLEMENTATIONS,
    INSTALLED_CONTROL_VALVE_METHOD_REGISTRY,
    INSTALLED_CONTROL_VALVE_SCREEN_ADAPTER,
    INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    AerodynamicNoisePriority,
    CapacityCurveStatus,
    FactorTravelCoherenceStatus,
    InstalledCaseRole,
    InstalledControlValveInputError,
    InstalledControlValveScreenRequest,
    InstalledControlValveScreenResult,
    InstalledOperatingCase,
    RangeabilityStatus,
    TraceableDownstreamAcousticState,
    TraceableInstalledValveCandidate,
    TraceableMachLimit,
    TraceableTravelCapacityPoint,
    TravelWindowStatus,
    evaluate_installed_control_valve_scenarios,
)
from app.engineering.calculations.dp_flow import DP_FLOW_METHOD_REGISTRY
from app.engineering.calculations.models import MethodLifecycleStatus


def compressible_result(
    *,
    flow_kg_h: float,
    case_id: str,
    factor_travel: float,
    p2_pa: float = 800_000.0,
    candidate_id: str = "CAND-101",
    trim_id: str = "TRIM-101",
    flow_direction: str = "flow to open",
    fluid_identity: str = "controlled nitrogen basis",
    installation_basis: ValveInstallationBasis = ValveInstallationBasis.BARE_VALVE,
    installation_context_id: str = "INSTALLATION-101",
):
    properties = CompressibleFlowingProperties(
        fluid_phase="gas",
        fluid_identity=fluid_identity,
        upstream_temperature_k=300.0,
        upstream_density_kg_m3=10.0,
        isentropic_exponent=1.4,
        compressibility_factor=1.0,
        molecular_mass_kg_kmol=28.0134,
        property_source_reference="controlled property record PROP-101",
        condition_basis="properties at the exact upstream P1 and T1 state",
    )
    pressure = CompressibleControlValvePressureState(
        upstream_pressure_absolute_pa=1_000_000.0,
        downstream_pressure_absolute_pa=p2_pa,
        pressure_basis="absolute",
        pressure_source_reference="controlled operating record OP-101",
        condition_basis="simultaneous steady upstream and downstream pressures",
    )
    factor_values: dict[str, object] = {
        "candidate_id": candidate_id,
        "trim_id": trim_id,
        "installation_context_id": installation_context_id,
        "travel_percent": factor_travel,
        "flow_direction": flow_direction,
        "installation_basis": installation_basis,
        "source_reference": "controlled factor record XT-101",
        "applicable_conditions": "exact candidate trim travel direction and state",
        "supplied_by": "competent control-valve engineer",
    }
    if installation_basis is ValveInstallationBasis.BARE_VALVE:
        factor_values["bare_valve_pressure_drop_ratio_factor"] = 0.5
    else:
        factor_values["piping_geometry_factor"] = 0.9
        factor_values["installed_pressure_drop_ratio_factor"] = 0.5
    factors = TraceableCompressibleValveFactors(
        **factor_values,
    )
    values = CompressibleControlValveSizingInput(
        case_id=case_id,
        mass_flow_kg_h=flow_kg_h,
        mass_flow_source_reference="controlled mass-flow record FLOW-101",
        flow_condition_basis="steady mass rate at the declared flowing state",
        pressure_state=pressure,
        properties=properties,
        factors=factors,
        turbulent_flow_confirmed=True,
        homogeneous_composition_confirmed=True,
        single_phase_inlet_confirmed=True,
        single_phase_outlet_confirmed=True,
        no_condensation_or_phase_change_confirmed=True,
        property_state_aligned_confirmed=True,
    )
    return size_compressible_control_valve(values)


def exact_node_results():
    return (
        compressible_result(flow_kg_h=1_000.0, case_id="CASE-MIN", factor_travel=20.0),
        compressible_result(
            flow_kg_h=2_000.0, case_id="CASE-NORMAL", factor_travel=40.0
        ),
        compressible_result(flow_kg_h=3_000.0, case_id="CASE-MAX", factor_travel=60.0),
    )


def candidate_from_results(
    results=None,
    *,
    minimum_travel: float = 15.0,
    maximum_travel: float = 90.0,
    rangeability: float = 50.0,
    candidate_id: str = "CAND-101",
    trim_id: str = "TRIM-101",
    flow_direction: str = "flow to open",
):
    values = results or exact_node_results()
    return TraceableInstalledValveCandidate(
        candidate_id=candidate_id,
        trim_id=trim_id,
        installation_context_id="INSTALLATION-101",
        flow_direction=flow_direction,
        capacity_curve=(
            TraceableTravelCapacityPoint(
                travel_percent=10.0,
                available_cv=values[0].required_cv / 2.0,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=20.0,
                available_cv=values[0].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=40.0,
                available_cv=values[1].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=60.0,
                available_cv=values[2].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=100.0,
                available_cv=values[2].required_cv * 2.0,
            ),
        ),
        minimum_controllable_travel_percent=minimum_travel,
        maximum_recommended_travel_percent=maximum_travel,
        declared_inherent_rangeability=rangeability,
        maximum_factor_travel_mismatch_percent=1.0,
        interpolation_basis="caller_supplied_piecewise_linear",
        source_reference="controlled installed characteristic record CURVE-101",
        applicable_conditions="exact candidate trim direction and installed context",
        supplied_by="competent control-valve engineer",
    )


def mach_limit(value: float = 0.3) -> TraceableMachLimit:
    return TraceableMachLimit(
        maximum_downstream_bulk_mach=value,
        source_reference="controlled project Mach limit MACH-101",
        applicable_conditions="the exact candidate and downstream operating state",
        supplied_by="competent piping engineer",
    )


def acoustic_state(
    *,
    case_id: str = "CASE-MIN",
    density: float = 8.0,
    speed_of_sound: float = 350.0,
    diameter: float = 0.2,
    limit: TraceableMachLimit | None = None,
    candidate_id: str = "CAND-101",
    trim_id: str = "TRIM-101",
) -> TraceableDownstreamAcousticState:
    return TraceableDownstreamAcousticState(
        sizing_case_id=case_id,
        candidate_id=candidate_id,
        trim_id=trim_id,
        flow_direction="flow to open",
        installation_context_id="INSTALLATION-101",
        downstream_density_kg_m3=density,
        downstream_speed_of_sound_m_s=speed_of_sound,
        downstream_pipe_inside_diameter_m=diameter,
        maximum_bulk_mach=limit,
        source_reference="controlled downstream-state record DOWN-101",
        condition_basis="exact simultaneous downstream density and sound speed",
    )


def request_for(
    candidate: TraceableInstalledValveCandidate,
    *,
    acoustic: bool = True,
    case_ids: tuple[str, str, str] = ("CASE-MIN", "CASE-NORMAL", "CASE-MAX"),
) -> InstalledControlValveScreenRequest:
    def state(case_id: str) -> TraceableDownstreamAcousticState | None:
        return acoustic_state(case_id=case_id) if acoustic else None

    return InstalledControlValveScreenRequest(
        screen_id="INSTALLED-SCREEN-101",
        candidate=candidate,
        operating_cases=(
            InstalledOperatingCase(
                role=InstalledCaseRole.NORMAL,
                sizing_case_id=case_ids[1],
                downstream_acoustic_state=state(case_ids[1]),
            ),
            InstalledOperatingCase(
                role=InstalledCaseRole.MAXIMUM,
                sizing_case_id=case_ids[2],
                downstream_acoustic_state=state(case_ids[2]),
            ),
            InstalledOperatingCase(
                role=InstalledCaseRole.MINIMUM,
                sizing_case_id=case_ids[0],
                downstream_acoustic_state=state(case_ids[0]),
            ),
        ),
        candidate_binding_confirmed=True,
        candidate_binding_source_reference="controlled candidate binding BIND-101",
    )


def successful_result():
    sizing = exact_node_results()
    return evaluate_installed_control_valve_scenarios(
        request_for(candidate_from_results(sizing)),
        sizing,
    )


def test_exact_minimum_normal_maximum_screen_is_deterministic() -> None:
    result = successful_result()
    assert tuple(item.evidence.role for item in result.case_results) == tuple(
        InstalledCaseRole
    )
    assert tuple(item.required_travel_percent for item in result.case_results) == (
        20.0,
        40.0,
        60.0,
    )
    assert all(item.inverse_solution_verified for item in result.case_results)
    assert all(item.inverse_iteration_count == 0 for item in result.case_results)
    assert all(item.capacity_residual_cv == 0.0 for item in result.case_results)
    assert all(
        item.travel_window_status is TravelWindowStatus.WITHIN_SUPPLIED_WINDOW
        for item in result.case_results
    )
    assert result.rangeability.status is RangeabilityStatus.WITHIN_SUPPLIED_RANGEABILITY
    assert result.candidate_capacity_and_travel_screen_passed is True
    assert result.selection_ready is False
    assert result.independent_review_required is True
    assert result.manufacturer_selection_performed is False
    assert result.sound_pressure_level_predicted is False
    assert result.standards_conformity_claimed is False


def test_piecewise_linear_interpolation_has_forward_residual_proof() -> None:
    temporary = tuple(
        compressible_result(
            flow_kg_h=flow,
            case_id=case_id,
            factor_travel=50.0,
        )
        for flow, case_id in (
            (1_000.0, "CASE-MIN"),
            (2_000.0, "CASE-NORMAL"),
            (3_000.0, "CASE-MAX"),
        )
    )
    interpolated = tuple(
        compressible_result(
            flow_kg_h=item.normalized_input.mass_flow_kg_h,
            case_id=item.normalized_input.case_id,
            factor_travel=item.required_cv * 2.0,
        )
        for item in temporary
    )
    candidate = TraceableInstalledValveCandidate(
        candidate_id="CAND-101",
        trim_id="TRIM-101",
        installation_context_id="INSTALLATION-101",
        flow_direction="flow to open",
        capacity_curve=(
            TraceableTravelCapacityPoint(travel_percent=10.0, available_cv=5.0),
            TraceableTravelCapacityPoint(travel_percent=100.0, available_cv=50.0),
        ),
        minimum_controllable_travel_percent=10.0,
        maximum_recommended_travel_percent=100.0,
        declared_inherent_rangeability=10.0,
        maximum_factor_travel_mismatch_percent=1.0,
        interpolation_basis="caller_supplied_piecewise_linear",
        source_reference="controlled linear curve CURVE-101-L",
        applicable_conditions="exact candidate trim direction and installed context",
        supplied_by="competent control-valve engineer",
    )
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate),
        interpolated,
    )
    for case in result.case_results:
        assert case.capacity_curve_status is CapacityCurveStatus.WITHIN_CURVE
        assert case.available_cv_at_required_travel == pytest.approx(
            case.evidence.required_cv
        )
        assert case.relative_capacity_residual <= 1e-12
        assert case.inverse_solution_verified is True
        assert (
            case.factor_travel_coherence_status is FactorTravelCoherenceStatus.MATCHED
        )


@pytest.mark.parametrize(
    ("scale", "expected"),
    ((0.01, CapacityCurveStatus.ABOVE_CURVE), (100.0, CapacityCurveStatus.BELOW_CURVE)),
)
def test_outside_curve_never_extrapolates(
    scale: float,
    expected: CapacityCurveStatus,
) -> None:
    sizing = exact_node_results()
    base = candidate_from_results(sizing)
    values = base.model_dump(mode="python")
    for point in values["capacity_curve"]:
        point["available_cv"] *= scale
    candidate = TraceableInstalledValveCandidate.model_validate(values)
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate),
        sizing,
    )
    assert all(item.capacity_curve_status is expected for item in result.case_results)
    assert all(item.required_travel_percent is None for item in result.case_results)
    assert all(item.inverse_solution_verified is False for item in result.case_results)
    assert result.candidate_capacity_and_travel_screen_passed is False


@pytest.mark.parametrize(
    ("minimum", "maximum", "role", "expected"),
    (
        (
            30.0,
            90.0,
            InstalledCaseRole.MINIMUM,
            TravelWindowStatus.BELOW_MINIMUM_TRAVEL,
        ),
        (
            15.0,
            50.0,
            InstalledCaseRole.MAXIMUM,
            TravelWindowStatus.ABOVE_MAXIMUM_TRAVEL,
        ),
    ),
)
def test_supplied_travel_window_is_screened(
    minimum: float,
    maximum: float,
    role: InstalledCaseRole,
    expected: TravelWindowStatus,
) -> None:
    sizing = exact_node_results()
    result = evaluate_installed_control_valve_scenarios(
        request_for(
            candidate_from_results(
                sizing,
                minimum_travel=minimum,
                maximum_travel=maximum,
            )
        ),
        sizing,
    )
    by_role = {item.evidence.role: item for item in result.case_results}
    assert by_role[role].travel_window_status is expected
    assert result.candidate_capacity_and_travel_screen_passed is False


def test_declared_rangeability_can_be_the_limiting_evidence() -> None:
    sizing = exact_node_results()
    candidate = candidate_from_results(sizing, rangeability=2.0)
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate),
        sizing,
    )
    assert result.rangeability.required_capacity_ratio == pytest.approx(3.0)
    assert result.rangeability.effective_supplied_rangeability == 2.0
    assert (
        result.rangeability.status is RangeabilityStatus.EXCEEDS_SUPPLIED_RANGEABILITY
    )
    assert result.candidate_capacity_and_travel_screen_passed is False


def test_factor_travel_mismatch_blocks_screen_pass() -> None:
    sizing = (
        compressible_result(flow_kg_h=1_000.0, case_id="CASE-MIN", factor_travel=25.0),
        compressible_result(
            flow_kg_h=2_000.0, case_id="CASE-NORMAL", factor_travel=45.0
        ),
        compressible_result(flow_kg_h=3_000.0, case_id="CASE-MAX", factor_travel=65.0),
    )
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate_from_results(sizing)),
        sizing,
    )
    assert all(
        item.factor_travel_coherence_status is FactorTravelCoherenceStatus.MISMATCHED
        for item in result.case_results
    )
    assert result.candidate_capacity_and_travel_screen_passed is False


@pytest.mark.parametrize(
    "candidate_change",
    (
        {"candidate_id": "WRONG-CANDIDATE"},
        {"trim_id": "WRONG-TRIM"},
        {"installation_context_id": "WRONG-INSTALLATION"},
        {"flow_direction": "flow to close"},
    ),
)
def test_compressible_factor_context_must_match_candidate_even_outside_curve(
    candidate_change: dict[str, str],
) -> None:
    sizing = exact_node_results()
    candidate_values = candidate_from_results(sizing).model_dump(mode="python")
    candidate_values.update(candidate_change)
    candidate = TraceableInstalledValveCandidate.model_validate(candidate_values)
    with pytest.raises(InstalledControlValveInputError, match="factor context"):
        evaluate_installed_control_valve_scenarios(
            request_for(candidate),
            sizing,
        )


def test_bulk_velocity_and_mach_are_calculated_from_downstream_state() -> None:
    result = successful_result()
    minimum = result.case_results[0]
    expected_velocity = (1_000.0 / 3600.0) / (8.0 * pi * 0.2**2 / 4.0)
    assert minimum.aerodynamic_noise.downstream_bulk_velocity_m_s == pytest.approx(
        float(expected_velocity)
    )
    assert minimum.aerodynamic_noise.downstream_bulk_mach == pytest.approx(
        float(expected_velocity) / 350.0
    )
    assert (
        minimum.aerodynamic_noise.priority is AerodynamicNoisePriority.REVIEW_REQUIRED
    )
    assert minimum.aerodynamic_noise.sound_pressure_level_predicted is False


@pytest.mark.parametrize(
    ("diameter", "limit_value", "expected_priority", "within"),
    (
        (0.2, 0.3, AerodynamicNoisePriority.REVIEW_REQUIRED, True),
        (0.01, 0.01, AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW, False),
    ),
)
def test_traceable_mach_limit_controls_review_priority_without_clearing_noise(
    diameter: float,
    limit_value: float,
    expected_priority: AerodynamicNoisePriority,
    within: bool,
) -> None:
    sizing = exact_node_results()
    request = request_for(candidate_from_results(sizing))
    values = request.model_dump(mode="python")
    for item in values["operating_cases"]:
        item["downstream_acoustic_state"] = acoustic_state(
            case_id=item["sizing_case_id"],
            diameter=diameter,
            limit=mach_limit(limit_value),
        ).model_dump(mode="python")
    result = evaluate_installed_control_valve_scenarios(
        InstalledControlValveScreenRequest.model_validate(values),
        sizing,
    )
    assert result.case_results[0].aerodynamic_noise.priority is expected_priority
    assert result.case_results[0].aerodynamic_noise.within_supplied_mach_limit is within
    assert (
        result.case_results[0].aerodynamic_noise.sound_pressure_level_predicted is False
    )


def test_sonic_bulk_mach_is_high_priority_even_without_project_limit() -> None:
    sizing = exact_node_results()
    request = request_for(candidate_from_results(sizing))
    values = request.model_dump(mode="python")
    for item in values["operating_cases"]:
        item["downstream_acoustic_state"] = acoustic_state(
            case_id=item["sizing_case_id"],
            diameter=0.001,
        ).model_dump(mode="python")
    result = evaluate_installed_control_valve_scenarios(
        InstalledControlValveScreenRequest.model_validate(values),
        sizing,
    )
    maximum = result.case_results[-1].aerodynamic_noise
    assert maximum.downstream_bulk_mach > 1.0
    assert maximum.priority is AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
    assert maximum.sound_pressure_level_predicted is False


def test_missing_acoustic_state_is_unassessed_for_subcritical_flow() -> None:
    sizing = exact_node_results()
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate_from_results(sizing), acoustic=False),
        sizing,
    )
    assert all(
        item.aerodynamic_noise.priority is AerodynamicNoisePriority.NOT_ASSESSED
        for item in result.case_results
    )


def test_missing_acoustic_state_is_high_priority_for_choked_flow() -> None:
    sizing = tuple(
        compressible_result(
            flow_kg_h=flow,
            case_id=case_id,
            factor_travel=travel,
            p2_pa=100_000.0,
        )
        for flow, case_id, travel in (
            (1_000.0, "CASE-MIN", 20.0),
            (2_000.0, "CASE-NORMAL", 40.0),
            (3_000.0, "CASE-MAX", 60.0),
        )
    )
    result = evaluate_installed_control_valve_scenarios(
        request_for(candidate_from_results(sizing), acoustic=False),
        sizing,
    )
    assert all(item.evidence.choked for item in result.case_results)
    assert all(
        item.aerodynamic_noise.priority is AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
        for item in result.case_results
    )


def test_acoustic_state_candidate_and_trim_binding_is_mandatory() -> None:
    sizing = exact_node_results()
    request = request_for(candidate_from_results(sizing))
    values = request.model_dump(mode="python")
    values["operating_cases"][0]["downstream_acoustic_state"]["candidate_id"] = "WRONG"
    with pytest.raises(InstalledControlValveInputError, match="acoustic state"):
        evaluate_installed_control_valve_scenarios(
            InstalledControlValveScreenRequest.model_validate(values),
            sizing,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sizing_case_id", "WRONG-CASE"),
        ("flow_direction", "flow to close"),
        ("installation_context_id", "WRONG-INSTALLATION"),
    ),
)
def test_acoustic_state_is_bound_to_exact_case_direction_and_context(
    field: str,
    value: str,
) -> None:
    sizing = exact_node_results()
    request = request_for(candidate_from_results(sizing))
    values = request.model_dump(mode="python")
    values["operating_cases"][0]["downstream_acoustic_state"][field] = value
    with pytest.raises(InstalledControlValveInputError, match="acoustic state"):
        evaluate_installed_control_valve_scenarios(
            InstalledControlValveScreenRequest.model_validate(values),
            sizing,
        )


@pytest.mark.parametrize("diameter", (5e-324, 1e308))
def test_extreme_acoustic_geometry_fails_with_controlled_domain_error(
    diameter: float,
) -> None:
    sizing = exact_node_results()
    request = request_for(candidate_from_results(sizing))
    values = request.model_dump(mode="python")
    for item in values["operating_cases"]:
        item["downstream_acoustic_state"] = acoustic_state(
            case_id=item["sizing_case_id"],
            diameter=diameter,
        ).model_dump(mode="python")
    with pytest.raises(InstalledControlValveInputError, match="flow area|evaluated"):
        evaluate_installed_control_valve_scenarios(
            InstalledControlValveScreenRequest.model_validate(values),
            sizing,
        )


def liquid_result(*, flow_m3_h: float, case_id: str):
    values = LiquidControlValveSizingInput(
        case_id=case_id,
        actual_volumetric_flow_m3_h=flow_m3_h,
        volumetric_flow_basis="actual_at_inlet_conditions",
        flow_source_reference="controlled liquid flow record LIQ-101",
        flow_condition_basis="actual liquid volume at the declared inlet state",
        properties=LiquidControlValveProperties(
            specific_gravity=1.0,
            flowing_temperature_k=293.15,
            vapor_pressure_absolute_pa=20_000.0,
            critical_pressure_absolute_pa=22_064_000.0,
            thermodynamic_pressure_basis="absolute",
            property_source_reference="controlled liquid property record",
            condition_basis="properties at the declared single-phase inlet state",
        ),
        pressure_state=LiquidControlValvePressureState(
            upstream_pressure_absolute_pa=1_000_000.0,
            downstream_pressure_absolute_pa=700_000.0,
            pressure_basis="absolute",
            pressure_source_reference="controlled liquid pressure record",
            condition_basis="simultaneous steady operating pressures",
        ),
        factors=TraceableLiquidValveFactors(
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_recovery_factor=0.9,
            source_reference="controlled liquid factor record",
            applicable_conditions="exact candidate and bare-valve arrangement",
            supplied_by="competent valve engineer",
        ),
        outlet_inside_diameter_m=0.2,
        outlet_diameter_source_reference="controlled liquid pipe record",
        fluid_phase="liquid",
        rheology="newtonian",
        turbulent_flow_confirmed=True,
        incompressible_flow_confirmed=True,
        single_phase_inlet_confirmed=True,
        suspended_solids_absent_confirmed=True,
    )
    return size_liquid_control_valve(values)


def test_liquid_results_are_supported_but_aerodynamic_noise_is_not_applicable() -> None:
    sizing = (
        liquid_result(flow_m3_h=10.0, case_id="LIQ-MIN"),
        liquid_result(flow_m3_h=20.0, case_id="LIQ-NORMAL"),
        liquid_result(flow_m3_h=30.0, case_id="LIQ-MAX"),
    )
    candidate = candidate_from_results(sizing)
    result = evaluate_installed_control_valve_scenarios(
        request_for(
            candidate,
            acoustic=False,
            case_ids=("LIQ-MIN", "LIQ-NORMAL", "LIQ-MAX"),
        ),
        sizing,
    )
    assert all(item.evidence.fluid_phase == "liquid" for item in result.case_results)
    assert all(
        item.factor_travel_coherence_status
        is FactorTravelCoherenceStatus.NOT_MACHINE_VERIFIABLE_LIQUID
        for item in result.case_results
    )
    assert all(
        item.aerodynamic_noise.priority
        is AerodynamicNoisePriority.NOT_APPLICABLE_LIQUID
        for item in result.case_results
    )
    assert result.candidate_capacity_and_travel_screen_passed is False


def test_liquid_case_rejects_aerodynamic_acoustic_state() -> None:
    sizing = (
        liquid_result(flow_m3_h=10.0, case_id="LIQ-MIN"),
        liquid_result(flow_m3_h=20.0, case_id="LIQ-NORMAL"),
        liquid_result(flow_m3_h=30.0, case_id="LIQ-MAX"),
    )
    with pytest.raises(InstalledControlValveInputError, match="liquid case"):
        evaluate_installed_control_valve_scenarios(
            request_for(
                candidate_from_results(sizing),
                case_ids=("LIQ-MIN", "LIQ-NORMAL", "LIQ-MAX"),
            ),
            sizing,
        )


@pytest.mark.parametrize(
    "roles",
    (
        ("minimum", "minimum", "maximum"),
        ("minimum", "normal", "normal"),
    ),
)
def test_request_requires_exactly_one_of_each_role(roles: tuple[str, str, str]) -> None:
    candidate = candidate_from_results()
    with pytest.raises(ValidationError, match="exactly one"):
        InstalledControlValveScreenRequest(
            screen_id="BAD-ROLES",
            candidate=candidate,
            operating_cases=tuple(
                InstalledOperatingCase(role=role, sizing_case_id=f"CASE-{index}")
                for index, role in enumerate(roles)
            ),
            candidate_binding_confirmed=True,
            candidate_binding_source_reference="controlled binding record",
        )


def test_candidate_binding_confirmation_is_mandatory() -> None:
    values = request_for(candidate_from_results()).model_dump(mode="python")
    values["candidate_binding_confirmed"] = False
    with pytest.raises(ValidationError, match="binding"):
        InstalledControlValveScreenRequest.model_validate(values)


@pytest.mark.parametrize(
    "points",
    (
        ((10.0, 1.0), (10.0, 2.0)),
        ((10.0, 2.0), (20.0, 2.0)),
        ((20.0, 1.0), (10.0, 2.0)),
        ((10.0, 2.0), (20.0, 1.0)),
    ),
)
def test_curve_travel_and_capacity_must_be_strictly_increasing(
    points: tuple[tuple[float, float], tuple[float, float]],
) -> None:
    values = candidate_from_results().model_dump(mode="python")
    values["capacity_curve"] = [
        {"travel_percent": travel, "available_cv": cv} for travel, cv in points
    ]
    values["minimum_controllable_travel_percent"] = min(item[0] for item in points)
    values["maximum_recommended_travel_percent"] = max(item[0] for item in points)
    with pytest.raises(ValidationError):
        TraceableInstalledValveCandidate.model_validate(values)


@pytest.mark.parametrize(
    "value",
    (
        True,
        False,
        "1.0",
        Decimal("1.0"),
        float("nan"),
        float("inf"),
        float("-inf"),
        10**400,
    ),
)
def test_raw_curve_numbers_reject_coercive_or_nonfinite_values(value: object) -> None:
    with pytest.raises((ValidationError, OverflowError)):
        TraceableTravelCapacityPoint(travel_percent=value, available_cv=1.0)


def test_flow_roles_must_be_strictly_increasing() -> None:
    sizing = (
        compressible_result(flow_kg_h=2_000.0, case_id="CASE-MIN", factor_travel=20.0),
        compressible_result(
            flow_kg_h=1_000.0, case_id="CASE-NORMAL", factor_travel=40.0
        ),
        compressible_result(flow_kg_h=3_000.0, case_id="CASE-MAX", factor_travel=60.0),
    )
    with pytest.raises(InstalledControlValveInputError, match="strictly increasing"):
        evaluate_installed_control_valve_scenarios(
            request_for(candidate_from_results()),
            sizing,
        )


def test_compressible_cases_require_one_fluid_identity() -> None:
    sizing = (
        compressible_result(
            flow_kg_h=1_000.0,
            case_id="CASE-MIN",
            factor_travel=20.0,
            fluid_identity="nitrogen",
        ),
        compressible_result(
            flow_kg_h=2_000.0,
            case_id="CASE-NORMAL",
            factor_travel=40.0,
            fluid_identity="hydrogen",
        ),
        compressible_result(
            flow_kg_h=3_000.0,
            case_id="CASE-MAX",
            factor_travel=60.0,
            fluid_identity="carbon dioxide",
        ),
    )
    with pytest.raises(InstalledControlValveInputError, match="fluid identity"):
        evaluate_installed_control_valve_scenarios(
            request_for(candidate_from_results()),
            sizing,
        )


def test_compressible_cases_require_one_installation_basis() -> None:
    sizing = (
        compressible_result(flow_kg_h=1_000.0, case_id="CASE-MIN", factor_travel=20.0),
        compressible_result(
            flow_kg_h=2_000.0,
            case_id="CASE-NORMAL",
            factor_travel=40.0,
            installation_basis=ValveInstallationBasis.ATTACHED_FITTINGS,
        ),
        compressible_result(flow_kg_h=3_000.0, case_id="CASE-MAX", factor_travel=60.0),
    )
    with pytest.raises(InstalledControlValveInputError, match="installation basis"):
        evaluate_installed_control_valve_scenarios(
            request_for(candidate_from_results()),
            sizing,
        )


def test_compressible_cases_require_one_installation_context() -> None:
    sizing = (
        compressible_result(flow_kg_h=1_000.0, case_id="CASE-MIN", factor_travel=20.0),
        compressible_result(
            flow_kg_h=2_000.0,
            case_id="CASE-NORMAL",
            factor_travel=40.0,
            installation_context_id="OTHER-INSTALLATION",
        ),
        compressible_result(flow_kg_h=3_000.0, case_id="CASE-MAX", factor_travel=60.0),
    )
    with pytest.raises(InstalledControlValveInputError, match="installation context"):
        evaluate_installed_control_valve_scenarios(
            request_for(candidate_from_results()),
            sizing,
        )


def test_sizing_results_must_be_exactly_three_validated_tuple_members() -> None:
    request = request_for(candidate_from_results())
    with pytest.raises(InstalledControlValveInputError, match="exactly three"):
        evaluate_installed_control_valve_scenarios(request, exact_node_results()[:2])
    with pytest.raises(InstalledControlValveInputError, match="exactly three"):
        evaluate_installed_control_valve_scenarios(
            request,
            list(exact_node_results()),  # type: ignore[arg-type]
        )


def test_request_case_ids_must_match_all_and_only_supplied_results() -> None:
    sizing = exact_node_results()
    request = request_for(
        candidate_from_results(sizing),
        case_ids=("CASE-MIN", "CASE-NORMAL", "MISSING"),
    )
    with pytest.raises(InstalledControlValveInputError, match="reference"):
        evaluate_installed_control_valve_scenarios(request, sizing)


def test_public_hash_cannot_authorize_forged_travel_output() -> None:
    result = successful_result()
    values = result.model_dump(mode="python")
    values["case_results"][0]["required_travel_percent"] = 21.0
    values["result_fingerprint"] = fingerprint_control_valve_payload(
        module._result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError):
        InstalledControlValveScreenResult.model_validate(values)


def test_public_hash_cannot_authorize_forged_noise_priority() -> None:
    result = successful_result()
    values = result.model_dump(mode="python")
    values["case_results"][0]["aerodynamic_noise"]["priority"] = (
        AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
    )
    values["result_fingerprint"] = fingerprint_control_valve_payload(
        module._result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError):
        InstalledControlValveScreenResult.model_validate(values)


def test_public_hash_cannot_authorize_forged_sizing_evidence() -> None:
    result = successful_result()
    values = result.model_dump(mode="python")
    values["sizing_evidence"][0]["required_cv"] *= 2.0
    values["result_fingerprint"] = fingerprint_control_valve_payload(
        module._result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError):
        InstalledControlValveScreenResult.model_validate(values)


def test_fingerprints_are_deterministic_and_provenance_sensitive() -> None:
    first = successful_result()
    second = successful_result()
    request_values = first.normalized_request.model_dump(mode="python")
    request_values["candidate_binding_source_reference"] = (
        "controlled candidate binding BIND-101-REV2"
    )
    changed = evaluate_installed_control_valve_scenarios(
        InstalledControlValveScreenRequest.model_validate(request_values),
        first.normalized_sizing_results,
    )
    assert first.input_fingerprint == second.input_fingerprint
    assert first.result_fingerprint == second.result_fingerprint
    assert changed.input_fingerprint != first.input_fingerprint
    assert changed.result_fingerprint != first.result_fingerprint


def test_exact_version_registry_is_immutable_and_coherent() -> None:
    key = (
        INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    )
    assert CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION == "1.0.0"
    assert CONTROL_VALVE_INSTALLED_METHOD_VERSION == "1.0.0"
    assert isinstance(INSTALLED_CONTROL_VALVE_METHOD_REGISTRY, MappingProxyType)
    assert isinstance(INSTALLED_CONTROL_VALVE_METHOD_IMPLEMENTATIONS, MappingProxyType)
    assert INSTALLED_CONTROL_VALVE_METHOD_REGISTRY[key] is (
        INSTALLED_CONTROL_VALVE_SCREEN_ADAPTER
    )
    assert INSTALLED_CONTROL_VALVE_METHOD_IMPLEMENTATIONS[key] is (
        evaluate_installed_control_valve_scenarios
    )
    with pytest.raises(TypeError):
        INSTALLED_CONTROL_VALVE_METHOD_REGISTRY[key] = object()  # type: ignore[index]


def test_standards_discovery_entries_are_inert_and_nonconforming() -> None:
    assert INSTALLED_CONTROL_VALVE_DISCOVERY_ENTRIES == (
        IEC_60534_2_4_ADAPTER,
        IEC_60534_8_3_ADAPTER,
    )
    for adapter in INSTALLED_CONTROL_VALVE_DISCOVERY_ENTRIES:
        assert adapter.lifecycle_status is MethodLifecycleStatus.STANDARDS_REVIEW
        assert adapter.executable is False
        assert adapter.conformity_claimed is False
        assert adapter.official_catalog_url.startswith("https://webstore.iec.ch/")


def test_module_has_no_dynamic_execution_network_api_or_persistence_imports() -> None:
    tree = ast.parse(inspect.getsource(module))
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called_names.add(node.func.id)
    assert not imported_roots.intersection(
        {"requests", "httpx", "socket", "subprocess", "sqlalchemy", "fastapi"}
    )
    assert not called_names.intersection({"eval", "exec", "compile", "__import__"})


def test_module_exports_are_explicit_and_complete() -> None:
    expected = {
        "InstalledControlValveScreenRequest",
        "InstalledControlValveScreenResult",
        "TraceableInstalledValveCandidate",
        "evaluate_installed_control_valve_scenarios",
    }
    assert expected.issubset(set(module.__all__))
    assert len(module.__all__) == len(set(module.__all__))
    assert all(hasattr(module, name) for name in module.__all__)


def test_package_boundary_exports_both_step101_modules_by_identity() -> None:
    import app.engineering.calculations.control_valve_compressible as compressible

    for source in (compressible, module):
        for name in source.__all__:
            assert getattr(calculation_package, name) is getattr(source, name)
    assert len(calculation_package.__all__) == len(set(calculation_package.__all__))


def test_cumulative_control_valve_pack_registry_is_exact_and_immutable() -> None:
    expected_keys = {
        (
            "valve.control.liquid.cv-kv-sizing.supplied-factors",
            "1.0.0",
        ),
        (
            "valve.control.compressible.cv-kv-sizing.supplied-properties-factors",
            "1.0.0",
        ),
        (INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID, "1.0.0"),
    }
    assert calculation_package.CONTROL_VALVE_PACK_VERSION == "1.1.0"
    assert set(calculation_package.CONTROL_VALVE_PACK_METHOD_REGISTRY) == expected_keys
    assert set(calculation_package.CONTROL_VALVE_PACK_METHOD_IMPLEMENTATIONS) == (
        expected_keys
    )
    assert isinstance(
        calculation_package.CONTROL_VALVE_PACK_METHOD_REGISTRY,
        MappingProxyType,
    )
    assert len(calculation_package.CONTROL_VALVE_PACK_EXECUTABLE_ADAPTERS) == 3
    assert len(calculation_package.CONTROL_VALVE_PACK_DISCOVERY_ENTRIES) == 4


def test_step101_does_not_mutate_foundations_or_core_method_counts() -> None:
    assert calculation_package.PHASE_NUMBER == 7
    assert calculation_package.FOUNDATION_VERSION == "0.6.0"
    assert calculation_package.CONTROL_VALVE_CALCULATORS_VERSION == "1.0.0"
    assert len(calculation_package.ENGINEERING_METHOD_IDS) == 26
    assert len(DP_FLOW_METHOD_REGISTRY) == 7
