"""Phase 7 Step 104 generic pressure-relief required-area tests."""

from __future__ import annotations

import ast
import inspect
from math import exp, inf, log, nan, nextafter, pi, sqrt
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import ValidationError

from app.engineering import calculations
from app.engineering.calculations import pressure_relief as foundation
from app.engineering.calculations import pressure_relief_required_area as area
from app.engineering.calculations.models import (
    CalculationStatus,
    MethodLifecycleStatus,
)

EDITION_REFERENCE = "CONTROLLED-STANDARD-REGISTER-REV-F"
PROPERTY_REFERENCE = "PROCESS-DATASHEET-RELIEF-REV-E"
ATMOSPHERIC_PRESSURE_PA = 100_000.0


def flow_basis(
    required_mass_flow_kg_s: float = 5.0,
) -> foundation.PressureReliefFlowBasis:
    return foundation.PressureReliefFlowBasis(
        required_relieving_mass_flow_kg_s=required_mass_flow_kg_s,
        load_determination_reference="CALC-RELIEF-LOAD-104",
        load_determination_basis=(
            "Required mass flow is supplied by the separately reviewed "
            "overpressure scenario study."
        ),
        supplied_by="Process engineering",
    )


def scenario(
    *,
    scenario_id: str = "blocked-outlet-104",
    required_mass_flow_kg_s: float = 5.0,
    credible: bool = True,
) -> foundation.PressureReliefScenarioBasis:
    return foundation.PressureReliefScenarioBasis(
        scenario_id=scenario_id,
        scenario_kind=foundation.PressureReliefScenarioKind.BLOCKED_OUTLET,
        title="Documented Step 104 blocked-outlet case",
        protected_equipment_reference="V-104",
        scenario_description=(
            "The reviewed process study identifies a credible blocked outlet "
            "while feed continues at the documented relieving condition."
        ),
        credibility_confirmed=credible,
        credibility_basis_reference="HAZOP-REV-F-NODE-104" if credible else None,
        flow_basis=flow_basis(required_mass_flow_kg_s),
    )


def pressure_basis(
    *,
    relieving_pressure_pa: float = 1_000_000.0,
    backpressure_pa: float = 100_000.0,
    basis_kind: foundation.PressureReliefPressureBasisKind = (
        foundation.PressureReliefPressureBasisKind.ABSOLUTE
    ),
    atmosphere_pa: float | None = None,
) -> foundation.PressureReliefPressureBasis:
    return foundation.PressureReliefPressureBasis(
        basis_kind=basis_kind,
        set_pressure_pa=relieving_pressure_pa,
        maximum_allowable_working_pressure_pa=relieving_pressure_pa,
        relieving_pressure_pa=relieving_pressure_pa,
        total_backpressure_pa=backpressure_pa,
        atmospheric_pressure_absolute_pa=atmosphere_pa,
        pressure_source_reference="V-104-DESIGN-DATA-REV-F",
    )


def jurisdiction_basis() -> foundation.PressureReliefJurisdictionBasis:
    return foundation.PressureReliefJurisdictionBasis(
        jurisdiction_id="ZA-project-jurisdiction",
        authority_having_jurisdiction="Project pressure-equipment authority",
        applicable_design_code_reference="PROJECT-DESIGN-CODE-REV-F",
        standards_family=foundation.PressureReliefStandardsFamily.API_520_521,
        exact_edition_and_amendment_reference=EDITION_REFERENCE,
        jurisdiction_source_reference="PROJECT-CODE-BASIS-REV-F",
    )


def fluid_properties(
    phase: foundation.PressureReliefFluidPhase,
    **updates: object,
) -> foundation.PressureReliefFluidProperties:
    common: dict[str, object] = {
        "phase": phase,
        "relieving_temperature_k": 300.0,
        "property_source_reference": PROPERTY_REFERENCE,
        "condition_basis": (
            "Properties are evaluated at the documented relieving pressure "
            "and temperature."
        ),
    }
    if phase is foundation.PressureReliefFluidPhase.LIQUID:
        common["liquid_density_kg_m3"] = 1_000.0
    elif phase is foundation.PressureReliefFluidPhase.GAS_VAPOUR:
        common.update(
            gas_molar_mass_kg_kmol=28.0,
            compressibility_factor=1.0,
            isentropic_exponent=1.4,
        )
    else:
        common.update(
            steam_specific_volume_m3_kg=0.2,
            dry_or_superheated_steam_confirmed=True,
        )
    common.update(updates)
    return foundation.PressureReliefFluidProperties(**common)


def complete_request(
    phase: foundation.PressureReliefFluidPhase,
    *,
    relieving_pressure_pa: float = 1_000_000.0,
    backpressure_pa: float = 100_000.0,
    required_mass_flow_kg_s: float = 5.0,
    basis_kind: foundation.PressureReliefPressureBasisKind = (
        foundation.PressureReliefPressureBasisKind.ABSOLUTE
    ),
    atmosphere_pa: float | None = None,
    properties: foundation.PressureReliefFluidProperties | None = None,
) -> foundation.PressureReliefReadinessRequest:
    return foundation.PressureReliefReadinessRequest(
        request_id=f"step104-{phase.value}",
        scenarios=(scenario(required_mass_flow_kg_s=required_mass_flow_kg_s),),
        pressure_basis=pressure_basis(
            relieving_pressure_pa=relieving_pressure_pa,
            backpressure_pa=backpressure_pa,
            basis_kind=basis_kind,
            atmosphere_pa=atmosphere_pa,
        ),
        jurisdiction_basis=jurisdiction_basis(),
        fluid_properties=properties or fluid_properties(phase),
        selected_standards_pack_id=foundation.API_520_521_STANDARDS_PACK_ID,
        selected_standards_pack_version=(
            foundation.PRESSURE_RELIEF_STANDARDS_PACK_VERSION
        ),
        competency_requirement_acknowledged=True,
        proposed_reviewer_evidence_reference="REVIEW-ASSIGNMENT-PRV-104",
    )


def required_area_case(
    phase: foundation.PressureReliefFluidPhase,
    **request_kwargs: object,
) -> area.PressureReliefRequiredAreaCase:
    return area.PressureReliefRequiredAreaCase(
        readiness_request=complete_request(phase, **request_kwargs),
        scenario_id="blocked-outlet-104",
        method_basis_reference=EDITION_REFERENCE,
        application_basis=(
            "The generic equation was selected for this separately reviewed "
            "scenario within the stated Step 104 applicability boundary."
        ),
        supplied_by="Pressure-systems engineer",
        device_inlet_pressure_basis_confirmed=True,
        downstream_system_basis_confirmed=True,
    )


def coefficients(
    *,
    discharge_coefficient: float = 0.8,
    combined_correction_factor: float = 1.0,
    standards_basis_reference: str = EDITION_REFERENCE,
) -> area.TraceableReliefAreaCoefficients:
    return area.TraceableReliefAreaCoefficients(
        coefficient_set_id="coefficients.step104.reviewed",
        discharge_coefficient=discharge_coefficient,
        discharge_coefficient_source_reference="COEFF-CD-RECORD-REV-F",
        discharge_coefficient_role="capacity_discharge_coefficient",
        combined_correction_factor=combined_correction_factor,
        combined_correction_factor_source_reference="COEFF-K-RECORD-REV-F",
        combined_correction_factor_role="combined_correction_factor",
        standards_basis_reference=standards_basis_reference,
        applicable_conditions=(
            "The supplied coefficients apply to this fluid, pressure, "
            "temperature, backpressure, and installation basis."
        ),
        supplied_by="Pressure-systems engineer",
        all_required_corrections_included=True,
        double_counting_review_completed=True,
    )


def liquid_applicability(
    *,
    vapor_pressure_absolute_pa: float = 50_000.0,
) -> area.TraceableLiquidReliefApplicability:
    return area.TraceableLiquidReliefApplicability(
        vapor_pressure_absolute_pa=vapor_pressure_absolute_pa,
        vapor_pressure_source_reference="FLUID-PROPERTY-RECORD-REV-F",
        confirmation_reference="LIQUID-APPLICABILITY-REVIEW-REV-F",
        single_phase_incompressible_confirmed=True,
        nonflashing_noncavitating_confirmed=True,
        newtonian_or_calibrated_coefficient_confirmed=True,
    )


def gas_applicability() -> area.TraceableGasVapourReliefApplicability:
    return area.TraceableGasVapourReliefApplicability(
        confirmation_reference="GAS-APPLICABILITY-REVIEW-REV-F",
        single_phase_gas_vapour_confirmed=True,
        no_condensation_or_phase_transition_confirmed=True,
        isentropic_flow_model_confirmed=True,
        constant_k_and_upstream_z_approximation_accepted=True,
        property_variation_review_completed=True,
    )


def steam_flow(
    *,
    steam_mass_flux_coefficient: float = 0.75,
    critical_pressure_ratio: float = 0.55,
    steam_state: area.EligiblePressureReliefSteamState = (
        area.EligiblePressureReliefSteamState.DRY_SATURATED
    ),
    standards_basis_reference: str = EDITION_REFERENCE,
    specific_volume_basis_reference: str = PROPERTY_REFERENCE,
) -> area.TraceableSteamFlowCoefficient:
    return area.TraceableSteamFlowCoefficient(
        coefficient_id="steam.coefficient.step104",
        steam_mass_flux_coefficient=steam_mass_flux_coefficient,
        critical_pressure_ratio=critical_pressure_ratio,
        steam_state=steam_state,
        source_reference="STEAM-FLOW-BASIS-RECORD-REV-F",
        critical_pressure_ratio_source_reference="STEAM-CRITICAL-RATIO-REV-F",
        eligibility_source_reference="STEAM-ELIGIBILITY-REVIEW-REV-F",
        standards_basis_reference=standards_basis_reference,
        specific_volume_basis_reference=specific_volume_basis_reference,
        applicable_conditions=(
            "The supplied normalization applies to this eligible dry-steam "
            "state, pressure ratio, pressure, and specific-volume basis."
        ),
        supplied_by="Pressure-systems engineer",
        choked_flow_applicability_confirmed=True,
        no_entrained_liquid_confirmed=True,
        below_critical_pressure_confirmed=True,
        coefficient_normalization="G = C_s * sqrt(P1_abs / v1)",
    )


def liquid_input(**request_kwargs: object) -> area.LiquidPressureReliefRequiredAreaInput:
    return area.LiquidPressureReliefRequiredAreaInput(
        case=required_area_case(
            foundation.PressureReliefFluidPhase.LIQUID,
            **request_kwargs,
        ),
        coefficients=coefficients(),
        applicability=liquid_applicability(),
    )


def gas_input(**request_kwargs: object) -> area.GasVapourPressureReliefRequiredAreaInput:
    return area.GasVapourPressureReliefRequiredAreaInput(
        case=required_area_case(
            foundation.PressureReliefFluidPhase.GAS_VAPOUR,
            **request_kwargs,
        ),
        coefficients=coefficients(),
        applicability=gas_applicability(),
    )


def steam_input(**request_kwargs: object) -> area.EligibleSteamPressureReliefRequiredAreaInput:
    return area.EligibleSteamPressureReliefRequiredAreaInput(
        case=required_area_case(
            foundation.PressureReliefFluidPhase.STEAM,
            **request_kwargs,
        ),
        coefficients=coefficients(),
        steam_flow=steam_flow(),
    )


def replace_nested_model(model: Any, field_name: str, value: object) -> Any:
    values = model.model_dump(mode="python", round_trip=True)
    values[field_name] = value
    return type(model).model_validate(values)


def recompute_result_fingerprint(values: dict[str, object]) -> None:
    values["result_fingerprint"] = foundation.fingerprint_pressure_relief_readiness(
        area.build_pressure_relief_required_area_result_fingerprint_payload(values)
    )


def test_exact_versions_and_method_ids() -> None:
    assert area.PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION == "1.0.0"
    assert area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION == "1.0.0"
    assert area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID == (
        "pressure-relief.liquid.required-area.supplied-factors"
    )
    assert area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID == (
        "pressure-relief.gas-vapour.required-area.supplied-factors"
    )
    assert area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID == (
        "pressure-relief.eligible-steam.required-area.supplied-factors"
    )


def test_step103_gate_and_execution_registries_remain_inert() -> None:
    assert foundation.PRESSURE_RELIEF_EXECUTABLE_ADAPTERS == ()
    assert dict(foundation.PRESSURE_RELIEF_METHOD_REGISTRY) == {}
    assert dict(foundation.PRESSURE_RELIEF_METHOD_IMPLEMENTATIONS) == {}
    for entry in foundation.PRESSURE_RELIEF_DISCOVERY_ENTRIES:
        assert entry.lifecycle_status is MethodLifecycleStatus.STANDARDS_REVIEW
        assert entry.executable is False
        assert entry.conformity_claimed is False


@pytest.mark.parametrize(
    "phase",
    tuple(foundation.PressureReliefFluidPhase),
)
def test_step103_complete_request_still_has_only_unapproved_method_block(
    phase: foundation.PressureReliefFluidPhase,
) -> None:
    gate = foundation.assess_pressure_relief_readiness(complete_request(phase))
    assert tuple(finding.finding_id for finding in gate.blocking_findings) == (
        foundation.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,
    )
    assert gate.calculation_performed is False
    assert gate.ready_for_sizing is False


def test_liquid_independent_reference_vector() -> None:
    result = area.calculate_liquid_pressure_relief_required_area(
        liquid_input(
            relieving_pressure_pa=1_100_000.0,
            required_mass_flow_kg_s=10.0,
        )
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        44_721.35954999579,
        rel=1e-14,
    )
    assert result.required_area_m2 == pytest.approx(
        0.0002795084971874737,
        rel=1e-14,
    )
    assert result.required_area_mm2 == pytest.approx(
        279.5084971874737,
        rel=1e-14,
    )
    assert result.equivalent_circular_diameter_m == pytest.approx(
        0.01886481570831235,
        rel=1e-14,
    )


def test_choked_gas_independent_reference_vector() -> None:
    result = area.calculate_gas_vapour_pressure_relief_required_area(gas_input())
    assert result.critical_pressure_ratio == pytest.approx(
        0.5282817877171741,
        rel=1e-14,
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        2_294.148759701686,
        rel=1e-14,
    )
    assert result.required_area_m2 == pytest.approx(
        0.002724322027318187,
        rel=1e-14,
    )
    assert result.equivalent_circular_diameter_m == pytest.approx(
        0.05889579388865205,
        rel=1e-14,
    )
    assert result.flow_regime is area.PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_CHOKED


def test_subcritical_gas_independent_reference_vector() -> None:
    result = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=800_000.0)
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        1_878.458729789441,
        rel=1e-14,
    )
    assert result.required_area_m2 == pytest.approx(
        0.003327195802007623,
        rel=1e-14,
    )
    assert result.equivalent_circular_diameter_m == pytest.approx(
        0.06508699768919235,
        rel=1e-14,
    )
    assert result.flow_regime is (
        area.PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL
    )


def test_steam_independent_reference_vector() -> None:
    result = area.calculate_eligible_steam_pressure_relief_required_area(
        steam_input()
    )
    assert result.base_mass_flux_kg_m2_s == pytest.approx(
        2_236.067977499790,
        rel=1e-14,
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        1_677.050983124842,
        rel=1e-14,
    )
    assert result.required_area_m2 == pytest.approx(
        0.003726779962499649,
        rel=1e-14,
    )
    assert result.equivalent_circular_diameter_m == pytest.approx(
        0.06888456737746983,
        rel=1e-14,
    )


@pytest.mark.parametrize(
    ("builder", "calculator", "method_id", "result_type"),
    (
        (
            liquid_input,
            area.calculate_liquid_pressure_relief_required_area,
            area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            area.LiquidPressureReliefRequiredAreaResult,
        ),
        (
            gas_input,
            area.calculate_gas_vapour_pressure_relief_required_area,
            area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            area.GasVapourPressureReliefRequiredAreaResult,
        ),
        (
            steam_input,
            area.calculate_eligible_steam_pressure_relief_required_area,
            area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            area.EligibleSteamPressureReliefRequiredAreaResult,
        ),
    ),
)
def test_complete_results_are_preliminary_and_never_select_devices(
    builder: Any,
    calculator: Any,
    method_id: str,
    result_type: type[Any],
) -> None:
    result = calculator(builder())
    assert isinstance(result, result_type)
    assert result.method_id == method_id
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert result.calculation_performed is True
    assert result.ready_for_device_selection is False
    assert result.device_selected is False
    assert result.manufacturer_selection_performed is False
    assert result.standards_conformity_claimed is False
    assert result.preliminary_engineering_decision_support is True
    assert result.independent_review_required is True
    assert result.warnings
    assert result.exclusions
    assert result.authorization.replaced_finding_id == (
        foundation.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID
    )


@pytest.mark.parametrize(
    ("builder", "calculator", "method_id"),
    (
        (
            liquid_input,
            area.calculate_liquid_pressure_relief_required_area,
            area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        ),
        (
            gas_input,
            area.calculate_gas_vapour_pressure_relief_required_area,
            area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        ),
        (
            steam_input,
            area.calculate_eligible_steam_pressure_relief_required_area,
            area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        ),
    ),
)
def test_exact_dispatch_matches_direct_execution(
    builder: Any,
    calculator: Any,
    method_id: str,
) -> None:
    sizing_input = builder()
    direct = calculator(sizing_input)
    dispatched = area.execute_pressure_relief_required_area(
        method_id=method_id,
        method_version="1.0.0",
        sizing_input=sizing_input,
    )
    assert dispatched == direct


@pytest.mark.parametrize(
    ("method_id", "method_version"),
    (
        ("pressure-relief.unknown", "1.0.0"),
        (area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "1.0.1"),
        (area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "0.9.0"),
        (f" {area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID}", "1.0.0"),
        (area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "1.0.0 "),
        ("", "1.0.0"),
    ),
)
def test_dispatch_fails_closed_for_nonexact_identity(
    method_id: str,
    method_version: str,
) -> None:
    with pytest.raises((area.PressureReliefRequiredAreaInputError, ValueError)):
        area.execute_pressure_relief_required_area(
            method_id=method_id,
            method_version=method_version,
            sizing_input=liquid_input(),
        )


@pytest.mark.parametrize(
    ("method_id", "wrong_input"),
    (
        (area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, gas_input()),
        (area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, steam_input()),
        (area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, liquid_input()),
    ),
)
def test_dispatch_rejects_input_model_for_another_method(
    method_id: str,
    wrong_input: Any,
) -> None:
    with pytest.raises(area.PressureReliefRequiredAreaInputError):
        area.execute_pressure_relief_required_area(
            method_id=method_id,
            method_version="1.0.0",
            sizing_input=wrong_input,
        )


def test_registry_is_exact_bound_and_immutable() -> None:
    expected_keys = (
        (area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "1.0.0"),
        (area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "1.0.0"),
        (area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID, "1.0.0"),
    )
    assert isinstance(area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY, MappingProxyType)
    assert isinstance(
        area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS,
        MappingProxyType,
    )
    assert tuple(area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY) == expected_keys
    assert tuple(area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS) == expected_keys
    assert len(area.PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS) == 3
    assert calculations.PRESSURE_RELIEF_PACK_VERSION == "1.1.0"
    assert tuple(calculations.PRESSURE_RELIEF_PACK_METHOD_REGISTRY) == expected_keys
    assert tuple(calculations.PRESSURE_RELIEF_PACK_METHOD_IMPLEMENTATIONS) == (
        expected_keys
    )
    assert calculations.PRESSURE_RELIEF_PACK_EXECUTABLE_ADAPTERS == (
        area.PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS
    )
    assert calculations.PRESSURE_RELIEF_PACK_DISCOVERY_ENTRIES == (
        foundation.PRESSURE_RELIEF_DISCOVERY_ENTRIES
    )
    assert set(area.__all__).issubset(set(calculations.__all__))
    assert all(
        getattr(calculations, name) is getattr(area, name)
        for name in area.__all__
    )
    assert len(calculations.ENGINEERING_METHOD_IDS) == 26
    assert len(calculations.DP_FLOW_METHOD_REGISTRY) == 7
    assert len(calculations.CONTROL_VALVE_PACK_METHOD_REGISTRY) == 3
    for key, metadata in area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY.items():
        implementation = area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS[key]
        assert metadata.lifecycle_status is MethodLifecycleStatus.APPROVED
        assert metadata.executable is True
        assert metadata.standards_conformity_claimed is False
        assert metadata.preliminary_only is True
        assert metadata.independent_review_required is True
        assert metadata.implementation_name == implementation.__name__
        assert all(url.startswith("https://") for url in metadata.public_equation_basis_urls)
    with pytest.raises(TypeError):
        area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY[expected_keys[0]] = object()  # type: ignore[index]


@pytest.mark.parametrize(
    "field_name",
    ("discharge_coefficient", "combined_correction_factor"),
)
def test_capacity_coefficients_reject_invalid_values(
    field_name: str,
) -> None:
    for value in (True, "0.8", nan, inf, -inf, 0.0, -0.1, 1.0000001):
        values = coefficients().model_dump(mode="python", round_trip=True)
        values[field_name] = value
        with pytest.raises((ValidationError, TypeError)):
            area.TraceableReliefAreaCoefficients(**values)


def test_every_capacity_coefficient_field_is_mandatory() -> None:
    for field_name in (
        "coefficient_set_id",
        "discharge_coefficient",
        "discharge_coefficient_source_reference",
        "discharge_coefficient_role",
        "combined_correction_factor",
        "combined_correction_factor_source_reference",
        "combined_correction_factor_role",
        "standards_basis_reference",
        "applicable_conditions",
        "supplied_by",
        "all_required_corrections_included",
        "double_counting_review_completed",
    ):
        values = coefficients().model_dump(mode="python", round_trip=True)
        del values[field_name]
        with pytest.raises(ValidationError):
            area.TraceableReliefAreaCoefficients(**values)


@pytest.mark.parametrize(
    "field_name",
    (
        "coefficient_set_id",
        "discharge_coefficient_source_reference",
        "combined_correction_factor_source_reference",
        "standards_basis_reference",
        "applicable_conditions",
        "supplied_by",
    ),
)
def test_capacity_coefficient_provenance_rejects_whitespace(field_name: str) -> None:
    values = coefficients().model_dump(mode="python", round_trip=True)
    values[field_name] = f" {values[field_name]}"
    with pytest.raises(ValidationError):
        area.TraceableReliefAreaCoefficients(**values)


@pytest.mark.parametrize(
    "field_name",
    ("all_required_corrections_included", "double_counting_review_completed"),
)
def test_capacity_coefficient_confirmations_must_be_explicit_true(
    field_name: str,
) -> None:
    for invalid_value in (False, 1, "true"):
        values = coefficients().model_dump(mode="python", round_trip=True)
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            area.TraceableReliefAreaCoefficients(**values)


@pytest.mark.parametrize(
    "field_name",
    (
        "single_phase_incompressible_confirmed",
        "nonflashing_noncavitating_confirmed",
        "newtonian_or_calibrated_coefficient_confirmed",
    ),
)
def test_liquid_applicability_confirmations_are_mandatory_true(
    field_name: str,
) -> None:
    for invalid_value in (False, 1, "true"):
        values = liquid_applicability().model_dump(mode="python", round_trip=True)
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            area.TraceableLiquidReliefApplicability(**values)


@pytest.mark.parametrize(
    "field_name",
    (
        "single_phase_gas_vapour_confirmed",
        "no_condensation_or_phase_transition_confirmed",
        "isentropic_flow_model_confirmed",
        "constant_k_and_upstream_z_approximation_accepted",
        "property_variation_review_completed",
    ),
)
def test_gas_applicability_confirmations_are_mandatory_true(field_name: str) -> None:
    for invalid_value in (False, 1, "true"):
        values = gas_applicability().model_dump(mode="python", round_trip=True)
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            area.TraceableGasVapourReliefApplicability(**values)


@pytest.mark.parametrize(
    "field_name",
    (
        "choked_flow_applicability_confirmed",
        "no_entrained_liquid_confirmed",
        "below_critical_pressure_confirmed",
    ),
)
def test_steam_applicability_confirmations_are_mandatory_true(field_name: str) -> None:
    for invalid_value in (False, 1, "true"):
        values = steam_flow().model_dump(mode="python", round_trip=True)
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            area.TraceableSteamFlowCoefficient(**values)


@pytest.mark.parametrize(
    "field_name",
    ("steam_mass_flux_coefficient", "critical_pressure_ratio"),
)
def test_steam_coefficients_reject_invalid_values(
    field_name: str,
) -> None:
    invalid_values = {
        "steam_mass_flux_coefficient": (
            True,
            "0.75",
            nan,
            inf,
            0.0,
            -0.1,
            1.000001,
        ),
        "critical_pressure_ratio": (
            True,
            "0.55",
            nan,
            inf,
            0.0,
            -0.1,
            1.0,
            1.1,
        ),
    }
    for value in invalid_values[field_name]:
        values = steam_flow().model_dump(mode="python", round_trip=True)
        values[field_name] = value
        with pytest.raises((ValidationError, TypeError)):
            area.TraceableSteamFlowCoefficient(**values)


@pytest.mark.parametrize(
    "field_name",
    ("device_inlet_pressure_basis_confirmed", "downstream_system_basis_confirmed"),
)
def test_case_pressure_basis_confirmations_are_mandatory_true(field_name: str) -> None:
    for invalid_value in (False, 1, "true"):
        values = required_area_case(
            foundation.PressureReliefFluidPhase.LIQUID
        ).model_dump(mode="python", round_trip=True)
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            area.PressureReliefRequiredAreaCase(**values)


@pytest.mark.parametrize(
    ("calculator", "sizing_input"),
    (
        (area.calculate_liquid_pressure_relief_required_area, gas_input()),
        (area.calculate_liquid_pressure_relief_required_area, steam_input()),
        (area.calculate_gas_vapour_pressure_relief_required_area, liquid_input()),
        (area.calculate_gas_vapour_pressure_relief_required_area, steam_input()),
        (area.calculate_eligible_steam_pressure_relief_required_area, liquid_input()),
        (area.calculate_eligible_steam_pressure_relief_required_area, gas_input()),
    ),
)
def test_each_calculator_rejects_another_phase_input(
    calculator: Any,
    sizing_input: Any,
) -> None:
    with pytest.raises(area.PressureReliefRequiredAreaInputError):
        calculator(sizing_input)


@pytest.mark.parametrize(
    ("phase", "builder", "calculator"),
    (
        (
            foundation.PressureReliefFluidPhase.LIQUID,
            liquid_input,
            area.calculate_liquid_pressure_relief_required_area,
        ),
        (
            foundation.PressureReliefFluidPhase.GAS_VAPOUR,
            gas_input,
            area.calculate_gas_vapour_pressure_relief_required_area,
        ),
        (
            foundation.PressureReliefFluidPhase.STEAM,
            steam_input,
            area.calculate_eligible_steam_pressure_relief_required_area,
        ),
    ),
)
def test_any_remaining_step103_block_prevents_arithmetic(
    phase: foundation.PressureReliefFluidPhase,
    builder: Any,
    calculator: Any,
) -> None:
    sizing_input = builder()
    request = sizing_input.case.readiness_request.model_copy(
        update={
            "competency_requirement_acknowledged": False,
            "proposed_reviewer_evidence_reference": None,
        }
    )
    case = sizing_input.case.model_copy(update={"readiness_request": request})
    blocked_input = sizing_input.model_copy(update={"case": case})
    with pytest.raises(area.PressureReliefRequiredAreaBlockedError) as captured:
        calculator(blocked_input)
    finding_ids = tuple(
        finding.finding_id
        for finding in captured.value.gate_result.blocking_findings
    )
    assert foundation.PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID in finding_ids


def test_scenario_selection_must_resolve_exactly() -> None:
    sizing_input = liquid_input()
    case = sizing_input.case.model_copy(update={"scenario_id": "missing-scenario"})
    with pytest.raises(
        area.PressureReliefRequiredAreaInputError,
        match="resolve exactly once",
    ):
        area.calculate_liquid_pressure_relief_required_area(
            sizing_input.model_copy(update={"case": case})
        )


@pytest.mark.parametrize(
    ("location", "wrong_reference"),
    (
        ("method", "WRONG-METHOD-EDITION"),
        ("coefficient", "WRONG-COEFFICIENT-EDITION"),
    ),
)
def test_liquid_execution_rejects_edition_provenance_mismatch(
    location: str,
    wrong_reference: str,
) -> None:
    sizing_input = liquid_input()
    if location == "method":
        case = sizing_input.case.model_copy(
            update={"method_basis_reference": wrong_reference}
        )
        sizing_input = sizing_input.model_copy(update={"case": case})
    else:
        sizing_input = sizing_input.model_copy(
            update={
                "coefficients": coefficients(
                    standards_basis_reference=wrong_reference
                )
            }
        )
    with pytest.raises(area.PressureReliefRequiredAreaInputError, match="basis"):
        area.calculate_liquid_pressure_relief_required_area(sizing_input)


@pytest.mark.parametrize("vapor_pressure_pa", (100_000.0, 100_001.0, 900_000.0))
def test_liquid_blocks_flashing_or_cavitation_boundary(
    vapor_pressure_pa: float,
) -> None:
    sizing_input = liquid_input().model_copy(
        update={
            "applicability": liquid_applicability(
                vapor_pressure_absolute_pa=vapor_pressure_pa
            )
        }
    )
    with pytest.raises(
        area.PressureReliefRequiredAreaInputError,
        match="vapor pressure",
    ):
        area.calculate_liquid_pressure_relief_required_area(sizing_input)


@pytest.mark.parametrize(
    "steam_state",
    (
        area.EligiblePressureReliefSteamState.DRY_SATURATED,
        area.EligiblePressureReliefSteamState.SUPERHEATED,
    ),
)
def test_both_explicitly_eligible_steam_states_are_supported(
    steam_state: area.EligiblePressureReliefSteamState,
) -> None:
    sizing_input = steam_input().model_copy(
        update={"steam_flow": steam_flow(steam_state=steam_state)}
    )
    result = area.calculate_eligible_steam_pressure_relief_required_area(sizing_input)
    assert result.steam_state is steam_state


@pytest.mark.parametrize(
    ("update", "match"),
    (
        ({"standards_basis_reference": "WRONG-STEAM-EDITION"}, "jurisdiction"),
        ({"specific_volume_basis_reference": "WRONG-PROPERTY-SOURCE"}, "specific-volume"),
    ),
)
def test_steam_rejects_provenance_mismatch(
    update: dict[str, object],
    match: str,
) -> None:
    values = steam_flow().model_dump(mode="python", round_trip=True)
    values.update(update)
    sizing_input = steam_input().model_copy(
        update={"steam_flow": area.TraceableSteamFlowCoefficient(**values)}
    )
    with pytest.raises(area.PressureReliefRequiredAreaInputError, match=match):
        area.calculate_eligible_steam_pressure_relief_required_area(sizing_input)


def test_steam_rejects_subcritical_pressure_ratio() -> None:
    with pytest.raises(
        area.PressureReliefRequiredAreaInputError,
        match="subcritical steam",
    ):
        area.calculate_eligible_steam_pressure_relief_required_area(
            steam_input(backpressure_pa=550_000.0000001)
        )


def test_steam_accepts_exact_supplied_critical_ratio() -> None:
    result = area.calculate_eligible_steam_pressure_relief_required_area(
        steam_input(backpressure_pa=550_000.0)
    )
    assert result.downstream_to_upstream_pressure_ratio == pytest.approx(0.55)


def test_steam_rejects_water_critical_pressure_boundary() -> None:
    with pytest.raises(
        area.PressureReliefRequiredAreaInputError,
        match="supercritical-water",
    ):
        area.calculate_eligible_steam_pressure_relief_required_area(
            steam_input(
                relieving_pressure_pa=area.WATER_CRITICAL_PRESSURE_PA,
                backpressure_pa=1_000_000.0,
            )
        )


@pytest.mark.parametrize(
    ("builder", "calculator"),
    (
        (liquid_input, area.calculate_liquid_pressure_relief_required_area),
        (gas_input, area.calculate_gas_vapour_pressure_relief_required_area),
        (steam_input, area.calculate_eligible_steam_pressure_relief_required_area),
    ),
)
def test_gauge_and_absolute_pressure_bases_are_equivalent(
    builder: Any,
    calculator: Any,
) -> None:
    absolute = builder(
        relieving_pressure_pa=1_000_000.0,
        backpressure_pa=200_000.0,
    )
    gauge = builder(
        relieving_pressure_pa=900_000.0,
        backpressure_pa=100_000.0,
        basis_kind=(
            foundation.PressureReliefPressureBasisKind.GAUGE_WITH_ATMOSPHERIC_REFERENCE
        ),
        atmosphere_pa=ATMOSPHERIC_PRESSURE_PA,
    )
    absolute_result = calculator(absolute)
    gauge_result = calculator(gauge)
    assert gauge_result.required_area_m2 == pytest.approx(
        absolute_result.required_area_m2,
        rel=1e-14,
    )
    assert gauge_result.pressure_state.relieving_pressure_absolute_pa == 1_000_000.0
    assert gauge_result.pressure_state.backpressure_absolute_pa == 200_000.0
    assert gauge_result.pressure_state.atmospheric_pressure_absolute_pa_used == (
        ATMOSPHERIC_PRESSURE_PA
    )


def test_gas_exact_critical_ratio_uses_choked_branch() -> None:
    critical_ratio = exp((1.4 / 0.4) * log(2.0 / 2.4))
    result = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=critical_ratio * 1_000_000.0)
    )
    assert result.flow_regime is (
        area.PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_CHOKED
    )


def test_gas_next_float_above_critical_ratio_uses_subcritical_branch() -> None:
    critical_ratio = exp((1.4 / 0.4) * log(2.0 / 2.4))
    above = nextafter(critical_ratio, 1.0)
    result = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=above * 1_000_000.0)
    )
    assert result.flow_regime is (
        area.PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL
    )


def test_gas_branches_are_continuous_at_critical_ratio() -> None:
    critical_ratio = exp((1.4 / 0.4) * log(2.0 / 2.4))
    at_boundary = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=critical_ratio * 1_000_000.0)
    )
    just_above = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=nextafter(critical_ratio, 1.0) * 1_000_000.0)
    )
    assert just_above.theoretical_mass_flux_kg_m2_s == pytest.approx(
        at_boundary.theoretical_mass_flux_kg_m2_s,
        rel=2e-14,
    )


def test_gas_near_unity_pressure_ratio_remains_finite() -> None:
    result = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=999_999.999)
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        0.1498360402205289,
        rel=1e-7,
    )
    assert result.required_area_m2 == pytest.approx(
        41.71226088730882,
        rel=1e-7,
    )


def test_gas_k_near_one_remains_stable() -> None:
    properties = fluid_properties(
        foundation.PressureReliefFluidPhase.GAS_VAPOUR,
        isentropic_exponent=1.000001,
    )
    result = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=800_000.0, properties=properties)
    )
    assert result.theoretical_mass_flux_kg_m2_s == pytest.approx(
        1_790.599766684042,
        rel=2e-10,
    )
    assert result.required_area_m2 == pytest.approx(
        0.003490450583255792,
        rel=2e-10,
    )


def test_choked_gas_area_is_independent_of_lower_backpressure() -> None:
    low = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=100_000.0)
    )
    higher = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(backpressure_pa=400_000.0)
    )
    assert higher.required_area_m2 == pytest.approx(low.required_area_m2, rel=1e-15)
    assert higher.input_fingerprint != low.input_fingerprint
    assert higher.result_fingerprint != low.result_fingerprint


@pytest.mark.parametrize(
    ("builder", "calculator"),
    (
        (liquid_input, area.calculate_liquid_pressure_relief_required_area),
        (gas_input, area.calculate_gas_vapour_pressure_relief_required_area),
        (steam_input, area.calculate_eligible_steam_pressure_relief_required_area),
    ),
)
def test_required_area_scales_linearly_with_required_mass_flow(
    builder: Any,
    calculator: Any,
) -> None:
    base = calculator(builder(required_mass_flow_kg_s=5.0))
    doubled = calculator(builder(required_mass_flow_kg_s=10.0))
    assert doubled.required_area_m2 == pytest.approx(2.0 * base.required_area_m2)


@pytest.mark.parametrize(
    ("builder", "calculator"),
    (
        (liquid_input, area.calculate_liquid_pressure_relief_required_area),
        (gas_input, area.calculate_gas_vapour_pressure_relief_required_area),
        (steam_input, area.calculate_eligible_steam_pressure_relief_required_area),
    ),
)
def test_required_area_is_inverse_to_supplied_capacity_product(
    builder: Any,
    calculator: Any,
) -> None:
    base_input = builder()
    base = calculator(base_input)
    reduced = calculator(
        base_input.model_copy(
            update={
                "coefficients": coefficients(
                    discharge_coefficient=0.4,
                    combined_correction_factor=1.0,
                )
            }
        )
    )
    assert reduced.required_area_m2 == pytest.approx(2.0 * base.required_area_m2)


def test_liquid_area_has_expected_density_and_pressure_scaling() -> None:
    base = area.calculate_liquid_pressure_relief_required_area(liquid_input())
    dense_properties = fluid_properties(
        foundation.PressureReliefFluidPhase.LIQUID,
        liquid_density_kg_m3=4_000.0,
    )
    dense = area.calculate_liquid_pressure_relief_required_area(
        liquid_input(properties=dense_properties)
    )
    greater_delta = area.calculate_liquid_pressure_relief_required_area(
        liquid_input(
            relieving_pressure_pa=3_700_000.0,
            backpressure_pa=100_000.0,
        )
    )
    assert dense.required_area_m2 == pytest.approx(base.required_area_m2 / 2.0)
    assert greater_delta.required_area_m2 == pytest.approx(
        base.required_area_m2 / 2.0
    )


@pytest.mark.parametrize(
    ("property_update", "expected_factor"),
    (
        ({"relieving_temperature_k": 1_200.0}, 2.0),
        ({"compressibility_factor": 4.0}, 2.0),
        ({"gas_molar_mass_kg_kmol": 112.0}, 0.5),
    ),
)
def test_choked_gas_property_scaling(
    property_update: dict[str, object],
    expected_factor: float,
) -> None:
    base = area.calculate_gas_vapour_pressure_relief_required_area(gas_input())
    properties = fluid_properties(
        foundation.PressureReliefFluidPhase.GAS_VAPOUR,
        **property_update,
    )
    changed = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(properties=properties)
    )
    assert changed.required_area_m2 == pytest.approx(
        expected_factor * base.required_area_m2
    )


def test_gas_equal_ratio_pressure_scaling() -> None:
    base = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(relieving_pressure_pa=1_000_000.0, backpressure_pa=800_000.0)
    )
    doubled = area.calculate_gas_vapour_pressure_relief_required_area(
        gas_input(relieving_pressure_pa=2_000_000.0, backpressure_pa=1_600_000.0)
    )
    assert doubled.required_area_m2 == pytest.approx(base.required_area_m2 / 2.0)


def test_steam_specific_volume_scaling() -> None:
    base = area.calculate_eligible_steam_pressure_relief_required_area(steam_input())
    properties = fluid_properties(
        foundation.PressureReliefFluidPhase.STEAM,
        steam_specific_volume_m3_kg=0.8,
    )
    changed = area.calculate_eligible_steam_pressure_relief_required_area(
        steam_input(properties=properties).model_copy(
            update={
                "steam_flow": steam_flow(
                    specific_volume_basis_reference=PROPERTY_REFERENCE
                )
            }
        )
    )
    assert changed.required_area_m2 == pytest.approx(2.0 * base.required_area_m2)


@pytest.mark.parametrize(
    ("builder", "calculator", "result_type"),
    (
        (
            liquid_input,
            area.calculate_liquid_pressure_relief_required_area,
            area.LiquidPressureReliefRequiredAreaResult,
        ),
        (
            gas_input,
            area.calculate_gas_vapour_pressure_relief_required_area,
            area.GasVapourPressureReliefRequiredAreaResult,
        ),
        (
            steam_input,
            area.calculate_eligible_steam_pressure_relief_required_area,
            area.EligibleSteamPressureReliefRequiredAreaResult,
        ),
    ),
)
def test_results_are_deterministic_round_trippable_and_self_validating(
    builder: Any,
    calculator: Any,
    result_type: type[Any],
) -> None:
    first = calculator(builder())
    second = calculator(builder())
    assert first == second
    assert first.input_fingerprint == second.input_fingerprint
    assert first.result_fingerprint == second.result_fingerprint
    assert first.input_fingerprint != first.result_fingerprint
    assert first.reconstructed_mass_flow_kg_s == pytest.approx(
        first.required_relieving_mass_flow_kg_s,
        rel=1e-15,
    )
    assert first.relative_round_trip_residual <= 1e-12
    assert first.required_area_mm2 == pytest.approx(first.required_area_m2 * 1e6)
    assert first.equivalent_circular_diameter_m == pytest.approx(
        sqrt(4.0 * first.required_area_m2 / pi)
    )
    assert result_type.model_validate(
        first.model_dump(mode="python", round_trip=True)
    ) == first


@pytest.mark.parametrize(
    "field_name",
    (
        "required_area_m2",
        "required_area_mm2",
        "equivalent_circular_diameter_m",
        "corrected_mass_flux_kg_m2_s",
        "reconstructed_mass_flow_kg_s",
        "relative_round_trip_residual",
    ),
)
def test_result_rejects_common_arithmetic_tampering_even_with_new_fingerprint(
    field_name: str,
) -> None:
    result = area.calculate_liquid_pressure_relief_required_area(liquid_input())
    values = result.model_dump(mode="python", round_trip=True)
    values[field_name] = float(values[field_name]) * 1.01 + 1e-12
    recompute_result_fingerprint(values)
    with pytest.raises(ValidationError):
        area.LiquidPressureReliefRequiredAreaResult.model_validate(values)

    if field_name == "required_area_m2":
        coherent_forgery = result.model_dump(mode="python", round_trip=True)
        coherent_forgery["required_relieving_mass_flow_kg_s"] *= 2.0
        coherent_forgery["required_area_m2"] *= 2.0
        coherent_forgery["required_area_mm2"] *= 2.0
        coherent_forgery["equivalent_circular_diameter_m"] *= sqrt(2.0)
        coherent_forgery["reconstructed_mass_flow_kg_s"] *= 2.0
        recompute_result_fingerprint(coherent_forgery)
        with pytest.raises(ValidationError, match="relieving flow"):
            area.LiquidPressureReliefRequiredAreaResult.model_validate(
                coherent_forgery
            )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("downstream_to_upstream_pressure_ratio", 0.2),
        ("critical_pressure_ratio", 0.2),
        (
            "flow_regime",
            area.PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL,
        ),
    ),
)
def test_gas_result_rejects_branch_tampering_even_with_new_fingerprint(
    field_name: str,
    replacement: object,
) -> None:
    result = area.calculate_gas_vapour_pressure_relief_required_area(gas_input())
    values = result.model_dump(mode="python", round_trip=True)
    values[field_name] = replacement
    recompute_result_fingerprint(values)
    with pytest.raises(ValidationError):
        area.GasVapourPressureReliefRequiredAreaResult.model_validate(values)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("base_mass_flux_kg_m2_s", 100.0),
        ("theoretical_mass_flux_kg_m2_s", 100.0),
        ("downstream_to_upstream_pressure_ratio", 0.9),
    ),
)
def test_steam_result_rejects_equation_tampering_even_with_new_fingerprint(
    field_name: str,
    replacement: float,
) -> None:
    result = area.calculate_eligible_steam_pressure_relief_required_area(steam_input())
    values = result.model_dump(mode="python", round_trip=True)
    values[field_name] = replacement
    recompute_result_fingerprint(values)
    with pytest.raises(ValidationError):
        area.EligibleSteamPressureReliefRequiredAreaResult.model_validate(values)


def test_authorization_cannot_replace_any_other_readiness_finding() -> None:
    result = area.calculate_liquid_pressure_relief_required_area(liquid_input())
    authorization = result.authorization.model_dump(mode="python", round_trip=True)
    incomplete_gate = foundation.assess_pressure_relief_readiness(
        foundation.PressureReliefReadinessRequest(request_id="incomplete-104")
    )
    authorization["readiness_gate_result"] = incomplete_gate
    authorization["readiness_request_fingerprint"] = incomplete_gate.request_fingerprint
    with pytest.raises(ValidationError, match="exact placeholder"):
        area.PressureReliefRequiredAreaAuthorization(**authorization)

    authorization = result.authorization.model_dump(mode="python", round_trip=True)
    authorization["method_id"] = "pressure-relief.unregistered.required-area"
    with pytest.raises(ValidationError):
        area.PressureReliefRequiredAreaAuthorization(**authorization)


def test_input_fingerprint_changes_when_traceable_input_changes() -> None:
    first_input = liquid_input()
    second_input = first_input.model_copy(
        update={
            "coefficients": coefficients(
                discharge_coefficient=0.79,
                combined_correction_factor=1.0,
            )
        }
    )
    first = area.calculate_liquid_pressure_relief_required_area(first_input)
    second = area.calculate_liquid_pressure_relief_required_area(second_input)
    assert first.input_fingerprint != second.input_fingerprint
    assert first.result_fingerprint != second.result_fingerprint


@pytest.mark.parametrize(
    "invalid_value",
    (None, 1, 1.0, True, ()),
)
def test_fingerprint_helpers_reject_unsupported_top_level_values(
    invalid_value: object,
) -> None:
    with pytest.raises(area.PressureReliefRequiredAreaInputError):
        area.build_pressure_relief_required_area_input_fingerprint_payload(
            invalid_value  # type: ignore[arg-type]
        )
    with pytest.raises(area.PressureReliefRequiredAreaInputError):
        area.build_pressure_relief_required_area_result_fingerprint_payload(
            invalid_value  # type: ignore[arg-type]
        )


def test_result_fingerprint_payload_excludes_only_its_self_hash() -> None:
    result = area.calculate_liquid_pressure_relief_required_area(liquid_input())
    payload = area.build_pressure_relief_required_area_result_fingerprint_payload(
        result
    )
    public_fields = set(type(result).model_fields)
    result_fields = set(payload["result"])
    assert result_fields == public_fields - {"result_fingerprint"}
    assert payload["calculator_version"] == "1.0.0"


def test_required_area_module_has_no_io_framework_or_persistence_imports() -> None:
    source = inspect.getsource(area)
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert imported_roots.isdisjoint(
        {
            "fastapi",
            "sqlalchemy",
            "requests",
            "httpx",
            "subprocess",
            "socket",
            "pathlib",
        }
    )


def test_public_module_does_not_expose_selection_or_conformity_operations() -> None:
    prohibited_public_fragments = (
        "select_device",
        "select_manufacturer",
        "select_orifice",
        "certify_capacity",
        "claim_conformity",
    )
    assert not any(
        fragment in name
        for name in area.__all__
        for fragment in prohibited_public_fragments
    )


def test_coefficient_fields_have_no_silent_numeric_defaults() -> None:
    coefficient_fields = area.TraceableReliefAreaCoefficients.model_fields
    assert coefficient_fields["discharge_coefficient"].is_required()
    assert coefficient_fields["combined_correction_factor"].is_required()
    assert coefficient_fields["discharge_coefficient_role"].is_required()
    assert coefficient_fields["combined_correction_factor_role"].is_required()
    steam_fields = area.TraceableSteamFlowCoefficient.model_fields
    assert steam_fields["steam_mass_flux_coefficient"].is_required()
    assert steam_fields["critical_pressure_ratio"].is_required()
    assert steam_fields["coefficient_normalization"].is_required()

    coefficient_values = coefficients().model_dump(mode="python", round_trip=True)
    coefficient_values["discharge_coefficient_role"] = "correction_factor"
    with pytest.raises(ValidationError):
        area.TraceableReliefAreaCoefficients(**coefficient_values)

    steam_values = steam_flow().model_dump(mode="python", round_trip=True)
    steam_values["coefficient_normalization"] = "undocumented normalization"
    with pytest.raises(ValidationError):
        area.TraceableSteamFlowCoefficient(**steam_values)
