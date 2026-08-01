"""Focused acceptance tests for Phase 7 Step 100 liquid valve sizing."""

from __future__ import annotations

import ast
import inspect
from decimal import Decimal
from math import inf, nextafter, pi, sqrt
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

import app.engineering.calculations as calculation_package
import app.engineering.calculations.control_valve as control_valve_module
from app.engineering.calculations.control_valve import (
    CONTROL_VALVE_CALCULATORS_VERSION,
    CONTROL_VALVE_DISCOVERY_ENTRIES,
    CONTROL_VALVE_EXECUTABLE_ADAPTERS,
    CONTROL_VALVE_METHOD_IMPLEMENTATIONS,
    CONTROL_VALVE_METHOD_REGISTRY,
    CONTROL_VALVE_METHOD_VERSION,
    CV_PER_KV,
    IEC_60534_2_1_ADAPTER,
    IEC_60534_2_1_ADAPTER_ID,
    KV_PER_CV,
    LIQUID_CONTROL_VALVE_SIZING_ADAPTER,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    ControlValveInputError,
    LiquidCavitationStatus,
    LiquidControlValvePressureState,
    LiquidControlValveProperties,
    LiquidControlValveSizingInput,
    LiquidControlValveSizingResult,
    LiquidValveFlowRegime,
    LiquidValveRegimeResult,
    LiquidValveVelocityResult,
    LiquidVelocityStatus,
    TraceableLiquidValveFactors,
    TraceableVelocityLimit,
    ValveInstallationBasis,
    assess_liquid_control_valve_regime,
    build_liquid_control_valve_input_fingerprint_payload,
    build_liquid_control_valve_result_fingerprint_payload,
    canonical_control_valve_fingerprint_bytes,
    check_liquid_control_valve_velocity,
    convert_cv_to_kv,
    convert_kv_to_cv,
    derive_liquid_critical_pressure_ratio_factor,
    fingerprint_control_valve_payload,
    size_liquid_control_valve,
)
from app.engineering.calculations.dp_flow import (
    DP_FLOW_CALCULATORS_VERSION,
    DP_FLOW_METHOD_REGISTRY,
)
from app.engineering.calculations.models import MethodLifecycleStatus


def velocity_limit(value: float = 5.0) -> TraceableVelocityLimit:
    return TraceableVelocityLimit(
        maximum_velocity_m_s=value,
        source_reference="controlled project velocity limit VL-100",
        applicable_conditions=(
            "the declared liquid, downstream line, and operating case"
        ),
        supplied_by="project piping engineer",
    )


def bare_factors(value: float = 0.9) -> TraceableLiquidValveFactors:
    return TraceableLiquidValveFactors(
        installation_basis=ValveInstallationBasis.BARE_VALVE,
        bare_valve_pressure_recovery_factor=value,
        source_reference="controlled candidate factor record FL-100",
        applicable_conditions=(
            "exact valve candidate, size, trim, travel, flow direction, "
            "and bare-valve test arrangement"
        ),
        supplied_by="competent control-valve engineer",
    )


def attached_factors(
    piping_geometry_factor: float = 0.85,
    combined_pressure_recovery_factor: float = 0.72,
) -> TraceableLiquidValveFactors:
    return TraceableLiquidValveFactors(
        installation_basis=ValveInstallationBasis.ATTACHED_FITTINGS,
        piping_geometry_factor=piping_geometry_factor,
        combined_pressure_recovery_factor=(combined_pressure_recovery_factor),
        source_reference="controlled installed factor record FP-FLP-100",
        applicable_conditions=(
            "same exact candidate, size, trim, travel, flow direction, "
            "reducers, expanders, and attached piping arrangement"
        ),
        supplied_by="competent control-valve engineer",
    )


def liquid_properties(
    *,
    specific_gravity: float = 1.0,
    vapor_pressure_absolute_pa: float = 20_000.0,
    critical_pressure_absolute_pa: float = 22_064_000.0,
) -> LiquidControlValveProperties:
    return LiquidControlValveProperties(
        specific_gravity=specific_gravity,
        flowing_temperature_k=293.15,
        vapor_pressure_absolute_pa=vapor_pressure_absolute_pa,
        critical_pressure_absolute_pa=critical_pressure_absolute_pa,
        thermodynamic_pressure_basis="absolute",
        property_source_reference="controlled fluid-property record FP-100",
        condition_basis=(
            "properties apply at the declared single-phase inlet condition"
        ),
    )


def pressure_state(
    *,
    upstream_pressure_absolute_pa: float = 1_000_000.0,
    downstream_pressure_absolute_pa: float = 700_000.0,
) -> LiquidControlValvePressureState:
    return LiquidControlValvePressureState(
        upstream_pressure_absolute_pa=upstream_pressure_absolute_pa,
        downstream_pressure_absolute_pa=downstream_pressure_absolute_pa,
        pressure_basis="absolute",
        pressure_source_reference="controlled operating case OP-100",
        condition_basis="simultaneous steady design operating pressures",
    )


def sizing_input(
    *,
    flow_m3_h: float = 100.0,
    p1_pa: float = 1_000_000.0,
    p2_pa: float = 700_000.0,
    vapor_pa: float = 20_000.0,
    critical_pa: float = 22_064_000.0,
    specific_gravity: float = 1.0,
    factors: TraceableLiquidValveFactors | None = None,
    outlet_diameter_m: float = 0.15,
    maximum_velocity: TraceableVelocityLimit | None = None,
    case_id: str = "CV-STEP100-V1",
) -> LiquidControlValveSizingInput:
    return LiquidControlValveSizingInput(
        case_id=case_id,
        actual_volumetric_flow_m3_h=flow_m3_h,
        volumetric_flow_basis="actual_at_inlet_conditions",
        flow_source_reference="controlled design flow record Q-100",
        flow_condition_basis=("actual liquid volume at the declared inlet condition"),
        properties=liquid_properties(
            specific_gravity=specific_gravity,
            vapor_pressure_absolute_pa=vapor_pa,
            critical_pressure_absolute_pa=critical_pa,
        ),
        pressure_state=pressure_state(
            upstream_pressure_absolute_pa=p1_pa,
            downstream_pressure_absolute_pa=p2_pa,
        ),
        factors=factors if factors is not None else bare_factors(),
        outlet_inside_diameter_m=outlet_diameter_m,
        outlet_diameter_source_reference=(
            "controlled downstream piping record PIPE-100"
        ),
        maximum_outlet_velocity=maximum_velocity,
        fluid_phase="liquid",
        rheology="newtonian",
        turbulent_flow_confirmed=True,
        incompressible_flow_confirmed=True,
        single_phase_inlet_confirmed=True,
        suspended_solids_absent_confirmed=True,
    )


def result_with(**values: object) -> LiquidControlValveSizingResult:
    return size_liquid_control_valve(sizing_input(**values))


def test_cv_kv_conversion_is_derived_at_full_registry_precision() -> None:
    assert KV_PER_CV == pytest.approx(
        0.8649776554423018,
        rel=1e-15,
    )
    assert CV_PER_KV == pytest.approx(
        1.1560992283536564,
        rel=1e-15,
    )
    assert KV_PER_CV * CV_PER_KV == pytest.approx(1.0, rel=1e-15)
    assert KV_PER_CV != 0.865


@pytest.mark.parametrize("value", (1e-9, 0.1, 1.0, 57.735, 1e6))
def test_cv_kv_conversion_round_trips(value: float) -> None:
    assert convert_kv_to_cv(convert_cv_to_kv(value)) == pytest.approx(
        value,
        rel=2e-15,
    )
    assert convert_cv_to_kv(convert_kv_to_cv(value)) == pytest.approx(
        value,
        rel=2e-15,
    )


@pytest.mark.parametrize(
    "value",
    (
        0.0,
        -1.0,
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
@pytest.mark.parametrize("converter", (convert_cv_to_kv, convert_kv_to_cv))
def test_cv_kv_conversion_rejects_invalid_values(
    value: object,
    converter: object,
) -> None:
    with pytest.raises(ControlValveInputError):
        converter(value)  # type: ignore[operator]


def test_reference_vector_v1_bare_nonchoked() -> None:
    result = result_with(maximum_velocity=velocity_limit(2.0))
    assert result.regime.critical_pressure_ratio_factor == pytest.approx(
        0.9515699353592208,
        rel=1e-15,
    )
    assert result.regime.actual_pressure_drop_pa == 300_000.0
    assert result.regime.terminal_pressure_drop_pa == pytest.approx(
        794_584.5670471806,
        rel=1e-15,
    )
    assert result.regime.sizing_pressure_drop_pa == 300_000.0
    assert result.regime.choking_index == pytest.approx(
        0.3775557850498582,
        rel=1e-15,
    )
    assert result.required_kv == pytest.approx(57.73502691896258)
    assert result.required_cv == pytest.approx(66.74742006999022)
    assert result.regime.flow_regime is LiquidValveFlowRegime.SUBCRITICAL
    assert result.regime.choked is False
    assert result.regime.flashing is False
    assert result.regime.cavitation_status is LiquidCavitationStatus.NOT_EXCLUDED
    assert result.velocity.outlet_velocity_m_s == pytest.approx(1.571900672512547)
    assert result.velocity.velocity_status is (
        LiquidVelocityStatus.WITHIN_SUPPLIED_LIMIT
    )
    assert result.standards_conformity_claimed is False
    assert result.manufacturer_selection_performed is False
    assert result.selection_ready is False


def test_reference_vector_v2_choked_cavitation() -> None:
    result = result_with(
        p2_pa=100_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        outlet_diameter_m=0.1,
        maximum_velocity=velocity_limit(4.0),
        case_id="CV-STEP100-V2",
    )
    assert result.regime.critical_pressure_ratio_factor == pytest.approx(0.932)
    assert result.regime.actual_pressure_drop_pa == 900_000.0
    assert result.regime.terminal_pressure_drop_pa == pytest.approx(467_166.0)
    assert result.regime.choking_index == pytest.approx(1.926510062804228)
    assert result.required_kv == pytest.approx(46.26625915771819)
    assert result.required_cv == pytest.approx(53.48838651104829)
    assert result.regime.flow_regime is LiquidValveFlowRegime.CHOKED
    assert result.regime.choked is True
    assert result.regime.flashing is False
    assert result.regime.cavitation_status is (
        LiquidCavitationStatus.CHOKED_CAVITATION_INDICATED
    )
    assert result.velocity.outlet_velocity_m_s == pytest.approx(3.53677651315323)


def test_reference_vector_v3_flashing_preserves_choked_capacity() -> None:
    choked = result_with(
        p2_pa=100_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        outlet_diameter_m=0.1,
        maximum_velocity=velocity_limit(4.0),
        case_id="CV-STEP100-V2",
    )
    flashing = result_with(
        p2_pa=40_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        outlet_diameter_m=0.1,
        maximum_velocity=velocity_limit(4.0),
        case_id="CV-STEP100-V3",
    )
    assert flashing.regime.actual_pressure_drop_pa == 960_000.0
    assert flashing.regime.sizing_pressure_drop_pa == (
        choked.regime.sizing_pressure_drop_pa
    )
    assert flashing.required_kv == choked.required_kv
    assert flashing.required_cv == choked.required_cv
    assert flashing.regime.flashing is True
    assert flashing.regime.cavitation_status is (
        LiquidCavitationStatus.FLASHING_PRESENT
    )
    assert flashing.velocity.outlet_velocity_m_s is None
    assert flashing.velocity.within_supplied_limit is None
    assert flashing.velocity.velocity_status is (
        LiquidVelocityStatus.SUPPRESSED_FLASHING
    )


def test_reference_vector_v4_attached_fittings_choked() -> None:
    result = result_with(
        flow_m3_h=250.0,
        p1_pa=1_200_000.0,
        p2_pa=300_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        specific_gravity=0.8,
        factors=attached_factors(0.85, 0.72),
        outlet_diameter_m=0.2,
        maximum_velocity=velocity_limit(3.0),
        case_id="CV-STEP100-V4",
    )
    assert result.regime.terminal_pressure_drop_pa == pytest.approx(827_574.4775086505)
    assert result.regime.choking_index == pytest.approx(1.087515413367243)
    assert result.required_kv == pytest.approx(91.44554070893634)
    assert result.required_cv == pytest.approx(105.7201190499842)
    assert result.velocity.outlet_velocity_m_s == pytest.approx(2.210485320720769)


def test_reference_vector_v4_attached_fittings_nonchoked_variant() -> None:
    result = result_with(
        flow_m3_h=250.0,
        p1_pa=1_200_000.0,
        p2_pa=1_000_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        specific_gravity=0.8,
        factors=attached_factors(0.85, 0.72),
        outlet_diameter_m=0.2,
        case_id="CV-STEP100-V4-NORMAL",
    )
    assert result.regime.choked is False
    assert result.required_kv == pytest.approx(186.0163329510811)
    assert result.required_cv == pytest.approx(215.0533389859217)


def test_exact_choking_transition_below_at_and_above() -> None:
    p1 = 100_000.0
    terminal = 25_000.0
    boundary_p2 = p1 - terminal
    common = {
        "p1_pa": p1,
        "vapor_pa": 0.0,
        "critical_pa": 1_000_000.0,
        "factors": bare_factors(0.5),
        "outlet_diameter_m": 0.2,
    }
    below = result_with(
        **common,
        p2_pa=nextafter(boundary_p2, inf),
        case_id="TRANSITION-BELOW",
    )
    at = result_with(
        **common,
        p2_pa=boundary_p2,
        case_id="TRANSITION-AT",
    )
    above = result_with(
        **common,
        p2_pa=nextafter(boundary_p2, -inf),
        case_id="TRANSITION-ABOVE",
    )
    assert below.regime.actual_pressure_drop_pa < terminal
    assert below.regime.choked is False
    assert below.regime.choking_pressure_margin_pa > 0.0
    assert at.regime.actual_pressure_drop_pa == terminal
    assert at.regime.choked is True
    assert at.regime.choking_pressure_margin_pa == 0.0
    assert above.regime.actual_pressure_drop_pa > terminal
    assert above.regime.choked is True
    assert above.regime.choking_pressure_margin_pa < 0.0
    assert at.required_kv == above.required_kv
    assert below.required_kv == pytest.approx(at.required_kv, rel=1e-15)


def test_choked_plateau_does_not_return_false_capacity_convergence() -> None:
    first = result_with(
        p2_pa=100_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
    )
    second = result_with(
        p2_pa=60_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
    )
    assert first.regime.choked and second.regime.choked
    assert first.required_kv == second.required_kv
    for result in (first, second):
        reconstructed = (
            result.required_kv
            * result.regime.effective_piping_geometry_factor
            * sqrt(
                (result.regime.sizing_pressure_drop_pa / 100_000.0)
                / result.normalized_input.properties.specific_gravity
            )
        )
        assert reconstructed == pytest.approx(
            result.normalized_input.actual_volumetric_flow_m3_h,
            rel=1e-12,
        )
        assert "converged" not in type(result).model_fields


def test_flashing_boundary_below_at_and_above_vapor_pressure() -> None:
    vapor = 50_000.0
    above = result_with(
        p2_pa=nextafter(vapor, inf),
        vapor_pa=vapor,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        case_id="FLASH-ABOVE",
    )
    at = result_with(
        p2_pa=vapor,
        vapor_pa=vapor,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        case_id="FLASH-AT",
    )
    below = result_with(
        p2_pa=nextafter(vapor, -inf),
        vapor_pa=vapor,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        case_id="FLASH-BELOW",
    )
    assert above.regime.flashing is False
    assert above.velocity.outlet_velocity_m_s is not None
    assert at.regime.flashing is True
    assert below.regime.flashing is True
    assert at.velocity.outlet_velocity_m_s is None
    assert below.velocity.outlet_velocity_m_s is None
    assert at.required_kv == below.required_kv


def test_velocity_limit_below_equal_and_above() -> None:
    base = sizing_input(maximum_velocity=None)
    expected = (base.actual_volumetric_flow_m3_h / 3600.0) / (
        pi * base.outlet_inside_diameter_m**2 / 4.0
    )
    too_low = size_liquid_control_valve(
        base.model_copy(
            update={
                "maximum_outlet_velocity": velocity_limit(nextafter(expected, -inf))
            }
        )
    )
    equal = size_liquid_control_valve(
        base.model_copy(update={"maximum_outlet_velocity": velocity_limit(expected)})
    )
    above = size_liquid_control_valve(
        base.model_copy(
            update={"maximum_outlet_velocity": velocity_limit(nextafter(expected, inf))}
        )
    )
    assert too_low.velocity.velocity_status is (
        LiquidVelocityStatus.EXCEEDS_SUPPLIED_LIMIT
    )
    assert too_low.velocity.within_supplied_limit is False
    assert equal.velocity.velocity_status is (
        LiquidVelocityStatus.WITHIN_SUPPLIED_LIMIT
    )
    assert equal.velocity.within_supplied_limit is True
    assert above.velocity.within_supplied_limit is True


def test_missing_velocity_limit_is_explicitly_not_assessed() -> None:
    result = result_with(maximum_velocity=None)
    assert result.velocity.outlet_velocity_m_s is not None
    assert result.velocity.supplied_maximum_velocity_m_s is None
    assert result.velocity.within_supplied_limit is None
    assert result.velocity.velocity_status is LiquidVelocityStatus.NOT_ASSESSED
    assert any("not assessed" in item for item in result.velocity.warnings)


def test_capacity_and_velocity_scale_linearly_with_flow() -> None:
    base = result_with(flow_m3_h=100.0)
    doubled = result_with(flow_m3_h=200.0, case_id="FLOW-DOUBLE")
    assert doubled.required_kv == pytest.approx(2.0 * base.required_kv)
    assert doubled.required_cv == pytest.approx(2.0 * base.required_cv)
    assert doubled.velocity.outlet_velocity_m_s == pytest.approx(
        2.0 * base.velocity.outlet_velocity_m_s  # type: ignore[operator]
    )


def test_nonchoked_capacity_scales_with_specific_gravity() -> None:
    base = result_with(specific_gravity=1.0)
    dense = result_with(specific_gravity=4.0, case_id="SG-FOUR")
    assert base.regime.choked is False and dense.regime.choked is False
    assert dense.required_kv == pytest.approx(2.0 * base.required_kv)


def test_nonchoked_capacity_scales_with_inverse_sqrt_pressure_drop() -> None:
    one_bar = result_with(p2_pa=900_000.0, case_id="DP-ONE")
    four_bar = result_with(p2_pa=600_000.0, case_id="DP-FOUR")
    assert one_bar.regime.choked is False
    assert four_bar.regime.choked is False
    assert four_bar.required_kv == pytest.approx(one_bar.required_kv / 2.0)


def test_nonchoked_capacity_scales_inverse_to_piping_factor() -> None:
    lower_fp = result_with(
        p2_pa=900_000.0,
        factors=attached_factors(0.8, 0.6),
        case_id="FP-LOWER",
    )
    unit_fp = result_with(
        p2_pa=900_000.0,
        factors=attached_factors(1.0, 0.6),
        case_id="FP-UNIT",
    )
    assert lower_fp.regime.choked is False and unit_fp.regime.choked is False
    assert lower_fp.required_kv == pytest.approx(unit_fp.required_kv / 0.8)


def test_choked_attached_capacity_cancels_fp_when_flp_is_fixed() -> None:
    first = result_with(
        p1_pa=1_200_000.0,
        p2_pa=300_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=attached_factors(0.85, 0.72),
        case_id="CHOKED-FP-85",
    )
    second = result_with(
        p1_pa=1_200_000.0,
        p2_pa=300_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=attached_factors(0.9, 0.72),
        case_id="CHOKED-FP-90",
    )
    assert first.regime.choked and second.regime.choked
    assert first.required_kv == pytest.approx(second.required_kv, rel=1e-15)


def test_scaling_all_absolute_pressures_preserves_ff_and_scales_capacity() -> None:
    base = result_with(
        p1_pa=1_000_000.0,
        p2_pa=700_000.0,
        vapor_pa=20_000.0,
        critical_pa=22_064_000.0,
    )
    scaled = result_with(
        p1_pa=4_000_000.0,
        p2_pa=2_800_000.0,
        vapor_pa=80_000.0,
        critical_pa=88_256_000.0,
        case_id="PRESSURE-SCALED",
    )
    assert scaled.regime.critical_pressure_ratio_factor == (
        base.regime.critical_pressure_ratio_factor
    )
    assert scaled.required_kv == pytest.approx(base.required_kv / 2.0)


def test_bare_and_equivalent_attached_factor_forms_match() -> None:
    bare = result_with(factors=bare_factors(0.9), case_id="BARE")
    attached = result_with(
        factors=attached_factors(1.0, 0.9),
        case_id="ATTACHED-EQUIVALENT",
    )
    assert attached.regime.terminal_pressure_drop_pa == (
        bare.regime.terminal_pressure_drop_pa
    )
    assert attached.required_kv == bare.required_kv


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("specific_gravity", 0.0),
        ("specific_gravity", -1.0),
        ("specific_gravity", True),
        ("specific_gravity", "1.0"),
        ("specific_gravity", float("nan")),
        ("specific_gravity", float("inf")),
        ("flowing_temperature_k", 0.0),
        ("vapor_pressure_absolute_pa", -1.0),
        ("critical_pressure_absolute_pa", 20_000.0),
        ("thermodynamic_pressure_basis", "gauge"),
    ),
)
def test_liquid_property_invalid_states_fail_closed(
    field: str,
    value: object,
) -> None:
    values = liquid_properties().model_dump(mode="python", round_trip=True)
    values[field] = value
    with pytest.raises((ValidationError, ControlValveInputError)):
        LiquidControlValveProperties(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("upstream_pressure_absolute_pa", 700_000.0),
        ("downstream_pressure_absolute_pa", 0.0),
        ("upstream_pressure_absolute_pa", True),
        ("downstream_pressure_absolute_pa", "700000"),
        ("upstream_pressure_absolute_pa", float("nan")),
        ("pressure_basis", "gauge"),
    ),
)
def test_pressure_state_invalid_states_fail_closed(
    field: str,
    value: object,
) -> None:
    values = pressure_state().model_dump(mode="python", round_trip=True)
    values[field] = value
    with pytest.raises((ValidationError, ControlValveInputError)):
        LiquidControlValvePressureState(**values)


def test_upstream_pressure_at_or_below_vapor_pressure_is_blocked() -> None:
    with pytest.raises(ValidationError, match="must exceed vapor"):
        sizing_input(
            p1_pa=20_000.0,
            p2_pa=10_000.0,
            vapor_pa=20_000.0,
            critical_pa=1_000_000.0,
        )


@pytest.mark.parametrize(
    "values",
    (
        {
            "installation_basis": "bare_valve",
            "bare_valve_pressure_recovery_factor": None,
        },
        {
            "installation_basis": "bare_valve",
            "bare_valve_pressure_recovery_factor": 0.9,
            "piping_geometry_factor": 1.0,
        },
        {
            "installation_basis": "bare_valve",
            "bare_valve_pressure_recovery_factor": 0.0,
        },
        {
            "installation_basis": "bare_valve",
            "bare_valve_pressure_recovery_factor": 1.01,
        },
        {
            "installation_basis": "attached_fittings",
            "piping_geometry_factor": 0.85,
            "combined_pressure_recovery_factor": None,
        },
        {
            "installation_basis": "attached_fittings",
            "bare_valve_pressure_recovery_factor": 0.7,
            "piping_geometry_factor": 0.85,
            "combined_pressure_recovery_factor": 0.72,
        },
        {
            "installation_basis": "attached_fittings",
            "piping_geometry_factor": 0.85,
            "combined_pressure_recovery_factor": 0.86,
        },
        {
            "installation_basis": "attached_fittings",
            "piping_geometry_factor": 1.01,
            "combined_pressure_recovery_factor": 0.72,
        },
        {
            "installation_basis": "attached_fittings",
            "piping_geometry_factor": True,
            "combined_pressure_recovery_factor": 0.72,
        },
    ),
)
def test_factor_arrangements_fail_closed(values: dict[str, object]) -> None:
    complete: dict[str, object] = {
        "bare_valve_pressure_recovery_factor": None,
        "piping_geometry_factor": None,
        "combined_pressure_recovery_factor": None,
        "source_reference": "controlled factor record BAD",
        "applicable_conditions": (
            "exact candidate size trim travel direction and arrangement"
        ),
        "supplied_by": "competent engineer",
    }
    complete.update(values)
    with pytest.raises((ValidationError, ControlValveInputError)):
        TraceableLiquidValveFactors(**complete)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_reference", "   "),
        ("source_reference", " record "),
        ("applicable_conditions", "   "),
        ("supplied_by", " engineer "),
    ),
)
def test_factor_provenance_rejects_blank_or_padded_text(
    field: str,
    value: str,
) -> None:
    values = bare_factors().model_dump(mode="python", round_trip=True)
    values[field] = value
    with pytest.raises(ValidationError):
        TraceableLiquidValveFactors(**values)


def test_factor_provenance_rejects_nontext_as_validation_error() -> None:
    values = bare_factors().model_dump(mode="python", round_trip=True)
    values["source_reference"] = 123
    with pytest.raises(ValidationError, match="must be text"):
        TraceableLiquidValveFactors(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("actual_volumetric_flow_m3_h", 0.0),
        ("actual_volumetric_flow_m3_h", -1.0),
        ("actual_volumetric_flow_m3_h", True),
        ("actual_volumetric_flow_m3_h", "100"),
        ("actual_volumetric_flow_m3_h", float("inf")),
        ("actual_volumetric_flow_m3_h", 10**400),
        ("outlet_inside_diameter_m", 0.0),
        ("volumetric_flow_basis", "standard_conditions"),
        ("fluid_phase", "gas"),
        ("rheology", "non_newtonian"),
        ("turbulent_flow_confirmed", False),
        ("turbulent_flow_confirmed", 1),
        ("incompressible_flow_confirmed", False),
        ("incompressible_flow_confirmed", 1),
        ("single_phase_inlet_confirmed", False),
        ("suspended_solids_absent_confirmed", False),
    ),
)
def test_sizing_input_invalid_states_fail_closed(
    field: str,
    value: object,
) -> None:
    values = sizing_input().model_dump(mode="python", round_trip=True)
    values[field] = value
    with pytest.raises((ValidationError, ControlValveInputError)):
        LiquidControlValveSizingInput(**values)


def test_public_functions_reject_unvalidated_mappings() -> None:
    with pytest.raises(ControlValveInputError):
        size_liquid_control_valve(  # type: ignore[arg-type]
            sizing_input().model_dump(mode="python")
        )
    with pytest.raises(ControlValveInputError):
        assess_liquid_control_valve_regime(  # type: ignore[arg-type]
            pressure_state=pressure_state().model_dump(),
            properties=liquid_properties(),
            factors=bare_factors(),
        )


def test_regime_result_rejects_impossible_or_forged_values() -> None:
    values = result_with().regime.model_dump(mode="python", round_trip=True)
    mutations = (
        {"actual_pressure_drop_pa": -1.0},
        {"critical_pressure_ratio_factor": 0.0},
        {"terminal_pressure_drop_pa": -1.0},
        {"sizing_pressure_drop_pa": -1.0},
        {"choking_pressure_margin_pa": values["choking_pressure_margin_pa"] + 1.0},
        {"choking_index": values["choking_index"] + 1.0},
        {"effective_piping_geometry_factor": 1.1},
        {"effective_pressure_recovery_factor": 0.0},
        {"warnings": ("forged warning",)},
    )
    for mutation in mutations:
        forged = dict(values)
        forged.update(mutation)
        with pytest.raises(ValidationError):
            LiquidValveRegimeResult(**forged)


def test_velocity_result_rejects_impossible_or_forged_values() -> None:
    values = result_with(maximum_velocity=velocity_limit()).velocity.model_dump(
        mode="python",
        round_trip=True,
    )
    mutations = (
        {"outlet_inside_diameter_m": -1.0},
        {"outlet_area_m2": -1.0},
        {"outlet_area_m2": values["outlet_area_m2"] * 2.0},
        {"outlet_velocity_m_s": -1.0},
        {"supplied_maximum_velocity_m_s": 0.0},
        {"supplied_limit_source_reference": 123},
        {"warnings": ("forged warning",)},
    )
    for mutation in mutations:
        forged = dict(values)
        forged.update(mutation)
        with pytest.raises(ValidationError):
            LiquidValveVelocityResult(**forged)


@pytest.mark.parametrize(
    "value",
    (True, "1", Decimal(1), float("nan"), float("inf"), 10**400),
)
def test_direct_helpers_reject_coercive_and_nonfinite_numbers(
    value: object,
) -> None:
    with pytest.raises(ControlValveInputError):
        derive_liquid_critical_pressure_ratio_factor(
            vapor_pressure_absolute_pa=value,
            critical_pressure_absolute_pa=1_000_000.0,
        )
    with pytest.raises(ControlValveInputError):
        check_liquid_control_valve_velocity(
            actual_volumetric_flow_m3_h=value,
            outlet_inside_diameter_m=0.1,
            incompressible_flow_confirmed=True,
            flashing=False,
        )


@pytest.mark.parametrize("confirmation", (False, 1))
def test_direct_velocity_helper_requires_strict_incompressible_confirmation(
    confirmation: object,
) -> None:
    with pytest.raises(ControlValveInputError, match="incompressible"):
        check_liquid_control_valve_velocity(
            actual_volumetric_flow_m3_h=100.0,
            outlet_inside_diameter_m=0.1,
            incompressible_flow_confirmed=confirmation,  # type: ignore[arg-type]
            flashing=False,
        )


def test_calculated_overflow_and_underflow_fail_as_domain_errors() -> None:
    huge = sizing_input(
        flow_m3_h=1e308,
        p2_pa=nextafter(1_000_000.0, -inf),
        case_id="OVERFLOW-CAPACITY",
    )
    with pytest.raises(ControlValveInputError):
        size_liquid_control_valve(huge)
    tiny_diameter = sizing_input().model_copy(
        update={"outlet_inside_diameter_m": 5e-324}
    )
    with pytest.raises(ControlValveInputError):
        size_liquid_control_valve(tiny_diameter)


@pytest.mark.parametrize(
    "model",
    (
        bare_factors(),
        velocity_limit(),
        liquid_properties(),
        pressure_state(),
        sizing_input(),
        result_with(),
    ),
)
def test_public_models_are_frozen_and_forbid_extras(model: object) -> None:
    field_name = next(iter(type(model).model_fields))  # type: ignore[attr-defined]
    with pytest.raises((ValidationError, TypeError)):
        setattr(model, field_name, getattr(model, field_name))
    values = model.model_dump(mode="python", round_trip=True)  # type: ignore[attr-defined]
    values["unexpected"] = "blocked"
    with pytest.raises(ValidationError):
        type(model)(**values)


@pytest.mark.parametrize(
    "model",
    (
        bare_factors(),
        velocity_limit(),
        liquid_properties(),
        pressure_state(),
        sizing_input(),
        result_with(),
    ),
)
def test_public_models_round_trip_through_json(model: object) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


def test_input_fingerprint_is_canonical_and_signed_zero_stable() -> None:
    positive = sizing_input(
        vapor_pa=0.0,
        critical_pa=1_000_000.0,
        factors=bare_factors(0.5),
    )
    negative = sizing_input(
        vapor_pa=-0.0,
        critical_pa=1_000_000.0,
        factors=bare_factors(0.5),
    )
    positive_payload = build_liquid_control_valve_input_fingerprint_payload(positive)
    negative_payload = build_liquid_control_valve_input_fingerprint_payload(negative)
    assert canonical_control_valve_fingerprint_bytes(positive_payload) == (
        canonical_control_valve_fingerprint_bytes(negative_payload)
    )
    assert fingerprint_control_valve_payload(positive_payload) == (
        fingerprint_control_valve_payload(negative_payload)
    )
    assert fingerprint_control_valve_payload({"b": 2, "a": 1}) == (
        fingerprint_control_valve_payload({"a": 1, "b": 2})
    )


@pytest.mark.parametrize("payload", ({1: "numeric"}, {"1": "text", 1: "numeric"}))
def test_fingerprint_payload_rejects_nonstring_mapping_keys(
    payload: dict[object, str],
) -> None:
    with pytest.raises(ControlValveInputError, match="keys must be strings"):
        canonical_control_valve_fingerprint_bytes(payload)


@pytest.mark.parametrize(
    "updated",
    (
        {"actual_volumetric_flow_m3_h": 101.0},
        {"flow_source_reference": "controlled design flow record Q-CHANGED"},
        {"outlet_inside_diameter_m": 0.16},
        {"case_id": "CV-STEP100-CHANGED"},
    ),
)
def test_input_fingerprint_changes_with_material_value_or_provenance(
    updated: dict[str, object],
) -> None:
    baseline = sizing_input()
    changed = baseline.model_copy(update=updated)
    baseline_fingerprint = fingerprint_control_valve_payload(
        build_liquid_control_valve_input_fingerprint_payload(baseline)
    )
    changed_fingerprint = fingerprint_control_valve_payload(
        build_liquid_control_valve_input_fingerprint_payload(changed)
    )
    assert changed_fingerprint != baseline_fingerprint


def test_nested_factor_provenance_changes_input_fingerprint() -> None:
    baseline = sizing_input()
    changed_factors = baseline.factors.model_copy(
        update={"source_reference": "controlled candidate factor record FL-CHANGED"}
    )
    changed = baseline.model_copy(update={"factors": changed_factors})
    assert size_liquid_control_valve(baseline).input_fingerprint != (
        size_liquid_control_valve(changed).input_fingerprint
    )


def test_forged_input_or_result_fingerprint_is_rejected() -> None:
    result = result_with()
    values = result.model_dump(mode="python", round_trip=True)
    values["input_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="input fingerprint"):
        LiquidControlValveSizingResult(**values)
    values = result.model_dump(mode="python", round_trip=True)
    values["result_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="result fingerprint"):
        LiquidControlValveSizingResult(**values)


def test_result_fingerprint_is_stable_and_sensitive_to_outputs() -> None:
    first = result_with()
    second = result_with()
    assert first.result_fingerprint == second.result_fingerprint
    values = first.model_dump(mode="python", round_trip=True)
    values["required_kv"] = first.required_kv + 1.0
    with pytest.raises(ValidationError):
        LiquidControlValveSizingResult(**values)


def test_recomputed_public_hash_cannot_authorize_forged_capacity() -> None:
    result = result_with()
    values = result.model_dump(mode="python", round_trip=True)
    values["required_kv"] = result.required_kv + 1.0
    values["required_cv"] = convert_kv_to_cv(values["required_kv"])
    values["result_fingerprint"] = fingerprint_control_valve_payload(
        build_liquid_control_valve_result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError, match="capacity is not reproducible"):
        LiquidControlValveSizingResult(**values)


def test_recomputed_public_hash_cannot_authorize_foreign_regime_or_velocity() -> None:
    baseline = result_with(maximum_velocity=velocity_limit(5.0))
    alternate = result_with(
        p2_pa=100_000.0,
        vapor_pa=50_000.0,
        critical_pa=5_000_000.0,
        factors=bare_factors(0.7),
        outlet_diameter_m=0.1,
        maximum_velocity=velocity_limit(4.0),
        case_id="FORGED-ALTERNATE",
    )
    for field in ("regime", "velocity"):
        values = baseline.model_dump(mode="python", round_trip=True)
        values[field] = getattr(alternate, field).model_dump(
            mode="python",
            round_trip=True,
        )
        values["result_fingerprint"] = fingerprint_control_valve_payload(
            build_liquid_control_valve_result_fingerprint_payload(values)
        )
        with pytest.raises(ValidationError, match="not reproducible"):
            LiquidControlValveSizingResult(**values)


def test_method_registry_is_exact_versioned_and_immutable() -> None:
    expected_key = (
        LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    )
    assert CONTROL_VALVE_CALCULATORS_VERSION == "1.0.0"
    assert CONTROL_VALVE_METHOD_VERSION == "1.0.0"
    assert LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION == "1.0.0"
    assert CONTROL_VALVE_EXECUTABLE_ADAPTERS == (LIQUID_CONTROL_VALVE_SIZING_ADAPTER,)
    assert isinstance(CONTROL_VALVE_METHOD_REGISTRY, MappingProxyType)
    assert isinstance(CONTROL_VALVE_METHOD_IMPLEMENTATIONS, MappingProxyType)
    assert tuple(CONTROL_VALVE_METHOD_REGISTRY) == (expected_key,)
    assert tuple(CONTROL_VALVE_METHOD_IMPLEMENTATIONS) == (expected_key,)
    assert CONTROL_VALVE_METHOD_REGISTRY[expected_key] is (
        LIQUID_CONTROL_VALVE_SIZING_ADAPTER
    )
    assert CONTROL_VALVE_METHOD_IMPLEMENTATIONS[expected_key] is (
        size_liquid_control_valve
    )
    with pytest.raises(TypeError):
        CONTROL_VALVE_METHOD_REGISTRY[expected_key] = (  # type: ignore[index]
            LIQUID_CONTROL_VALVE_SIZING_ADAPTER
        )
    with pytest.raises(TypeError):
        CONTROL_VALVE_METHOD_IMPLEMENTATIONS[expected_key] = (  # type: ignore[index]
            size_liquid_control_valve
        )


def test_iec_adapter_is_discoverable_inert_and_nonconforming() -> None:
    assert IEC_60534_2_1_ADAPTER.adapter_id == IEC_60534_2_1_ADAPTER_ID
    assert CONTROL_VALVE_DISCOVERY_ENTRIES == (IEC_60534_2_1_ADAPTER,)
    assert IEC_60534_2_1_ADAPTER.lifecycle_status is (
        MethodLifecycleStatus.STANDARDS_REVIEW
    )
    assert IEC_60534_2_1_ADAPTER.executable is False
    assert IEC_60534_2_1_ADAPTER.conformity_claimed is False
    assert "No protected tables" in IEC_60534_2_1_ADAPTER.boundary
    assert "conformity assessment" in IEC_60534_2_1_ADAPTER.boundary


def test_step100_preserves_frozen_phase7_boundaries() -> None:
    assert calculation_package.FOUNDATION_VERSION == "0.6.0"
    assert calculation_package.PHASE_NUMBER == 7
    assert len(calculation_package.ENGINEERING_METHOD_IDS) == 26
    assert len(calculation_package.ENGINEERING_METHOD_REGISTRY.definitions) == 26
    assert DP_FLOW_CALCULATORS_VERSION == "1.1.1"
    assert len(DP_FLOW_METHOD_REGISTRY) == 7
    assert (
        LIQUID_CONTROL_VALVE_SIZING_METHOD_ID
        not in calculation_package.ENGINEERING_METHOD_IDS
    )


def test_package_exports_complete_control_valve_surface() -> None:
    expected = set(control_valve_module.__all__)
    assert len(control_valve_module.__all__) == len(expected)
    assert expected.issubset(set(calculation_package.__all__))
    for name in control_valve_module.__all__:
        assert getattr(control_valve_module, name) is not None
        assert getattr(calculation_package, name) is getattr(
            control_valve_module,
            name,
        )
    assert len(calculation_package.__all__) == len(set(calculation_package.__all__))


def test_control_valve_module_has_no_dynamic_or_external_execution() -> None:
    source = inspect.getsource(control_valve_module)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "asyncio",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    imported_roots: set[str] = set()
    forbidden_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ):
            forbidden_calls.add(node.func.id)
    assert imported_roots.isdisjoint(forbidden_import_roots)
    assert forbidden_calls == set()
    assert "voice" not in source.casefold()
    assert "manufacturer_selection_performed=True" not in source


def test_step100_exact_file_scope_is_calculation_only() -> None:
    module_path = Path(control_valve_module.__file__).resolve()
    assert module_path.name == "control_valve.py"
    assert "engineering/calculations" in module_path.as_posix()
    assert "api" not in control_valve_module.__all__
    assert "service" not in control_valve_module.__all__
    assert "persistence" not in control_valve_module.__all__
