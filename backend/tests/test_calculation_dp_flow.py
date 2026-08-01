"""Focused acceptance tests for Phase 7 Steps 97-98 DP-flow calculations."""

from __future__ import annotations

from math import pi, sqrt

import pytest
from pydantic import ValidationError

import app.engineering.calculations.dp_flow as dp_flow_module
from app.engineering.calculations.dp_flow import AveragingPitotFlowResult
from app.engineering.calculations.dp_flow import CircularRestrictionFlowResult
from app.engineering.calculations.dp_flow import DPFlowConvergenceError
from app.engineering.calculations.dp_flow import DPFlowInputError
from app.engineering.calculations.dp_flow import DP_FLOW_DISCOVERY_ENTRIES
from app.engineering.calculations.dp_flow import DP_FLOW_METHOD_IMPLEMENTATIONS
from app.engineering.calculations.dp_flow import DP_FLOW_METHOD_REGISTRY
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_ID
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_VERSION
from app.engineering.calculations.dp_flow import DP_TRANSMITTER_RANGE_METHOD_ID
from app.engineering.calculations.dp_flow import DP_TRANSMITTER_RANGE_METHOD_VERSION
from app.engineering.calculations.dp_flow import FlowReferenceConditions
from app.engineering.calculations.dp_flow import FlowingFluidProperties
from app.engineering.calculations.dp_flow import GENERIC_AVERAGING_PITOT_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_AVERAGING_PITOT_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_NOZZLE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_NOZZLE_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_NOZZLE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_NOZZLE_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_TUBE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_TUBE_METHOD_VERSION
from app.engineering.calculations.dp_flow import ISO_5167_2_ADAPTER
from app.engineering.calculations.dp_flow import ISO_5167_3_ADAPTER
from app.engineering.calculations.dp_flow import ISO_5167_4_ADAPTER
from app.engineering.calculations.dp_flow import MAX_SOLVER_ITERATIONS
from app.engineering.calculations.dp_flow import OrificeFlowResult
from app.engineering.calculations.dp_flow import PERMANENT_PRESSURE_LOSS_METHOD_ID
from app.engineering.calculations.dp_flow import PERMANENT_PRESSURE_LOSS_METHOD_VERSION
from app.engineering.calculations.dp_flow import RelativeUncertaintyComponent
from app.engineering.calculations.dp_flow import StandardsAdapterMetadata
from app.engineering.calculations.dp_flow import TraceableCoefficient
from app.engineering.calculations.dp_flow import assess_generic_orifice_applicability
from app.engineering.calculations.dp_flow import calculate_generic_averaging_pitot_flow
from app.engineering.calculations.dp_flow import calculate_generic_circular_restriction_flow
from app.engineering.calculations.dp_flow import calculate_generic_nozzle_flow
from app.engineering.calculations.dp_flow import calculate_generic_orifice_flow
from app.engineering.calculations.dp_flow import calculate_generic_venturi_nozzle_flow
from app.engineering.calculations.dp_flow import calculate_generic_venturi_tube_flow
from app.engineering.calculations.dp_flow import calculate_permanent_pressure_loss
from app.engineering.calculations.dp_flow import combine_dp_flow_relative_uncertainty
from app.engineering.calculations.dp_flow import screen_dp_transmitter_range
from app.engineering.calculations.dp_flow import solve_orifice_bore_for_mass_flow
from app.engineering.calculations.models import MethodLifecycleStatus


def fluid() -> FlowingFluidProperties:
    return FlowingFluidProperties(
        density_kg_m3=998.2,
        dynamic_viscosity_pa_s=1.002e-3,
        pressure_absolute_pa=300_000.0,
        temperature_k=293.15,
        phase="liquid",
        property_source_reference="controlled fluid-property record FP-001",
        condition_basis="single-phase water at the stated flowing condition",
    )


def coefficient(value: float, name: str) -> TraceableCoefficient:
    return TraceableCoefficient(
        value=value,
        source_reference=f"controlled coefficient record {name}",
        applicable_conditions="this exact geometry and operating point",
        supplied_by="competent flow engineer",
    )


def inputs() -> dict[str, object]:
    return {
        "pipe_inside_diameter_m": 0.100,
        "bore_diameter_m": 0.050,
        "differential_pressure_pa": 10_000.0,
        "fluid": fluid(),
        "discharge_coefficient": coefficient(0.61, "CD-001"),
        "expansibility_factor": coefficient(1.0, "EPS-001"),
    }


def circular_inputs() -> dict[str, object]:
    return {
        "pipe_inside_diameter_m": 0.100,
        "throat_diameter_m": 0.050,
        "differential_pressure_pa": 10_000.0,
        "fluid": fluid(),
        "discharge_coefficient": coefficient(0.61, "CD-STEP98"),
        "expansibility_factor": coefficient(0.98, "EPS-STEP98"),
    }


def test_iso_adapter_is_discoverable_and_fail_closed() -> None:
    assert DP_FLOW_DISCOVERY_ENTRIES == (
        ISO_5167_2_ADAPTER,
        ISO_5167_3_ADAPTER,
        ISO_5167_4_ADAPTER,
    )
    assert all(
        adapter.lifecycle_status is MethodLifecycleStatus.STANDARDS_REVIEW
        and adapter.executable is False
        and adapter.conformity_claimed is False
        for adapter in DP_FLOW_DISCOVERY_ENTRIES
    )
    assert "No ISO coefficient correlation" in ISO_5167_2_ADAPTER.boundary
    assert "No protected nozzle correlation" in ISO_5167_3_ADAPTER.boundary
    assert "No protected Venturi correlation" in ISO_5167_4_ADAPTER.boundary


def test_generic_orifice_reference_vector() -> None:
    values = inputs()
    result = calculate_generic_orifice_flow(**values)
    beta = 0.5
    expected = 0.61 * (pi * 0.05**2 / 4.0) * sqrt(2.0 * 10_000.0 * 998.2) / sqrt(1.0 - beta**4)
    assert result.mass_flow_kg_s == pytest.approx(expected, rel=1e-12)
    assert result.actual_volumetric_flow_m3_s == pytest.approx(expected / 998.2)
    assert result.beta_ratio == pytest.approx(beta)
    assert result.standards_conformity_claimed is False
    assert result.calculation_basis == "caller-supplied traceable coefficients"


def test_reynolds_number_uses_pipe_diameter_and_flowing_viscosity() -> None:
    result = calculate_generic_orifice_flow(**inputs())
    expected = 4.0 * result.mass_flow_kg_s / (pi * 0.1 * 1.002e-3)
    assert result.pipe_reynolds_number == pytest.approx(expected)


@pytest.mark.parametrize(
    ("field", "value"),
    (("pipe_inside_diameter_m", 0.0), ("bore_diameter_m", -1.0), ("differential_pressure_pa", float("nan"))),
)
def test_invalid_scalar_input_fails_closed(field: str, value: float) -> None:
    values = inputs()
    values[field] = value
    with pytest.raises(DPFlowInputError):
        calculate_generic_orifice_flow(**values)


def test_bore_equal_to_pipe_is_blocked() -> None:
    values = inputs()
    values["bore_diameter_m"] = values["pipe_inside_diameter_m"]
    applicability = assess_generic_orifice_applicability(**values)
    assert applicability.applicable is False
    assert applicability.standards_conformity_claimed is False
    with pytest.raises(DPFlowInputError, match="smaller"):
        calculate_generic_orifice_flow(**values)


def test_expansibility_above_one_is_blocked() -> None:
    values = inputs()
    values["expansibility_factor"] = coefficient(1.0001, "EPS-INVALID")
    with pytest.raises(DPFlowInputError, match="cannot exceed"):
        calculate_generic_orifice_flow(**values)


@pytest.mark.parametrize("value", (0.0, -1.0, float("inf"), float("nan")))
def test_coefficient_requires_finite_positive_value(value: float) -> None:
    with pytest.raises(ValidationError):
        coefficient(value, "INVALID")


def test_coefficient_requires_traceability() -> None:
    with pytest.raises(ValidationError):
        TraceableCoefficient(value=0.61, source_reference="", applicable_conditions="", supplied_by="")


def test_fluid_properties_are_condition_specific_and_positive() -> None:
    with pytest.raises(ValidationError):
        FlowingFluidProperties(
            density_kg_m3=0.0,
            dynamic_viscosity_pa_s=1e-3,
            pressure_absolute_pa=100_000.0,
            temperature_k=300.0,
            phase="liquid",
            property_source_reference="record",
            condition_basis="flowing condition",
        )


def test_reference_conditions_are_explicit_and_immutable() -> None:
    reference = FlowReferenceConditions(
        pressure_absolute_pa=101_325.0,
        temperature_k=288.15,
        compressibility_factor=1.0,
        reference_name="project normal condition",
        source_reference="controlled project basis PB-001",
    )
    assert reference.pressure_absolute_pa == 101_325.0
    with pytest.raises((ValidationError, TypeError)):
        reference.temperature_k = 273.15  # type: ignore[misc]


def test_solver_recovers_known_bore() -> None:
    values = inputs()
    target = calculate_generic_orifice_flow(**values).mass_flow_kg_s
    result = solve_orifice_bore_for_mass_flow(
        target_mass_flow_kg_s=target,
        pipe_inside_diameter_m=0.1,
        differential_pressure_pa=10_000.0,
        fluid=fluid(),
        discharge_coefficient=coefficient(0.61, "CD-001"),
        expansibility_factor=coefficient(1.0, "EPS-001"),
        minimum_bore_diameter_m=0.01,
        maximum_bore_diameter_m=0.09,
    )
    assert result.converged is True
    assert result.bore_diameter_m == pytest.approx(0.05, rel=1e-8)
    assert result.relative_error <= 1e-9
    assert result.iterations <= 96
    assert result.standards_conformity_claimed is False


def test_solver_rejects_unbracketed_target() -> None:
    with pytest.raises(DPFlowConvergenceError, match="not bracketed"):
        solve_orifice_bore_for_mass_flow(
            target_mass_flow_kg_s=1e9,
            pipe_inside_diameter_m=0.1,
            differential_pressure_pa=10_000.0,
            fluid=fluid(),
            discharge_coefficient=coefficient(0.61, "CD"),
            expansibility_factor=coefficient(1.0, "EPS"),
            minimum_bore_diameter_m=0.01,
            maximum_bore_diameter_m=0.09,
        )


@pytest.mark.parametrize("iterations", (0, MAX_SOLVER_ITERATIONS + 1, True, 1.5))
def test_solver_iteration_limit_is_strict(iterations: object) -> None:
    with pytest.raises(DPFlowInputError, match="maximum iterations"):
        solve_orifice_bore_for_mass_flow(
            target_mass_flow_kg_s=1.0,
            pipe_inside_diameter_m=0.1,
            differential_pressure_pa=10_000.0,
            fluid=fluid(),
            discharge_coefficient=coefficient(0.61, "CD"),
            expansibility_factor=coefficient(1.0, "EPS"),
            minimum_bore_diameter_m=0.01,
            maximum_bore_diameter_m=0.09,
            maximum_iterations=iterations,  # type: ignore[arg-type]
        )


def test_solver_never_returns_false_convergence() -> None:
    target = calculate_generic_orifice_flow(**inputs()).mass_flow_kg_s
    with pytest.raises(DPFlowConvergenceError, match="did not converge"):
        solve_orifice_bore_for_mass_flow(
            target_mass_flow_kg_s=target,
            pipe_inside_diameter_m=0.1,
            differential_pressure_pa=10_000.0,
            fluid=fluid(),
            discharge_coefficient=coefficient(0.61, "CD"),
            expansibility_factor=coefficient(1.0, "EPS"),
            minimum_bore_diameter_m=0.01,
            maximum_bore_diameter_m=0.08,
            relative_tolerance=1e-15,
            maximum_iterations=1,
        )


@pytest.mark.parametrize(
    ("calculator", "primary_element"),
    (
        (calculate_generic_nozzle_flow, "flow_nozzle"),
        (calculate_generic_venturi_nozzle_flow, "venturi_nozzle"),
        (calculate_generic_venturi_tube_flow, "venturi_tube"),
    ),
)
def test_step98_circular_element_reference_vectors(
    calculator: object,
    primary_element: str,
) -> None:
    result = calculator(**circular_inputs())  # type: ignore[operator]
    assert isinstance(result, CircularRestrictionFlowResult)
    expected = (
        0.61
        * 0.98
        * (pi * 0.05**2 / 4.0)
        * sqrt(2.0 * 10_000.0 * 998.2)
        / sqrt(1.0 - 0.5**4)
    )
    assert result.primary_element == primary_element
    assert result.mass_flow_kg_s == pytest.approx(expected, rel=1e-12)
    assert result.actual_volumetric_flow_m3_s == pytest.approx(expected / 998.2)
    assert result.beta_ratio == pytest.approx(0.5)
    assert result.discharge_coefficient_used == pytest.approx(0.61)
    assert result.expansibility_factor_used == pytest.approx(0.98)
    assert result.standards_conformity_claimed is False
    assert any("does not establish standards conformity" in item for item in result.warnings)


def test_direct_circular_element_boundary_rejects_unknown_element() -> None:
    with pytest.raises(DPFlowInputError, match="primary element"):
        calculate_generic_circular_restriction_flow(
            primary_element="unknown",  # type: ignore[arg-type]
            **circular_inputs(),
        )


def test_high_discharge_coefficient_warning_is_not_discarded() -> None:
    values = inputs()
    values["discharge_coefficient"] = coefficient(2.1, "CD-REVIEW")
    result = calculate_generic_orifice_flow(**values)
    assert any("unusually high" in warning for warning in result.warnings)


def test_generic_averaging_pitot_reference_vector() -> None:
    result = calculate_generic_averaging_pitot_flow(
        pipe_inside_diameter_m=0.1,
        differential_pressure_pa=2_500.0,
        fluid=fluid(),
        meter_coefficient=coefficient(0.72, "K-APT"),
        expansibility_factor=coefficient(0.98, "EPS-APT"),
    )
    assert isinstance(result, AveragingPitotFlowResult)
    area = pi * 0.1**2 / 4.0
    expected_volume = 0.72 * 0.98 * area * sqrt(2.0 * 2_500.0 / 998.2)
    expected_mass = expected_volume * 998.2
    assert result.pipe_area_m2 == pytest.approx(area)
    assert result.actual_volumetric_flow_m3_s == pytest.approx(expected_volume)
    assert result.mass_flow_kg_s == pytest.approx(expected_mass)
    assert result.mean_velocity_m_s == pytest.approx(expected_volume / area)
    assert result.pipe_reynolds_number == pytest.approx(
        998.2 * (expected_volume / area) * 0.1 / 1.002e-3
    )
    assert result.meter_coefficient_used == pytest.approx(0.72)
    assert result.expansibility_factor_used == pytest.approx(0.98)
    assert result.standards_conformity_claimed is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("pipe_inside_diameter_m", 0.0),
        ("pipe_inside_diameter_m", True),
        ("pipe_inside_diameter_m", "0.1"),
        ("pipe_inside_diameter_m", 1.0e308),
        ("differential_pressure_pa", float("inf")),
    ),
)
def test_averaging_pitot_scalar_inputs_fail_closed(field: str, value: object) -> None:
    values: dict[str, object] = {
        "pipe_inside_diameter_m": 0.1,
        "differential_pressure_pa": 2_500.0,
        "fluid": fluid(),
        "meter_coefficient": coefficient(0.72, "K-APT"),
        "expansibility_factor": coefficient(0.98, "EPS-APT"),
    }
    values[field] = value
    with pytest.raises(DPFlowInputError):
        calculate_generic_averaging_pitot_flow(**values)  # type: ignore[arg-type]


def test_dp_transmitter_range_screen_reports_low_signal() -> None:
    result = screen_dp_transmitter_range(
        minimum_dp_pa=100.0,
        normal_dp_pa=2_500.0,
        maximum_dp_pa=10_000.0,
        configured_lrv_pa=0.0,
        configured_urv_pa=10_000.0,
        sensor_lrl_pa=-500.0,
        sensor_url_pa=15_000.0,
        minimum_required_dp_fraction_of_span=0.02,
    )
    assert result.configured_span_pa == pytest.approx(10_000.0)
    assert result.minimum_required_dp_fraction_of_span == pytest.approx(0.02)
    assert result.configured_range_within_sensor_limits is True
    assert result.operating_cases_within_configured_range is True
    assert result.minimum_dp_fraction_of_span == pytest.approx(0.01)
    assert result.minimum_flow_fraction_of_span == pytest.approx(0.1)
    assert result.inferred_flow_turndown == pytest.approx(10.0)
    assert result.low_flow_signal_adequate is False
    assert result.screen_passed is False
    assert result.blocking_reasons == (
        "minimum DP signal is below the supplied fraction-of-span requirement",
    )


def test_dp_transmitter_zero_minimum_has_no_finite_turndown() -> None:
    result = screen_dp_transmitter_range(
        minimum_dp_pa=0.0,
        normal_dp_pa=2_500.0,
        maximum_dp_pa=10_000.0,
        configured_lrv_pa=0.0,
        configured_urv_pa=10_000.0,
        sensor_lrl_pa=-500.0,
        sensor_url_pa=15_000.0,
        minimum_required_dp_fraction_of_span=0.0,
    )
    assert result.minimum_dp_fraction_of_span == 0.0
    assert result.minimum_flow_fraction_of_span == 0.0
    assert result.inferred_flow_turndown is None
    assert result.screen_passed is True


def test_dp_transmitter_range_reports_capability_failures() -> None:
    result = screen_dp_transmitter_range(
        minimum_dp_pa=100.0,
        normal_dp_pa=2_500.0,
        maximum_dp_pa=12_000.0,
        configured_lrv_pa=0.0,
        configured_urv_pa=10_000.0,
        sensor_lrl_pa=100.0,
        sensor_url_pa=15_000.0,
        minimum_required_dp_fraction_of_span=0.01,
    )
    assert result.configured_range_within_sensor_limits is False
    assert result.operating_cases_within_configured_range is False
    assert result.low_flow_signal_adequate is True
    assert result.screen_passed is False
    assert len(result.blocking_reasons) == 2


@pytest.mark.parametrize(
    "overrides",
    (
        {"minimum_dp_pa": 3_000.0, "normal_dp_pa": 2_500.0},
        {"maximum_dp_pa": 0.0, "normal_dp_pa": 0.0, "minimum_dp_pa": 0.0},
        {"configured_lrv_pa": -100.0},
        {"configured_urv_pa": 0.0},
        {"sensor_lrl_pa": 15_000.0},
        {"minimum_required_dp_fraction_of_span": 1.1},
        {"minimum_required_dp_fraction_of_span": True},
    ),
)
def test_dp_transmitter_range_invalid_contract_fails_closed(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "minimum_dp_pa": 100.0,
        "normal_dp_pa": 2_500.0,
        "maximum_dp_pa": 10_000.0,
        "configured_lrv_pa": 0.0,
        "configured_urv_pa": 10_000.0,
        "sensor_lrl_pa": -500.0,
        "sensor_url_pa": 15_000.0,
        "minimum_required_dp_fraction_of_span": 0.01,
    }
    values.update(overrides)
    with pytest.raises(DPFlowInputError):
        screen_dp_transmitter_range(**values)  # type: ignore[arg-type]


def test_permanent_pressure_loss_uses_traceable_supplied_ratio() -> None:
    ratio = coefficient(0.35, "LOSS-RATIO")
    result = calculate_permanent_pressure_loss(
        measured_differential_pressure_pa=12_000.0,
        permanent_loss_ratio=ratio,
    )
    assert result.permanent_pressure_loss_pa == pytest.approx(4_200.0)
    assert result.permanent_loss_ratio_used == pytest.approx(0.35)
    assert result.source_reference == ratio.source_reference
    assert result.applicable_conditions == ratio.applicable_conditions
    assert result.supplied_by == ratio.supplied_by
    assert result.standards_conformity_claimed is False
    zero = calculate_permanent_pressure_loss(
        measured_differential_pressure_pa=0.0,
        permanent_loss_ratio=ratio,
    )
    assert zero.permanent_pressure_loss_pa == 0.0


@pytest.mark.parametrize("value", (-1.0, float("nan"), True, None))
def test_permanent_pressure_loss_invalid_dp_fails_closed(value: object) -> None:
    with pytest.raises(DPFlowInputError):
        calculate_permanent_pressure_loss(
            measured_differential_pressure_pa=value,  # type: ignore[arg-type]
            permanent_loss_ratio=coefficient(0.35, "LOSS-RATIO"),
        )


def test_permanent_pressure_loss_rejects_ratio_above_one() -> None:
    with pytest.raises(DPFlowInputError, match="cannot exceed"):
        calculate_permanent_pressure_loss(
            measured_differential_pressure_pa=1_000.0,
            permanent_loss_ratio=coefficient(1.01, "LOSS-RATIO"),
        )


def uncertainty_component(
    component_id: str,
    uncertainty_percent: float,
    sensitivity: float,
) -> RelativeUncertaintyComponent:
    return RelativeUncertaintyComponent(
        component_id=component_id,
        relative_standard_uncertainty_percent=uncertainty_percent,
        sensitivity_coefficient=sensitivity,
        source_reference=f"controlled uncertainty record {component_id}",
    )


def test_relative_uncertainty_rss_reference_vector() -> None:
    components = (
        uncertainty_component("component-3", 3.0, 1.0),
        uncertainty_component("component-4", 4.0, -1.0),
    )
    result = combine_dp_flow_relative_uncertainty(components=components)
    assert result.combined_relative_standard_uncertainty_percent == pytest.approx(5.0)
    assert result.coverage_factor == pytest.approx(2.0)
    assert result.expanded_relative_uncertainty_percent == pytest.approx(10.0)
    assert result.component_count == 2
    assert result.components == components
    assert result.independence_assumed is True
    assert result.standards_conformity_claimed is False


def test_relative_uncertainty_contract_fails_closed() -> None:
    component = uncertainty_component("component-a", 1.0, 1.0)
    with pytest.raises(DPFlowInputError, match="ordered tuple"):
        combine_dp_flow_relative_uncertainty(components=[component])  # type: ignore[arg-type]
    with pytest.raises(DPFlowInputError, match="unique"):
        combine_dp_flow_relative_uncertainty(
            components=(
                component,
                uncertainty_component("COMPONENT-A", 2.0, 1.0),
            )
        )
    with pytest.raises(DPFlowInputError, match="one through 64"):
        combine_dp_flow_relative_uncertainty(
            components=tuple(
                uncertainty_component(f"component-{index}", 1.0, 1.0)
                for index in range(65)
            )
        )
    with pytest.raises(DPFlowInputError, match="coverage factor"):
        combine_dp_flow_relative_uncertainty(
            components=(component,),
            coverage_factor=float("inf"),
        )


@pytest.mark.parametrize(
    "values",
        (
            {"component_id": "component", "relative_standard_uncertainty_percent": -1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": " component ", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": " component", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": "component ", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": "\tcomponent\n", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": 123, "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": "component", "relative_standard_uncertainty_percent": True, "sensitivity_coefficient": 1.0, "source_reference": "record"},
            {"component_id": "component", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": True, "source_reference": "record"},
            {"component_id": "component", "relative_standard_uncertainty_percent": 1.0, "sensitivity_coefficient": float("nan"), "source_reference": "record"},
        ),
)
def test_uncertainty_component_validation(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RelativeUncertaintyComponent(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_reference", "   "),
        ("applicable_conditions", "   "),
        ("supplied_by", "  "),
    ),
)
def test_coefficient_rejects_whitespace_traceability(field: str, value: str) -> None:
    values = {
        "value": 0.61,
        "source_reference": "controlled record",
        "applicable_conditions": "exact service",
        "supplied_by": "engineer",
    }
    values[field] = value
    with pytest.raises(ValidationError):
        TraceableCoefficient(**values)  # type: ignore[arg-type]
    values[field] = "controlled record"
    values["value"] = True
    with pytest.raises(ValidationError):
        TraceableCoefficient(**values)  # type: ignore[arg-type]


def test_fluid_and_reference_models_reject_whitespace_traceability() -> None:
    fluid_values = fluid().model_dump()
    fluid_values["property_source_reference"] = "   "
    with pytest.raises(ValidationError):
        FlowingFluidProperties(**fluid_values)
    fluid_values = fluid().model_dump()
    fluid_values["density_kg_m3"] = True
    with pytest.raises(ValidationError):
        FlowingFluidProperties(**fluid_values)
    with pytest.raises(ValidationError):
        FlowReferenceConditions(
            pressure_absolute_pa=101_325.0,
            temperature_k=288.15,
            compressibility_factor=1.0,
            reference_name="  ",
            source_reference="controlled record",
        )


def test_no_conformity_contracts_are_structural() -> None:
    orifice = calculate_generic_orifice_flow(**inputs())
    with pytest.raises(ValidationError):
        OrificeFlowResult(
            **{
                **orifice.model_dump(),
                "standards_conformity_claimed": True,
            }
        )
    with pytest.raises(ValidationError):
        StandardsAdapterMetadata(
            **{
                **ISO_5167_2_ADAPTER.model_dump(),
                "conformity_claimed": True,
            }
        )
    with pytest.raises(ValidationError):
        StandardsAdapterMetadata(
            **{
                **ISO_5167_2_ADAPTER.model_dump(),
                "lifecycle_status": MethodLifecycleStatus.APPROVED,
            }
        )


def test_step98_exact_version_registry_is_immutable_and_callable() -> None:
    expected_keys = {
        (GENERIC_NOZZLE_METHOD_ID, GENERIC_NOZZLE_METHOD_VERSION),
        (GENERIC_VENTURI_NOZZLE_METHOD_ID, GENERIC_VENTURI_NOZZLE_METHOD_VERSION),
        (GENERIC_VENTURI_TUBE_METHOD_ID, GENERIC_VENTURI_TUBE_METHOD_VERSION),
        (GENERIC_AVERAGING_PITOT_METHOD_ID, GENERIC_AVERAGING_PITOT_METHOD_VERSION),
        (DP_TRANSMITTER_RANGE_METHOD_ID, DP_TRANSMITTER_RANGE_METHOD_VERSION),
        (PERMANENT_PRESSURE_LOSS_METHOD_ID, PERMANENT_PRESSURE_LOSS_METHOD_VERSION),
        (DP_FLOW_UNCERTAINTY_METHOD_ID, DP_FLOW_UNCERTAINTY_METHOD_VERSION),
    }
    assert set(DP_FLOW_METHOD_REGISTRY) == expected_keys
    assert set(DP_FLOW_METHOD_IMPLEMENTATIONS) == expected_keys
    assert len(DP_FLOW_METHOD_REGISTRY) == 7
    implementation_names: set[str] = set()
    for key, adapter in DP_FLOW_METHOD_REGISTRY.items():
        implementation = DP_FLOW_METHOD_IMPLEMENTATIONS[key]
        assert key == (adapter.method_id, adapter.method_version)
        assert adapter.lifecycle_status is MethodLifecycleStatus.APPROVED
        assert adapter.executable is True
        assert adapter.standards_conformity_claimed is False
        assert implementation is getattr(dp_flow_module, adapter.implementation_name)
        implementation_names.add(adapter.implementation_name)
    assert len(implementation_names) == 7
    with pytest.raises(KeyError):
        _ = DP_FLOW_METHOD_REGISTRY[(GENERIC_NOZZLE_METHOD_ID, "9.9.9")]
    with pytest.raises(TypeError):
        DP_FLOW_METHOD_REGISTRY[("new", "1.0.0")] = next(  # type: ignore[index]
            iter(DP_FLOW_METHOD_REGISTRY.values())
        )


def test_package_exports_step99_hardening_boundary() -> None:
    from app.engineering import calculations

    assert calculations.FOUNDATION_VERSION == "0.6.0"
    assert calculations.ISO_5167_2_ADAPTER.executable is False
    assert calculations.ISO_5167_3_ADAPTER.executable is False
    assert calculations.ISO_5167_4_ADAPTER.executable is False
    assert calculations.DP_FLOW_CALCULATORS_VERSION == "1.1.1"
    assert len(calculations.DP_FLOW_METHOD_REGISTRY) == 7
    assert len(calculations.ENGINEERING_METHOD_REGISTRY.definitions) == 26
    assert calculations.EXECUTABLE_METHODS_ENABLED is True
