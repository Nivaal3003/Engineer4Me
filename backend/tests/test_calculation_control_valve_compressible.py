"""Focused acceptance tests for Step 101 compressible valve sizing."""

from __future__ import annotations

import ast
import inspect
from decimal import Decimal
from math import nextafter
from types import MappingProxyType

import pytest
from pydantic import ValidationError

import app.engineering.calculations.control_valve_compressible as module
from app.engineering.calculations.control_valve import (
    ControlValveInputError,
    ValveInstallationBasis,
)
from app.engineering.calculations.control_valve_compressible import (
    COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION,
    COMPRESSIBLE_CONTROL_VALVE_DISCOVERY_ENTRIES,
    COMPRESSIBLE_CONTROL_VALVE_EXECUTABLE_ADAPTERS,
    COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS,
    COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY,
    COMPRESSIBLE_CONTROL_VALVE_METHOD_VERSION,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
    IEC_60534_2_1_COMPRESSIBLE_ADAPTER,
    CompressibleControlValvePressureState,
    CompressibleControlValveSizingInput,
    CompressibleControlValveSizingResult,
    CompressibleFlowingProperties,
    CompressibleFluidPhase,
    CompressibleValveFlowRegime,
    EligibleSteamState,
    TraceableCompressibleValveFactors,
    assess_compressible_control_valve_regime,
    build_compressible_control_valve_input_fingerprint_payload,
    build_compressible_control_valve_result_fingerprint_payload,
    canonical_compressible_control_valve_fingerprint_bytes,
    fingerprint_compressible_control_valve_payload,
    size_compressible_control_valve,
)
from app.engineering.calculations.models import MethodLifecycleStatus


def factors(
    *,
    x_t: float = 0.5,
    candidate_id: str = "CV-G-100",
    trim_id: str = "TRIM-G-100",
    travel_percent: float = 100.0,
) -> TraceableCompressibleValveFactors:
    return TraceableCompressibleValveFactors(
        candidate_id=candidate_id,
        trim_id=trim_id,
        installation_context_id="INSTALLATION-101",
        travel_percent=travel_percent,
        flow_direction="flow to open",
        installation_basis=ValveInstallationBasis.BARE_VALVE,
        bare_valve_pressure_drop_ratio_factor=x_t,
        source_reference="controlled candidate factor record XT-101",
        applicable_conditions=(
            "exact valve, trim, travel, direction, and bare-valve arrangement"
        ),
        supplied_by="competent control-valve engineer",
    )


def installed_factors(
    *,
    f_p: float = 0.9,
    x_tp: float = 0.55,
) -> TraceableCompressibleValveFactors:
    return TraceableCompressibleValveFactors(
        candidate_id="CV-G-200",
        trim_id="TRIM-G-200",
        installation_context_id="INSTALLATION-200",
        travel_percent=100.0,
        flow_direction="flow to close",
        installation_basis=ValveInstallationBasis.ATTACHED_FITTINGS,
        piping_geometry_factor=f_p,
        installed_pressure_drop_ratio_factor=x_tp,
        source_reference="controlled candidate record FP-XTP-101",
        applicable_conditions=(
            "exact valve, trim, travel, direction, reducers, and expanders"
        ),
        supplied_by="competent control-valve engineer",
    )


def gas_properties(
    *,
    phase: CompressibleFluidPhase = CompressibleFluidPhase.GAS,
    density: float = 10.0,
    gamma: float = 1.4,
) -> CompressibleFlowingProperties:
    return CompressibleFlowingProperties(
        fluid_phase=phase,
        fluid_identity="controlled nitrogen basis",
        upstream_temperature_k=300.0,
        upstream_density_kg_m3=density,
        isentropic_exponent=gamma,
        compressibility_factor=1.0,
        molecular_mass_kg_kmol=28.0134,
        property_source_reference="controlled property record PROP-101",
        condition_basis="all properties at the declared upstream P1 and T1 state",
    )


def steam_properties(
    *,
    state: EligibleSteamState = EligibleSteamState.DRY_SATURATED,
    temperature_k: float = 423.15,
    saturation_temperature_k: float = 423.15,
    saturation_pressure_absolute_pa: float = 475_000.0,
    uncertainty_k: float = 0.1,
    pressure_uncertainty_pa: float = 100.0,
    saturation_pair_confirmed: bool = True,
    quality: float | None = 1.0,
    density: float = 2.54,
    gamma: float = 1.3,
    liquid_absent: bool = True,
) -> CompressibleFlowingProperties:
    return CompressibleFlowingProperties(
        fluid_phase=CompressibleFluidPhase.STEAM,
        fluid_identity="ordinary-water steam",
        upstream_temperature_k=temperature_k,
        upstream_density_kg_m3=density,
        isentropic_exponent=gamma,
        compressibility_factor=0.98,
        molecular_mass_kg_kmol=18.01528,
        property_source_reference="controlled steam property record STEAM-101",
        condition_basis="properties at the declared upstream steam state",
        steam_state=state,
        steam_quality_fraction=quality,
        saturation_temperature_k=saturation_temperature_k,
        saturation_pressure_absolute_pa=saturation_pressure_absolute_pa,
        state_uncertainty_k=uncertainty_k,
        state_pressure_uncertainty_pa=pressure_uncertainty_pa,
        saturation_state_pair_confirmed=saturation_pair_confirmed,
        entrained_liquid_absent_confirmed=liquid_absent,
    )


def pressure_state(
    *,
    p1_pa: float = 1_000_000.0,
    p2_pa: float = 800_000.0,
) -> CompressibleControlValvePressureState:
    return CompressibleControlValvePressureState(
        upstream_pressure_absolute_pa=p1_pa,
        downstream_pressure_absolute_pa=p2_pa,
        pressure_basis="absolute",
        pressure_source_reference="controlled operating case OP-101",
        condition_basis="simultaneous steady upstream and downstream pressures",
    )


def sizing_input(
    *,
    mass_flow_kg_h: float = 10_000.0,
    p1_pa: float = 1_000_000.0,
    p2_pa: float = 800_000.0,
    properties: CompressibleFlowingProperties | None = None,
    supplied_factors: TraceableCompressibleValveFactors | None = None,
    case_id: str = "CV-STEP101-GAS-V1",
    **confirmations: bool,
) -> CompressibleControlValveSizingInput:
    values = {
        "turbulent_flow_confirmed": True,
        "homogeneous_composition_confirmed": True,
        "single_phase_inlet_confirmed": True,
        "single_phase_outlet_confirmed": True,
        "no_condensation_or_phase_change_confirmed": True,
        "property_state_aligned_confirmed": True,
    }
    values.update(confirmations)
    return CompressibleControlValveSizingInput(
        case_id=case_id,
        mass_flow_kg_h=mass_flow_kg_h,
        mass_flow_source_reference="controlled mass-flow record FLOW-101",
        flow_condition_basis="steady mass rate at the declared flowing condition",
        pressure_state=pressure_state(p1_pa=p1_pa, p2_pa=p2_pa),
        properties=properties or gas_properties(),
        factors=supplied_factors or factors(),
        **values,
    )


def result_with(**values: object) -> CompressibleControlValveSizingResult:
    return size_compressible_control_valve(sizing_input(**values))


def test_independent_density_reference_vector_is_exactly_reproduced() -> None:
    result = result_with()
    assert result.regime.actual_pressure_drop_ratio == 0.2
    assert result.regime.terminal_pressure_drop_ratio == 0.5
    assert result.regime.sizing_pressure_drop_ratio == 0.2
    assert result.regime.expansion_factor == pytest.approx(0.8666666666666667)
    assert result.required_cv == pytest.approx(94.5083676035414, rel=1e-14)
    assert result.required_kv == pytest.approx(81.74762622939043, rel=1e-14)
    assert result.reconstructed_mass_flow_kg_h == 10_000.0
    assert result.relative_round_trip_residual <= 1e-15
    assert result.regime.flow_regime is CompressibleValveFlowRegime.SUBCRITICAL
    assert result.regime.choked is False


def test_exact_choke_boundary_is_choked_and_y_is_two_thirds() -> None:
    result = result_with(p2_pa=500_000.0)
    assert result.regime.actual_pressure_drop_ratio == 0.5
    assert result.regime.choked is True
    assert result.regime.flow_regime is CompressibleValveFlowRegime.CHOKED
    assert result.regime.expansion_factor == pytest.approx(2.0 / 3.0)


def test_choked_capacity_plateaus_below_terminal_downstream_pressure() -> None:
    at_boundary = result_with(p2_pa=500_000.0)
    below_boundary = result_with(p2_pa=100_000.0)
    assert below_boundary.required_cv == at_boundary.required_cv
    assert below_boundary.required_kv == at_boundary.required_kv
    assert below_boundary.regime.sizing_pressure_drop_ratio == 0.5


def test_nextafter_values_classify_each_side_of_choke_boundary() -> None:
    p1 = 1_000_000.0
    boundary_p2 = 500_000.0
    subcritical = result_with(p1_pa=p1, p2_pa=nextafter(boundary_p2, p1))
    choked = result_with(p1_pa=p1, p2_pa=nextafter(boundary_p2, 0.0))
    assert subcritical.regime.choked is False
    assert subcritical.regime.expansion_factor > 2.0 / 3.0
    assert choked.regime.choked is True
    assert choked.regime.expansion_factor == pytest.approx(2.0 / 3.0)


def test_independent_installed_reference_vector() -> None:
    result = result_with(
        mass_flow_kg_h=2_500.0,
        p1_pa=2_000_000.0,
        p2_pa=1_500_000.0,
        properties=gas_properties(density=8.0, gamma=1.25),
        supplied_factors=installed_factors(),
    )
    assert result.regime.terminal_pressure_drop_ratio == pytest.approx(
        0.49107142857142866
    )
    assert result.regime.expansion_factor == pytest.approx(0.8303030303030303)
    assert result.required_cv == pytest.approx(19.37618326930439, rel=1e-14)
    assert result.required_kv == pytest.approx(16.759965575703266, rel=1e-14)


def test_official_valmet_steam_vector_preserves_rounded_reference() -> None:
    result = result_with(
        mass_flow_kg_h=7_000.0,
        p1_pa=475_000.0,
        p2_pa=425_000.0,
        properties=steam_properties(),
        supplied_factors=factors(x_t=0.41),
        case_id="VALMET-STEAM-REFERENCE",
    )
    assert result.regime.actual_pressure_drop_ratio == pytest.approx(
        0.10526315789473684
    )
    assert result.regime.terminal_pressure_drop_ratio == pytest.approx(
        0.3807142857142857
    )
    assert result.required_cv == pytest.approx(250.6256919020894, rel=1e-14)
    assert result.required_cv == pytest.approx(253.0, rel=0.011)


def test_dry_saturated_and_superheated_steam_are_eligible() -> None:
    dry = result_with(
        p1_pa=475_000.0,
        p2_pa=425_000.0,
        properties=steam_properties(),
        supplied_factors=factors(x_t=0.7),
    )
    superheated = result_with(
        p1_pa=475_000.0,
        p2_pa=425_000.0,
        properties=steam_properties(
            state=EligibleSteamState.SUPERHEATED,
            temperature_k=450.0,
            saturation_temperature_k=423.15,
            uncertainty_k=1.0,
            quality=None,
        ),
        supplied_factors=factors(x_t=0.7),
    )
    assert (
        dry.normalized_input.properties.steam_state is EligibleSteamState.DRY_SATURATED
    )
    assert (
        superheated.normalized_input.properties.steam_state
        is EligibleSteamState.SUPERHEATED
    )


def test_supercritical_water_state_is_outside_eligible_steam_boundary() -> None:
    with pytest.raises(ValidationError, match="critical pressure"):
        sizing_input(
            p1_pa=22_064_000.0,
            p2_pa=20_000_000.0,
            properties=steam_properties(
                saturation_pressure_absolute_pa=22_064_000.0,
                pressure_uncertainty_pa=1.0,
            ),
        )


def test_steam_saturation_pressure_must_numerically_bind_to_p1() -> None:
    with pytest.raises(ValidationError, match="coherent with upstream P1"):
        sizing_input(
            p1_pa=1_000_000.0,
            p2_pa=800_000.0,
            properties=steam_properties(),
        )


def test_steam_saturation_temperature_pressure_pair_requires_confirmation() -> None:
    with pytest.raises(ValidationError, match="pair coherence"):
        steam_properties(saturation_pair_confirmed=False)


@pytest.mark.parametrize("saturation_temperature_k", (273.15, 647.096, 700.0))
def test_nonphysical_water_saturation_temperatures_fail_closed(
    saturation_temperature_k: float,
) -> None:
    with pytest.raises(ValidationError, match="triple and critical"):
        steam_properties(saturation_temperature_k=saturation_temperature_k)


@pytest.mark.parametrize(
    "changes",
    (
        {"quality": 0.99},
        {"quality": None},
        {"liquid_absent": False},
        {
            "temperature_k": 424.0,
            "saturation_temperature_k": 423.15,
            "uncertainty_k": 0.1,
        },
    ),
)
def test_dry_saturated_steam_rejects_wet_or_incoherent_state(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        steam_properties(**changes)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    (
        {"quality": 1.0},
        {"temperature_k": 424.0, "uncertainty_k": 1.0, "quality": None},
        {"temperature_k": 423.0, "uncertainty_k": 0.1, "quality": None},
        {"liquid_absent": False, "quality": None},
    ),
)
def test_superheated_steam_requires_proven_superheat_margin(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "state": EligibleSteamState.SUPERHEATED,
        "temperature_k": 450.0,
        "quality": None,
    }
    values.update(changes)
    with pytest.raises(ValidationError):
        steam_properties(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (
        True,
        False,
        "0.5",
        Decimal("0.5"),
        float("nan"),
        float("inf"),
        float("-inf"),
        10**400,
    ),
)
def test_factor_raw_numeric_boundary_rejects_coercive_or_nonfinite_data(
    value: object,
) -> None:
    with pytest.raises((ValidationError, OverflowError)):
        TraceableCompressibleValveFactors(
            candidate_id="CV-X",
            trim_id="TRIM-X",
            installation_context_id="INSTALLATION-X",
            travel_percent=value,
            flow_direction="flow to open",
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_drop_ratio_factor=0.5,
            source_reference="controlled factor record",
            applicable_conditions="exact candidate and declared arrangement",
            supplied_by="valve engineer",
        )


@pytest.mark.parametrize("x_t", (0.0, -0.1, 0.8400000001))
def test_bare_factor_bounds_fail_closed(x_t: float) -> None:
    with pytest.raises(ValidationError):
        factors(x_t=x_t)


@pytest.mark.parametrize(
    ("f_p", "x_tp"),
    ((0.0, 0.5), (-0.1, 0.5), (1.01, 0.5), (0.9, 0.0), (0.9, -0.1), (0.9, 0.85)),
)
def test_installed_factor_bounds_fail_closed(f_p: float, x_tp: float) -> None:
    with pytest.raises(ValidationError):
        installed_factors(f_p=f_p, x_tp=x_tp)


def test_factor_arrangements_are_mutually_exclusive() -> None:
    with pytest.raises(ValidationError):
        TraceableCompressibleValveFactors(
            candidate_id="CV-X",
            trim_id="TRIM-X",
            installation_context_id="INSTALLATION-X",
            travel_percent=100.0,
            flow_direction="flow to open",
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_drop_ratio_factor=0.5,
            piping_geometry_factor=0.9,
            source_reference="controlled factor record",
            applicable_conditions="exact candidate and declared arrangement",
            supplied_by="valve engineer",
        )
    with pytest.raises(ValidationError):
        TraceableCompressibleValveFactors(
            candidate_id="CV-X",
            trim_id="TRIM-X",
            installation_context_id="INSTALLATION-X",
            travel_percent=100.0,
            flow_direction="flow to open",
            installation_basis=ValveInstallationBasis.ATTACHED_FITTINGS,
            piping_geometry_factor=0.9,
            source_reference="controlled factor record",
            applicable_conditions="exact candidate and declared arrangement",
            supplied_by="valve engineer",
        )


@pytest.mark.parametrize(
    ("p1", "p2"),
    ((0.0, -1.0), (100_000.0, 0.0), (100_000.0, 100_000.0), (100_000.0, 200_000.0)),
)
def test_absolute_pressure_order_is_strict(p1: float, p2: float) -> None:
    with pytest.raises(ValidationError):
        pressure_state(p1_pa=p1, p2_pa=p2)


@pytest.mark.parametrize(
    "field",
    (
        "turbulent_flow_confirmed",
        "homogeneous_composition_confirmed",
        "single_phase_inlet_confirmed",
        "single_phase_outlet_confirmed",
        "no_condensation_or_phase_change_confirmed",
        "property_state_aligned_confirmed",
    ),
)
def test_each_applicability_confirmation_is_mandatory(field: str) -> None:
    with pytest.raises(ValidationError):
        sizing_input(**{field: False})


@pytest.mark.parametrize(
    "phase", (CompressibleFluidPhase.GAS, CompressibleFluidPhase.VAPOUR)
)
def test_gas_and_vapour_are_both_explicitly_supported(
    phase: CompressibleFluidPhase,
) -> None:
    result = result_with(properties=gas_properties(phase=phase))
    assert result.normalized_input.properties.fluid_phase is phase


def test_nonsteam_cannot_smuggle_steam_state_fields() -> None:
    values = gas_properties().model_dump(mode="python")
    values["steam_state"] = EligibleSteamState.DRY_SATURATED
    values["steam_quality_fraction"] = 1.0
    values["saturation_temperature_k"] = 300.0
    values["state_uncertainty_k"] = 1.0
    values["entrained_liquid_absent_confirmed"] = True
    with pytest.raises(ValidationError):
        CompressibleFlowingProperties(**values)


def test_regime_public_boundary_revalidates_nested_models() -> None:
    with pytest.raises(ControlValveInputError):
        assess_compressible_control_valve_regime(
            pressure_state=object(),  # type: ignore[arg-type]
            properties=gas_properties(),
            factors=factors(),
        )


def test_regime_public_boundary_enforces_steam_critical_pressure() -> None:
    steam = steam_properties(
        saturation_temperature_k=600.0,
        saturation_pressure_absolute_pa=20_000_000.0,
        pressure_uncertainty_pa=15_000_000.0,
        temperature_k=600.0,
        uncertainty_k=0.1,
    )
    with pytest.raises(ControlValveInputError, match="critical pressure"):
        assess_compressible_control_valve_regime(
            pressure_state=pressure_state(p1_pa=30_000_000.0, p2_pa=29_000_000.0),
            properties=steam,
            factors=factors(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("effective_piping_geometry_factor", 999.0),
        ("effective_pressure_drop_ratio_factor", 999.0),
        ("specific_heat_ratio_factor", 999.0),
        ("sizing_pressure_drop_pa", 1.0),
    ),
)
def test_standalone_regime_model_rejects_forged_physics(
    field: str,
    value: float,
) -> None:
    regime = result_with().regime
    values = regime.model_dump(mode="python")
    values[field] = value
    with pytest.raises(ValidationError):
        type(regime).model_validate(values)


def test_result_fingerprint_is_deterministic_and_provenance_sensitive() -> None:
    first = result_with()
    second = result_with()
    changed = result_with(case_id="CV-STEP101-GAS-V2")
    assert first.input_fingerprint == second.input_fingerprint
    assert first.result_fingerprint == second.result_fingerprint
    assert changed.input_fingerprint != first.input_fingerprint
    assert changed.result_fingerprint != first.result_fingerprint


def test_canonical_payload_rejects_nonstring_mapping_keys_and_nonfinite_data() -> None:
    with pytest.raises(ControlValveInputError):
        canonical_compressible_control_valve_fingerprint_bytes({1: "bad"})
    with pytest.raises(ControlValveInputError):
        canonical_compressible_control_valve_fingerprint_bytes({"bad": float("nan")})


def test_public_hash_cannot_authorize_forged_capacity() -> None:
    result = result_with()
    values = result.model_dump(mode="python")
    values["required_cv"] = result.required_cv * 2.0
    values["result_fingerprint"] = fingerprint_compressible_control_valve_payload(
        build_compressible_control_valve_result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError, match="not reproducible"):
        CompressibleControlValveSizingResult.model_validate(values)


def test_public_hash_cannot_authorize_forged_regime() -> None:
    result = result_with()
    values = result.model_dump(mode="python")
    values["regime"]["choked"] = True
    values["regime"]["flow_regime"] = CompressibleValveFlowRegime.CHOKED
    values["result_fingerprint"] = fingerprint_compressible_control_valve_payload(
        build_compressible_control_valve_result_fingerprint_payload(values)
    )
    with pytest.raises(ValidationError):
        CompressibleControlValveSizingResult.model_validate(values)


def test_fingerprint_builders_have_version_bound_schemas() -> None:
    inputs = sizing_input()
    result = size_compressible_control_valve(inputs)
    input_payload = build_compressible_control_valve_input_fingerprint_payload(inputs)
    result_payload = build_compressible_control_valve_result_fingerprint_payload(result)
    assert input_payload["calculator_version"] == "1.0.0"
    assert input_payload["method_id"] == COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID
    assert str(input_payload["schema"]).endswith(".v1")
    assert str(result_payload["schema"]).endswith(".v1")
    assert "result_fingerprint" not in result_payload["result"]


def test_exact_version_registry_is_immutable_and_coherent() -> None:
    key = (
        COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
    )
    assert COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION == "1.0.0"
    assert COMPRESSIBLE_CONTROL_VALVE_METHOD_VERSION == "1.0.0"
    assert COMPRESSIBLE_CONTROL_VALVE_EXECUTABLE_ADAPTERS == (
        COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER,
    )
    assert isinstance(COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY, MappingProxyType)
    assert isinstance(
        COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS, MappingProxyType
    )
    assert COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY[key] is (
        COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER
    )
    assert COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS[key] is (
        size_compressible_control_valve
    )
    with pytest.raises(TypeError):
        COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY[key] = object()  # type: ignore[index]


def test_standards_adapter_is_inert_and_claims_no_conformity() -> None:
    assert COMPRESSIBLE_CONTROL_VALVE_DISCOVERY_ENTRIES == (
        IEC_60534_2_1_COMPRESSIBLE_ADAPTER,
    )
    assert IEC_60534_2_1_COMPRESSIBLE_ADAPTER.lifecycle_status is (
        MethodLifecycleStatus.STANDARDS_REVIEW
    )
    assert IEC_60534_2_1_COMPRESSIBLE_ADAPTER.executable is False
    assert IEC_60534_2_1_COMPRESSIBLE_ADAPTER.conformity_claimed is False
    assert IEC_60534_2_1_COMPRESSIBLE_ADAPTER.official_catalog_url.startswith(
        "https://webstore.iec.ch/"
    )


def test_preliminary_result_never_selects_or_clears_service() -> None:
    for result in (result_with(), result_with(p2_pa=100_000.0)):
        assert result.selection_ready is False
        assert result.independent_review_required is True
        assert result.manufacturer_selection_performed is False
        assert result.standards_conformity_claimed is False
        assert any("not final" in warning for warning in result.warnings)
        assert any("noise" in warning for warning in result.regime.warnings)


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
        "CompressibleControlValveSizingInput",
        "CompressibleControlValveSizingResult",
        "TraceableCompressibleValveFactors",
        "assess_compressible_control_valve_regime",
        "size_compressible_control_valve",
    }
    assert expected.issubset(set(module.__all__))
    assert all(hasattr(module, name) for name in module.__all__)
