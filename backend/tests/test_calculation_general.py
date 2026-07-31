"""Independent reference tests for Step 94 general calculations.

The vectors in this module are calculated independently from the production
implementation.  They exercise public typed functions and the reviewed
calculation-engine registrations.  Every physical state that could otherwise
be ambiguous is supplied explicitly.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from math import isclose
from math import nan
from math import pi
from uuid import UUID

from pydantic import ValidationError
import pytest

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.general import (
    GENERAL_METHOD_REGISTRY,
)
from app.engineering.calculations.general import (
    actual_volume_from_mass_flow,
)
from app.engineering.calculations.general import (
    assess_dp_transmitter_range,
)
from app.engineering.calculations.general import (
    combine_independent_standard_uncertainties,
)
from app.engineering.calculations.general import convert_pressure
from app.engineering.calculations.general import (
    convert_referenced_gas_volume,
)
from app.engineering.calculations.general import (
    current_from_linear_fraction,
)
from app.engineering.calculations.general import (
    current_from_square_root_flow_fraction,
)
from app.engineering.calculations.general import dc_loop_voltage_budget
from app.engineering.calculations.general import (
    density_from_specific_gravity,
)
from app.engineering.calculations.general import (
    dynamic_viscosity_from_kinematic,
)
from app.engineering.calculations.general import (
    flow_fraction_from_square_root_signal,
)
from app.engineering.calculations.general import hydrostatic_pressure
from app.engineering.calculations.general import (
    kinematic_viscosity_from_dynamic,
)
from app.engineering.calculations.general import (
    linear_fraction_from_current,
)
from app.engineering.calculations.general import (
    mass_flow_from_actual_volume,
)
from app.engineering.calculations.general import (
    pipe_area_velocity_reynolds,
)
from app.engineering.calculations.general import pressure_head
from app.engineering.calculations.general import (
    propagate_independent_uncertainty,
)
from app.engineering.calculations.general import (
    specific_gravity_from_density,
)
from app.engineering.calculations.general import (
    square_root_flow_fraction_from_current,
)
from app.engineering.calculations.general import (
    square_root_signal_fraction_from_flow,
)
from app.engineering.calculations.general import (
    transmitter_linear_fraction,
)
from app.engineering.calculations.general import (
    transmitter_value_from_fraction,
)
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.units import CompressibilityTreatment
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import FlowReferenceBasis
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import ReferenceConditions
from app.engineering.calculations.units import ReferencedVolumetricFlow


FIXED_TIME = datetime(2026, 7, 31, 8, 0, tzinfo=UTC)
FIXED_REQUEST_ID = UUID("94000000-0000-4000-8000-000000000001")
FIXED_CALCULATION_ID = UUID("94000000-0000-4000-8000-000000000002")

EXPECTED_METHOD_IDS = (
    "general.density.from-specific-gravity",
    "general.density.to-specific-gravity",
    "general.flow.actual-volume-to-mass",
    "general.flow.mass-to-actual-volume",
    "general.flow.reference-state",
    "general.loop.dc-voltage-budget",
    "general.pipe.velocity-reynolds",
    "general.pressure.absolute-to-gauge",
    "general.pressure.gauge-to-absolute",
    "general.signal.4-20ma-to-percent",
    "general.signal.dp-square-root",
    "general.signal.flow-square",
    "general.signal.percent-to-4-20ma",
    "general.transmitter.dp-range",
    "general.uncertainty.independent-relative-rss",
    "general.viscosity.dynamic-to-kinematic",
    "general.viscosity.kinematic-to-dynamic",
)


def quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
    *,
    uncertainty: float | None = None,
    uncertainty_basis: str | None = None,
) -> EngineeringQuantity:
    """Build one explicit finite engineering quantity."""

    return EngineeringQuantity(
        quantity_kind=kind.value,
        value=value,
        unit=unit,
        uncertainty=uncertainty,
        uncertainty_basis=uncertainty_basis,
    )


def reference_conditions(
    reference_id: str,
    basis: FlowReferenceBasis,
    *,
    pressure: float,
    pressure_unit: str,
    temperature: float,
    temperature_unit: str,
    compressibility_factor: float | None = None,
) -> ReferenceConditions:
    """Build a fully explicit gas reference state."""

    return ReferenceConditions(
        reference_id=reference_id,
        basis=basis,
        absolute_pressure=quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            pressure,
            pressure_unit,
        ),
        absolute_temperature=quantity(
            QuantityKind.ABSOLUTE_TEMPERATURE,
            temperature,
            temperature_unit,
        ),
        compressibility_treatment=(
            CompressibilityTreatment.IDEAL_GAS
            if compressibility_factor is None
            else CompressibilityTreatment.SPECIFIED_FACTOR
        ),
        compressibility_factor=compressibility_factor,
    )


def referenced_flow(
    value: float = 100.0,
    unit: str = "m3/h",
) -> ReferencedVolumetricFlow:
    """Build the source state for the independent gas-flow vector."""

    return ReferencedVolumetricFlow(
        quantity=quantity(
            QuantityKind.STANDARD_VOLUMETRIC_FLOW,
            value,
            unit,
        ),
        reference_conditions=reference_conditions(
            "source-standard",
            FlowReferenceBasis.STANDARD,
            pressure=101.325,
            pressure_unit="kPa",
            temperature=15.0,
            temperature_unit="degC",
            compressibility_factor=0.98,
        ),
    )


def normal_conditions() -> ReferenceConditions:
    """Return an explicit normal state with no hidden base convention."""

    return reference_conditions(
        "target-normal",
        FlowReferenceBasis.NORMAL,
        pressure=1.0,
        pressure_unit="bar",
        temperature=0.0,
        temperature_unit="degC",
    )


def assert_quantity(
    result: EngineeringQuantity,
    *,
    kind: QuantityKind,
    unit: str,
    expected: float,
    rel: float = 1e-12,
    abs_: float = 1e-12,
) -> None:
    """Assert quantity identity and a high-precision reference value."""

    assert result.quantity_kind == kind.value
    assert result.unit == unit
    assert result.value == pytest.approx(expected, rel=rel, abs=abs_)


def test_step94_reuses_unit_and_temperature_foundation() -> None:
    """General methods retain Step 91's unit-safe temperature boundary."""

    freezing = DEFAULT_UNIT_REGISTRY.convert_quantity(
        quantity(
            QuantityKind.ABSOLUTE_TEMPERATURE,
            32.0,
            "degF",
        ),
        "K",
    )
    pressure = DEFAULT_UNIT_REGISTRY.convert_quantity(
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            1.0,
            "bar",
        ),
        "kPa",
    )

    assert freezing.value == pytest.approx(273.15, abs=1e-12)
    assert pressure.value == pytest.approx(100.0, abs=1e-12)


def test_step94_retains_absolute_zero_validation() -> None:
    """General-calculator integration does not weaken absolute-zero checks."""

    with pytest.raises((TypeError, ValueError, ValidationError)):
        DEFAULT_UNIT_REGISTRY.validate_quantity(
            quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                -1.0,
                "K",
            )
        )


def test_pressure_reference_vectors_and_round_trip() -> None:
    """Gauge/absolute conversion uses the supplied atmospheric pressure."""

    gauge = quantity(QuantityKind.GAUGE_PRESSURE, 250.0, "kPa")
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
    )

    absolute = convert_pressure(
        gauge,
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
        target_unit="kPa",
    )
    restored = convert_pressure(
        absolute,
        QuantityKind.GAUGE_PRESSURE,
        atmospheric_pressure=atmosphere,
        target_unit="kPa",
    )

    assert_quantity(
        absolute,
        kind=QuantityKind.ABSOLUTE_PRESSURE,
        unit="kPa",
        expected=351.325,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.GAUGE_PRESSURE,
        unit="kPa",
        expected=250.0,
    )


@pytest.mark.parametrize(
    ("gauge_value", "atmosphere_value"),
    (
        (-50.0, 101.325),
        (0.0, 80.0),
        (9_000.0, 100.0),
    ),
)
def test_pressure_round_trip_is_metamorphic(
    gauge_value: float,
    atmosphere_value: float,
) -> None:
    """Changing explicit atmosphere never destabilises a valid round trip."""

    gauge = quantity(
        QuantityKind.GAUGE_PRESSURE,
        gauge_value,
        "kPa",
    )
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        atmosphere_value,
        "kPa",
    )

    absolute = convert_pressure(
        gauge,
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
        target_unit="Pa",
    )
    restored = convert_pressure(
        absolute,
        QuantityKind.GAUGE_PRESSURE,
        atmospheric_pressure=atmosphere,
        target_unit="kPa",
    )

    assert restored.value == pytest.approx(gauge_value, abs=1e-12)


def test_pressure_same_basis_conversion_does_not_require_atmosphere() -> None:
    """Ordinary pressure-unit scaling does not invent a basis change."""

    result = convert_pressure(
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            100.0,
            "kPa",
        ),
        QuantityKind.DIFFERENTIAL_PRESSURE,
        target_unit="bar",
    )

    assert_quantity(
        result,
        kind=QuantityKind.DIFFERENTIAL_PRESSURE,
        unit="bar",
        expected=1.0,
    )


def test_pressure_basis_change_requires_explicit_atmosphere() -> None:
    """There is no implicit sea-level atmosphere."""

    with pytest.raises((TypeError, ValueError)):
        convert_pressure(
            quantity(QuantityKind.GAUGE_PRESSURE, 1.0, "bar"),
            QuantityKind.ABSOLUTE_PRESSURE,
        )


@pytest.mark.parametrize(
    "atmosphere",
    (
        quantity(QuantityKind.GAUGE_PRESSURE, 101.325, "kPa"),
        quantity(QuantityKind.ABSOLUTE_PRESSURE, 0.0, "Pa"),
        quantity(QuantityKind.LENGTH, 1.0, "m"),
    ),
)
def test_pressure_rejects_invalid_explicit_atmosphere(
    atmosphere: EngineeringQuantity,
) -> None:
    """Atmosphere must be positive, absolute, and pressure-dimensional."""

    with pytest.raises((TypeError, ValueError)):
        convert_pressure(
            quantity(QuantityKind.GAUGE_PRESSURE, 10.0, "kPa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=atmosphere,
        )


def test_pressure_rejects_absolute_result_below_vacuum_limit() -> None:
    """A gauge value cannot imply negative absolute pressure."""

    with pytest.raises((TypeError, ValueError)):
        convert_pressure(
            quantity(QuantityKind.GAUGE_PRESSURE, -102.0, "kPa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE,
                101.325,
                "kPa",
            ),
        )


def test_reference_condition_vector_and_inverse() -> None:
    """Fixed-molar-flow state conversion matches the ideal-gas identity."""

    target = normal_conditions()
    converted = convert_referenced_gas_volume(
        referenced_flow(),
        target,
        target_unit="m3/h",
    )

    # Q2 = 100 * (101325 / 100000) * (273.15 / 288.15)
    #      * (1.0 / 0.98)
    expected = 98.01061575072507
    assert converted.reference_conditions == target
    assert_quantity(
        converted.quantity,
        kind=QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        unit="m3/h",
        expected=expected,
    )

    restored = convert_referenced_gas_volume(
        converted,
        referenced_flow().reference_conditions,
        target_unit="m3/h",
    )
    assert restored.quantity.value == pytest.approx(100.0, rel=1e-12)


def test_reference_condition_conversion_is_linear_in_flow() -> None:
    """Doubling source flow doubles target flow at fixed explicit states."""

    once = convert_referenced_gas_volume(
        referenced_flow(25.0),
        normal_conditions(),
    )
    twice = convert_referenced_gas_volume(
        referenced_flow(50.0),
        normal_conditions(),
    )

    assert twice.quantity.value == pytest.approx(
        2.0 * once.quantity.value,
        rel=1e-12,
    )


def test_reference_condition_conversion_requires_target_state() -> None:
    """A named standard or normal flow can never detach from its state."""

    with pytest.raises(TypeError):
        convert_referenced_gas_volume(referenced_flow())  # type: ignore[call-arg]


def test_mass_and_actual_volume_reference_vector_and_inverse() -> None:
    """Mass flow and actual volume use one explicit operating density."""

    density = quantity(QuantityKind.DENSITY, 850.0, "kg/m3")
    mass_flow = quantity(QuantityKind.MASS_FLOW, 3.4, "kg/s")

    actual_flow = actual_volume_from_mass_flow(
        mass_flow,
        density,
        target_unit="m3/h",
    )
    restored = mass_flow_from_actual_volume(
        actual_flow,
        density,
        target_unit="kg/s",
    )

    assert_quantity(
        actual_flow,
        kind=QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        unit="m3/h",
        expected=14.4,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.MASS_FLOW,
        unit="kg/s",
        expected=3.4,
    )


def test_mass_volume_conversion_is_linear_and_unit_invariant() -> None:
    """Scaling actual volume scales mass flow at fixed explicit density."""

    density = quantity(QuantityKind.DENSITY, 0.85, "g/cm3")
    first = mass_flow_from_actual_volume(
        quantity(
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            1.0,
            "m3/h",
        ),
        density,
        target_unit="kg/h",
    )
    second = mass_flow_from_actual_volume(
        quantity(
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            2.0,
            "m3/h",
        ),
        density,
        target_unit="kg/h",
    )

    assert first.value == pytest.approx(850.0)
    assert second.value == pytest.approx(1_700.0)


def test_mass_volume_conversion_requires_density() -> None:
    """No water, air, or process density is silently selected."""

    with pytest.raises(TypeError):
        actual_volume_from_mass_flow(  # type: ignore[call-arg]
            quantity(QuantityKind.MASS_FLOW, 1.0, "kg/s")
        )


@pytest.mark.parametrize(
    ("flow", "density"),
    (
        (
            quantity(QuantityKind.MASS_FLOW, -1.0, "kg/s"),
            quantity(QuantityKind.DENSITY, 850.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.MASS_FLOW, 1.0, "kg/s"),
            quantity(QuantityKind.DENSITY, 0.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.ACTUAL_VOLUMETRIC_FLOW, 1.0, "m3/s"),
            quantity(QuantityKind.DENSITY, 850.0, "kg/m3"),
        ),
    ),
)
def test_mass_to_volume_rejects_invalid_domain_or_kind(
    flow: EngineeringQuantity,
    density: EngineeringQuantity,
) -> None:
    """Mass flow is nonnegative and density is positive with exact kinds."""

    with pytest.raises((TypeError, ValueError)):
        actual_volume_from_mass_flow(flow, density)


def test_density_specific_gravity_reference_and_inverse() -> None:
    """Density is specific gravity times an explicit reference density."""

    specific_gravity = quantity(
        QuantityKind.SPECIFIC_GRAVITY,
        1.025,
        "1",
    )
    reference_density = quantity(
        QuantityKind.DENSITY,
        998.2,
        "kg/m3",
    )

    density = density_from_specific_gravity(
        specific_gravity,
        reference_density,
        target_unit="kg/m3",
    )
    restored = specific_gravity_from_density(
        density,
        reference_density,
    )

    assert_quantity(
        density,
        kind=QuantityKind.DENSITY,
        unit="kg/m3",
        expected=1023.155,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.SPECIFIC_GRAVITY,
        unit="1",
        expected=1.025,
    )


def test_density_specific_gravity_is_unit_invariant() -> None:
    """Equivalent density units produce the same dimensionless ratio."""

    density = quantity(QuantityKind.DENSITY, 0.85, "g/cm3")
    reference = quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3")

    result = specific_gravity_from_density(density, reference)

    assert result.value == pytest.approx(0.85, rel=1e-12)


def test_density_requires_explicit_reference_density() -> None:
    """The calculator never assumes water at an unstated temperature."""

    with pytest.raises(TypeError):
        density_from_specific_gravity(  # type: ignore[call-arg]
            quantity(QuantityKind.SPECIFIC_GRAVITY, 1.0, "1")
        )


@pytest.mark.parametrize(
    ("specific_gravity", "reference_density"),
    (
        (
            quantity(QuantityKind.SPECIFIC_GRAVITY, 0.0, "1"),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.SPECIFIC_GRAVITY, 1.0, "1"),
            quantity(QuantityKind.DENSITY, 0.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.RATIO, 1.0, "1"),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        ),
    ),
)
def test_density_rejects_invalid_domain_or_semantics(
    specific_gravity: EngineeringQuantity,
    reference_density: EngineeringQuantity,
) -> None:
    """Only positive, explicitly typed SG and density values are accepted."""

    with pytest.raises((TypeError, ValueError)):
        density_from_specific_gravity(
            specific_gravity,
            reference_density,
        )


def test_viscosity_reference_vectors_and_round_trip() -> None:
    """Dynamic viscosity equals kinematic viscosity times density."""

    kinematic = quantity(
        QuantityKind.KINEMATIC_VISCOSITY,
        1.0,
        "cSt",
    )
    density = quantity(QuantityKind.DENSITY, 998.2, "kg/m3")

    dynamic = dynamic_viscosity_from_kinematic(
        kinematic,
        density,
        target_unit="mPa.s",
    )
    restored = kinematic_viscosity_from_dynamic(
        dynamic,
        density,
        target_unit="cSt",
    )

    assert_quantity(
        dynamic,
        kind=QuantityKind.DYNAMIC_VISCOSITY,
        unit="mPa.s",
        expected=0.9982,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.KINEMATIC_VISCOSITY,
        unit="mm2/s",
        expected=1.0,
    )


@pytest.mark.parametrize(
    ("kinematic", "density"),
    (
        (
            quantity(QuantityKind.KINEMATIC_VISCOSITY, 0.0, "m2/s"),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.KINEMATIC_VISCOSITY, 1e-6, "m2/s"),
            quantity(QuantityKind.DENSITY, 0.0, "kg/m3"),
        ),
        (
            quantity(QuantityKind.DYNAMIC_VISCOSITY, 1.0, "mPa.s"),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        ),
    ),
)
def test_viscosity_rejects_zero_or_wrong_dimension(
    kinematic: EngineeringQuantity,
    density: EngineeringQuantity,
) -> None:
    """Viscosity conversion requires positive quantities of exact kinds."""

    with pytest.raises((TypeError, ValueError)):
        dynamic_viscosity_from_kinematic(kinematic, density)


def test_hydrostatic_pressure_and_head_independent_vector() -> None:
    """Hydrostatic pressure/head implements p = rho g h bidirectionally."""

    density = quantity(QuantityKind.DENSITY, 998.2, "kg/m3")
    height = quantity(QuantityKind.LENGTH, 10.0, "m")
    gravity = quantity(
        QuantityKind.ACCELERATION,
        9.80665,
        "m/s2",
    )

    pressure = hydrostatic_pressure(
        density,
        height,
        gravity,
        target_unit="Pa",
    )
    restored = pressure_head(
        pressure,
        density,
        gravity,
        target_unit="m",
    )

    assert_quantity(
        pressure,
        kind=QuantityKind.DIFFERENTIAL_PRESSURE,
        unit="Pa",
        expected=97_889.9803,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.LENGTH,
        unit="m",
        expected=10.0,
    )


def test_hydrostatic_zero_is_a_valid_boundary() -> None:
    """Zero column produces zero differential pressure without a default."""

    result = hydrostatic_pressure(
        quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        quantity(QuantityKind.LENGTH, 0.0, "m"),
        quantity(QuantityKind.ACCELERATION, 9.81, "m/s2"),
    )

    assert result.value == 0.0


@pytest.mark.parametrize(
    ("density", "height", "gravity"),
    (
        (0.0, 1.0, 9.81),
        (1_000.0, -1.0, 9.81),
        (1_000.0, 1.0, 0.0),
    ),
)
def test_hydrostatic_rejects_invalid_physical_domain(
    density: float,
    height: float,
    gravity: float,
) -> None:
    """Density/gravity are positive and unsigned head is non-negative."""

    with pytest.raises((TypeError, ValueError)):
        hydrostatic_pressure(
            quantity(QuantityKind.DENSITY, density, "kg/m3"),
            quantity(QuantityKind.LENGTH, height, "m"),
            quantity(QuantityKind.ACCELERATION, gravity, "m/s2"),
        )


def test_pipe_reference_vector() -> None:
    """Pipe area, velocity, and Reynolds number match independent arithmetic."""

    result = pipe_area_velocity_reynolds(
        quantity(QuantityKind.LENGTH, 154.0, "mm"),
        quantity(
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            64.8,
            "m3/h",
        ),
        quantity(QuantityKind.DENSITY, 998.2, "kg/m3"),
        quantity(
            QuantityKind.DYNAMIC_VISCOSITY,
            0.89,
            "mPa.s",
        ),
        True,
        True,
    )

    assert_quantity(
        result.cross_sectional_area,
        kind=QuantityKind.AREA,
        unit="m2",
        expected=0.018626502843133884,
    )
    assert_quantity(
        result.mean_velocity,
        kind=QuantityKind.VELOCITY,
        unit="m/s",
        expected=0.9663649774512113,
    )
    assert_quantity(
        result.reynolds_number,
        kind=QuantityKind.DIMENSIONLESS,
        unit="1",
        expected=166_912.73051206413,
        rel=1e-11,
    )


def test_pipe_flow_scaling_is_metamorphic() -> None:
    """Flow doubles velocity/Re while diameter scaling follows geometry."""

    def calculate(diameter: float, flow: float):
        return pipe_area_velocity_reynolds(
            quantity(QuantityKind.LENGTH, diameter, "m"),
            quantity(
                QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                flow,
                "m3/s",
            ),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
            quantity(
                QuantityKind.DYNAMIC_VISCOSITY,
                0.001,
                "Pa.s",
            ),
            True,
            True,
        )

    base = calculate(0.1, 0.01)
    doubled_flow = calculate(0.1, 0.02)
    doubled_diameter = calculate(0.2, 0.01)

    assert doubled_flow.cross_sectional_area.value == pytest.approx(
        base.cross_sectional_area.value
    )
    assert doubled_flow.mean_velocity.value == pytest.approx(
        2.0 * base.mean_velocity.value
    )
    assert doubled_flow.reynolds_number.value == pytest.approx(
        2.0 * base.reynolds_number.value
    )
    assert doubled_diameter.cross_sectional_area.value == pytest.approx(
        4.0 * base.cross_sectional_area.value
    )
    assert doubled_diameter.mean_velocity.value == pytest.approx(
        base.mean_velocity.value / 4.0
    )
    assert doubled_diameter.reynolds_number.value == pytest.approx(
        base.reynolds_number.value / 2.0
    )


def test_pipe_zero_flow_boundary() -> None:
    """A stationary fluid has zero velocity and Reynolds number."""

    result = pipe_area_velocity_reynolds(
        quantity(QuantityKind.LENGTH, 0.1, "m"),
        quantity(QuantityKind.ACTUAL_VOLUMETRIC_FLOW, 0.0, "m3/s"),
        quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        quantity(QuantityKind.DYNAMIC_VISCOSITY, 0.001, "Pa.s"),
        True,
        True,
    )

    assert result.mean_velocity.value == 0.0
    assert result.reynolds_number.value == 0.0


@pytest.mark.parametrize(
    ("diameter", "flow", "density", "viscosity"),
    (
        (0.0, 0.01, 1_000.0, 0.001),
        (0.1, -0.01, 1_000.0, 0.001),
        (0.1, 0.01, 0.0, 0.001),
        (0.1, 0.01, 1_000.0, 0.0),
    ),
)
def test_pipe_rejects_invalid_physical_domain(
    diameter: float,
    flow: float,
    density: float,
    viscosity: float,
) -> None:
    """Pipe geometry and fluid properties fail closed outside their domain."""

    with pytest.raises((TypeError, ValueError)):
        pipe_area_velocity_reynolds(
            quantity(QuantityKind.LENGTH, diameter, "m"),
            quantity(
                QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                flow,
                "m3/s",
            ),
            quantity(QuantityKind.DENSITY, density, "kg/m3"),
            quantity(
                QuantityKind.DYNAMIC_VISCOSITY,
                viscosity,
                "Pa.s",
            ),
            True,
            True,
        )


@pytest.mark.parametrize(
    ("full_pipe_confirmed", "representative_properties_confirmed"),
    ((False, True), (True, False)),
)
def test_pipe_requires_explicit_applicability_confirmations(
    full_pipe_confirmed: bool,
    representative_properties_confirmed: bool,
) -> None:
    """Reynolds screening never assumes full pipe or valid properties."""

    with pytest.raises((TypeError, ValueError)):
        pipe_area_velocity_reynolds(
            quantity(QuantityKind.LENGTH, 0.1, "m"),
            quantity(
                QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                0.01,
                "m3/s",
            ),
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
            quantity(
                QuantityKind.DYNAMIC_VISCOSITY,
                0.001,
                "Pa.s",
            ),
            full_pipe_confirmed,
            representative_properties_confirmed,
        )


def test_transmitter_reference_vector_and_inverse() -> None:
    """Suppressed-range scaling uses (PV-LRV)/(URV-LRV)."""

    process_value = quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        25.0,
        "kPa",
    )
    lower = quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        -50.0,
        "kPa",
    )
    upper = quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        150.0,
        "kPa",
    )

    fraction = transmitter_linear_fraction(process_value, lower, upper)
    restored = transmitter_value_from_fraction(
        fraction,
        lower,
        upper,
        target_unit="kPa",
    )

    assert_quantity(
        fraction,
        kind=QuantityKind.RATIO,
        unit="1",
        expected=0.375,
    )
    assert_quantity(
        restored,
        kind=QuantityKind.DIFFERENTIAL_PRESSURE,
        unit="kPa",
        expected=25.0,
    )


def test_transmitter_scaling_is_unit_invariant() -> None:
    """Mixed compatible units normalize before span arithmetic."""

    result = transmitter_linear_fraction(
        quantity(QuantityKind.GAUGE_PRESSURE, 50.0, "kPa"),
        quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "bar"),
        quantity(QuantityKind.GAUGE_PRESSURE, 1.0, "bar"),
    )

    assert result.value == pytest.approx(0.5)


def test_dp_transmitter_range_reference_vector() -> None:
    """Sensor and calibrated spans use explicit LRL/URL/LRV/URV."""

    result = assess_dp_transmitter_range(
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            25.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            -1_000.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            1_000.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            -50.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            150.0,
            "kPa",
        ),
    )

    assert result.sensor_span.value == pytest.approx(2_000_000.0)
    assert result.sensor_span.unit == "Pa"
    assert result.calibrated_span.value == pytest.approx(200_000.0)
    assert result.calibrated_span.unit == "Pa"
    assert result.fraction_of_range.value == pytest.approx(0.375)
    assert result.percent_of_range.value == pytest.approx(37.5)
    assert result.turndown_ratio.value == pytest.approx(10.0)
    assert result.range_status == "within_range"
    assert result.calibration_within_sensor_limits is True


@pytest.mark.parametrize(
    ("applied", "expected_status"),
    (
        (-50.0, "within_range"),
        (150.0, "within_range"),
        (-50.001, "below_range"),
        (150.001, "above_range"),
    ),
)
def test_dp_transmitter_range_boundary_status(
    applied: float,
    expected_status: str,
) -> None:
    """LRV/URV are inclusive and excursions are reported deterministically."""

    result = assess_dp_transmitter_range(
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            applied,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            -1_000.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            1_000.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            -50.0,
            "kPa",
        ),
        quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            150.0,
            "kPa",
        ),
    )

    assert result.range_status == expected_status


def test_dp_transmitter_range_requires_explicit_sensor_limits() -> None:
    """Turndown cannot be calculated from invented LRL or URL values."""

    with pytest.raises(TypeError):
        assess_dp_transmitter_range(  # type: ignore[call-arg]
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                50.0,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                -50.0,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                150.0,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                1_000.0,
                "kPa",
            ),
        )


@pytest.mark.parametrize(
    ("lrl", "url", "lrv", "urv"),
    (
        (0.0, 0.0, 0.0, 10.0),
        (10.0, 0.0, 0.0, 10.0),
        (-100.0, 100.0, 10.0, 10.0),
        (-100.0, 100.0, 20.0, 10.0),
        (-100.0, 100.0, -101.0, 10.0),
        (-100.0, 100.0, -10.0, 101.0),
    ),
)
def test_dp_transmitter_range_rejects_invalid_sensor_or_calibration(
    lrl: float,
    url: float,
    lrv: float,
    urv: float,
) -> None:
    """Invalid sensor order or calibration outside limits fails closed."""

    with pytest.raises((TypeError, ValueError)):
        assess_dp_transmitter_range(
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                0.0,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                lrl,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                url,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                lrv,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                urv,
                "kPa",
            ),
        )


@pytest.mark.parametrize(
    ("lower", "upper"),
    ((10.0, 10.0), (20.0, 10.0)),
)
def test_transmitter_rejects_zero_or_reversed_span(
    lower: float,
    upper: float,
) -> None:
    """The supported forward range must have a positive span."""

    with pytest.raises((TypeError, ValueError)):
        transmitter_linear_fraction(
            quantity(QuantityKind.LENGTH, 10.0, "m"),
            quantity(QuantityKind.LENGTH, lower, "m"),
            quantity(QuantityKind.LENGTH, upper, "m"),
        )


def test_generic_transmitter_helper_supports_calibrated_extrapolation() -> None:
    """The primitive reports a fraction outside range without clamping."""

    fraction = transmitter_linear_fraction(
        quantity(QuantityKind.DIFFERENTIAL_PRESSURE, 125.0, "kPa"),
        quantity(QuantityKind.DIFFERENTIAL_PRESSURE, 0.0, "kPa"),
        quantity(QuantityKind.DIFFERENTIAL_PRESSURE, 100.0, "kPa"),
    )
    restored = transmitter_value_from_fraction(
        fraction,
        quantity(QuantityKind.DIFFERENTIAL_PRESSURE, 0.0, "kPa"),
        quantity(QuantityKind.DIFFERENTIAL_PRESSURE, 100.0, "kPa"),
    )

    assert fraction.value == pytest.approx(1.25)
    assert restored.value == pytest.approx(125.0)
    assert restored.unit == "kPa"


def test_transmitter_rejects_mixed_dimensions() -> None:
    """Range values cannot silently mix physical dimensions."""

    with pytest.raises((TypeError, ValueError)):
        transmitter_linear_fraction(
            quantity(QuantityKind.LENGTH, 1.0, "m"),
            quantity(QuantityKind.LENGTH, 0.0, "m"),
            quantity(QuantityKind.ABSOLUTE_PRESSURE, 100.0, "kPa"),
        )


@pytest.mark.parametrize(
    ("fraction", "expected_milliamps"),
    ((0.0, 4.0), (0.25, 8.0), (0.5, 12.0), (1.0, 20.0)),
)
def test_linear_4_20ma_reference_vectors(
    fraction: float,
    expected_milliamps: float,
) -> None:
    """Linear signal maps exact range fractions to 4–20 mA."""

    ratio = quantity(QuantityKind.RATIO, fraction, "1")
    current = current_from_linear_fraction(ratio, target_unit="mA")
    restored = linear_fraction_from_current(current)

    assert_quantity(
        current,
        kind=QuantityKind.ELECTRIC_CURRENT,
        unit="mA",
        expected=expected_milliamps,
    )
    assert restored.value == pytest.approx(fraction, abs=1e-12)


@pytest.mark.parametrize("fraction", (-0.000001, 1.000001))
def test_linear_4_20ma_rejects_out_of_range_fraction(
    fraction: float,
) -> None:
    """The supported nominal signal mapping is bounded to [0, 1]."""

    with pytest.raises((TypeError, ValueError)):
        current_from_linear_fraction(
            quantity(QuantityKind.RATIO, fraction, "1")
        )


@pytest.mark.parametrize(
    ("signal_fraction", "flow_fraction"),
    ((0.0, 0.0), (0.04, 0.2), (0.25, 0.5), (1.0, 1.0)),
)
def test_square_root_extraction_reference_and_inverse(
    signal_fraction: float,
    flow_fraction: float,
) -> None:
    """Flow fraction is the positive square root of signal fraction."""

    extracted = flow_fraction_from_square_root_signal(
        quantity(QuantityKind.RATIO, signal_fraction, "1")
    )
    inverted = square_root_signal_fraction_from_flow(extracted)

    assert extracted.value == pytest.approx(flow_fraction, abs=1e-12)
    assert inverted.value == pytest.approx(signal_fraction, abs=1e-12)


@pytest.mark.parametrize(
    ("flow_fraction", "expected_milliamps"),
    ((0.0, 4.0), (0.25, 5.0), (0.5, 8.0), (1.0, 20.0)),
)
def test_square_root_current_reference_and_inverse(
    flow_fraction: float,
    expected_milliamps: float,
) -> None:
    """Square-root flow maps through the squared 4–20 mA signal fraction."""

    flow = quantity(QuantityKind.RATIO, flow_fraction, "1")
    current = current_from_square_root_flow_fraction(
        flow,
        target_unit="mA",
    )
    restored = square_root_flow_fraction_from_current(current)

    assert current.value == pytest.approx(expected_milliamps, abs=1e-12)
    assert restored.value == pytest.approx(flow_fraction, abs=1e-12)


@pytest.mark.parametrize("fraction", (-0.1, 1.1))
def test_square_root_functions_reject_invalid_domain(
    fraction: float,
) -> None:
    """Negative radicands and out-of-range fractions fail closed."""

    value = quantity(QuantityKind.RATIO, fraction, "1")
    with pytest.raises((TypeError, ValueError)):
        flow_fraction_from_square_root_signal(value)
    with pytest.raises((TypeError, ValueError)):
        square_root_signal_fraction_from_flow(value)


def test_dc_loop_voltage_budget_reference_vector() -> None:
    """Loop budget accounts independently for every explicit voltage drop."""

    result = dc_loop_voltage_budget(
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 24.0, "V"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 12.0, "V"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 1.0, "V"),
        quantity(QuantityKind.ELECTRIC_CURRENT, 20.0, "mA"),
        quantity(QuantityKind.ELECTRICAL_RESISTANCE, 250.0, "ohm"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 2.0, "V"),
        False,
    )

    assert result.load_voltage_drop.value == pytest.approx(5.0)
    assert result.total_required_voltage.value == pytest.approx(20.0)
    assert result.signed_voltage_residual.value == pytest.approx(4.0)
    assert result.maximum_external_load_resistance.value == pytest.approx(
        450.0
    )
    assert result.adequate_voltage is True


def test_dc_loop_budget_reports_deficit_without_hiding_result() -> None:
    """An undersupplied loop returns a deterministic failed screen."""

    result = dc_loop_voltage_budget(
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 18.0, "V"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 12.0, "V"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 1.0, "V"),
        quantity(QuantityKind.ELECTRIC_CURRENT, 20.0, "mA"),
        quantity(QuantityKind.ELECTRICAL_RESISTANCE, 300.0, "ohm"),
        quantity(QuantityKind.ELECTRIC_POTENTIAL, 2.0, "V"),
        False,
    )

    assert result.load_voltage_drop.value == pytest.approx(6.0)
    assert result.total_required_voltage.value == pytest.approx(21.0)
    assert result.signed_voltage_residual.value == pytest.approx(-3.0)
    assert result.maximum_external_load_resistance.value == pytest.approx(
        150.0
    )
    assert result.adequate_voltage is False


def test_dc_loop_rejects_zero_maximum_current() -> None:
    """Maximum loop current must be positive for resistance screening."""

    with pytest.raises((TypeError, ValueError)):
        dc_loop_voltage_budget(
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 24.0, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 12.0, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 1.0, "V"),
            quantity(QuantityKind.ELECTRIC_CURRENT, 0.0, "A"),
            quantity(
                QuantityKind.ELECTRICAL_RESISTANCE,
                250.0,
                "ohm",
            ),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 2.0, "V"),
            False,
        )


def test_dc_loop_rejects_hazardous_or_intrinsically_safe_scope() -> None:
    """A simple voltage budget cannot assess an IS/hazardous-area loop."""

    with pytest.raises((TypeError, ValueError)):
        dc_loop_voltage_budget(
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 24.0, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 12.0, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 1.0, "V"),
            quantity(QuantityKind.ELECTRIC_CURRENT, 20.0, "mA"),
            quantity(
                QuantityKind.ELECTRICAL_RESISTANCE,
                250.0,
                "ohm",
            ),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, 2.0, "V"),
            True,
        )


@pytest.mark.parametrize(
    ("supply", "device", "drop", "current", "load", "margin"),
    (
        (0.0, 12.0, 1.0, 0.02, 250.0, 2.0),
        (24.0, 0.0, 1.0, 0.02, 250.0, 2.0),
        (24.0, 12.0, -1.0, 0.02, 250.0, 2.0),
        (24.0, 12.0, 1.0, 0.0, 250.0, 2.0),
        (24.0, 12.0, 1.0, 0.02, -1.0, 2.0),
        (24.0, 12.0, 1.0, 0.02, 250.0, -1.0),
    ),
)
def test_dc_loop_rejects_invalid_physical_domain(
    supply: float,
    device: float,
    drop: float,
    current: float,
    load: float,
    margin: float,
) -> None:
    """Supply/device/current are positive; passive drops/loads non-negative."""

    with pytest.raises((TypeError, ValueError)):
        dc_loop_voltage_budget(
            quantity(QuantityKind.ELECTRIC_POTENTIAL, supply, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, device, "V"),
            quantity(QuantityKind.ELECTRIC_POTENTIAL, drop, "V"),
            quantity(QuantityKind.ELECTRIC_CURRENT, current, "A"),
            quantity(
                QuantityKind.ELECTRICAL_RESISTANCE,
                load,
                "ohm",
            ),
            quantity(
                QuantityKind.ELECTRIC_POTENTIAL,
                margin,
                "V",
            ),
            False,
        )


def test_independent_uncertainty_reference_vector_and_units() -> None:
    """Independent standard components combine by root-sum-square."""

    result = combine_independent_standard_uncertainties(
        (
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                0.2,
                "kPa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                300.0,
                "Pa",
            ),
            quantity(
                QuantityKind.DIFFERENTIAL_PRESSURE,
                0.4,
                "kPa",
            ),
        ),
        target_unit="kPa",
    )

    assert_quantity(
        result,
        kind=QuantityKind.DIFFERENTIAL_PRESSURE,
        unit="kPa",
        expected=0.5385164807134504,
    )


def test_sensitivity_uncertainty_reference_vector_and_sign_invariance() -> None:
    """u_y = sqrt(sum((c_i * u_i)^2)); coefficient sign is immaterial."""

    first = propagate_independent_uncertainty(
        (2.0, 3.0),
        (0.1, 0.2),
    )
    second = propagate_independent_uncertainty(
        (-2.0, 3.0),
        (0.1, 0.2),
    )

    assert first == pytest.approx(0.6324555320336759)
    assert second == pytest.approx(first)


@pytest.mark.parametrize(
    ("coefficients", "uncertainties"),
    (
        ((), ()),
        ((1.0,), ()),
        ((1.0,), (-0.1,)),
        ((nan,), (0.1,)),
        ((1.0,), (nan,)),
    ),
)
def test_sensitivity_uncertainty_rejects_invalid_contract(
    coefficients: tuple[float, ...],
    uncertainties: tuple[float, ...],
) -> None:
    """The supported independent-RSS boundary is finite and shape exact."""

    with pytest.raises((TypeError, ValueError)):
        propagate_independent_uncertainty(
            coefficients,
            uncertainties,
        )


def test_combined_uncertainty_rejects_dimension_mismatch() -> None:
    """Independent uncertainty terms must share one physical dimension."""

    with pytest.raises((TypeError, ValueError)):
        combine_independent_standard_uncertainties(
            (
                quantity(QuantityKind.LENGTH, 0.1, "m"),
                quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    0.1,
                    "Pa",
                ),
            )
        )


def test_combined_uncertainty_rejects_negative_component() -> None:
    """Standard uncertainty magnitudes cannot be negative."""

    with pytest.raises((TypeError, ValueError)):
        combine_independent_standard_uncertainties(
            (quantity(QuantityKind.LENGTH, -0.1, "m"),)
        )


def test_public_functions_revalidate_constructed_nonfinite_quantities() -> None:
    """Bypassed model construction cannot inject NaN into calculations."""

    bypassed = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.DENSITY.value,
        value=nan,
        unit="kg/m3",
        uncertainty=None,
        uncertainty_basis=None,
        significant_figures=None,
        decimal_places=None,
    )

    with pytest.raises((TypeError, ValueError, ValidationError)):
        specific_gravity_from_density(
            bypassed,
            quantity(QuantityKind.DENSITY, 1_000.0, "kg/m3"),
        )


def test_general_registry_exact_identity_and_review_state() -> None:
    """Step 94 registers only the frozen, exact, reviewed method set."""

    assert GENERAL_METHOD_REGISTRY.method_ids == EXPECTED_METHOD_IDS
    assert len(GENERAL_METHOD_REGISTRY.definitions) == 17
    assert all(
        definition.method_version == "1.0.0"
        for definition in GENERAL_METHOD_REGISTRY.definitions
    )
    assert all(
        definition.lifecycle_status is MethodLifecycleStatus.APPROVED
        for definition in GENERAL_METHOD_REGISTRY.definitions
    )
    assert all(
        definition.test_vector_reference_ids
        for definition in GENERAL_METHOD_REGISTRY.definitions
    )


def registered_request(
    method_id: str,
    values: dict[str, EngineeringQuantity | bool | str],
) -> CalculationRequest:
    """Build an exact request from one method's reviewed input schema."""

    definition = GENERAL_METHOD_REGISTRY.resolve(method_id, "1.0.0")
    assert set(values) == {
        specification.input_id
        for specification in definition.input_specifications
    }
    inputs: list[CalculationInput] = []
    for specification in definition.input_specifications:
        value = values[specification.input_id]
        inputs.append(
            CalculationInput(
                input_id=specification.input_id,
                name=specification.name,
                origin=InputOrigin.USER_SUPPLIED,
                **(
                    {"quantity": value}
                    if isinstance(value, EngineeringQuantity)
                    else {"categorical_value": value}
                ),
            )
        )

    return CalculationRequest(
        request_id=FIXED_REQUEST_ID,
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        inputs=tuple(inputs),
    )


def registry_execution_cases() -> tuple[
    tuple[
        str,
        dict[str, EngineeringQuantity | bool | str],
        str,
        float | bool | str,
        str | None,
    ],
    ...,
]:
    """Return one independent executable vector for every exact method."""

    return (
        (
            "general.density.from-specific-gravity",
            {
                "specific-gravity": quantity(
                    QuantityKind.SPECIFIC_GRAVITY,
                    1.025,
                    "1",
                ),
                "reference-density": quantity(
                    QuantityKind.DENSITY,
                    998.2,
                    "kg/m3",
                ),
                "reference-density-description": (
                    "Water density explicitly supplied at the design state"
                ),
            },
            "density",
            1023.155,
            "kg/m3",
        ),
        (
            "general.density.to-specific-gravity",
            {
                "density": quantity(
                    QuantityKind.DENSITY,
                    1023.155,
                    "kg/m3",
                ),
                "reference-density": quantity(
                    QuantityKind.DENSITY,
                    998.2,
                    "kg/m3",
                ),
                "reference-density-description": (
                    "Water density explicitly supplied at the design state"
                ),
            },
            "specific-gravity",
            1.025,
            "1",
        ),
        (
            "general.flow.actual-volume-to-mass",
            {
                "actual-volumetric-flow": quantity(
                    QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                    0.004,
                    "m3/s",
                ),
                "density": quantity(
                    QuantityKind.DENSITY,
                    850.0,
                    "kg/m3",
                ),
            },
            "mass-flow",
            3.4,
            "kg/s",
        ),
        (
            "general.flow.mass-to-actual-volume",
            {
                "mass-flow": quantity(
                    QuantityKind.MASS_FLOW,
                    3.4,
                    "kg/s",
                ),
                "density": quantity(
                    QuantityKind.DENSITY,
                    850.0,
                    "kg/m3",
                ),
            },
            "actual-volumetric-flow",
            0.004,
            "m3/s",
        ),
        (
            "general.flow.reference-state",
            {
                "source-flow": quantity(
                    QuantityKind.REFERENCE_VOLUMETRIC_FLOW,
                    100.0,
                    "m3/h",
                ),
                "source-basis": "standard",
                "source-reference-id": "source-standard-vector",
                "source-absolute-pressure": quantity(
                    QuantityKind.ABSOLUTE_PRESSURE,
                    101.325,
                    "kPa",
                ),
                "source-absolute-temperature": quantity(
                    QuantityKind.ABSOLUTE_TEMPERATURE,
                    15.0,
                    "degC",
                ),
                "source-compressibility-treatment": "specified_factor",
                "source-compressibility-factor": quantity(
                    QuantityKind.RATIO,
                    0.98,
                    "1",
                ),
                "target-basis": "normal",
                "target-reference-id": "target-normal-vector",
                "target-absolute-pressure": quantity(
                    QuantityKind.ABSOLUTE_PRESSURE,
                    1.0,
                    "bar",
                ),
                "target-absolute-temperature": quantity(
                    QuantityKind.ABSOLUTE_TEMPERATURE,
                    0.0,
                    "degC",
                ),
                "target-compressibility-treatment": "ideal_gas",
                "target-compressibility-factor": quantity(
                    QuantityKind.RATIO,
                    1.0,
                    "1",
                ),
            },
            "target-flow",
            0.027225171041868074,
            "m3/s",
        ),
        (
            "general.loop.dc-voltage-budget",
            {
                "minimum-supply-voltage": quantity(
                    QuantityKind.ELECTRIC_POTENTIAL,
                    24.0,
                    "V",
                ),
                "minimum-device-voltage": quantity(
                    QuantityKind.ELECTRIC_POTENTIAL,
                    12.0,
                    "V",
                ),
                "fixed-series-voltage-drop": quantity(
                    QuantityKind.ELECTRIC_POTENTIAL,
                    1.0,
                    "V",
                ),
                "maximum-loop-current": quantity(
                    QuantityKind.ELECTRIC_CURRENT,
                    20.0,
                    "mA",
                ),
                "proposed-external-load-resistance": quantity(
                    QuantityKind.ELECTRICAL_RESISTANCE,
                    250.0,
                    "ohm",
                ),
                "required-voltage-margin": quantity(
                    QuantityKind.ELECTRIC_POTENTIAL,
                    2.0,
                    "V",
                ),
                "intrinsically-safe-or-hazardous-area": False,
            },
            "signed-voltage-residual",
            4.0,
            "V",
        ),
        (
            "general.pipe.velocity-reynolds",
            {
                "internal-diameter": quantity(
                    QuantityKind.LENGTH,
                    154.0,
                    "mm",
                ),
                "actual-volumetric-flow": quantity(
                    QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                    64.8,
                    "m3/h",
                ),
                "density": quantity(
                    QuantityKind.DENSITY,
                    998.2,
                    "kg/m3",
                ),
                "dynamic-viscosity": quantity(
                    QuantityKind.DYNAMIC_VISCOSITY,
                    0.89,
                    "mPa.s",
                ),
                "full-pipe-confirmed": True,
                "representative-properties-confirmed": True,
            },
            "mean-velocity",
            0.9663649774512113,
            "m/s",
        ),
        (
            "general.pressure.absolute-to-gauge",
            {
                "absolute-pressure": quantity(
                    QuantityKind.ABSOLUTE_PRESSURE,
                    351.325,
                    "kPa",
                ),
                "atmospheric-pressure": quantity(
                    QuantityKind.ABSOLUTE_PRESSURE,
                    101.325,
                    "kPa",
                ),
            },
            "gauge-pressure",
            250_000.0,
            "Pa",
        ),
        (
            "general.pressure.gauge-to-absolute",
            {
                "gauge-pressure": quantity(
                    QuantityKind.GAUGE_PRESSURE,
                    250.0,
                    "kPa",
                ),
                "atmospheric-pressure": quantity(
                    QuantityKind.ABSOLUTE_PRESSURE,
                    101.325,
                    "kPa",
                ),
            },
            "absolute-pressure",
            351_325.0,
            "Pa",
        ),
        (
            "general.signal.4-20ma-to-percent",
            {
                "loop-current": quantity(
                    QuantityKind.ELECTRIC_CURRENT,
                    12.0,
                    "mA",
                ),
            },
            "percent-of-range",
            50.0,
            "%",
        ),
        (
            "general.signal.dp-square-root",
            {
                "dp-fraction": quantity(
                    QuantityKind.RATIO,
                    0.25,
                    "1",
                ),
            },
            "flow-fraction",
            0.5,
            "1",
        ),
        (
            "general.signal.flow-square",
            {
                "flow-fraction": quantity(
                    QuantityKind.RATIO,
                    0.5,
                    "1",
                ),
            },
            "dp-fraction",
            0.25,
            "1",
        ),
        (
            "general.signal.percent-to-4-20ma",
            {
                "percent-of-range": quantity(
                    QuantityKind.RATIO,
                    50.0,
                    "%",
                ),
            },
            "loop-current",
            12.0,
            "mA",
        ),
        (
            "general.transmitter.dp-range",
            {
                "applied-dp": quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    25.0,
                    "kPa",
                ),
                "lower-range-limit": quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    -1_000.0,
                    "kPa",
                ),
                "upper-range-limit": quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    1_000.0,
                    "kPa",
                ),
                "lower-range-value": quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    -50.0,
                    "kPa",
                ),
                "upper-range-value": quantity(
                    QuantityKind.DIFFERENTIAL_PRESSURE,
                    150.0,
                    "kPa",
                ),
            },
            "turndown-ratio",
            10.0,
            "1",
        ),
        (
            "general.uncertainty.independent-relative-rss",
            {
                "relative-uncertainty-1": quantity(
                    QuantityKind.RATIO,
                    1.0,
                    "%",
                ),
                "relative-uncertainty-2": quantity(
                    QuantityKind.RATIO,
                    2.0,
                    "%",
                ),
                "relative-uncertainty-3": quantity(
                    QuantityKind.RATIO,
                    0.5,
                    "%",
                ),
                "relative-uncertainty-4": quantity(
                    QuantityKind.RATIO,
                    0.0,
                    "%",
                ),
                "uncorrelated-confirmed": True,
                "all-material-components-confirmed": True,
                "standard-uncertainty-components-confirmed": True,
            },
            "combined-relative-standard-uncertainty",
            0.0229128784747792,
            "1",
        ),
        (
            "general.viscosity.dynamic-to-kinematic",
            {
                "dynamic-viscosity": quantity(
                    QuantityKind.DYNAMIC_VISCOSITY,
                    0.9982,
                    "mPa.s",
                ),
                "density": quantity(
                    QuantityKind.DENSITY,
                    998.2,
                    "kg/m3",
                ),
            },
            "kinematic-viscosity",
            1e-6,
            "m2/s",
        ),
        (
            "general.viscosity.kinematic-to-dynamic",
            {
                "kinematic-viscosity": quantity(
                    QuantityKind.KINEMATIC_VISCOSITY,
                    1.0,
                    "cSt",
                ),
                "density": quantity(
                    QuantityKind.DENSITY,
                    998.2,
                    "kg/m3",
                ),
            },
            "dynamic-viscosity",
            0.0009982,
            "Pa.s",
        ),
    )


@pytest.mark.parametrize(
    (
        "method_id",
        "values",
        "output_id",
        "expected",
        "expected_unit",
    ),
    registry_execution_cases(),
    ids=EXPECTED_METHOD_IDS,
)
def test_every_registered_method_executes_reference_vector(
    method_id: str,
    values: dict[str, EngineeringQuantity | bool | str],
    output_id: str,
    expected: float | bool | str,
    expected_unit: str | None,
) -> None:
    """Every reviewed registration executes through the controlled engine."""

    engine = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )
    result = engine.execute(registered_request(method_id, values))

    assert result.status is CalculationStatus.COMPLETED
    assert len(result.result_fingerprint) == 64
    assert result.trace_steps[-1].kind.value == "calculation"
    output = next(
        value
        for value in result.outputs
        if value.output_id == output_id
    )
    if output.quantity is not None:
        assert output.quantity.value == pytest.approx(
            float(expected),
            rel=1e-11,
            abs=1e-12,
        )
        assert output.quantity.unit == expected_unit
    else:
        assert output.categorical_value == expected
        assert expected_unit is None


@pytest.mark.parametrize(
    ("method_id", "omitted_input_id"),
    (
        (
            "general.pressure.gauge-to-absolute",
            "atmospheric-pressure",
        ),
        (
            "general.flow.reference-state",
            "target-absolute-pressure",
        ),
        (
            "general.density.from-specific-gravity",
            "reference-density",
        ),
    ),
)
def test_registry_never_invents_missing_physical_state(
    method_id: str,
    omitted_input_id: str,
) -> None:
    """Atmosphere, base state, and reference density remain mandatory."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == method_id
    )
    complete = registered_request(method_id, case[1])
    incomplete = CalculationRequest(
        request_id=complete.request_id,
        calculation_type=complete.calculation_type,
        method_id=complete.method_id,
        method_version=complete.method_version,
        requested_at=complete.requested_at,
        inputs=tuple(
            value
            for value in complete.inputs
            if value.input_id != omitted_input_id
        ),
    )
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(incomplete)

    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert result.outputs == ()
    assert any(
        missing.input_id == omitted_input_id
        for missing in result.missing_inputs
    )


@pytest.mark.parametrize(
    "confirmation_id",
    (
        "uncorrelated-confirmed",
        "all-material-components-confirmed",
        "standard-uncertainty-components-confirmed",
    ),
)
def test_registry_uncertainty_requires_explicit_independence_confirmation(
    confirmation_id: str,
) -> None:
    """Unsupported correlation or omitted contributors never produce RSS."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == "general.uncertainty.independent-relative-rss"
    )
    values = dict(case[1])
    values[confirmation_id] = False
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(
        registered_request(
            "general.uncertainty.independent-relative-rss",
            values,
        )
    )

    assert result.status is CalculationStatus.BLOCKED
    assert result.outputs == ()


@pytest.mark.parametrize(
    "confirmation_id",
    (
        "full-pipe-confirmed",
        "representative-properties-confirmed",
    ),
)
def test_registry_pipe_requires_explicit_applicability_confirmation(
    confirmation_id: str,
) -> None:
    """A pipe result cannot assume full pipe or representative properties."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == "general.pipe.velocity-reynolds"
    )
    values = dict(case[1])
    values[confirmation_id] = False
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(
        registered_request(
            "general.pipe.velocity-reynolds",
            values,
        )
    )

    assert result.status is CalculationStatus.BLOCKED
    assert result.outputs == ()


@pytest.mark.parametrize(
    ("method_id", "confirmation_id"),
    (
        (
            "general.pipe.velocity-reynolds",
            "full-pipe-confirmed",
        ),
        (
            "general.pipe.velocity-reynolds",
            "representative-properties-confirmed",
        ),
        (
            "general.uncertainty.independent-relative-rss",
            "uncorrelated-confirmed",
        ),
        (
            "general.uncertainty.independent-relative-rss",
            "all-material-components-confirmed",
        ),
        (
            "general.uncertainty.independent-relative-rss",
            "standard-uncertainty-components-confirmed",
        ),
    ),
)
def test_registry_applicability_confirmation_is_required(
    method_id: str,
    confirmation_id: str,
) -> None:
    """Omitted applicability evidence produces no numerical output."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == method_id
    )
    complete = registered_request(method_id, case[1])
    incomplete = CalculationRequest(
        request_id=complete.request_id,
        calculation_type=complete.calculation_type,
        method_id=complete.method_id,
        method_version=complete.method_version,
        requested_at=complete.requested_at,
        inputs=tuple(
            value
            for value in complete.inputs
            if value.input_id != confirmation_id
        ),
    )
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(incomplete)

    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert result.outputs == ()


def test_registry_loop_blocks_hazardous_or_intrinsically_safe_scope() -> None:
    """Hazardous/IS loops stop at the registered safety boundary."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == "general.loop.dc-voltage-budget"
    )
    values = dict(case[1])
    values["intrinsically-safe-or-hazardous-area"] = True
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(
        registered_request(
            "general.loop.dc-voltage-budget",
            values,
        )
    )

    assert result.status is CalculationStatus.BLOCKED
    assert result.outputs == ()


def test_registry_loop_rejects_zero_maximum_current() -> None:
    """Zero current cannot produce a maximum-load resistance result."""

    case = next(
        value
        for value in registry_execution_cases()
        if value[0] == "general.loop.dc-voltage-budget"
    )
    values = dict(case[1])
    values["maximum-loop-current"] = quantity(
        QuantityKind.ELECTRIC_CURRENT,
        0.0,
        "A",
    )
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(
        registered_request(
            "general.loop.dc-voltage-budget",
            values,
        )
    )

    assert result.status not in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }
    assert result.outputs == ()


@pytest.mark.parametrize(
    ("field_id", "value"),
    (
        ("upper-range-limit", -1_000.0),
        ("upper-range-value", -50.0),
        ("lower-range-value", -1_001.0),
        ("upper-range-value", 1_001.0),
    ),
)
def test_registry_dp_invalid_limits_never_complete(
    field_id: str,
    value: float,
) -> None:
    """Invalid sensor/calibration ordering produces no DP range result."""

    case = next(
        item
        for item in registry_execution_cases()
        if item[0] == "general.transmitter.dp-range"
    )
    values = dict(case[1])
    values[field_id] = quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        value,
        "kPa",
    )
    result = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    ).execute(
        registered_request(
            "general.transmitter.dp-range",
            values,
        )
    )

    assert result.status not in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }
    assert result.outputs == ()


def test_registry_fingerprint_is_normalized_unit_invariant() -> None:
    """Equivalent material input units produce the same result fingerprint."""

    engine = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )
    ratio_request = registered_request(
        "general.signal.percent-to-4-20ma",
        {
            "percent-of-range": quantity(
                QuantityKind.RATIO,
                0.5,
                "1",
            )
        },
    )
    percent_request = registered_request(
        "general.signal.percent-to-4-20ma",
        {
            "percent-of-range": quantity(
                QuantityKind.RATIO,
                50.0,
                "%",
            )
        },
    )

    ratio_result = engine.execute(ratio_request)
    percent_result = engine.execute(percent_request)

    assert ratio_result.status is CalculationStatus.COMPLETED
    assert percent_result.status is CalculationStatus.COMPLETED
    assert ratio_result.outputs == percent_result.outputs
    assert (
        ratio_result.result_fingerprint
        == percent_result.result_fingerprint
    )


def test_registry_execution_is_deterministic() -> None:
    """A reviewed registry method produces a stable numerical fingerprint."""

    definition = GENERAL_METHOD_REGISTRY.resolve(
        "general.signal.percent-to-4-20ma",
        "1.0.0",
    )
    input_specification = definition.input_specifications[0]
    request = CalculationRequest(
        request_id=FIXED_REQUEST_ID,
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        inputs=(
            CalculationInput(
                input_id=input_specification.input_id,
                name=input_specification.name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=quantity(QuantityKind.RATIO, 0.5, "1"),
            ),
        ),
    )
    engine = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )

    first = engine.execute(request)
    second = engine.execute(request)

    assert first.status is CalculationStatus.COMPLETED
    assert first.outputs[0].quantity is not None
    assert first.outputs[0].quantity.value == pytest.approx(12.0)
    assert first.outputs[0].quantity.unit == "mA"
    assert first.result_fingerprint == second.result_fingerprint
    assert first.trace_steps == second.trace_steps
    assert first.outputs == second.outputs


def test_registry_fingerprint_changes_with_material_input() -> None:
    """A material signal change changes the result and its fingerprint."""

    definition = GENERAL_METHOD_REGISTRY.resolve(
        "general.signal.percent-to-4-20ma",
        "1.0.0",
    )
    specification = definition.input_specifications[0]
    engine = CalculationEngine(
        registry=GENERAL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )

    def execute(value: float):
        return engine.execute(
            CalculationRequest(
                request_id=FIXED_REQUEST_ID,
                calculation_type=definition.calculation_type,
                method_id=definition.method_id,
                method_version=definition.method_version,
                requested_at=FIXED_TIME,
                inputs=(
                    CalculationInput(
                        input_id=specification.input_id,
                        name=specification.name,
                        origin=InputOrigin.USER_SUPPLIED,
                        quantity=quantity(
                            QuantityKind.RATIO,
                            value,
                            "1",
                        ),
                    ),
                ),
            )
        )

    low = execute(0.25)
    high = execute(0.75)

    assert low.status is CalculationStatus.COMPLETED
    assert high.status is CalculationStatus.COMPLETED
    assert low.outputs != high.outputs
    assert low.result_fingerprint != high.result_fingerprint


def test_reference_arithmetic_is_independent_of_binary_pi_constant() -> None:
    """The pipe vector's independent geometry identity remains visible."""

    expected_area = pi * 0.154**2 / 4.0
    expected_velocity = 0.018 / expected_area

    result = pipe_area_velocity_reynolds(
        quantity(QuantityKind.LENGTH, 0.154, "m"),
        quantity(
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            0.018,
            "m3/s",
        ),
        quantity(QuantityKind.DENSITY, 998.2, "kg/m3"),
        quantity(
            QuantityKind.DYNAMIC_VISCOSITY,
            0.00089,
            "Pa.s",
        ),
        True,
        True,
    )

    assert isclose(
        result.cross_sectional_area.value,
        expected_area,
        rel_tol=1e-15,
    )
    assert isclose(
        result.mean_velocity.value,
        expected_velocity,
        rel_tol=1e-15,
    )
