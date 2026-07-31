"""Independent reference tests for Phase 7 Step 95 level calculations.

The vectors in this module are derived independently from the production
implementation.  Elevation is positive upward, pressure propagation follows
``P_B = P_A + rho * g * (z_A - z_B)``, and transmitter differential pressure
is always high-side pressure minus low-side pressure.  Every density,
gravitational acceleration, pressure basis, and installation confirmation is
supplied explicitly.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from math import nan
from math import pi
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
import pytest

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.general import GENERAL_METHOD_REGISTRY
from app.engineering.calculations.level import (
    ENGINEERING_METHOD_REGISTRY,
)
from app.engineering.calculations.level import LEVEL_METHOD_IDS
from app.engineering.calculations.level import LEVEL_METHOD_REGISTRY
from app.engineering.calculations.level import (
    LevelCalculationDomainError,
)
from app.engineering.calculations.level import (
    LevelCalculationInputError,
)
from app.engineering.calculations.level import dry_leg_dp_range
from app.engineering.calculations.level import (
    horizontal_cylindrical_tank_volume,
)
from app.engineering.calculations.level import interface_dp_range
from app.engineering.calculations.level import liquid_column_pressure
from app.engineering.calculations.level import liquid_head_from_pressure
from app.engineering.calculations.level import open_vessel_dp_range
from app.engineering.calculations.level import remote_seal_dp_range
from app.engineering.calculations.level import (
    screen_level_transmitter_range,
)
from app.engineering.calculations.level import screen_pressure_limits
from app.engineering.calculations.level import (
    vertical_cylindrical_tank_volume,
)
from app.engineering.calculations.level import wet_leg_dp_range
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.units import QuantityKind


FIXED_TIME = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
FIXED_REQUEST_ID = UUID("95000000-0000-4000-8000-000000000001")
FIXED_CALCULATION_ID = UUID("95000000-0000-4000-8000-000000000002")

EXPECTED_LEVEL_METHOD_IDS = (
    "level.dp.closed-dry-leg-range",
    "level.dp.closed-wet-leg-range",
    "level.dp.endpoint-range",
    "level.dp.interface-range",
    "level.dp.open-vessel-range",
    "level.dp.remote-seal-range",
    "level.hydrostatic.column-pressure",
    "level.tank.horizontal-cylinder",
    "level.tank.vertical-cylinder",
)


def quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
    *,
    uncertainty: float | None = None,
    uncertainty_basis: str | None = None,
) -> EngineeringQuantity:
    """Build one explicit engineering quantity."""

    return EngineeringQuantity(
        quantity_kind=kind.value,
        value=value,
        unit=unit,
        uncertainty=uncertainty,
        uncertainty_basis=uncertainty_basis,
    )


def length(value: float, unit: str = "m") -> EngineeringQuantity:
    return quantity(QuantityKind.LENGTH, value, unit)


def density(value: float, unit: str = "kg/m3") -> EngineeringQuantity:
    return quantity(QuantityKind.DENSITY, value, unit)


def gravity(value: float = 9.80665, unit: str = "m/s2") -> EngineeringQuantity:
    return quantity(QuantityKind.ACCELERATION, value, unit)


def absolute_pressure(value: float, unit: str = "Pa") -> EngineeringQuantity:
    return quantity(QuantityKind.ABSOLUTE_PRESSURE, value, unit)


def differential_pressure(
    value: float,
    unit: str = "Pa",
) -> EngineeringQuantity:
    return quantity(QuantityKind.DIFFERENTIAL_PRESSURE, value, unit)


def assert_quantity(
    result: EngineeringQuantity,
    *,
    kind: QuantityKind,
    expected: float,
    unit: str,
    rel: float = 1e-12,
    abs_: float = 1e-9,
) -> None:
    """Assert quantity semantics, unit, and numerical value."""

    assert result.quantity_kind == kind.value
    assert result.unit == unit
    assert result.value == pytest.approx(expected, rel=rel, abs=abs_)


def open_reference():
    """Return the independent open-vessel reference vector."""

    return open_vessel_dp_range(
        length(1.0),
        length(5.0),
        length(0.0),
        length(-1.0),
        density(850.0),
        density(850.0),
        gravity(),
        absolute_pressure(101_325.0),
        absolute_pressure(101_325.0),
    )


def dry_reference():
    """Return the independent closed-vessel dry-leg reference vector."""

    return dry_leg_dp_range(
        length(1.0),
        length(5.0),
        length(-1.0),
        length(-1.0),
        density(850.0),
        density(5.0),
        gravity(),
        absolute_pressure(500_000.0),
    )


def wet_reference():
    """Return the independent closed-vessel wet-leg reference vector."""

    return wet_leg_dp_range(
        length(1.0),
        length(5.0),
        length(-1.0),
        length(6.0),
        length(-1.0),
        density(850.0),
        density(5.0),
        density(1_000.0),
        gravity(),
        absolute_pressure(500_000.0),
    )


def remote_reference(
    *,
    geometry_confirmed: bool = True,
    fill_density_confirmed: bool = True,
):
    """Return the independent dual-remote-seal reference vector."""

    return remote_seal_dp_range(
        length(1.0),
        length(5.0),
        length(0.0),
        length(6.0),
        length(-1.0),
        length(-1.0),
        density(850.0),
        density(5.0),
        density(950.0),
        density(950.0),
        gravity(),
        absolute_pressure(500_000.0),
        geometry_confirmed,
        fill_density_confirmed,
    )


def interface_reference():
    """Return the independent two-liquid interface reference vector."""

    return interface_dp_range(
        length(1.0),
        length(3.0),
        length(0.0),
        length(4.0),
        length(0.0),
        length(4.0),
        density(1_000.0),
        density(800.0),
        gravity(),
        absolute_pressure(500_000.0),
    )


def endpoint_reference():
    """Return the independent transmitter range and overpressure screen."""

    return screen_level_transmitter_range(
        differential_pressure(-100.0, "kPa"),
        differential_pressure(100.0, "kPa"),
        absolute_pressure(600.0, "kPa"),
        absolute_pressure(650.0, "kPa"),
        absolute_pressure(700.0, "kPa"),
        absolute_pressure(620.0, "kPa"),
        absolute_pressure(900.0, "kPa"),
        absolute_pressure(850.0, "kPa"),
        differential_pressure(150.0, "kPa"),
        differential_pressure(-120.0, "kPa"),
        absolute_pressure(1_000.0, "kPa"),
        differential_pressure(200.0, "kPa"),
        differential_pressure(-200.0, "kPa"),
    )


def test_liquid_column_reference_vector() -> None:
    """rho*g*h is evaluated with explicit density, height, and gravity."""

    result = liquid_column_pressure(
        density(998.2),
        length(3.5),
        gravity(),
    )

    assert_quantity(
        result,
        kind=QuantityKind.DIFFERENTIAL_PRESSURE,
        expected=34_261.493105,
        unit="Pa",
    )


def test_liquid_column_and_head_are_inverse_operations() -> None:
    """The supported positive pressure/head pair round-trips."""

    rho = density(998.2)
    g = gravity()
    pressure = liquid_column_pressure(rho, length(3.5), g)
    restored = liquid_head_from_pressure(pressure, rho, g)

    assert_quantity(
        restored,
        kind=QuantityKind.LENGTH,
        expected=3.5,
        unit="m",
    )


def test_liquid_column_is_dimensionally_invariant() -> None:
    """Equivalent density, height, gravity, and output units agree."""

    metric = liquid_column_pressure(
        density(998.2),
        length(3.5),
        gravity(),
    )
    alternate = liquid_column_pressure(
        density(0.9982, "kg/L"),
        length(3_500.0, "mm"),
        gravity(32.17404855643044, "ft/s2"),
        target_unit="kPa",
    )

    assert metric.value == pytest.approx(alternate.value * 1_000.0)


def test_zero_liquid_column_has_zero_pressure() -> None:
    result = liquid_column_pressure(
        density(1_000.0),
        length(0.0),
        gravity(),
    )

    assert result.value == 0.0


@pytest.mark.parametrize(
    ("rho", "height", "g"),
    (
        (density(0.0), length(1.0), gravity()),
        (density(-1.0), length(1.0), gravity()),
        (density(1_000.0), length(-1.0), gravity()),
        (density(1_000.0), length(1.0), gravity(0.0)),
        (density(1_000.0), length(1.0), gravity(-9.80665)),
    ),
)
def test_liquid_column_rejects_invalid_physical_domain(
    rho: EngineeringQuantity,
    height: EngineeringQuantity,
    g: EngineeringQuantity,
) -> None:
    with pytest.raises(LevelCalculationDomainError):
        liquid_column_pressure(rho, height, g)


def test_liquid_column_rejects_wrong_dimension() -> None:
    with pytest.raises(LevelCalculationInputError):
        liquid_column_pressure(
            length(998.2),
            length(3.5),
            gravity(),
        )


def test_public_level_helpers_do_not_discard_uncertainty() -> None:
    uncertain_density = quantity(
        QuantityKind.DENSITY,
        998.2,
        "kg/m3",
        uncertainty=0.5,
        uncertainty_basis="standard uncertainty",
    )

    with pytest.raises(LevelCalculationInputError):
        liquid_column_pressure(
            uncertain_density,
            length(3.5),
            gravity(),
        )


def test_public_level_helpers_revalidate_constructed_nonfinite_values() -> None:
    bypassed = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.DENSITY.value,
        value=nan,
        unit="kg/m3",
        uncertainty=None,
        uncertainty_basis=None,
        significant_figures=None,
        decimal_places=None,
    )

    with pytest.raises((LevelCalculationInputError, ValidationError)):
        liquid_column_pressure(bypassed, length(1.0), gravity())


def test_open_vessel_reference_vector_and_absolute_pressures() -> None:
    """Open-vessel endpoints preserve explicit atmosphere and port head."""

    result = open_reference()

    assert result.lower_endpoint_differential_pressure.value == pytest.approx(
        16_671.305
    )
    assert result.upper_endpoint_differential_pressure.value == pytest.approx(
        50_013.915
    )
    assert result.lower_endpoint_high_side_absolute_pressure.value == (
        pytest.approx(117_996.305)
    )
    assert result.upper_endpoint_high_side_absolute_pressure.value == (
        pytest.approx(151_338.915)
    )
    assert result.lower_endpoint_low_side_absolute_pressure.value == (
        pytest.approx(101_325.0)
    )
    assert result.upper_endpoint_low_side_absolute_pressure.value == (
        pytest.approx(101_325.0)
    )
    assert result.lower_range_value == (
        result.lower_endpoint_differential_pressure
    )
    assert result.upper_range_value == (
        result.upper_endpoint_differential_pressure
    )
    assert result.signed_span.value == pytest.approx(33_342.61)
    assert result.span.value == pytest.approx(33_342.61)
    assert result.output_direction == "increasing"


def test_open_vessel_requires_one_consistent_explicit_atmosphere() -> None:
    """Different atmospheric references cannot be silently reconciled."""

    with pytest.raises(LevelCalculationDomainError):
        open_vessel_dp_range(
            length(1.0),
            length(5.0),
            length(0.0),
            length(-1.0),
            density(850.0),
            density(850.0),
            gravity(),
            absolute_pressure(102_000.0),
            absolute_pressure(100_000.0),
        )


def test_open_vessel_high_side_leg_density_effect_is_explicit() -> None:
    same_density = open_reference()
    lighter_leg = open_vessel_dp_range(
        length(1.0),
        length(5.0),
        length(0.0),
        length(-1.0),
        density(850.0),
        density(800.0),
        gravity(),
        absolute_pressure(101_325.0),
        absolute_pressure(101_325.0),
    )

    expected_offset = (850.0 - 800.0) * 9.80665 * 1.0
    assert same_density.lower_range_value.value - lighter_leg.lower_range_value.value == (
        pytest.approx(expected_offset)
    )
    assert same_density.span.value == pytest.approx(lighter_leg.span.value)


def test_dry_leg_reference_vector_and_vapour_density_effect() -> None:
    """Closed dry-leg DP includes the explicitly supplied dry-leg density."""

    result = dry_reference()

    assert result.lower_range_value.value == pytest.approx(16_573.2385)
    assert result.upper_range_value.value == pytest.approx(49_719.7155)
    assert result.signed_span.value == pytest.approx(33_146.477)
    assert result.span.value == pytest.approx(33_146.477)
    assert result.output_direction == "increasing"
    assert (
        result.lower_endpoint_high_side_absolute_pressure.value
        - result.lower_endpoint_low_side_absolute_pressure.value
    ) == pytest.approx(result.lower_range_value.value)


def test_dry_leg_common_pressure_is_dp_invariant() -> None:
    base = dry_reference()
    shifted = dry_leg_dp_range(
        length(1.0),
        length(5.0),
        length(-1.0),
        length(-1.0),
        density(850.0),
        density(5.0),
        gravity(),
        absolute_pressure(800_000.0),
    )

    assert shifted.lower_range_value.value == pytest.approx(
        base.lower_range_value.value
    )
    assert shifted.upper_range_value.value == pytest.approx(
        base.upper_range_value.value
    )
    assert (
        shifted.lower_endpoint_high_side_absolute_pressure.value
        - base.lower_endpoint_high_side_absolute_pressure.value
    ) == pytest.approx(300_000.0)
    assert (
        shifted.lower_endpoint_low_side_absolute_pressure.value
        - base.lower_endpoint_low_side_absolute_pressure.value
    ) == pytest.approx(300_000.0)


def test_wet_leg_reference_vector_has_suppressed_zero() -> None:
    """The explicit wet-leg fill column can suppress both calibrated endpoints."""

    result = wet_reference()

    assert result.lower_range_value.value == pytest.approx(-51_730.07875)
    assert result.upper_range_value.value == pytest.approx(-18_583.60175)
    assert result.signed_span.value == pytest.approx(33_146.477)
    assert result.span.value == pytest.approx(33_146.477)
    assert result.output_direction == "increasing"


def test_wet_leg_fill_density_changes_offset_but_not_span() -> None:
    base = wet_reference()
    lighter_fill = wet_leg_dp_range(
        length(1.0),
        length(5.0),
        length(-1.0),
        length(6.0),
        length(-1.0),
        density(850.0),
        density(5.0),
        density(900.0),
        gravity(),
        absolute_pressure(500_000.0),
    )

    expected_offset = 100.0 * 9.80665 * 7.0
    assert lighter_fill.lower_range_value.value - base.lower_range_value.value == (
        pytest.approx(expected_offset)
    )
    assert lighter_fill.span.value == pytest.approx(base.span.value)


def test_remote_seal_reference_vector_includes_both_fill_heads() -> None:
    result = remote_reference()

    assert result.lower_range_value.value == pytest.approx(-47_317.08625)
    assert result.upper_range_value.value == pytest.approx(-14_170.60925)
    assert result.signed_span.value == pytest.approx(33_146.477)
    assert result.output_direction == "increasing"


@pytest.mark.parametrize(
    ("geometry_confirmed", "density_confirmed"),
    ((False, True), (True, False), (False, False)),
)
def test_remote_seal_requires_explicit_installation_confirmations(
    geometry_confirmed: bool,
    density_confirmed: bool,
) -> None:
    with pytest.raises(LevelCalculationDomainError):
        remote_reference(
            geometry_confirmed=geometry_confirmed,
            fill_density_confirmed=density_confirmed,
        )


def test_remote_seal_equal_fill_density_common_port_shift_is_invariant() -> None:
    """Moving both sensing ports together does not change equal-fill DP."""

    base = remote_reference()
    shifted = remote_seal_dp_range(
        length(1.0),
        length(5.0),
        length(0.0),
        length(6.0),
        length(-3.0),
        length(-3.0),
        density(850.0),
        density(5.0),
        density(950.0),
        density(950.0),
        gravity(),
        absolute_pressure(500_000.0),
        True,
        True,
    )

    assert shifted.lower_range_value.value == pytest.approx(
        base.lower_range_value.value
    )
    assert shifted.upper_range_value.value == pytest.approx(
        base.upper_range_value.value
    )


def test_common_elevation_datum_translation_is_invariant() -> None:
    """Adding one constant to every elevation cannot change pressure heads."""

    shifted_results = (
        open_vessel_dp_range(
            length(11.0),
            length(15.0),
            length(10.0),
            length(9.0),
            density(850.0),
            density(850.0),
            gravity(),
            absolute_pressure(101_325.0),
            absolute_pressure(101_325.0),
        ),
        dry_leg_dp_range(
            length(11.0),
            length(15.0),
            length(9.0),
            length(9.0),
            density(850.0),
            density(5.0),
            gravity(),
            absolute_pressure(500_000.0),
        ),
        wet_leg_dp_range(
            length(11.0),
            length(15.0),
            length(9.0),
            length(16.0),
            length(9.0),
            density(850.0),
            density(5.0),
            density(1_000.0),
            gravity(),
            absolute_pressure(500_000.0),
        ),
        remote_seal_dp_range(
            length(11.0),
            length(15.0),
            length(10.0),
            length(16.0),
            length(9.0),
            length(9.0),
            density(850.0),
            density(5.0),
            density(950.0),
            density(950.0),
            gravity(),
            absolute_pressure(500_000.0),
            True,
            True,
        ),
        interface_dp_range(
            length(11.0),
            length(13.0),
            length(10.0),
            length(4.0),
            length(10.0),
            length(14.0),
            density(1_000.0),
            density(800.0),
            gravity(),
            absolute_pressure(500_000.0),
        ),
    )
    base_results = (
        open_reference(),
        dry_reference(),
        wet_reference(),
        remote_reference(),
        interface_reference(),
    )

    for base, shifted in zip(base_results, shifted_results, strict=True):
        assert shifted.lower_range_value.value == pytest.approx(
            base.lower_range_value.value
        )
        assert shifted.upper_range_value.value == pytest.approx(
            base.upper_range_value.value
        )
        assert shifted.span.value == pytest.approx(base.span.value)


def test_lowering_open_vessel_hp_port_increases_zero_and_full_dp() -> None:
    """A lower flooded HP port produces the expected elevated-zero offset."""

    base = open_reference()
    lowered = open_vessel_dp_range(
        length(1.0),
        length(5.0),
        length(0.0),
        length(-2.0),
        density(850.0),
        density(850.0),
        gravity(),
        absolute_pressure(101_325.0),
        absolute_pressure(101_325.0),
    )
    expected_offset = 850.0 * 9.80665

    assert lowered.lower_range_value.value - base.lower_range_value.value == (
        pytest.approx(expected_offset)
    )
    assert lowered.upper_range_value.value - base.upper_range_value.value == (
        pytest.approx(expected_offset)
    )
    assert lowered.span.value == pytest.approx(base.span.value)


def test_zero_dry_leg_density_is_an_explicit_approximation() -> None:
    result = dry_leg_dp_range(
        length(1.0),
        length(5.0),
        length(-1.0),
        length(-1.0),
        density(850.0),
        density(0.0),
        gravity(),
        absolute_pressure(500_000.0),
    )

    assert result.lower_range_value.value == pytest.approx(
        850.0 * 9.80665 * 2.0
    )
    assert result.span.value == pytest.approx(850.0 * 9.80665 * 4.0)


def test_interface_reference_vector_and_density_ordering() -> None:
    result = interface_reference()

    assert result.lower_range_value.value == pytest.approx(33_342.61)
    assert result.upper_range_value.value == pytest.approx(37_265.27)
    assert result.signed_span.value == pytest.approx(3_922.66)
    assert result.output_direction == "increasing"
    assert (
        result.lower_endpoint_high_side_absolute_pressure.value
        - result.lower_endpoint_low_side_absolute_pressure.value
    ) == pytest.approx(33_342.61)


def test_interface_span_scales_with_density_difference() -> None:
    base = interface_reference()
    wider_contrast = interface_dp_range(
        length(1.0),
        length(3.0),
        length(0.0),
        length(4.0),
        length(0.0),
        length(4.0),
        density(1_100.0),
        density(700.0),
        gravity(),
        absolute_pressure(500_000.0),
    )

    assert wider_contrast.span.value == pytest.approx(2.0 * base.span.value)


@pytest.mark.parametrize(
    ("lower_density", "upper_density"),
    ((800.0, 800.0), (700.0, 800.0)),
)
def test_interface_requires_heavier_lower_fluid(
    lower_density: float,
    upper_density: float,
) -> None:
    with pytest.raises(
        (LevelCalculationDomainError, LevelCalculationInputError)
    ):
        interface_dp_range(
            length(1.0),
            length(3.0),
            length(0.0),
            length(4.0),
            length(0.0),
            length(4.0),
            density(lower_density),
            density(upper_density),
            gravity(),
            absolute_pressure(500_000.0),
        )


@pytest.mark.parametrize(
    ("lower_interface", "upper_interface"),
    ((-0.1, 3.0), (1.0, 4.1), (3.0, 1.0), (2.0, 2.0)),
)
def test_interface_rejects_invalid_or_degenerate_bounds(
    lower_interface: float,
    upper_interface: float,
) -> None:
    with pytest.raises(LevelCalculationDomainError):
        interface_dp_range(
            length(lower_interface),
            length(upper_interface),
            length(0.0),
            length(4.0),
            length(0.0),
            length(4.0),
            density(1_000.0),
            density(800.0),
            gravity(),
            absolute_pressure(500_000.0),
        )


def test_endpoint_range_and_pressure_limit_reference_vector() -> None:
    result = endpoint_reference()

    assert result.lower_range_value.value == pytest.approx(-50_000.0)
    assert result.upper_range_value.value == pytest.approx(80_000.0)
    assert result.signed_span.value == pytest.approx(130_000.0)
    assert result.span.value == pytest.approx(130_000.0)
    assert result.output_direction == "increasing"
    assert result.lower_range_margin.value == pytest.approx(50_000.0)
    assert result.upper_range_margin.value == pytest.approx(20_000.0)
    assert result.high_side_static_pressure_margin.value == pytest.approx(
        100_000.0
    )
    assert result.low_side_static_pressure_margin.value == pytest.approx(
        150_000.0
    )
    assert result.positive_overpressure_margin.value == pytest.approx(
        50_000.0
    )
    assert result.negative_overpressure_margin.value == pytest.approx(
        80_000.0
    )
    assert result.configured_range_within_sensor_limits is True
    assert result.within_static_pressure_limit is True
    assert result.within_differential_overpressure_limits is True
    assert result.pressure_limits_adequate is True


def test_endpoint_range_derives_dp_from_absolute_side_pressures() -> None:
    result = endpoint_reference()

    assert result.lower_endpoint_differential_pressure.value == pytest.approx(
        600_000.0 - 650_000.0
    )
    assert result.upper_endpoint_differential_pressure.value == pytest.approx(
        700_000.0 - 620_000.0
    )


def test_endpoint_range_preserves_reverse_output_direction() -> None:
    result = screen_level_transmitter_range(
        differential_pressure(-100.0, "kPa"),
        differential_pressure(100.0, "kPa"),
        absolute_pressure(700.0, "kPa"),
        absolute_pressure(620.0, "kPa"),
        absolute_pressure(600.0, "kPa"),
        absolute_pressure(650.0, "kPa"),
        absolute_pressure(900.0, "kPa"),
        absolute_pressure(850.0, "kPa"),
        differential_pressure(150.0, "kPa"),
        differential_pressure(-120.0, "kPa"),
        absolute_pressure(1_000.0, "kPa"),
        differential_pressure(200.0, "kPa"),
        differential_pressure(-200.0, "kPa"),
    )

    assert result.lower_range_value.value == pytest.approx(80_000.0)
    assert result.upper_range_value.value == pytest.approx(-50_000.0)
    assert result.signed_span.value == pytest.approx(-130_000.0)
    assert result.span.value == pytest.approx(130_000.0)
    assert result.output_direction == "decreasing"


def test_endpoint_screen_reports_inadequate_device_without_false_adequacy() -> None:
    result = screen_level_transmitter_range(
        differential_pressure(-40.0, "kPa"),
        differential_pressure(40.0, "kPa"),
        absolute_pressure(600.0, "kPa"),
        absolute_pressure(650.0, "kPa"),
        absolute_pressure(700.0, "kPa"),
        absolute_pressure(620.0, "kPa"),
        absolute_pressure(1_100.0, "kPa"),
        absolute_pressure(850.0, "kPa"),
        differential_pressure(250.0, "kPa"),
        differential_pressure(-250.0, "kPa"),
        absolute_pressure(1_000.0, "kPa"),
        differential_pressure(200.0, "kPa"),
        differential_pressure(-200.0, "kPa"),
    )

    assert result.configured_range_within_sensor_limits is False
    assert result.within_static_pressure_limit is False
    assert result.within_differential_overpressure_limits is False
    assert result.pressure_limits_adequate is False
    assert result.lower_range_margin.value < 0.0
    assert result.upper_range_margin.value < 0.0
    assert result.high_side_static_pressure_margin.value < 0.0
    assert result.positive_overpressure_margin.value < 0.0
    assert result.negative_overpressure_margin.value < 0.0


def test_standalone_pressure_screen_matches_endpoint_screen() -> None:
    combined = endpoint_reference()
    standalone = screen_pressure_limits(
        absolute_pressure(900.0, "kPa"),
        absolute_pressure(850.0, "kPa"),
        absolute_pressure(1_000.0, "kPa"),
        differential_pressure(150.0, "kPa"),
        differential_pressure(-120.0, "kPa"),
        differential_pressure(200.0, "kPa"),
        differential_pressure(-200.0, "kPa"),
    )

    assert standalone.high_side_static_pressure_margin == (
        combined.high_side_static_pressure_margin
    )
    assert standalone.low_side_static_pressure_margin == (
        combined.low_side_static_pressure_margin
    )
    assert standalone.positive_overpressure_margin == (
        combined.positive_overpressure_margin
    )
    assert standalone.negative_overpressure_margin == (
        combined.negative_overpressure_margin
    )
    assert standalone.pressure_limits_adequate is True


@pytest.mark.parametrize(
    ("lower_high", "lower_low", "upper_high", "upper_low"),
    (
        (600.0, 650.0, 600.0, 650.0),
        (-1.0, 650.0, 700.0, 620.0),
        (600.0, -1.0, 700.0, 620.0),
    ),
)
def test_endpoint_screen_rejects_zero_span_or_negative_absolute_pressure(
    lower_high: float,
    lower_low: float,
    upper_high: float,
    upper_low: float,
) -> None:
    with pytest.raises(
        (LevelCalculationDomainError, LevelCalculationInputError)
    ):
        screen_level_transmitter_range(
            differential_pressure(-100.0, "kPa"),
            differential_pressure(100.0, "kPa"),
            absolute_pressure(lower_high, "kPa"),
            absolute_pressure(lower_low, "kPa"),
            absolute_pressure(upper_high, "kPa"),
            absolute_pressure(upper_low, "kPa"),
            absolute_pressure(900.0, "kPa"),
            absolute_pressure(850.0, "kPa"),
            differential_pressure(150.0, "kPa"),
            differential_pressure(-120.0, "kPa"),
            absolute_pressure(1_000.0, "kPa"),
            differential_pressure(200.0, "kPa"),
            differential_pressure(-200.0, "kPa"),
        )


def test_vertical_cylinder_reference_and_boundary_vectors() -> None:
    result = vertical_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(3.0),
        True,
        True,
    )
    empty = vertical_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(0.0),
        True,
        True,
    )
    full = vertical_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(5.0),
        True,
        True,
    )

    assert result.liquid_volume.value == pytest.approx(3.0 * pi)
    assert result.full_capacity.value == pytest.approx(5.0 * pi)
    assert result.fill_fraction.value == pytest.approx(0.6)
    assert empty.liquid_volume.value == 0.0
    assert empty.fill_fraction.value == 0.0
    assert full.liquid_volume == full.full_capacity
    assert full.fill_fraction.value == 1.0


def test_vertical_cylinder_unit_invariance() -> None:
    metres = vertical_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(3.0),
        True,
        True,
    )
    millimetres = vertical_cylindrical_tank_volume(
        length(2_000.0, "mm"),
        length(5_000.0, "mm"),
        length(3_000.0, "mm"),
        True,
        True,
    )

    assert millimetres == metres


def test_horizontal_cylinder_reference_and_boundary_vectors() -> None:
    quarter_depth = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(0.5),
        True,
        True,
    )
    empty = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(0.0),
        True,
        True,
    )
    half = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(1.0),
        True,
        True,
    )
    full = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(2.0),
        True,
        True,
    )

    assert quarter_depth.liquid_volume.value == pytest.approx(
        3.070924246521893
    )
    assert quarter_depth.full_capacity.value == pytest.approx(
        15.707963267948966
    )
    assert quarter_depth.fill_fraction.value == pytest.approx(
        0.19550110947788538
    )
    assert empty.liquid_volume.value == 0.0
    assert half.liquid_volume.value == pytest.approx(0.5 * 5.0 * pi)
    assert half.fill_fraction.value == pytest.approx(0.5)
    assert full.liquid_volume == full.full_capacity
    assert full.fill_fraction.value == 1.0


def test_horizontal_cylinder_complementary_depth_identity() -> None:
    """V(h) + V(D-h) equals the full flat-ended cylindrical capacity."""

    low = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(0.5),
        True,
        True,
    )
    high = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(1.5),
        True,
        True,
    )

    assert low.liquid_volume.value + high.liquid_volume.value == pytest.approx(
        low.full_capacity.value
    )
    assert low.fill_fraction.value + high.fill_fraction.value == pytest.approx(
        1.0
    )


def test_horizontal_cylinder_near_empty_stability_and_symmetry() -> None:
    """A tiny positive level remains finite, positive, and complementary."""

    tiny_height = 1.0e-12
    low = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(tiny_height),
        True,
        True,
    )
    high = horizontal_cylindrical_tank_volume(
        length(2.0),
        length(5.0),
        length(2.0 - tiny_height),
        True,
        True,
    )

    assert 0.0 < low.liquid_volume.value < low.full_capacity.value
    assert 0.0 < high.liquid_volume.value < high.full_capacity.value
    assert low.liquid_volume.value + high.liquid_volume.value == pytest.approx(
        low.full_capacity.value,
        rel=1e-14,
        abs=1e-14,
    )


def test_horizontal_cylinder_volume_is_monotonic_across_depth() -> None:
    volumes = tuple(
        horizontal_cylindrical_tank_volume(
            length(2.0),
            length(5.0),
            length(height),
            True,
            True,
        ).liquid_volume.value
        for height in (0.0, 0.1, 0.5, 1.0, 1.5, 1.9, 2.0)
    )

    assert volumes == tuple(sorted(volumes))
    assert len(set(volumes)) == len(volumes)


@pytest.mark.parametrize(
    ("function_name", "dimensions", "confirmations"),
    (
        ("vertical", (0.0, 5.0, 1.0), (True, True)),
        ("vertical", (-2.0, 5.0, 1.0), (True, True)),
        ("vertical", (2.0, 0.0, 0.0), (True, True)),
        ("vertical", (2.0, 5.0, -0.1), (True, True)),
        ("vertical", (2.0, 5.0, 5.1), (True, True)),
        ("horizontal", (0.0, 5.0, 1.0), (True, True)),
        ("horizontal", (2.0, 0.0, 1.0), (True, True)),
        ("horizontal", (2.0, 5.0, -0.1), (True, True)),
        ("horizontal", (2.0, 5.0, 2.1), (True, True)),
        ("vertical", (2.0, 5.0, 1.0), (False, True)),
        ("vertical", (2.0, 5.0, 1.0), (True, False)),
        ("horizontal", (2.0, 5.0, 1.0), (False, True)),
        ("horizontal", (2.0, 5.0, 1.0), (True, False)),
    ),
)
def test_tank_geometry_rejects_degenerate_or_unconfirmed_cases(
    function_name: str,
    dimensions: tuple[float, float, float],
    confirmations: tuple[bool, bool],
) -> None:
    function = (
        vertical_cylindrical_tank_volume
        if function_name == "vertical"
        else horizontal_cylindrical_tank_volume
    )

    with pytest.raises(LevelCalculationDomainError):
        function(
            *(length(value) for value in dimensions),
            *confirmations,
        )


@pytest.mark.parametrize(
    ("case", "invoke"),
    (
        (
            "open tap above minimum level",
            lambda: open_vessel_dp_range(
                length(1.0),
                length(5.0),
                length(1.1),
                length(-1.0),
                density(850.0),
                density(850.0),
                gravity(),
                absolute_pressure(101_325.0),
                absolute_pressure(101_325.0),
            ),
        ),
        (
            "dry-leg HP port above minimum level",
            lambda: dry_leg_dp_range(
                length(1.0),
                length(5.0),
                length(1.1),
                length(-1.0),
                density(850.0),
                density(5.0),
                gravity(),
                absolute_pressure(500_000.0),
            ),
        ),
        (
            "wet-leg top below maximum level",
            lambda: wet_leg_dp_range(
                length(1.0),
                length(5.0),
                length(-1.0),
                length(4.9),
                length(-1.0),
                density(850.0),
                density(5.0),
                density(1_000.0),
                gravity(),
                absolute_pressure(500_000.0),
            ),
        ),
        (
            "remote HP seal above minimum level",
            lambda: remote_seal_dp_range(
                length(1.0),
                length(5.0),
                length(1.1),
                length(6.0),
                length(-1.0),
                length(-1.0),
                density(850.0),
                density(5.0),
                density(950.0),
                density(950.0),
                gravity(),
                absolute_pressure(500_000.0),
                True,
                True,
            ),
        ),
        (
            "remote LP seal below maximum level",
            lambda: remote_seal_dp_range(
                length(1.0),
                length(5.0),
                length(0.0),
                length(4.9),
                length(-1.0),
                length(-1.0),
                density(850.0),
                density(5.0),
                density(950.0),
                density(950.0),
                gravity(),
                absolute_pressure(500_000.0),
                True,
                True,
            ),
        ),
        (
            "zero flooded height",
            lambda: interface_dp_range(
                length(0.0),
                length(0.1),
                length(0.0),
                length(0.0),
                length(0.0),
                length(0.0),
                density(1_000.0),
                density(800.0),
                gravity(),
                absolute_pressure(500_000.0),
            ),
        ),
    ),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_installation_geometry_boundaries_are_enforced(case, invoke) -> None:
    del case
    with pytest.raises(LevelCalculationDomainError):
        invoke()


@pytest.mark.parametrize(
    "factory",
    (open_reference, dry_reference, wet_reference, interface_reference),
)
def test_range_functions_are_deterministic(factory) -> None:
    assert factory() == factory()


def registered_values() -> dict[
    str,
    dict[str, EngineeringQuantity | bool],
]:
    """Return one independently calculated input vector per registered method."""

    return {
        "level.dp.closed-dry-leg-range": {
            "lower-level-elevation": length(1.0),
            "upper-level-elevation": length(5.0),
            "high-side-port-elevation": length(-1.0),
            "low-side-port-elevation": length(-1.0),
            "process-liquid-density": density(850.0),
            "dry-leg-vapour-density": density(5.0),
            "gravitational-acceleration": gravity(),
            "vessel-vapour-absolute-pressure": absolute_pressure(500_000.0),
        },
        "level.dp.closed-wet-leg-range": {
            "lower-level-elevation": length(1.0),
            "upper-level-elevation": length(5.0),
            "high-side-port-elevation": length(-1.0),
            "low-side-reference-elevation": length(6.0),
            "low-side-port-elevation": length(-1.0),
            "process-liquid-density": density(850.0),
            "vapour-density": density(5.0),
            "wet-leg-fill-density": density(1_000.0),
            "gravitational-acceleration": gravity(),
            "vessel-vapour-absolute-pressure": absolute_pressure(500_000.0),
        },
        "level.dp.endpoint-range": {
            "sensor-lower-range-limit": differential_pressure(-100.0, "kPa"),
            "sensor-upper-range-limit": differential_pressure(100.0, "kPa"),
            "lower-endpoint-high-side-absolute-pressure": absolute_pressure(
                600.0, "kPa"
            ),
            "lower-endpoint-low-side-absolute-pressure": absolute_pressure(
                650.0, "kPa"
            ),
            "upper-endpoint-high-side-absolute-pressure": absolute_pressure(
                700.0, "kPa"
            ),
            "upper-endpoint-low-side-absolute-pressure": absolute_pressure(
                620.0, "kPa"
            ),
            "maximum-high-side-absolute-pressure": absolute_pressure(
                900.0, "kPa"
            ),
            "maximum-low-side-absolute-pressure": absolute_pressure(
                850.0, "kPa"
            ),
            "maximum-positive-differential-pressure": differential_pressure(
                150.0, "kPa"
            ),
            "maximum-negative-differential-pressure": differential_pressure(
                -120.0, "kPa"
            ),
            "maximum-static-absolute-pressure": absolute_pressure(
                1_000.0, "kPa"
            ),
            "positive-overpressure-limit": differential_pressure(
                200.0, "kPa"
            ),
            "negative-overpressure-limit": differential_pressure(
                -200.0, "kPa"
            ),
        },
        "level.dp.interface-range": {
            "lower-interface-elevation": length(1.0),
            "upper-interface-elevation": length(3.0),
            "bottom-reference-elevation": length(0.0),
            "total-flooded-height": length(4.0),
            "high-side-port-elevation": length(0.0),
            "low-side-port-elevation": length(4.0),
            "lower-fluid-density": density(1_000.0),
            "upper-fluid-density": density(800.0),
            "gravitational-acceleration": gravity(),
            "top-reference-absolute-pressure": absolute_pressure(500_000.0),
        },
        "level.dp.open-vessel-range": {
            "lower-level-elevation": length(1.0),
            "upper-level-elevation": length(5.0),
            "high-side-tap-elevation": length(0.0),
            "high-side-port-elevation": length(-1.0),
            "process-liquid-density": density(850.0),
            "high-side-leg-density": density(850.0),
            "gravitational-acceleration": gravity(),
            "vessel-surface-atmospheric-absolute-pressure": absolute_pressure(
                101_325.0
            ),
            "low-side-reference-atmospheric-absolute-pressure": absolute_pressure(
                101_325.0
            ),
        },
        "level.dp.remote-seal-range": {
            "lower-level-elevation": length(1.0),
            "upper-level-elevation": length(5.0),
            "high-side-seal-elevation": length(0.0),
            "low-side-seal-elevation": length(6.0),
            "high-side-port-elevation": length(-1.0),
            "low-side-port-elevation": length(-1.0),
            "process-liquid-density": density(850.0),
            "vapour-density": density(5.0),
            "high-side-fill-density": density(950.0),
            "low-side-fill-density": density(950.0),
            "gravitational-acceleration": gravity(),
            "vessel-vapour-absolute-pressure": absolute_pressure(500_000.0),
            "installed-geometry-confirmed": True,
            "fill-fluid-temperature-density-confirmed": True,
        },
        "level.hydrostatic.column-pressure": {
            "density": density(998.2),
            "vertical-height": length(3.5),
            "gravitational-acceleration": gravity(),
        },
        "level.tank.horizontal-cylinder": {
            "internal-diameter": length(2.0),
            "cylindrical-length": length(5.0),
            "liquid-height": length(0.5),
            "flat-end-internal-geometry-confirmed": True,
            "level-cylinder-geometry-confirmed": True,
        },
        "level.tank.vertical-cylinder": {
            "internal-diameter": length(2.0),
            "straight-side-height": length(5.0),
            "liquid-height": length(3.0),
            "flat-end-internal-geometry-confirmed": True,
            "liquid-level-within-cylinder-confirmed": True,
        },
    }


def registered_request(
    method_id: str,
    values: dict[str, EngineeringQuantity | bool],
) -> CalculationRequest:
    """Build a request from an exact method's public input contract."""

    definition = LEVEL_METHOD_REGISTRY.resolve(method_id, "1.0.0")
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


def level_engine() -> CalculationEngine:
    return CalculationEngine(
        registry=LEVEL_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )


def test_level_registry_exact_identity_and_review_state() -> None:
    """Only the nine frozen Step 95 exact-version methods are registered."""

    assert LEVEL_METHOD_IDS == EXPECTED_LEVEL_METHOD_IDS
    assert LEVEL_METHOD_REGISTRY.method_ids == EXPECTED_LEVEL_METHOD_IDS
    assert len(LEVEL_METHOD_REGISTRY.definitions) == 9
    assert all(
        definition.method_version == "1.0.0"
        for definition in LEVEL_METHOD_REGISTRY.definitions
    )
    assert all(
        definition.lifecycle_status is MethodLifecycleStatus.APPROVED
        for definition in LEVEL_METHOD_REGISTRY.definitions
    )
    assert all(
        definition.test_vector_reference_ids
        for definition in LEVEL_METHOD_REGISTRY.definitions
    )
    assert all(
        definition.reviews
        for definition in LEVEL_METHOD_REGISTRY.definitions
    )


def test_engineering_registry_composes_general_and_level_without_mutation() -> None:
    assert len(GENERAL_METHOD_REGISTRY.definitions) == 17
    assert len(ENGINEERING_METHOD_REGISTRY.definitions) == 26
    assert ENGINEERING_METHOD_REGISTRY.method_ids == tuple(
        sorted(
            GENERAL_METHOD_REGISTRY.method_ids
            + LEVEL_METHOD_REGISTRY.method_ids
        )
    )


@pytest.mark.parametrize(
    ("method_id", "output_id", "expected", "expected_unit"),
    (
        (
            "level.dp.closed-dry-leg-range",
            "lower-range-value",
            16_573.2385,
            "Pa",
        ),
        (
            "level.dp.closed-wet-leg-range",
            "lower-range-value",
            -51_730.07875,
            "Pa",
        ),
        (
            "level.dp.endpoint-range",
            "lower-range-value",
            -50_000.0,
            "Pa",
        ),
        (
            "level.dp.interface-range",
            "lower-range-value",
            33_342.61,
            "Pa",
        ),
        (
            "level.dp.open-vessel-range",
            "lower-range-value",
            16_671.305,
            "Pa",
        ),
        (
            "level.dp.remote-seal-range",
            "lower-range-value",
            -47_317.08625,
            "Pa",
        ),
        (
            "level.hydrostatic.column-pressure",
            "differential-pressure",
            34_261.493105,
            "Pa",
        ),
        (
            "level.tank.horizontal-cylinder",
            "liquid-volume",
            3.070924246521893,
            "m3",
        ),
        (
            "level.tank.vertical-cylinder",
            "liquid-volume",
            9.42477796076938,
            "m3",
        ),
    ),
    ids=EXPECTED_LEVEL_METHOD_IDS,
)
def test_every_registered_level_method_executes_reference_vector(
    method_id: str,
    output_id: str,
    expected: float,
    expected_unit: str,
) -> None:
    result = level_engine().execute(
        registered_request(method_id, registered_values()[method_id])
    )

    assert result.status is CalculationStatus.COMPLETED
    assert len(result.result_fingerprint) == 64
    assert result.trace_steps[-1].formula_identifier.startswith(
        "level.formula."
    )
    output = next(item for item in result.outputs if item.output_id == output_id)
    assert output.quantity is not None
    assert output.quantity.value == pytest.approx(expected, rel=1e-11)
    assert output.quantity.unit == expected_unit


@pytest.mark.parametrize(
    ("method_id", "omitted_input_id"),
    (
        ("level.dp.closed-dry-leg-range", "dry-leg-vapour-density"),
        ("level.dp.closed-wet-leg-range", "wet-leg-fill-density"),
        ("level.dp.endpoint-range", "maximum-static-absolute-pressure"),
        ("level.dp.interface-range", "top-reference-absolute-pressure"),
        (
            "level.dp.open-vessel-range",
            "vessel-surface-atmospheric-absolute-pressure",
        ),
        (
            "level.dp.remote-seal-range",
            "fill-fluid-temperature-density-confirmed",
        ),
        ("level.hydrostatic.column-pressure", "gravitational-acceleration"),
        (
            "level.tank.horizontal-cylinder",
            "level-cylinder-geometry-confirmed",
        ),
        ("level.tank.vertical-cylinder", "straight-side-height"),
    ),
    ids=EXPECTED_LEVEL_METHOD_IDS,
)
def test_registered_methods_never_invent_missing_physical_state(
    method_id: str,
    omitted_input_id: str,
) -> None:
    complete = registered_request(method_id, registered_values()[method_id])
    incomplete = CalculationRequest(
        request_id=complete.request_id,
        calculation_type=complete.calculation_type,
        method_id=complete.method_id,
        method_version=complete.method_version,
        requested_at=complete.requested_at,
        inputs=tuple(
            item
            for item in complete.inputs
            if item.input_id != omitted_input_id
        ),
    )

    result = level_engine().execute(incomplete)

    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert result.outputs == ()
    assert any(
        item.input_id == omitted_input_id
        for item in result.missing_inputs
    )


@pytest.mark.parametrize(
    ("method_id", "confirmation_id"),
    (
        ("level.dp.remote-seal-range", "installed-geometry-confirmed"),
        (
            "level.dp.remote-seal-range",
            "fill-fluid-temperature-density-confirmed",
        ),
        (
            "level.tank.horizontal-cylinder",
            "flat-end-internal-geometry-confirmed",
        ),
        (
            "level.tank.horizontal-cylinder",
            "level-cylinder-geometry-confirmed",
        ),
        (
            "level.tank.vertical-cylinder",
            "flat-end-internal-geometry-confirmed",
        ),
        (
            "level.tank.vertical-cylinder",
            "liquid-level-within-cylinder-confirmed",
        ),
    ),
)
def test_registered_methods_block_unconfirmed_applicability(
    method_id: str,
    confirmation_id: str,
) -> None:
    values = dict(registered_values()[method_id])
    values[confirmation_id] = False

    result = level_engine().execute(registered_request(method_id, values))

    assert result.status in {
        CalculationStatus.BLOCKED,
        CalculationStatus.NOT_APPLICABLE,
    }
    assert result.outputs == ()


def test_registered_inadequate_endpoint_screen_completes_with_warning() -> None:
    values = dict(registered_values()["level.dp.endpoint-range"])
    values["sensor-lower-range-limit"] = differential_pressure(-40.0, "kPa")
    values["sensor-upper-range-limit"] = differential_pressure(40.0, "kPa")
    values["maximum-high-side-absolute-pressure"] = absolute_pressure(
        1_100.0, "kPa"
    )
    values["maximum-positive-differential-pressure"] = differential_pressure(
        250.0, "kPa"
    )
    values["maximum-negative-differential-pressure"] = differential_pressure(
        -250.0, "kPa"
    )

    result = level_engine().execute(
        registered_request("level.dp.endpoint-range", values)
    )

    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert result.outputs
    adequacy = next(
        item
        for item in result.outputs
        if item.output_id == "pressure-limits-adequate"
    )
    assert adequacy.categorical_value is False
    assert any(not finding.blocking for finding in result.findings)


def test_registered_column_fingerprint_is_unit_invariant() -> None:
    canonical = registered_values()["level.hydrostatic.column-pressure"]
    alternate = {
        "density": density(0.9982, "kg/L"),
        "vertical-height": length(3_500.0, "mm"),
        "gravitational-acceleration": gravity(),
    }
    engine = level_engine()

    first = engine.execute(
        registered_request("level.hydrostatic.column-pressure", canonical)
    )
    second = engine.execute(
        registered_request("level.hydrostatic.column-pressure", alternate)
    )

    assert first.outputs == second.outputs
    assert first.result_fingerprint == second.result_fingerprint


def test_registered_execution_is_deterministic_and_materially_sensitive() -> None:
    values = registered_values()["level.tank.vertical-cylinder"]
    engine = level_engine()
    request = registered_request("level.tank.vertical-cylinder", values)

    first = engine.execute(request)
    second = engine.execute(request)
    changed_values = dict(values)
    changed_values["liquid-height"] = length(4.0)
    changed = engine.execute(
        registered_request("level.tank.vertical-cylinder", changed_values)
    )

    assert first.status is CalculationStatus.COMPLETED
    assert first.outputs == second.outputs
    assert first.trace_steps == second.trace_steps
    assert first.result_fingerprint == second.result_fingerprint
    assert changed.outputs != first.outputs
    assert changed.result_fingerprint != first.result_fingerprint


@pytest.mark.parametrize(
    ("method_id", "field_id", "replacement"),
    (
        (
            "level.dp.open-vessel-range",
            "upper-level-elevation",
            length(1.0),
        ),
        (
            "level.dp.closed-dry-leg-range",
            "process-liquid-density",
            density(5.0),
        ),
        (
            "level.dp.closed-wet-leg-range",
            "upper-level-elevation",
            length(7.0),
        ),
        (
            "level.dp.interface-range",
            "lower-fluid-density",
            density(700.0),
        ),
        (
            "level.dp.endpoint-range",
            "sensor-upper-range-limit",
            differential_pressure(-100.0, "kPa"),
        ),
        (
            "level.tank.horizontal-cylinder",
            "liquid-height",
            length(2.1),
        ),
        (
            "level.tank.vertical-cylinder",
            "liquid-height",
            length(5.1),
        ),
    ),
)
def test_registered_invalid_domains_never_produce_outputs(
    method_id: str,
    field_id: str,
    replacement: EngineeringQuantity,
) -> None:
    values = dict(registered_values()[method_id])
    values[field_id] = replacement

    result = level_engine().execute(registered_request(method_id, values))

    assert result.status not in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }
    assert result.outputs == ()


def test_level_module_contains_no_dynamic_execution_or_voice_boundary() -> None:
    """Step 95 remains reviewed Python and does not pull Phase 10 voice in."""

    source_path = Path(__file__).parents[1] / "app/engineering/calculations/level.py"
    source = source_path.read_text(encoding="utf-8")

    prohibited = (
        "eval(",
        "exec(",
        "compile(",
        "importlib",
        "subprocess",
        "pickle.loads",
        "marshal.loads",
    )
    assert all(token not in source for token in prohibited)
    assert "voice" not in source.casefold()
