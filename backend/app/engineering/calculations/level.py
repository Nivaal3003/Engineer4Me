"""Reviewed pressure and level calculations for Phase 7 Step 95.

This module implements deterministic hydrostatic, differential-pressure
level, transmitter-range, pressure-limit, and cylindrical-tank geometry
methods.  Every density, gravitational acceleration, pressure basis, and
elevation is explicit.  Elevations increase upward and every differential
pressure is high-side pressure minus low-side pressure.

The direct functions revalidate immutable quantities at their public
boundaries.  The registered methods at the bottom of the module are an exact
allow-list; formula identifiers are trace metadata and are never evaluated.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from math import asin
from math import cos
from math import isfinite
from math import nextafter
from math import pi
from math import sin
from math import sqrt
from typing import Final

from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.method_models import FormulaMetadata
from app.engineering.calculations.method_models import InputNormalizationMode
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import MethodExecutionContext
from app.engineering.calculations.method_models import MethodExecutionOutcome
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import MethodReviewRecord
from app.engineering.calculations.method_models import MethodReviewType
from app.engineering.calculations.method_models import (
    NumericApplicabilityRange,
)
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.registry import CalculationMethodRegistry
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import UnitSystemError


LEVEL_CALCULATORS_VERSION: Final = "1.0.0"
LEVEL_CALCULATION_TYPE_PREFIX: Final = "level"
LEVEL_METHOD_VERSION: Final = "1.0.0"

_MAXIMUM_MAGNITUDE: Final = 1.0e300


class LevelCalculationError(ValueError):
    """Base error for deterministic pressure/level calculations."""

    code = "level_calculation_error"


class LevelCalculationInputError(LevelCalculationError):
    """Raised when a public input violates the typed contract."""

    code = "level_calculation_input_error"


class LevelCalculationDomainError(LevelCalculationError):
    """Raised when finite inputs are outside the physical model domain."""

    code = "level_calculation_domain_error"


class LevelRangeResult(CalculationModel):
    """Differential pressure at lower and upper level endpoints."""

    lower_endpoint_differential_pressure: EngineeringQuantity
    upper_endpoint_differential_pressure: EngineeringQuantity
    lower_range_value: EngineeringQuantity
    upper_range_value: EngineeringQuantity
    signed_span: EngineeringQuantity
    span: EngineeringQuantity
    output_direction: str


class PressureLevelRangeResult(LevelRangeResult):
    """Level range with explicit endpoint side absolute pressures."""

    lower_endpoint_high_side_absolute_pressure: EngineeringQuantity
    lower_endpoint_low_side_absolute_pressure: EngineeringQuantity
    upper_endpoint_high_side_absolute_pressure: EngineeringQuantity
    upper_endpoint_low_side_absolute_pressure: EngineeringQuantity


class LevelTransmitterRangeResult(CalculationModel):
    """Level range plus a sensor differential-pressure range screen."""

    lower_endpoint_differential_pressure: EngineeringQuantity
    upper_endpoint_differential_pressure: EngineeringQuantity
    lower_range_value: EngineeringQuantity
    upper_range_value: EngineeringQuantity
    signed_span: EngineeringQuantity
    span: EngineeringQuantity
    output_direction: str
    lower_range_margin: EngineeringQuantity
    upper_range_margin: EngineeringQuantity
    high_side_static_pressure_margin: EngineeringQuantity
    low_side_static_pressure_margin: EngineeringQuantity
    positive_overpressure_margin: EngineeringQuantity
    negative_overpressure_margin: EngineeringQuantity
    configured_range_within_sensor_limits: bool
    within_static_pressure_limit: bool
    within_differential_overpressure_limits: bool
    pressure_limits_adequate: bool


class PressureLimitScreenResult(CalculationModel):
    """Static/absolute and one-sided differential overpressure screen."""

    high_side_static_pressure_margin: EngineeringQuantity
    low_side_static_pressure_margin: EngineeringQuantity
    positive_overpressure_margin: EngineeringQuantity
    negative_overpressure_margin: EngineeringQuantity
    within_static_pressure_limit: bool
    within_differential_overpressure_limits: bool
    pressure_limits_adequate: bool


class TankVolumeResult(CalculationModel):
    """Liquid volume, full capacity, and dimensionless fill fraction."""

    liquid_volume: EngineeringQuantity
    full_capacity: EngineeringQuantity
    fill_fraction: EngineeringQuantity


def _revalidate_quantity(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> EngineeringQuantity:
    """Return a fresh unit-registry-validated quantity."""

    if not isinstance(quantity, EngineeringQuantity):
        raise LevelCalculationInputError(
            f"{field_name} must be an EngineeringQuantity."
        )
    try:
        validated = EngineeringQuantity.model_validate(
            quantity.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
        return DEFAULT_UNIT_REGISTRY.validate_quantity(validated)
    except Exception as exc:
        raise LevelCalculationInputError(
            f"{field_name} is not a valid supported engineering quantity."
        ) from exc


def _canonical_quantity(
    quantity: EngineeringQuantity,
    expected_kind: QuantityKind,
    *,
    field_name: str,
) -> EngineeringQuantity:
    """Validate one exact quantity kind and return its canonical value."""

    validated = _revalidate_quantity(quantity, field_name=field_name)
    if validated.quantity_kind != expected_kind.value:
        raise LevelCalculationInputError(
            f"{field_name} must use quantity kind {expected_kind.value!r}."
        )
    if validated.uncertainty is not None:
        raise LevelCalculationInputError(
            f"{field_name} uncertainty cannot be silently discarded."
        )
    try:
        return DEFAULT_UNIT_REGISTRY.canonicalize_quantity(validated)
    except UnitSystemError as exc:
        raise LevelCalculationInputError(
            f"{field_name} cannot be converted to its canonical unit."
        ) from exc


def _finite_result(value: float, *, field_name: str) -> float:
    """Reject non-finite or unsupported numerical results."""

    if not isfinite(value) or abs(value) > _MAXIMUM_MAGNITUDE:
        raise LevelCalculationDomainError(
            f"{field_name} exceeds the supported numerical range."
        )
    return 0.0 if value == 0.0 else value


def _quantity(
    quantity_kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    """Build one finite output quantity."""

    return EngineeringQuantity(
        quantity_kind=quantity_kind.value,
        value=_finite_result(value, field_name="calculation result"),
        unit=unit,
    )


def _convert_result(
    quantity: EngineeringQuantity,
    target_unit: str | None,
) -> EngineeringQuantity:
    """Convert one result only through the controlled unit registry."""

    if target_unit is None:
        return quantity
    if not isinstance(target_unit, str) or not target_unit.strip():
        raise LevelCalculationInputError(
            "target_unit must be a non-blank supported unit."
        )
    try:
        return DEFAULT_UNIT_REGISTRY.convert_quantity(quantity, target_unit)
    except UnitSystemError as exc:
        raise LevelCalculationInputError(
            "target_unit is incompatible with the result quantity."
        ) from exc


def _require_positive(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> None:
    if quantity.value <= 0.0:
        raise LevelCalculationDomainError(
            f"{field_name} must be greater than zero."
        )


def _require_nonnegative(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> None:
    if quantity.value < 0.0:
        raise LevelCalculationDomainError(f"{field_name} cannot be negative.")


def _require_ordered(
    lower: EngineeringQuantity,
    upper: EngineeringQuantity,
    *,
    lower_name: str,
    upper_name: str,
    allow_equal: bool = False,
) -> None:
    ordered = (
        lower.value <= upper.value
        if allow_equal
        else lower.value < upper.value
    )
    if not ordered:
        relation = "less than or equal to" if allow_equal else "less than"
        raise LevelCalculationDomainError(
            f"{lower_name} must be {relation} {upper_name}."
        )


def liquid_column_pressure(
    density: EngineeringQuantity,
    vertical_height: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    *,
    target_unit: str = "Pa",
) -> EngineeringQuantity:
    """Calculate positive liquid-column differential pressure, rho*g*h."""

    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    height = _canonical_quantity(
        vertical_height,
        QuantityKind.LENGTH,
        field_name="vertical_height",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    _require_positive(density_value, field_name="density")
    _require_nonnegative(height, field_name="vertical_height")
    _require_positive(gravity, field_name="gravitational_acceleration")
    result = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        density_value.value * gravity.value * height.value,
        "Pa",
    )
    return _convert_result(result, target_unit)


def liquid_head_from_pressure(
    differential_pressure: EngineeringQuantity,
    density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    *,
    target_unit: str = "m",
) -> EngineeringQuantity:
    """Calculate positive liquid head from explicit DP, density, and gravity."""

    pressure = _canonical_quantity(
        differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="differential_pressure",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    _require_nonnegative(pressure, field_name="differential_pressure")
    _require_positive(density_value, field_name="density")
    _require_positive(gravity, field_name="gravitational_acceleration")
    result = _quantity(
        QuantityKind.LENGTH,
        pressure.value / (density_value.value * gravity.value),
        "m",
    )
    return _convert_result(result, target_unit)


def _range_result(
    lower_dp_value: float,
    upper_dp_value: float,
) -> LevelRangeResult:
    """Build one range result while preserving the signed response."""

    lower = _finite_result(lower_dp_value, field_name="lower level DP")
    upper = _finite_result(upper_dp_value, field_name="upper level DP")
    signed = _finite_result(upper - lower, field_name="signed span")
    if signed == 0.0:
        raise LevelCalculationDomainError(
            "The level endpoints produce a degenerate zero span."
        )
    direction = "increasing" if signed > 0.0 else "decreasing"
    lower_quantity = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        lower,
        "Pa",
    )
    upper_quantity = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        upper,
        "Pa",
    )
    return LevelRangeResult(
        lower_endpoint_differential_pressure=lower_quantity,
        upper_endpoint_differential_pressure=upper_quantity,
        lower_range_value=lower_quantity,
        upper_range_value=upper_quantity,
        signed_span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            signed,
            "Pa",
        ),
        span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            abs(signed),
            "Pa",
        ),
        output_direction=direction,
    )


def _pressure_range_result(
    lower_high_pressure: float,
    lower_low_pressure: float,
    upper_high_pressure: float,
    upper_low_pressure: float,
    *,
    lower_differential_pressure: float | None = None,
    upper_differential_pressure: float | None = None,
) -> PressureLevelRangeResult:
    """Build a range after enforcing nonnegative absolute side pressure."""

    pressures = (
        lower_high_pressure,
        lower_low_pressure,
        upper_high_pressure,
        upper_low_pressure,
    )
    if any(value < 0.0 for value in pressures):
        raise LevelCalculationDomainError(
            "Calculated side absolute pressure cannot be negative."
        )
    base = _range_result(
        (
            lower_high_pressure - lower_low_pressure
            if lower_differential_pressure is None
            else lower_differential_pressure
        ),
        (
            upper_high_pressure - upper_low_pressure
            if upper_differential_pressure is None
            else upper_differential_pressure
        ),
    )
    return PressureLevelRangeResult(
        **base.model_dump(mode="python", round_trip=True, warnings="error"),
        lower_endpoint_high_side_absolute_pressure=_quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            lower_high_pressure,
            "Pa",
        ),
        lower_endpoint_low_side_absolute_pressure=_quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            lower_low_pressure,
            "Pa",
        ),
        upper_endpoint_high_side_absolute_pressure=_quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            upper_high_pressure,
            "Pa",
        ),
        upper_endpoint_low_side_absolute_pressure=_quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            upper_low_pressure,
            "Pa",
        ),
    )


def open_vessel_dp_range(
    lower_level_elevation: EngineeringQuantity,
    upper_level_elevation: EngineeringQuantity,
    high_side_tap_elevation: EngineeringQuantity,
    high_side_port_elevation: EngineeringQuantity,
    process_liquid_density: EngineeringQuantity,
    high_side_leg_density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    vessel_surface_atmospheric_absolute_pressure: EngineeringQuantity,
    low_side_reference_atmospheric_absolute_pressure: EngineeringQuantity,
) -> PressureLevelRangeResult:
    """Calculate an atmosphere-referenced open-vessel DP level range."""

    lower = _canonical_quantity(
        lower_level_elevation,
        QuantityKind.LENGTH,
        field_name="lower_level_elevation",
    )
    upper = _canonical_quantity(
        upper_level_elevation,
        QuantityKind.LENGTH,
        field_name="upper_level_elevation",
    )
    tap = _canonical_quantity(
        high_side_tap_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_tap_elevation",
    )
    port = _canonical_quantity(
        high_side_port_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_port_elevation",
    )
    density = _canonical_quantity(
        process_liquid_density,
        QuantityKind.DENSITY,
        field_name="process_liquid_density",
    )
    leg_density = _canonical_quantity(
        high_side_leg_density,
        QuantityKind.DENSITY,
        field_name="high_side_leg_density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    surface_atmosphere = _canonical_quantity(
        vessel_surface_atmospheric_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="vessel_surface_atmospheric_absolute_pressure",
    )
    reference_atmosphere = _canonical_quantity(
        low_side_reference_atmospheric_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="low_side_reference_atmospheric_absolute_pressure",
    )
    _require_ordered(
        lower,
        upper,
        lower_name="lower_level_elevation",
        upper_name="upper_level_elevation",
    )
    if tap.value > lower.value:
        raise LevelCalculationDomainError(
            "high_side_tap_elevation cannot exceed the lower calibrated "
            "liquid elevation."
        )
    _require_positive(density, field_name="process_liquid_density")
    _require_positive(leg_density, field_name="high_side_leg_density")
    _require_positive(gravity, field_name="gravitational_acceleration")
    _require_nonnegative(
        surface_atmosphere,
        field_name="vessel_surface_atmospheric_absolute_pressure",
    )
    _require_nonnegative(
        reference_atmosphere,
        field_name="low_side_reference_atmospheric_absolute_pressure",
    )
    if surface_atmosphere.value != reference_atmosphere.value:
        raise LevelCalculationDomainError(
            "Open-vessel surface and low-side reference atmospheric absolute "
            "pressures must be equal for this model."
        )

    fixed_leg_head = (
        leg_density.value * gravity.value * (tap.value - port.value)
    )
    lower_high = surface_atmosphere.value + (
        density.value * gravity.value * (lower.value - tap.value)
        + fixed_leg_head
    )
    upper_high = surface_atmosphere.value + (
        density.value * gravity.value * (upper.value - tap.value)
        + fixed_leg_head
    )
    return _pressure_range_result(
        lower_high,
        reference_atmosphere.value,
        upper_high,
        reference_atmosphere.value,
        lower_differential_pressure=(
            density.value * gravity.value * (lower.value - tap.value)
            + fixed_leg_head
        ),
        upper_differential_pressure=(
            density.value * gravity.value * (upper.value - tap.value)
            + fixed_leg_head
        ),
    )


def dry_leg_dp_range(
    lower_level_elevation: EngineeringQuantity,
    upper_level_elevation: EngineeringQuantity,
    high_side_sensor_elevation: EngineeringQuantity,
    low_side_sensor_elevation: EngineeringQuantity,
    process_liquid_density: EngineeringQuantity,
    dry_leg_fluid_density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    vessel_vapour_absolute_pressure: EngineeringQuantity,
) -> PressureLevelRangeResult:
    """Calculate HP-minus-LP range for an explicit uniform dry-leg fluid.

    The common vessel pressure cancels.  The high-side path from liquid
    surface to sensor uses process-liquid density; the low-side path from the
    same surface datum to sensor uses the explicit dry-leg-fluid density.
    """

    lower = _canonical_quantity(
        lower_level_elevation,
        QuantityKind.LENGTH,
        field_name="lower_level_elevation",
    )
    upper = _canonical_quantity(
        upper_level_elevation,
        QuantityKind.LENGTH,
        field_name="upper_level_elevation",
    )
    high_sensor = _canonical_quantity(
        high_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_sensor_elevation",
    )
    low_sensor = _canonical_quantity(
        low_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_sensor_elevation",
    )
    process_density = _canonical_quantity(
        process_liquid_density,
        QuantityKind.DENSITY,
        field_name="process_liquid_density",
    )
    dry_density = _canonical_quantity(
        dry_leg_fluid_density,
        QuantityKind.DENSITY,
        field_name="dry_leg_fluid_density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    vessel_pressure = _canonical_quantity(
        vessel_vapour_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="vessel_vapour_absolute_pressure",
    )
    _require_ordered(
        lower,
        upper,
        lower_name="lower_level_elevation",
        upper_name="upper_level_elevation",
    )
    _require_positive(process_density, field_name="process_liquid_density")
    _require_nonnegative(dry_density, field_name="dry_leg_fluid_density")
    _require_positive(gravity, field_name="gravitational_acceleration")
    _require_nonnegative(
        vessel_pressure,
        field_name="vessel_vapour_absolute_pressure",
    )
    if process_density.value == dry_density.value:
        raise LevelCalculationDomainError(
            "Equal process and dry-leg densities produce no level response."
        )

    if high_sensor.value > lower.value:
        raise LevelCalculationDomainError(
            "high_side_sensor_elevation cannot exceed the lower calibrated "
            "liquid elevation for this flooded high-side model."
        )

    def calculate(level: float) -> tuple[float, float]:
        high_pressure = vessel_pressure.value + gravity.value * (
            process_density.value * (level - high_sensor.value)
        )
        low_pressure = vessel_pressure.value + gravity.value * (
            dry_density.value * (level - low_sensor.value)
        )
        return high_pressure, low_pressure

    lower_high, lower_low = calculate(lower.value)
    upper_high, upper_low = calculate(upper.value)
    return _pressure_range_result(
        lower_high,
        lower_low,
        upper_high,
        upper_low,
        lower_differential_pressure=gravity.value
        * (
            process_density.value * (lower.value - high_sensor.value)
            - dry_density.value * (lower.value - low_sensor.value)
        ),
        upper_differential_pressure=gravity.value
        * (
            process_density.value * (upper.value - high_sensor.value)
            - dry_density.value * (upper.value - low_sensor.value)
        ),
    )


def wet_leg_dp_range(
    lower_level_elevation: EngineeringQuantity,
    upper_level_elevation: EngineeringQuantity,
    high_side_sensor_elevation: EngineeringQuantity,
    low_side_reference_elevation: EngineeringQuantity,
    low_side_sensor_elevation: EngineeringQuantity,
    process_liquid_density: EngineeringQuantity,
    vapour_density: EngineeringQuantity,
    wet_leg_fill_density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    vessel_vapour_absolute_pressure: EngineeringQuantity,
) -> PressureLevelRangeResult:
    """Calculate HP-minus-LP range for an explicit wet-leg arrangement."""

    lower = _canonical_quantity(
        lower_level_elevation,
        QuantityKind.LENGTH,
        field_name="lower_level_elevation",
    )
    upper = _canonical_quantity(
        upper_level_elevation,
        QuantityKind.LENGTH,
        field_name="upper_level_elevation",
    )
    high_sensor = _canonical_quantity(
        high_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_sensor_elevation",
    )
    low_reference = _canonical_quantity(
        low_side_reference_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_reference_elevation",
    )
    low_sensor = _canonical_quantity(
        low_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_sensor_elevation",
    )
    process_density = _canonical_quantity(
        process_liquid_density,
        QuantityKind.DENSITY,
        field_name="process_liquid_density",
    )
    gas_density = _canonical_quantity(
        vapour_density,
        QuantityKind.DENSITY,
        field_name="vapour_density",
    )
    fill_density = _canonical_quantity(
        wet_leg_fill_density,
        QuantityKind.DENSITY,
        field_name="wet_leg_fill_density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    vessel_pressure = _canonical_quantity(
        vessel_vapour_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="vessel_vapour_absolute_pressure",
    )
    _require_ordered(
        lower,
        upper,
        lower_name="lower_level_elevation",
        upper_name="upper_level_elevation",
    )
    if upper.value > low_reference.value:
        raise LevelCalculationDomainError(
            "upper_level_elevation cannot exceed the low-side reference "
            "elevation for this wet-leg model."
        )
    _require_positive(process_density, field_name="process_liquid_density")
    _require_nonnegative(gas_density, field_name="vapour_density")
    _require_positive(fill_density, field_name="wet_leg_fill_density")
    _require_positive(gravity, field_name="gravitational_acceleration")
    _require_nonnegative(
        vessel_pressure,
        field_name="vessel_vapour_absolute_pressure",
    )
    if process_density.value == gas_density.value:
        raise LevelCalculationDomainError(
            "Equal process-liquid and vapour densities produce no level "
            "response."
        )

    low_fill_head = fill_density.value * (
        low_reference.value - low_sensor.value
    )

    if high_sensor.value > lower.value:
        raise LevelCalculationDomainError(
            "high_side_sensor_elevation cannot exceed the lower calibrated "
            "liquid elevation for this flooded high-side model."
        )

    def calculate(level: float) -> tuple[float, float]:
        high_pressure = vessel_pressure.value + gravity.value * (
            process_density.value * (level - high_sensor.value)
        )
        low_pressure = vessel_pressure.value + gravity.value * (
            gas_density.value * (level - low_reference.value) + low_fill_head
        )
        return high_pressure, low_pressure

    lower_high, lower_low = calculate(lower.value)
    upper_high, upper_low = calculate(upper.value)
    return _pressure_range_result(
        lower_high,
        lower_low,
        upper_high,
        upper_low,
        lower_differential_pressure=gravity.value
        * (
            process_density.value * (lower.value - high_sensor.value)
            - gas_density.value * (lower.value - low_reference.value)
            - low_fill_head
        ),
        upper_differential_pressure=gravity.value
        * (
            process_density.value * (upper.value - high_sensor.value)
            - gas_density.value * (upper.value - low_reference.value)
            - low_fill_head
        ),
    )


def remote_seal_dp_range(
    lower_level_elevation: EngineeringQuantity,
    upper_level_elevation: EngineeringQuantity,
    high_side_seal_elevation: EngineeringQuantity,
    low_side_seal_elevation: EngineeringQuantity,
    high_side_sensor_elevation: EngineeringQuantity,
    low_side_sensor_elevation: EngineeringQuantity,
    process_liquid_density: EngineeringQuantity,
    vapour_density: EngineeringQuantity,
    high_side_fill_density: EngineeringQuantity,
    low_side_fill_density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    vessel_vapour_absolute_pressure: EngineeringQuantity,
    installed_geometry_confirmed: bool,
    fill_fluid_temperature_density_confirmed: bool,
) -> PressureLevelRangeResult:
    """Calculate a dual-remote-seal level range with explicit capillary head."""

    if not isinstance(installed_geometry_confirmed, bool) or not isinstance(
        fill_fluid_temperature_density_confirmed,
        bool,
    ):
        raise LevelCalculationInputError(
            "Remote-seal applicability confirmations must be booleans."
        )
    if not installed_geometry_confirmed:
        raise LevelCalculationDomainError(
            "Installed seal, transmitter, and elevation geometry must be "
            "explicitly confirmed."
        )
    if not fill_fluid_temperature_density_confirmed:
        raise LevelCalculationDomainError(
            "Fill-fluid suitability and temperature-specific density must "
            "be explicitly confirmed."
        )

    lower = _canonical_quantity(
        lower_level_elevation,
        QuantityKind.LENGTH,
        field_name="lower_level_elevation",
    )
    upper = _canonical_quantity(
        upper_level_elevation,
        QuantityKind.LENGTH,
        field_name="upper_level_elevation",
    )
    high_seal = _canonical_quantity(
        high_side_seal_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_seal_elevation",
    )
    low_seal = _canonical_quantity(
        low_side_seal_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_seal_elevation",
    )
    high_sensor = _canonical_quantity(
        high_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_sensor_elevation",
    )
    low_sensor = _canonical_quantity(
        low_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_sensor_elevation",
    )
    process_density = _canonical_quantity(
        process_liquid_density,
        QuantityKind.DENSITY,
        field_name="process_liquid_density",
    )
    gas_density = _canonical_quantity(
        vapour_density,
        QuantityKind.DENSITY,
        field_name="vapour_density",
    )
    high_fill_density = _canonical_quantity(
        high_side_fill_density,
        QuantityKind.DENSITY,
        field_name="high_side_fill_density",
    )
    low_fill_density = _canonical_quantity(
        low_side_fill_density,
        QuantityKind.DENSITY,
        field_name="low_side_fill_density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    vessel_pressure = _canonical_quantity(
        vessel_vapour_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="vessel_vapour_absolute_pressure",
    )
    _require_ordered(
        lower,
        upper,
        lower_name="lower_level_elevation",
        upper_name="upper_level_elevation",
    )
    if high_seal.value > lower.value:
        raise LevelCalculationDomainError(
            "high_side_seal_elevation must remain submerged at the lower "
            "calibrated level."
        )
    if low_seal.value < upper.value:
        raise LevelCalculationDomainError(
            "low_side_seal_elevation must remain above the upper calibrated "
            "level."
        )
    for value, name in (
        (process_density, "process_liquid_density"),
        (high_fill_density, "high_side_fill_density"),
        (low_fill_density, "low_side_fill_density"),
        (gravity, "gravitational_acceleration"),
    ):
        _require_positive(value, field_name=name)
    _require_nonnegative(gas_density, field_name="vapour_density")
    _require_nonnegative(
        vessel_pressure,
        field_name="vessel_vapour_absolute_pressure",
    )
    if process_density.value == gas_density.value:
        raise LevelCalculationDomainError(
            "Equal process-liquid and vapour densities produce no level "
            "response."
        )

    high_capillary_head = high_fill_density.value * (
        high_seal.value - high_sensor.value
    )
    low_capillary_head = low_fill_density.value * (
        low_seal.value - low_sensor.value
    )

    def calculate(level: float) -> tuple[float, float]:
        high_pressure = vessel_pressure.value + gravity.value * (
            process_density.value * (level - high_seal.value)
            + high_capillary_head
        )
        low_pressure = vessel_pressure.value + gravity.value * (
            gas_density.value * (level - low_seal.value) + low_capillary_head
        )
        return high_pressure, low_pressure

    lower_high, lower_low = calculate(lower.value)
    upper_high, upper_low = calculate(upper.value)
    return _pressure_range_result(
        lower_high,
        lower_low,
        upper_high,
        upper_low,
        lower_differential_pressure=gravity.value
        * (
            process_density.value * (lower.value - high_seal.value)
            + high_capillary_head
            - gas_density.value * (lower.value - low_seal.value)
            - low_capillary_head
        ),
        upper_differential_pressure=gravity.value
        * (
            process_density.value * (upper.value - high_seal.value)
            + high_capillary_head
            - gas_density.value * (upper.value - low_seal.value)
            - low_capillary_head
        ),
    )


def interface_dp_range(
    lower_interface_elevation: EngineeringQuantity,
    upper_interface_elevation: EngineeringQuantity,
    bottom_reference_elevation: EngineeringQuantity,
    total_flooded_height: EngineeringQuantity,
    high_side_sensor_elevation: EngineeringQuantity,
    low_side_sensor_elevation: EngineeringQuantity,
    lower_fluid_density: EngineeringQuantity,
    upper_fluid_density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    top_reference_absolute_pressure: EngineeringQuantity,
) -> PressureLevelRangeResult:
    """Calculate DP interface range across a fully flooded two-liquid height."""

    lower_interface = _canonical_quantity(
        lower_interface_elevation,
        QuantityKind.LENGTH,
        field_name="lower_interface_elevation",
    )
    upper_interface = _canonical_quantity(
        upper_interface_elevation,
        QuantityKind.LENGTH,
        field_name="upper_interface_elevation",
    )
    bottom = _canonical_quantity(
        bottom_reference_elevation,
        QuantityKind.LENGTH,
        field_name="bottom_reference_elevation",
    )
    flooded_height = _canonical_quantity(
        total_flooded_height,
        QuantityKind.LENGTH,
        field_name="total_flooded_height",
    )
    high_sensor = _canonical_quantity(
        high_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="high_side_sensor_elevation",
    )
    low_sensor = _canonical_quantity(
        low_side_sensor_elevation,
        QuantityKind.LENGTH,
        field_name="low_side_sensor_elevation",
    )
    lower_density = _canonical_quantity(
        lower_fluid_density,
        QuantityKind.DENSITY,
        field_name="lower_fluid_density",
    )
    upper_density = _canonical_quantity(
        upper_fluid_density,
        QuantityKind.DENSITY,
        field_name="upper_fluid_density",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    top_pressure = _canonical_quantity(
        top_reference_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="top_reference_absolute_pressure",
    )
    _require_positive(flooded_height, field_name="total_flooded_height")
    top_elevation = bottom.value + flooded_height.value
    _require_ordered(
        lower_interface,
        upper_interface,
        lower_name="lower_interface_elevation",
        upper_name="upper_interface_elevation",
    )
    if (
        lower_interface.value < bottom.value
        or upper_interface.value > top_elevation
    ):
        raise LevelCalculationDomainError(
            "Interface range must remain inside the bottom/top references."
        )
    _require_positive(lower_density, field_name="lower_fluid_density")
    _require_positive(upper_density, field_name="upper_fluid_density")
    _require_positive(gravity, field_name="gravitational_acceleration")
    _require_nonnegative(
        top_pressure,
        field_name="top_reference_absolute_pressure",
    )
    if lower_density.value <= upper_density.value:
        raise LevelCalculationDomainError(
            "lower_fluid_density must exceed upper_fluid_density."
        )

    def calculate(interface: float) -> tuple[float, float]:
        high_pressure = top_pressure.value + gravity.value * (
            upper_density.value * (top_elevation - interface)
            + lower_density.value * (interface - high_sensor.value)
        )
        low_pressure = top_pressure.value + gravity.value * (
            upper_density.value * (top_elevation - low_sensor.value)
        )
        return high_pressure, low_pressure

    lower_high, lower_low = calculate(lower_interface.value)
    upper_high, upper_low = calculate(upper_interface.value)
    return _pressure_range_result(
        lower_high,
        lower_low,
        upper_high,
        upper_low,
        lower_differential_pressure=gravity.value
        * (
            upper_density.value * (top_elevation - lower_interface.value)
            + lower_density.value * (lower_interface.value - high_sensor.value)
            - upper_density.value * (top_elevation - low_sensor.value)
        ),
        upper_differential_pressure=gravity.value
        * (
            upper_density.value * (top_elevation - upper_interface.value)
            + lower_density.value * (upper_interface.value - high_sensor.value)
            - upper_density.value * (top_elevation - low_sensor.value)
        ),
    )


def screen_level_transmitter_range(
    sensor_lower_range_limit: EngineeringQuantity,
    sensor_upper_range_limit: EngineeringQuantity,
    lower_endpoint_high_side_absolute_pressure: EngineeringQuantity,
    lower_endpoint_low_side_absolute_pressure: EngineeringQuantity,
    upper_endpoint_high_side_absolute_pressure: EngineeringQuantity,
    upper_endpoint_low_side_absolute_pressure: EngineeringQuantity,
    maximum_high_side_absolute_pressure: EngineeringQuantity,
    maximum_low_side_absolute_pressure: EngineeringQuantity,
    maximum_positive_differential_pressure: EngineeringQuantity,
    maximum_negative_differential_pressure: EngineeringQuantity,
    maximum_static_absolute_pressure: EngineeringQuantity,
    positive_overpressure_limit: EngineeringQuantity,
    negative_overpressure_limit: EngineeringQuantity,
) -> LevelTransmitterRangeResult:
    """Screen range, side static pressure, and one-sided DP limits."""
    lower_limit = _canonical_quantity(
        sensor_lower_range_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="sensor_lower_range_limit",
    )
    upper_limit = _canonical_quantity(
        sensor_upper_range_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="sensor_upper_range_limit",
    )
    lower_high = _canonical_quantity(
        lower_endpoint_high_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="lower_endpoint_high_side_absolute_pressure",
    )
    lower_low = _canonical_quantity(
        lower_endpoint_low_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="lower_endpoint_low_side_absolute_pressure",
    )
    upper_high = _canonical_quantity(
        upper_endpoint_high_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="upper_endpoint_high_side_absolute_pressure",
    )
    upper_low = _canonical_quantity(
        upper_endpoint_low_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="upper_endpoint_low_side_absolute_pressure",
    )
    maximum_high = _canonical_quantity(
        maximum_high_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_high_side_absolute_pressure",
    )
    maximum_low = _canonical_quantity(
        maximum_low_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_low_side_absolute_pressure",
    )
    maximum_positive_dp = _canonical_quantity(
        maximum_positive_differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="maximum_positive_differential_pressure",
    )
    maximum_negative_dp = _canonical_quantity(
        maximum_negative_differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="maximum_negative_differential_pressure",
    )
    static_limit = _canonical_quantity(
        maximum_static_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_static_absolute_pressure",
    )
    positive_limit = _canonical_quantity(
        positive_overpressure_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="positive_overpressure_limit",
    )
    negative_limit = _canonical_quantity(
        negative_overpressure_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="negative_overpressure_limit",
    )
    _require_ordered(
        lower_limit,
        upper_limit,
        lower_name="sensor_lower_range_limit",
        upper_name="sensor_upper_range_limit",
    )
    for value, name in (
        (lower_high, "lower_endpoint_high_side_absolute_pressure"),
        (lower_low, "lower_endpoint_low_side_absolute_pressure"),
        (upper_high, "upper_endpoint_high_side_absolute_pressure"),
        (upper_low, "upper_endpoint_low_side_absolute_pressure"),
        (maximum_high, "maximum_high_side_absolute_pressure"),
        (maximum_low, "maximum_low_side_absolute_pressure"),
        (maximum_positive_dp, "maximum_positive_differential_pressure"),
        (static_limit, "maximum_static_absolute_pressure"),
        (positive_limit, "positive_overpressure_limit"),
    ):
        _require_nonnegative(value, field_name=name)
    if negative_limit.value >= 0.0:
        raise LevelCalculationDomainError(
            "negative_overpressure_limit must be negative."
        )
    if maximum_negative_dp.value > 0.0:
        raise LevelCalculationDomainError(
            "maximum_negative_differential_pressure must be zero or negative."
        )
    lower_dp = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        lower_high.value - lower_low.value,
        "Pa",
    )
    upper_dp = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        upper_high.value - upper_low.value,
        "Pa",
    )
    signed_span = upper_dp.value - lower_dp.value
    if signed_span == 0.0:
        raise LevelCalculationDomainError(
            "Level endpoints cannot configure a zero transmitter span."
        )
    minimum_dp = min(lower_dp.value, upper_dp.value)
    maximum_dp = max(lower_dp.value, upper_dp.value)
    within = (
        minimum_dp >= lower_limit.value and maximum_dp <= upper_limit.value
    )
    if maximum_high.value < max(lower_high.value, upper_high.value):
        raise LevelCalculationDomainError(
            "maximum_high_side_absolute_pressure cannot be below an endpoint."
        )
    if maximum_low.value < max(lower_low.value, upper_low.value):
        raise LevelCalculationDomainError(
            "maximum_low_side_absolute_pressure cannot be below an endpoint."
        )
    if maximum_positive_dp.value < max(0.0, maximum_dp):
        raise LevelCalculationDomainError(
            "maximum_positive_differential_pressure cannot be below a "
            "positive calibrated endpoint."
        )
    if maximum_negative_dp.value > min(0.0, minimum_dp):
        raise LevelCalculationDomainError(
            "maximum_negative_differential_pressure cannot be above a "
            "negative calibrated endpoint."
        )
    high_static_margin = static_limit.value - maximum_high.value
    low_static_margin = static_limit.value - maximum_low.value
    positive_margin = positive_limit.value - maximum_positive_dp.value
    negative_margin = maximum_negative_dp.value - negative_limit.value
    static_ok = high_static_margin >= 0.0 and low_static_margin >= 0.0
    overpressure_ok = positive_margin >= 0.0 and negative_margin >= 0.0
    return LevelTransmitterRangeResult(
        lower_endpoint_differential_pressure=lower_dp,
        upper_endpoint_differential_pressure=upper_dp,
        lower_range_value=lower_dp,
        upper_range_value=upper_dp,
        signed_span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            signed_span,
            "Pa",
        ),
        span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            abs(signed_span),
            "Pa",
        ),
        output_direction=("increasing" if signed_span > 0.0 else "decreasing"),
        lower_range_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum_dp - lower_limit.value,
            "Pa",
        ),
        upper_range_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            upper_limit.value - maximum_dp,
            "Pa",
        ),
        high_side_static_pressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            high_static_margin,
            "Pa",
        ),
        low_side_static_pressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            low_static_margin,
            "Pa",
        ),
        positive_overpressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            positive_margin,
            "Pa",
        ),
        negative_overpressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            negative_margin,
            "Pa",
        ),
        configured_range_within_sensor_limits=within,
        within_static_pressure_limit=static_ok,
        within_differential_overpressure_limits=overpressure_ok,
        pressure_limits_adequate=within and static_ok and overpressure_ok,
    )


def screen_pressure_limits(
    maximum_high_side_absolute_pressure: EngineeringQuantity,
    maximum_low_side_absolute_pressure: EngineeringQuantity,
    maximum_static_absolute_pressure: EngineeringQuantity,
    maximum_positive_differential_pressure: EngineeringQuantity,
    maximum_negative_differential_pressure: EngineeringQuantity,
    positive_overpressure_limit: EngineeringQuantity,
    negative_overpressure_limit: EngineeringQuantity,
) -> PressureLimitScreenResult:
    """Screen explicit absolute/static and signed DP maxima against limits."""

    high = _canonical_quantity(
        maximum_high_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_high_side_absolute_pressure",
    )
    low = _canonical_quantity(
        maximum_low_side_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_low_side_absolute_pressure",
    )
    static_limit = _canonical_quantity(
        maximum_static_absolute_pressure,
        QuantityKind.ABSOLUTE_PRESSURE,
        field_name="maximum_static_absolute_pressure",
    )
    positive_dp = _canonical_quantity(
        maximum_positive_differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="maximum_positive_differential_pressure",
    )
    negative_dp = _canonical_quantity(
        maximum_negative_differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="maximum_negative_differential_pressure",
    )
    positive_limit = _canonical_quantity(
        positive_overpressure_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="positive_overpressure_limit",
    )
    negative_limit = _canonical_quantity(
        negative_overpressure_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="negative_overpressure_limit",
    )
    for value, name in (
        (high, "maximum_high_side_absolute_pressure"),
        (low, "maximum_low_side_absolute_pressure"),
        (static_limit, "maximum_static_absolute_pressure"),
        (positive_dp, "maximum_positive_differential_pressure"),
        (positive_limit, "positive_overpressure_limit"),
    ):
        _require_nonnegative(value, field_name=name)
    if negative_dp.value > 0.0:
        raise LevelCalculationDomainError(
            "maximum_negative_differential_pressure must be zero or negative."
        )
    if negative_limit.value >= 0.0:
        raise LevelCalculationDomainError(
            "negative_overpressure_limit must be negative."
        )

    high_margin = static_limit.value - high.value
    low_margin = static_limit.value - low.value
    positive_margin = positive_limit.value - positive_dp.value
    negative_margin = negative_dp.value - negative_limit.value
    static_ok = high_margin >= 0.0 and low_margin >= 0.0
    dp_ok = positive_margin >= 0.0 and negative_margin >= 0.0
    return PressureLimitScreenResult(
        high_side_static_pressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            high_margin,
            "Pa",
        ),
        low_side_static_pressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            low_margin,
            "Pa",
        ),
        positive_overpressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            positive_margin,
            "Pa",
        ),
        negative_overpressure_margin=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            negative_margin,
            "Pa",
        ),
        within_static_pressure_limit=static_ok,
        within_differential_overpressure_limits=dp_ok,
        pressure_limits_adequate=static_ok and dp_ok,
    )


def vertical_cylindrical_tank_volume(
    internal_diameter: EngineeringQuantity,
    straight_side_height: EngineeringQuantity,
    liquid_height: EngineeringQuantity,
    flat_end_internal_geometry_confirmed: bool,
    liquid_level_within_cylinder_confirmed: bool,
) -> TankVolumeResult:
    """Calculate flat-ended vertical cylindrical tank volume."""

    if not isinstance(
        flat_end_internal_geometry_confirmed,
        bool,
    ) or not isinstance(liquid_level_within_cylinder_confirmed, bool):
        raise LevelCalculationInputError(
            "Tank geometry confirmations must be booleans."
        )
    if not flat_end_internal_geometry_confirmed:
        raise LevelCalculationDomainError(
            "Flat-end internal cylindrical geometry must be confirmed."
        )
    if not liquid_level_within_cylinder_confirmed:
        raise LevelCalculationDomainError(
            "The level datum and liquid containment within the cylindrical "
            "section must be confirmed."
        )

    diameter = _canonical_quantity(
        internal_diameter,
        QuantityKind.LENGTH,
        field_name="internal_diameter",
    )
    height = _canonical_quantity(
        straight_side_height,
        QuantityKind.LENGTH,
        field_name="straight_side_height",
    )
    liquid = _canonical_quantity(
        liquid_height,
        QuantityKind.LENGTH,
        field_name="liquid_height",
    )
    _require_positive(diameter, field_name="internal_diameter")
    _require_positive(height, field_name="straight_side_height")
    _require_nonnegative(liquid, field_name="liquid_height")
    if liquid.value > height.value:
        raise LevelCalculationDomainError(
            "liquid_height cannot exceed straight_side_height."
        )
    area = pi * diameter.value * diameter.value / 4.0
    capacity = _finite_result(area * height.value, field_name="tank capacity")
    volume = _finite_result(area * liquid.value, field_name="liquid volume")
    if capacity <= 0.0:
        raise LevelCalculationDomainError(
            "Tank geometry is too small to produce a representable capacity."
        )
    return TankVolumeResult(
        liquid_volume=_quantity(QuantityKind.VOLUME, volume, "m3"),
        full_capacity=_quantity(QuantityKind.VOLUME, capacity, "m3"),
        fill_fraction=_quantity(
            QuantityKind.RATIO,
            liquid.value / height.value,
            "1",
        ),
    )


def horizontal_cylindrical_tank_volume(
    internal_diameter: EngineeringQuantity,
    cylindrical_length: EngineeringQuantity,
    liquid_height: EngineeringQuantity,
    flat_end_internal_geometry_confirmed: bool,
    level_cylinder_geometry_confirmed: bool,
) -> TankVolumeResult:
    """Calculate volume in a level, flat-ended horizontal cylinder."""

    if not isinstance(
        flat_end_internal_geometry_confirmed,
        bool,
    ) or not isinstance(level_cylinder_geometry_confirmed, bool):
        raise LevelCalculationInputError(
            "Tank geometry confirmations must be booleans."
        )
    if not flat_end_internal_geometry_confirmed:
        raise LevelCalculationDomainError(
            "Flat-end internal cylindrical geometry must be confirmed."
        )
    if not level_cylinder_geometry_confirmed:
        raise LevelCalculationDomainError(
            "A level horizontal cylinder and bottom-referenced liquid level "
            "must be confirmed."
        )

    diameter = _canonical_quantity(
        internal_diameter,
        QuantityKind.LENGTH,
        field_name="internal_diameter",
    )
    length = _canonical_quantity(
        cylindrical_length,
        QuantityKind.LENGTH,
        field_name="cylindrical_length",
    )
    liquid = _canonical_quantity(
        liquid_height,
        QuantityKind.LENGTH,
        field_name="liquid_height",
    )
    _require_positive(diameter, field_name="internal_diameter")
    _require_positive(length, field_name="cylindrical_length")
    _require_nonnegative(liquid, field_name="liquid_height")
    if liquid.value > diameter.value:
        raise LevelCalculationDomainError(
            "liquid_height cannot exceed internal_diameter."
        )
    radius = diameter.value / 2.0
    capacity = _finite_result(
        pi * radius * radius * length.value,
        field_name="tank capacity",
    )
    full_area = pi * radius * radius

    def lower_segment_area(segment_height: float) -> float:
        theta = 2.0 * asin(sqrt(segment_height / (2.0 * radius)))
        if theta < 1.0e-3:
            theta2 = theta * theta
            theta3 = theta * theta2
            return (
                radius
                * radius
                * theta3
                * (
                    (2.0 / 3.0)
                    - (2.0 / 15.0) * theta2
                    + (4.0 / 315.0) * theta2 * theta2
                    - (2.0 / 2835.0) * theta2 * theta2 * theta2
                )
            )
        return radius * radius * (theta - sin(theta) * cos(theta))

    if liquid.value == 0.0:
        segment_area = 0.0
    elif liquid.value == diameter.value:
        segment_area = full_area
    elif liquid.value == radius:
        segment_area = full_area / 2.0
    elif liquid.value < radius:
        segment_area = lower_segment_area(liquid.value)
    else:
        complementary_area = lower_segment_area(diameter.value - liquid.value)
        segment_area = full_area - complementary_area
        if complementary_area > 0.0 and segment_area >= full_area:
            segment_area = nextafter(full_area, 0.0)
    volume = _finite_result(
        segment_area * length.value,
        field_name="liquid volume",
    )
    if 0.0 < liquid.value < diameter.value and volume >= capacity:
        volume = nextafter(capacity, 0.0)
    if capacity <= 0.0:
        raise LevelCalculationDomainError(
            "Tank geometry is too small to produce a representable capacity."
        )
    return TankVolumeResult(
        liquid_volume=_quantity(QuantityKind.VOLUME, volume, "m3"),
        full_capacity=_quantity(QuantityKind.VOLUME, capacity, "m3"),
        fill_fraction=_quantity(QuantityKind.RATIO, volume / capacity, "1"),
    )


def _context_quantity(
    context: MethodExecutionContext,
    input_id: str,
) -> EngineeringQuantity:
    """Return one exact normalized quantity from an execution context."""

    for calculation_input in context.normalized_inputs:
        if calculation_input.input_id == input_id:
            if calculation_input.quantity is None:
                raise LevelCalculationInputError(
                    f"{input_id} must be a quantity."
                )
            return calculation_input.quantity
    raise LevelCalculationInputError(
        f"Required normalized input {input_id!r} is unavailable."
    )


def _context_boolean(
    context: MethodExecutionContext,
    input_id: str,
) -> bool:
    """Return one exact normalized boolean confirmation."""

    for calculation_input in context.normalized_inputs:
        if calculation_input.input_id == input_id:
            value = calculation_input.categorical_value
            if not isinstance(value, bool):
                raise LevelCalculationInputError(
                    f"{input_id} must be a boolean."
                )
            return value
    raise LevelCalculationInputError(
        f"Required normalized input {input_id!r} is unavailable."
    )


def _execution_outcome(
    *,
    formula_identifier: str,
    title: str,
    description: str,
    input_ids: tuple[str, ...],
    quantity_outputs: tuple[
        tuple[str, str, EngineeringQuantity, str | None],
        ...,
    ] = (),
    categorical_outputs: tuple[
        tuple[str, str, bool | str, str | None],
        ...,
    ] = (),
    findings: tuple[CalculationFinding, ...] = (),
) -> MethodExecutionOutcome:
    """Build one deterministic trace step and its linked outputs."""

    values: list[CalculationTraceValue] = []
    outputs: list[CalculationOutput] = []
    for output_id, name, quantity, output_description in quantity_outputs:
        value_id = f"value.{output_id}"
        values.append(
            CalculationTraceValue(
                value_id=value_id,
                name=name,
                quantity=quantity,
                description=output_description,
            )
        )
        outputs.append(
            CalculationOutput(
                output_id=output_id,
                name=name,
                quantity=quantity,
                source_step_ids=("step.calculate",),
                source_value_ids=(value_id,),
                description=output_description,
            )
        )
    for output_id, name, value, output_description in categorical_outputs:
        value_id = f"value.{output_id}"
        values.append(
            CalculationTraceValue(
                value_id=value_id,
                name=name,
                categorical_value=value,
                description=output_description,
            )
        )
        outputs.append(
            CalculationOutput(
                output_id=output_id,
                name=name,
                categorical_value=value,
                source_step_ids=("step.calculate",),
                source_value_ids=(value_id,),
                description=output_description,
            )
        )
    return MethodExecutionOutcome(
        trace_steps=(
            CalculationTraceStep(
                step_id="step.calculate",
                sequence=1,
                kind=TraceStepKind.CALCULATION,
                title=title,
                description=description,
                formula_identifier=formula_identifier,
                input_ids=input_ids,
                output_values=tuple(values),
            ),
        ),
        outputs=tuple(outputs),
        findings=findings,
    )


def _range_quantity_outputs(
    result: LevelRangeResult,
) -> tuple[tuple[str, str, EngineeringQuantity, str | None], ...]:
    """Return the common numerical level-range outputs."""

    return (
        (
            "lower-endpoint-dp",
            "Lower endpoint differential pressure",
            result.lower_endpoint_differential_pressure,
            "Transmitter HP minus LP pressure at the lower endpoint.",
        ),
        (
            "upper-endpoint-dp",
            "Upper endpoint differential pressure",
            result.upper_endpoint_differential_pressure,
            "Transmitter HP minus LP pressure at the upper endpoint.",
        ),
        (
            "lower-range-value",
            "Lower range value",
            result.lower_range_value,
            "LRV at the lower calibrated level endpoint.",
        ),
        (
            "upper-range-value",
            "Upper range value",
            result.upper_range_value,
            "URV at the upper calibrated level endpoint.",
        ),
        (
            "signed-span",
            "Signed span",
            result.signed_span,
            "URV minus LRV with direction preserved.",
        ),
        (
            "span",
            "Span",
            result.span,
            "Absolute magnitude of URV minus LRV.",
        ),
    )


def _pressure_range_quantity_outputs(
    result: PressureLevelRangeResult,
) -> tuple[tuple[str, str, EngineeringQuantity, str | None], ...]:
    """Return common range outputs plus endpoint side absolute pressures."""

    return _range_quantity_outputs(result) + (
        (
            "lower-endpoint-high-side-absolute-pressure",
            "Lower endpoint high-side absolute pressure",
            result.lower_endpoint_high_side_absolute_pressure,
            "Calculated HP-port absolute pressure at lower level.",
        ),
        (
            "lower-endpoint-low-side-absolute-pressure",
            "Lower endpoint low-side absolute pressure",
            result.lower_endpoint_low_side_absolute_pressure,
            "Calculated LP-port absolute pressure at lower level.",
        ),
        (
            "upper-endpoint-high-side-absolute-pressure",
            "Upper endpoint high-side absolute pressure",
            result.upper_endpoint_high_side_absolute_pressure,
            "Calculated HP-port absolute pressure at upper level.",
        ),
        (
            "upper-endpoint-low-side-absolute-pressure",
            "Upper endpoint low-side absolute pressure",
            result.upper_endpoint_low_side_absolute_pressure,
            "Calculated LP-port absolute pressure at upper level.",
        ),
    )


def _require_noniterative_controller(iteration_controller: object) -> None:
    """Reject an engine iteration controller for closed-form methods."""

    if iteration_controller is not None:
        raise LevelCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )


def execute_column_pressure(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute liquid-column hydrostatic pressure."""

    _require_noniterative_controller(iteration_controller)
    result = liquid_column_pressure(
        _context_quantity(context, "density"),
        _context_quantity(context, "vertical-height"),
        _context_quantity(context, "gravitational-acceleration"),
    )
    return _execution_outcome(
        formula_identifier="level.formula.column-pressure",
        title="Calculate liquid-column pressure",
        description="Density, gravity, and vertical height were multiplied.",
        input_ids=(
            "density",
            "vertical-height",
            "gravitational-acceleration",
        ),
        quantity_outputs=(
            (
                "differential-pressure",
                "Differential pressure",
                result,
                "Positive hydrostatic pressure difference across the column.",
            ),
        ),
    )


def execute_open_vessel_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute open-vessel DP level range."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "lower-level-elevation",
        "upper-level-elevation",
        "high-side-tap-elevation",
        "high-side-port-elevation",
        "process-liquid-density",
        "high-side-leg-density",
        "gravitational-acceleration",
        "vessel-surface-atmospheric-absolute-pressure",
        "low-side-reference-atmospheric-absolute-pressure",
    )
    result = open_vessel_dp_range(
        *(_context_quantity(context, input_id) for input_id in input_ids)
    )
    return _execution_outcome(
        formula_identifier="level.formula.open-vessel-range",
        title="Calculate open-vessel DP level range",
        description=(
            "Explicit process and high-side leg heads were applied from a "
            "common upward-positive elevation datum; DP is HP minus LP."
        ),
        input_ids=input_ids,
        quantity_outputs=_pressure_range_quantity_outputs(result),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as level rises.",
            ),
        ),
    )


def execute_closed_dry_leg_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute closed-vessel dry-leg DP level range."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "lower-level-elevation",
        "upper-level-elevation",
        "high-side-port-elevation",
        "low-side-port-elevation",
        "process-liquid-density",
        "dry-leg-vapour-density",
        "gravitational-acceleration",
        "vessel-vapour-absolute-pressure",
    )
    result = dry_leg_dp_range(
        _context_quantity(context, input_ids[0]),
        _context_quantity(context, input_ids[1]),
        _context_quantity(context, input_ids[2]),
        _context_quantity(context, input_ids[3]),
        _context_quantity(context, input_ids[4]),
        _context_quantity(context, input_ids[5]),
        _context_quantity(context, input_ids[6]),
        _context_quantity(context, input_ids[7]),
    )
    return _execution_outcome(
        formula_identifier="level.formula.closed-dry-leg-range",
        title="Calculate closed-vessel dry-leg range",
        description=(
            "Process-liquid and explicit dry-leg vapour heads were applied "
            "to the common vessel-surface absolute pressure."
        ),
        input_ids=input_ids,
        quantity_outputs=_pressure_range_quantity_outputs(result),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as level rises.",
            ),
        ),
    )


def execute_closed_wet_leg_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute closed-vessel wet-leg DP level range."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "lower-level-elevation",
        "upper-level-elevation",
        "high-side-port-elevation",
        "low-side-reference-elevation",
        "low-side-port-elevation",
        "process-liquid-density",
        "vapour-density",
        "wet-leg-fill-density",
        "gravitational-acceleration",
        "vessel-vapour-absolute-pressure",
    )
    result = wet_leg_dp_range(
        *(_context_quantity(context, input_id) for input_id in input_ids)
    )
    return _execution_outcome(
        formula_identifier="level.formula.closed-wet-leg-range",
        title="Calculate closed-vessel wet-leg range",
        description=(
            "Process, vapour, and wet-leg fill heads were resolved at both "
            "transmitter ports using one explicit elevation datum."
        ),
        input_ids=input_ids,
        quantity_outputs=_pressure_range_quantity_outputs(result),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as level rises.",
            ),
        ),
    )


def execute_remote_seal_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute dual-remote-seal DP level range."""

    _require_noniterative_controller(iteration_controller)
    quantity_input_ids = (
        "lower-level-elevation",
        "upper-level-elevation",
        "high-side-seal-elevation",
        "low-side-seal-elevation",
        "high-side-port-elevation",
        "low-side-port-elevation",
        "process-liquid-density",
        "vapour-density",
        "high-side-fill-density",
        "low-side-fill-density",
        "gravitational-acceleration",
        "vessel-vapour-absolute-pressure",
    )
    confirmation_ids = (
        "installed-geometry-confirmed",
        "fill-fluid-temperature-density-confirmed",
    )
    result = remote_seal_dp_range(
        *(
            _context_quantity(context, input_id)
            for input_id in quantity_input_ids
        ),
        _context_boolean(context, confirmation_ids[0]),
        _context_boolean(context, confirmation_ids[1]),
    )
    return _execution_outcome(
        formula_identifier="level.formula.remote-seal-range",
        title="Calculate remote-seal DP level range",
        description=(
            "Process, vapour, and two explicit capillary fill heads were "
            "resolved for confirmed installed geometry and temperature."
        ),
        input_ids=quantity_input_ids + confirmation_ids,
        quantity_outputs=_pressure_range_quantity_outputs(result),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as level rises.",
            ),
        ),
    )


def execute_interface_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute two-liquid interface DP range."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "lower-interface-elevation",
        "upper-interface-elevation",
        "bottom-reference-elevation",
        "total-flooded-height",
        "high-side-port-elevation",
        "low-side-port-elevation",
        "lower-fluid-density",
        "upper-fluid-density",
        "gravitational-acceleration",
        "top-reference-absolute-pressure",
    )
    result = interface_dp_range(
        *(_context_quantity(context, input_id) for input_id in input_ids)
    )
    return _execution_outcome(
        formula_identifier="level.formula.interface-range",
        title="Calculate two-liquid interface DP range",
        description=(
            "Known lower and upper fluid heads were resolved across the "
            "explicit flooded height; lower density must exceed upper."
        ),
        input_ids=input_ids,
        quantity_outputs=_pressure_range_quantity_outputs(result),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as interface elevation rises.",
            ),
        ),
    )


def execute_endpoint_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute endpoint range and transmitter pressure-capability screen."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "sensor-lower-range-limit",
        "sensor-upper-range-limit",
        "lower-endpoint-high-side-absolute-pressure",
        "lower-endpoint-low-side-absolute-pressure",
        "upper-endpoint-high-side-absolute-pressure",
        "upper-endpoint-low-side-absolute-pressure",
        "maximum-high-side-absolute-pressure",
        "maximum-low-side-absolute-pressure",
        "maximum-positive-differential-pressure",
        "maximum-negative-differential-pressure",
        "maximum-static-absolute-pressure",
        "positive-overpressure-limit",
        "negative-overpressure-limit",
    )
    result = screen_level_transmitter_range(
        *(_context_quantity(context, input_id) for input_id in input_ids)
    )
    findings: tuple[CalculationFinding, ...] = ()
    if not result.pressure_limits_adequate:
        findings = (
            CalculationFinding(
                finding_id="level.endpoint-range.inadequate",
                category=FindingCategory.APPLICABILITY,
                severity=FindingSeverity.WARNING,
                title="Transmitter range or pressure capability is inadequate",
                message=(
                    "At least one calibrated-range, static-pressure, or "
                    "one-sided differential-overpressure margin is negative."
                ),
                blocking=False,
                required_action=(
                    "Select and independently verify a suitable transmitter "
                    "and installation before design approval."
                ),
            ),
        )
    return _execution_outcome(
        formula_identifier="level.formula.endpoint-range",
        title="Calculate endpoint range and screen pressure capability",
        description=(
            "LRV and URV were derived from endpoint HP-minus-LP absolute "
            "pressures and screened against separate worst-case limits."
        ),
        input_ids=input_ids,
        quantity_outputs=(
            (
                "lower-endpoint-dp",
                "Lower endpoint differential pressure",
                result.lower_endpoint_differential_pressure,
                "Derived endpoint HP minus LP pressure.",
            ),
            (
                "upper-endpoint-dp",
                "Upper endpoint differential pressure",
                result.upper_endpoint_differential_pressure,
                "Derived endpoint HP minus LP pressure.",
            ),
            (
                "lower-range-value",
                "Lower range value",
                result.lower_range_value,
                "LRV at the lower calibrated level.",
            ),
            (
                "upper-range-value",
                "Upper range value",
                result.upper_range_value,
                "URV at the upper calibrated level.",
            ),
            (
                "signed-span",
                "Signed span",
                result.signed_span,
                "URV minus LRV.",
            ),
            ("span", "Span", result.span, "Absolute calibrated span."),
            (
                "lower-range-margin",
                "Lower range margin",
                result.lower_range_margin,
                "Minimum calibrated DP minus sensor LRL.",
            ),
            (
                "upper-range-margin",
                "Upper range margin",
                result.upper_range_margin,
                "Sensor URL minus maximum calibrated DP.",
            ),
            (
                "high-side-static-pressure-margin",
                "High-side static pressure margin",
                result.high_side_static_pressure_margin,
                "Static absolute limit minus worst-case HP absolute pressure.",
            ),
            (
                "low-side-static-pressure-margin",
                "Low-side static pressure margin",
                result.low_side_static_pressure_margin,
                "Static absolute limit minus worst-case LP absolute pressure.",
            ),
            (
                "positive-overpressure-margin",
                "Positive overpressure margin",
                result.positive_overpressure_margin,
                "Positive overload limit minus worst positive DP case.",
            ),
            (
                "negative-overpressure-margin",
                "Negative overpressure margin",
                result.negative_overpressure_margin,
                "Worst negative DP minus negative overload limit.",
            ),
        ),
        categorical_outputs=(
            (
                "output-direction",
                "Output direction",
                result.output_direction,
                "Increasing or decreasing DP as level rises.",
            ),
            (
                "configured-range-within-sensor-limits",
                "Configured range within sensor limits",
                result.configured_range_within_sensor_limits,
                "Whether both configured endpoints fit LRL through URL.",
            ),
            (
                "within-static-pressure-limit",
                "Within static pressure limit",
                result.within_static_pressure_limit,
                "Whether both worst-case side absolute pressures fit.",
            ),
            (
                "within-differential-overpressure-limits",
                "Within differential overpressure limits",
                result.within_differential_overpressure_limits,
                "Whether both one-sided overload cases fit.",
            ),
            (
                "pressure-limits-adequate",
                "Pressure limits adequate",
                result.pressure_limits_adequate,
                "Combined preliminary pressure-capability disposition.",
            ),
        ),
        findings=findings,
    )


def execute_vertical_cylinder(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute flat-ended vertical-cylinder volume."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "internal-diameter",
        "straight-side-height",
        "liquid-height",
        "flat-end-internal-geometry-confirmed",
        "liquid-level-within-cylinder-confirmed",
    )
    result = vertical_cylindrical_tank_volume(
        _context_quantity(context, input_ids[0]),
        _context_quantity(context, input_ids[1]),
        _context_quantity(context, input_ids[2]),
        _context_boolean(context, input_ids[3]),
        _context_boolean(context, input_ids[4]),
    )
    return _tank_outcome(
        formula_identifier="level.formula.vertical-cylinder",
        title="Calculate vertical cylindrical tank volume",
        description=(
            "Flat-ended internal circular area was multiplied by liquid and "
            "straight-side heights."
        ),
        input_ids=input_ids,
        result=result,
    )


def execute_horizontal_cylinder(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute flat-ended level horizontal-cylinder volume."""

    _require_noniterative_controller(iteration_controller)
    input_ids = (
        "internal-diameter",
        "cylindrical-length",
        "liquid-height",
        "flat-end-internal-geometry-confirmed",
        "level-cylinder-geometry-confirmed",
    )
    result = horizontal_cylindrical_tank_volume(
        _context_quantity(context, input_ids[0]),
        _context_quantity(context, input_ids[1]),
        _context_quantity(context, input_ids[2]),
        _context_boolean(context, input_ids[3]),
        _context_boolean(context, input_ids[4]),
    )
    return _tank_outcome(
        formula_identifier="level.formula.horizontal-cylinder",
        title="Calculate horizontal cylindrical tank volume",
        description=(
            "The circular-segment area at bottom-referenced level was "
            "multiplied by internal cylindrical length."
        ),
        input_ids=input_ids,
        result=result,
    )


def _tank_outcome(
    *,
    formula_identifier: str,
    title: str,
    description: str,
    input_ids: tuple[str, ...],
    result: TankVolumeResult,
) -> MethodExecutionOutcome:
    """Build common tank-geometry result outputs."""

    return _execution_outcome(
        formula_identifier=formula_identifier,
        title=title,
        description=description,
        input_ids=input_ids,
        quantity_outputs=(
            (
                "liquid-volume",
                "Liquid volume",
                result.liquid_volume,
                "Contained liquid volume inside the modeled cylinder.",
            ),
            (
                "full-capacity",
                "Full capacity",
                result.full_capacity,
                "Full flat-ended cylindrical capacity.",
            ),
            (
                "fill-fraction",
                "Fill fraction",
                result.fill_fraction,
                "Liquid volume divided by full cylindrical capacity.",
            ),
        ),
    )


_REVIEWED_AT: Final = datetime(2026, 7, 31, 14, 0, tzinfo=UTC)
_FINAL_REVIEWED_AT: Final = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)

_BIPM_REFERENCE: Final = CalculationReference(
    reference_id="level.reference.bipm-si",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title="The International System of Units, SI Brochure, 9th edition",
    publisher_or_owner="Bureau International des Poids et Mesures",
    document_number="SI Brochure",
    edition_or_revision="9th edition, updated 2026",
    relevant_section="Coherent SI units and derived-unit definitions",
    implementation_basis=(
        "The implementation uses coherent SI pressure, density, length, "
        "acceleration, and volume quantities. Hydrostatic and geometrical "
        "equations were independently implemented and verified without "
        "reproducing protected tables."
    ),
    source_location="https://doi.org/10.59161/AUEZ1291",
    verified=True,
    verified_by="Engineer4Me Step 95 technical review",
    verified_at=_REVIEWED_AT,
)

_DOE_PRESSURE_LEVEL_REFERENCE: Final = CalculationReference(
    reference_id="level.reference.doe-fundamentals",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title="DOE Fundamentals Handbook — Instrumentation and Control",
    publisher_or_owner="United States Department of Energy",
    document_number="DOE-HDBK-1013/1-92",
    edition_or_revision="June 1992",
    relevant_section=(
        "Pressure measurement and differential-pressure level detection"
    ),
    implementation_basis=(
        "Public hydrostatic pressure and differential-pressure level "
        "principles anchor the generic equations. No protected table or "
        "extended handbook text is reproduced."
    ),
    source_location=("https://www.energy.gov/ehss/articles/doe-hdbk-10131-92"),
    verified=True,
    verified_by="Engineer4Me Step 95 technical review",
    verified_at=_REVIEWED_AT,
)

_YOKOGAWA_LEVEL_REFERENCE: Final = CalculationReference(
    reference_id="level.reference.yokogawa-smart-level-setup",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title="Smart Level Setup Feature",
    publisher_or_owner="Yokogawa Electric Corporation",
    document_number="FISD-T-20-001",
    edition_or_revision="Official application note reviewed 2026-07-31",
    relevant_section=(
        "DP level installation elevation, zero suppression, and range setup"
    ),
    implementation_basis=(
        "The reference informs explicit installed-geometry and range "
        "requirements. This implementation is vendor neutral and does not "
        "replicate proprietary configuration software."
    ),
    applicability=(
        "Generic installed differential-pressure level measurement geometry."
    ),
    source_location=(
        "https://www.yokogawa.com/za/library/resources/application-notes/"
        "fisd-t-20-001-smart-level-setup-feature/"
    ),
    verified=True,
    verified_by="Engineer4Me Step 95 technical review",
    verified_at=_REVIEWED_AT,
)

_NIST_GEOMETRY_REFERENCE: Final = CalculationReference(
    reference_id="level.reference.nist-volume",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title="Circumference, Area and Volume",
    publisher_or_owner="National Institute of Standards and Technology",
    document_number="NIST Office of Weights and Measures reference",
    edition_or_revision="Official web reference reviewed 2026-07-31",
    relevant_section="Circle area and cylinder volume relationships",
    implementation_basis=(
        "Internal cylinder capacity and circular-segment volume calculations "
        "use independently implemented mathematical geometry."
    ),
    source_location=(
        "https://www.nist.gov/pml/owm/circumference-area-and-volume"
    ),
    verified=True,
    verified_by="Engineer4Me Step 95 technical review",
    verified_at=_REVIEWED_AT,
)

_PRESSURE_REFERENCES: Final = (
    _BIPM_REFERENCE,
    _DOE_PRESSURE_LEVEL_REFERENCE,
    _YOKOGAWA_LEVEL_REFERENCE,
)
_GEOMETRY_REFERENCES: Final = (
    _BIPM_REFERENCE,
    _NIST_GEOMETRY_REFERENCE,
)


def _test_vector_reference(method_id: str) -> CalculationReference:
    """Build a method-specific independently checked vector reference."""

    return CalculationReference(
        reference_id=f"{method_id}.vector",
        reference_type=ReferenceType.TEST_VECTOR,
        title=f"Engineer4Me Step 95 reference vectors for {method_id}",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-P7-S95-VECTORS",
        edition_or_revision=LEVEL_METHOD_VERSION,
        relevant_section=method_id,
        implementation_basis=(
            "Independent reference, inverse, elevation-shift, endpoint, "
            "boundary, dimensional, and metamorphic vectors were reviewed "
            "for this exact method version."
        ),
        source_location="backend/tests/test_calculation_level.py",
        verified=True,
        verified_by="Engineer4Me Step 95 software review",
        verified_at=_REVIEWED_AT,
    )


def _review_records(
    vector_reference_id: str,
) -> tuple[MethodReviewRecord, ...]:
    """Build all immutable approved-method review records."""

    competencies = {
        MethodReviewType.TECHNICAL: (
            "Competent pressure and level measurement engineer"
        ),
        MethodReviewType.SAFETY: "Competent process safety reviewer",
        MethodReviewType.STANDARDS: "Competent engineering standards reviewer",
        MethodReviewType.LEGAL_COMPLIANCE: (
            "Competent technical legal and compliance reviewer"
        ),
        MethodReviewType.SOFTWARE: "Competent numerical software reviewer",
        MethodReviewType.FINAL_APPROVAL: (
            "Authorised Engineer4Me method approver"
        ),
    }
    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=True,
            reviewer=f"Engineer4Me Step 95 {review_type.value} review",
            reviewer_competency=competencies[review_type],
            reviewed_at=(
                _FINAL_REVIEWED_AT
                if review_type is MethodReviewType.FINAL_APPROVAL
                else _REVIEWED_AT
            ),
            evidence_reference_ids=(vector_reference_id,),
            notes=(
                "Approval is limited to this exact generic method version "
                "and is not site design approval or equipment certification."
            ),
        )
        for review_type in MethodReviewType
    )


def _quantity_specification(
    input_id: str,
    name: str,
    description: str,
    quantity_kind: QuantityKind,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    minimum_inclusive: bool = True,
) -> MethodInputSpecification:
    """Build one required canonical bounded quantity input."""

    numeric_range = (
        None
        if minimum is None and maximum is None
        else NumericApplicabilityRange(
            minimum=minimum,
            maximum=maximum,
            minimum_inclusive=minimum_inclusive,
        )
    )
    return MethodInputSpecification(
        input_id=input_id,
        name=name,
        description=description,
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
        quantity_kind=quantity_kind,
        canonical_unit=DEFAULT_UNIT_REGISTRY.canonical_unit_for(quantity_kind),
        numeric_range=numeric_range,
    )


def _length_specification(
    input_id: str,
    name: str,
    description: str,
    *,
    nonnegative: bool = False,
    positive: bool = False,
) -> MethodInputSpecification:
    if nonnegative and positive:
        raise ValueError("Length specification cannot use two lower bounds.")
    return _quantity_specification(
        input_id,
        name,
        description,
        QuantityKind.LENGTH,
        minimum=0.0 if nonnegative or positive else -1.0e12,
        maximum=1.0e12,
        minimum_inclusive=not positive,
    )


def _density_specification(
    input_id: str,
    name: str,
    description: str,
    *,
    allow_zero: bool = False,
) -> MethodInputSpecification:
    return _quantity_specification(
        input_id,
        name,
        description,
        QuantityKind.DENSITY,
        minimum=0.0,
        maximum=1.0e12,
        minimum_inclusive=allow_zero,
    )


def _differential_pressure_specification(
    input_id: str,
    name: str,
    description: str,
) -> MethodInputSpecification:
    return _quantity_specification(
        input_id,
        name,
        description,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        minimum=-1.0e15,
        maximum=1.0e15,
    )


def _absolute_pressure_specification(
    input_id: str,
    name: str,
    description: str,
) -> MethodInputSpecification:
    return _quantity_specification(
        input_id,
        name,
        description,
        QuantityKind.ABSOLUTE_PRESSURE,
        minimum=0.0,
        maximum=1.0e15,
    )


def _gravity_specification() -> MethodInputSpecification:
    return _quantity_specification(
        "gravitational-acceleration",
        "Gravitational acceleration",
        "Explicit positive gravitational acceleration for the site/model.",
        QuantityKind.ACCELERATION,
        minimum=0.0,
        maximum=1.0e6,
        minimum_inclusive=False,
    )


def _true_confirmation_specification(
    input_id: str,
    name: str,
    description: str,
) -> MethodInputSpecification:
    return MethodInputSpecification(
        input_id=input_id,
        name=name,
        description=description,
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.CATEGORICAL_BOOLEAN,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=(True,),
    )


def _approved_method(
    *,
    method_id: str,
    title: str,
    description: str,
    input_specifications: tuple[MethodInputSpecification, ...],
    formula_description: str,
    source_references: tuple[CalculationReference, ...] = (
        _PRESSURE_REFERENCES
    ),
    limitations: tuple[str, ...],
    exclusions: tuple[str, ...],
    required_reviewer_competency: str = (
        "Competent pressure and level measurement engineer"
    ),
) -> CalculationMethodDefinition:
    """Build one complete exact-version approved level method."""

    vector_reference = _test_vector_reference(method_id)
    verification = VerificationRequirement(
        verification_id="level.verify.result",
        description=(
            "Independently verify the common elevation datum, pressure bases, "
            "densities at applicable conditions, gravity, geometry, and all "
            "calculated range or volume outputs."
        ),
        method=(
            "Repeat the calculation independently using controlled inputs and "
            "current approved equipment documentation."
        ),
        expected_result=(
            "Independent values agree within the project's documented "
            "numerical tolerance and all capability margins are nonnegative."
        ),
        acceptance_criteria=(
            "Inputs, sign convention, units, pressure basis, result, and "
            "applicability are documented and accepted by the reviewer."
        ),
        required_competency=required_reviewer_competency,
        verifier_role="Independent competent engineering reviewer",
        independent_verification_required=True,
        evidence_required=(
            "Controlled input record",
            "Independent calculation record",
            "Applicable equipment capability data",
        ),
    )
    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=LEVEL_METHOD_VERSION,
        calculation_type=method_id,
        title=title,
        description=description,
        implementation_owner="Engineer4Me engineering calculations",
        lifecycle_status=MethodLifecycleStatus.APPROVED,
        engine_compatibility=EngineCompatibility(
            minimum_version="1.0.0",
            maximum_exclusive_version="2.0.0",
        ),
        input_specifications=input_specifications,
        formulas=(
            FormulaMetadata(
                formula_identifier=f"level.formula.{method_id.rsplit('.', 1)[-1]}",
                title=title,
                description=formula_description,
                reference_ids=tuple(
                    reference.reference_id for reference in source_references
                ),
            ),
        ),
        references=source_references + (vector_reference,),
        verification_requirements=(verification,),
        reviews=_review_records(vector_reference.reference_id),
        test_vector_reference_ids=(vector_reference.reference_id,),
        limitations=limitations,
        exclusions=exclusions,
        required_reviewer_competency=required_reviewer_competency,
        disclaimer=(
            "Engineer4Me provides preliminary deterministic engineering "
            "decision support only. Verify installed elevations, process and "
            "fill-fluid properties, pressure bases, equipment capabilities, "
            "site requirements, and the result before design or operation."
        ),
    )


_COLUMN_PRESSURE_DEFINITION: Final = _approved_method(
    method_id="level.hydrostatic.column-pressure",
    title="Liquid-column hydrostatic differential pressure",
    description=(
        "Calculate rho-g-h differential pressure using explicit density, "
        "vertical height, and gravitational acceleration."
    ),
    input_specifications=(
        _density_specification(
            "density",
            "Liquid density",
            "Positive representative liquid density.",
        ),
        _length_specification(
            "vertical-height",
            "Vertical height",
            "Nonnegative vertical liquid-column height.",
            nonnegative=True,
        ),
        _gravity_specification(),
    ),
    formula_description="Differential pressure equals density times g times h.",
    limitations=(
        "Density is treated as uniform over the specified vertical column.",
    ),
    exclusions=(
        "Dynamic, compressible, accelerating, and multiphase columns are excluded.",
    ),
)


_OPEN_VESSEL_DEFINITION: Final = _approved_method(
    method_id="level.dp.open-vessel-range",
    title="Open-vessel differential-pressure level range",
    description=(
        "Calculate endpoint port pressures, LRV, URV, span, and direction for "
        "an open vessel with explicit equal atmospheric references."
    ),
    input_specifications=(
        _length_specification(
            "lower-level-elevation",
            "Lower level elevation",
            "Lower calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "upper-level-elevation",
            "Upper level elevation",
            "Upper calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "high-side-tap-elevation",
            "High-side tap elevation",
            "High-side process tapping elevation.",
        ),
        _length_specification(
            "high-side-port-elevation",
            "High-side port elevation",
            "Transmitter HP-port elevation.",
        ),
        _density_specification(
            "process-liquid-density",
            "Process liquid density",
            "Positive process density between surface and tap.",
        ),
        _density_specification(
            "high-side-leg-density",
            "High-side leg density",
            "Positive flooded HP-leg density between tap and port.",
        ),
        _gravity_specification(),
        _absolute_pressure_specification(
            "vessel-surface-atmospheric-absolute-pressure",
            "Vessel-surface atmospheric pressure",
            "Explicit atmospheric absolute pressure acting on the open surface.",
        ),
        _absolute_pressure_specification(
            "low-side-reference-atmospheric-absolute-pressure",
            "Low-side atmospheric reference",
            "Explicit atmospheric absolute pressure at the vented LP reference.",
        ),
    ),
    formula_description=(
        "HP pressure is the open-surface absolute pressure plus process and "
        "flooded-leg heads; LP is the explicit equal atmospheric reference."
    ),
    limitations=(
        "The HP tap must remain flooded throughout the calibrated range.",
        "Both explicit atmospheric reference pressures must be equal.",
    ),
    exclusions=(
        "Sealed, purged, bubbler, boiling, or density-stratified service is excluded.",
    ),
)


_DRY_LEG_DEFINITION: Final = _approved_method(
    method_id="level.dp.closed-dry-leg-range",
    title="Closed-vessel dry-leg differential-pressure level range",
    description=(
        "Calculate endpoint port pressures and calibrated range using explicit "
        "process-liquid and dry-leg vapour densities."
    ),
    input_specifications=(
        _length_specification(
            "lower-level-elevation",
            "Lower level elevation",
            "Lower calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "upper-level-elevation",
            "Upper level elevation",
            "Upper calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "high-side-port-elevation",
            "High-side port elevation",
            "Transmitter HP-port elevation.",
        ),
        _length_specification(
            "low-side-port-elevation",
            "Low-side port elevation",
            "Transmitter LP-port elevation.",
        ),
        _density_specification(
            "process-liquid-density",
            "Process liquid density",
            "Positive uniform process-liquid density.",
        ),
        _density_specification(
            "dry-leg-vapour-density",
            "Dry-leg vapour density",
            "Explicit nonnegative uniform vapour density; zero is an explicit approximation.",
            allow_zero=True,
        ),
        _gravity_specification(),
        _absolute_pressure_specification(
            "vessel-vapour-absolute-pressure",
            "Vessel vapour absolute pressure",
            "Explicit absolute pressure at the liquid surface.",
        ),
    ),
    formula_description=(
        "Both port absolute pressures are propagated from the common surface "
        "pressure using their explicit fluid densities and elevations."
    ),
    limitations=(
        "Each pressure path is represented by one uniform density.",
        "The HP path must remain liquid filled over the calibrated range.",
    ),
    exclusions=(
        "Condensing dry legs, purge flow, plugged lines, and transient density are excluded.",
    ),
)


_WET_LEG_DEFINITION: Final = _approved_method(
    method_id="level.dp.closed-wet-leg-range",
    title="Closed-vessel wet-leg differential-pressure level range",
    description=(
        "Calculate endpoint port pressures and range with explicit process, "
        "vapour, and wet-leg fill densities and elevations."
    ),
    input_specifications=(
        _length_specification(
            "lower-level-elevation",
            "Lower level elevation",
            "Lower calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "upper-level-elevation",
            "Upper level elevation",
            "Upper calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "high-side-port-elevation",
            "High-side port elevation",
            "Transmitter HP-port elevation.",
        ),
        _length_specification(
            "low-side-reference-elevation",
            "Low-side reference elevation",
            "Top of the maintained wet-leg fill column.",
        ),
        _length_specification(
            "low-side-port-elevation",
            "Low-side port elevation",
            "Transmitter LP-port elevation.",
        ),
        _density_specification(
            "process-liquid-density",
            "Process liquid density",
            "Positive uniform process-liquid density.",
        ),
        _density_specification(
            "vapour-density",
            "Vapour density",
            "Explicit nonnegative uniform vessel-vapour density.",
            allow_zero=True,
        ),
        _density_specification(
            "wet-leg-fill-density",
            "Wet-leg fill density",
            "Positive maintained wet-leg fill density.",
        ),
        _gravity_specification(),
        _absolute_pressure_specification(
            "vessel-vapour-absolute-pressure",
            "Vessel vapour absolute pressure",
            "Explicit absolute pressure at the liquid surface.",
        ),
    ),
    formula_description=(
        "HP and LP absolute pressures are propagated from the vessel-surface "
        "pressure through explicit process, vapour, and wet-leg columns."
    ),
    limitations=(
        "The wet leg is full, stable, and uniform at the supplied density.",
        "The upper level remains at or below the low-side reference elevation.",
    ),
    exclusions=(
        "Evaporating, leaking, freezing, or composition-changing wet legs are excluded.",
    ),
)


_REMOTE_SEAL_DEFINITION: Final = _approved_method(
    method_id="level.dp.remote-seal-range",
    title="Dual-remote-seal differential-pressure level range",
    description=(
        "Calculate endpoint pressure and range using explicit seal, port, "
        "process, vapour, capillary-fill, and temperature suitability inputs."
    ),
    input_specifications=(
        _length_specification(
            "lower-level-elevation",
            "Lower level elevation",
            "Lower calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "upper-level-elevation",
            "Upper level elevation",
            "Upper calibrated liquid-surface elevation.",
        ),
        _length_specification(
            "high-side-seal-elevation",
            "High-side seal elevation",
            "Process elevation of the HP remote seal.",
        ),
        _length_specification(
            "low-side-seal-elevation",
            "Low-side seal elevation",
            "Process elevation of the LP remote seal.",
        ),
        _length_specification(
            "high-side-port-elevation",
            "High-side port elevation",
            "Transmitter HP-port elevation.",
        ),
        _length_specification(
            "low-side-port-elevation",
            "Low-side port elevation",
            "Transmitter LP-port elevation.",
        ),
        _density_specification(
            "process-liquid-density",
            "Process liquid density",
            "Positive process-liquid density.",
        ),
        _density_specification(
            "vapour-density",
            "Vapour density",
            "Explicit nonnegative vessel-vapour density.",
            allow_zero=True,
        ),
        _density_specification(
            "high-side-fill-density",
            "High-side fill density",
            "Positive HP capillary fill density at applicable temperature.",
        ),
        _density_specification(
            "low-side-fill-density",
            "Low-side fill density",
            "Positive LP capillary fill density at applicable temperature.",
        ),
        _gravity_specification(),
        _absolute_pressure_specification(
            "vessel-vapour-absolute-pressure",
            "Vessel vapour absolute pressure",
            "Explicit liquid-surface absolute pressure.",
        ),
        _true_confirmation_specification(
            "installed-geometry-confirmed",
            "Installed geometry confirmed",
            "Confirm actual seal, capillary, transmitter, and elevation arrangement.",
        ),
        _true_confirmation_specification(
            "fill-fluid-temperature-density-confirmed",
            "Fill-fluid temperature and density confirmed",
            "Confirm OEM fill-fluid suitability and density at applicable temperature.",
        ),
    ),
    formula_description=(
        "Each port pressure is propagated from the vessel surface through "
        "process/vapour head and its separately specified capillary fill head."
    ),
    limitations=(
        "The HP seal remains submerged and the LP seal remains above maximum level.",
        "Only static fill-fluid head is calculated.",
    ),
    exclusions=(
        "Capillary thermal transient, response time, vacuum boiling, and OEM seal sizing are excluded.",
    ),
)


_INTERFACE_DEFINITION: Final = _approved_method(
    method_id="level.dp.interface-range",
    title="Two-liquid interface differential-pressure range",
    description=(
        "Calculate a fully flooded two-liquid interface range with a known "
        "heavier lower fluid and lighter upper fluid."
    ),
    input_specifications=(
        _length_specification(
            "lower-interface-elevation",
            "Lower interface elevation",
            "Lower calibrated interface elevation.",
        ),
        _length_specification(
            "upper-interface-elevation",
            "Upper interface elevation",
            "Upper calibrated interface elevation.",
        ),
        _length_specification(
            "bottom-reference-elevation",
            "Bottom reference elevation",
            "Bottom of the fully flooded modeled height.",
        ),
        _length_specification(
            "total-flooded-height",
            "Total flooded height",
            "Positive total two-liquid flooded height.",
            positive=True,
        ),
        _length_specification(
            "high-side-port-elevation",
            "High-side port elevation",
            "HP-port elevation connected through lower fluid.",
        ),
        _length_specification(
            "low-side-port-elevation",
            "Low-side port elevation",
            "LP-port elevation connected through upper fluid.",
        ),
        _density_specification(
            "lower-fluid-density",
            "Lower fluid density",
            "Positive density of the heavier lower fluid.",
        ),
        _density_specification(
            "upper-fluid-density",
            "Upper fluid density",
            "Positive density of the lighter upper fluid.",
        ),
        _gravity_specification(),
        _absolute_pressure_specification(
            "top-reference-absolute-pressure",
            "Top reference absolute pressure",
            "Explicit absolute pressure at the top reference elevation.",
        ),
    ),
    formula_description=(
        "Endpoint HP and LP absolute pressures are calculated from the top "
        "reference through explicit upper/lower liquid columns."
    ),
    limitations=(
        "Both liquids fully occupy the modeled height with one sharp interface.",
        "Lower-fluid density must be strictly greater than upper-fluid density.",
    ),
    exclusions=(
        "Emulsions, rag layers, more than two fluids, and varying density are excluded.",
    ),
)


_ENDPOINT_RANGE_DEFINITION: Final = _approved_method(
    method_id="level.dp.endpoint-range",
    title="DP level endpoint range and pressure-capability screen",
    description=(
        "Derive LRV and URV from endpoint HP/LP absolute pressures and screen "
        "sensor range, static pressure, and separate one-sided overload cases."
    ),
    input_specifications=(
        _differential_pressure_specification(
            "sensor-lower-range-limit",
            "Sensor lower range limit",
            "Explicit sensor LRL.",
        ),
        _differential_pressure_specification(
            "sensor-upper-range-limit",
            "Sensor upper range limit",
            "Explicit sensor URL.",
        ),
        _absolute_pressure_specification(
            "lower-endpoint-high-side-absolute-pressure",
            "Lower endpoint HP pressure",
            "HP-port absolute pressure at lower calibrated level.",
        ),
        _absolute_pressure_specification(
            "lower-endpoint-low-side-absolute-pressure",
            "Lower endpoint LP pressure",
            "LP-port absolute pressure at lower calibrated level.",
        ),
        _absolute_pressure_specification(
            "upper-endpoint-high-side-absolute-pressure",
            "Upper endpoint HP pressure",
            "HP-port absolute pressure at upper calibrated level.",
        ),
        _absolute_pressure_specification(
            "upper-endpoint-low-side-absolute-pressure",
            "Upper endpoint LP pressure",
            "LP-port absolute pressure at upper calibrated level.",
        ),
        _absolute_pressure_specification(
            "maximum-high-side-absolute-pressure",
            "Worst-case HP absolute pressure",
            "Maximum credible HP-port absolute pressure including non-calibration cases.",
        ),
        _absolute_pressure_specification(
            "maximum-low-side-absolute-pressure",
            "Worst-case LP absolute pressure",
            "Maximum credible LP-port absolute pressure including non-calibration cases.",
        ),
        _differential_pressure_specification(
            "maximum-positive-differential-pressure",
            "Worst positive differential pressure",
            "Maximum credible nonnegative HP-minus-LP pressure.",
        ),
        _differential_pressure_specification(
            "maximum-negative-differential-pressure",
            "Worst negative differential pressure",
            "Most negative credible HP-minus-LP pressure.",
        ),
        _absolute_pressure_specification(
            "maximum-static-absolute-pressure",
            "Maximum static absolute pressure",
            "Transmitter maximum allowable side absolute/static pressure.",
        ),
        _differential_pressure_specification(
            "positive-overpressure-limit",
            "Positive overpressure limit",
            "Positive one-sided DP overload capability.",
        ),
        _differential_pressure_specification(
            "negative-overpressure-limit",
            "Negative overpressure limit",
            "Negative one-sided DP overload capability.",
        ),
    ),
    formula_description=(
        "Endpoint DP is derived as HP minus LP; range and independent "
        "static/positive/negative pressure margins are then calculated."
    ),
    limitations=(
        "This is a preliminary numerical capability screen, not an equipment selection.",
        "Worst-case pressures must include credible start-up, shutdown, isolation, and fault cases.",
    ),
    exclusions=(
        "Dynamic pressure shock, temperature derating, hazardous-area approval, and material compatibility are excluded.",
    ),
)


_VERTICAL_CYLINDER_DEFINITION: Final = _approved_method(
    method_id="level.tank.vertical-cylinder",
    title="Flat-ended vertical cylindrical tank volume",
    description=(
        "Calculate liquid volume, cylindrical capacity, and fill fraction from "
        "internal diameter, straight-side height, and bottom-referenced level."
    ),
    input_specifications=(
        _length_specification(
            "internal-diameter",
            "Internal diameter",
            "Positive internal cylindrical diameter.",
            positive=True,
        ),
        _length_specification(
            "straight-side-height",
            "Straight-side height",
            "Positive internal straight-side height.",
            positive=True,
        ),
        _length_specification(
            "liquid-height",
            "Liquid height",
            "Bottom-referenced contained liquid height.",
            nonnegative=True,
        ),
        _true_confirmation_specification(
            "flat-end-internal-geometry-confirmed",
            "Flat-end internal geometry confirmed",
            "Confirm dimensions are internal and end-head volume is excluded.",
        ),
        _true_confirmation_specification(
            "liquid-level-within-cylinder-confirmed",
            "Liquid level within cylinder confirmed",
            "Confirm the level is bottom referenced and within the straight cylindrical section.",
        ),
    ),
    formula_description=(
        "Internal circular cross-sectional area is multiplied by height for "
        "liquid volume and straight-side height for full capacity."
    ),
    source_references=_GEOMETRY_REFERENCES,
    limitations=(
        "Only the flat-ended straight cylindrical internal volume is modeled.",
    ),
    exclusions=(
        "Heads, cones, internals, dead volume, tilt, and calibration-table corrections are excluded.",
    ),
)


_HORIZONTAL_CYLINDER_DEFINITION: Final = _approved_method(
    method_id="level.tank.horizontal-cylinder",
    title="Flat-ended level horizontal cylindrical tank volume",
    description=(
        "Calculate liquid volume, capacity, and fill fraction using a stable "
        "circular-segment implementation."
    ),
    input_specifications=(
        _length_specification(
            "internal-diameter",
            "Internal diameter",
            "Positive internal cylindrical diameter.",
            positive=True,
        ),
        _length_specification(
            "cylindrical-length",
            "Cylindrical length",
            "Positive internal flat-ended cylinder length.",
            positive=True,
        ),
        _length_specification(
            "liquid-height",
            "Liquid height",
            "Bottom-referenced liquid height from zero through diameter.",
            nonnegative=True,
        ),
        _true_confirmation_specification(
            "flat-end-internal-geometry-confirmed",
            "Flat-end internal geometry confirmed",
            "Confirm dimensions are internal and end-head volume is excluded.",
        ),
        _true_confirmation_specification(
            "level-cylinder-geometry-confirmed",
            "Level cylinder geometry confirmed",
            "Confirm the cylinder axis is level and liquid height is bottom referenced.",
        ),
    ),
    formula_description=(
        "A numerically stable circular-segment area is multiplied by internal "
        "cylindrical length; the complementary segment is used above half full."
    ),
    source_references=_GEOMETRY_REFERENCES,
    limitations=(
        "The cylinder is level, flat ended, circular, and uses internal dimensions.",
    ),
    exclusions=(
        "Heads, tilt, noncircular shells, internals, and strapping-table corrections are excluded.",
    ),
)


LEVEL_METHOD_REGISTRATIONS: Final = (
    MethodRegistration(
        definition=_COLUMN_PRESSURE_DEFINITION,
        implementation=execute_column_pressure,
    ),
    MethodRegistration(
        definition=_OPEN_VESSEL_DEFINITION,
        implementation=execute_open_vessel_range,
    ),
    MethodRegistration(
        definition=_DRY_LEG_DEFINITION,
        implementation=execute_closed_dry_leg_range,
    ),
    MethodRegistration(
        definition=_WET_LEG_DEFINITION,
        implementation=execute_closed_wet_leg_range,
    ),
    MethodRegistration(
        definition=_REMOTE_SEAL_DEFINITION,
        implementation=execute_remote_seal_range,
    ),
    MethodRegistration(
        definition=_INTERFACE_DEFINITION,
        implementation=execute_interface_range,
    ),
    MethodRegistration(
        definition=_ENDPOINT_RANGE_DEFINITION,
        implementation=execute_endpoint_range,
    ),
    MethodRegistration(
        definition=_VERTICAL_CYLINDER_DEFINITION,
        implementation=execute_vertical_cylinder,
    ),
    MethodRegistration(
        definition=_HORIZONTAL_CYLINDER_DEFINITION,
        implementation=execute_horizontal_cylinder,
    ),
)

LEVEL_METHOD_REGISTRY: Final = CalculationMethodRegistry(
    LEVEL_METHOD_REGISTRATIONS
)
LEVEL_METHOD_IDS: Final = LEVEL_METHOD_REGISTRY.method_ids

from app.engineering.calculations.engine import CalculationEngine  # noqa: E402
from app.engineering.calculations.general import (  # noqa: E402
    GENERAL_METHOD_REGISTRATIONS,
)


LEVEL_CALCULATION_ENGINE: Final = CalculationEngine(
    registry=LEVEL_METHOD_REGISTRY
)
ENGINEERING_METHOD_REGISTRATIONS: Final = (
    GENERAL_METHOD_REGISTRATIONS + LEVEL_METHOD_REGISTRATIONS
)
ENGINEERING_METHOD_REGISTRY: Final = CalculationMethodRegistry(
    ENGINEERING_METHOD_REGISTRATIONS
)
ENGINEERING_METHOD_IDS: Final = ENGINEERING_METHOD_REGISTRY.method_ids
ENGINEERING_CALCULATION_ENGINE: Final = CalculationEngine(
    registry=ENGINEERING_METHOD_REGISTRY
)


__all__ = [
    "ENGINEERING_CALCULATION_ENGINE",
    "ENGINEERING_METHOD_IDS",
    "ENGINEERING_METHOD_REGISTRATIONS",
    "ENGINEERING_METHOD_REGISTRY",
    "LEVEL_CALCULATION_ENGINE",
    "LEVEL_CALCULATION_TYPE_PREFIX",
    "LEVEL_CALCULATORS_VERSION",
    "LEVEL_METHOD_IDS",
    "LEVEL_METHOD_REGISTRATIONS",
    "LEVEL_METHOD_REGISTRY",
    "LEVEL_METHOD_VERSION",
    "LevelCalculationDomainError",
    "LevelCalculationError",
    "LevelCalculationInputError",
    "LevelRangeResult",
    "LevelTransmitterRangeResult",
    "PressureLevelRangeResult",
    "PressureLimitScreenResult",
    "TankVolumeResult",
    "dry_leg_dp_range",
    "horizontal_cylindrical_tank_volume",
    "interface_dp_range",
    "liquid_column_pressure",
    "liquid_head_from_pressure",
    "open_vessel_dp_range",
    "remote_seal_dp_range",
    "screen_level_transmitter_range",
    "screen_pressure_limits",
    "vertical_cylindrical_tank_volume",
    "wet_leg_dp_range",
]
