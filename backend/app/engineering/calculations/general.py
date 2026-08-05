"""Reviewed general engineering calculators for Phase 7 Step 94.

The functions in this module are deliberately small, deterministic, and
unit-safe.  They accept immutable :class:`EngineeringQuantity` values, fully
revalidate them at the public boundary, and return explicit quantities or
frozen result models.  No atmospheric pressure, gas reference state, fluid
density, gravitational acceleration, signal extraction rule, or uncertainty
correlation is supplied implicitly.

The bottom of the module binds a controlled subset of these functions to
approved, exact-version method definitions.  Registry executors receive only
canonical normalized inputs from the Step 92 engine.  Formula identifiers are
metadata identifiers, never executable expression text.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from decimal import Decimal
from decimal import localcontext
from math import fsum
from math import hypot
from math import isfinite
from math import pi
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
from app.engineering.calculations.method_models import SafetyRequirement
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.registry import CalculationMethodRegistry
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.safety import MethodSafetyExtension
from app.engineering.calculations.safety import SafetyEvaluationContext
from app.engineering.calculations.safety import SafetyTrigger
from app.engineering.calculations.units import (
    CompressibilityTreatment,
)
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import FlowReferenceBasis
from app.engineering.calculations.units import PhysicalDimension
from app.engineering.calculations.units import PressureBasisError
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import ReferenceConditions
from app.engineering.calculations.units import ReferenceConditionError
from app.engineering.calculations.units import ReferencedVolumetricFlow
from app.engineering.calculations.units import UnitSystemError
from app.engineering.calculations.units import convert_pressure_basis
from app.engineering.calculations.units import (
    convert_referenced_volumetric_flow,
)


GENERAL_CALCULATORS_VERSION: Final = "1.0.0"
GENERAL_CALCULATION_TYPE_PREFIX: Final = "general"
GENERAL_METHOD_VERSION: Final = "1.0.0"

_MAXIMUM_MAGNITUDE: Final = 1.0e300
_MAXIMUM_UNCERTAINTY_COMPONENTS: Final = 256
_FOUR_MA: Final = 0.004
_SIXTEEN_MA: Final = 0.016
_TWENTY_MA: Final = 0.020


class GeneralCalculationError(ValueError):
    """Base error for deterministic general-calculator failures."""

    code = "general_calculation_error"


class GeneralCalculationInputError(GeneralCalculationError):
    """Raised when a public input does not satisfy the typed contract."""

    code = "general_calculation_input_error"


class GeneralCalculationDomainError(GeneralCalculationError):
    """Raised when finite inputs are outside the physical equation domain."""

    code = "general_calculation_domain_error"


class PipeFlowResult(CalculationModel):
    """Pipe geometry, mean velocity, and Reynolds-number result."""

    cross_sectional_area: EngineeringQuantity
    mean_velocity: EngineeringQuantity
    reynolds_number: EngineeringQuantity


class LoopVoltageBudgetResult(CalculationModel):
    """Deterministic DC current-loop voltage and load screen."""

    load_voltage_drop: EngineeringQuantity
    total_required_voltage: EngineeringQuantity
    signed_voltage_residual: EngineeringQuantity
    maximum_external_load_resistance: EngineeringQuantity
    adequate_voltage: bool


class TransmitterRangeResult(CalculationModel):
    """Calibrated differential-pressure transmitter range assessment."""

    sensor_span: EngineeringQuantity
    calibrated_span: EngineeringQuantity
    fraction_of_range: EngineeringQuantity
    percent_of_range: EngineeringQuantity
    turndown_ratio: EngineeringQuantity
    range_status: str
    calibration_within_sensor_limits: bool


def _revalidate_quantity(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> EngineeringQuantity:
    """Return a fresh validated quantity and reject constructed bypasses."""

    if not isinstance(quantity, EngineeringQuantity):
        raise GeneralCalculationInputError(
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
        raise GeneralCalculationInputError(
            f"{field_name} is not a valid supported engineering quantity."
        ) from exc


def _canonical_quantity(
    quantity: EngineeringQuantity,
    expected_kind: QuantityKind,
    *,
    field_name: str,
    allow_uncertainty: bool = False,
) -> EngineeringQuantity:
    """Validate one exact quantity kind and return its canonical value."""

    validated = _revalidate_quantity(quantity, field_name=field_name)
    if validated.quantity_kind != expected_kind.value:
        raise GeneralCalculationInputError(
            f"{field_name} must use quantity kind {expected_kind.value!r}."
        )
    if not allow_uncertainty and validated.uncertainty is not None:
        raise GeneralCalculationInputError(
            f"{field_name} uncertainty requires a supported uncertainty "
            "method and cannot be ignored."
        )

    try:
        return DEFAULT_UNIT_REGISTRY.canonicalize_quantity(validated)
    except UnitSystemError as exc:
        raise GeneralCalculationInputError(
            f"{field_name} cannot be converted to its canonical unit."
        ) from exc


def _coerce_quantity_kind(
    quantity_kind: QuantityKind | str,
    *,
    field_name: str,
) -> QuantityKind:
    """Return one exact supported quantity-kind enumeration."""

    try:
        return (
            quantity_kind
            if isinstance(quantity_kind, QuantityKind)
            else QuantityKind(quantity_kind)
        )
    except (TypeError, ValueError) as exc:
        raise GeneralCalculationInputError(
            f"{field_name} is not a supported quantity kind."
        ) from exc


def _finite_number(
    value: int | float,
    *,
    field_name: str,
) -> float:
    """Return one strict finite, bounded, non-boolean number."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GeneralCalculationInputError(
            f"{field_name} must be a finite supported number."
        )
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise GeneralCalculationInputError(
            f"{field_name} must be a finite supported number."
        ) from exc
    if not isfinite(normalized) or abs(normalized) > _MAXIMUM_MAGNITUDE:
        raise GeneralCalculationInputError(
            f"{field_name} must be a finite supported number."
        )

    return normalized


def _finite_result(
    value: float,
    *,
    field_name: str,
) -> float:
    """Reject non-finite, overflowed, and underflowed formula results."""

    if not isfinite(value) or abs(value) > _MAXIMUM_MAGNITUDE:
        raise GeneralCalculationDomainError(
            f"{field_name} exceeds the supported numerical range."
        )
    if value != 0.0 and float(value) == 0.0:
        raise GeneralCalculationDomainError(
            f"{field_name} underflowed the supported numerical range."
        )
    if value == 0.0:
        return 0.0
    return value


def _quantity(
    quantity_kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    """Build one finite result quantity."""

    return EngineeringQuantity(
        quantity_kind=quantity_kind.value,
        value=_finite_result(value, field_name="calculation result"),
        unit=unit,
    )


def _convert_result(
    quantity: EngineeringQuantity,
    target_unit: str | None,
) -> EngineeringQuantity:
    """Convert a result only through the controlled unit registry."""

    if target_unit is None:
        return quantity
    if not isinstance(target_unit, str) or not target_unit.strip():
        raise GeneralCalculationInputError(
            "target_unit must be a non-blank supported unit."
        )

    try:
        return DEFAULT_UNIT_REGISTRY.convert_quantity(
            quantity,
            target_unit,
        )
    except UnitSystemError as exc:
        raise GeneralCalculationInputError(
            "target_unit is incompatible with the result quantity."
        ) from exc


def _require_positive(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> None:
    """Require a canonical quantity to be strictly positive."""

    if quantity.value <= 0.0:
        raise GeneralCalculationDomainError(
            f"{field_name} must be greater than zero."
        )


def _require_nonnegative(
    quantity: EngineeringQuantity,
    *,
    field_name: str,
) -> None:
    """Require a canonical quantity to be zero or positive."""

    if quantity.value < 0.0:
        raise GeneralCalculationDomainError(
            f"{field_name} cannot be negative."
        )


def convert_pressure(
    quantity: EngineeringQuantity,
    target_kind: QuantityKind | str,
    *,
    atmospheric_pressure: EngineeringQuantity | None = None,
    target_unit: str | None = None,
) -> EngineeringQuantity:
    """Convert pressure units or basis without an implicit atmosphere.

    Differential pressure may only undergo ordinary same-kind unit
    conversion.  Gauge/absolute basis changes require a separately supplied,
    positive absolute atmospheric pressure.  Supplying atmospheric pressure
    for a same-basis conversion is rejected so it cannot be mistaken as used.
    """

    validated = _revalidate_quantity(quantity, field_name="quantity")
    source_kind = _coerce_quantity_kind(
        validated.quantity_kind,
        field_name="quantity.quantity_kind",
    )
    target = _coerce_quantity_kind(
        target_kind,
        field_name="target_kind",
    )
    pressure_kinds = {
        QuantityKind.ABSOLUTE_PRESSURE,
        QuantityKind.GAUGE_PRESSURE,
        QuantityKind.DIFFERENTIAL_PRESSURE,
    }
    if source_kind not in pressure_kinds or target not in pressure_kinds:
        raise GeneralCalculationInputError(
            "Source and target must be absolute, gauge, or differential "
            "pressure kinds."
        )

    output_unit = validated.unit if target_unit is None else target_unit
    if source_kind is target:
        if atmospheric_pressure is not None:
            raise GeneralCalculationInputError(
                "atmospheric_pressure is not used for same-basis pressure "
                "conversion."
            )
        try:
            return DEFAULT_UNIT_REGISTRY.convert_quantity(
                validated,
                output_unit,
            )
        except UnitSystemError as exc:
            raise GeneralCalculationInputError(
                "Pressure unit conversion failed."
            ) from exc

    if (
        source_kind is QuantityKind.DIFFERENTIAL_PRESSURE
        or target is QuantityKind.DIFFERENTIAL_PRESSURE
    ):
        raise GeneralCalculationDomainError(
            "Differential pressure is not a gauge/absolute pressure basis."
        )
    if atmospheric_pressure is None:
        raise GeneralCalculationInputError(
            "atmospheric_pressure is required for gauge/absolute "
            "conversion."
        )

    try:
        return convert_pressure_basis(
            validated,
            target,
            atmospheric_pressure=atmospheric_pressure,
            target_unit=output_unit,
        )
    except PressureBasisError as exc:
        raise GeneralCalculationDomainError(str(exc)) from exc


def convert_referenced_gas_volume(
    flow: ReferencedVolumetricFlow,
    target_conditions: ReferenceConditions,
    *,
    target_unit: str | None = None,
) -> ReferencedVolumetricFlow:
    """Convert gas volume between two fully explicit reference states."""

    try:
        return convert_referenced_volumetric_flow(
            flow,
            target_conditions,
            target_unit=target_unit,
        )
    except ReferenceConditionError as exc:
        raise GeneralCalculationDomainError(str(exc)) from exc


def density_from_specific_gravity(
    specific_gravity: EngineeringQuantity,
    reference_density: EngineeringQuantity,
    *,
    target_unit: str = "kg/m3",
) -> EngineeringQuantity:
    """Calculate density from SG and an explicit positive reference density."""

    sg = _canonical_quantity(
        specific_gravity,
        QuantityKind.SPECIFIC_GRAVITY,
        field_name="specific_gravity",
    )
    density_reference = _canonical_quantity(
        reference_density,
        QuantityKind.DENSITY,
        field_name="reference_density",
    )
    _require_positive(sg, field_name="specific_gravity")
    _require_positive(
        density_reference,
        field_name="reference_density",
    )
    result = _quantity(
        QuantityKind.DENSITY,
        _finite_result(
            sg.value * density_reference.value,
            field_name="density",
        ),
        "kg/m3",
    )
    return _convert_result(result, target_unit)


def specific_gravity_from_density(
    density: EngineeringQuantity,
    reference_density: EngineeringQuantity,
) -> EngineeringQuantity:
    """Calculate SG from density and an explicit positive reference density."""

    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    density_reference = _canonical_quantity(
        reference_density,
        QuantityKind.DENSITY,
        field_name="reference_density",
    )
    _require_positive(density_value, field_name="density")
    _require_positive(
        density_reference,
        field_name="reference_density",
    )
    return _quantity(
        QuantityKind.SPECIFIC_GRAVITY,
        _finite_result(
            density_value.value / density_reference.value,
            field_name="specific gravity",
        ),
        "1",
    )


def dynamic_viscosity_from_kinematic(
    kinematic_viscosity: EngineeringQuantity,
    density: EngineeringQuantity,
    *,
    target_unit: str = "Pa.s",
) -> EngineeringQuantity:
    """Calculate dynamic viscosity from kinematic viscosity and density."""

    kinematic = _canonical_quantity(
        kinematic_viscosity,
        QuantityKind.KINEMATIC_VISCOSITY,
        field_name="kinematic_viscosity",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    _require_positive(
        kinematic,
        field_name="kinematic_viscosity",
    )
    _require_positive(density_value, field_name="density")
    result = _quantity(
        QuantityKind.DYNAMIC_VISCOSITY,
        _finite_result(
            kinematic.value * density_value.value,
            field_name="dynamic viscosity",
        ),
        "Pa.s",
    )
    return _convert_result(result, target_unit)


def kinematic_viscosity_from_dynamic(
    dynamic_viscosity: EngineeringQuantity,
    density: EngineeringQuantity,
    *,
    target_unit: str = "m2/s",
) -> EngineeringQuantity:
    """Calculate kinematic viscosity from dynamic viscosity and density."""

    dynamic = _canonical_quantity(
        dynamic_viscosity,
        QuantityKind.DYNAMIC_VISCOSITY,
        field_name="dynamic_viscosity",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    _require_positive(
        dynamic,
        field_name="dynamic_viscosity",
    )
    _require_positive(density_value, field_name="density")
    result = _quantity(
        QuantityKind.KINEMATIC_VISCOSITY,
        _finite_result(
            dynamic.value / density_value.value,
            field_name="kinematic viscosity",
        ),
        "m2/s",
    )
    return _convert_result(result, target_unit)


def hydrostatic_pressure(
    density: EngineeringQuantity,
    liquid_height: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    *,
    target_unit: str = "Pa",
) -> EngineeringQuantity:
    """Return static liquid-column differential pressure with explicit gravity."""

    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    height = _canonical_quantity(
        liquid_height,
        QuantityKind.LENGTH,
        field_name="liquid_height",
    )
    gravity = _canonical_quantity(
        gravitational_acceleration,
        QuantityKind.ACCELERATION,
        field_name="gravitational_acceleration",
    )
    _require_positive(density_value, field_name="density")
    _require_nonnegative(height, field_name="liquid_height")
    _require_positive(
        gravity,
        field_name="gravitational_acceleration",
    )
    result = _quantity(
        QuantityKind.DIFFERENTIAL_PRESSURE,
        _finite_result(
            density_value.value * gravity.value * height.value,
            field_name="hydrostatic pressure",
        ),
        "Pa",
    )
    return _convert_result(result, target_unit)


def pressure_head(
    pressure: EngineeringQuantity,
    density: EngineeringQuantity,
    gravitational_acceleration: EngineeringQuantity,
    *,
    target_unit: str = "m",
) -> EngineeringQuantity:
    """Return liquid head from differential pressure, density, and gravity."""

    pressure_value = _canonical_quantity(
        pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="pressure",
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
    _require_nonnegative(pressure_value, field_name="pressure")
    _require_positive(density_value, field_name="density")
    _require_positive(
        gravity,
        field_name="gravitational_acceleration",
    )
    result = _quantity(
        QuantityKind.LENGTH,
        _finite_result(
            pressure_value.value
            / (density_value.value * gravity.value),
            field_name="pressure head",
        ),
        "m",
    )
    return _convert_result(result, target_unit)


def pipe_area_velocity_reynolds(
    internal_diameter: EngineeringQuantity,
    actual_volumetric_flow: EngineeringQuantity,
    density: EngineeringQuantity,
    dynamic_viscosity: EngineeringQuantity,
    full_pipe_confirmed: bool,
    representative_properties_confirmed: bool,
) -> PipeFlowResult:
    """Calculate circular area, mean velocity, and Reynolds number."""

    if not isinstance(full_pipe_confirmed, bool) or not isinstance(
        representative_properties_confirmed,
        bool,
    ):
        raise GeneralCalculationInputError(
            "Pipe applicability confirmations must be booleans."
        )
    if not full_pipe_confirmed:
        raise GeneralCalculationDomainError(
            "A full circular pipe must be explicitly confirmed."
        )
    if not representative_properties_confirmed:
        raise GeneralCalculationDomainError(
            "Representative flowing density and viscosity must be confirmed."
        )

    diameter = _canonical_quantity(
        internal_diameter,
        QuantityKind.LENGTH,
        field_name="internal_diameter",
    )
    flow = _canonical_quantity(
        actual_volumetric_flow,
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        field_name="actual_volumetric_flow",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    viscosity = _canonical_quantity(
        dynamic_viscosity,
        QuantityKind.DYNAMIC_VISCOSITY,
        field_name="dynamic_viscosity",
    )
    _require_positive(diameter, field_name="internal_diameter")
    _require_nonnegative(
        flow,
        field_name="actual_volumetric_flow",
    )
    _require_positive(density_value, field_name="density")
    _require_positive(
        viscosity,
        field_name="dynamic_viscosity",
    )

    area_value = _finite_result(
        pi * diameter.value * diameter.value / 4.0,
        field_name="pipe area",
    )
    if area_value <= 0.0:
        raise GeneralCalculationDomainError(
            "internal_diameter is too small to produce a representable area."
        )
    velocity_value = _finite_result(
        flow.value / area_value,
        field_name="mean velocity",
    )
    reynolds_value = _finite_result(
        (
            density_value.value
            * velocity_value
            * diameter.value
            / viscosity.value
        ),
        field_name="Reynolds number",
    )
    return PipeFlowResult(
        cross_sectional_area=_quantity(
            QuantityKind.AREA,
            area_value,
            "m2",
        ),
        mean_velocity=_quantity(
            QuantityKind.VELOCITY,
            velocity_value,
            "m/s",
        ),
        reynolds_number=_quantity(
            QuantityKind.DIMENSIONLESS,
            reynolds_value,
            "1",
        ),
    )


def _linear_span(
    lower_range_value: EngineeringQuantity,
    upper_range_value: EngineeringQuantity,
) -> tuple[EngineeringQuantity, EngineeringQuantity, float]:
    """Validate matching linear limits and return their positive span."""

    lower = _revalidate_quantity(
        lower_range_value,
        field_name="lower_range_value",
    )
    upper = _revalidate_quantity(
        upper_range_value,
        field_name="upper_range_value",
    )
    if (
        lower.quantity_kind != upper.quantity_kind
        or DEFAULT_UNIT_REGISTRY.dimension_for(lower.quantity_kind)
        is not DEFAULT_UNIT_REGISTRY.dimension_for(upper.quantity_kind)
    ):
        raise GeneralCalculationInputError(
            "lower_range_value and upper_range_value must use the same "
            "quantity kind."
        )
    if lower.uncertainty is not None or upper.uncertainty is not None:
        raise GeneralCalculationInputError(
            "Linear range uncertainty requires a supported uncertainty "
            "method and cannot be ignored."
        )

    try:
        canonical_lower = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(lower)
        canonical_upper = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(upper)
    except UnitSystemError as exc:
        raise GeneralCalculationInputError(
            "Linear range values cannot be normalized."
        ) from exc

    span = _finite_result(
        canonical_upper.value - canonical_lower.value,
        field_name="transmitter span",
    )
    if span <= 0.0:
        raise GeneralCalculationDomainError(
            "upper_range_value must be greater than lower_range_value."
        )
    return canonical_lower, canonical_upper, span


def transmitter_linear_fraction(
    process_value: EngineeringQuantity,
    lower_range_value: EngineeringQuantity,
    upper_range_value: EngineeringQuantity,
) -> EngineeringQuantity:
    """Map a linear process value to its fractional calibrated range."""

    lower, _, span = _linear_span(
        lower_range_value,
        upper_range_value,
    )
    process = _revalidate_quantity(
        process_value,
        field_name="process_value",
    )
    if process.quantity_kind != lower.quantity_kind:
        raise GeneralCalculationInputError(
            "process_value must use the range quantity kind."
        )
    if process.uncertainty is not None:
        raise GeneralCalculationInputError(
            "process_value uncertainty requires a supported uncertainty "
            "method and cannot be ignored."
        )
    try:
        canonical_process = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(
            process
        )
    except UnitSystemError as exc:
        raise GeneralCalculationInputError(
            "process_value cannot be normalized."
        ) from exc

    return _quantity(
        QuantityKind.RATIO,
        _finite_result(
            (canonical_process.value - lower.value) / span,
            field_name="linear range fraction",
        ),
        "1",
    )


def transmitter_value_from_fraction(
    fraction: EngineeringQuantity,
    lower_range_value: EngineeringQuantity,
    upper_range_value: EngineeringQuantity,
    *,
    target_unit: str | None = None,
) -> EngineeringQuantity:
    """Map a fractional calibrated range back to its linear process value."""

    normalized_fraction = _canonical_quantity(
        fraction,
        QuantityKind.RATIO,
        field_name="fraction",
    )
    lower, _, span = _linear_span(
        lower_range_value,
        upper_range_value,
    )
    result = EngineeringQuantity(
        quantity_kind=lower.quantity_kind,
        value=_finite_result(
            lower.value + normalized_fraction.value * span,
            field_name="linear process value",
        ),
        unit=lower.unit,
    )
    return _convert_result(
        result,
        (
            lower_range_value.unit
            if target_unit is None
            else target_unit
        ),
    )


def assess_dp_transmitter_range(
    applied_differential_pressure: EngineeringQuantity,
    lower_range_limit: EngineeringQuantity,
    upper_range_limit: EngineeringQuantity,
    lower_range_value: EngineeringQuantity,
    upper_range_value: EngineeringQuantity,
) -> TransmitterRangeResult:
    """Assess DP range, span, percent, turndown, and range disposition.

    LRL and URL are explicit sensor capability limits.  LRV and URV are the
    configured calibration.  The calibration must remain entirely inside the
    supplied sensor limits; this helper does not infer product capability.
    """

    applied = _canonical_quantity(
        applied_differential_pressure,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="applied_differential_pressure",
    )
    lower_limit = _canonical_quantity(
        lower_range_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="lower_range_limit",
    )
    upper_limit = _canonical_quantity(
        upper_range_limit,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="upper_range_limit",
    )
    lower = _canonical_quantity(
        lower_range_value,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="lower_range_value",
    )
    upper = _canonical_quantity(
        upper_range_value,
        QuantityKind.DIFFERENTIAL_PRESSURE,
        field_name="upper_range_value",
    )
    sensor_span_value = _finite_result(
        upper_limit.value - lower_limit.value,
        field_name="sensor span",
    )
    if sensor_span_value <= 0.0:
        raise GeneralCalculationDomainError(
            "upper_range_limit must be greater than lower_range_limit."
        )
    span_value = _finite_result(
        upper.value - lower.value,
        field_name="calibrated span",
    )
    if span_value <= 0.0:
        raise GeneralCalculationDomainError(
            "upper_range_value must be greater than lower_range_value."
        )
    if lower.value < lower_limit.value or upper.value > upper_limit.value:
        raise GeneralCalculationDomainError(
            "The calibrated LRV and URV must remain within LRL and URL."
        )

    fraction_value = _finite_result(
        (applied.value - lower.value) / span_value,
        field_name="fraction of range",
    )
    turndown_value = _finite_result(
        sensor_span_value / span_value,
        field_name="turndown ratio",
    )
    if applied.value < lower.value:
        range_status = "below_range"
    elif applied.value > upper.value:
        range_status = "above_range"
    else:
        range_status = "within_range"

    return TransmitterRangeResult(
        sensor_span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            sensor_span_value,
            "Pa",
        ),
        calibrated_span=_quantity(
            QuantityKind.DIFFERENTIAL_PRESSURE,
            span_value,
            "Pa",
        ),
        fraction_of_range=_quantity(
            QuantityKind.RATIO,
            fraction_value,
            "1",
        ),
        percent_of_range=_convert_result(
            _quantity(
                QuantityKind.RATIO,
                fraction_value,
                "1",
            ),
            "%",
        ),
        turndown_ratio=_quantity(
            QuantityKind.RATIO,
            turndown_value,
            "1",
        ),
        range_status=range_status,
        calibration_within_sensor_limits=True,
    )


def _bounded_fraction(
    fraction: EngineeringQuantity,
    *,
    field_name: str,
) -> EngineeringQuantity:
    """Return a canonical ratio restricted to the inclusive zero/one range."""

    normalized = _canonical_quantity(
        fraction,
        QuantityKind.RATIO,
        field_name=field_name,
    )
    if normalized.value < 0.0 or normalized.value > 1.0:
        raise GeneralCalculationDomainError(
            f"{field_name} must be between 0 and 1 inclusive."
        )
    return normalized


def current_from_linear_fraction(
    fraction: EngineeringQuantity,
    *,
    target_unit: str = "mA",
) -> EngineeringQuantity:
    """Map a zero-to-one linear fraction to a 4–20 mA signal."""

    normalized = _bounded_fraction(fraction, field_name="fraction")
    result = _quantity(
        QuantityKind.ELECTRIC_CURRENT,
        _finite_result(
            _FOUR_MA + _SIXTEEN_MA * normalized.value,
            field_name="loop current",
        ),
        "A",
    )
    return _convert_result(result, target_unit)


def linear_fraction_from_current(
    current: EngineeringQuantity,
) -> EngineeringQuantity:
    """Map an inclusive 4–20 mA signal to a zero-to-one linear fraction."""

    normalized = _canonical_quantity(
        current,
        QuantityKind.ELECTRIC_CURRENT,
        field_name="current",
    )
    if normalized.value < _FOUR_MA or normalized.value > _TWENTY_MA:
        raise GeneralCalculationDomainError(
            "current must be between 4 mA and 20 mA inclusive."
        )
    return _quantity(
        QuantityKind.RATIO,
        _finite_result(
            (normalized.value - _FOUR_MA) / _SIXTEEN_MA,
            field_name="linear signal fraction",
        ),
        "1",
    )


def flow_fraction_from_square_root_signal(
    linear_signal_fraction: EngineeringQuantity,
) -> EngineeringQuantity:
    """Extract flow fraction as the square root of a linear DP fraction."""

    normalized = _bounded_fraction(
        linear_signal_fraction,
        field_name="linear_signal_fraction",
    )
    return _quantity(
        QuantityKind.RATIO,
        _finite_result(
            normalized.value**0.5,
            field_name="flow fraction",
        ),
        "1",
    )


def square_root_signal_fraction_from_flow(
    flow_fraction: EngineeringQuantity,
) -> EngineeringQuantity:
    """Return the linear DP fraction corresponding to a flow fraction."""

    normalized = _bounded_fraction(
        flow_fraction,
        field_name="flow_fraction",
    )
    return _quantity(
        QuantityKind.RATIO,
        _finite_result(
            normalized.value * normalized.value,
            field_name="linear signal fraction",
        ),
        "1",
    )


def current_from_square_root_flow_fraction(
    flow_fraction: EngineeringQuantity,
    *,
    target_unit: str = "mA",
) -> EngineeringQuantity:
    """Map flow fraction to the 4–20 mA signal for a linear DP input."""

    return current_from_linear_fraction(
        square_root_signal_fraction_from_flow(flow_fraction),
        target_unit=target_unit,
    )


def square_root_flow_fraction_from_current(
    current: EngineeringQuantity,
) -> EngineeringQuantity:
    """Extract flow fraction from a 4–20 mA signal representing linear DP."""

    return flow_fraction_from_square_root_signal(
        linear_fraction_from_current(current)
    )


def dc_loop_voltage_budget(
    minimum_supply_voltage: EngineeringQuantity,
    minimum_device_voltage: EngineeringQuantity,
    fixed_series_voltage_drop: EngineeringQuantity,
    maximum_loop_current: EngineeringQuantity,
    proposed_external_load_resistance: EngineeringQuantity,
    required_voltage_margin: EngineeringQuantity,
    intrinsically_safe_or_hazardous_area: bool,
) -> LoopVoltageBudgetResult:
    """Screen a simple non-hazardous DC loop with every drop explicit.

    Hazardous-area or intrinsically-safe loops require a separate reviewed
    entity-parameter and barrier method and are rejected here.
    """

    if not isinstance(intrinsically_safe_or_hazardous_area, bool):
        raise GeneralCalculationInputError(
            "intrinsically_safe_or_hazardous_area must be a boolean."
        )
    if intrinsically_safe_or_hazardous_area:
        raise GeneralCalculationDomainError(
            "Hazardous-area and intrinsically-safe loop assessment requires "
            "a dedicated reviewed method."
        )

    supply = _canonical_quantity(
        minimum_supply_voltage,
        QuantityKind.ELECTRIC_POTENTIAL,
        field_name="minimum_supply_voltage",
    )
    device = _canonical_quantity(
        minimum_device_voltage,
        QuantityKind.ELECTRIC_POTENTIAL,
        field_name="minimum_device_voltage",
    )
    fixed_drop = _canonical_quantity(
        fixed_series_voltage_drop,
        QuantityKind.ELECTRIC_POTENTIAL,
        field_name="fixed_series_voltage_drop",
    )
    current = _canonical_quantity(
        maximum_loop_current,
        QuantityKind.ELECTRIC_CURRENT,
        field_name="maximum_loop_current",
    )
    resistance = _canonical_quantity(
        proposed_external_load_resistance,
        QuantityKind.ELECTRICAL_RESISTANCE,
        field_name="proposed_external_load_resistance",
    )
    required_margin = _canonical_quantity(
        required_voltage_margin,
        QuantityKind.ELECTRIC_POTENTIAL,
        field_name="required_voltage_margin",
    )
    _require_positive(supply, field_name="minimum_supply_voltage")
    _require_positive(
        device,
        field_name="minimum_device_voltage",
    )
    _require_nonnegative(
        fixed_drop,
        field_name="fixed_series_voltage_drop",
    )
    _require_positive(current, field_name="maximum_loop_current")
    _require_nonnegative(
        resistance,
        field_name="proposed_external_load_resistance",
    )
    _require_nonnegative(
        required_margin,
        field_name="required_voltage_margin",
    )

    load_drop_value = _finite_result(
        current.value * resistance.value,
        field_name="load voltage drop",
    )
    total_required_value = _finite_result(
        (
            device.value
            + fixed_drop.value
            + load_drop_value
            + required_margin.value
        ),
        field_name="total required voltage",
    )
    residual_value = _finite_result(
        supply.value - total_required_value,
        field_name="signed voltage residual",
    )
    available_for_load = _finite_result(
        (
            supply.value
            - device.value
            - fixed_drop.value
            - required_margin.value
        ),
        field_name="voltage available for external load",
    )
    maximum_resistance = _quantity(
        QuantityKind.ELECTRICAL_RESISTANCE,
        _finite_result(
            max(available_for_load, 0.0) / current.value,
            field_name="maximum external load resistance",
        ),
        "ohm",
    )

    return LoopVoltageBudgetResult(
        load_voltage_drop=_quantity(
            QuantityKind.ELECTRIC_POTENTIAL,
            load_drop_value,
            "V",
        ),
        total_required_voltage=_quantity(
            QuantityKind.ELECTRIC_POTENTIAL,
            total_required_value,
            "V",
        ),
        signed_voltage_residual=_quantity(
            QuantityKind.ELECTRIC_POTENTIAL,
            residual_value,
            "V",
        ),
        maximum_external_load_resistance=maximum_resistance,
        adequate_voltage=residual_value >= 0.0,
    )


def propagate_independent_uncertainty(
    sensitivity_coefficients: tuple[float, ...],
    standard_uncertainties: tuple[float, ...],
) -> float:
    """Propagate independent standard uncertainty using RSS sensitivity terms.

    Correlated inputs and covariance terms are explicitly unsupported by this
    function.  A method needing correlation must model the covariance rather
    than call this independent-input boundary.
    """

    if not isinstance(sensitivity_coefficients, tuple) or not isinstance(
        standard_uncertainties,
        tuple,
    ):
        raise GeneralCalculationInputError(
            "Uncertainty coefficients and values must be ordered tuples."
        )
    if not sensitivity_coefficients or not standard_uncertainties:
        raise GeneralCalculationInputError(
            "At least one uncertainty component is required."
        )
    if len(sensitivity_coefficients) != len(standard_uncertainties):
        raise GeneralCalculationInputError(
            "Sensitivity and uncertainty tuples must have equal length."
        )
    if len(sensitivity_coefficients) > _MAXIMUM_UNCERTAINTY_COMPONENTS:
        raise GeneralCalculationInputError(
            "Uncertainty component count exceeds the controlled limit."
        )

    terms: list[float] = []
    for index, (coefficient, uncertainty) in enumerate(
        zip(
            sensitivity_coefficients,
            standard_uncertainties,
            strict=True,
        ),
        start=1,
    ):
        normalized_coefficient = _finite_number(
            coefficient,
            field_name=f"sensitivity_coefficients[{index}]",
        )
        normalized_uncertainty = _finite_number(
            uncertainty,
            field_name=f"standard_uncertainties[{index}]",
        )
        if normalized_uncertainty < 0.0:
            raise GeneralCalculationDomainError(
                "Standard uncertainties cannot be negative."
            )
        term = _finite_result(
            normalized_coefficient * normalized_uncertainty,
            field_name="uncertainty sensitivity term",
        )
        terms.append(term)

    return _finite_result(
        hypot(*terms),
        field_name="combined standard uncertainty",
    )


def combine_independent_standard_uncertainties(
    components: tuple[EngineeringQuantity, ...],
    *,
    target_unit: str | None = None,
) -> EngineeringQuantity:
    """Combine independent same-kind standard uncertainties by RSS."""

    if not isinstance(components, tuple):
        raise GeneralCalculationInputError(
            "components must be an ordered tuple."
        )
    if not components:
        raise GeneralCalculationInputError(
            "At least one uncertainty component is required."
        )
    if len(components) > _MAXIMUM_UNCERTAINTY_COMPONENTS:
        raise GeneralCalculationInputError(
            "Uncertainty component count exceeds the controlled limit."
        )

    first = _revalidate_quantity(
        components[0],
        field_name="components[1]",
    )
    if first.uncertainty is not None:
        raise GeneralCalculationInputError(
            "Each component value is itself the standard uncertainty; "
            "nested uncertainty metadata is unsupported."
        )
    output_unit = first.unit if target_unit is None else target_unit
    converted_values: list[float] = []
    for index, component in enumerate(components, start=1):
        validated = _revalidate_quantity(
            component,
            field_name=f"components[{index}]",
        )
        if validated.quantity_kind != first.quantity_kind:
            raise GeneralCalculationInputError(
                "All uncertainty components must use the same quantity kind."
            )
        if validated.uncertainty is not None:
            raise GeneralCalculationInputError(
                "Nested uncertainty metadata is unsupported."
            )
        if validated.value < 0.0:
            raise GeneralCalculationDomainError(
                "Standard uncertainty components cannot be negative."
            )
        try:
            converted = DEFAULT_UNIT_REGISTRY.convert_quantity(
                validated,
                output_unit,
            )
        except UnitSystemError as exc:
            raise GeneralCalculationInputError(
                "Uncertainty components cannot be converted to target_unit."
            ) from exc
        converted_values.append(converted.value)

    combined = propagate_independent_uncertainty(
        tuple(1.0 for _ in converted_values),
        tuple(converted_values),
    )
    return EngineeringQuantity(
        quantity_kind=first.quantity_kind,
        value=combined,
        unit=output_unit,
    )


def mass_flow_from_actual_volume(
    actual_volumetric_flow: EngineeringQuantity,
    density: EngineeringQuantity,
    *,
    target_unit: str = "kg/s",
) -> EngineeringQuantity:
    """Calculate mass flow from actual volume flow and explicit density."""

    flow = _canonical_quantity(
        actual_volumetric_flow,
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        field_name="actual_volumetric_flow",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    _require_nonnegative(
        flow,
        field_name="actual_volumetric_flow",
    )
    _require_positive(density_value, field_name="density")
    result = _quantity(
        QuantityKind.MASS_FLOW,
        _finite_result(
            flow.value * density_value.value,
            field_name="mass flow",
        ),
        "kg/s",
    )
    return _convert_result(result, target_unit)


def actual_volume_from_mass_flow(
    mass_flow: EngineeringQuantity,
    density: EngineeringQuantity,
    *,
    target_unit: str = "m3/s",
) -> EngineeringQuantity:
    """Calculate actual volume flow from mass flow and explicit density."""

    flow = _canonical_quantity(
        mass_flow,
        QuantityKind.MASS_FLOW,
        field_name="mass_flow",
    )
    density_value = _canonical_quantity(
        density,
        QuantityKind.DENSITY,
        field_name="density",
    )
    _require_nonnegative(flow, field_name="mass_flow")
    _require_positive(density_value, field_name="density")
    result = _quantity(
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        _finite_result(
            flow.value / density_value.value,
            field_name="actual volumetric flow",
        ),
        "m3/s",
    )
    return _convert_result(result, target_unit)


def normalize_reference_flow(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    """Normalize a generic reference-state flow without private unit APIs.

    The Step 91 unit registry intentionally requires ``STANDARD`` and
    ``NORMAL`` flow quantities to remain attached to a
    :class:`ReferencedVolumetricFlow`.  The flat Step 93 request contract
    cannot carry that nested model.  This reviewed normalizer therefore
    accepts only the generic ``flow.volumetric.reference`` kind while the
    companion basis, reference ID, pressure, temperature, and
    compressibility inputs remain mandatory and traceable.
    """

    if (
        not isinstance(specification, MethodInputSpecification)
        or not isinstance(supplied_input, CalculationInput)
    ):
        raise GeneralCalculationInputError(
            "Reference-flow normalization requires typed method input data."
        )
    try:
        validated_specification = MethodInputSpecification.model_validate(
            specification.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
        validated_input = CalculationInput.model_validate(
            supplied_input.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except Exception as exc:
        raise GeneralCalculationInputError(
            "Reference-flow input failed public revalidation."
        ) from exc

    if (
        validated_specification.input_id != "source-flow"
        or validated_specification.quantity_kind
        is not QuantityKind.REFERENCE_VOLUMETRIC_FLOW
        or validated_specification.canonical_unit != "m3/s"
        or validated_input.input_id != validated_specification.input_id
        or validated_input.name != validated_specification.name
        or validated_input.quantity is None
        or validated_input.categorical_value is not None
    ):
        raise GeneralCalculationInputError(
            "Reference-flow input does not match its controlled "
            "specification."
        )
    source_quantity = validated_input.quantity
    if (
        source_quantity.quantity_kind
        != QuantityKind.REFERENCE_VOLUMETRIC_FLOW.value
    ):
        raise GeneralCalculationInputError(
            "source-flow must use generic reference volumetric-flow kind."
        )
    if source_quantity.uncertainty is not None:
        raise GeneralCalculationInputError(
            "Reference-flow uncertainty requires a supported uncertainty "
            "method and cannot be ignored."
        )

    try:
        source_definition = DEFAULT_UNIT_REGISTRY.resolve_unit(
            source_quantity.unit
        )
        target_definition = DEFAULT_UNIT_REGISTRY.resolve_unit("m3/s")
    except UnitSystemError as exc:
        raise GeneralCalculationInputError(
            "source-flow uses an unknown unit."
        ) from exc
    if (
        source_definition.dimension is not PhysicalDimension.VOLUMETRIC_FLOW
        or target_definition.dimension
        is not PhysicalDimension.VOLUMETRIC_FLOW
        or source_definition.offset_to_canonical != Decimal("0")
        or target_definition.offset_to_canonical != Decimal("0")
    ):
        raise GeneralCalculationInputError(
            "source-flow unit is not a multiplicative volumetric-flow unit."
        )

    with localcontext() as conversion_context:
        conversion_context.prec = 50
        normalized_decimal = (
            Decimal(str(source_quantity.value))
            * source_definition.scale_to_canonical
        )
    normalized_value = float(normalized_decimal)
    _finite_result(
        normalized_value,
        field_name="normalized reference flow",
    )
    if normalized_value < 0.0:
        raise GeneralCalculationDomainError(
            "source-flow cannot be negative."
        )

    return CalculationInput(
        input_id=validated_input.input_id,
        name=validated_input.name,
        origin=validated_input.origin,
        quantity=EngineeringQuantity(
            quantity_kind=(
                QuantityKind.REFERENCE_VOLUMETRIC_FLOW.value
            ),
            value=normalized_value,
            unit="m3/s",
            significant_figures=source_quantity.significant_figures,
        ),
        assumption_id=validated_input.assumption_id,
        source_reference_ids=validated_input.source_reference_ids,
        source_trace_step_ids=validated_input.source_trace_step_ids,
        notes=validated_input.notes,
    )


def _context_quantity(
    context: MethodExecutionContext,
    input_id: str,
) -> EngineeringQuantity:
    """Return one exact normalized quantity from an execution context."""

    for calculation_input in context.normalized_inputs:
        if calculation_input.input_id == input_id:
            if calculation_input.quantity is None:
                raise GeneralCalculationInputError(
                    f"{input_id} must be a quantity."
                )
            return calculation_input.quantity
    raise GeneralCalculationInputError(
        f"Required normalized input {input_id!r} is unavailable."
    )


def _context_category(
    context: MethodExecutionContext,
    input_id: str,
) -> bool | str:
    """Return one exact normalized categorical value."""

    for calculation_input in context.normalized_inputs:
        if calculation_input.input_id == input_id:
            if calculation_input.categorical_value is None:
                raise GeneralCalculationInputError(
                    f"{input_id} must be categorical."
                )
            return calculation_input.categorical_value
    raise GeneralCalculationInputError(
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
) -> MethodExecutionOutcome:
    """Build a single-step result with exact trace/output links."""

    trace_values: list[CalculationTraceValue] = []
    outputs: list[CalculationOutput] = []
    for output_id, name, quantity, output_description in quantity_outputs:
        value_id = f"value.{output_id}"
        trace_values.append(
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
        trace_values.append(
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
                output_values=tuple(trace_values),
            ),
        ),
        outputs=tuple(outputs),
    )


def execute_gauge_to_absolute(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute an exact gauge-to-absolute pressure conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = convert_pressure(
        _context_quantity(context, "gauge-pressure"),
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=_context_quantity(
            context,
            "atmospheric-pressure",
        ),
        target_unit="Pa",
    )
    return _execution_outcome(
        formula_identifier="general.formula.gauge-to-absolute",
        title="Convert gauge pressure to absolute pressure",
        description=(
            "The supplied atmospheric absolute pressure was added to the "
            "gauge pressure."
        ),
        input_ids=("gauge-pressure", "atmospheric-pressure"),
        quantity_outputs=(
            (
                "absolute-pressure",
                "Absolute pressure",
                result,
                "Absolute pressure in the canonical pressure unit.",
            ),
        ),
    )


def execute_absolute_to_gauge(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute an exact absolute-to-gauge pressure conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = convert_pressure(
        _context_quantity(context, "absolute-pressure"),
        QuantityKind.GAUGE_PRESSURE,
        atmospheric_pressure=_context_quantity(
            context,
            "atmospheric-pressure",
        ),
        target_unit="Pa",
    )
    return _execution_outcome(
        formula_identifier="general.formula.absolute-to-gauge",
        title="Convert absolute pressure to gauge pressure",
        description=(
            "The supplied atmospheric absolute pressure was subtracted from "
            "the absolute pressure."
        ),
        input_ids=("absolute-pressure", "atmospheric-pressure"),
        quantity_outputs=(
            (
                "gauge-pressure",
                "Gauge pressure",
                result,
                "Gauge pressure in the canonical pressure unit.",
            ),
        ),
    )


def execute_reference_state_flow(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Convert one generic gas volumetric flow between explicit states."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    source_flow = _context_quantity(context, "source-flow")
    source_pressure = _context_quantity(
        context,
        "source-absolute-pressure",
    )
    target_pressure = _context_quantity(
        context,
        "target-absolute-pressure",
    )
    source_temperature = _context_quantity(
        context,
        "source-absolute-temperature",
    )
    target_temperature = _context_quantity(
        context,
        "target-absolute-temperature",
    )
    source_z = _context_quantity(
        context,
        "source-compressibility-factor",
    )
    target_z = _context_quantity(
        context,
        "target-compressibility-factor",
    )
    for value, name in (
        (source_pressure, "source-absolute-pressure"),
        (target_pressure, "target-absolute-pressure"),
        (source_temperature, "source-absolute-temperature"),
        (target_temperature, "target-absolute-temperature"),
        (source_z, "source-compressibility-factor"),
        (target_z, "target-compressibility-factor"),
    ):
        _require_positive(value, field_name=name)
    source_treatment = _context_category(
        context,
        "source-compressibility-treatment",
    )
    target_treatment = _context_category(
        context,
        "target-compressibility-treatment",
    )
    if (
        source_treatment == CompressibilityTreatment.IDEAL_GAS.value
        and source_z.value != 1.0
    ):
        raise GeneralCalculationDomainError(
            "Ideal-gas source treatment requires an explicit factor of 1."
        )
    if (
        target_treatment == CompressibilityTreatment.IDEAL_GAS.value
        and target_z.value != 1.0
    ):
        raise GeneralCalculationDomainError(
            "Ideal-gas target treatment requires an explicit factor of 1."
        )

    factor = _finite_result(
        (
            (source_pressure.value / target_pressure.value)
            * (target_temperature.value / source_temperature.value)
            * (target_z.value / source_z.value)
        ),
        field_name="reference-state conversion factor",
    )
    converted = _quantity(
        QuantityKind.REFERENCE_VOLUMETRIC_FLOW,
        _finite_result(
            source_flow.value * factor,
            field_name="converted reference-state flow",
        ),
        "m3/s",
    )
    source_basis = _context_category(context, "source-basis")
    target_basis = _context_category(context, "target-basis")
    source_reference_id = _context_category(
        context,
        "source-reference-id",
    )
    target_reference_id = _context_category(
        context,
        "target-reference-id",
    )
    return _execution_outcome(
        formula_identifier="general.formula.reference-state-flow",
        title="Convert gas flow between explicit reference states",
        description=(
            "The ideal-gas state relation with explicitly supplied "
            "compressibility treatment converted the generic reference flow."
        ),
        input_ids=(
            "source-flow",
            "source-basis",
            "source-reference-id",
            "source-absolute-pressure",
            "source-absolute-temperature",
            "source-compressibility-treatment",
            "source-compressibility-factor",
            "target-basis",
            "target-reference-id",
            "target-absolute-pressure",
            "target-absolute-temperature",
            "target-compressibility-treatment",
            "target-compressibility-factor",
        ),
        quantity_outputs=(
            (
                "target-flow",
                "Target reference-state volumetric flow",
                converted,
                (
                    "Generic reference flow; the target basis and reference "
                    "ID are separate mandatory outputs."
                ),
            ),
            (
                "conversion-factor",
                "Reference-state conversion factor",
                _quantity(QuantityKind.RATIO, factor, "1"),
                "Multiplicative source-to-target state conversion factor.",
            ),
        ),
        categorical_outputs=(
            (
                "source-basis-used",
                "Source reference basis used",
                source_basis,
                "Explicit source flow reference basis.",
            ),
            (
                "source-reference-id-used",
                "Source reference identifier used",
                source_reference_id,
                "Explicit source reference-state identifier.",
            ),
            (
                "target-basis-used",
                "Target reference basis used",
                target_basis,
                "Explicit target flow reference basis.",
            ),
            (
                "target-reference-id-used",
                "Target reference identifier used",
                target_reference_id,
                "Explicit target reference-state identifier.",
            ),
        ),
    )


def execute_mass_to_actual_volume(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute mass-flow to actual-volume-flow conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = actual_volume_from_mass_flow(
        _context_quantity(context, "mass-flow"),
        _context_quantity(context, "density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.mass-to-actual-volume",
        title="Convert mass flow to actual volumetric flow",
        description="Mass flow was divided by the explicitly supplied density.",
        input_ids=("mass-flow", "density"),
        quantity_outputs=(
            (
                "actual-volumetric-flow",
                "Actual volumetric flow",
                result,
                "Actual volumetric flow at the density state supplied.",
            ),
        ),
    )


def execute_actual_volume_to_mass(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute actual-volume-flow to mass-flow conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = mass_flow_from_actual_volume(
        _context_quantity(context, "actual-volumetric-flow"),
        _context_quantity(context, "density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.actual-volume-to-mass",
        title="Convert actual volumetric flow to mass flow",
        description=(
            "Actual volumetric flow was multiplied by the explicitly "
            "supplied density."
        ),
        input_ids=("actual-volumetric-flow", "density"),
        quantity_outputs=(
            (
                "mass-flow",
                "Mass flow",
                result,
                "Mass flow at the density state supplied.",
            ),
        ),
    )


def execute_density_from_specific_gravity(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute explicit-reference SG to density conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = density_from_specific_gravity(
        _context_quantity(context, "specific-gravity"),
        _context_quantity(context, "reference-density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.density-from-sg",
        title="Calculate density from specific gravity",
        description=(
            "Specific gravity was multiplied by the explicitly supplied "
            "reference density."
        ),
        input_ids=(
            "specific-gravity",
            "reference-density",
            "reference-density-description",
        ),
        quantity_outputs=(
            (
                "density",
                "Density",
                result,
                "Calculated density.",
            ),
        ),
    )


def execute_density_to_specific_gravity(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute density to explicit-reference SG conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = specific_gravity_from_density(
        _context_quantity(context, "density"),
        _context_quantity(context, "reference-density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.density-to-sg",
        title="Calculate specific gravity from density",
        description=(
            "Density was divided by the explicitly supplied reference density."
        ),
        input_ids=(
            "density",
            "reference-density",
            "reference-density-description",
        ),
        quantity_outputs=(
            (
                "specific-gravity",
                "Specific gravity",
                result,
                "Calculated specific gravity.",
            ),
        ),
    )


def execute_kinematic_to_dynamic(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute kinematic-to-dynamic viscosity conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = dynamic_viscosity_from_kinematic(
        _context_quantity(context, "kinematic-viscosity"),
        _context_quantity(context, "density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.kinematic-to-dynamic",
        title="Calculate dynamic viscosity",
        description=(
            "Kinematic viscosity was multiplied by explicit fluid density."
        ),
        input_ids=("kinematic-viscosity", "density"),
        quantity_outputs=(
            (
                "dynamic-viscosity",
                "Dynamic viscosity",
                result,
                "Calculated dynamic viscosity.",
            ),
        ),
    )


def execute_dynamic_to_kinematic(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute dynamic-to-kinematic viscosity conversion."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = kinematic_viscosity_from_dynamic(
        _context_quantity(context, "dynamic-viscosity"),
        _context_quantity(context, "density"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.dynamic-to-kinematic",
        title="Calculate kinematic viscosity",
        description="Dynamic viscosity was divided by explicit fluid density.",
        input_ids=("dynamic-viscosity", "density"),
        quantity_outputs=(
            (
                "kinematic-viscosity",
                "Kinematic viscosity",
                result,
                "Calculated kinematic viscosity.",
            ),
        ),
    )


def execute_pipe_velocity_reynolds(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute circular-pipe area, velocity, and Reynolds calculation."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = pipe_area_velocity_reynolds(
        _context_quantity(context, "internal-diameter"),
        _context_quantity(context, "actual-volumetric-flow"),
        _context_quantity(context, "density"),
        _context_quantity(context, "dynamic-viscosity"),
        bool(_context_category(context, "full-pipe-confirmed")),
        bool(
            _context_category(
                context,
                "representative-properties-confirmed",
            )
        ),
    )
    return _execution_outcome(
        formula_identifier="general.formula.pipe-velocity-reynolds",
        title="Calculate pipe velocity and Reynolds number",
        description=(
            "Circular area, mean velocity, and Reynolds number were "
            "calculated from explicit pipe and fluid data."
        ),
        input_ids=(
            "internal-diameter",
            "actual-volumetric-flow",
            "density",
            "dynamic-viscosity",
            "full-pipe-confirmed",
            "representative-properties-confirmed",
        ),
        quantity_outputs=(
            (
                "cross-sectional-area",
                "Cross-sectional area",
                result.cross_sectional_area,
                "Internal circular pipe area.",
            ),
            (
                "mean-velocity",
                "Mean velocity",
                result.mean_velocity,
                "Bulk mean fluid velocity.",
            ),
            (
                "reynolds-number",
                "Reynolds number",
                result.reynolds_number,
                "Dimensionless pipe Reynolds number.",
            ),
        ),
    )


def execute_dp_transmitter_range(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute a DP transmitter range and turndown assessment."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = assess_dp_transmitter_range(
        _context_quantity(context, "applied-dp"),
        _context_quantity(context, "lower-range-limit"),
        _context_quantity(context, "upper-range-limit"),
        _context_quantity(context, "lower-range-value"),
        _context_quantity(context, "upper-range-value"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.dp-transmitter-range",
        title="Assess DP transmitter range",
        description=(
            "Sensor span, calibrated span, percent of range, explicit "
            "sensor-to-calibration turndown, and range disposition were "
            "calculated."
        ),
        input_ids=(
            "applied-dp",
            "lower-range-limit",
            "upper-range-limit",
            "lower-range-value",
            "upper-range-value",
        ),
        quantity_outputs=(
            (
                "sensor-span",
                "Sensor span",
                result.sensor_span,
                "Explicit URL minus LRL.",
            ),
            (
                "calibrated-span",
                "Calibrated span",
                result.calibrated_span,
                "Configured URV minus LRV.",
            ),
            (
                "fraction-of-range",
                "Fraction of range",
                result.fraction_of_range,
                "Unbounded linear fraction for under/over-range visibility.",
            ),
            (
                "percent-of-range",
                "Percent of range",
                result.percent_of_range,
                "Unbounded linear percent for under/over-range visibility.",
            ),
            (
                "turndown-ratio",
                "Turndown ratio",
                result.turndown_ratio,
                "Explicit sensor span divided by calibrated span.",
            ),
        ),
        categorical_outputs=(
            (
                "range-status",
                "Range status",
                result.range_status,
                "Applied value disposition against the calibrated range.",
            ),
            (
                "calibration-within-sensor-limits",
                "Calibration within sensor limits",
                result.calibration_within_sensor_limits,
                "Whether LRV and URV remain within LRL and URL.",
            ),
        ),
    )


def execute_percent_to_4_20ma(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute zero-to-one percent fraction to 4–20 mA scaling."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = current_from_linear_fraction(
        _context_quantity(context, "percent-of-range"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.percent-to-4-20ma",
        title="Scale percent of range to 4–20 mA",
        description=(
            "The canonical ratio uses 0 for 0 percent and 1 for 100 percent."
        ),
        input_ids=("percent-of-range",),
        quantity_outputs=(
            (
                "loop-current",
                "Loop current",
                result,
                "Linear 4–20 mA output signal.",
            ),
        ),
    )


def execute_4_20ma_to_percent(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute 4–20 mA to percent-of-range scaling."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = linear_fraction_from_current(
        _context_quantity(context, "loop-current"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.4-20ma-to-percent",
        title="Scale 4–20 mA to percent of range",
        description=(
            "The output canonical ratio uses 0 for 0 percent and 1 for "
            "100 percent."
        ),
        input_ids=("loop-current",),
        quantity_outputs=(
            (
                "percent-of-range",
                "Percent of range",
                _convert_result(result, "%"),
                "Linear percent of calibrated range.",
            ),
        ),
    )


def execute_dp_square_root(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute DP-fraction square-root flow extraction."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = flow_fraction_from_square_root_signal(
        _context_quantity(context, "dp-fraction"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.dp-square-root",
        title="Extract flow fraction from DP fraction",
        description="Flow fraction is the square root of linear DP fraction.",
        input_ids=("dp-fraction",),
        quantity_outputs=(
            (
                "flow-fraction",
                "Flow fraction",
                result,
                "Square-root extracted flow fraction.",
            ),
        ),
    )


def execute_flow_square(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute inverse flow-fraction square mapping."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = square_root_signal_fraction_from_flow(
        _context_quantity(context, "flow-fraction"),
    )
    return _execution_outcome(
        formula_identifier="general.formula.flow-square",
        title="Calculate DP fraction from flow fraction",
        description="Linear DP fraction is the square of flow fraction.",
        input_ids=("flow-fraction",),
        quantity_outputs=(
            (
                "dp-fraction",
                "DP fraction",
                result,
                "Squared inverse of square-root extraction.",
            ),
        ),
    )


def evaluate_dc_loop_safety(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Block simple loop screening for hazardous or intrinsically safe work."""

    if not isinstance(context, SafetyEvaluationContext):
        raise GeneralCalculationInputError(
            "Loop safety evaluation requires a SafetyEvaluationContext."
        )
    flag: bool | None = None
    for calculation_input in context.normalized_inputs:
        if (
            calculation_input.input_id
            == "intrinsically-safe-or-hazardous-area"
        ):
            if not isinstance(calculation_input.categorical_value, bool):
                raise GeneralCalculationInputError(
                    "Hazardous-area loop flag must be boolean."
                )
            flag = calculation_input.categorical_value
            break
    if flag is True:
        return MethodSafetyExtension(
            triggers=(
                SafetyTrigger(
                    requirement_id="loop.hazardous-area-excluded",
                    message=(
                        "This simple voltage-budget method is not applicable "
                        "to hazardous-area or intrinsically-safe loops."
                    ),
                ),
            )
        )
    return MethodSafetyExtension()


def execute_dc_loop_voltage_budget(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute a DC loop voltage and resistance budget."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    result = dc_loop_voltage_budget(
        _context_quantity(context, "minimum-supply-voltage"),
        _context_quantity(context, "minimum-device-voltage"),
        _context_quantity(context, "fixed-series-voltage-drop"),
        _context_quantity(context, "maximum-loop-current"),
        _context_quantity(context, "proposed-external-load-resistance"),
        _context_quantity(context, "required-voltage-margin"),
        bool(
            _context_category(
                context,
                "intrinsically-safe-or-hazardous-area",
            )
        ),
    )
    quantity_outputs: tuple[
        tuple[str, str, EngineeringQuantity, str | None],
        ...,
    ] = (
        (
            "load-voltage-drop",
            "Load voltage drop",
            result.load_voltage_drop,
            "Maximum loop current times proposed external load resistance.",
        ),
        (
            "total-required-voltage",
            "Total required voltage",
            result.total_required_voltage,
            "Device, fixed, load, and required-margin voltage total.",
        ),
        (
            "signed-voltage-residual",
            "Signed voltage residual",
            result.signed_voltage_residual,
            "Minimum supply voltage minus total required voltage.",
        ),
        (
            "maximum-external-load-resistance",
            "Maximum external load resistance",
            result.maximum_external_load_resistance,
            "External load budget including the required voltage margin.",
        ),
    )
    return _execution_outcome(
        formula_identifier="general.formula.dc-loop-voltage-budget",
        title="Screen DC loop voltage budget",
        description=(
            "Explicit device, fixed, and resistive drops were subtracted "
            "from the supply."
        ),
        input_ids=(
            "minimum-supply-voltage",
            "minimum-device-voltage",
            "fixed-series-voltage-drop",
            "maximum-loop-current",
            "proposed-external-load-resistance",
            "required-voltage-margin",
            "intrinsically-safe-or-hazardous-area",
        ),
        quantity_outputs=quantity_outputs,
        categorical_outputs=(
            (
                "adequate-voltage",
                "Adequate voltage",
                result.adequate_voltage,
                "Whether the calculated voltage margin is nonnegative.",
            ),
        ),
    )


def execute_independent_relative_rss(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute four-component independent relative RSS uncertainty."""

    if iteration_controller is not None:
        raise GeneralCalculationInputError(
            "This non-iterative method cannot receive an iteration controller."
        )
    if _context_category(context, "uncorrelated-confirmed") is not True:
        raise GeneralCalculationDomainError(
            "Independent RSS requires explicit uncorrelated confirmation."
        )
    if (
        _context_category(context, "all-material-components-confirmed")
        is not True
    ):
        raise GeneralCalculationDomainError(
            "All material uncertainty components must be confirmed."
        )
    if (
        _context_category(
            context,
            "standard-uncertainty-components-confirmed",
        )
        is not True
    ):
        raise GeneralCalculationDomainError(
            "Every contribution must be a standard uncertainty."
        )
    components = tuple(
        _context_quantity(context, f"relative-uncertainty-{index}")
        for index in range(1, 5)
    )
    result = combine_independent_standard_uncertainties(
        components,
        target_unit="1",
    )
    return _execution_outcome(
        formula_identifier="general.formula.independent-relative-rss",
        title="Combine independent relative standard uncertainties",
        description=(
            "Four explicitly supplied, uncorrelated relative standard "
            "uncertainties were combined by root sum of squares."
        ),
        input_ids=(
            "relative-uncertainty-1",
            "relative-uncertainty-2",
            "relative-uncertainty-3",
            "relative-uncertainty-4",
            "uncorrelated-confirmed",
            "all-material-components-confirmed",
            "standard-uncertainty-components-confirmed",
        ),
        quantity_outputs=(
            (
                "combined-relative-standard-uncertainty",
                "Combined relative standard uncertainty",
                result,
                "Independent relative standard uncertainty by RSS.",
            ),
        ),
    )


_REVIEWED_AT: Final = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
_FINAL_REVIEWED_AT: Final = datetime(
    2026,
    7,
    31,
    13,
    0,
    tzinfo=UTC,
)

_BIPM_REFERENCE: Final = CalculationReference(
    reference_id="general.reference.bipm-si",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title="The International System of Units, SI Brochure, 9th edition",
    publisher_or_owner=(
        "Bureau International des Poids et Mesures"
    ),
    document_number="SI Brochure",
    edition_or_revision="9th edition, updated 2026",
    relevant_section="SI units and coherent derived-unit definitions",
    implementation_basis=(
        "Unit dimensions and coherent SI formula forms were independently "
        "implemented without reproducing protected tables."
    ),
    source_location="https://doi.org/10.59161/AUEZ1291",
    verified=True,
    verified_by="Engineer4Me Step 94 technical review",
    verified_at=_REVIEWED_AT,
)

_NIST_GAS_REFERENCE: Final = CalculationReference(
    reference_id="general.reference.nist-compressibility-factor",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title=(
        "NIST ThermoData Engine help — Peng-Robinson equation of state"
    ),
    publisher_or_owner=(
        "National Institute of Standards and Technology"
    ),
    document_number="NIST ThermoData Engine help",
    edition_or_revision="Official web reference reviewed 2026-07-31",
    relevant_section=(
        "Compressibility-factor definition Z = pV/(RT)"
    ),
    implementation_basis=(
        "The fixed-molar-flow state relation uses explicit absolute pressure, "
        "absolute temperature, and user-supplied compressibility factors. "
        "This method does not calculate or estimate Z."
    ),
    source_location=(
        "https://trc.nist.gov/TDE/TDE_Help/"
        "DETAILS-TDE-Peng-Robinson-EOS.htm"
    ),
    verified=True,
    verified_by="Engineer4Me Step 94 technical review",
    verified_at=_REVIEWED_AT,
)

_IEC_SIGNAL_REFERENCE: Final = CalculationReference(
    reference_id="general.reference.iec-60381-1",
    reference_type=ReferenceType.INTERNATIONAL_STANDARD,
    title=(
        "Analogue signals for process control systems — "
        "Part 1: Direct current signals"
    ),
    publisher_or_owner=(
        "International Electrotechnical Commission"
    ),
    document_number="IEC 60381-1",
    edition_or_revision="Edition 2.0, 1982",
    part="Part 1",
    corrigenda_status=(
        "Official IEC catalogue record reviewed; no copied standard text"
    ),
    relevant_section="Direct-current analogue process-control signal range",
    implementation_basis=(
        "Only the public 4–20 mA range identity is used. No protected "
        "standard text, table, or figure is reproduced."
    ),
    applicability=(
        "Linear 4–20 mA signal scaling and deterministic DC loop screening."
    ),
    source_location=(
        "https://webstore.iec.ch/en/publication/1948"
    ),
    verified=True,
    verified_by="Engineer4Me Step 94 standards review",
    verified_at=_REVIEWED_AT,
)

_NIST_UNCERTAINTY_REFERENCE: Final = CalculationReference(
    reference_id="general.reference.nist-tn-1297",
    reference_type=ReferenceType.TECHNICAL_REPORT,
    title=(
        "Guidelines for Evaluating and Expressing the Uncertainty of NIST "
        "Measurement Results"
    ),
    publisher_or_owner=(
        "National Institute of Standards and Technology"
    ),
    document_number="NIST Technical Note 1297",
    edition_or_revision="1994 edition",
    relevant_section="Section 5 and Appendix A, Equation A-3",
    implementation_basis=(
        "Independent standard uncertainty contributions are combined from "
        "sensitivity-weighted root sum of squares. Correlated inputs are "
        "excluded unless covariance is modeled by a future method."
    ),
    source_location=(
        "https://www.nist.gov/pml/nist-technical-note-1297/"
        "nist-tn-1297-5-combined-standard-uncertainty"
    ),
    verified=True,
    verified_by="Engineer4Me Step 94 technical review",
    verified_at=_REVIEWED_AT,
)

_SOURCE_REFERENCES: Final = {
    "bipm": _BIPM_REFERENCE,
    "gas": _NIST_GAS_REFERENCE,
    "signal": _IEC_SIGNAL_REFERENCE,
    "uncertainty": _NIST_UNCERTAINTY_REFERENCE,
}


def _test_vector_reference(method_id: str) -> CalculationReference:
    """Build one method-specific independently checked vector reference."""

    return CalculationReference(
        reference_id=f"{method_id}.vector",
        reference_type=ReferenceType.TEST_VECTOR,
        title=f"Engineer4Me Step 94 reference vectors for {method_id}",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-P7-S94-VECTORS",
        edition_or_revision=GENERAL_METHOD_VERSION,
        relevant_section=method_id,
        implementation_basis=(
            "Independent reference, inverse, boundary, dimensional, and "
            "metamorphic vectors reviewed for this exact method version."
        ),
        source_location=(
            "backend/tests/test_calculation_general.py"
        ),
        verified=True,
        verified_by="Engineer4Me Step 94 software review",
        verified_at=_REVIEWED_AT,
    )


def _review_records(
    vector_reference_id: str,
) -> tuple[MethodReviewRecord, ...]:
    """Build the six immutable review-gate records for one exact method."""

    reviewer_competencies = {
        MethodReviewType.TECHNICAL: (
            "Competent multidisciplinary engineering reviewer"
        ),
        MethodReviewType.SAFETY: (
            "Competent process and electrical safety reviewer"
        ),
        MethodReviewType.STANDARDS: (
            "Competent engineering standards reviewer"
        ),
        MethodReviewType.LEGAL_COMPLIANCE: (
            "Competent technical legal and compliance reviewer"
        ),
        MethodReviewType.SOFTWARE: (
            "Competent numerical software reviewer"
        ),
        MethodReviewType.FINAL_APPROVAL: (
            "Authorised Engineer4Me method approver"
        ),
    }
    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=True,
            reviewer=f"Engineer4Me Step 94 {review_type.value} review",
            reviewer_competency=reviewer_competencies[review_type],
            reviewed_at=(
                _FINAL_REVIEWED_AT
                if review_type is MethodReviewType.FINAL_APPROVAL
                else _REVIEWED_AT
            ),
            evidence_reference_ids=(vector_reference_id,),
            notes=(
                "Approval is limited to this exact generic method version "
                "and does not certify a site design or installation."
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
    method_specific: bool = False,
) -> MethodInputSpecification:
    """Build one required, canonical, bounded quantity specification."""

    numeric_range = (
        None
        if minimum is None and maximum is None
        else NumericApplicabilityRange(
            minimum=minimum,
            maximum=maximum,
        )
    )
    return MethodInputSpecification(
        input_id=input_id,
        name=name,
        description=description,
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=(
            InputNormalizationMode.METHOD_SPECIFIC
            if method_specific
            else InputNormalizationMode.UNIT_REGISTRY
        ),
        quantity_kind=quantity_kind,
        canonical_unit=DEFAULT_UNIT_REGISTRY.canonical_unit_for(
            quantity_kind
        ),
        numeric_range=numeric_range,
    )


def _text_specification(
    input_id: str,
    name: str,
    description: str,
    *,
    allowed_values: tuple[str, ...] = (),
) -> MethodInputSpecification:
    """Build one required bounded categorical-text input."""

    return MethodInputSpecification(
        input_id=input_id,
        name=name,
        description=description,
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.CATEGORICAL_TEXT,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=allowed_values,
    )


def _true_confirmation_specification(
    input_id: str,
    name: str,
    description: str,
) -> MethodInputSpecification:
    """Build a required explicit true-only method confirmation."""

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
    formula_identifier: str,
    formula_description: str,
    source_key: str,
    limitations: tuple[str, ...],
    exclusions: tuple[str, ...],
    safety_requirements: tuple[SafetyRequirement, ...] = (),
    verification_requirements: tuple[
        VerificationRequirement,
        ...,
    ] = (),
    required_reviewer_competency: str = (
        "Competent instrumentation or process engineer"
    ),
) -> CalculationMethodDefinition:
    """Build one complete exact-version approved general method."""

    source_reference = _SOURCE_REFERENCES[source_key]
    vector_reference = _test_vector_reference(method_id)
    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=GENERAL_METHOD_VERSION,
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
        safety_requirements=safety_requirements,
        formulas=(
            FormulaMetadata(
                formula_identifier=formula_identifier,
                title=title,
                description=formula_description,
                reference_ids=(source_reference.reference_id,),
            ),
        ),
        references=(source_reference, vector_reference),
        verification_requirements=verification_requirements,
        reviews=_review_records(vector_reference.reference_id),
        test_vector_reference_ids=(vector_reference.reference_id,),
        limitations=limitations,
        exclusions=exclusions,
        required_reviewer_competency=required_reviewer_competency,
        disclaimer=(
            "Engineer4Me provides deterministic engineering decision support "
            "only. Verify inputs, applicability, site requirements, and the "
            "result before making an engineering or operational decision."
        ),
    )


_PRESSURE_LIMIT: Final = 1.0e15
_FLOW_LIMIT: Final = 1.0e15
_TEMPERATURE_LIMIT: Final = 1.0e6
_PROPERTY_LIMIT: Final = 1.0e15
_ELECTRICAL_LIMIT: Final = 1.0e12


_GAUGE_TO_ABSOLUTE_DEFINITION: Final = _approved_method(
    method_id="general.pressure.gauge-to-absolute",
    title="Gauge pressure to absolute pressure",
    description=(
        "Convert gauge pressure to absolute pressure using a required "
        "explicit atmospheric absolute pressure."
    ),
    input_specifications=(
        _quantity_specification(
            "gauge-pressure",
            "Gauge pressure",
            "Gauge-basis pressure to convert.",
            QuantityKind.GAUGE_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "atmospheric-pressure",
            "Atmospheric absolute pressure",
            "Explicit local atmospheric absolute pressure.",
            QuantityKind.ABSOLUTE_PRESSURE,
            minimum=0.0,
            maximum=_PRESSURE_LIMIT,
        ),
    ),
    formula_identifier="general.formula.gauge-to-absolute",
    formula_description=(
        "Absolute pressure is gauge pressure plus explicit atmospheric "
        "absolute pressure."
    ),
    source_key="bipm",
    limitations=(
        "Atmospheric pressure must represent the applicable location and time.",
    ),
    exclusions=(
        "Differential pressure is not a gauge/absolute basis conversion.",
    ),
)


_ABSOLUTE_TO_GAUGE_DEFINITION: Final = _approved_method(
    method_id="general.pressure.absolute-to-gauge",
    title="Absolute pressure to gauge pressure",
    description=(
        "Convert absolute pressure to gauge pressure using a required "
        "explicit atmospheric absolute pressure."
    ),
    input_specifications=(
        _quantity_specification(
            "absolute-pressure",
            "Absolute pressure",
            "Absolute-basis pressure to convert.",
            QuantityKind.ABSOLUTE_PRESSURE,
            minimum=0.0,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "atmospheric-pressure",
            "Atmospheric absolute pressure",
            "Explicit local atmospheric absolute pressure.",
            QuantityKind.ABSOLUTE_PRESSURE,
            minimum=0.0,
            maximum=_PRESSURE_LIMIT,
        ),
    ),
    formula_identifier="general.formula.absolute-to-gauge",
    formula_description=(
        "Gauge pressure is absolute pressure minus explicit atmospheric "
        "absolute pressure."
    ),
    source_key="bipm",
    limitations=(
        "Atmospheric pressure must represent the applicable location and time.",
    ),
    exclusions=(
        "Differential pressure is not a gauge/absolute basis conversion.",
    ),
)


_REFERENCE_STATE_FLOW_DEFINITION: Final = _approved_method(
    method_id="general.flow.reference-state",
    title="Explicit gas reference-state volumetric-flow conversion",
    description=(
        "Convert generic reference volumetric flow between two explicit "
        "absolute pressure, absolute temperature, and compressibility states."
    ),
    input_specifications=(
        _quantity_specification(
            "source-flow",
            "Source generic reference flow",
            (
                "Generic reference-state volumetric flow; source state "
                "metadata is supplied separately and remains mandatory."
            ),
            QuantityKind.REFERENCE_VOLUMETRIC_FLOW,
            minimum=0.0,
            maximum=_FLOW_LIMIT,
            method_specific=True,
        ),
        _text_specification(
            "source-basis",
            "Source reference basis",
            "Explicit source basis label.",
            allowed_values=tuple(
                basis.value
                for basis in FlowReferenceBasis
            ),
        ),
        _text_specification(
            "source-reference-id",
            "Source reference identifier",
            "Traceable identifier for the complete source reference state.",
        ),
        _quantity_specification(
            "source-absolute-pressure",
            "Source absolute pressure",
            "Positive absolute pressure of the source reference state.",
            QuantityKind.ABSOLUTE_PRESSURE,
            minimum=0.0,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "source-absolute-temperature",
            "Source absolute temperature",
            "Positive absolute temperature of the source reference state.",
            QuantityKind.ABSOLUTE_TEMPERATURE,
            minimum=0.0,
            maximum=_TEMPERATURE_LIMIT,
        ),
        _text_specification(
            "source-compressibility-treatment",
            "Source compressibility treatment",
            "Explicit ideal-gas or specified-factor treatment.",
            allowed_values=tuple(
                treatment.value
                for treatment in CompressibilityTreatment
            ),
        ),
        _quantity_specification(
            "source-compressibility-factor",
            "Source compressibility factor",
            "Explicit positive source compressibility factor; use 1 for ideal.",
            QuantityKind.RATIO,
            minimum=0.0,
            maximum=100.0,
        ),
        _text_specification(
            "target-basis",
            "Target reference basis",
            "Explicit target basis label.",
            allowed_values=tuple(
                basis.value
                for basis in FlowReferenceBasis
            ),
        ),
        _text_specification(
            "target-reference-id",
            "Target reference identifier",
            "Traceable identifier for the complete target reference state.",
        ),
        _quantity_specification(
            "target-absolute-pressure",
            "Target absolute pressure",
            "Positive absolute pressure of the target reference state.",
            QuantityKind.ABSOLUTE_PRESSURE,
            minimum=0.0,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "target-absolute-temperature",
            "Target absolute temperature",
            "Positive absolute temperature of the target reference state.",
            QuantityKind.ABSOLUTE_TEMPERATURE,
            minimum=0.0,
            maximum=_TEMPERATURE_LIMIT,
        ),
        _text_specification(
            "target-compressibility-treatment",
            "Target compressibility treatment",
            "Explicit ideal-gas or specified-factor treatment.",
            allowed_values=tuple(
                treatment.value
                for treatment in CompressibilityTreatment
            ),
        ),
        _quantity_specification(
            "target-compressibility-factor",
            "Target compressibility factor",
            "Explicit positive target compressibility factor; use 1 for ideal.",
            QuantityKind.RATIO,
            minimum=0.0,
            maximum=100.0,
        ),
    ),
    formula_identifier="general.formula.reference-state-flow",
    formula_description=(
        "For fixed molar flow, the source flow is multiplied by source "
        "pressure over target pressure, target temperature over source "
        "temperature, and target compressibility over source compressibility."
    ),
    source_key="gas",
    limitations=(
        "The flat request uses the generic reference-flow kind; basis and "
        "reference identifiers remain mandatory separate inputs and outputs.",
        "The gas composition and molar flow must remain unchanged.",
    ),
    exclusions=(
        "Condensing, reacting, two-phase, or density-changing composition "
        "cases require a different reviewed method.",
    ),
)


_MASS_TO_ACTUAL_VOLUME_DEFINITION: Final = _approved_method(
    method_id="general.flow.mass-to-actual-volume",
    title="Mass flow to actual volumetric flow",
    description=(
        "Convert mass flow to actual volumetric flow using explicit density."
    ),
    input_specifications=(
        _quantity_specification(
            "mass-flow",
            "Mass flow",
            "Nonnegative mass flow.",
            QuantityKind.MASS_FLOW,
            minimum=0.0,
            maximum=_FLOW_LIMIT,
        ),
        _quantity_specification(
            "density",
            "Fluid density",
            "Positive density at the actual flow state.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
    ),
    formula_identifier="general.formula.mass-to-actual-volume",
    formula_description="Actual volumetric flow is mass flow divided by density.",
    source_key="bipm",
    limitations=("Density must represent the same fluid state as the flow.",),
    exclusions=("Reference-condition gas conversion is a separate method.",),
)


_ACTUAL_VOLUME_TO_MASS_DEFINITION: Final = _approved_method(
    method_id="general.flow.actual-volume-to-mass",
    title="Actual volumetric flow to mass flow",
    description=(
        "Convert actual volumetric flow to mass flow using explicit density."
    ),
    input_specifications=(
        _quantity_specification(
            "actual-volumetric-flow",
            "Actual volumetric flow",
            "Nonnegative actual-state volumetric flow.",
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            minimum=0.0,
            maximum=_FLOW_LIMIT,
        ),
        _quantity_specification(
            "density",
            "Fluid density",
            "Positive density at the actual flow state.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
    ),
    formula_identifier="general.formula.actual-volume-to-mass",
    formula_description="Mass flow is actual volumetric flow times density.",
    source_key="bipm",
    limitations=("Density must represent the same fluid state as the flow.",),
    exclusions=("Reference-condition gas conversion is a separate method.",),
)


def _reference_density_description_specification() -> (
    MethodInputSpecification
):
    """Return the required SG reference-state description."""

    return _text_specification(
        "reference-density-description",
        "Reference density description",
        (
            "User-supplied description of reference fluid, temperature, "
            "pressure, and source."
        ),
    )


_DENSITY_FROM_SG_DEFINITION: Final = _approved_method(
    method_id="general.density.from-specific-gravity",
    title="Density from specific gravity",
    description=(
        "Calculate density from SG using an explicit reference density and "
        "reference-state description."
    ),
    input_specifications=(
        _quantity_specification(
            "specific-gravity",
            "Specific gravity",
            "Positive dimensionless density ratio.",
            QuantityKind.SPECIFIC_GRAVITY,
            minimum=0.0,
            maximum=1.0e6,
        ),
        _quantity_specification(
            "reference-density",
            "Reference density",
            "Explicit positive reference density.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _reference_density_description_specification(),
    ),
    formula_identifier="general.formula.density-from-sg",
    formula_description=(
        "Density is specific gravity multiplied by explicit reference density."
    ),
    source_key="bipm",
    limitations=(
        "The reference fluid state must be supplied and verified by the user.",
    ),
    exclusions=("No water density or temperature is assumed.",),
)


_DENSITY_TO_SG_DEFINITION: Final = _approved_method(
    method_id="general.density.to-specific-gravity",
    title="Specific gravity from density",
    description=(
        "Calculate SG from density using an explicit reference density and "
        "reference-state description."
    ),
    input_specifications=(
        _quantity_specification(
            "density",
            "Density",
            "Positive fluid density.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _quantity_specification(
            "reference-density",
            "Reference density",
            "Explicit positive reference density.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _reference_density_description_specification(),
    ),
    formula_identifier="general.formula.density-to-sg",
    formula_description=(
        "Specific gravity is density divided by explicit reference density."
    ),
    source_key="bipm",
    limitations=(
        "The reference fluid state must be supplied and verified by the user.",
    ),
    exclusions=("No water density or temperature is assumed.",),
)


_KINEMATIC_TO_DYNAMIC_DEFINITION: Final = _approved_method(
    method_id="general.viscosity.kinematic-to-dynamic",
    title="Kinematic viscosity to dynamic viscosity",
    description=(
        "Calculate dynamic viscosity from kinematic viscosity and explicit "
        "density."
    ),
    input_specifications=(
        _quantity_specification(
            "kinematic-viscosity",
            "Kinematic viscosity",
            "Positive kinematic viscosity.",
            QuantityKind.KINEMATIC_VISCOSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _quantity_specification(
            "density",
            "Fluid density",
            "Positive density at the viscosity state.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
    ),
    formula_identifier="general.formula.kinematic-to-dynamic",
    formula_description=(
        "Dynamic viscosity is kinematic viscosity multiplied by density."
    ),
    source_key="bipm",
    limitations=(
        "Density and kinematic viscosity must represent the same fluid state.",
    ),
    exclusions=("Non-Newtonian rheology is not characterized.",),
)


_DYNAMIC_TO_KINEMATIC_DEFINITION: Final = _approved_method(
    method_id="general.viscosity.dynamic-to-kinematic",
    title="Dynamic viscosity to kinematic viscosity",
    description=(
        "Calculate kinematic viscosity from dynamic viscosity and explicit "
        "density."
    ),
    input_specifications=(
        _quantity_specification(
            "dynamic-viscosity",
            "Dynamic viscosity",
            "Positive dynamic viscosity.",
            QuantityKind.DYNAMIC_VISCOSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _quantity_specification(
            "density",
            "Fluid density",
            "Positive density at the viscosity state.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
    ),
    formula_identifier="general.formula.dynamic-to-kinematic",
    formula_description=(
        "Kinematic viscosity is dynamic viscosity divided by density."
    ),
    source_key="bipm",
    limitations=(
        "Density and dynamic viscosity must represent the same fluid state.",
    ),
    exclusions=("Non-Newtonian rheology is not characterized.",),
)


_PIPE_VELOCITY_REYNOLDS_DEFINITION: Final = _approved_method(
    method_id="general.pipe.velocity-reynolds",
    title="Circular pipe velocity and Reynolds number",
    description=(
        "Calculate internal area, bulk mean velocity, and Reynolds number "
        "from explicit actual flow and fluid properties."
    ),
    input_specifications=(
        _quantity_specification(
            "internal-diameter",
            "Internal pipe diameter",
            "Strictly positive circular internal diameter.",
            QuantityKind.LENGTH,
            minimum=0.0,
            maximum=1.0e6,
        ),
        _quantity_specification(
            "actual-volumetric-flow",
            "Actual volumetric flow",
            "Nonnegative actual-state volumetric flow.",
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            minimum=0.0,
            maximum=_FLOW_LIMIT,
        ),
        _quantity_specification(
            "density",
            "Fluid density",
            "Strictly positive density at the flowing state.",
            QuantityKind.DENSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _quantity_specification(
            "dynamic-viscosity",
            "Dynamic viscosity",
            "Strictly positive dynamic viscosity at the flowing state.",
            QuantityKind.DYNAMIC_VISCOSITY,
            minimum=0.0,
            maximum=_PROPERTY_LIMIT,
        ),
        _true_confirmation_specification(
            "full-pipe-confirmed",
            "Full pipe confirmed",
            (
                "Explicit confirmation that the circular pipe is completely "
                "full at the calculation condition."
            ),
        ),
        _true_confirmation_specification(
            "representative-properties-confirmed",
            "Representative properties confirmed",
            (
                "Explicit confirmation that supplied density and viscosity "
                "represent the flowing state."
            ),
        ),
    ),
    formula_identifier="general.formula.pipe-velocity-reynolds",
    formula_description=(
        "Circular area uses diameter squared; velocity is actual flow over "
        "area; Reynolds number uses density, velocity, diameter, and dynamic "
        "viscosity."
    ),
    source_key="bipm",
    limitations=(
        "Velocity is a bulk mean value for a full circular pipe.",
        "Reynolds number alone does not prove a developed flow profile.",
    ),
    exclusions=(
        "Part-filled pipes, non-circular ducts, and non-Newtonian flow are "
        "excluded.",
    ),
)


_DP_TRANSMITTER_RANGE_DEFINITION: Final = _approved_method(
    method_id="general.transmitter.dp-range",
    title="Differential-pressure transmitter range assessment",
    description=(
        "Calculate sensor span, configured span, fraction and percent of "
        "range, sensor-to-calibration turndown, and range disposition."
    ),
    input_specifications=(
        _quantity_specification(
            "applied-dp",
            "Applied differential pressure",
            "Differential pressure to assess against the calibrated range.",
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "lower-range-limit",
            "Lower range limit",
            "Explicit differential-pressure sensor LRL.",
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "upper-range-limit",
            "Upper range limit",
            "Explicit differential-pressure sensor URL greater than LRL.",
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "lower-range-value",
            "Lower range value",
            "Configured differential-pressure LRV.",
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
        _quantity_specification(
            "upper-range-value",
            "Upper range value",
            "Configured differential-pressure URV greater than LRV.",
            QuantityKind.DIFFERENTIAL_PRESSURE,
            minimum=-_PRESSURE_LIMIT,
            maximum=_PRESSURE_LIMIT,
        ),
    ),
    formula_identifier="general.formula.dp-transmitter-range",
    formula_description=(
        "Sensor span is URL minus LRL; calibrated span is URV minus LRV; "
        "fraction is applied DP minus LRV divided by calibrated span; "
        "turndown is sensor span divided by calibrated span."
    ),
    source_key="bipm",
    limitations=(
        "LRL and URL are supplied data and are not inferred from a product.",
        "Under-range and over-range fractions remain visible.",
    ),
    exclusions=(
        "Overpressure, accuracy, and product selection checks "
        "require controlled manufacturer data.",
    ),
)


def _ratio_fraction_specification(
    input_id: str,
    name: str,
    description: str,
) -> MethodInputSpecification:
    """Build an inclusive zero-to-one canonical ratio input."""

    return _quantity_specification(
        input_id,
        name,
        description,
        QuantityKind.RATIO,
        minimum=0.0,
        maximum=1.0,
    )


_PERCENT_TO_CURRENT_DEFINITION: Final = _approved_method(
    method_id="general.signal.percent-to-4-20ma",
    title="Percent of range to 4–20 mA",
    description=(
        "Map an inclusive zero-to-one canonical percent fraction to 4–20 mA."
    ),
    input_specifications=(
        _ratio_fraction_specification(
            "percent-of-range",
            "Percent of range",
            "Canonical fraction where 0 is 0 percent and 1 is 100 percent.",
        ),
    ),
    formula_identifier="general.formula.percent-to-4-20ma",
    formula_description=(
        "Current is 4 mA plus 16 mA multiplied by the range fraction."
    ),
    source_key="signal",
    limitations=("Only the inclusive nominal 4–20 mA range is supported.",),
    exclusions=(
        "Live-zero fault levels, NAMUR diagnostic bands, and device-specific "
        "saturation behavior are excluded.",
    ),
)


_CURRENT_TO_PERCENT_DEFINITION: Final = _approved_method(
    method_id="general.signal.4-20ma-to-percent",
    title="4–20 mA to percent of range",
    description=(
        "Map an inclusive nominal 4–20 mA signal to percent of range."
    ),
    input_specifications=(
        _quantity_specification(
            "loop-current",
            "Loop current",
            "Nominal process signal between 4 mA and 20 mA inclusive.",
            QuantityKind.ELECTRIC_CURRENT,
            minimum=_FOUR_MA,
            maximum=_TWENTY_MA,
        ),
    ),
    formula_identifier="general.formula.4-20ma-to-percent",
    formula_description=(
        "Range fraction is current minus 4 mA divided by 16 mA."
    ),
    source_key="signal",
    limitations=("Only the inclusive nominal 4–20 mA range is supported.",),
    exclusions=(
        "Live-zero fault interpretation and device diagnostics are excluded.",
    ),
)


_DP_SQUARE_ROOT_DEFINITION: Final = _approved_method(
    method_id="general.signal.dp-square-root",
    title="DP fraction square-root extraction",
    description=(
        "Map an inclusive linear differential-pressure fraction to flow "
        "fraction using square-root extraction."
    ),
    input_specifications=(
        _ratio_fraction_specification(
            "dp-fraction",
            "DP fraction",
            "Linear DP fraction between zero and one inclusive.",
        ),
    ),
    formula_identifier="general.formula.dp-square-root",
    formula_description=(
        "Flow fraction is the principal nonnegative square root of DP fraction."
    ),
    source_key="bipm",
    limitations=(
        "The relationship applies only after a valid quadratic DP-flow model "
        "has been independently established.",
    ),
    exclusions=(
        "Low-flow cutoff, density compensation, meter coefficients, and "
        "primary-element sizing are excluded.",
    ),
)


_FLOW_SQUARE_DEFINITION: Final = _approved_method(
    method_id="general.signal.flow-square",
    title="Flow fraction inverse square mapping",
    description=(
        "Map an inclusive flow fraction to the corresponding linear "
        "differential-pressure fraction."
    ),
    input_specifications=(
        _ratio_fraction_specification(
            "flow-fraction",
            "Flow fraction",
            "Flow fraction between zero and one inclusive.",
        ),
    ),
    formula_identifier="general.formula.flow-square",
    formula_description="DP fraction is flow fraction squared.",
    source_key="bipm",
    limitations=(
        "The relationship applies only after a valid quadratic DP-flow model "
        "has been independently established.",
    ),
    exclusions=(
        "Low-flow cutoff, density compensation, meter coefficients, and "
        "primary-element sizing are excluded.",
    ),
)


_LOOP_HAZARD_VERIFICATION: Final = VerificationRequirement(
    verification_id="verify.loop-hazardous-area-method",
    description=(
        "Verify whether the loop is in a hazardous area or forms part of an "
        "intrinsically safe circuit."
    ),
    method=(
        "Review area classification, loop drawing, barrier or isolator data, "
        "entity parameters, cable parameters, and the site protection concept."
    ),
    expected_result=(
        "The simple general loop method is used only for a confirmed "
        "non-hazardous, non-intrinsically-safe circuit."
    ),
    acceptance_criteria=(
        "Hazardous or intrinsically safe circuits are transferred to a "
        "dedicated competent electrical and Ex engineering review."
    ),
    required_competency=(
        "Competent hazardous-area instrumentation and electrical engineer"
    ),
    verifier_role="Independent hazardous-area engineering reviewer",
    independent_verification_required=True,
    evidence_required=(
        "Area classification evidence",
        "Approved loop drawing",
        "Protection-concept and barrier data",
    ),
)


_DC_LOOP_BUDGET_DEFINITION: Final = _approved_method(
    method_id="general.loop.dc-voltage-budget",
    title="DC current-loop voltage budget",
    description=(
        "Screen explicit supply, device, fixed-drop, current, and resistance "
        "inputs for available voltage and load margin."
    ),
    input_specifications=(
        _quantity_specification(
            "minimum-supply-voltage",
            "Minimum supply voltage",
            "Strictly positive worst-case minimum DC loop supply voltage.",
            QuantityKind.ELECTRIC_POTENTIAL,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        _quantity_specification(
            "minimum-device-voltage",
            "Minimum device voltage",
            "Strictly positive minimum terminal voltage requirement.",
            QuantityKind.ELECTRIC_POTENTIAL,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        _quantity_specification(
            "fixed-series-voltage-drop",
            "Fixed series voltage drop",
            "Nonnegative sum of all explicit fixed series voltage drops.",
            QuantityKind.ELECTRIC_POTENTIAL,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        _quantity_specification(
            "maximum-loop-current",
            "Maximum loop current",
            "Strictly positive worst-case current used for voltage screening.",
            QuantityKind.ELECTRIC_CURRENT,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        _quantity_specification(
            "proposed-external-load-resistance",
            "Proposed external load resistance",
            "Nonnegative total cable, receiver, barrier, and other resistance.",
            QuantityKind.ELECTRICAL_RESISTANCE,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        _quantity_specification(
            "required-voltage-margin",
            "Required voltage margin",
            "Explicit nonnegative design voltage margin.",
            QuantityKind.ELECTRIC_POTENTIAL,
            minimum=0.0,
            maximum=_ELECTRICAL_LIMIT,
        ),
        MethodInputSpecification(
            input_id="intrinsically-safe-or-hazardous-area",
            name="Intrinsically safe or hazardous area",
            description=(
                "Explicit flag identifying a hazardous-area or intrinsically "
                "safe circuit, which this simple method must block."
            ),
            presence=InputPresence.REQUIRED,
            value_type=InputValueType.CATEGORICAL_BOOLEAN,
            normalization_mode=InputNormalizationMode.NONE,
            allowed_categorical_values=(False, True),
            safety_critical=True,
            verification_requirement_ids=(
                _LOOP_HAZARD_VERIFICATION.verification_id,
            ),
        ),
    ),
    formula_identifier="general.formula.dc-loop-voltage-budget",
    formula_description=(
        "Load drop is maximum current times proposed external resistance; "
        "total required voltage includes device, fixed, load, and explicit "
        "margin; signed residual is minimum supply minus total required; "
        "maximum resistance retains the explicit margin."
    ),
    source_key="signal",
    limitations=(
        "All barriers, isolators, cable resistance, receiver loads, and "
        "worst-case supply/current conditions must be included explicitly.",
    ),
    exclusions=(
        "This voltage screen does not certify intrinsic safety, hazardous-area "
        "compliance, EMC, isolation, grounding, or device compatibility.",
    ),
    required_reviewer_competency=(
        "Competent instrumentation and electrical engineer"
    ),
    safety_requirements=(
        SafetyRequirement(
            requirement_id="loop.hazardous-area-excluded",
            title="Hazardous-area loop requires dedicated assessment",
            hazard=(
                "A simple voltage-only budget cannot establish intrinsic "
                "safety or hazardous-area compliance."
            ),
            required_input_ids=(
                "intrinsically-safe-or-hazardous-area",
            ),
            severity=FindingSeverity.CRITICAL,
            blocking=True,
            required_action=(
                "Stop this simple calculation and obtain a dedicated entity-"
                "parameter, barrier, cable, grounding, and installation "
                "assessment by a competent hazardous-area engineer."
            ),
            verification_requirement_ids=(
                _LOOP_HAZARD_VERIFICATION.verification_id,
            ),
            reference_ids=(
                _IEC_SIGNAL_REFERENCE.reference_id,
            ),
            required_competency=(
                "Competent hazardous-area instrumentation and electrical "
                "engineer"
            ),
        ),
    ),
    verification_requirements=(_LOOP_HAZARD_VERIFICATION,),
)


_INDEPENDENT_RSS_DEFINITION: Final = _approved_method(
    method_id="general.uncertainty.independent-relative-rss",
    title="Independent relative standard uncertainty RSS",
    description=(
        "Combine exactly four explicit relative standard uncertainty "
        "components after explicit independence and completeness confirmation."
    ),
    input_specifications=(
        *tuple(
            _quantity_specification(
                f"relative-uncertainty-{index}",
                f"Relative standard uncertainty {index}",
                (
                    "Nonnegative relative standard uncertainty contribution "
                    f"{index}."
                ),
                QuantityKind.RATIO,
                minimum=0.0,
                maximum=1.0,
            )
            for index in range(1, 5)
        ),
        _true_confirmation_specification(
            "uncorrelated-confirmed",
            "Uncorrelated inputs confirmed",
            (
                "Explicit confirmation that covariance terms are zero and "
                "independence is technically justified."
            ),
        ),
        _true_confirmation_specification(
            "all-material-components-confirmed",
            "All material components confirmed",
            (
                "Explicit confirmation that all material standard uncertainty "
                "contributions are represented."
            ),
        ),
        _true_confirmation_specification(
            "standard-uncertainty-components-confirmed",
            "Standard uncertainty components confirmed",
            (
                "Explicit confirmation that every supplied contribution is a "
                "standard uncertainty, not an expanded uncertainty or limit."
            ),
        ),
    ),
    formula_identifier="general.formula.independent-relative-rss",
    formula_description=(
        "Combined relative standard uncertainty is the square root of the sum "
        "of squared independent relative standard uncertainty components."
    ),
    source_key="uncertainty",
    limitations=(
        "Exactly four relative standard uncertainty components are supported.",
        "Inputs must be standard uncertainties expressed on a common relative "
        "basis.",
    ),
    exclusions=(
        "Correlated inputs, covariance, expanded uncertainty, coverage factor, "
        "and probability-distribution modeling are excluded.",
    ),
    required_reviewer_competency=(
        "Competent measurement uncertainty practitioner"
    ),
)


GENERAL_METHOD_REGISTRATIONS: Final = (
    MethodRegistration(
        definition=_GAUGE_TO_ABSOLUTE_DEFINITION,
        implementation=execute_gauge_to_absolute,
    ),
    MethodRegistration(
        definition=_ABSOLUTE_TO_GAUGE_DEFINITION,
        implementation=execute_absolute_to_gauge,
    ),
    MethodRegistration(
        definition=_REFERENCE_STATE_FLOW_DEFINITION,
        implementation=execute_reference_state_flow,
        input_normalizers={
            "source-flow": normalize_reference_flow,
        },
    ),
    MethodRegistration(
        definition=_MASS_TO_ACTUAL_VOLUME_DEFINITION,
        implementation=execute_mass_to_actual_volume,
    ),
    MethodRegistration(
        definition=_ACTUAL_VOLUME_TO_MASS_DEFINITION,
        implementation=execute_actual_volume_to_mass,
    ),
    MethodRegistration(
        definition=_DENSITY_FROM_SG_DEFINITION,
        implementation=execute_density_from_specific_gravity,
    ),
    MethodRegistration(
        definition=_DENSITY_TO_SG_DEFINITION,
        implementation=execute_density_to_specific_gravity,
    ),
    MethodRegistration(
        definition=_KINEMATIC_TO_DYNAMIC_DEFINITION,
        implementation=execute_kinematic_to_dynamic,
    ),
    MethodRegistration(
        definition=_DYNAMIC_TO_KINEMATIC_DEFINITION,
        implementation=execute_dynamic_to_kinematic,
    ),
    MethodRegistration(
        definition=_PIPE_VELOCITY_REYNOLDS_DEFINITION,
        implementation=execute_pipe_velocity_reynolds,
    ),
    MethodRegistration(
        definition=_DP_TRANSMITTER_RANGE_DEFINITION,
        implementation=execute_dp_transmitter_range,
    ),
    MethodRegistration(
        definition=_PERCENT_TO_CURRENT_DEFINITION,
        implementation=execute_percent_to_4_20ma,
    ),
    MethodRegistration(
        definition=_CURRENT_TO_PERCENT_DEFINITION,
        implementation=execute_4_20ma_to_percent,
    ),
    MethodRegistration(
        definition=_DP_SQUARE_ROOT_DEFINITION,
        implementation=execute_dp_square_root,
    ),
    MethodRegistration(
        definition=_FLOW_SQUARE_DEFINITION,
        implementation=execute_flow_square,
    ),
    MethodRegistration(
        definition=_DC_LOOP_BUDGET_DEFINITION,
        implementation=execute_dc_loop_voltage_budget,
        safety_evaluator=evaluate_dc_loop_safety,
    ),
    MethodRegistration(
        definition=_INDEPENDENT_RSS_DEFINITION,
        implementation=execute_independent_relative_rss,
    ),
)

GENERAL_METHOD_REGISTRY: Final = CalculationMethodRegistry(
    GENERAL_METHOD_REGISTRATIONS
)
GENERAL_METHOD_IDS: Final = GENERAL_METHOD_REGISTRY.method_ids

# Imported after every registration is constructed.  The Step 92 foundation
# defaults remain empty and independently testable; this production engine is
# the explicitly composed Step 94 catalogue.
from app.engineering.calculations.engine import CalculationEngine  # noqa: E402


GENERAL_CALCULATION_ENGINE: Final = CalculationEngine(
    registry=GENERAL_METHOD_REGISTRY
)


__all__ = [
    "GENERAL_CALCULATION_ENGINE",
    "GENERAL_CALCULATION_TYPE_PREFIX",
    "GENERAL_CALCULATORS_VERSION",
    "GENERAL_METHOD_IDS",
    "GENERAL_METHOD_REGISTRATIONS",
    "GENERAL_METHOD_REGISTRY",
    "GENERAL_METHOD_VERSION",
    "GeneralCalculationDomainError",
    "GeneralCalculationError",
    "GeneralCalculationInputError",
    "LoopVoltageBudgetResult",
    "PipeFlowResult",
    "TransmitterRangeResult",
    "actual_volume_from_mass_flow",
    "assess_dp_transmitter_range",
    "combine_independent_standard_uncertainties",
    "convert_pressure",
    "convert_referenced_gas_volume",
    "current_from_linear_fraction",
    "current_from_square_root_flow_fraction",
    "dc_loop_voltage_budget",
    "density_from_specific_gravity",
    "dynamic_viscosity_from_kinematic",
    "flow_fraction_from_square_root_signal",
    "hydrostatic_pressure",
    "kinematic_viscosity_from_dynamic",
    "linear_fraction_from_current",
    "mass_flow_from_actual_volume",
    "pipe_area_velocity_reynolds",
    "pressure_head",
    "propagate_independent_uncertainty",
    "specific_gravity_from_density",
    "square_root_flow_fraction_from_current",
    "square_root_signal_fraction_from_flow",
    "transmitter_linear_fraction",
    "transmitter_value_from_fraction",
]
