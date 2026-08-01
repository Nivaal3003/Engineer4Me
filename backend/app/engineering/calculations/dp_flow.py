"""Fail-closed differential-pressure flow calculations for Phase 7 Steps 97-98.

The executable kernel is deliberately generic.  It evaluates the differential-
pressure restriction equation only when the caller supplies traceable flowing
properties, discharge coefficient, and expansibility factor.  It does not
derive ISO 5167 coefficients and makes no standards-conformity claim.

Step 98 adds generic supplied-coefficient nozzle, Venturi, and averaging-Pitot
adapters plus transmitter-range, supplied pressure-loss, and supported
uncertainty screening. Protected correlations remain absent.
"""

from __future__ import annotations

from math import hypot, isfinite, pi, sqrt
from types import MappingProxyType
from typing import Final, Literal

from pydantic import Field, field_validator, model_validator

from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import MethodLifecycleStatus


DP_FLOW_CALCULATORS_VERSION: Final = "1.1.1"
DP_FLOW_METHOD_VERSION: Final = "1.0.0"
GENERIC_ORIFICE_METHOD_ID: Final = "flow.dp.generic-orifice.supplied-coefficients"
ISO_5167_2_ADAPTER_ID: Final = "flow.dp.iso-5167-2.orifice-adapter"
ISO_5167_3_ADAPTER_ID: Final = "flow.dp.iso-5167-3.nozzle-adapter"
ISO_5167_4_ADAPTER_ID: Final = "flow.dp.iso-5167-4.venturi-adapter"
GENERIC_NOZZLE_METHOD_ID: Final = "flow.dp.generic-nozzle.supplied-coefficients"
GENERIC_NOZZLE_METHOD_VERSION: Final = "1.0.0"
GENERIC_VENTURI_NOZZLE_METHOD_ID: Final = "flow.dp.generic-venturi-nozzle.supplied-coefficients"
GENERIC_VENTURI_NOZZLE_METHOD_VERSION: Final = "1.0.0"
GENERIC_VENTURI_TUBE_METHOD_ID: Final = "flow.dp.generic-venturi-tube.supplied-coefficients"
GENERIC_VENTURI_TUBE_METHOD_VERSION: Final = "1.0.0"
GENERIC_AVERAGING_PITOT_METHOD_ID: Final = "flow.dp.generic-averaging-pitot.supplied-coefficient"
GENERIC_AVERAGING_PITOT_METHOD_VERSION: Final = "1.0.0"
DP_TRANSMITTER_RANGE_METHOD_ID: Final = "flow.dp.transmitter-range.screen"
DP_TRANSMITTER_RANGE_METHOD_VERSION: Final = "1.0.0"
PERMANENT_PRESSURE_LOSS_METHOD_ID: Final = "flow.dp.permanent-pressure-loss.supplied-ratio"
PERMANENT_PRESSURE_LOSS_METHOD_VERSION: Final = "1.0.0"
DP_FLOW_UNCERTAINTY_METHOD_ID: Final = "flow.dp.relative-uncertainty.independent-rss"
DP_FLOW_UNCERTAINTY_METHOD_VERSION: Final = "1.0.0"
MAX_SOLVER_ITERATIONS: Final = 128


class DPFlowCalculationError(ValueError):
    """Base error for the Steps 97-98 DP-flow boundary."""


class DPFlowInputError(DPFlowCalculationError):
    """Raised for incomplete, untraceable, or physically invalid input."""


class DPFlowConvergenceError(DPFlowCalculationError):
    """Raised when a bounded bore solver cannot establish a result."""


def _finite_number(value: object, *, field_name: str) -> float:
    """Return one finite real scalar while rejecting booleans and coercion."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DPFlowInputError(f"{field_name} must be a finite real number")
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise DPFlowInputError(f"{field_name} must be a finite real number") from error
    if not isfinite(normalized):
        raise DPFlowInputError(f"{field_name} must be a finite real number")
    return normalized


def _nonblank(value: str, *, field_name: str) -> str:
    """Reject traceability text containing only whitespace."""

    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    return value


class TraceableCoefficient(CalculationModel):
    """Dimensionless coefficient with mandatory caller traceability."""

    value: float
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=3, max_length=1000)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator("value", mode="before")
    @classmethod
    def validate_raw_value(cls, value: object) -> float:
        return _finite_number(value, field_name="coefficient value")

    @field_validator("source_reference", "applicable_conditions", "supplied_by")
    @classmethod
    def validate_traceability_text(cls, value: str) -> str:
        return _nonblank(value, field_name="coefficient traceability text")

    @model_validator(mode="after")
    def validate_value(self) -> "TraceableCoefficient":
        if not isfinite(self.value) or self.value <= 0.0:
            raise ValueError("coefficient value must be finite and positive")
        return self


class FlowingFluidProperties(CalculationModel):
    """Fluid properties at one explicit flowing condition."""

    density_kg_m3: float
    dynamic_viscosity_pa_s: float
    pressure_absolute_pa: float
    temperature_k: float
    phase: Literal["liquid", "gas", "vapour"]
    property_source_reference: str = Field(min_length=3, max_length=500)
    condition_basis: str = Field(min_length=3, max_length=1000)

    @field_validator(
        "density_kg_m3",
        "dynamic_viscosity_pa_s",
        "pressure_absolute_pa",
        "temperature_k",
        mode="before",
    )
    @classmethod
    def validate_raw_properties(cls, value: object) -> float:
        return _finite_number(value, field_name="flowing property")

    @field_validator("property_source_reference", "condition_basis")
    @classmethod
    def validate_property_traceability_text(cls, value: str) -> str:
        return _nonblank(value, field_name="fluid-property traceability text")

    @model_validator(mode="after")
    def validate_properties(self) -> "FlowingFluidProperties":
        positive = (
            self.density_kg_m3,
            self.dynamic_viscosity_pa_s,
            self.pressure_absolute_pa,
            self.temperature_k,
        )
        if any(not isfinite(value) or value <= 0.0 for value in positive):
            raise ValueError("all flowing properties and conditions must be finite and positive")
        return self


class FlowReferenceConditions(CalculationModel):
    """Optional explicit reference state; never confused with flowing volume."""

    pressure_absolute_pa: float
    temperature_k: float
    compressibility_factor: float
    reference_name: str = Field(min_length=2, max_length=200)
    source_reference: str = Field(min_length=3, max_length=500)

    @field_validator(
        "pressure_absolute_pa",
        "temperature_k",
        "compressibility_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_reference_values(cls, value: object) -> float:
        return _finite_number(value, field_name="reference-condition value")

    @field_validator("reference_name", "source_reference")
    @classmethod
    def validate_reference_text(cls, value: str) -> str:
        return _nonblank(value, field_name="reference-condition traceability text")

    @model_validator(mode="after")
    def validate_reference(self) -> "FlowReferenceConditions":
        values = (self.pressure_absolute_pa, self.temperature_k, self.compressibility_factor)
        if any(not isfinite(value) or value <= 0.0 for value in values):
            raise ValueError("reference pressure, temperature, and compressibility must be positive")
        return self


class DPFlowApplicability(CalculationModel):
    """Explicit applicability result for the generic restriction kernel."""

    applicable: bool
    beta_ratio: float | None
    blocking_reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False


class OrificeFlowResult(CalculationModel):
    """Calculated mass/actual-volume flow and diagnostic state."""

    mass_flow_kg_s: float
    actual_volumetric_flow_m3_s: float
    beta_ratio: float
    velocity_m_s: float
    pipe_reynolds_number: float
    discharge_coefficient_used: float
    expansibility_factor_used: float
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False
    calculation_basis: str = "caller-supplied traceable coefficients"


class BoreSolverResult(CalculationModel):
    """Bounded bisection outcome for a target mass flow."""

    bore_diameter_m: float
    achieved_mass_flow_kg_s: float
    relative_error: float
    iterations: int
    converged: bool
    lower_bound_m: float
    upper_bound_m: float
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False


class StandardsAdapterMetadata(CalculationModel):
    """Discoverable but inert standards-adapter lifecycle record."""

    adapter_id: str
    title: str
    standard_family: str
    lifecycle_status: Literal[MethodLifecycleStatus.STANDARDS_REVIEW]
    executable: Literal[False]
    conformity_claimed: Literal[False]
    boundary: str


class DPFlowMethodAdapterMetadata(CalculationModel):
    """Exact-version registration for one reviewed generic direct method."""

    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    title: str = Field(min_length=3, max_length=240)
    lifecycle_status: Literal[MethodLifecycleStatus.APPROVED]
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    executable: Literal[True]
    coefficient_policy: str = Field(min_length=10, max_length=1000)
    standards_conformity_claimed: Literal[False] = False


class CircularRestrictionFlowResult(CalculationModel):
    """Generic circular-throat DP result with supplied coefficients."""

    primary_element: Literal["flow_nozzle", "venturi_nozzle", "venturi_tube"]
    mass_flow_kg_s: float
    actual_volumetric_flow_m3_s: float
    beta_ratio: float
    velocity_m_s: float
    pipe_reynolds_number: float
    discharge_coefficient_used: float
    expansibility_factor_used: float
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False
    calculation_basis: str = "caller-supplied traceable coefficients"


class AveragingPitotFlowResult(CalculationModel):
    """Generic averaging-Pitot result using a traceable meter coefficient."""

    mass_flow_kg_s: float
    actual_volumetric_flow_m3_s: float
    pipe_area_m2: float
    mean_velocity_m_s: float
    pipe_reynolds_number: float
    meter_coefficient_used: float
    expansibility_factor_used: float
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False
    calculation_basis: str = "caller-supplied traceable meter coefficient"


class DPTransmitterRangeScreenResult(CalculationModel):
    """Minimum/normal/maximum DP and low-signal range screen."""

    minimum_dp_pa: float
    normal_dp_pa: float
    maximum_dp_pa: float
    configured_lrv_pa: float
    configured_urv_pa: float
    sensor_lrl_pa: float
    sensor_url_pa: float
    configured_span_pa: float
    minimum_required_dp_fraction_of_span: float
    configured_range_within_sensor_limits: bool
    operating_cases_within_configured_range: bool
    minimum_dp_fraction_of_span: float
    minimum_flow_fraction_of_span: float
    inferred_flow_turndown: float | None
    low_flow_signal_adequate: bool
    screen_passed: bool
    blocking_reasons: tuple[str, ...]


class PermanentPressureLossResult(CalculationModel):
    """Permanent pressure loss from a supplied traceable loss ratio."""

    measured_differential_pressure_pa: float
    permanent_pressure_loss_pa: float
    permanent_loss_ratio_used: float
    source_reference: str
    applicable_conditions: str
    supplied_by: str
    standards_conformity_claimed: Literal[False] = False


class RelativeUncertaintyComponent(CalculationModel):
    """One independent relative standard-uncertainty contributor."""

    component_id: str = Field(min_length=2, max_length=120)
    relative_standard_uncertainty_percent: float = Field(ge=0.0, le=100.0)
    sensitivity_coefficient: float
    source_reference: str = Field(min_length=3, max_length=500)

    @field_validator(
        "relative_standard_uncertainty_percent",
        "sensitivity_coefficient",
        mode="before",
    )
    @classmethod
    def validate_raw_numeric_values(cls, value: object) -> float:
        return _finite_number(value, field_name="uncertainty component value")

    @field_validator("component_id", mode="before")
    @classmethod
    def validate_component_id(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        validated = _nonblank(value, field_name="uncertainty component identifier")
        if value != value.strip():
            raise ValueError("uncertainty component identifier cannot have surrounding whitespace")
        return validated

    @field_validator("source_reference")
    @classmethod
    def validate_component_source(cls, value: str) -> str:
        return _nonblank(value, field_name="uncertainty component source reference")

    @model_validator(mode="after")
    def validate_finite_component(self) -> "RelativeUncertaintyComponent":
        if not isfinite(self.relative_standard_uncertainty_percent) or not isfinite(self.sensitivity_coefficient):
            raise ValueError("uncertainty values must be finite")
        return self


class DPFlowUncertaintyResult(CalculationModel):
    """RSS combined and expanded relative uncertainty."""

    combined_relative_standard_uncertainty_percent: float
    coverage_factor: float
    expanded_relative_uncertainty_percent: float
    component_count: int
    components: tuple[RelativeUncertaintyComponent, ...]
    independence_assumed: Literal[True] = True
    standards_conformity_claimed: Literal[False] = False


ISO_5167_2_ADAPTER: Final = StandardsAdapterMetadata(
    adapter_id=ISO_5167_2_ADAPTER_ID,
    title="ISO 5167-2 orifice-plate coefficient adapter",
    standard_family="ISO 5167-2",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary=(
        "Metadata discovery only. No ISO coefficient correlation, tapping rule, "
        "installation rule, uncertainty claim, or conformity assessment is executable."
    ),
)

ISO_5167_3_ADAPTER: Final = StandardsAdapterMetadata(
    adapter_id=ISO_5167_3_ADAPTER_ID,
    title="ISO 5167-3 nozzle and Venturi-nozzle coefficient adapter",
    standard_family="ISO 5167-3",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary=(
        "Metadata discovery only. No protected nozzle correlation, geometry "
        "limit, installation rule, uncertainty claim, or conformity assessment is executable."
    ),
)

ISO_5167_4_ADAPTER: Final = StandardsAdapterMetadata(
    adapter_id=ISO_5167_4_ADAPTER_ID,
    title="ISO 5167-4 Venturi-tube coefficient adapter",
    standard_family="ISO 5167-4",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary=(
        "Metadata discovery only. No protected Venturi correlation, fabrication "
        "rule, calibration rule, uncertainty claim, or conformity assessment is executable."
    ),
)


def assess_generic_orifice_applicability(
    *,
    pipe_inside_diameter_m: float,
    bore_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> DPFlowApplicability:
    """Validate only the mathematical/traceability domain of the generic kernel."""

    reasons: list[str] = []
    warnings: list[str] = []
    scalars: dict[str, object] = {
        "pipe inside diameter": pipe_inside_diameter_m,
        "bore diameter": bore_diameter_m,
        "differential pressure": differential_pressure_pa,
    }
    normalized_scalars: dict[str, float] = {}
    for name, value in scalars.items():
        try:
            normalized = _finite_number(value, field_name=name)
        except DPFlowInputError:
            reasons.append(f"{name} must be a finite real number")
            continue
        normalized_scalars[name] = normalized
        if normalized <= 0.0:
            reasons.append(f"{name} must be finite and positive")
    if not isinstance(fluid, FlowingFluidProperties):
        reasons.append("fluid must be validated flowing-fluid properties")
    if not isinstance(discharge_coefficient, TraceableCoefficient):
        reasons.append("discharge coefficient must include validated traceability")
    if not isinstance(expansibility_factor, TraceableCoefficient):
        reasons.append("expansibility factor must include validated traceability")
    beta = None
    if (
        len(normalized_scalars) == len(scalars)
        and normalized_scalars["pipe inside diameter"] > 0.0
        and normalized_scalars["bore diameter"] > 0.0
        and normalized_scalars["differential pressure"] > 0.0
    ):
        beta = (
            normalized_scalars["bore diameter"]
            / normalized_scalars["pipe inside diameter"]
        )
        if not 0.0 < beta < 1.0:
            reasons.append("bore diameter must be smaller than pipe inside diameter")
    if isinstance(expansibility_factor, TraceableCoefficient) and expansibility_factor.value > 1.0:
        reasons.append("expansibility factor cannot exceed 1.0")
    if isinstance(discharge_coefficient, TraceableCoefficient) and discharge_coefficient.value > 2.0:
        warnings.append("supplied discharge coefficient is unusually high and requires review")
    warnings.append("This generic supplied-coefficient kernel does not establish standards conformity")
    return DPFlowApplicability(
        applicable=not reasons,
        beta_ratio=beta,
        blocking_reasons=tuple(reasons),
        warnings=tuple(warnings),
    )


def calculate_generic_orifice_flow(
    *,
    pipe_inside_diameter_m: float,
    bore_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> OrificeFlowResult:
    """Evaluate the generic restriction equation with supplied coefficients."""

    applicability = assess_generic_orifice_applicability(
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        bore_diameter_m=bore_diameter_m,
        differential_pressure_pa=differential_pressure_pa,
        fluid=fluid,
        discharge_coefficient=discharge_coefficient,
        expansibility_factor=expansibility_factor,
    )
    if not applicability.applicable or applicability.beta_ratio is None:
        raise DPFlowInputError("; ".join(applicability.blocking_reasons))
    pipe_inside_diameter_m = float(pipe_inside_diameter_m)
    bore_diameter_m = float(bore_diameter_m)
    differential_pressure_pa = float(differential_pressure_pa)
    beta = applicability.beta_ratio
    area = pi * bore_diameter_m * bore_diameter_m / 4.0
    denominator = sqrt(1.0 - beta**4)
    mass_flow = (
        discharge_coefficient.value
        * expansibility_factor.value
        * area
        * sqrt(2.0 * differential_pressure_pa * fluid.density_kg_m3)
        / denominator
    )
    actual_volume = mass_flow / fluid.density_kg_m3
    pipe_area = pi * pipe_inside_diameter_m**2 / 4.0
    velocity = actual_volume / pipe_area
    reynolds = (
        fluid.density_kg_m3
        * velocity
        * pipe_inside_diameter_m
        / fluid.dynamic_viscosity_pa_s
    )
    outputs = (mass_flow, actual_volume, velocity, reynolds)
    if any(not isfinite(value) or value <= 0.0 for value in outputs):
        raise DPFlowInputError("calculation produced a non-finite or non-positive result")
    return OrificeFlowResult(
        mass_flow_kg_s=mass_flow,
        actual_volumetric_flow_m3_s=actual_volume,
        beta_ratio=beta,
        velocity_m_s=velocity,
        pipe_reynolds_number=reynolds,
        discharge_coefficient_used=discharge_coefficient.value,
        expansibility_factor_used=expansibility_factor.value,
        warnings=applicability.warnings,
    )


def calculate_generic_circular_restriction_flow(
    *,
    primary_element: Literal["flow_nozzle", "venturi_nozzle", "venturi_tube"],
    pipe_inside_diameter_m: float,
    throat_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> CircularRestrictionFlowResult:
    """Evaluate a generic circular-throat element with supplied coefficients.

    The equation is a generic continuity/DP kernel. The caller remains
    responsible for the coefficient, geometry, tap, and applicability basis.
    """

    allowed_elements = {"flow_nozzle", "venturi_nozzle", "venturi_tube"}
    if not isinstance(primary_element, str) or primary_element not in allowed_elements:
        raise DPFlowInputError("primary element is not supported by the circular-throat kernel")

    base = calculate_generic_orifice_flow(
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        bore_diameter_m=throat_diameter_m,
        differential_pressure_pa=differential_pressure_pa,
        fluid=fluid,
        discharge_coefficient=discharge_coefficient,
        expansibility_factor=expansibility_factor,
    )
    return CircularRestrictionFlowResult(
        primary_element=primary_element,
        mass_flow_kg_s=base.mass_flow_kg_s,
        actual_volumetric_flow_m3_s=base.actual_volumetric_flow_m3_s,
        beta_ratio=base.beta_ratio,
        velocity_m_s=base.velocity_m_s,
        pipe_reynolds_number=base.pipe_reynolds_number,
        discharge_coefficient_used=base.discharge_coefficient_used,
        expansibility_factor_used=base.expansibility_factor_used,
        warnings=base.warnings,
    )


def calculate_generic_nozzle_flow(
    *,
    pipe_inside_diameter_m: float,
    throat_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> CircularRestrictionFlowResult:
    """Calculate a generic nozzle using caller-supplied traceable coefficients."""

    return calculate_generic_circular_restriction_flow(
        primary_element="flow_nozzle",
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        throat_diameter_m=throat_diameter_m,
        differential_pressure_pa=differential_pressure_pa,
        fluid=fluid,
        discharge_coefficient=discharge_coefficient,
        expansibility_factor=expansibility_factor,
    )


def calculate_generic_venturi_nozzle_flow(
    *,
    pipe_inside_diameter_m: float,
    throat_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> CircularRestrictionFlowResult:
    """Calculate a generic Venturi nozzle with supplied coefficients."""

    return calculate_generic_circular_restriction_flow(
        primary_element="venturi_nozzle",
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        throat_diameter_m=throat_diameter_m,
        differential_pressure_pa=differential_pressure_pa,
        fluid=fluid,
        discharge_coefficient=discharge_coefficient,
        expansibility_factor=expansibility_factor,
    )


def calculate_generic_venturi_tube_flow(
    *,
    pipe_inside_diameter_m: float,
    throat_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> CircularRestrictionFlowResult:
    """Calculate a generic Venturi tube with supplied coefficients."""

    return calculate_generic_circular_restriction_flow(
        primary_element="venturi_tube",
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        throat_diameter_m=throat_diameter_m,
        differential_pressure_pa=differential_pressure_pa,
        fluid=fluid,
        discharge_coefficient=discharge_coefficient,
        expansibility_factor=expansibility_factor,
    )


def calculate_generic_averaging_pitot_flow(
    *,
    pipe_inside_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    meter_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
) -> AveragingPitotFlowResult:
    """Calculate flow using a supplied dimensionless velocity coefficient."""

    pipe_inside_diameter_m = _finite_number(
        pipe_inside_diameter_m,
        field_name="pipe inside diameter",
    )
    differential_pressure_pa = _finite_number(
        differential_pressure_pa,
        field_name="differential pressure",
    )
    if pipe_inside_diameter_m <= 0.0 or differential_pressure_pa <= 0.0:
        raise DPFlowInputError("pipe diameter and differential pressure must be finite and positive")
    if not isinstance(fluid, FlowingFluidProperties):
        raise DPFlowInputError("fluid must be validated flowing-fluid properties")
    if not isinstance(meter_coefficient, TraceableCoefficient):
        raise DPFlowInputError("meter coefficient must include validated traceability")
    if not isinstance(expansibility_factor, TraceableCoefficient):
        raise DPFlowInputError("expansibility factor must include validated traceability")
    if expansibility_factor.value > 1.0:
        raise DPFlowInputError("expansibility factor cannot exceed 1.0")
    pipe_area = pi * pipe_inside_diameter_m * pipe_inside_diameter_m / 4.0
    actual_volume = (
        meter_coefficient.value
        * expansibility_factor.value
        * pipe_area
        * sqrt(2.0 * differential_pressure_pa / fluid.density_kg_m3)
    )
    mass_flow = actual_volume * fluid.density_kg_m3
    mean_velocity = actual_volume / pipe_area
    reynolds = (
        fluid.density_kg_m3
        * mean_velocity
        * pipe_inside_diameter_m
        / fluid.dynamic_viscosity_pa_s
    )
    if any(not isfinite(value) or value <= 0.0 for value in (pipe_area, actual_volume, mass_flow, mean_velocity, reynolds)):
        raise DPFlowInputError("averaging-Pitot calculation produced an invalid result")
    return AveragingPitotFlowResult(
        mass_flow_kg_s=mass_flow,
        actual_volumetric_flow_m3_s=actual_volume,
        pipe_area_m2=pipe_area,
        mean_velocity_m_s=mean_velocity,
        pipe_reynolds_number=reynolds,
        meter_coefficient_used=meter_coefficient.value,
        expansibility_factor_used=expansibility_factor.value,
        warnings=(
            "This generic supplied-coefficient method does not establish standards conformity",
        ),
    )


def screen_dp_transmitter_range(
    *,
    minimum_dp_pa: float,
    normal_dp_pa: float,
    maximum_dp_pa: float,
    configured_lrv_pa: float,
    configured_urv_pa: float,
    sensor_lrl_pa: float,
    sensor_url_pa: float,
    minimum_required_dp_fraction_of_span: float,
) -> DPTransmitterRangeScreenResult:
    """Screen DP cases, sensor limits, inferred turndown, and low signal."""

    minimum_dp_pa = _finite_number(minimum_dp_pa, field_name="minimum DP")
    normal_dp_pa = _finite_number(normal_dp_pa, field_name="normal DP")
    maximum_dp_pa = _finite_number(maximum_dp_pa, field_name="maximum DP")
    configured_lrv_pa = _finite_number(configured_lrv_pa, field_name="configured LRV")
    configured_urv_pa = _finite_number(configured_urv_pa, field_name="configured URV")
    sensor_lrl_pa = _finite_number(sensor_lrl_pa, field_name="sensor LRL")
    sensor_url_pa = _finite_number(sensor_url_pa, field_name="sensor URL")
    minimum_required_dp_fraction_of_span = _finite_number(
        minimum_required_dp_fraction_of_span,
        field_name="minimum required DP fraction of span",
    )
    if not 0.0 <= minimum_dp_pa <= normal_dp_pa <= maximum_dp_pa:
        raise DPFlowInputError("DP cases must satisfy 0 <= minimum <= normal <= maximum")
    if maximum_dp_pa <= 0.0:
        raise DPFlowInputError("maximum DP must be positive for a DP-flow range screen")
    if not sensor_lrl_pa < sensor_url_pa or not configured_lrv_pa < configured_urv_pa:
        raise DPFlowInputError("sensor and configured ranges must have positive span")
    if configured_lrv_pa != 0.0:
        raise DPFlowInputError(
            "configured LRV must be zero for supported unidirectional square-root DP-flow inference"
        )
    if not 0.0 <= minimum_required_dp_fraction_of_span <= 1.0:
        raise DPFlowInputError("minimum required DP fraction must be from zero through one")
    configured_span = _finite_number(
        configured_urv_pa - configured_lrv_pa,
        field_name="configured span",
    )
    minimum_fraction = _finite_number(
        (minimum_dp_pa - configured_lrv_pa) / configured_span,
        field_name="minimum DP fraction of span",
    )
    nonnegative_fraction = max(0.0, minimum_fraction)
    flow_fraction = _finite_number(
        sqrt(nonnegative_fraction),
        field_name="minimum flow fraction of span",
    )
    if minimum_dp_pa == 0.0:
        turndown = None
    else:
        turndown_ratio_squared = _finite_number(
            maximum_dp_pa / minimum_dp_pa,
            field_name="squared inferred flow turndown",
        )
        turndown = sqrt(turndown_ratio_squared)
    configured_within_sensor = (
        sensor_lrl_pa <= configured_lrv_pa < configured_urv_pa <= sensor_url_pa
    )
    cases_within_configured = (
        configured_lrv_pa
        <= minimum_dp_pa
        <= normal_dp_pa
        <= maximum_dp_pa
        <= configured_urv_pa
    )
    low_signal_adequate = minimum_fraction >= minimum_required_dp_fraction_of_span
    blocking_reasons: list[str] = []
    if not configured_within_sensor:
        blocking_reasons.append("configured range is outside the supplied sensor limits")
    if not cases_within_configured:
        blocking_reasons.append("one or more operating DP cases are outside the configured range")
    if not low_signal_adequate:
        blocking_reasons.append("minimum DP signal is below the supplied fraction-of-span requirement")
    return DPTransmitterRangeScreenResult(
        minimum_dp_pa=minimum_dp_pa,
        normal_dp_pa=normal_dp_pa,
        maximum_dp_pa=maximum_dp_pa,
        configured_lrv_pa=configured_lrv_pa,
        configured_urv_pa=configured_urv_pa,
        sensor_lrl_pa=sensor_lrl_pa,
        sensor_url_pa=sensor_url_pa,
        configured_span_pa=configured_span,
        minimum_required_dp_fraction_of_span=minimum_required_dp_fraction_of_span,
        configured_range_within_sensor_limits=configured_within_sensor,
        operating_cases_within_configured_range=cases_within_configured,
        minimum_dp_fraction_of_span=minimum_fraction,
        minimum_flow_fraction_of_span=flow_fraction,
        inferred_flow_turndown=turndown,
        low_flow_signal_adequate=low_signal_adequate,
        screen_passed=not blocking_reasons,
        blocking_reasons=tuple(blocking_reasons),
    )


def calculate_permanent_pressure_loss(
    *,
    measured_differential_pressure_pa: float,
    permanent_loss_ratio: TraceableCoefficient,
) -> PermanentPressureLossResult:
    """Apply a supplied traceable permanent-loss/DP ratio."""

    measured_differential_pressure_pa = _finite_number(
        measured_differential_pressure_pa,
        field_name="measured differential pressure",
    )
    if measured_differential_pressure_pa < 0.0:
        raise DPFlowInputError("measured differential pressure must be finite and nonnegative")
    if not isinstance(permanent_loss_ratio, TraceableCoefficient):
        raise DPFlowInputError("permanent loss ratio must include validated traceability")
    if permanent_loss_ratio.value > 1.0:
        raise DPFlowInputError("permanent loss ratio cannot exceed 1.0")
    loss = _finite_number(
        measured_differential_pressure_pa * permanent_loss_ratio.value,
        field_name="permanent pressure loss",
    )
    return PermanentPressureLossResult(
        measured_differential_pressure_pa=measured_differential_pressure_pa,
        permanent_pressure_loss_pa=loss,
        permanent_loss_ratio_used=permanent_loss_ratio.value,
        source_reference=permanent_loss_ratio.source_reference,
        applicable_conditions=permanent_loss_ratio.applicable_conditions,
        supplied_by=permanent_loss_ratio.supplied_by,
    )


def combine_dp_flow_relative_uncertainty(
    *,
    components: tuple[RelativeUncertaintyComponent, ...],
    coverage_factor: float = 2.0,
) -> DPFlowUncertaintyResult:
    """Combine independent relative standard uncertainties by RSS."""

    if not isinstance(components, tuple):
        raise DPFlowInputError("uncertainty components must be an ordered tuple")
    if not components or len(components) > 64:
        raise DPFlowInputError("one through 64 uncertainty components are required")
    if any(not isinstance(component, RelativeUncertaintyComponent) for component in components):
        raise DPFlowInputError("every uncertainty component must use the validated component model")
    ids = tuple(component.component_id.casefold() for component in components)
    if len(ids) != len(set(ids)):
        raise DPFlowInputError("uncertainty component identifiers must be unique")
    coverage_factor = _finite_number(coverage_factor, field_name="coverage factor")
    if not 1.0 <= coverage_factor <= 5.0:
        raise DPFlowInputError("coverage factor must be finite from one through five")
    terms = tuple(
        component.sensitivity_coefficient
        * component.relative_standard_uncertainty_percent
        for component in components
    )
    combined = _finite_number(
        hypot(*terms),
        field_name="combined relative standard uncertainty",
    )
    expanded = _finite_number(
        combined * coverage_factor,
        field_name="expanded relative uncertainty",
    )
    return DPFlowUncertaintyResult(
        combined_relative_standard_uncertainty_percent=combined,
        coverage_factor=coverage_factor,
        expanded_relative_uncertainty_percent=expanded,
        component_count=len(components),
        components=components,
    )


def solve_orifice_bore_for_mass_flow(
    *,
    target_mass_flow_kg_s: float,
    pipe_inside_diameter_m: float,
    differential_pressure_pa: float,
    fluid: FlowingFluidProperties,
    discharge_coefficient: TraceableCoefficient,
    expansibility_factor: TraceableCoefficient,
    minimum_bore_diameter_m: float,
    maximum_bore_diameter_m: float,
    relative_tolerance: float = 1.0e-9,
    maximum_iterations: int = 96,
) -> BoreSolverResult:
    """Solve bore by deterministic bounded bisection; never extrapolate bounds."""

    target_mass_flow_kg_s = _finite_number(
        target_mass_flow_kg_s,
        field_name="target mass flow",
    )
    pipe_inside_diameter_m = _finite_number(
        pipe_inside_diameter_m,
        field_name="pipe inside diameter",
    )
    differential_pressure_pa = _finite_number(
        differential_pressure_pa,
        field_name="differential pressure",
    )
    minimum_bore_diameter_m = _finite_number(
        minimum_bore_diameter_m,
        field_name="minimum bore diameter",
    )
    maximum_bore_diameter_m = _finite_number(
        maximum_bore_diameter_m,
        field_name="maximum bore diameter",
    )
    relative_tolerance = _finite_number(
        relative_tolerance,
        field_name="relative tolerance",
    )
    if target_mass_flow_kg_s <= 0.0:
        raise DPFlowInputError("target mass flow must be finite and positive")
    if differential_pressure_pa <= 0.0:
        raise DPFlowInputError("differential pressure must be finite and positive")
    if not 0.0 < relative_tolerance < 1.0:
        raise DPFlowInputError("relative tolerance must be between zero and one")
    if not isinstance(maximum_iterations, int) or isinstance(maximum_iterations, bool):
        raise DPFlowInputError("maximum iterations must be an integer")
    if not 1 <= maximum_iterations <= MAX_SOLVER_ITERATIONS:
        raise DPFlowInputError(f"maximum iterations must be from 1 through {MAX_SOLVER_ITERATIONS}")
    if not (0.0 < minimum_bore_diameter_m < maximum_bore_diameter_m < pipe_inside_diameter_m):
        raise DPFlowInputError("solver bounds must satisfy 0 < minimum < maximum < pipe diameter")

    def evaluate(bore: float) -> OrificeFlowResult:
        return calculate_generic_orifice_flow(
            pipe_inside_diameter_m=pipe_inside_diameter_m,
            bore_diameter_m=bore,
            differential_pressure_pa=differential_pressure_pa,
            fluid=fluid,
            discharge_coefficient=discharge_coefficient,
            expansibility_factor=expansibility_factor,
        )

    low = minimum_bore_diameter_m
    high = maximum_bore_diameter_m
    low_result = evaluate(low)
    high_result = evaluate(high)
    if (
        target_mass_flow_kg_s < low_result.mass_flow_kg_s
        or target_mass_flow_kg_s > high_result.mass_flow_kg_s
    ):
        raise DPFlowConvergenceError("target mass flow is not bracketed by the supplied bore bounds")
    for iteration in range(1, maximum_iterations + 1):
        middle = _finite_number(
            low + (high - low) / 2.0,
            field_name="bisection midpoint",
        )
        achieved_result = evaluate(middle)
        achieved = achieved_result.mass_flow_kg_s
        error = abs(achieved - target_mass_flow_kg_s) / target_mass_flow_kg_s
        if error <= relative_tolerance:
            return BoreSolverResult(
                bore_diameter_m=middle,
                achieved_mass_flow_kg_s=achieved,
                relative_error=error,
                iterations=iteration,
                converged=True,
                lower_bound_m=minimum_bore_diameter_m,
                upper_bound_m=maximum_bore_diameter_m,
                warnings=achieved_result.warnings,
            )
        if achieved < target_mass_flow_kg_s:
            low = middle
        else:
            high = middle
    raise DPFlowConvergenceError(
        f"bounded solver did not converge within {maximum_iterations} iterations"
    )


GENERIC_NOZZLE_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=GENERIC_NOZZLE_METHOD_ID,
    method_version=GENERIC_NOZZLE_METHOD_VERSION,
    title="Generic flow-nozzle calculation with supplied coefficients",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="calculate_generic_nozzle_flow",
    executable=True,
    coefficient_policy=(
        "The caller must supply traceable discharge and expansibility coefficients "
        "for the exact geometry and operating conditions."
    ),
)

GENERIC_VENTURI_NOZZLE_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=GENERIC_VENTURI_NOZZLE_METHOD_ID,
    method_version=GENERIC_VENTURI_NOZZLE_METHOD_VERSION,
    title="Generic Venturi-nozzle calculation with supplied coefficients",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="calculate_generic_venturi_nozzle_flow",
    executable=True,
    coefficient_policy=(
        "The caller must supply traceable discharge and expansibility coefficients "
        "for the exact geometry and operating conditions."
    ),
)

GENERIC_VENTURI_TUBE_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=GENERIC_VENTURI_TUBE_METHOD_ID,
    method_version=GENERIC_VENTURI_TUBE_METHOD_VERSION,
    title="Generic Venturi-tube calculation with supplied coefficients",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="calculate_generic_venturi_tube_flow",
    executable=True,
    coefficient_policy=(
        "The caller must supply traceable discharge and expansibility coefficients "
        "for the exact geometry and operating conditions."
    ),
)

GENERIC_AVERAGING_PITOT_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=GENERIC_AVERAGING_PITOT_METHOD_ID,
    method_version=GENERIC_AVERAGING_PITOT_METHOD_VERSION,
    title="Generic averaging-Pitot calculation with supplied meter coefficient",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="calculate_generic_averaging_pitot_flow",
    executable=True,
    coefficient_policy=(
        "The caller must supply a traceable meter coefficient and expansibility "
        "factor for the exact probe, installation, and operating conditions."
    ),
)

DP_TRANSMITTER_RANGE_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=DP_TRANSMITTER_RANGE_METHOD_ID,
    method_version=DP_TRANSMITTER_RANGE_METHOD_VERSION,
    title="DP transmitter operating-range and low-signal screen",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="screen_dp_transmitter_range",
    executable=True,
    coefficient_policy=(
        "No coefficient is derived; all sensor limits, configured limits, operating "
        "cases, and the minimum acceptable signal fraction are caller supplied."
    ),
)

PERMANENT_PRESSURE_LOSS_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=PERMANENT_PRESSURE_LOSS_METHOD_ID,
    method_version=PERMANENT_PRESSURE_LOSS_METHOD_VERSION,
    title="Permanent pressure loss from a supplied traceable loss ratio",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="calculate_permanent_pressure_loss",
    executable=True,
    coefficient_policy=(
        "The caller must supply a traceable permanent-loss-to-measured-DP ratio "
        "applicable to the exact element and operating conditions."
    ),
)

DP_FLOW_UNCERTAINTY_ADAPTER: Final = DPFlowMethodAdapterMetadata(
    method_id=DP_FLOW_UNCERTAINTY_METHOD_ID,
    method_version=DP_FLOW_UNCERTAINTY_METHOD_VERSION,
    title="Independent relative DP-flow uncertainty combination by RSS",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="combine_dp_flow_relative_uncertainty",
    executable=True,
    coefficient_policy=(
        "Sensitivity coefficients and independent relative standard uncertainties "
        "must be supplied explicitly; correlated terms are outside this method."
    ),
)

DP_FLOW_EXECUTABLE_ADAPTERS: Final = (
    GENERIC_NOZZLE_ADAPTER,
    GENERIC_VENTURI_NOZZLE_ADAPTER,
    GENERIC_VENTURI_TUBE_ADAPTER,
    GENERIC_AVERAGING_PITOT_ADAPTER,
    DP_TRANSMITTER_RANGE_ADAPTER,
    PERMANENT_PRESSURE_LOSS_ADAPTER,
    DP_FLOW_UNCERTAINTY_ADAPTER,
)
DP_FLOW_METHOD_REGISTRY: Final = MappingProxyType(
    {
        (adapter.method_id, adapter.method_version): adapter
        for adapter in DP_FLOW_EXECUTABLE_ADAPTERS
    }
)
DP_FLOW_METHOD_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        (GENERIC_NOZZLE_METHOD_ID, GENERIC_NOZZLE_METHOD_VERSION): calculate_generic_nozzle_flow,
        (
            GENERIC_VENTURI_NOZZLE_METHOD_ID,
            GENERIC_VENTURI_NOZZLE_METHOD_VERSION,
        ): calculate_generic_venturi_nozzle_flow,
        (
            GENERIC_VENTURI_TUBE_METHOD_ID,
            GENERIC_VENTURI_TUBE_METHOD_VERSION,
        ): calculate_generic_venturi_tube_flow,
        (
            GENERIC_AVERAGING_PITOT_METHOD_ID,
            GENERIC_AVERAGING_PITOT_METHOD_VERSION,
        ): calculate_generic_averaging_pitot_flow,
        (
            DP_TRANSMITTER_RANGE_METHOD_ID,
            DP_TRANSMITTER_RANGE_METHOD_VERSION,
        ): screen_dp_transmitter_range,
        (
            PERMANENT_PRESSURE_LOSS_METHOD_ID,
            PERMANENT_PRESSURE_LOSS_METHOD_VERSION,
        ): calculate_permanent_pressure_loss,
        (
            DP_FLOW_UNCERTAINTY_METHOD_ID,
            DP_FLOW_UNCERTAINTY_METHOD_VERSION,
        ): combine_dp_flow_relative_uncertainty,
    }
)
if len(DP_FLOW_METHOD_REGISTRY) != len(DP_FLOW_EXECUTABLE_ADAPTERS):
    raise RuntimeError("duplicate exact-version DP-flow method adapter registration")
if DP_FLOW_METHOD_REGISTRY.keys() != DP_FLOW_METHOD_IMPLEMENTATIONS.keys():
    raise RuntimeError("DP-flow metadata and implementation registrations are inconsistent")
if any(
    adapter.implementation_name != DP_FLOW_METHOD_IMPLEMENTATIONS[key].__name__
    for key, adapter in DP_FLOW_METHOD_REGISTRY.items()
):
    raise RuntimeError("DP-flow implementation registration does not match its metadata")

DP_FLOW_DISCOVERY_ENTRIES: Final = (
    ISO_5167_2_ADAPTER,
    ISO_5167_3_ADAPTER,
    ISO_5167_4_ADAPTER,
)


__all__ = [
    "AveragingPitotFlowResult",
    "BoreSolverResult",
    "CircularRestrictionFlowResult",
    "DPFlowApplicability",
    "DPFlowCalculationError",
    "DPFlowConvergenceError",
    "DPFlowInputError",
    "DPFlowMethodAdapterMetadata",
    "DPFlowUncertaintyResult",
    "DPTransmitterRangeScreenResult",
    "DP_FLOW_CALCULATORS_VERSION",
    "DP_FLOW_DISCOVERY_ENTRIES",
    "DP_FLOW_EXECUTABLE_ADAPTERS",
    "DP_FLOW_METHOD_IMPLEMENTATIONS",
    "DP_FLOW_METHOD_REGISTRY",
    "DP_FLOW_METHOD_VERSION",
    "DP_FLOW_UNCERTAINTY_ADAPTER",
    "DP_FLOW_UNCERTAINTY_METHOD_ID",
    "DP_FLOW_UNCERTAINTY_METHOD_VERSION",
    "DP_TRANSMITTER_RANGE_ADAPTER",
    "DP_TRANSMITTER_RANGE_METHOD_ID",
    "DP_TRANSMITTER_RANGE_METHOD_VERSION",
    "FlowReferenceConditions",
    "FlowingFluidProperties",
    "GENERIC_AVERAGING_PITOT_ADAPTER",
    "GENERIC_AVERAGING_PITOT_METHOD_ID",
    "GENERIC_AVERAGING_PITOT_METHOD_VERSION",
    "GENERIC_NOZZLE_ADAPTER",
    "GENERIC_NOZZLE_METHOD_ID",
    "GENERIC_NOZZLE_METHOD_VERSION",
    "GENERIC_ORIFICE_METHOD_ID",
    "GENERIC_VENTURI_NOZZLE_ADAPTER",
    "GENERIC_VENTURI_NOZZLE_METHOD_ID",
    "GENERIC_VENTURI_NOZZLE_METHOD_VERSION",
    "GENERIC_VENTURI_TUBE_ADAPTER",
    "GENERIC_VENTURI_TUBE_METHOD_ID",
    "GENERIC_VENTURI_TUBE_METHOD_VERSION",
    "ISO_5167_2_ADAPTER",
    "ISO_5167_2_ADAPTER_ID",
    "ISO_5167_3_ADAPTER",
    "ISO_5167_3_ADAPTER_ID",
    "ISO_5167_4_ADAPTER",
    "ISO_5167_4_ADAPTER_ID",
    "MAX_SOLVER_ITERATIONS",
    "OrificeFlowResult",
    "PERMANENT_PRESSURE_LOSS_ADAPTER",
    "PERMANENT_PRESSURE_LOSS_METHOD_ID",
    "PERMANENT_PRESSURE_LOSS_METHOD_VERSION",
    "PermanentPressureLossResult",
    "RelativeUncertaintyComponent",
    "StandardsAdapterMetadata",
    "TraceableCoefficient",
    "assess_generic_orifice_applicability",
    "calculate_generic_averaging_pitot_flow",
    "calculate_generic_circular_restriction_flow",
    "calculate_generic_nozzle_flow",
    "calculate_generic_orifice_flow",
    "calculate_generic_venturi_nozzle_flow",
    "calculate_generic_venturi_tube_flow",
    "calculate_permanent_pressure_loss",
    "combine_dp_flow_relative_uncertainty",
    "screen_dp_transmitter_range",
    "solve_orifice_bore_for_mass_flow",
]
