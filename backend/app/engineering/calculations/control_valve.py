"""Fail-closed liquid control-valve capacity sizing for Phase 7 Step 100.

This module provides one deterministic preliminary sizing method for a
single, turbulent, incompressible, Newtonian, single-phase liquid inlet case.
It calculates the required ``Kv`` and ``Cv`` from explicit absolute pressures,
fluid properties, and caller-supplied traceable valve factors.  It also
identifies the choked transition, screens flashing and cavitation, and checks
a caller-supplied outlet-velocity limit.

The executable method does not derive valve recovery or piping factors from
protected tables, select a manufacturer or product, or claim conformity with
IEC 60534.  Gas, vapour, steam, two-phase inlet, laminar, non-Newtonian,
slurry, noise, actuator, material, leakage, and final-selection work remain
outside this Step 100 boundary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from math import isclose, isfinite, pi, sqrt
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from app.engineering.calculations.models import CalculationModel, MethodLifecycleStatus
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY, QuantityKind

CONTROL_VALVE_CALCULATORS_VERSION: Final = "1.0.0"
CONTROL_VALVE_METHOD_VERSION: Final = "1.0.0"
LIQUID_CONTROL_VALVE_SIZING_METHOD_ID: Final = (
    "valve.control.liquid.cv-kv-sizing.supplied-factors"
)
LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION: Final = "1.0.0"
IEC_60534_2_1_ADAPTER_ID: Final = "valve.control.iec-60534-2-1.liquid-sizing-adapter"

_INPUT_FINGERPRINT_SCHEMA: Final = "engineer4me.control-valve.liquid-sizing-input.v1"
_RESULT_FINGERPRINT_SCHEMA: Final = "engineer4me.control-valve.liquid-sizing-result.v1"

_M3_H_PER_US_GPM: Final = DEFAULT_UNIT_REGISTRY.convert_value(
    1.0,
    "US gal/min",
    "m3/h",
    quantity_kind=QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
)
_PSI_PER_BAR: Final = DEFAULT_UNIT_REGISTRY.convert_value(
    1.0,
    "bar",
    "psi",
    quantity_kind=QuantityKind.DIFFERENTIAL_PRESSURE,
)
KV_PER_CV: Final = _M3_H_PER_US_GPM * sqrt(_PSI_PER_BAR)
CV_PER_KV: Final = 1.0 / KV_PER_CV

_REGIME_FLASHING_WARNINGS: Final = (
    (
        "Downstream absolute pressure is at or below vapor pressure; "
        "flashing and two-phase outlet review are required."
    ),
    (
        "Preliminary capacity does not select flashing-service trim, "
        "materials, piping, or a manufacturer."
    ),
)
_REGIME_CHOKED_WARNINGS: Final = (
    (
        "The liquid sizing pressure drop is capped at the terminal "
        "pressure drop; choked cavitating service is indicated."
    ),
    "Competent severe-service and OEM factor review is required.",
)
_REGIME_SUBCRITICAL_WARNINGS: Final = (
    (
        "Cavitation is not excluded by this capacity method; no "
        "incipient-damage or OEM cavitation correlation is applied."
    ),
)
_VELOCITY_FLASHING_WARNINGS: Final = (
    (
        "Single-phase liquid outlet velocity is suppressed because "
        "the downstream state is flashing."
    ),
)
_VELOCITY_NOT_ASSESSED_WARNINGS: Final = (
    (
        "No traceable project or OEM outlet-velocity limit was supplied; "
        "velocity acceptability is not assessed."
    ),
)
_VELOCITY_EXCEEDS_WARNINGS: Final = (
    (
        "Calculated single-phase outlet velocity exceeds the "
        "caller-supplied traceable limit."
    ),
)
_PRELIMINARY_RESULT_WARNING: Final = (
    "This result is preliminary capacity-sizing support and is not final "
    "valve, trim, material, actuator, or brand selection."
)
_NO_CONFORMITY_WARNING: Final = "No standards-conformity claim is made."
_RESULT_EXCLUSIONS: Final = (
    "gas, vapour, steam, and two-phase inlet sizing",
    "laminar, high-viscosity, non-Newtonian, slurry, and solids corrections",
    (
        "noise, erosion, material, trim, actuator, leakage, rangeability, "
        "SIL, and hazardous-area selection"
    ),
    (
        "proprietary factor derivation, manufacturer ranking, product "
        "selection, and standards conformity"
    ),
)


class ControlValveCalculationError(ValueError):
    """Base error for the Step 100 liquid control-valve boundary."""


class ControlValveInputError(ControlValveCalculationError):
    """Raised when an input is incomplete, untraceable, or inapplicable."""


def _finite_number(value: object, *, field_name: str) -> float:
    """Return a finite float while rejecting booleans and coercive inputs."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ControlValveInputError(f"{field_name} must be a finite real number")
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise ControlValveInputError(
            f"{field_name} must be a finite real number"
        ) from error
    if not isfinite(normalized):
        raise ControlValveInputError(f"{field_name} must be a finite real number")
    if normalized == 0.0:
        return 0.0
    return normalized


def _checked_result(
    value: object,
    *,
    field_name: str,
    allow_zero: bool = False,
) -> float:
    """Validate one calculated public float and reject under/overflow."""

    normalized = _finite_number(value, field_name=field_name)
    if normalized < 0.0 or (not allow_zero and normalized == 0.0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ControlValveInputError(f"{field_name} must remain finite and {qualifier}")
    return normalized


def _strict_text(value: object, *, field_name: str) -> str:
    """Require nonblank, already-trimmed provenance or identifier text."""

    if not isinstance(value, str):
        raise ControlValveInputError(f"{field_name} must be text")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    if value != value.strip():
        raise ValueError(f"{field_name} cannot contain surrounding whitespace")
    return value


def _revalidate_model(value: object, model_type: type[CalculationModel]) -> Any:
    """Revalidate an immutable model at a public calculation boundary."""

    if not isinstance(value, model_type):
        raise ControlValveInputError(f"{model_type.__name__} input is required")
    try:
        return model_type.model_validate(
            value.model_dump(mode="python", round_trip=True)
        )
    except Exception as error:
        raise ControlValveInputError(
            f"{model_type.__name__} failed validation"
        ) from error


class ValveInstallationBasis(StrEnum):
    """Supported Step 100 valve/fitting arrangements."""

    BARE_VALVE = "bare_valve"
    ATTACHED_FITTINGS = "attached_fittings"


class LiquidValveFlowRegime(StrEnum):
    """Deterministic liquid-capacity pressure regime."""

    SUBCRITICAL = "subcritical"
    CHOKED = "choked"


class LiquidCavitationStatus(StrEnum):
    """Conservative preliminary cavitation/flashing classification."""

    NOT_EXCLUDED = "not_excluded"
    CHOKED_CAVITATION_INDICATED = "choked_cavitation_indicated"
    FLASHING_PRESENT = "flashing_present"


class LiquidVelocityStatus(StrEnum):
    """State of the caller-bounded single-phase velocity check."""

    NOT_ASSESSED = "not_assessed"
    WITHIN_SUPPLIED_LIMIT = "within_supplied_limit"
    EXCEEDS_SUPPLIED_LIMIT = "exceeds_supplied_limit"
    SUPPRESSED_FLASHING = "suppressed_flashing"


class TraceableLiquidValveFactors(CalculationModel):
    """Caller-supplied recovery/fitting factors for one coherent candidate."""

    installation_basis: ValveInstallationBasis
    bare_valve_pressure_recovery_factor: float | None = None
    piping_geometry_factor: float | None = None
    combined_pressure_recovery_factor: float | None = None
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=10, max_length=1500)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator(
        "bare_valve_pressure_recovery_factor",
        "piping_geometry_factor",
        "combined_pressure_recovery_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_factors(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite_number(value, field_name="liquid valve factor")

    @field_validator(
        "source_reference",
        "applicable_conditions",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_factor_provenance(cls, value: object) -> str:
        return _strict_text(value, field_name="factor provenance")

    @model_validator(mode="after")
    def validate_factor_arrangement(self) -> TraceableLiquidValveFactors:
        if self.installation_basis is ValveInstallationBasis.BARE_VALVE:
            recovery = self.bare_valve_pressure_recovery_factor
            if recovery is None:
                raise ValueError(
                    "bare-valve service requires a pressure recovery factor"
                )
            if (
                self.piping_geometry_factor is not None
                or self.combined_pressure_recovery_factor is not None
            ):
                raise ValueError(
                    "bare-valve service cannot supply attached-fitting factors"
                )
            if recovery <= 0.0 or recovery > 1.0:
                raise ValueError(
                    "bare-valve pressure recovery factor must be in (0, 1]"
                )
            return self

        if self.bare_valve_pressure_recovery_factor is not None:
            raise ValueError(
                "attached-fitting service cannot supply a bare-valve factor"
            )
        piping = self.piping_geometry_factor
        combined = self.combined_pressure_recovery_factor
        if piping is None or combined is None:
            raise ValueError("attached-fitting service requires both FP and FLP")
        if piping <= 0.0 or piping > 1.0:
            raise ValueError("piping geometry factor must be in (0, 1]")
        if combined <= 0.0 or combined > piping:
            raise ValueError("combined pressure recovery factor must be in (0, FP]")
        return self

    def effective_factors(self) -> tuple[float, float]:
        """Return effective ``FP`` and ``FLP`` without deriving OEM data."""

        if self.installation_basis is ValveInstallationBasis.BARE_VALVE:
            recovery = self.bare_valve_pressure_recovery_factor
            if recovery is None:  # pragma: no cover - guarded by validation
                raise ControlValveInputError(
                    "validated bare-valve recovery factor is missing"
                )
            return (1.0, recovery)
        piping = self.piping_geometry_factor
        combined = self.combined_pressure_recovery_factor
        if piping is None or combined is None:  # pragma: no cover
            raise ControlValveInputError(
                "validated attached-fitting factors are missing"
            )
        return (piping, combined)


class TraceableVelocityLimit(CalculationModel):
    """Caller-supplied project or OEM velocity limit and provenance."""

    maximum_velocity_m_s: float
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=10, max_length=1500)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator("maximum_velocity_m_s", mode="before")
    @classmethod
    def validate_raw_limit(cls, value: object) -> float:
        return _finite_number(value, field_name="maximum outlet velocity")

    @field_validator(
        "source_reference",
        "applicable_conditions",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_limit_provenance(cls, value: object) -> str:
        return _strict_text(value, field_name="velocity-limit provenance")

    @model_validator(mode="after")
    def validate_limit(self) -> TraceableVelocityLimit:
        if self.maximum_velocity_m_s <= 0.0:
            raise ValueError("maximum outlet velocity must be positive")
        return self


class LiquidControlValveProperties(CalculationModel):
    """Liquid properties at the explicit inlet flowing condition."""

    specific_gravity: float
    flowing_temperature_k: float
    vapor_pressure_absolute_pa: float
    critical_pressure_absolute_pa: float
    thermodynamic_pressure_basis: Literal["absolute"]
    property_source_reference: str = Field(min_length=3, max_length=500)
    condition_basis: str = Field(min_length=10, max_length=1500)

    @field_validator(
        "specific_gravity",
        "flowing_temperature_k",
        "vapor_pressure_absolute_pa",
        "critical_pressure_absolute_pa",
        mode="before",
    )
    @classmethod
    def validate_raw_properties(cls, value: object) -> float:
        return _finite_number(value, field_name="liquid property")

    @field_validator(
        "property_source_reference",
        "condition_basis",
        mode="before",
    )
    @classmethod
    def validate_property_provenance(cls, value: object) -> str:
        return _strict_text(value, field_name="fluid-property provenance")

    @model_validator(mode="after")
    def validate_properties(self) -> LiquidControlValveProperties:
        if self.specific_gravity <= 0.0:
            raise ValueError("specific gravity must be positive")
        if self.flowing_temperature_k <= 0.0:
            raise ValueError("flowing absolute temperature must be positive")
        if self.vapor_pressure_absolute_pa < 0.0:
            raise ValueError("vapor absolute pressure cannot be negative")
        if self.critical_pressure_absolute_pa <= self.vapor_pressure_absolute_pa:
            raise ValueError("critical absolute pressure must exceed vapor pressure")
        return self


class LiquidControlValvePressureState(CalculationModel):
    """Upstream/downstream pressure state on one explicit absolute basis."""

    upstream_pressure_absolute_pa: float
    downstream_pressure_absolute_pa: float
    pressure_basis: Literal["absolute"]
    pressure_source_reference: str = Field(min_length=3, max_length=500)
    condition_basis: str = Field(min_length=10, max_length=1500)

    @field_validator(
        "upstream_pressure_absolute_pa",
        "downstream_pressure_absolute_pa",
        mode="before",
    )
    @classmethod
    def validate_raw_pressures(cls, value: object) -> float:
        return _finite_number(value, field_name="absolute pressure")

    @field_validator(
        "pressure_source_reference",
        "condition_basis",
        mode="before",
    )
    @classmethod
    def validate_pressure_provenance(cls, value: object) -> str:
        return _strict_text(value, field_name="pressure-state provenance")

    @model_validator(mode="after")
    def validate_pressure_order(self) -> LiquidControlValvePressureState:
        if self.downstream_pressure_absolute_pa <= 0.0:
            raise ValueError("downstream absolute pressure must be positive")
        if self.upstream_pressure_absolute_pa <= self.downstream_pressure_absolute_pa:
            raise ValueError(
                "upstream absolute pressure must exceed downstream pressure"
            )
        return self


class LiquidControlValveSizingInput(CalculationModel):
    """Complete strict input for one preliminary liquid sizing case."""

    case_id: str = Field(
        min_length=2,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    )
    actual_volumetric_flow_m3_h: float
    volumetric_flow_basis: Literal["actual_at_inlet_conditions"]
    flow_source_reference: str = Field(min_length=3, max_length=500)
    flow_condition_basis: str = Field(min_length=10, max_length=1500)
    properties: LiquidControlValveProperties
    pressure_state: LiquidControlValvePressureState
    factors: TraceableLiquidValveFactors
    outlet_inside_diameter_m: float
    outlet_diameter_source_reference: str = Field(
        min_length=3,
        max_length=500,
    )
    maximum_outlet_velocity: TraceableVelocityLimit | None = None
    fluid_phase: Literal["liquid"]
    rheology: Literal["newtonian"]
    turbulent_flow_confirmed: StrictBool
    incompressible_flow_confirmed: StrictBool
    single_phase_inlet_confirmed: StrictBool
    suspended_solids_absent_confirmed: StrictBool

    @field_validator("case_id", mode="before")
    @classmethod
    def validate_case_id(cls, value: object) -> str:
        return _strict_text(value, field_name="case identifier")

    @field_validator(
        "flow_source_reference",
        "flow_condition_basis",
        "outlet_diameter_source_reference",
        mode="before",
    )
    @classmethod
    def validate_case_provenance(cls, value: object) -> str:
        return _strict_text(value, field_name="sizing-input provenance")

    @field_validator(
        "actual_volumetric_flow_m3_h",
        "outlet_inside_diameter_m",
        mode="before",
    )
    @classmethod
    def validate_raw_case_values(cls, value: object) -> float:
        return _finite_number(value, field_name="liquid sizing input")

    @model_validator(mode="after")
    def validate_case(self) -> LiquidControlValveSizingInput:
        if self.actual_volumetric_flow_m3_h <= 0.0:
            raise ValueError("actual inlet volumetric flow must be positive")
        if self.outlet_inside_diameter_m <= 0.0:
            raise ValueError("outlet inside diameter must be positive")
        if (
            self.pressure_state.upstream_pressure_absolute_pa
            <= self.properties.vapor_pressure_absolute_pa
        ):
            raise ValueError("upstream absolute pressure must exceed vapor pressure")
        confirmations = (
            self.turbulent_flow_confirmed,
            self.incompressible_flow_confirmed,
            self.single_phase_inlet_confirmed,
            self.suspended_solids_absent_confirmed,
        )
        if not all(confirmations):
            raise ValueError(
                "turbulent, incompressible, single-phase inlet, solids-free "
                "applicability must be explicitly confirmed"
            )
        return self


class LiquidValveRegimeResult(CalculationModel):
    """Pressure-regime, choking, cavitation, and flashing screen."""

    actual_pressure_drop_pa: float
    critical_pressure_ratio_factor: float
    terminal_pressure_drop_pa: float
    sizing_pressure_drop_pa: float
    choking_pressure_margin_pa: float
    choking_index: float
    effective_piping_geometry_factor: float
    effective_pressure_recovery_factor: float
    flow_regime: LiquidValveFlowRegime
    choked: StrictBool
    flashing: StrictBool
    cavitation_status: LiquidCavitationStatus
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False

    @field_validator(
        "actual_pressure_drop_pa",
        "critical_pressure_ratio_factor",
        "terminal_pressure_drop_pa",
        "sizing_pressure_drop_pa",
        "choking_pressure_margin_pa",
        "choking_index",
        "effective_piping_geometry_factor",
        "effective_pressure_recovery_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_regime_values(cls, value: object) -> float:
        return _finite_number(value, field_name="liquid pressure-regime result")

    @model_validator(mode="after")
    def validate_regime_contract(self) -> LiquidValveRegimeResult:
        positive_values = (
            self.actual_pressure_drop_pa,
            self.terminal_pressure_drop_pa,
            self.sizing_pressure_drop_pa,
            self.choking_index,
        )
        if any(value <= 0.0 for value in positive_values):
            raise ValueError("liquid pressure-regime values must be positive")
        bounded_factors = (
            self.critical_pressure_ratio_factor,
            self.effective_piping_geometry_factor,
            self.effective_pressure_recovery_factor,
        )
        if any(value <= 0.0 or value > 1.0 for value in bounded_factors):
            raise ValueError("liquid pressure-regime factors must be in (0, 1]")
        expected_choked = self.actual_pressure_drop_pa >= self.terminal_pressure_drop_pa
        expected_regime = (
            LiquidValveFlowRegime.CHOKED
            if expected_choked
            else LiquidValveFlowRegime.SUBCRITICAL
        )
        if (
            self.choked is not expected_choked
            or self.flow_regime is not expected_regime
        ):
            raise ValueError("liquid pressure-regime fields are inconsistent")
        expected_sizing = min(
            self.actual_pressure_drop_pa,
            self.terminal_pressure_drop_pa,
        )
        if self.sizing_pressure_drop_pa != expected_sizing:
            raise ValueError("liquid sizing pressure drop is inconsistent")
        if self.choking_pressure_margin_pa != (
            self.terminal_pressure_drop_pa - self.actual_pressure_drop_pa
        ):
            raise ValueError("liquid choking pressure margin is inconsistent")
        if self.choking_index != (
            self.actual_pressure_drop_pa / self.terminal_pressure_drop_pa
        ):
            raise ValueError("liquid choking index is inconsistent")
        if self.flashing:
            expected_cavitation = LiquidCavitationStatus.FLASHING_PRESENT
            expected_warnings = _REGIME_FLASHING_WARNINGS
        elif self.choked:
            expected_cavitation = LiquidCavitationStatus.CHOKED_CAVITATION_INDICATED
            expected_warnings = _REGIME_CHOKED_WARNINGS
        else:
            expected_cavitation = LiquidCavitationStatus.NOT_EXCLUDED
            expected_warnings = _REGIME_SUBCRITICAL_WARNINGS
        if self.cavitation_status is not expected_cavitation:
            raise ValueError("liquid cavitation classification is inconsistent")
        if self.warnings != expected_warnings:
            raise ValueError("liquid pressure-regime warnings are inconsistent")
        return self


class LiquidValveVelocityResult(CalculationModel):
    """Single-phase outlet velocity and supplied-limit comparison."""

    outlet_inside_diameter_m: float
    outlet_area_m2: float
    outlet_velocity_m_s: float | None
    supplied_maximum_velocity_m_s: float | None
    supplied_limit_source_reference: str | None
    within_supplied_limit: StrictBool | None
    velocity_status: LiquidVelocityStatus
    warnings: tuple[str, ...]

    @field_validator(
        "outlet_inside_diameter_m",
        "outlet_area_m2",
        "outlet_velocity_m_s",
        "supplied_maximum_velocity_m_s",
        mode="before",
    )
    @classmethod
    def validate_raw_velocity_values(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite_number(value, field_name="liquid velocity result")

    @field_validator("supplied_limit_source_reference", mode="before")
    @classmethod
    def validate_limit_source(cls, value: object) -> str | None:
        if value is None:
            return None
        return _strict_text(value, field_name="velocity-limit source reference")

    @model_validator(mode="after")
    def validate_velocity_contract(self) -> LiquidValveVelocityResult:
        if self.outlet_inside_diameter_m <= 0.0 or self.outlet_area_m2 <= 0.0:
            raise ValueError("outlet diameter and flow area must be positive")
        if self.outlet_area_m2 != pi * self.outlet_inside_diameter_m**2 / 4.0:
            raise ValueError("outlet flow area is inconsistent with diameter")
        if self.outlet_velocity_m_s is not None and self.outlet_velocity_m_s <= 0.0:
            raise ValueError("outlet velocity must be positive when available")
        if (
            self.supplied_maximum_velocity_m_s is not None
            and self.supplied_maximum_velocity_m_s <= 0.0
        ):
            raise ValueError("supplied maximum velocity must be positive")
        supplied_limit_complete = (
            self.supplied_maximum_velocity_m_s is not None
            and self.supplied_limit_source_reference is not None
        )
        if supplied_limit_complete != (
            self.supplied_maximum_velocity_m_s is not None
            or self.supplied_limit_source_reference is not None
        ):
            raise ValueError("supplied velocity-limit fields are incomplete")
        if self.velocity_status is LiquidVelocityStatus.SUPPRESSED_FLASHING:
            if (
                self.outlet_velocity_m_s is not None
                or self.within_supplied_limit is not None
            ):
                raise ValueError("flashing velocity output must remain unavailable")
            if self.warnings != _VELOCITY_FLASHING_WARNINGS:
                raise ValueError("flashing velocity warnings are inconsistent")
            return self
        if self.outlet_velocity_m_s is None:
            raise ValueError("nonflashing velocity output cannot be missing")
        if self.velocity_status is LiquidVelocityStatus.NOT_ASSESSED:
            if (
                self.supplied_maximum_velocity_m_s is not None
                or self.supplied_limit_source_reference is not None
                or self.within_supplied_limit is not None
            ):
                raise ValueError("unassessed velocity fields are inconsistent")
            if self.warnings != _VELOCITY_NOT_ASSESSED_WARNINGS:
                raise ValueError("unassessed velocity warnings are inconsistent")
            return self
        if (
            self.supplied_maximum_velocity_m_s is None
            or self.supplied_limit_source_reference is None
            or self.within_supplied_limit is None
        ):
            raise ValueError("assessed velocity fields are incomplete")
        expected_within = self.outlet_velocity_m_s <= self.supplied_maximum_velocity_m_s
        expected_status = (
            LiquidVelocityStatus.WITHIN_SUPPLIED_LIMIT
            if expected_within
            else LiquidVelocityStatus.EXCEEDS_SUPPLIED_LIMIT
        )
        if (
            self.within_supplied_limit is not expected_within
            or self.velocity_status is not expected_status
        ):
            raise ValueError("velocity-limit classification is inconsistent")
        expected_warnings = () if expected_within else _VELOCITY_EXCEEDS_WARNINGS
        if self.warnings != expected_warnings:
            raise ValueError("velocity-limit warnings are inconsistent")
        return self


class LiquidControlValveSizingResult(CalculationModel):
    """Preliminary required capacity and conservative screening result."""

    method_id: Literal["valve.control.liquid.cv-kv-sizing.supplied-factors"] = (
        LIQUID_CONTROL_VALVE_SIZING_METHOD_ID
    )
    method_version: Literal["1.0.0"] = LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION
    calculator_version: Literal["1.0.0"] = CONTROL_VALVE_CALCULATORS_VERSION
    normalized_input: LiquidControlValveSizingInput
    required_kv: float
    required_cv: float
    regime: LiquidValveRegimeResult
    velocity: LiquidValveVelocityResult
    warnings: tuple[str, ...]
    exclusions: tuple[str, ...]
    selection_ready: Literal[False] = False
    independent_review_required: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    calculation_basis: Literal[
        "preliminary turbulent incompressible Newtonian liquid sizing with traceable factors"
    ] = "preliminary turbulent incompressible Newtonian liquid sizing with traceable factors"
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("required_kv", "required_cv", mode="before")
    @classmethod
    def validate_raw_capacity_values(cls, value: object) -> float:
        return _finite_number(value, field_name="required valve capacity")

    @model_validator(mode="after")
    def validate_result_contract(self) -> LiquidControlValveSizingResult:
        if self.required_kv <= 0.0 or self.required_cv <= 0.0:
            raise ValueError("required valve capacity must be positive")
        expected_regime = assess_liquid_control_valve_regime(
            pressure_state=self.normalized_input.pressure_state,
            properties=self.normalized_input.properties,
            factors=self.normalized_input.factors,
        )
        if self.regime != expected_regime:
            raise ValueError("liquid pressure-regime result is not reproducible")
        expected_velocity = check_liquid_control_valve_velocity(
            actual_volumetric_flow_m3_h=(
                self.normalized_input.actual_volumetric_flow_m3_h
            ),
            outlet_inside_diameter_m=(self.normalized_input.outlet_inside_diameter_m),
            incompressible_flow_confirmed=(
                self.normalized_input.incompressible_flow_confirmed
            ),
            flashing=expected_regime.flashing,
            maximum_outlet_velocity=(self.normalized_input.maximum_outlet_velocity),
        )
        if self.velocity != expected_velocity:
            raise ValueError("liquid velocity result is not reproducible")
        expected_kv = _calculate_required_liquid_kv(
            self.normalized_input,
            expected_regime,
        )
        expected_cv = convert_kv_to_cv(expected_kv)
        if self.required_kv != expected_kv or self.required_cv != expected_cv:
            raise ValueError("required liquid valve capacity is not reproducible")
        expected_warnings = tuple(
            dict.fromkeys(
                (
                    *expected_regime.warnings,
                    *expected_velocity.warnings,
                    _PRELIMINARY_RESULT_WARNING,
                    _NO_CONFORMITY_WARNING,
                )
            )
        )
        if self.warnings != expected_warnings:
            raise ValueError("liquid sizing result warnings are inconsistent")
        if self.exclusions != _RESULT_EXCLUSIONS:
            raise ValueError("liquid sizing exclusions are inconsistent")
        expected_input = fingerprint_control_valve_payload(
            build_liquid_control_valve_input_fingerprint_payload(self.normalized_input)
        )
        if self.input_fingerprint != expected_input:
            raise ValueError("liquid sizing input fingerprint is stale")
        expected_result = fingerprint_control_valve_payload(
            build_liquid_control_valve_result_fingerprint_payload(self)
        )
        if self.result_fingerprint != expected_result:
            raise ValueError("liquid sizing result fingerprint is stale")
        return self


class ControlValveMethodAdapterMetadata(CalculationModel):
    """Exact-version registration for a reviewed direct sizing method."""

    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    title: str = Field(min_length=3, max_length=240)
    lifecycle_status: Literal[MethodLifecycleStatus.APPROVED]
    implementation_name: str = Field(
        pattern=r"^[a-z][a-z0-9_]+$",
        max_length=160,
    )
    executable: Literal[True]
    applicability_boundary: str = Field(min_length=20, max_length=1500)
    factor_policy: str = Field(min_length=20, max_length=1500)
    standards_conformity_claimed: Literal[False] = False


class ControlValveStandardsAdapterMetadata(CalculationModel):
    """Discoverable but inert control-valve standards-adapter record."""

    adapter_id: str
    title: str
    standard_family: str
    official_catalog_url: str
    lifecycle_status: Literal[MethodLifecycleStatus.STANDARDS_REVIEW]
    executable: Literal[False]
    conformity_claimed: Literal[False]
    boundary: str


def _canonicalize_fingerprint_value(value: object) -> object:
    """Return a JSON-safe deterministic value with canonical signed zero."""

    if isinstance(value, CalculationModel):
        return _canonicalize_fingerprint_value(
            value.model_dump(mode="json", round_trip=True)
        )
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ControlValveInputError(
                "control-valve fingerprint mapping keys must be strings"
            )
        return {
            key: _canonicalize_fingerprint_value(item) for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_canonicalize_fingerprint_value(item) for item in value]
    if isinstance(value, float):
        if not isfinite(value):
            raise ControlValveInputError(
                "fingerprint payload cannot contain a non-finite number"
            )
        return 0.0 if value == 0.0 else value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ControlValveInputError(
        f"unsupported control-valve fingerprint value: {type(value).__name__}"
    )


def canonical_control_valve_fingerprint_bytes(payload: object) -> bytes:
    """Serialize one payload to canonical UTF-8 JSON bytes."""

    canonical = _canonicalize_fingerprint_value(payload)
    try:
        text = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise ControlValveInputError(
            "control-valve fingerprint payload is not canonicalizable"
        ) from error
    return text.encode("utf-8")


def fingerprint_control_valve_payload(payload: object) -> str:
    """Return a lowercase SHA-256 fingerprint for a canonical payload."""

    return sha256(canonical_control_valve_fingerprint_bytes(payload)).hexdigest()


def build_liquid_control_valve_input_fingerprint_payload(
    sizing_input: LiquidControlValveSizingInput,
) -> dict[str, object]:
    """Build the complete version-bound input fingerprint payload."""

    validated = _revalidate_model(
        sizing_input,
        LiquidControlValveSizingInput,
    )
    return {
        "schema": _INPUT_FINGERPRINT_SCHEMA,
        "calculator_version": CONTROL_VALVE_CALCULATORS_VERSION,
        "method_id": LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        "method_version": LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        "input": validated.model_dump(mode="json", round_trip=True),
    }


def build_liquid_control_valve_result_fingerprint_payload(
    result: LiquidControlValveSizingResult | Mapping[str, object],
) -> dict[str, object]:
    """Build the result payload while excluding its self-fingerprint."""

    if isinstance(result, LiquidControlValveSizingResult):
        values: dict[str, object] = result.model_dump(
            mode="json",
            round_trip=True,
            exclude={"result_fingerprint"},
        )
    elif isinstance(result, Mapping):
        values = dict(result)
        values.pop("result_fingerprint", None)
    else:
        raise ControlValveInputError(
            "validated liquid sizing result or mapping is required"
        )
    return {
        "schema": _RESULT_FINGERPRINT_SCHEMA,
        "result": values,
    }


def convert_cv_to_kv(cv: object) -> float:
    """Convert a positive ``Cv`` to ``Kv`` using the frozen unit registry."""

    normalized = _finite_number(cv, field_name="Cv")
    if normalized <= 0.0:
        raise ControlValveInputError("Cv must be positive")
    return _checked_result(
        normalized * KV_PER_CV,
        field_name="converted Kv",
    )


def convert_kv_to_cv(kv: object) -> float:
    """Convert a positive ``Kv`` to ``Cv`` using the frozen unit registry."""

    normalized = _finite_number(kv, field_name="Kv")
    if normalized <= 0.0:
        raise ControlValveInputError("Kv must be positive")
    return _checked_result(
        normalized * CV_PER_KV,
        field_name="converted Cv",
    )


def _calculate_required_liquid_kv(
    values: LiquidControlValveSizingInput,
    regime: LiquidValveRegimeResult,
) -> float:
    """Calculate required ``Kv`` from validated input and regime data."""

    pressure_drop_bar = regime.sizing_pressure_drop_pa / 100_000.0
    try:
        denominator = regime.effective_piping_geometry_factor * sqrt(
            pressure_drop_bar / values.properties.specific_gravity
        )
        required_kv = values.actual_volumetric_flow_m3_h / denominator
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise ControlValveInputError(
            "required liquid capacity could not be calculated"
        ) from error
    return _checked_result(required_kv, field_name="required Kv")


def derive_liquid_critical_pressure_ratio_factor(
    *,
    vapor_pressure_absolute_pa: object,
    critical_pressure_absolute_pa: object,
) -> float:
    """Return the reviewed preliminary liquid critical-pressure factor."""

    vapor = _finite_number(
        vapor_pressure_absolute_pa,
        field_name="vapor absolute pressure",
    )
    critical = _finite_number(
        critical_pressure_absolute_pa,
        field_name="critical absolute pressure",
    )
    if vapor < 0.0:
        raise ControlValveInputError("vapor absolute pressure cannot be negative")
    if critical <= vapor:
        raise ControlValveInputError(
            "critical absolute pressure must exceed vapor pressure"
        )
    try:
        factor = 0.96 - 0.28 * sqrt(vapor / critical)
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise ControlValveInputError(
            "critical-pressure factor could not be calculated"
        ) from error
    return _checked_result(
        factor,
        field_name="critical-pressure ratio factor",
    )


def assess_liquid_control_valve_regime(
    *,
    pressure_state: LiquidControlValvePressureState,
    properties: LiquidControlValveProperties,
    factors: TraceableLiquidValveFactors,
) -> LiquidValveRegimeResult:
    """Assess the exact choked transition and conservative phase screens."""

    state = _revalidate_model(
        pressure_state,
        LiquidControlValvePressureState,
    )
    fluid = _revalidate_model(properties, LiquidControlValveProperties)
    factor_set = _revalidate_model(factors, TraceableLiquidValveFactors)
    p1 = state.upstream_pressure_absolute_pa
    p2 = state.downstream_pressure_absolute_pa
    vapor = fluid.vapor_pressure_absolute_pa
    if p1 <= vapor:
        raise ControlValveInputError(
            "upstream absolute pressure must exceed vapor pressure"
        )
    piping, combined = factor_set.effective_factors()
    ff = derive_liquid_critical_pressure_ratio_factor(
        vapor_pressure_absolute_pa=vapor,
        critical_pressure_absolute_pa=fluid.critical_pressure_absolute_pa,
    )
    try:
        actual_drop = p1 - p2
        effective_recovery = combined / piping
        terminal_drop = effective_recovery**2 * (p1 - ff * vapor)
        sizing_drop = min(actual_drop, terminal_drop)
        choking_margin = terminal_drop - actual_drop
        choking_index = actual_drop / terminal_drop
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise ControlValveInputError(
            "liquid pressure regime could not be calculated"
        ) from error
    actual_drop = _checked_result(
        actual_drop,
        field_name="actual valve pressure drop",
    )
    terminal_drop = _checked_result(
        terminal_drop,
        field_name="terminal valve pressure drop",
    )
    sizing_drop = _checked_result(
        sizing_drop,
        field_name="liquid sizing pressure drop",
    )
    choking_margin = _finite_number(
        choking_margin,
        field_name="choking pressure margin",
    )
    choking_index = _checked_result(
        choking_index,
        field_name="choking index",
    )
    choked = actual_drop >= terminal_drop
    flashing = p2 <= vapor
    if flashing:
        cavitation = LiquidCavitationStatus.FLASHING_PRESENT
        warnings = _REGIME_FLASHING_WARNINGS
    elif choked:
        cavitation = LiquidCavitationStatus.CHOKED_CAVITATION_INDICATED
        warnings = _REGIME_CHOKED_WARNINGS
    else:
        cavitation = LiquidCavitationStatus.NOT_EXCLUDED
        warnings = _REGIME_SUBCRITICAL_WARNINGS
    return LiquidValveRegimeResult(
        actual_pressure_drop_pa=actual_drop,
        critical_pressure_ratio_factor=ff,
        terminal_pressure_drop_pa=terminal_drop,
        sizing_pressure_drop_pa=sizing_drop,
        choking_pressure_margin_pa=choking_margin,
        choking_index=choking_index,
        effective_piping_geometry_factor=piping,
        effective_pressure_recovery_factor=effective_recovery,
        flow_regime=(
            LiquidValveFlowRegime.CHOKED
            if choked
            else LiquidValveFlowRegime.SUBCRITICAL
        ),
        choked=choked,
        flashing=flashing,
        cavitation_status=cavitation,
        warnings=warnings,
    )


def check_liquid_control_valve_velocity(
    *,
    actual_volumetric_flow_m3_h: object,
    outlet_inside_diameter_m: object,
    incompressible_flow_confirmed: StrictBool,
    flashing: StrictBool,
    maximum_outlet_velocity: TraceableVelocityLimit | None = None,
) -> LiquidValveVelocityResult:
    """Check incompressible outlet velocity against an optional traceable limit."""

    flow = _finite_number(
        actual_volumetric_flow_m3_h,
        field_name="actual inlet volumetric flow",
    )
    diameter = _finite_number(
        outlet_inside_diameter_m,
        field_name="outlet inside diameter",
    )
    if flow <= 0.0:
        raise ControlValveInputError("actual inlet volumetric flow must be positive")
    if diameter <= 0.0:
        raise ControlValveInputError("outlet inside diameter must be positive")
    if not isinstance(incompressible_flow_confirmed, bool):
        raise ControlValveInputError(
            "incompressible-flow confirmation must be a strict boolean"
        )
    if not incompressible_flow_confirmed:
        raise ControlValveInputError(
            "incompressible flow must be explicitly confirmed for outlet velocity"
        )
    if not isinstance(flashing, bool):
        raise ControlValveInputError("flashing state must be a strict boolean")
    limit = None
    if maximum_outlet_velocity is not None:
        limit = _revalidate_model(
            maximum_outlet_velocity,
            TraceableVelocityLimit,
        )
    try:
        area = pi * diameter**2 / 4.0
    except OverflowError as error:
        raise ControlValveInputError("outlet area could not be calculated") from error
    area = _checked_result(area, field_name="outlet flow area")
    if flashing:
        return LiquidValveVelocityResult(
            outlet_inside_diameter_m=diameter,
            outlet_area_m2=area,
            outlet_velocity_m_s=None,
            supplied_maximum_velocity_m_s=(
                None if limit is None else limit.maximum_velocity_m_s
            ),
            supplied_limit_source_reference=(
                None if limit is None else limit.source_reference
            ),
            within_supplied_limit=None,
            velocity_status=LiquidVelocityStatus.SUPPRESSED_FLASHING,
            warnings=_VELOCITY_FLASHING_WARNINGS,
        )
    try:
        velocity = (flow / 3600.0) / area
    except (OverflowError, ZeroDivisionError) as error:
        raise ControlValveInputError(
            "outlet velocity could not be calculated"
        ) from error
    velocity = _checked_result(velocity, field_name="outlet velocity")
    if limit is None:
        return LiquidValveVelocityResult(
            outlet_inside_diameter_m=diameter,
            outlet_area_m2=area,
            outlet_velocity_m_s=velocity,
            supplied_maximum_velocity_m_s=None,
            supplied_limit_source_reference=None,
            within_supplied_limit=None,
            velocity_status=LiquidVelocityStatus.NOT_ASSESSED,
            warnings=_VELOCITY_NOT_ASSESSED_WARNINGS,
        )
    within = velocity <= limit.maximum_velocity_m_s
    return LiquidValveVelocityResult(
        outlet_inside_diameter_m=diameter,
        outlet_area_m2=area,
        outlet_velocity_m_s=velocity,
        supplied_maximum_velocity_m_s=limit.maximum_velocity_m_s,
        supplied_limit_source_reference=limit.source_reference,
        within_supplied_limit=within,
        velocity_status=(
            LiquidVelocityStatus.WITHIN_SUPPLIED_LIMIT
            if within
            else LiquidVelocityStatus.EXCEEDS_SUPPLIED_LIMIT
        ),
        warnings=() if within else _VELOCITY_EXCEEDS_WARNINGS,
    )


def size_liquid_control_valve(
    sizing_input: LiquidControlValveSizingInput,
) -> LiquidControlValveSizingResult:
    """Calculate preliminary required liquid ``Kv``/``Cv`` and screens."""

    values = _revalidate_model(
        sizing_input,
        LiquidControlValveSizingInput,
    )
    regime = assess_liquid_control_valve_regime(
        pressure_state=values.pressure_state,
        properties=values.properties,
        factors=values.factors,
    )
    velocity = check_liquid_control_valve_velocity(
        actual_volumetric_flow_m3_h=values.actual_volumetric_flow_m3_h,
        outlet_inside_diameter_m=values.outlet_inside_diameter_m,
        incompressible_flow_confirmed=values.incompressible_flow_confirmed,
        flashing=regime.flashing,
        maximum_outlet_velocity=values.maximum_outlet_velocity,
    )
    required_kv = _calculate_required_liquid_kv(values, regime)
    required_cv = convert_kv_to_cv(required_kv)
    pressure_drop_bar = regime.sizing_pressure_drop_pa / 100_000.0
    try:
        reconstructed_flow = (
            required_kv
            * regime.effective_piping_geometry_factor
            * sqrt(pressure_drop_bar / values.properties.specific_gravity)
        )
    except (OverflowError, ValueError) as error:
        raise ControlValveInputError(
            "liquid capacity round-trip could not be evaluated"
        ) from error
    reconstructed_flow = _checked_result(
        reconstructed_flow,
        field_name="reconstructed liquid flow",
    )
    if not isclose(
        reconstructed_flow,
        values.actual_volumetric_flow_m3_h,
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        raise ControlValveCalculationError(
            "required capacity failed its deterministic flow round-trip"
        )
    warnings = tuple(
        dict.fromkeys(
            (
                *regime.warnings,
                *velocity.warnings,
                _PRELIMINARY_RESULT_WARNING,
                _NO_CONFORMITY_WARNING,
            )
        )
    )
    input_fingerprint = fingerprint_control_valve_payload(
        build_liquid_control_valve_input_fingerprint_payload(values)
    )
    result_values: dict[str, object] = {
        "method_id": LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        "method_version": LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        "calculator_version": CONTROL_VALVE_CALCULATORS_VERSION,
        "normalized_input": values,
        "required_kv": required_kv,
        "required_cv": required_cv,
        "regime": regime,
        "velocity": velocity,
        "warnings": warnings,
        "exclusions": _RESULT_EXCLUSIONS,
        "selection_ready": False,
        "independent_review_required": True,
        "manufacturer_selection_performed": False,
        "standards_conformity_claimed": False,
        "calculation_basis": (
            "preliminary turbulent incompressible Newtonian liquid sizing "
            "with traceable factors"
        ),
        "input_fingerprint": input_fingerprint,
    }
    result_fingerprint = fingerprint_control_valve_payload(
        build_liquid_control_valve_result_fingerprint_payload(result_values)
    )
    return LiquidControlValveSizingResult(
        **result_values,
        result_fingerprint=result_fingerprint,
    )


LIQUID_CONTROL_VALVE_SIZING_ADAPTER: Final = ControlValveMethodAdapterMetadata(
    method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    title="Preliminary liquid Cv/Kv sizing with traceable factors",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="size_liquid_control_valve",
    executable=True,
    applicability_boundary=(
        "One turbulent, incompressible, Newtonian, solids-free, single-phase "
        "liquid inlet case with actual inlet volume, negligible density change, "
        "and explicit absolute pressures."
    ),
    factor_policy=(
        "FL, or the coherent installed FP and FLP pair, must be supplied "
        "with traceability for the exact candidate and arrangement; this "
        "method never derives proprietary valve or fitting factors."
    ),
)

IEC_60534_2_1_ADAPTER: Final = ControlValveStandardsAdapterMetadata(
    adapter_id=IEC_60534_2_1_ADAPTER_ID,
    title="IEC 60534-2-1 liquid sizing discovery adapter",
    standard_family="IEC 60534-2-1",
    official_catalog_url="https://webstore.iec.ch/en/publication/2461",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary=(
        "Metadata discovery only. No protected tables, valve or fitting-factor "
        "derivation, installation rules, noise prediction, product selection, "
        "or conformity assessment are executable."
    ),
)

CONTROL_VALVE_EXECUTABLE_ADAPTERS: Final = (LIQUID_CONTROL_VALVE_SIZING_ADAPTER,)
CONTROL_VALVE_METHOD_REGISTRY: Final = MappingProxyType(
    {
        (adapter.method_id, adapter.method_version): adapter
        for adapter in CONTROL_VALVE_EXECUTABLE_ADAPTERS
    }
)
CONTROL_VALVE_METHOD_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        (
            LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
            LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        ): size_liquid_control_valve,
    }
)
if len(CONTROL_VALVE_METHOD_REGISTRY) != len(CONTROL_VALVE_EXECUTABLE_ADAPTERS):
    raise RuntimeError("duplicate exact-version control-valve method registration")
if CONTROL_VALVE_METHOD_REGISTRY.keys() != CONTROL_VALVE_METHOD_IMPLEMENTATIONS.keys():
    raise RuntimeError(
        "control-valve metadata and implementation keys are inconsistent"
    )
if any(
    adapter.implementation_name != CONTROL_VALVE_METHOD_IMPLEMENTATIONS[key].__name__
    for key, adapter in CONTROL_VALVE_METHOD_REGISTRY.items()
):
    raise RuntimeError("control-valve implementation does not match adapter metadata")

CONTROL_VALVE_DISCOVERY_ENTRIES: Final = (IEC_60534_2_1_ADAPTER,)


__all__ = [
    "CONTROL_VALVE_CALCULATORS_VERSION",
    "CONTROL_VALVE_DISCOVERY_ENTRIES",
    "CONTROL_VALVE_EXECUTABLE_ADAPTERS",
    "CONTROL_VALVE_METHOD_IMPLEMENTATIONS",
    "CONTROL_VALVE_METHOD_REGISTRY",
    "CONTROL_VALVE_METHOD_VERSION",
    "CV_PER_KV",
    "IEC_60534_2_1_ADAPTER",
    "IEC_60534_2_1_ADAPTER_ID",
    "KV_PER_CV",
    "LIQUID_CONTROL_VALVE_SIZING_ADAPTER",
    "LIQUID_CONTROL_VALVE_SIZING_METHOD_ID",
    "LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION",
    "ControlValveCalculationError",
    "ControlValveInputError",
    "ControlValveMethodAdapterMetadata",
    "ControlValveStandardsAdapterMetadata",
    "LiquidCavitationStatus",
    "LiquidControlValvePressureState",
    "LiquidControlValveProperties",
    "LiquidControlValveSizingInput",
    "LiquidControlValveSizingResult",
    "LiquidValveFlowRegime",
    "LiquidValveRegimeResult",
    "LiquidValveVelocityResult",
    "LiquidVelocityStatus",
    "TraceableLiquidValveFactors",
    "TraceableVelocityLimit",
    "ValveInstallationBasis",
    "assess_liquid_control_valve_regime",
    "build_liquid_control_valve_input_fingerprint_payload",
    "build_liquid_control_valve_result_fingerprint_payload",
    "canonical_control_valve_fingerprint_bytes",
    "check_liquid_control_valve_velocity",
    "convert_cv_to_kv",
    "convert_kv_to_cv",
    "derive_liquid_critical_pressure_ratio_factor",
    "fingerprint_control_valve_payload",
    "size_liquid_control_valve",
]
