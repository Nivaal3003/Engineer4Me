"""Fail-closed gas, vapour, and eligible-steam valve sizing for Step 101.

The executable method in this module is a deterministic preliminary capacity
calculation for fully turbulent, single-phase compressible flow.  It uses the
public density-form control-valve equation with explicit absolute pressures
and caller-supplied, traceable ``xT`` or coherent installed ``FP``/``xTP``
factors.  Dry-saturated and demonstrably superheated ordinary-water steam are
eligible; wet, entrained-liquid, desuperheating, and other two-phase services
fail closed.

The method does not derive proprietary valve factors, predict sound pressure,
select a valve or manufacturer, or claim conformity with IEC 60534.  The IEC
record at the bottom of the module is discovery metadata only.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from math import isclose, isfinite, sqrt
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from app.engineering.calculations.control_valve import (
    ControlValveCalculationError,
    ControlValveInputError,
    ControlValveMethodAdapterMetadata,
    ControlValveStandardsAdapterMetadata,
    ValveInstallationBasis,
    convert_cv_to_kv,
)
from app.engineering.calculations.models import CalculationModel, MethodLifecycleStatus

COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION: Final = "1.0.0"
COMPRESSIBLE_CONTROL_VALVE_METHOD_VERSION: Final = "1.0.0"
COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID: Final = (
    "valve.control.compressible.cv-kv-sizing.supplied-properties-factors"
)
COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION: Final = "1.0.0"
IEC_60534_2_1_COMPRESSIBLE_ADAPTER_ID: Final = (
    "valve.control.iec-60534-2-1.compressible-sizing-adapter"
)

_INPUT_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.control-valve.compressible-sizing-input.v1"
)
_RESULT_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.control-valve.compressible-sizing-result.v1"
)
_MASS_CAPACITY_CONSTANT: Final = 27.3
_ORDINARY_WATER_TRIPLE_TEMPERATURE_K: Final = 273.16
_ORDINARY_WATER_CRITICAL_TEMPERATURE_K: Final = 647.096
_ORDINARY_WATER_TRIPLE_PRESSURE_PA: Final = 611.657
_ORDINARY_WATER_CRITICAL_PRESSURE_PA: Final = 22_064_000.0

_CHOKED_WARNINGS: Final = (
    (
        "The pressure-drop ratio is at or above the supplied terminal ratio; "
        "capacity is choked and does not increase with lower downstream pressure."
    ),
    (
        "Choked compressible service requires competent severe-service and "
        "aerodynamic-noise review."
    ),
)
_SUBCRITICAL_WARNINGS: Final = (
    (
        "Subcritical capacity does not establish acceptable aerodynamic noise, "
        "vibration, erosion, or installed performance."
    ),
)
_PRELIMINARY_WARNING: Final = (
    "This result is preliminary capacity-sizing support and is not final valve, "
    "trim, material, actuator, or brand selection."
)
_NO_CONFORMITY_WARNING: Final = "No standards-conformity claim is made."
_RESULT_EXCLUSIONS: Final = (
    "wet steam, entrained liquid, condensation, flashing, and two-phase flow",
    "laminar flow, nonhomogeneous composition, solids, and reacting service",
    (
        "aerodynamic sound-pressure prediction, vibration, erosion, materials, "
        "actuator, leakage, and pressure-rating selection"
    ),
    (
        "proprietary factor derivation, installed travel prediction, manufacturer "
        "ranking, product selection, and standards conformity"
    ),
)


class CompressibleFluidPhase(StrEnum):
    """Eligible single-phase compressible fluid classifications."""

    GAS = "gas"
    VAPOUR = "vapour"
    STEAM = "steam"


class EligibleSteamState(StrEnum):
    """Steam states admitted by this preliminary method."""

    DRY_SATURATED = "dry_saturated"
    SUPERHEATED = "superheated"


class CompressibleValveFlowRegime(StrEnum):
    """Pressure-ratio regime at the supplied factor condition."""

    SUBCRITICAL = "subcritical"
    CHOKED = "choked"


def _finite_number(value: object, *, field_name: str) -> float:
    """Return a strict finite float without accepting booleans or strings."""

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
    return 0.0 if normalized == 0.0 else normalized


def _positive_result(value: object, *, field_name: str) -> float:
    normalized = _finite_number(value, field_name=field_name)
    if normalized <= 0.0:
        raise ControlValveInputError(f"{field_name} must remain finite and positive")
    return normalized


def _strict_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ControlValveInputError(f"{field_name} must be text")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    if value != value.strip():
        raise ValueError(f"{field_name} cannot contain surrounding whitespace")
    return value


def _revalidate_model(value: object, model_type: type[CalculationModel]) -> Any:
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


class TraceableCompressibleValveFactors(CalculationModel):
    """Supplied factors tied to one candidate, trim, travel, and arrangement."""

    candidate_id: str = Field(min_length=2, max_length=160)
    trim_id: str = Field(min_length=2, max_length=160)
    installation_context_id: str = Field(min_length=2, max_length=160)
    travel_percent: float
    flow_direction: str = Field(min_length=2, max_length=160)
    installation_basis: ValveInstallationBasis
    bare_valve_pressure_drop_ratio_factor: float | None = None
    piping_geometry_factor: float | None = None
    installed_pressure_drop_ratio_factor: float | None = None
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=10, max_length=1500)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator(
        "candidate_id",
        "trim_id",
        "installation_context_id",
        "flow_direction",
        "source_reference",
        "applicable_conditions",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _strict_text(value, field_name="compressible-factor provenance")

    @field_validator(
        "travel_percent",
        "bare_valve_pressure_drop_ratio_factor",
        "piping_geometry_factor",
        "installed_pressure_drop_ratio_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_factors(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite_number(value, field_name="compressible valve factor")

    @model_validator(mode="after")
    def validate_arrangement(self) -> TraceableCompressibleValveFactors:
        if self.travel_percent <= 0.0 or self.travel_percent > 100.0:
            raise ValueError("factor travel must be in (0, 100]")
        if self.installation_basis is ValveInstallationBasis.BARE_VALVE:
            x_t = self.bare_valve_pressure_drop_ratio_factor
            if x_t is None:
                raise ValueError("bare-valve service requires supplied xT")
            if (
                self.piping_geometry_factor is not None
                or self.installed_pressure_drop_ratio_factor is not None
            ):
                raise ValueError("bare-valve service cannot supply FP or xTP")
            if x_t <= 0.0 or x_t > 0.84:
                raise ValueError("bare-valve xT must be in (0, 0.84]")
            return self

        if self.bare_valve_pressure_drop_ratio_factor is not None:
            raise ValueError("installed service cannot supply bare-valve xT")
        if (
            self.piping_geometry_factor is None
            or self.installed_pressure_drop_ratio_factor is None
        ):
            raise ValueError("installed service requires coherent supplied FP and xTP")
        if self.piping_geometry_factor <= 0.0 or self.piping_geometry_factor > 1.0:
            raise ValueError("installed FP must be in (0, 1]")
        if (
            self.installed_pressure_drop_ratio_factor <= 0.0
            or self.installed_pressure_drop_ratio_factor > 0.84
        ):
            raise ValueError("installed xTP must be in (0, 0.84]")
        return self

    def effective_factors(self) -> tuple[float, float]:
        """Return effective ``FP`` and ``xT/xTP`` without deriving either."""

        if self.installation_basis is ValveInstallationBasis.BARE_VALVE:
            x_t = self.bare_valve_pressure_drop_ratio_factor
            if x_t is None:  # pragma: no cover - model validation guards this
                raise ControlValveInputError("validated bare-valve xT is missing")
            return (1.0, x_t)
        f_p = self.piping_geometry_factor
        x_tp = self.installed_pressure_drop_ratio_factor
        if f_p is None or x_tp is None:  # pragma: no cover
            raise ControlValveInputError("validated installed factors are missing")
        return (f_p, x_tp)


class CompressibleControlValvePressureState(CalculationModel):
    """One simultaneous upstream/downstream absolute-pressure state."""

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
        return _finite_number(value, field_name="compressible absolute pressure")

    @field_validator("pressure_source_reference", "condition_basis", mode="before")
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _strict_text(value, field_name="pressure-state provenance")

    @model_validator(mode="after")
    def validate_pressure_order(self) -> CompressibleControlValvePressureState:
        if self.downstream_pressure_absolute_pa <= 0.0:
            raise ValueError("downstream absolute pressure must be positive")
        if self.upstream_pressure_absolute_pa <= self.downstream_pressure_absolute_pa:
            raise ValueError(
                "upstream absolute pressure must exceed downstream pressure"
            )
        return self


class CompressibleFlowingProperties(CalculationModel):
    """Traceable properties at the declared compressible-flow conditions."""

    fluid_phase: CompressibleFluidPhase
    fluid_identity: str = Field(min_length=2, max_length=240)
    upstream_temperature_k: float
    upstream_density_kg_m3: float
    isentropic_exponent: float
    compressibility_factor: float
    molecular_mass_kg_kmol: float
    property_source_reference: str = Field(min_length=3, max_length=500)
    condition_basis: str = Field(min_length=10, max_length=1500)
    steam_state: EligibleSteamState | None = None
    steam_quality_fraction: float | None = None
    saturation_temperature_k: float | None = None
    saturation_pressure_absolute_pa: float | None = None
    state_uncertainty_k: float | None = None
    state_pressure_uncertainty_pa: float | None = None
    saturation_state_pair_confirmed: StrictBool | None = None
    entrained_liquid_absent_confirmed: StrictBool | None = None

    @field_validator(
        "upstream_temperature_k",
        "upstream_density_kg_m3",
        "isentropic_exponent",
        "compressibility_factor",
        "molecular_mass_kg_kmol",
        "steam_quality_fraction",
        "saturation_temperature_k",
        "saturation_pressure_absolute_pa",
        "state_uncertainty_k",
        "state_pressure_uncertainty_pa",
        mode="before",
    )
    @classmethod
    def validate_raw_properties(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite_number(value, field_name="compressible fluid property")

    @field_validator(
        "fluid_identity",
        "property_source_reference",
        "condition_basis",
        mode="before",
    )
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _strict_text(value, field_name="fluid-property provenance")

    @model_validator(mode="after")
    def validate_properties(self) -> CompressibleFlowingProperties:
        positive = (
            self.upstream_temperature_k,
            self.upstream_density_kg_m3,
            self.compressibility_factor,
            self.molecular_mass_kg_kmol,
        )
        if any(value <= 0.0 for value in positive):
            raise ValueError(
                "temperature, density, Z, and molecular mass must be positive"
            )
        if self.isentropic_exponent <= 1.0 or self.isentropic_exponent > 1.67:
            raise ValueError("isentropic exponent must be in (1, 1.67]")
        steam_fields = (
            self.steam_state,
            self.steam_quality_fraction,
            self.saturation_temperature_k,
            self.saturation_pressure_absolute_pa,
            self.state_uncertainty_k,
            self.state_pressure_uncertainty_pa,
            self.saturation_state_pair_confirmed,
            self.entrained_liquid_absent_confirmed,
        )
        if self.fluid_phase is not CompressibleFluidPhase.STEAM:
            if any(value is not None for value in steam_fields):
                raise ValueError(
                    "non-steam properties cannot include steam-state fields"
                )
            return self

        if self.isentropic_exponent > 1.4:
            raise ValueError("eligible steam isentropic exponent cannot exceed 1.4")
        if self.steam_state is None:
            raise ValueError("steam requires an eligible declared steam state")
        if (
            self.saturation_temperature_k is None
            or self.saturation_pressure_absolute_pa is None
            or self.state_uncertainty_k is None
            or self.state_pressure_uncertainty_pa is None
        ):
            raise ValueError(
                "steam requires saturation temperature, saturation pressure, "
                "and their uncertainties"
            )
        if self.state_uncertainty_k < 0.0 or self.state_pressure_uncertainty_pa < 0.0:
            raise ValueError("steam state uncertainties cannot be negative")
        if not (
            _ORDINARY_WATER_TRIPLE_TEMPERATURE_K
            <= self.saturation_temperature_k
            < _ORDINARY_WATER_CRITICAL_TEMPERATURE_K
        ):
            raise ValueError(
                "eligible steam saturation temperature must remain between the "
                "ordinary-water triple and critical temperatures"
            )
        if not (
            _ORDINARY_WATER_TRIPLE_PRESSURE_PA
            <= self.saturation_pressure_absolute_pa
            < _ORDINARY_WATER_CRITICAL_PRESSURE_PA
        ):
            raise ValueError(
                "eligible steam saturation pressure must remain between the "
                "ordinary-water triple and critical pressures"
            )
        if self.entrained_liquid_absent_confirmed is not True:
            raise ValueError("eligible steam requires absence of entrained liquid")
        if self.saturation_state_pair_confirmed is not True:
            raise ValueError(
                "eligible steam requires confirmed saturation temperature/pressure "
                "pair coherence"
            )
        if self.steam_state is EligibleSteamState.DRY_SATURATED:
            if self.steam_quality_fraction != 1.0:
                raise ValueError("dry-saturated steam requires quality exactly 1")
            if (
                abs(self.upstream_temperature_k - self.saturation_temperature_k)
                > self.state_uncertainty_k
            ):
                raise ValueError(
                    "dry-saturated steam temperature is outside uncertainty"
                )
            return self
        if self.steam_quality_fraction is not None:
            raise ValueError("superheated steam cannot supply a saturation quality")
        if (
            self.upstream_temperature_k - self.saturation_temperature_k
            <= self.state_uncertainty_k
        ):
            raise ValueError("superheat margin must exceed the supplied uncertainty")
        return self


def _validate_compressible_applicability(
    *,
    pressure_state: CompressibleControlValvePressureState,
    properties: CompressibleFlowingProperties,
    factors: TraceableCompressibleValveFactors,
) -> None:
    """Enforce cross-record factor and steam-state coherence."""

    f_gamma = properties.isentropic_exponent / 1.4
    _, x_t_effective = factors.effective_factors()
    if f_gamma * x_t_effective > 1.0:
        raise ValueError("supplied factors make the terminal pressure ratio exceed 1")
    if properties.fluid_phase is not CompressibleFluidPhase.STEAM:
        return
    if (
        pressure_state.upstream_pressure_absolute_pa
        >= _ORDINARY_WATER_CRITICAL_PRESSURE_PA
    ):
        raise ValueError(
            "eligible dry-saturated or superheated steam must remain below "
            "the ordinary-water critical pressure"
        )
    saturation_pressure = properties.saturation_pressure_absolute_pa
    pressure_uncertainty = properties.state_pressure_uncertainty_pa
    if saturation_pressure is None or pressure_uncertainty is None:  # pragma: no cover
        raise ValueError("validated steam saturation-pressure evidence is missing")
    if (
        abs(pressure_state.upstream_pressure_absolute_pa - saturation_pressure)
        > pressure_uncertainty
    ):
        raise ValueError(
            "declared steam saturation pressure is not coherent with upstream P1"
        )


class CompressibleControlValveSizingInput(CalculationModel):
    """Complete strict input for one preliminary compressible sizing case."""

    case_id: str = Field(
        min_length=2,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    )
    mass_flow_kg_h: float
    mass_flow_source_reference: str = Field(min_length=3, max_length=500)
    flow_condition_basis: str = Field(min_length=10, max_length=1500)
    pressure_state: CompressibleControlValvePressureState
    properties: CompressibleFlowingProperties
    factors: TraceableCompressibleValveFactors
    turbulent_flow_confirmed: StrictBool
    homogeneous_composition_confirmed: StrictBool
    single_phase_inlet_confirmed: StrictBool
    single_phase_outlet_confirmed: StrictBool
    no_condensation_or_phase_change_confirmed: StrictBool
    property_state_aligned_confirmed: StrictBool

    @field_validator("mass_flow_kg_h", mode="before")
    @classmethod
    def validate_raw_flow(cls, value: object) -> float:
        return _finite_number(value, field_name="compressible mass flow")

    @field_validator(
        "case_id",
        "mass_flow_source_reference",
        "flow_condition_basis",
        mode="before",
    )
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _strict_text(value, field_name="compressible sizing provenance")

    @model_validator(mode="after")
    def validate_case(self) -> CompressibleControlValveSizingInput:
        if self.mass_flow_kg_h <= 0.0:
            raise ValueError("mass flow must be positive")
        confirmations = (
            self.turbulent_flow_confirmed,
            self.homogeneous_composition_confirmed,
            self.single_phase_inlet_confirmed,
            self.single_phase_outlet_confirmed,
            self.no_condensation_or_phase_change_confirmed,
            self.property_state_aligned_confirmed,
        )
        if not all(confirmations):
            raise ValueError(
                "turbulent, homogeneous, single-phase, no-phase-change, and "
                "property-state applicability must be explicitly confirmed"
            )
        _validate_compressible_applicability(
            pressure_state=self.pressure_state,
            properties=self.properties,
            factors=self.factors,
        )
        return self


class CompressibleValveRegimeResult(CalculationModel):
    """Expansion-factor and terminal pressure-ratio result."""

    actual_pressure_drop_pa: float
    actual_pressure_drop_ratio: float
    specific_heat_ratio_factor: float
    effective_piping_geometry_factor: float
    effective_pressure_drop_ratio_factor: float
    terminal_pressure_drop_ratio: float
    sizing_pressure_drop_ratio: float
    sizing_pressure_drop_pa: float
    choking_ratio_margin: float
    choking_index: float
    expansion_factor: float
    flow_regime: CompressibleValveFlowRegime
    choked: StrictBool
    warnings: tuple[str, ...]
    standards_conformity_claimed: Literal[False] = False

    @field_validator(
        "actual_pressure_drop_pa",
        "actual_pressure_drop_ratio",
        "specific_heat_ratio_factor",
        "effective_piping_geometry_factor",
        "effective_pressure_drop_ratio_factor",
        "terminal_pressure_drop_ratio",
        "sizing_pressure_drop_ratio",
        "sizing_pressure_drop_pa",
        "choking_ratio_margin",
        "choking_index",
        "expansion_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_values(cls, value: object) -> float:
        return _finite_number(value, field_name="compressible regime result")

    @model_validator(mode="after")
    def validate_contract(self) -> CompressibleValveRegimeResult:
        if self.actual_pressure_drop_pa <= 0.0 or self.sizing_pressure_drop_pa <= 0.0:
            raise ValueError("compressible pressure drops must be positive")
        if not 0.0 < self.actual_pressure_drop_ratio < 1.0:
            raise ValueError("actual pressure-drop ratio must be in (0, 1)")
        if not 0.0 < self.terminal_pressure_drop_ratio <= 1.0:
            raise ValueError("terminal pressure-drop ratio must be in (0, 1]")
        if not 1.0 / 1.4 < self.specific_heat_ratio_factor <= 1.67 / 1.4:
            raise ValueError("specific-heat-ratio factor is outside applicability")
        if not 0.0 < self.effective_piping_geometry_factor <= 1.0:
            raise ValueError("effective FP must be in (0, 1]")
        if not 0.0 < self.effective_pressure_drop_ratio_factor <= 0.84:
            raise ValueError("effective xT/xTP must be in (0, 0.84]")
        if self.terminal_pressure_drop_ratio != (
            self.specific_heat_ratio_factor * self.effective_pressure_drop_ratio_factor
        ):
            raise ValueError("terminal pressure-drop ratio is inconsistent")
        expected_sizing = min(
            self.actual_pressure_drop_ratio,
            self.terminal_pressure_drop_ratio,
        )
        if self.sizing_pressure_drop_ratio != expected_sizing:
            raise ValueError("compressible sizing pressure ratio is inconsistent")
        inferred_p1_from_actual = (
            self.actual_pressure_drop_pa / self.actual_pressure_drop_ratio
        )
        inferred_p1_from_sizing = (
            self.sizing_pressure_drop_pa / self.sizing_pressure_drop_ratio
        )
        if not isclose(
            inferred_p1_from_actual,
            inferred_p1_from_sizing,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("compressible sizing pressure drop is inconsistent")
        if self.choking_ratio_margin != (
            self.terminal_pressure_drop_ratio - self.actual_pressure_drop_ratio
        ):
            raise ValueError("compressible choking margin is inconsistent")
        if self.choking_index != (
            self.actual_pressure_drop_ratio / self.terminal_pressure_drop_ratio
        ):
            raise ValueError("compressible choking index is inconsistent")
        expected_choked = (
            self.actual_pressure_drop_ratio >= self.terminal_pressure_drop_ratio
        )
        expected_regime = (
            CompressibleValveFlowRegime.CHOKED
            if expected_choked
            else CompressibleValveFlowRegime.SUBCRITICAL
        )
        if (
            self.choked is not expected_choked
            or self.flow_regime is not expected_regime
        ):
            raise ValueError("compressible regime classification is inconsistent")
        expected_y = 1.0 - (expected_sizing / (3.0 * self.terminal_pressure_drop_ratio))
        if self.expansion_factor != expected_y or not 2.0 / 3.0 <= expected_y < 1.0:
            raise ValueError("compressible expansion factor is inconsistent")
        expected_warnings = (
            _CHOKED_WARNINGS if expected_choked else _SUBCRITICAL_WARNINGS
        )
        if self.warnings != expected_warnings:
            raise ValueError("compressible regime warnings are inconsistent")
        return self


class CompressibleControlValveSizingResult(CalculationModel):
    """Self-validating preliminary compressible capacity result."""

    method_id: Literal[
        "valve.control.compressible.cv-kv-sizing.supplied-properties-factors"
    ] = COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID
    method_version: Literal["1.0.0"] = COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION
    calculator_version: Literal["1.0.0"] = (
        COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION
    )
    normalized_input: CompressibleControlValveSizingInput
    required_cv: float
    required_kv: float
    reconstructed_mass_flow_kg_h: float
    relative_round_trip_residual: float
    regime: CompressibleValveRegimeResult
    warnings: tuple[str, ...]
    exclusions: tuple[str, ...]
    selection_ready: Literal[False] = False
    independent_review_required: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    calculation_basis: Literal[
        "preliminary density-form turbulent single-phase compressible sizing with supplied factors"
    ] = "preliminary density-form turbulent single-phase compressible sizing with supplied factors"
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "required_cv",
        "required_kv",
        "reconstructed_mass_flow_kg_h",
        "relative_round_trip_residual",
        mode="before",
    )
    @classmethod
    def validate_raw_values(cls, value: object) -> float:
        return _finite_number(value, field_name="compressible sizing result")

    @model_validator(mode="after")
    def validate_result_contract(self) -> CompressibleControlValveSizingResult:
        if (
            self.required_cv <= 0.0
            or self.required_kv <= 0.0
            or self.reconstructed_mass_flow_kg_h <= 0.0
            or self.relative_round_trip_residual < 0.0
        ):
            raise ValueError("compressible capacity and residual fields are invalid")
        expected_regime = assess_compressible_control_valve_regime(
            pressure_state=self.normalized_input.pressure_state,
            properties=self.normalized_input.properties,
            factors=self.normalized_input.factors,
        )
        if self.regime != expected_regime:
            raise ValueError("compressible regime result is not reproducible")
        expected_cv = _calculate_required_cv(self.normalized_input, expected_regime)
        expected_kv = convert_cv_to_kv(expected_cv)
        expected_mass = _reconstruct_mass_flow(
            expected_cv,
            self.normalized_input,
            expected_regime,
        )
        expected_residual = (
            abs(expected_mass - self.normalized_input.mass_flow_kg_h)
            / self.normalized_input.mass_flow_kg_h
        )
        if (
            self.required_cv != expected_cv
            or self.required_kv != expected_kv
            or self.reconstructed_mass_flow_kg_h != expected_mass
            or self.relative_round_trip_residual != expected_residual
        ):
            raise ValueError("compressible capacity result is not reproducible")
        if expected_residual > 1e-12:
            raise ValueError("compressible capacity round-trip residual is excessive")
        expected_warnings = tuple(
            dict.fromkeys(
                (
                    *expected_regime.warnings,
                    _PRELIMINARY_WARNING,
                    _NO_CONFORMITY_WARNING,
                )
            )
        )
        if self.warnings != expected_warnings or self.exclusions != _RESULT_EXCLUSIONS:
            raise ValueError(
                "compressible result warnings or exclusions are inconsistent"
            )
        expected_input = fingerprint_compressible_control_valve_payload(
            build_compressible_control_valve_input_fingerprint_payload(
                self.normalized_input
            )
        )
        if self.input_fingerprint != expected_input:
            raise ValueError("compressible input fingerprint is stale")
        expected_result = fingerprint_compressible_control_valve_payload(
            build_compressible_control_valve_result_fingerprint_payload(self)
        )
        if self.result_fingerprint != expected_result:
            raise ValueError("compressible result fingerprint is stale")
        return self


def _canonicalize(value: object) -> object:
    if isinstance(value, CalculationModel):
        return _canonicalize(value.model_dump(mode="json", round_trip=True))
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ControlValveInputError("fingerprint mapping keys must be strings")
        return {key: _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, float):
        if not isfinite(value):
            raise ControlValveInputError("fingerprint payload contains non-finite data")
        return 0.0 if value == 0.0 else value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ControlValveInputError(
        f"unsupported compressible fingerprint value: {type(value).__name__}"
    )


def canonical_compressible_control_valve_fingerprint_bytes(
    payload: object,
) -> bytes:
    try:
        text = json.dumps(
            _canonicalize(payload),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise ControlValveInputError(
            "compressible fingerprint payload is not canonicalizable"
        ) from error
    return text.encode("utf-8")


def fingerprint_compressible_control_valve_payload(payload: object) -> str:
    return sha256(
        canonical_compressible_control_valve_fingerprint_bytes(payload)
    ).hexdigest()


def build_compressible_control_valve_input_fingerprint_payload(
    sizing_input: CompressibleControlValveSizingInput,
) -> dict[str, object]:
    values = _revalidate_model(sizing_input, CompressibleControlValveSizingInput)
    return {
        "schema": _INPUT_FINGERPRINT_SCHEMA,
        "calculator_version": COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION,
        "method_id": COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        "method_version": COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        "input": values.model_dump(mode="json", round_trip=True),
    }


def build_compressible_control_valve_result_fingerprint_payload(
    result: CompressibleControlValveSizingResult | Mapping[str, object],
) -> dict[str, object]:
    if isinstance(result, CompressibleControlValveSizingResult):
        values: dict[str, object] = result.model_dump(
            mode="json", round_trip=True, exclude={"result_fingerprint"}
        )
    elif isinstance(result, Mapping):
        values = dict(result)
        values.pop("result_fingerprint", None)
    else:
        raise ControlValveInputError(
            "validated compressible sizing result or mapping is required"
        )
    return {"schema": _RESULT_FINGERPRINT_SCHEMA, "result": values}


def assess_compressible_control_valve_regime(
    *,
    pressure_state: CompressibleControlValvePressureState,
    properties: CompressibleFlowingProperties,
    factors: TraceableCompressibleValveFactors,
) -> CompressibleValveRegimeResult:
    """Calculate the supplied-factor terminal ratio and expansion factor."""

    pressures = _revalidate_model(pressure_state, CompressibleControlValvePressureState)
    fluid = _revalidate_model(properties, CompressibleFlowingProperties)
    supplied = _revalidate_model(factors, TraceableCompressibleValveFactors)
    try:
        _validate_compressible_applicability(
            pressure_state=pressures,
            properties=fluid,
            factors=supplied,
        )
    except ValueError as error:
        raise ControlValveInputError(str(error)) from error
    p1 = pressures.upstream_pressure_absolute_pa
    actual_drop = _positive_result(
        p1 - pressures.downstream_pressure_absolute_pa,
        field_name="actual compressible pressure drop",
    )
    x_actual = _positive_result(
        actual_drop / p1,
        field_name="actual compressible pressure-drop ratio",
    )
    f_gamma = _positive_result(
        fluid.isentropic_exponent / 1.4,
        field_name="specific-heat-ratio factor",
    )
    f_p, x_t_effective = supplied.effective_factors()
    x_terminal = _positive_result(
        f_gamma * x_t_effective,
        field_name="terminal compressible pressure-drop ratio",
    )
    if x_terminal > 1.0:
        raise ControlValveInputError("terminal pressure-drop ratio cannot exceed 1")
    x_sizing = min(x_actual, x_terminal)
    choked = x_actual >= x_terminal
    y = _positive_result(
        1.0 - x_sizing / (3.0 * x_terminal),
        field_name="compressible expansion factor",
    )
    return CompressibleValveRegimeResult(
        actual_pressure_drop_pa=actual_drop,
        actual_pressure_drop_ratio=x_actual,
        specific_heat_ratio_factor=f_gamma,
        effective_piping_geometry_factor=f_p,
        effective_pressure_drop_ratio_factor=x_t_effective,
        terminal_pressure_drop_ratio=x_terminal,
        sizing_pressure_drop_ratio=x_sizing,
        sizing_pressure_drop_pa=x_sizing * p1,
        choking_ratio_margin=x_terminal - x_actual,
        choking_index=x_actual / x_terminal,
        expansion_factor=y,
        flow_regime=(
            CompressibleValveFlowRegime.CHOKED
            if choked
            else CompressibleValveFlowRegime.SUBCRITICAL
        ),
        choked=choked,
        warnings=_CHOKED_WARNINGS if choked else _SUBCRITICAL_WARNINGS,
        standards_conformity_claimed=False,
    )


def _calculate_required_cv(
    values: CompressibleControlValveSizingInput,
    regime: CompressibleValveRegimeResult,
) -> float:
    p1_bar_absolute = values.pressure_state.upstream_pressure_absolute_pa / 100_000.0
    try:
        denominator = (
            _MASS_CAPACITY_CONSTANT
            * regime.effective_piping_geometry_factor
            * regime.expansion_factor
            * sqrt(
                regime.sizing_pressure_drop_ratio
                * p1_bar_absolute
                * values.properties.upstream_density_kg_m3
            )
        )
        required_cv = values.mass_flow_kg_h / denominator
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise ControlValveInputError(
            "compressible capacity could not be evaluated"
        ) from error
    return _positive_result(required_cv, field_name="required compressible Cv")


def _reconstruct_mass_flow(
    cv: float,
    values: CompressibleControlValveSizingInput,
    regime: CompressibleValveRegimeResult,
) -> float:
    p1_bar_absolute = values.pressure_state.upstream_pressure_absolute_pa / 100_000.0
    try:
        mass_flow = (
            cv
            * _MASS_CAPACITY_CONSTANT
            * regime.effective_piping_geometry_factor
            * regime.expansion_factor
            * sqrt(
                regime.sizing_pressure_drop_ratio
                * p1_bar_absolute
                * values.properties.upstream_density_kg_m3
            )
        )
    except (OverflowError, ValueError) as error:
        raise ControlValveInputError(
            "compressible capacity round-trip could not be evaluated"
        ) from error
    return _positive_result(mass_flow, field_name="reconstructed compressible flow")


def size_compressible_control_valve(
    sizing_input: CompressibleControlValveSizingInput,
) -> CompressibleControlValveSizingResult:
    """Calculate required ``Cv``/``Kv`` for one eligible compressible case."""

    values = _revalidate_model(sizing_input, CompressibleControlValveSizingInput)
    regime = assess_compressible_control_valve_regime(
        pressure_state=values.pressure_state,
        properties=values.properties,
        factors=values.factors,
    )
    required_cv = _calculate_required_cv(values, regime)
    required_kv = convert_cv_to_kv(required_cv)
    reconstructed_mass = _reconstruct_mass_flow(required_cv, values, regime)
    residual = abs(reconstructed_mass - values.mass_flow_kg_h) / values.mass_flow_kg_h
    if not isclose(reconstructed_mass, values.mass_flow_kg_h, rel_tol=1e-12):
        raise ControlValveCalculationError(
            "required compressible capacity failed its deterministic flow round-trip"
        )
    warnings = tuple(
        dict.fromkeys((*regime.warnings, _PRELIMINARY_WARNING, _NO_CONFORMITY_WARNING))
    )
    input_fingerprint = fingerprint_compressible_control_valve_payload(
        build_compressible_control_valve_input_fingerprint_payload(values)
    )
    result_values: dict[str, object] = {
        "method_id": COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        "method_version": COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        "calculator_version": COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION,
        "normalized_input": values,
        "required_cv": required_cv,
        "required_kv": required_kv,
        "reconstructed_mass_flow_kg_h": reconstructed_mass,
        "relative_round_trip_residual": residual,
        "regime": regime,
        "warnings": warnings,
        "exclusions": _RESULT_EXCLUSIONS,
        "selection_ready": False,
        "independent_review_required": True,
        "manufacturer_selection_performed": False,
        "standards_conformity_claimed": False,
        "calculation_basis": (
            "preliminary density-form turbulent single-phase compressible sizing "
            "with supplied factors"
        ),
        "input_fingerprint": input_fingerprint,
    }
    result_fingerprint = fingerprint_compressible_control_valve_payload(
        build_compressible_control_valve_result_fingerprint_payload(result_values)
    )
    return CompressibleControlValveSizingResult(
        **result_values,
        result_fingerprint=result_fingerprint,
    )


COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER: Final = ControlValveMethodAdapterMetadata(
    method_id=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
    method_version=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
    title="Preliminary gas, vapour, and eligible-steam Cv/Kv sizing",
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="size_compressible_control_valve",
    executable=True,
    applicability_boundary=(
        "One fully turbulent, homogeneous, single-phase gas, vapour, dry-saturated "
        "steam, or demonstrably superheated steam case with absolute pressures, "
        "mass flow, and inlet density at the declared flowing state."
    ),
    factor_policy=(
        "The exact candidate's xT, or coherent installed FP and xTP, must be "
        "caller supplied with valve, trim, travel, direction, condition, and "
        "source traceability; no proprietary factor is inferred or derived."
    ),
)

IEC_60534_2_1_COMPRESSIBLE_ADAPTER: Final = ControlValveStandardsAdapterMetadata(
    adapter_id=IEC_60534_2_1_COMPRESSIBLE_ADAPTER_ID,
    title="IEC 60534-2-1 compressible sizing discovery adapter",
    standard_family="IEC 60534-2-1",
    official_catalog_url="https://webstore.iec.ch/en/publication/2461",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary=(
        "Metadata discovery only. No protected tables, factor derivation, "
        "installation rules, acoustic prediction, product selection, or "
        "conformity assessment are executable."
    ),
)

COMPRESSIBLE_CONTROL_VALVE_EXECUTABLE_ADAPTERS: Final = (
    COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER,
)
COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY: Final = MappingProxyType(
    {
        (adapter.method_id, adapter.method_version): adapter
        for adapter in COMPRESSIBLE_CONTROL_VALVE_EXECUTABLE_ADAPTERS
    }
)
COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        (
            COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
            COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        ): size_compressible_control_valve,
    }
)
if (
    COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY.keys()
    != COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS.keys()
):
    raise RuntimeError("compressible control-valve registries are inconsistent")

COMPRESSIBLE_CONTROL_VALVE_DISCOVERY_ENTRIES: Final = (
    IEC_60534_2_1_COMPRESSIBLE_ADAPTER,
)


__all__ = [
    "COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION",
    "COMPRESSIBLE_CONTROL_VALVE_DISCOVERY_ENTRIES",
    "COMPRESSIBLE_CONTROL_VALVE_EXECUTABLE_ADAPTERS",
    "COMPRESSIBLE_CONTROL_VALVE_METHOD_IMPLEMENTATIONS",
    "COMPRESSIBLE_CONTROL_VALVE_METHOD_REGISTRY",
    "COMPRESSIBLE_CONTROL_VALVE_METHOD_VERSION",
    "COMPRESSIBLE_CONTROL_VALVE_SIZING_ADAPTER",
    "COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID",
    "COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION",
    "IEC_60534_2_1_COMPRESSIBLE_ADAPTER",
    "IEC_60534_2_1_COMPRESSIBLE_ADAPTER_ID",
    "CompressibleControlValvePressureState",
    "CompressibleControlValveSizingInput",
    "CompressibleControlValveSizingResult",
    "CompressibleFlowingProperties",
    "CompressibleFluidPhase",
    "CompressibleValveFlowRegime",
    "CompressibleValveRegimeResult",
    "EligibleSteamState",
    "TraceableCompressibleValveFactors",
    "assess_compressible_control_valve_regime",
    "build_compressible_control_valve_input_fingerprint_payload",
    "build_compressible_control_valve_result_fingerprint_payload",
    "canonical_compressible_control_valve_fingerprint_bytes",
    "fingerprint_compressible_control_valve_payload",
    "size_compressible_control_valve",
]
