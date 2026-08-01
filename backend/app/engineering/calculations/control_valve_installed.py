"""Installed control-valve candidate screening for Phase 7 Step 101.

The screen consumes already validated liquid or compressible sizing results and
caller-supplied candidate data.  It performs deterministic inverse interpolation
of a traceable travel/Cv curve, checks the declared travel window and capacity
rangeability, and identifies preliminary aerodynamic-noise review priority from
compressible choking and a traceable downstream bulk-Mach calculation.

It does not predict sound pressure level, derive an OEM characteristic, select a
manufacturer or product, or claim conformity with IEC 60534.
"""

from __future__ import annotations

from enum import StrEnum
from itertools import pairwise
from math import isclose, isfinite, pi
from types import MappingProxyType
from typing import Final, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from app.engineering.calculations.control_valve import (
    KV_PER_CV,
    LiquidControlValveSizingResult,
    ValveInstallationBasis,
    fingerprint_control_valve_payload,
)
from app.engineering.calculations.control_valve_compressible import (
    CompressibleControlValveSizingResult,
)
from app.engineering.calculations.models import CalculationModel, MethodLifecycleStatus

CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION: Final = "1.0.0"
CONTROL_VALVE_INSTALLED_METHOD_VERSION: Final = "1.0.0"
INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID: Final = (
    "valve.control.installed.travel-rangeability-aerodynamic-noise.screen.supplied-data"
)
IEC_60534_2_4_ADAPTER_ID: Final = "valve.control.iec-60534-2-4.rangeability-adapter"
IEC_60534_8_3_ADAPTER_ID: Final = (
    "valve.control.iec-60534-8-3.aerodynamic-noise-adapter"
)

_INPUT_SCHEMA: Final = "engineer4me.control-valve.installed-screen-input.v1"
_RESULT_SCHEMA: Final = "engineer4me.control-valve.installed-screen-result.v1"
_COMPRESSIBLE_METHOD_ID: Final = (
    "valve.control.compressible.cv-kv-sizing.supplied-properties-factors"
)
_LIQUID_METHOD_ID: Final = "valve.control.liquid.cv-kv-sizing.supplied-factors"
_RESIDUAL_RELATIVE_TOLERANCE: Final = 1.0e-12
_LIQUID_NOISE_WARNINGS: Final = (
    "Aerodynamic-noise screening is not applicable to liquid flow.",
)
_MISSING_ACOUSTIC_WARNINGS: Final = (
    (
        "No downstream density, sound speed, and pipe geometry were supplied; "
        "no dBA prediction is made."
    ),
)
_MACH_SCREEN_WARNINGS: Final = (
    (
        "This is a bulk-Mach risk indicator, not an aerodynamic "
        "sound-pressure-level prediction."
    ),
)


class InstalledControlValveError(ValueError):
    """Base error for the Step 101 installed-candidate screen."""


class InstalledControlValveInputError(InstalledControlValveError):
    """Raised for incomplete, incoherent, or untraceable screen input."""


def _finite(value: object, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InstalledControlValveInputError(
            f"{field_name} must be a finite real number"
        )
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise InstalledControlValveInputError(
            f"{field_name} must be a finite real number"
        ) from error
    if not isfinite(normalized):
        raise InstalledControlValveInputError(
            f"{field_name} must be a finite real number"
        )
    return 0.0 if normalized == 0.0 else normalized


def _text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise InstalledControlValveInputError(f"{field_name} must be text")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    if value != value.strip():
        raise ValueError(f"{field_name} cannot contain surrounding whitespace")
    return value


def _revalidate(value: object, model_type: type[CalculationModel]):
    if not isinstance(value, model_type):
        raise InstalledControlValveInputError(f"{model_type.__name__} is required")
    try:
        return model_type.model_validate(
            value.model_dump(mode="python", round_trip=True)
        )
    except Exception as error:
        raise InstalledControlValveInputError(
            f"{model_type.__name__} failed validation"
        ) from error


class InstalledCaseRole(StrEnum):
    MINIMUM = "minimum"
    NORMAL = "normal"
    MAXIMUM = "maximum"


class SizingResultKind(StrEnum):
    LIQUID = "liquid"
    COMPRESSIBLE = "compressible"


class CapacityCurveStatus(StrEnum):
    WITHIN_CURVE = "within_curve"
    BELOW_CURVE = "below_curve"
    ABOVE_CURVE = "above_curve"


class TravelWindowStatus(StrEnum):
    WITHIN_SUPPLIED_WINDOW = "within_supplied_window"
    BELOW_MINIMUM_TRAVEL = "below_minimum_travel"
    ABOVE_MAXIMUM_TRAVEL = "above_maximum_travel"
    UNAVAILABLE_OUTSIDE_CURVE = "unavailable_outside_curve"


class RangeabilityStatus(StrEnum):
    WITHIN_SUPPLIED_RANGEABILITY = "within_supplied_rangeability"
    EXCEEDS_SUPPLIED_RANGEABILITY = "exceeds_supplied_rangeability"


class FactorTravelCoherenceStatus(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    NOT_MACHINE_VERIFIABLE_LIQUID = "not_machine_verifiable_liquid"
    UNAVAILABLE_OUTSIDE_CURVE = "unavailable_outside_curve"


class AerodynamicNoisePriority(StrEnum):
    NOT_APPLICABLE_LIQUID = "not_applicable_liquid"
    NOT_ASSESSED = "not_assessed"
    REVIEW_REQUIRED = "review_required"
    HIGH_PRIORITY_REVIEW = "high_priority_review"


class TraceableTravelCapacityPoint(CalculationModel):
    travel_percent: float
    available_cv: float

    @field_validator("travel_percent", "available_cv", mode="before")
    @classmethod
    def validate_numbers(cls, value: object) -> float:
        return _finite(value, field_name="travel-capacity value")

    @model_validator(mode="after")
    def validate_point(self) -> TraceableTravelCapacityPoint:
        if not 0.0 <= self.travel_percent <= 100.0:
            raise ValueError("travel percent must be from zero through 100")
        if self.available_cv <= 0.0:
            raise ValueError("available Cv must be positive")
        return self


class TraceableInstalledValveCandidate(CalculationModel):
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    trim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    installation_context_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    flow_direction: str = Field(min_length=2, max_length=120)
    capacity_curve: tuple[TraceableTravelCapacityPoint, ...] = Field(
        min_length=2, max_length=101
    )
    minimum_controllable_travel_percent: float
    maximum_recommended_travel_percent: float
    declared_inherent_rangeability: float
    maximum_factor_travel_mismatch_percent: float = Field(gt=0.0, le=5.0)
    interpolation_basis: Literal["caller_supplied_piecewise_linear"]
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=10, max_length=1500)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator(
        "minimum_controllable_travel_percent",
        "maximum_recommended_travel_percent",
        "declared_inherent_rangeability",
        "maximum_factor_travel_mismatch_percent",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object) -> float:
        return _finite(value, field_name="candidate numeric value")

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
        return _text(value, field_name="candidate traceability text")

    @model_validator(mode="after")
    def validate_candidate(self) -> TraceableInstalledValveCandidate:
        points = self.capacity_curve
        if any(
            right.travel_percent <= left.travel_percent
            or right.available_cv <= left.available_cv
            for left, right in pairwise(points)
        ):
            raise ValueError("travel and Cv points must be strictly increasing")
        minimum = self.minimum_controllable_travel_percent
        maximum = self.maximum_recommended_travel_percent
        if not 0.0 <= minimum < maximum <= 100.0:
            raise ValueError("travel window must satisfy 0 <= minimum < maximum <= 100")
        if minimum < points[0].travel_percent or maximum > points[-1].travel_percent:
            raise ValueError("capacity curve must cover the complete travel window")
        if self.declared_inherent_rangeability <= 1.0:
            raise ValueError("declared inherent rangeability must exceed one")
        return self


class TraceableMachLimit(CalculationModel):
    maximum_downstream_bulk_mach: float
    source_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=10, max_length=1500)
    supplied_by: str = Field(min_length=2, max_length=200)

    @field_validator("maximum_downstream_bulk_mach", mode="before")
    @classmethod
    def validate_limit(cls, value: object) -> float:
        return _finite(value, field_name="bulk-Mach limit")

    @field_validator(
        "source_reference", "applicable_conditions", "supplied_by", mode="before"
    )
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _text(value, field_name="Mach-limit provenance")

    @model_validator(mode="after")
    def validate_range(self) -> TraceableMachLimit:
        if not 0.0 < self.maximum_downstream_bulk_mach <= 1.0:
            raise ValueError("bulk-Mach limit must be in (0, 1]")
        return self


class TraceableDownstreamAcousticState(CalculationModel):
    sizing_case_id: str
    candidate_id: str
    trim_id: str
    flow_direction: str
    installation_context_id: str
    downstream_density_kg_m3: float
    downstream_speed_of_sound_m_s: float
    downstream_pipe_inside_diameter_m: float
    maximum_bulk_mach: TraceableMachLimit | None = None
    source_reference: str = Field(min_length=3, max_length=500)
    condition_basis: str = Field(min_length=10, max_length=1500)

    @field_validator(
        "downstream_density_kg_m3",
        "downstream_speed_of_sound_m_s",
        "downstream_pipe_inside_diameter_m",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object) -> float:
        return _finite(value, field_name="downstream acoustic-state value")

    @field_validator(
        "sizing_case_id",
        "candidate_id",
        "trim_id",
        "flow_direction",
        "installation_context_id",
        "source_reference",
        "condition_basis",
        mode="before",
    )
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _text(value, field_name="acoustic-state traceability text")

    @model_validator(mode="after")
    def validate_state(self) -> TraceableDownstreamAcousticState:
        if (
            min(
                self.downstream_density_kg_m3,
                self.downstream_speed_of_sound_m_s,
                self.downstream_pipe_inside_diameter_m,
            )
            <= 0.0
        ):
            raise ValueError("downstream acoustic-state values must be positive")
        return self


class InstalledOperatingCase(CalculationModel):
    role: InstalledCaseRole
    sizing_case_id: str
    downstream_acoustic_state: TraceableDownstreamAcousticState | None = None

    @field_validator("sizing_case_id", mode="before")
    @classmethod
    def validate_id(cls, value: object) -> str:
        return _text(value, field_name="sizing case identifier")


class InstalledControlValveScreenRequest(CalculationModel):
    screen_id: str
    candidate: TraceableInstalledValveCandidate
    operating_cases: tuple[InstalledOperatingCase, ...] = Field(
        min_length=3, max_length=3
    )
    candidate_binding_confirmed: StrictBool
    candidate_binding_source_reference: str = Field(min_length=3, max_length=500)

    @field_validator("screen_id", "candidate_binding_source_reference", mode="before")
    @classmethod
    def validate_text(cls, value: object) -> str:
        return _text(value, field_name="installed-screen traceability text")

    @model_validator(mode="after")
    def validate_request(self) -> InstalledControlValveScreenRequest:
        roles = tuple(item.role for item in self.operating_cases)
        if set(roles) != set(InstalledCaseRole) or len(set(roles)) != 3:
            raise ValueError(
                "exactly one minimum, normal, and maximum case is required"
            )
        ids = tuple(item.sizing_case_id for item in self.operating_cases)
        if len(set(ids)) != 3:
            raise ValueError("installed sizing case identifiers must be unique")
        if not self.candidate_binding_confirmed:
            raise ValueError(
                "candidate/factor/curve binding must be explicitly confirmed"
            )
        return self


class SizingResultEvidence(CalculationModel):
    role: InstalledCaseRole
    sizing_kind: SizingResultKind
    fluid_phase: str
    service_identity: str | None
    installation_basis: ValveInstallationBasis
    case_id: str
    method_id: str
    method_version: str
    calculator_version: str
    required_cv: float
    required_kv: float
    flow_value: float
    flow_basis: Literal["actual_inlet_m3_h", "mass_kg_h"]
    choked: StrictBool
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    factor_candidate_id: str | None = None
    factor_trim_id: str | None = None
    factor_installation_context_id: str | None = None
    factor_travel_percent: float | None = None
    factor_flow_direction: str | None = None

    @field_validator(
        "required_cv",
        "required_kv",
        "flow_value",
        "factor_travel_percent",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object):
        if value is None:
            return None
        return _finite(value, field_name="sizing-result evidence value")

    @field_validator(
        "fluid_phase",
        "service_identity",
        "case_id",
        "method_id",
        "method_version",
        "calculator_version",
        "factor_candidate_id",
        "factor_trim_id",
        "factor_installation_context_id",
        "factor_flow_direction",
        mode="before",
    )
    @classmethod
    def validate_text(cls, value: object) -> str | None:
        if value is None:
            return None
        return _text(value, field_name="sizing-result evidence text")

    @model_validator(mode="after")
    def validate_evidence(self) -> SizingResultEvidence:
        if min(self.required_cv, self.required_kv, self.flow_value) <= 0.0:
            raise ValueError("sizing evidence capacities and flow must be positive")
        if not isclose(
            self.required_kv,
            self.required_cv * KV_PER_CV,
            rel_tol=_RESIDUAL_RELATIVE_TOLERANCE,
            abs_tol=0.0,
        ):
            raise ValueError("Cv and Kv sizing evidence are inconsistent")
        context = (
            self.factor_candidate_id,
            self.factor_trim_id,
            self.factor_installation_context_id,
            self.factor_travel_percent,
            self.factor_flow_direction,
        )
        if self.sizing_kind is SizingResultKind.COMPRESSIBLE:
            if any(value is None for value in context):
                raise ValueError("compressible factor context must be complete")
            if (
                self.method_id != _COMPRESSIBLE_METHOD_ID
                or self.method_version != "1.0.0"
                or self.calculator_version != "1.0.0"
                or self.flow_basis != "mass_kg_h"
                or self.fluid_phase not in {"gas", "vapour", "steam"}
                or self.service_identity is None
            ):
                raise ValueError(
                    "compressible sizing evidence identity is inconsistent"
                )
        else:
            if any(value is not None for value in context):
                raise ValueError(
                    "Step 100 liquid evidence has no machine-bound factor context"
                )
            if (
                self.method_id != _LIQUID_METHOD_ID
                or self.method_version != "1.0.0"
                or self.calculator_version != "1.0.0"
                or self.flow_basis != "actual_inlet_m3_h"
                or self.fluid_phase != "liquid"
                or self.service_identity is not None
            ):
                raise ValueError("liquid sizing evidence identity is inconsistent")
        return self


class AerodynamicNoiseScreenResult(CalculationModel):
    priority: AerodynamicNoisePriority
    choked: StrictBool
    downstream_bulk_velocity_m_s: float | None
    downstream_bulk_mach: float | None
    supplied_maximum_bulk_mach: float | None
    within_supplied_mach_limit: StrictBool | None
    sound_pressure_level_predicted: Literal[False] = False
    warnings: tuple[str, ...]

    @field_validator(
        "downstream_bulk_velocity_m_s",
        "downstream_bulk_mach",
        "supplied_maximum_bulk_mach",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite(value, field_name="aerodynamic-noise screen value")

    @model_validator(mode="after")
    def validate_contract(self) -> AerodynamicNoiseScreenResult:
        numeric = (
            self.downstream_bulk_velocity_m_s,
            self.downstream_bulk_mach,
            self.supplied_maximum_bulk_mach,
        )
        if any(value is not None and value <= 0.0 for value in numeric):
            raise ValueError("available velocity, Mach, and limit must be positive")
        if self.priority is AerodynamicNoisePriority.NOT_APPLICABLE_LIQUID:
            if any(value is not None for value in numeric) or (
                self.within_supplied_mach_limit is not None
            ):
                raise ValueError("liquid aerodynamic screen fields are inconsistent")
            if self.warnings != _LIQUID_NOISE_WARNINGS:
                raise ValueError("liquid aerodynamic screen warning is inconsistent")
            return self
        if self.priority is AerodynamicNoisePriority.NOT_ASSESSED or (
            self.priority is AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
            and self.downstream_bulk_mach is None
        ):
            if any(value is not None for value in numeric) or (
                self.within_supplied_mach_limit is not None
            ):
                raise ValueError(
                    "unassessed aerodynamic screen fields are inconsistent"
                )
            if self.priority is AerodynamicNoisePriority.NOT_ASSESSED and self.choked:
                raise ValueError(
                    "a choked unassessed case requires high-priority review"
                )
            if (
                self.priority is AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
                and not self.choked
            ):
                raise ValueError("missing-data high priority requires a choked case")
            if self.warnings != _MISSING_ACOUSTIC_WARNINGS:
                raise ValueError("unassessed aerodynamic warning is inconsistent")
            return self
        if (
            self.downstream_bulk_velocity_m_s is None
            or self.downstream_bulk_mach is None
        ):
            raise ValueError("assessed aerodynamic screen requires velocity and Mach")
        if self.supplied_maximum_bulk_mach is None:
            if self.within_supplied_mach_limit is not None:
                raise ValueError("unsupplied Mach limit cannot have a comparison")
            exceeds = False
        else:
            if self.within_supplied_mach_limit is None:
                raise ValueError("supplied Mach limit requires a comparison")
            expected_within = (
                self.downstream_bulk_mach <= self.supplied_maximum_bulk_mach
            )
            if self.within_supplied_mach_limit is not expected_within:
                raise ValueError("Mach-limit comparison is inconsistent")
            exceeds = not expected_within
        expected_priority = (
            AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
            if self.choked or self.downstream_bulk_mach >= 1.0 or exceeds
            else AerodynamicNoisePriority.REVIEW_REQUIRED
        )
        if self.priority is not expected_priority:
            raise ValueError("aerodynamic review priority is inconsistent")
        if self.warnings != _MACH_SCREEN_WARNINGS:
            raise ValueError("assessed aerodynamic warning is inconsistent")
        return self


class InstalledCaseScreenResult(CalculationModel):
    evidence: SizingResultEvidence
    capacity_curve_status: CapacityCurveStatus
    required_travel_percent: float | None
    travel_window_status: TravelWindowStatus
    available_cv_at_required_travel: float | None
    capacity_residual_cv: float | None
    relative_capacity_residual: float | None
    inverse_solution_verified: StrictBool
    inverse_solution_method: Literal["direct_piecewise_linear_inverse"]
    inverse_iteration_count: Literal[0] = 0
    factor_travel_coherence_status: FactorTravelCoherenceStatus
    factor_travel_difference_percent: float | None
    aerodynamic_noise: AerodynamicNoiseScreenResult
    warnings: tuple[str, ...]

    @field_validator(
        "required_travel_percent",
        "available_cv_at_required_travel",
        "capacity_residual_cv",
        "relative_capacity_residual",
        "factor_travel_difference_percent",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object) -> float | None:
        if value is None:
            return None
        return _finite(value, field_name="installed case-screen value")

    @model_validator(mode="after")
    def validate_contract(self) -> InstalledCaseScreenResult:
        if self.aerodynamic_noise.choked is not self.evidence.choked:
            raise ValueError("case and aerodynamic choking evidence disagree")
        if self.capacity_curve_status is not CapacityCurveStatus.WITHIN_CURVE:
            unavailable = (
                self.required_travel_percent,
                self.available_cv_at_required_travel,
                self.capacity_residual_cv,
                self.relative_capacity_residual,
            )
            if any(value is not None for value in unavailable):
                raise ValueError("outside-curve case cannot claim an inverse solution")
            if self.inverse_solution_verified:
                raise ValueError("outside-curve inverse cannot be verified")
            if (
                self.travel_window_status
                is not TravelWindowStatus.UNAVAILABLE_OUTSIDE_CURVE
            ):
                raise ValueError("outside-curve travel status is inconsistent")
            return self
        if (
            self.required_travel_percent is None
            or self.available_cv_at_required_travel is None
            or self.capacity_residual_cv is None
            or self.relative_capacity_residual is None
        ):
            raise ValueError("within-curve inverse evidence is incomplete")
        if not 0.0 <= self.required_travel_percent <= 100.0:
            raise ValueError("required travel must be from zero through 100")
        if self.available_cv_at_required_travel <= 0.0:
            raise ValueError("available Cv must be positive")
        expected_residual = (
            self.available_cv_at_required_travel - self.evidence.required_cv
        )
        expected_relative = abs(expected_residual) / self.evidence.required_cv
        if (
            self.capacity_residual_cv != expected_residual
            or self.relative_capacity_residual != expected_relative
        ):
            raise ValueError("inverse residual evidence is inconsistent")
        expected_verified = expected_relative <= _RESIDUAL_RELATIVE_TOLERANCE
        if self.inverse_solution_verified is not expected_verified:
            raise ValueError("inverse convergence evidence is inconsistent")
        if self.factor_travel_difference_percent is not None and (
            self.factor_travel_difference_percent < 0.0
        ):
            raise ValueError("factor-travel difference cannot be negative")
        return self


class InstalledRangeabilityResult(CalculationModel):
    required_capacity_ratio: float
    curve_window_capacity_ratio: float
    declared_inherent_rangeability: float
    effective_supplied_rangeability: float
    status: RangeabilityStatus

    @field_validator(
        "required_capacity_ratio",
        "curve_window_capacity_ratio",
        "declared_inherent_rangeability",
        "effective_supplied_rangeability",
        mode="before",
    )
    @classmethod
    def validate_numbers(cls, value: object) -> float:
        return _finite(value, field_name="installed rangeability result")

    @model_validator(mode="after")
    def validate_contract(self) -> InstalledRangeabilityResult:
        values = (
            self.required_capacity_ratio,
            self.curve_window_capacity_ratio,
            self.declared_inherent_rangeability,
            self.effective_supplied_rangeability,
        )
        if any(value <= 0.0 for value in values):
            raise ValueError("rangeability ratios must be positive")
        expected_effective = min(
            self.curve_window_capacity_ratio,
            self.declared_inherent_rangeability,
        )
        if self.effective_supplied_rangeability != expected_effective:
            raise ValueError("effective supplied rangeability is inconsistent")
        expected_status = (
            RangeabilityStatus.WITHIN_SUPPLIED_RANGEABILITY
            if self.required_capacity_ratio <= expected_effective
            else RangeabilityStatus.EXCEEDS_SUPPLIED_RANGEABILITY
        )
        if self.status is not expected_status:
            raise ValueError("rangeability status is inconsistent")
        return self


class InstalledControlValveScreenResult(CalculationModel):
    method_id: Literal[INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID]
    method_version: Literal[CONTROL_VALVE_INSTALLED_METHOD_VERSION]
    calculator_version: Literal[CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION]
    normalized_request: InstalledControlValveScreenRequest
    normalized_sizing_results: tuple[
        LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...
    ] = Field(min_length=3, max_length=3)
    sizing_evidence: tuple[SizingResultEvidence, ...]
    case_results: tuple[InstalledCaseScreenResult, ...]
    rangeability: InstalledRangeabilityResult
    candidate_capacity_and_travel_screen_passed: StrictBool
    selection_ready: Literal[False] = False
    independent_review_required: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    sound_pressure_level_predicted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    warnings: tuple[str, ...]
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_fingerprints(self) -> InstalledControlValveScreenResult:
        expected_values = _derive_installed_screen_values(
            self.normalized_request,
            self.normalized_sizing_results,
        )
        reproducible_fields = (
            "normalized_sizing_results",
            "sizing_evidence",
            "case_results",
            "rangeability",
            "candidate_capacity_and_travel_screen_passed",
            "warnings",
        )
        if any(
            getattr(self, field_name) != expected_values[field_name]
            for field_name in reproducible_fields
        ):
            raise ValueError("installed-screen result is not reproducible")
        expected_input = _input_fingerprint(
            self.normalized_request,
            self.normalized_sizing_results,
        )
        if self.input_fingerprint != expected_input:
            raise ValueError("installed-screen input fingerprint is stale")
        expected_result = fingerprint_control_valve_payload(
            _result_fingerprint_payload(self)
        )
        if self.result_fingerprint != expected_result:
            raise ValueError("installed-screen result fingerprint is stale")
        return self


class InstalledControlValveMethodMetadata(CalculationModel):
    method_id: str
    method_version: str
    lifecycle_status: Literal[MethodLifecycleStatus.APPROVED]
    implementation_name: str
    executable: Literal[True]
    standards_conformity_claimed: Literal[False] = False


class InstalledControlValveStandardsMetadata(CalculationModel):
    adapter_id: str
    standard_family: str
    official_catalog_url: str
    lifecycle_status: Literal[MethodLifecycleStatus.STANDARDS_REVIEW]
    executable: Literal[False]
    conformity_claimed: Literal[False]
    boundary: str


def _capacity_at_travel(
    points: tuple[TraceableTravelCapacityPoint, ...], travel: float
) -> float:
    for point in points:
        if travel == point.travel_percent:
            return point.available_cv
    for left, right in pairwise(points):
        if left.travel_percent < travel < right.travel_percent:
            fraction = (travel - left.travel_percent) / (
                right.travel_percent - left.travel_percent
            )
            return left.available_cv + fraction * (
                right.available_cv - left.available_cv
            )
    raise InstalledControlValveInputError("travel is outside the supplied curve")


def _inverse_capacity(
    candidate: TraceableInstalledValveCandidate, required_cv: float
) -> tuple[CapacityCurveStatus, float | None, float | None, float | None]:
    points = candidate.capacity_curve
    if required_cv < points[0].available_cv:
        return (CapacityCurveStatus.BELOW_CURVE, None, None, None)
    if required_cv > points[-1].available_cv:
        return (CapacityCurveStatus.ABOVE_CURVE, None, None, None)
    for point in points:
        if required_cv == point.available_cv:
            return (
                CapacityCurveStatus.WITHIN_CURVE,
                point.travel_percent,
                required_cv,
                0.0,
            )
    for left, right in pairwise(points):
        if left.available_cv < required_cv < right.available_cv:
            fraction = (required_cv - left.available_cv) / (
                right.available_cv - left.available_cv
            )
            travel = left.travel_percent + fraction * (
                right.travel_percent - left.travel_percent
            )
            achieved = _capacity_at_travel(points, travel)
            residual = achieved - required_cv
            relative = abs(residual) / required_cv
            if relative > _RESIDUAL_RELATIVE_TOLERANCE:
                raise InstalledControlValveError(
                    "direct travel inverse failed its forward residual check"
                )
            return (CapacityCurveStatus.WITHIN_CURVE, travel, achieved, relative)
    raise InstalledControlValveError("required Cv was not bracketed by the curve")


def _extract_evidence(
    role: InstalledCaseRole,
    result: LiquidControlValveSizingResult | CompressibleControlValveSizingResult,
) -> SizingResultEvidence:
    if isinstance(result, LiquidControlValveSizingResult):
        value = _revalidate(result, LiquidControlValveSizingResult)
        return SizingResultEvidence(
            role=role,
            sizing_kind=SizingResultKind.LIQUID,
            fluid_phase="liquid",
            service_identity=None,
            installation_basis=value.normalized_input.factors.installation_basis,
            case_id=value.normalized_input.case_id,
            method_id=value.method_id,
            method_version=value.method_version,
            calculator_version=value.calculator_version,
            required_cv=value.required_cv,
            required_kv=value.required_kv,
            flow_value=value.normalized_input.actual_volumetric_flow_m3_h,
            flow_basis="actual_inlet_m3_h",
            choked=value.regime.choked,
            input_fingerprint=value.input_fingerprint,
            result_fingerprint=value.result_fingerprint,
        )
    if isinstance(result, CompressibleControlValveSizingResult):
        value = _revalidate(result, CompressibleControlValveSizingResult)
        if value.method_id != _COMPRESSIBLE_METHOD_ID:
            raise InstalledControlValveInputError(
                "unsupported compressible method identity"
            )
        factors = value.normalized_input.factors
        return SizingResultEvidence(
            role=role,
            sizing_kind=SizingResultKind.COMPRESSIBLE,
            fluid_phase=value.normalized_input.properties.fluid_phase.value,
            service_identity=value.normalized_input.properties.fluid_identity,
            installation_basis=factors.installation_basis,
            case_id=value.normalized_input.case_id,
            method_id=value.method_id,
            method_version=value.method_version,
            calculator_version=value.calculator_version,
            required_cv=value.required_cv,
            required_kv=value.required_kv,
            flow_value=value.normalized_input.mass_flow_kg_h,
            flow_basis="mass_kg_h",
            choked=value.regime.choked,
            input_fingerprint=value.input_fingerprint,
            result_fingerprint=value.result_fingerprint,
            factor_candidate_id=factors.candidate_id,
            factor_trim_id=factors.trim_id,
            factor_installation_context_id=factors.installation_context_id,
            factor_travel_percent=factors.travel_percent,
            factor_flow_direction=factors.flow_direction,
        )
    raise InstalledControlValveInputError(
        "a validated liquid or compressible sizing result is required"
    )


def _noise_screen(
    evidence: SizingResultEvidence,
    acoustic: TraceableDownstreamAcousticState | None,
    candidate: TraceableInstalledValveCandidate,
) -> AerodynamicNoiseScreenResult:
    if evidence.sizing_kind is SizingResultKind.LIQUID:
        if acoustic is not None:
            raise InstalledControlValveInputError(
                "aerodynamic acoustic state cannot be attached to a liquid case"
            )
        return AerodynamicNoiseScreenResult(
            priority=AerodynamicNoisePriority.NOT_APPLICABLE_LIQUID,
            choked=evidence.choked,
            downstream_bulk_velocity_m_s=None,
            downstream_bulk_mach=None,
            supplied_maximum_bulk_mach=None,
            within_supplied_mach_limit=None,
            warnings=_LIQUID_NOISE_WARNINGS,
        )
    if acoustic is None:
        return AerodynamicNoiseScreenResult(
            priority=(
                AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
                if evidence.choked
                else AerodynamicNoisePriority.NOT_ASSESSED
            ),
            choked=evidence.choked,
            downstream_bulk_velocity_m_s=None,
            downstream_bulk_mach=None,
            supplied_maximum_bulk_mach=None,
            within_supplied_mach_limit=None,
            warnings=_MISSING_ACOUSTIC_WARNINGS,
        )
    state = _revalidate(acoustic, TraceableDownstreamAcousticState)
    if (
        state.sizing_case_id != evidence.case_id
        or state.candidate_id != candidate.candidate_id
        or state.trim_id != candidate.trim_id
        or state.flow_direction != candidate.flow_direction
        or state.installation_context_id != candidate.installation_context_id
    ):
        raise InstalledControlValveInputError(
            "acoustic state case/candidate/trim/direction/context does not match "
            "the screened operating case"
        )
    mass_flow_kg_s = evidence.flow_value / 3600.0
    try:
        area = pi * state.downstream_pipe_inside_diameter_m**2 / 4.0
        mass_denominator = state.downstream_density_kg_m3 * area
        if (
            not isfinite(area)
            or area <= 0.0
            or not isfinite(mass_denominator)
            or mass_denominator <= 0.0
        ):
            raise InstalledControlValveInputError(
                "downstream geometry/density cannot form a finite positive flow area"
            )
        velocity = mass_flow_kg_s / mass_denominator
        mach = velocity / state.downstream_speed_of_sound_m_s
    except (OverflowError, ZeroDivisionError) as error:
        raise InstalledControlValveInputError(
            "bulk velocity/Mach could not be evaluated"
        ) from error
    if not isfinite(velocity) or not isfinite(mach) or velocity <= 0.0 or mach <= 0.0:
        raise InstalledControlValveInputError(
            "bulk velocity/Mach could not be calculated"
        )
    limit = state.maximum_bulk_mach
    within = None if limit is None else mach <= limit.maximum_downstream_bulk_mach
    priority = (
        AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW
        if evidence.choked or mach >= 1.0 or within is False
        else AerodynamicNoisePriority.REVIEW_REQUIRED
    )
    return AerodynamicNoiseScreenResult(
        priority=priority,
        choked=evidence.choked,
        downstream_bulk_velocity_m_s=velocity,
        downstream_bulk_mach=mach,
        supplied_maximum_bulk_mach=(
            None if limit is None else limit.maximum_downstream_bulk_mach
        ),
        within_supplied_mach_limit=within,
        warnings=_MACH_SCREEN_WARNINGS,
    )


def _input_fingerprint(
    request: InstalledControlValveScreenRequest,
    sizing_results: tuple[
        LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...
    ],
) -> str:
    return fingerprint_control_valve_payload(
        {
            "schema": _INPUT_SCHEMA,
            "calculator_version": CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION,
            "method_id": INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
            "method_version": CONTROL_VALVE_INSTALLED_METHOD_VERSION,
            "request": request.model_dump(mode="json", round_trip=True),
            "sizing_results": [
                item.model_dump(mode="json", round_trip=True) for item in sizing_results
            ],
        }
    )


def _result_fingerprint_payload(result: InstalledControlValveScreenResult | dict):
    values = (
        result.model_dump(mode="json", round_trip=True, exclude={"result_fingerprint"})
        if isinstance(result, InstalledControlValveScreenResult)
        else {
            key: value for key, value in result.items() if key != "result_fingerprint"
        }
    )
    return {"schema": _RESULT_SCHEMA, "result": values}


def _normalize_and_order_sizing_results(
    request: InstalledControlValveScreenRequest,
    sizing_results: tuple[
        LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...
    ],
) -> tuple[
    tuple[InstalledOperatingCase, ...],
    tuple[LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...],
    tuple[SizingResultEvidence, ...],
]:
    if not isinstance(sizing_results, tuple) or len(sizing_results) != 3:
        raise InstalledControlValveInputError(
            "exactly three sizing results are required"
        )
    result_by_id: dict[
        str, LiquidControlValveSizingResult | CompressibleControlValveSizingResult
    ] = {}
    for result in sizing_results:
        if isinstance(result, LiquidControlValveSizingResult):
            normalized = _revalidate(result, LiquidControlValveSizingResult)
        elif isinstance(result, CompressibleControlValveSizingResult):
            normalized = _revalidate(result, CompressibleControlValveSizingResult)
        else:
            raise InstalledControlValveInputError(
                "each sizing result must be a validated liquid or compressible result"
            )
        case_id = normalized.normalized_input.case_id
        if case_id in result_by_id:
            raise InstalledControlValveInputError(
                "sizing result case identities must be unique"
            )
        result_by_id[case_id] = normalized
    ordered_cases = tuple(
        sorted(
            request.operating_cases,
            key=lambda item: list(InstalledCaseRole).index(item.role),
        )
    )
    try:
        ordered_results = tuple(
            result_by_id[item.sizing_case_id] for item in ordered_cases
        )
    except KeyError as error:
        raise InstalledControlValveInputError(
            "each installed case must reference one supplied sizing result"
        ) from error
    if len(result_by_id) != len(ordered_results):
        raise InstalledControlValveInputError(
            "unreferenced sizing results are not permitted"
        )
    evidence = tuple(
        _extract_evidence(configuration.role, result)
        for configuration, result in zip(
            ordered_cases,
            ordered_results,
            strict=True,
        )
    )
    if (
        len({item.sizing_kind for item in evidence}) != 1
        or len({item.fluid_phase for item in evidence}) != 1
    ):
        raise InstalledControlValveInputError(
            "all installed cases must use one service phase and sizing kind"
        )
    if len({item.installation_basis for item in evidence}) != 1:
        raise InstalledControlValveInputError(
            "all installed cases must use one valve installation basis"
        )
    if evidence[0].sizing_kind is SizingResultKind.COMPRESSIBLE and (
        len({item.service_identity for item in evidence}) != 1
        or len({item.factor_installation_context_id for item in evidence}) != 1
    ):
        raise InstalledControlValveInputError(
            "all compressible cases must use one fluid identity and installation context"
        )
    if not evidence[0].flow_value < evidence[1].flow_value < evidence[2].flow_value:
        raise InstalledControlValveInputError(
            "minimum, normal, and maximum flow must be strictly increasing"
        )
    return (ordered_cases, ordered_results, evidence)


def _derive_installed_screen_values(
    request: InstalledControlValveScreenRequest,
    sizing_results: tuple[
        LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...
    ],
) -> dict[str, object]:
    """Derive every non-fingerprint output from fully revalidated inputs."""

    values = _revalidate(request, InstalledControlValveScreenRequest)
    ordered_cases, ordered_results, evidence = _normalize_and_order_sizing_results(
        values,
        sizing_results,
    )

    candidate = values.candidate
    case_results: list[InstalledCaseScreenResult] = []
    for configuration, item in zip(ordered_cases, evidence, strict=True):
        if item.sizing_kind is SizingResultKind.COMPRESSIBLE and (
            item.factor_candidate_id != candidate.candidate_id
            or item.factor_trim_id != candidate.trim_id
            or item.factor_installation_context_id != candidate.installation_context_id
            or item.factor_flow_direction != candidate.flow_direction
        ):
            raise InstalledControlValveInputError(
                "compressible sizing factor context does not match candidate"
            )
        status, travel, achieved, relative_residual = _inverse_capacity(
            candidate,
            item.required_cv,
        )
        if travel is None:
            travel_status = TravelWindowStatus.UNAVAILABLE_OUTSIDE_CURVE
            verified = False
            coherence = (
                FactorTravelCoherenceStatus.NOT_MACHINE_VERIFIABLE_LIQUID
                if item.sizing_kind is SizingResultKind.LIQUID
                else FactorTravelCoherenceStatus.UNAVAILABLE_OUTSIDE_CURVE
            )
            difference = None
        else:
            travel_status = (
                TravelWindowStatus.BELOW_MINIMUM_TRAVEL
                if travel < candidate.minimum_controllable_travel_percent
                else TravelWindowStatus.ABOVE_MAXIMUM_TRAVEL
                if travel > candidate.maximum_recommended_travel_percent
                else TravelWindowStatus.WITHIN_SUPPLIED_WINDOW
            )
            verified = (
                relative_residual is not None
                and relative_residual <= _RESIDUAL_RELATIVE_TOLERANCE
            )
            if item.sizing_kind is SizingResultKind.LIQUID:
                coherence = FactorTravelCoherenceStatus.NOT_MACHINE_VERIFIABLE_LIQUID
                difference = None
            else:
                if item.factor_travel_percent is None:  # pragma: no cover
                    raise InstalledControlValveError(
                        "validated compressible factor travel is unavailable"
                    )
                difference = abs(travel - item.factor_travel_percent)
                coherence = (
                    FactorTravelCoherenceStatus.MATCHED
                    if difference <= candidate.maximum_factor_travel_mismatch_percent
                    else FactorTravelCoherenceStatus.MISMATCHED
                )
        noise = _noise_screen(item, configuration.downstream_acoustic_state, candidate)
        warnings = tuple(
            filter(
                None,
                (
                    (
                        "Required capacity lies outside the supplied curve; no "
                        "extrapolation was performed."
                    )
                    if travel is None
                    else "",
                    (
                        "Required travel is outside the caller-supplied "
                        "controllable window."
                    )
                    if travel_status is not TravelWindowStatus.WITHIN_SUPPLIED_WINDOW
                    else "",
                    (
                        "Step 100 liquid factors have no machine-readable "
                        "candidate/travel identity; supplied binding requires review."
                    )
                    if coherence
                    is FactorTravelCoherenceStatus.NOT_MACHINE_VERIFIABLE_LIQUID
                    else "",
                    "Sizing-factor travel and curve-derived travel do not agree."
                    if coherence is FactorTravelCoherenceStatus.MISMATCHED
                    else "",
                ),
            )
        )
        case_results.append(
            InstalledCaseScreenResult(
                evidence=item,
                capacity_curve_status=status,
                required_travel_percent=travel,
                travel_window_status=travel_status,
                available_cv_at_required_travel=achieved,
                capacity_residual_cv=(
                    None if achieved is None else achieved - item.required_cv
                ),
                relative_capacity_residual=relative_residual,
                inverse_solution_verified=verified,
                inverse_solution_method="direct_piecewise_linear_inverse",
                factor_travel_coherence_status=coherence,
                factor_travel_difference_percent=difference,
                aerodynamic_noise=noise,
                warnings=warnings,
            )
        )
    case_tuple = tuple(case_results)
    required_ratio = max(item.required_cv for item in evidence) / min(
        item.required_cv for item in evidence
    )
    curve_min = _capacity_at_travel(
        candidate.capacity_curve,
        candidate.minimum_controllable_travel_percent,
    )
    curve_max = _capacity_at_travel(
        candidate.capacity_curve,
        candidate.maximum_recommended_travel_percent,
    )
    curve_ratio = curve_max / curve_min
    effective = min(curve_ratio, candidate.declared_inherent_rangeability)
    range_status = (
        RangeabilityStatus.WITHIN_SUPPLIED_RANGEABILITY
        if required_ratio <= effective
        else RangeabilityStatus.EXCEEDS_SUPPLIED_RANGEABILITY
    )
    rangeability = InstalledRangeabilityResult(
        required_capacity_ratio=required_ratio,
        curve_window_capacity_ratio=curve_ratio,
        declared_inherent_rangeability=candidate.declared_inherent_rangeability,
        effective_supplied_rangeability=effective,
        status=range_status,
    )
    passed = (
        range_status is RangeabilityStatus.WITHIN_SUPPLIED_RANGEABILITY
        and all(item.inverse_solution_verified for item in case_tuple)
        and all(
            item.travel_window_status is TravelWindowStatus.WITHIN_SUPPLIED_WINDOW
            for item in case_tuple
        )
        and all(
            item.factor_travel_coherence_status is FactorTravelCoherenceStatus.MATCHED
            for item in case_tuple
        )
    )
    warnings = (
        "Installed travel and rangeability are screened only against caller-supplied candidate data.",
        "No sound-pressure level, final valve selection, manufacturer ranking, or standards conformity is produced.",
    )
    return {
        "method_id": INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        "method_version": CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        "calculator_version": CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION,
        "normalized_request": values,
        "normalized_sizing_results": ordered_results,
        "sizing_evidence": evidence,
        "case_results": case_tuple,
        "rangeability": rangeability,
        "candidate_capacity_and_travel_screen_passed": passed,
        "selection_ready": False,
        "independent_review_required": True,
        "manufacturer_selection_performed": False,
        "sound_pressure_level_predicted": False,
        "standards_conformity_claimed": False,
        "warnings": warnings,
    }


def evaluate_installed_control_valve_scenarios(
    request: InstalledControlValveScreenRequest,
    sizing_results: tuple[
        LiquidControlValveSizingResult | CompressibleControlValveSizingResult, ...
    ],
) -> InstalledControlValveScreenResult:
    """Evaluate one traceable candidate against exact min/normal/max cases."""

    result_values = _derive_installed_screen_values(request, sizing_results)
    normalized_request = result_values["normalized_request"]
    normalized_sizing_results = result_values["normalized_sizing_results"]
    if not isinstance(normalized_request, InstalledControlValveScreenRequest):
        raise InstalledControlValveError("normalized installed request is invalid")
    if not isinstance(normalized_sizing_results, tuple):  # pragma: no cover
        raise InstalledControlValveError("normalized sizing results are invalid")
    input_fingerprint = _input_fingerprint(
        normalized_request,
        normalized_sizing_results,
    )
    result_values["input_fingerprint"] = input_fingerprint
    result_fingerprint = fingerprint_control_valve_payload(
        _result_fingerprint_payload(result_values)
    )
    return InstalledControlValveScreenResult(
        **result_values, result_fingerprint=result_fingerprint
    )


INSTALLED_CONTROL_VALVE_SCREEN_ADAPTER: Final = InstalledControlValveMethodMetadata(
    method_id=INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    method_version=CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    lifecycle_status=MethodLifecycleStatus.APPROVED,
    implementation_name="evaluate_installed_control_valve_scenarios",
    executable=True,
)
INSTALLED_CONTROL_VALVE_METHOD_REGISTRY: Final = MappingProxyType(
    {
        (
            INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
            CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        ): INSTALLED_CONTROL_VALVE_SCREEN_ADAPTER
    }
)
INSTALLED_CONTROL_VALVE_METHOD_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        (
            INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
            CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        ): evaluate_installed_control_valve_scenarios
    }
)

IEC_60534_2_4_ADAPTER: Final = InstalledControlValveStandardsMetadata(
    adapter_id=IEC_60534_2_4_ADAPTER_ID,
    standard_family="IEC 60534-2-4",
    official_catalog_url="https://webstore.iec.ch/en/publication/2463",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary="Metadata only; no protected characteristic, tolerance, or rangeability rule is executable.",
)
IEC_60534_8_3_ADAPTER: Final = InstalledControlValveStandardsMetadata(
    adapter_id=IEC_60534_8_3_ADAPTER_ID,
    standard_family="IEC 60534-8-3",
    official_catalog_url="https://webstore.iec.ch/en/publication/2474",
    lifecycle_status=MethodLifecycleStatus.STANDARDS_REVIEW,
    executable=False,
    conformity_claimed=False,
    boundary="Metadata only; no aerodynamic sound-pressure-level prediction or conformity assessment is executable.",
)
INSTALLED_CONTROL_VALVE_DISCOVERY_ENTRIES: Final = (
    IEC_60534_2_4_ADAPTER,
    IEC_60534_8_3_ADAPTER,
)


__all__ = [
    "CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION",
    "CONTROL_VALVE_INSTALLED_METHOD_VERSION",
    "IEC_60534_2_4_ADAPTER",
    "IEC_60534_2_4_ADAPTER_ID",
    "IEC_60534_8_3_ADAPTER",
    "IEC_60534_8_3_ADAPTER_ID",
    "INSTALLED_CONTROL_VALVE_DISCOVERY_ENTRIES",
    "INSTALLED_CONTROL_VALVE_METHOD_IMPLEMENTATIONS",
    "INSTALLED_CONTROL_VALVE_METHOD_REGISTRY",
    "INSTALLED_CONTROL_VALVE_SCREEN_ADAPTER",
    "INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID",
    "AerodynamicNoisePriority",
    "AerodynamicNoiseScreenResult",
    "CapacityCurveStatus",
    "FactorTravelCoherenceStatus",
    "InstalledCaseRole",
    "InstalledCaseScreenResult",
    "InstalledControlValveError",
    "InstalledControlValveInputError",
    "InstalledControlValveMethodMetadata",
    "InstalledControlValveScreenRequest",
    "InstalledControlValveScreenResult",
    "InstalledControlValveStandardsMetadata",
    "InstalledOperatingCase",
    "InstalledRangeabilityResult",
    "RangeabilityStatus",
    "SizingResultEvidence",
    "SizingResultKind",
    "TraceableDownstreamAcousticState",
    "TraceableInstalledValveCandidate",
    "TraceableMachLimit",
    "TraceableTravelCapacityPoint",
    "TravelWindowStatus",
    "evaluate_installed_control_valve_scenarios",
]
