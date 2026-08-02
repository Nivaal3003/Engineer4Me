"""Generic pressure-relief required-area methods for Phase 7 Step 104.

The three methods in this module calculate only a preliminary required flow
area for one explicitly selected, already documented relief scenario.  They
use independently derived SI equations and caller-supplied traceable capacity
coefficients.  They do not implement API 520/521 or ISO 4126, reproduce
protected tables, choose a lettered or nominal orifice, select a device or
manufacturer, or claim standards conformity.

Execution is layered over the byte-preserved Step 103 readiness gate.  Every
critical Step 103 input must be complete, and its sole remaining finding must
be the exact ``no approved method`` placeholder.  Step 104 replaces only that
placeholder with one exact-version approved generic method authorization.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from math import exp, expm1, isclose, isfinite, log, log1p, pi, sqrt
from types import MappingProxyType
from typing import Annotated, Any, Final, Literal

from pydantic import BeforeValidator, Field, field_validator, model_validator

from app.engineering.calculations.models import (
    CalculationModel,
    CalculationStatus,
    MethodLifecycleStatus,
)
from app.engineering.calculations.pressure_relief import (
    PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY,
    PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY,
    PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,
    PressureReliefFluidPhase,
    PressureReliefPressureBasisKind,
    PressureReliefReadinessRequest,
    PressureReliefSafetyGateResult,
    PressureReliefScenarioBasis,
    assess_pressure_relief_readiness,
    fingerprint_pressure_relief_readiness,
)

PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION: Final = "1.0.0"
PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION: Final = "1.0.0"

LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: Final = (
    "pressure-relief.liquid.required-area.supplied-factors"
)
GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: Final = (
    "pressure-relief.gas-vapour.required-area.supplied-factors"
)
ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: Final = (
    "pressure-relief.eligible-steam.required-area.supplied-factors"
)

LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION: Final = "1.0.0"
GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION: Final = "1.0.0"
ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION: Final = "1.0.0"

UNIVERSAL_GAS_CONSTANT_J_KMOL_K: Final = 8314.46261815324
WATER_CRITICAL_PRESSURE_PA: Final = 22_064_000.0

_INPUT_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.pressure-relief.required-area-input.v1"
)
_RESULT_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.pressure-relief.required-area-result.v1"
)
_MAX_PRESSURE_PA: Final = 1.0e12
_MAX_AREA_M2: Final = 1.0e6
_ROUND_TRIP_REL_TOL: Final = 1.0e-12

_COMMON_WARNINGS: Final = (
    (
        "The calculated area is preliminary engineering decision support; "
        "it is not a rated or selected device area."
    ),
    (
        "A competent pressure-systems engineer must independently review the "
        "scenario, load, coefficients, installation, disposal system, and result."
    ),
    (
        "No API, ISO, jurisdictional, manufacturer, or product conformity claim "
        "is made by this generic calculation."
    ),
)
_COMMON_EXCLUSIONS: Final = (
    "lettered or nominal orifice rounding and device selection",
    "certified capacity, tolerance, accumulation, installation, and inlet-loss review",
    "materials, reaction forces, noise, disposal-system, and backpressure design",
    "manufacturer, brand, product, model, and final controlling-scenario selection",
    "standards, legal, site-authority, and conformity approval",
)


class PressureReliefRequiredAreaError(ValueError):
    """Base error for the Step 104 required-area boundary."""


class PressureReliefRequiredAreaInputError(PressureReliefRequiredAreaError):
    """Raised for invalid, inapplicable, or untraceable Step 104 inputs."""


class PressureReliefRequiredAreaBlockedError(PressureReliefRequiredAreaError):
    """Raised without arithmetic when a Step 103 blocking finding remains."""

    def __init__(self, gate_result: PressureReliefSafetyGateResult) -> None:
        self.gate_result = gate_result
        finding_ids = ", ".join(
            finding.finding_id for finding in gate_result.blocking_findings
        )
        super().__init__(f"pressure-relief readiness is blocked: {finding_ids}")


def _strict_text(value: object, *, field_name: str) -> str:
    """Require caller text to be nonblank and already trimmed."""

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be text")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    if value != value.strip():
        raise ValueError(f"{field_name} cannot contain surrounding whitespace")
    return value


def _finite_number(value: object, *, field_name: str) -> float:
    """Return a finite non-boolean float without string coercion."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be a finite real number")
    normalized = float(value)
    if not isfinite(normalized):
        raise ValueError(f"{field_name} must be a finite real number")
    return 0.0 if normalized == 0.0 else normalized


def _require_exact_true(value: object) -> Literal[True]:
    """Reject truthy substitutes for explicit safety confirmations."""

    if value is not True:
        raise ValueError("an explicit boolean true confirmation is required")
    return True


def _require_exact_false(value: object) -> Literal[False]:
    """Reject falsy substitutes for explicit fail-closed result flags."""

    if value is not False:
        raise ValueError("an explicit boolean false value is required")
    return False


_ExactTrue = Annotated[Literal[True], BeforeValidator(_require_exact_true)]
_ExactFalse = Annotated[Literal[False], BeforeValidator(_require_exact_false)]


def _checked_positive(value: object, *, field_name: str) -> float:
    """Return a finite positive calculated value within the public bound."""

    try:
        normalized = _finite_number(value, field_name=field_name)
    except (TypeError, ValueError) as error:
        raise PressureReliefRequiredAreaInputError(
            f"{field_name} must remain a finite real number"
        ) from error
    if normalized <= 0.0:
        raise PressureReliefRequiredAreaInputError(
            f"{field_name} must remain positive"
        )
    if field_name == "required area" and normalized > _MAX_AREA_M2:
        raise PressureReliefRequiredAreaInputError(
            "required area exceeds the reviewed numerical bound"
        )
    return normalized


def _revalidate_model(value: object, model_type: type[CalculationModel]) -> Any:
    """Revalidate immutable input instances at every public boundary."""

    if not isinstance(value, model_type):
        raise PressureReliefRequiredAreaInputError(
            f"{model_type.__name__} input is required"
        )
    try:
        return model_type.model_validate(
            value.model_dump(mode="python", round_trip=True)
        )
    except Exception as error:
        raise PressureReliefRequiredAreaInputError(
            f"{model_type.__name__} failed validation"
        ) from error


class PressureReliefRequiredAreaFlowRegime(StrEnum):
    """Exact physical branch used by a Step 104 required-area result."""

    LIQUID_INCOMPRESSIBLE = "liquid_incompressible"
    GAS_VAPOUR_CHOKED = "gas_vapour_choked"
    GAS_VAPOUR_SUBCRITICAL = "gas_vapour_subcritical"
    ELIGIBLE_STEAM_CHOKED = "eligible_steam_choked"


class EligiblePressureReliefSteamState(StrEnum):
    """Steam states allowed by the generic Step 104 steam method."""

    DRY_SATURATED = "dry_saturated"
    SUPERHEATED = "superheated"


class TraceableReliefAreaCoefficients(CalculationModel):
    """Mandatory caller-supplied capacity coefficients for one exact basis."""

    coefficient_set_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    discharge_coefficient: float
    discharge_coefficient_source_reference: str = Field(
        min_length=3,
        max_length=500,
    )
    discharge_coefficient_role: Literal[
        "capacity_discharge_coefficient"
    ]
    combined_correction_factor: float
    combined_correction_factor_source_reference: str = Field(
        min_length=3,
        max_length=500,
    )
    combined_correction_factor_role: Literal[
        "combined_correction_factor"
    ]
    standards_basis_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=20, max_length=2000)
    supplied_by: str = Field(min_length=2, max_length=200)
    all_required_corrections_included: _ExactTrue
    double_counting_review_completed: _ExactTrue

    @field_validator(
        "discharge_coefficient",
        "combined_correction_factor",
        mode="before",
    )
    @classmethod
    def validate_raw_coefficients(cls, value: object, info) -> float:
        return _finite_number(value, field_name=info.field_name)

    @field_validator(
        "coefficient_set_id",
        "discharge_coefficient_source_reference",
        "combined_correction_factor_source_reference",
        "standards_basis_reference",
        "applicable_conditions",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_coefficient_domain(self) -> TraceableReliefAreaCoefficients:
        for field_name, value in (
            ("discharge coefficient", self.discharge_coefficient),
            ("combined correction factor", self.combined_correction_factor),
        ):
            if value <= 0.0 or value > 1.0:
                raise ValueError(f"{field_name} must be in (0, 1]")
        if not isfinite(self.effective_area_coefficient):
            raise ValueError("effective area coefficient must remain finite")
        if self.effective_area_coefficient <= 0.0:
            raise ValueError("effective area coefficient must not underflow to zero")
        return self

    @property
    def effective_area_coefficient(self) -> float:
        """Return the explicit coefficient product used by the equation."""

        return self.discharge_coefficient * self.combined_correction_factor


class TraceableLiquidReliefApplicability(CalculationModel):
    """Evidence that the generic incompressible liquid equation may be used."""

    vapor_pressure_absolute_pa: float
    vapor_pressure_source_reference: str = Field(min_length=3, max_length=500)
    confirmation_reference: str = Field(min_length=3, max_length=500)
    single_phase_incompressible_confirmed: _ExactTrue
    nonflashing_noncavitating_confirmed: _ExactTrue
    newtonian_or_calibrated_coefficient_confirmed: _ExactTrue

    @field_validator("vapor_pressure_absolute_pa", mode="before")
    @classmethod
    def validate_raw_vapor_pressure(cls, value: object) -> float:
        return _finite_number(value, field_name="vapor pressure")

    @field_validator(
        "vapor_pressure_source_reference",
        "confirmation_reference",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_vapor_pressure_domain(self) -> TraceableLiquidReliefApplicability:
        if (
            self.vapor_pressure_absolute_pa < 0.0
            or self.vapor_pressure_absolute_pa > _MAX_PRESSURE_PA
        ):
            raise ValueError("vapor pressure must be non-negative and bounded")
        return self


class TraceableGasVapourReliefApplicability(CalculationModel):
    """Evidence for the generic single-phase isentropic gas approximation."""

    confirmation_reference: str = Field(min_length=3, max_length=500)
    single_phase_gas_vapour_confirmed: _ExactTrue
    no_condensation_or_phase_transition_confirmed: _ExactTrue
    isentropic_flow_model_confirmed: _ExactTrue
    constant_k_and_upstream_z_approximation_accepted: _ExactTrue
    property_variation_review_completed: _ExactTrue

    @field_validator("confirmation_reference", mode="before")
    @classmethod
    def validate_raw_reference(cls, value: object) -> str:
        return _strict_text(value, field_name="confirmation_reference")


class TraceableSteamFlowCoefficient(CalculationModel):
    """Caller-supplied steam mass-flux normalization and choked boundary."""

    coefficient_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    steam_mass_flux_coefficient: float
    critical_pressure_ratio: float
    steam_state: EligiblePressureReliefSteamState
    source_reference: str = Field(min_length=3, max_length=500)
    critical_pressure_ratio_source_reference: str = Field(
        min_length=3,
        max_length=500,
    )
    eligibility_source_reference: str = Field(min_length=3, max_length=500)
    standards_basis_reference: str = Field(min_length=3, max_length=500)
    specific_volume_basis_reference: str = Field(min_length=3, max_length=500)
    applicable_conditions: str = Field(min_length=20, max_length=2000)
    supplied_by: str = Field(min_length=2, max_length=200)
    choked_flow_applicability_confirmed: _ExactTrue
    no_entrained_liquid_confirmed: _ExactTrue
    below_critical_pressure_confirmed: _ExactTrue
    coefficient_normalization: Literal["G = C_s * sqrt(P1_abs / v1)"]

    @field_validator(
        "steam_mass_flux_coefficient",
        "critical_pressure_ratio",
        mode="before",
    )
    @classmethod
    def validate_raw_coefficients(cls, value: object, info) -> float:
        return _finite_number(value, field_name=info.field_name)

    @field_validator(
        "coefficient_id",
        "source_reference",
        "critical_pressure_ratio_source_reference",
        "eligibility_source_reference",
        "standards_basis_reference",
        "specific_volume_basis_reference",
        "applicable_conditions",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_steam_coefficient_domain(self) -> TraceableSteamFlowCoefficient:
        if (
            self.steam_mass_flux_coefficient <= 0.0
            or self.steam_mass_flux_coefficient > 1.0
        ):
            raise ValueError("steam mass-flux coefficient must be in (0, 1]")
        if self.critical_pressure_ratio <= 0.0 or self.critical_pressure_ratio >= 1.0:
            raise ValueError("critical pressure ratio must be in (0, 1)")
        return self


class PressureReliefRequiredAreaCase(CalculationModel):
    """One Step 103 request and selected scenario authorised for Step 104."""

    readiness_request: PressureReliefReadinessRequest
    scenario_id: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z0-9][a-z0-9._-]+$",
    )
    method_basis_reference: str = Field(min_length=3, max_length=500)
    application_basis: str = Field(min_length=20, max_length=2000)
    supplied_by: str = Field(min_length=2, max_length=200)
    device_inlet_pressure_basis_confirmed: _ExactTrue
    downstream_system_basis_confirmed: _ExactTrue

    @field_validator(
        "scenario_id",
        "method_basis_reference",
        "application_basis",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)


class LiquidPressureReliefRequiredAreaInput(CalculationModel):
    """Strict input for one generic nonflashing liquid required area."""

    case: PressureReliefRequiredAreaCase
    coefficients: TraceableReliefAreaCoefficients
    applicability: TraceableLiquidReliefApplicability


class GasVapourPressureReliefRequiredAreaInput(CalculationModel):
    """Strict input for one generic single-phase gas/vapour required area."""

    case: PressureReliefRequiredAreaCase
    coefficients: TraceableReliefAreaCoefficients
    applicability: TraceableGasVapourReliefApplicability


class EligibleSteamPressureReliefRequiredAreaInput(CalculationModel):
    """Strict input for one generic eligible choked-steam required area."""

    case: PressureReliefRequiredAreaCase
    coefficients: TraceableReliefAreaCoefficients
    steam_flow: TraceableSteamFlowCoefficient


class ResolvedPressureReliefPressureState(CalculationModel):
    """Absolute equation pressures resolved from an explicit caller basis."""

    relieving_pressure_absolute_pa: float
    backpressure_absolute_pa: float
    driving_pressure_difference_pa: float
    original_basis_kind: PressureReliefPressureBasisKind
    atmospheric_pressure_absolute_pa_used: float | None = None

    @field_validator(
        "relieving_pressure_absolute_pa",
        "backpressure_absolute_pa",
        "driving_pressure_difference_pa",
        "atmospheric_pressure_absolute_pa_used",
        mode="before",
    )
    @classmethod
    def validate_raw_pressures(cls, value: object, info) -> float | None:
        if value is None and info.field_name == "atmospheric_pressure_absolute_pa_used":
            return None
        return _finite_number(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_pressure_coherence(self) -> ResolvedPressureReliefPressureState:
        p1 = self.relieving_pressure_absolute_pa
        p2 = self.backpressure_absolute_pa
        if p1 <= 0.0 or p2 <= 0.0 or p1 > _MAX_PRESSURE_PA:
            raise ValueError("resolved equation pressures must be positive and bounded")
        if p2 >= p1:
            raise ValueError("resolved backpressure must be below relieving pressure")
        expected_delta = p1 - p2
        if not isclose(
            self.driving_pressure_difference_pa,
            expected_delta,
            rel_tol=1e-15,
            abs_tol=0.0,
        ):
            raise ValueError("resolved driving pressure is inconsistent")
        atmosphere = self.atmospheric_pressure_absolute_pa_used
        if self.original_basis_kind is PressureReliefPressureBasisKind.ABSOLUTE:
            if atmosphere is not None:
                raise ValueError("absolute pressure basis cannot use an atmosphere")
        elif atmosphere is None or atmosphere <= 0.0:
            raise ValueError("gauge pressure basis requires a positive atmosphere")
        return self


class PressureReliefRequiredAreaAuthorization(CalculationModel):
    """Evidence that one exact Step 104 method replaced only the placeholder."""

    method_id: Literal[
        "pressure-relief.liquid.required-area.supplied-factors",
        "pressure-relief.gas-vapour.required-area.supplied-factors",
        "pressure-relief.eligible-steam.required-area.supplied-factors",
    ]
    method_version: Literal["1.0.0"]
    lifecycle_status: Literal[MethodLifecycleStatus.APPROVED] = (
        MethodLifecycleStatus.APPROVED
    )
    executable: _ExactTrue = True
    standards_conformity_claimed: _ExactFalse = False
    readiness_request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    readiness_gate_result: PressureReliefSafetyGateResult
    replaced_finding_id: Literal[
        "pressure-relief.no-approved-method"
    ] = PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID

    @field_validator("method_id", "method_version", mode="before")
    @classmethod
    def validate_raw_identity(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_gate_evidence(self) -> PressureReliefRequiredAreaAuthorization:
        finding_ids = tuple(
            finding.finding_id
            for finding in self.readiness_gate_result.blocking_findings
        )
        if finding_ids != (PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,):
            raise ValueError("authorization can replace only the exact placeholder")
        if (
            self.readiness_request_fingerprint
            != self.readiness_gate_result.request_fingerprint
        ):
            raise ValueError("authorization request fingerprint is inconsistent")
        return self


class PressureReliefRequiredAreaMethodMetadata(CalculationModel):
    """Allow-listed metadata for one independently reviewed generic method."""

    method_id: Literal[
        "pressure-relief.liquid.required-area.supplied-factors",
        "pressure-relief.gas-vapour.required-area.supplied-factors",
        "pressure-relief.eligible-steam.required-area.supplied-factors",
    ]
    method_version: Literal["1.0.0"] = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
    title: str = Field(min_length=3, max_length=240)
    required_phase: PressureReliefFluidPhase
    lifecycle_status: Literal[MethodLifecycleStatus.APPROVED] = (
        MethodLifecycleStatus.APPROVED
    )
    implementation_name: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_]+$",
    )
    executable: _ExactTrue = True
    standards_conformity_claimed: _ExactFalse = False
    preliminary_only: _ExactTrue = True
    independent_review_required: _ExactTrue = True
    applicability_boundary: str = Field(min_length=20, max_length=2000)
    coefficient_policy: str = Field(min_length=20, max_length=2000)
    public_equation_basis_urls: tuple[str, ...] = Field(min_length=1, max_length=4)

    @field_validator(
        "method_id",
        "title",
        "implementation_name",
        "applicability_boundary",
        "coefficient_policy",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        return _strict_text(value, field_name=info.field_name)

    @field_validator("public_equation_basis_urls", mode="before")
    @classmethod
    def validate_public_urls(cls, value: object) -> object:
        if isinstance(value, list):
            value = tuple(value)
        if not isinstance(value, tuple):
            raise TypeError("public equation basis URLs must be ordered")
        normalized = tuple(
            _strict_text(item, field_name="public equation basis URL")
            for item in value
        )
        if any(not item.startswith("https://") for item in normalized):
            raise ValueError("public equation basis URLs must use https")
        if len(normalized) != len(set(normalized)):
            raise ValueError("public equation basis URLs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_exact_binding(self) -> PressureReliefRequiredAreaMethodMetadata:
        expected_bindings = {
            LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: (
                PressureReliefFluidPhase.LIQUID,
                "calculate_liquid_pressure_relief_required_area",
            ),
            GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: (
                PressureReliefFluidPhase.GAS_VAPOUR,
                "calculate_gas_vapour_pressure_relief_required_area",
            ),
            ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID: (
                PressureReliefFluidPhase.STEAM,
                "calculate_eligible_steam_pressure_relief_required_area",
            ),
        }
        if (self.required_phase, self.implementation_name) != expected_bindings[
            self.method_id
        ]:
            raise ValueError("required-area method metadata binding is inconsistent")
        return self


def build_pressure_relief_required_area_input_fingerprint_payload(
    value: CalculationModel | Mapping[str, object],
) -> dict[str, object]:
    """Return the complete canonical Step 104 input fingerprint payload."""

    if isinstance(value, CalculationModel):
        normalized: object = value.model_dump(mode="python", round_trip=True)
    elif isinstance(value, Mapping):
        normalized = dict(value)
    else:
        raise PressureReliefRequiredAreaInputError(
            "required-area input fingerprint value must be a model or mapping"
        )
    return {
        "schema": _INPUT_FINGERPRINT_SCHEMA,
        "calculator_version": PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
        "input": normalized,
    }


def build_pressure_relief_required_area_result_fingerprint_payload(
    value: CalculationModel | Mapping[str, object],
) -> dict[str, object]:
    """Return every public result field except the self-referential hash."""

    if isinstance(value, CalculationModel):
        normalized = value.model_dump(mode="python", round_trip=True)
    elif isinstance(value, Mapping):
        normalized = dict(value)
    else:
        raise PressureReliefRequiredAreaInputError(
            "required-area result fingerprint value must be a model or mapping"
        )
    normalized.pop("result_fingerprint", None)
    return {
        "schema": _RESULT_FINGERPRINT_SCHEMA,
        "calculator_version": PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
        "result": normalized,
    }


def _validate_common_result_integrity(result: CalculationModel) -> None:
    """Recompute shared arithmetic, gate evidence, and both fingerprints."""

    values = result.model_dump(mode="python", round_trip=True)
    normalized_input = result.normalized_input
    expected_input_fingerprint = fingerprint_pressure_relief_readiness(
        build_pressure_relief_required_area_input_fingerprint_payload(
            normalized_input
        )
    )
    if result.input_fingerprint != expected_input_fingerprint:
        raise ValueError("required-area input fingerprint is inconsistent")

    expected_result_fingerprint = fingerprint_pressure_relief_readiness(
        build_pressure_relief_required_area_result_fingerprint_payload(values)
    )
    if result.result_fingerprint != expected_result_fingerprint:
        raise ValueError("required-area result fingerprint is inconsistent")

    case = normalized_input.case
    request = case.readiness_request
    metadata = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY.get(
        (result.method_id, result.method_version)
    )
    if metadata is None:
        raise ValueError("required-area result method is not registered")
    (
        prepared_input,
        scenario,
        expected_pressure_state,
        expected_authorization,
    ) = _prepare_execution(
        normalized_input,
        model_type=type(normalized_input),
        method_id=result.method_id,
        method_version=result.method_version,
        required_phase=metadata.required_phase,
    )
    if prepared_input != normalized_input:
        raise ValueError("required-area normalized input is not canonical")
    if result.pressure_state != expected_pressure_state:
        raise ValueError("required-area pressure state is inconsistent with the input")
    if result.selected_scenario_id != scenario.scenario_id:
        raise ValueError("required-area selected scenario is inconsistent")
    if result.protected_equipment_reference != scenario.protected_equipment_reference:
        raise ValueError("required-area protected-equipment reference is inconsistent")
    if scenario.flow_basis is None:
        raise ValueError("required-area selected scenario has no flow basis")
    expected_required_flow = scenario.flow_basis.required_relieving_mass_flow_kg_s
    if expected_required_flow is None:
        raise ValueError("required-area selected scenario has no relieving flow")
    expected_coefficient = normalized_input.coefficients.effective_area_coefficient
    if not isclose(
        result.effective_area_coefficient,
        expected_coefficient,
        rel_tol=1e-15,
        abs_tol=0.0,
    ):
        raise ValueError("required-area coefficient is inconsistent with the input")
    properties = request.fluid_properties
    if properties is None or properties.phase is not metadata.required_phase:
        raise ValueError("required-area method phase is inconsistent with the input")
    if result.warnings != _COMMON_WARNINGS or result.exclusions != _COMMON_EXCLUSIONS:
        raise ValueError("required-area safety boundary text is inconsistent")

    area = result.required_area_m2
    area_mm2 = result.required_area_mm2
    diameter = result.equivalent_circular_diameter_m
    corrected_flux = result.corrected_mass_flux_kg_m2_s
    required_flow = result.required_relieving_mass_flow_kg_s
    reconstructed = result.reconstructed_mass_flow_kg_s
    residual = result.relative_round_trip_residual
    for field_name, value in (
        ("required area", area),
        ("required area in square millimetres", area_mm2),
        ("equivalent circular diameter", diameter),
        ("corrected mass flux", corrected_flux),
        ("required relieving mass flow", required_flow),
        ("reconstructed relieving mass flow", reconstructed),
    ):
        _checked_positive(value, field_name=field_name)
    if not isclose(
        required_flow,
        expected_required_flow,
        rel_tol=1e-15,
        abs_tol=0.0,
    ):
        raise ValueError("required-area relieving flow is inconsistent with the input")
    if not isclose(area_mm2, area * 1_000_000.0, rel_tol=1e-12, abs_tol=0.0):
        raise ValueError("required-area unit conversion is inconsistent")
    if not isclose(
        diameter,
        sqrt(4.0 * area / pi),
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        raise ValueError("equivalent circular diameter is inconsistent")
    if not isclose(
        reconstructed,
        area * corrected_flux,
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        raise ValueError("reconstructed mass flow is inconsistent")
    if not isclose(
        area,
        required_flow / corrected_flux,
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        raise ValueError("required area is inconsistent with flow and mass flux")
    residual = _finite_number(residual, field_name="relative round-trip residual")
    if residual < 0.0:
        raise ValueError("required-area round-trip residual cannot be negative")
    expected_residual = abs(reconstructed - required_flow) / required_flow
    if not isclose(residual, expected_residual, rel_tol=1e-12, abs_tol=1e-18):
        raise ValueError("required-area round-trip residual is inconsistent")
    if residual > _ROUND_TRIP_REL_TOL:
        raise ValueError("required-area result exceeds round-trip tolerance")

    authorization = result.authorization
    if authorization != expected_authorization:
        raise ValueError("required-area authorization evidence is stale")


class LiquidPressureReliefRequiredAreaResult(CalculationModel):
    """Self-validating preliminary nonflashing-liquid area result."""

    method_id: Literal[
        "pressure-relief.liquid.required-area.supplied-factors"
    ] = LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID
    method_version: Literal[
        "1.0.0"
    ] = LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
    calculator_version: Literal[
        "1.0.0"
    ] = PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION
    normalized_input: LiquidPressureReliefRequiredAreaInput
    authorization: PressureReliefRequiredAreaAuthorization
    pressure_state: ResolvedPressureReliefPressureState
    selected_scenario_id: str
    protected_equipment_reference: str
    flow_regime: Literal[
        PressureReliefRequiredAreaFlowRegime.LIQUID_INCOMPRESSIBLE
    ]
    required_relieving_mass_flow_kg_s: float
    theoretical_mass_flux_kg_m2_s: float
    effective_area_coefficient: float
    corrected_mass_flux_kg_m2_s: float
    vapor_pressure_absolute_pa: float
    required_area_m2: float
    required_area_mm2: float
    equivalent_circular_diameter_m: float
    reconstructed_mass_flow_kg_s: float
    relative_round_trip_residual: float
    warnings: tuple[str, ...] = Field(min_length=1, max_length=16)
    exclusions: tuple[str, ...] = Field(min_length=1, max_length=16)
    status: Literal[CalculationStatus.COMPLETED_WITH_WARNINGS]
    calculation_performed: _ExactTrue
    ready_for_device_selection: _ExactFalse
    device_selected: _ExactFalse
    manufacturer_selection_performed: _ExactFalse
    standards_conformity_claimed: _ExactFalse
    preliminary_engineering_decision_support: _ExactTrue
    independent_review_required: _ExactTrue
    required_reviewer_competency: Literal[
        "Independent competent pressure-systems engineer"
    ]
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_integrity(self) -> LiquidPressureReliefRequiredAreaResult:
        _validate_common_result_integrity(self)
        properties = self.normalized_input.case.readiness_request.fluid_properties
        if properties is None or properties.liquid_density_kg_m3 is None:
            raise ValueError("liquid result requires the relieving density")
        applicability = self.normalized_input.applicability
        if not isclose(
            self.vapor_pressure_absolute_pa,
            applicability.vapor_pressure_absolute_pa,
            rel_tol=1e-15,
            abs_tol=0.0,
        ):
            raise ValueError("liquid vapor pressure is inconsistent with the input")
        if applicability.vapor_pressure_absolute_pa >= (
            self.pressure_state.backpressure_absolute_pa
        ):
            raise ValueError("liquid result is outside the nonflashing boundary")
        expected_theoretical_flux = sqrt(
            2.0
            * properties.liquid_density_kg_m3
            * self.pressure_state.driving_pressure_difference_pa
        )
        if not isclose(
            self.theoretical_mass_flux_kg_m2_s,
            expected_theoretical_flux,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("liquid theoretical mass flux is inconsistent")
        if not isclose(
            self.corrected_mass_flux_kg_m2_s,
            self.theoretical_mass_flux_kg_m2_s * self.effective_area_coefficient,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("liquid corrected mass flux is inconsistent")
        return self


class GasVapourPressureReliefRequiredAreaResult(CalculationModel):
    """Self-validating preliminary choked/subcritical gas area result."""

    method_id: Literal[
        "pressure-relief.gas-vapour.required-area.supplied-factors"
    ] = GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID
    method_version: Literal[
        "1.0.0"
    ] = GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
    calculator_version: Literal[
        "1.0.0"
    ] = PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION
    normalized_input: GasVapourPressureReliefRequiredAreaInput
    authorization: PressureReliefRequiredAreaAuthorization
    pressure_state: ResolvedPressureReliefPressureState
    selected_scenario_id: str
    protected_equipment_reference: str
    flow_regime: Literal[
        PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_CHOKED,
        PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL,
    ]
    required_relieving_mass_flow_kg_s: float
    downstream_to_upstream_pressure_ratio: float
    critical_pressure_ratio: float
    specific_gas_constant_j_kg_k: float
    theoretical_mass_flux_kg_m2_s: float
    effective_area_coefficient: float
    corrected_mass_flux_kg_m2_s: float
    required_area_m2: float
    required_area_mm2: float
    equivalent_circular_diameter_m: float
    reconstructed_mass_flow_kg_s: float
    relative_round_trip_residual: float
    warnings: tuple[str, ...] = Field(min_length=1, max_length=16)
    exclusions: tuple[str, ...] = Field(min_length=1, max_length=16)
    status: Literal[CalculationStatus.COMPLETED_WITH_WARNINGS]
    calculation_performed: _ExactTrue
    ready_for_device_selection: _ExactFalse
    device_selected: _ExactFalse
    manufacturer_selection_performed: _ExactFalse
    standards_conformity_claimed: _ExactFalse
    preliminary_engineering_decision_support: _ExactTrue
    independent_review_required: _ExactTrue
    required_reviewer_competency: Literal[
        "Independent competent pressure-systems engineer"
    ]
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_integrity(self) -> GasVapourPressureReliefRequiredAreaResult:
        _validate_common_result_integrity(self)
        properties = self.normalized_input.case.readiness_request.fluid_properties
        if properties is None or any(
            value is None
            for value in (
                properties.relieving_temperature_k,
                properties.gas_molar_mass_kg_kmol,
                properties.compressibility_factor,
                properties.isentropic_exponent,
            )
        ):
            raise ValueError("gas/vapour result requires complete relieving properties")
        (
            expected_flux,
            expected_ratio,
            expected_critical_ratio,
            expected_gas_constant,
            expected_regime,
        ) = _gas_mass_flux(
            pressure_state=self.pressure_state,
            temperature_k=properties.relieving_temperature_k,
            molar_mass_kg_kmol=properties.gas_molar_mass_kg_kmol,
            compressibility_factor=properties.compressibility_factor,
            isentropic_exponent=properties.isentropic_exponent,
        )
        for field_name, actual, expected in (
            (
                "gas/vapour theoretical mass flux",
                self.theoretical_mass_flux_kg_m2_s,
                expected_flux,
            ),
            (
                "gas/vapour pressure ratio",
                self.downstream_to_upstream_pressure_ratio,
                expected_ratio,
            ),
            (
                "gas/vapour critical pressure ratio",
                self.critical_pressure_ratio,
                expected_critical_ratio,
            ),
            (
                "gas/vapour specific gas constant",
                self.specific_gas_constant_j_kg_k,
                expected_gas_constant,
            ),
        ):
            if not isclose(actual, expected, rel_tol=1e-12, abs_tol=0.0):
                raise ValueError(f"{field_name} is inconsistent")
        if self.flow_regime is not expected_regime:
            raise ValueError("gas/vapour flow regime is inconsistent")
        if not isclose(
            self.corrected_mass_flux_kg_m2_s,
            self.theoretical_mass_flux_kg_m2_s * self.effective_area_coefficient,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("gas/vapour corrected mass flux is inconsistent")
        ratio = (
            self.pressure_state.backpressure_absolute_pa
            / self.pressure_state.relieving_pressure_absolute_pa
        )
        if not isclose(
            self.downstream_to_upstream_pressure_ratio,
            ratio,
            rel_tol=1e-15,
            abs_tol=0.0,
        ):
            raise ValueError("gas/vapour pressure ratio is inconsistent")
        expected_regime = (
            PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_CHOKED
            if ratio <= self.critical_pressure_ratio
            else PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL
        )
        if self.flow_regime is not expected_regime:
            raise ValueError("gas/vapour flow regime is inconsistent")
        return self


class EligibleSteamPressureReliefRequiredAreaResult(CalculationModel):
    """Self-validating preliminary eligible choked-steam area result."""

    method_id: Literal[
        "pressure-relief.eligible-steam.required-area.supplied-factors"
    ] = ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID
    method_version: Literal[
        "1.0.0"
    ] = ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
    calculator_version: Literal[
        "1.0.0"
    ] = PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION
    normalized_input: EligibleSteamPressureReliefRequiredAreaInput
    authorization: PressureReliefRequiredAreaAuthorization
    pressure_state: ResolvedPressureReliefPressureState
    selected_scenario_id: str
    protected_equipment_reference: str
    flow_regime: Literal[
        PressureReliefRequiredAreaFlowRegime.ELIGIBLE_STEAM_CHOKED
    ]
    steam_state: EligiblePressureReliefSteamState
    required_relieving_mass_flow_kg_s: float
    downstream_to_upstream_pressure_ratio: float
    supplied_critical_pressure_ratio: float
    supplied_steam_mass_flux_coefficient: float
    base_mass_flux_kg_m2_s: float
    theoretical_mass_flux_kg_m2_s: float
    effective_area_coefficient: float
    corrected_mass_flux_kg_m2_s: float
    required_area_m2: float
    required_area_mm2: float
    equivalent_circular_diameter_m: float
    reconstructed_mass_flow_kg_s: float
    relative_round_trip_residual: float
    warnings: tuple[str, ...] = Field(min_length=1, max_length=16)
    exclusions: tuple[str, ...] = Field(min_length=1, max_length=16)
    status: Literal[CalculationStatus.COMPLETED_WITH_WARNINGS]
    calculation_performed: _ExactTrue
    ready_for_device_selection: _ExactFalse
    device_selected: _ExactFalse
    manufacturer_selection_performed: _ExactFalse
    standards_conformity_claimed: _ExactFalse
    preliminary_engineering_decision_support: _ExactTrue
    independent_review_required: _ExactTrue
    required_reviewer_competency: Literal[
        "Independent competent pressure-systems engineer"
    ]
    input_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_integrity(self) -> EligibleSteamPressureReliefRequiredAreaResult:
        _validate_common_result_integrity(self)
        properties = self.normalized_input.case.readiness_request.fluid_properties
        if properties is None or properties.steam_specific_volume_m3_kg is None:
            raise ValueError("steam result requires the relieving specific volume")
        steam_flow = self.normalized_input.steam_flow
        jurisdiction = (
            self.normalized_input.case.readiness_request.jurisdiction_basis
        )
        if (
            properties.dry_or_superheated_steam_confirmed is not True
            or jurisdiction is None
            or jurisdiction.exact_edition_and_amendment_reference is None
        ):
            raise ValueError("steam result requires complete eligibility evidence")
        if steam_flow.standards_basis_reference != (
            jurisdiction.exact_edition_and_amendment_reference
        ):
            raise ValueError("steam coefficient basis is inconsistent")
        if steam_flow.specific_volume_basis_reference != (
            properties.property_source_reference
        ):
            raise ValueError("steam specific-volume basis is inconsistent")
        if self.pressure_state.relieving_pressure_absolute_pa >= (
            WATER_CRITICAL_PRESSURE_PA
        ):
            raise ValueError("steam result is above the reviewed pressure boundary")
        expected_base_flux = sqrt(
            self.pressure_state.relieving_pressure_absolute_pa
            / properties.steam_specific_volume_m3_kg
        )
        copied_fields = (
            (
                "steam mass-flux coefficient",
                self.supplied_steam_mass_flux_coefficient,
                steam_flow.steam_mass_flux_coefficient,
            ),
            (
                "steam critical pressure ratio",
                self.supplied_critical_pressure_ratio,
                steam_flow.critical_pressure_ratio,
            ),
            ("steam base mass flux", self.base_mass_flux_kg_m2_s, expected_base_flux),
        )
        for field_name, actual, expected in copied_fields:
            if not isclose(actual, expected, rel_tol=1e-12, abs_tol=0.0):
                raise ValueError(f"{field_name} is inconsistent")
        if self.steam_state is not steam_flow.steam_state:
            raise ValueError("steam state is inconsistent with the input")
        if not isclose(
            self.theoretical_mass_flux_kg_m2_s,
            self.base_mass_flux_kg_m2_s
            * self.supplied_steam_mass_flux_coefficient,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("steam theoretical mass flux is inconsistent")
        if not isclose(
            self.corrected_mass_flux_kg_m2_s,
            self.theoretical_mass_flux_kg_m2_s * self.effective_area_coefficient,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError("steam corrected mass flux is inconsistent")
        ratio = (
            self.pressure_state.backpressure_absolute_pa
            / self.pressure_state.relieving_pressure_absolute_pa
        )
        if not isclose(
            self.downstream_to_upstream_pressure_ratio,
            ratio,
            rel_tol=1e-15,
            abs_tol=0.0,
        ):
            raise ValueError("steam pressure ratio is inconsistent")
        if ratio > self.supplied_critical_pressure_ratio:
            raise ValueError("steam result is outside its supplied choked boundary")
        return self


def _resolve_pressure_state(
    request: PressureReliefReadinessRequest,
) -> ResolvedPressureReliefPressureState:
    """Resolve explicit absolute pressures without assuming an atmosphere."""

    pressure = request.pressure_basis
    if pressure is None or not pressure.is_complete:
        raise PressureReliefRequiredAreaInputError(
            "complete pressure basis is required"
        )
    if (
        pressure.basis_kind is None
        or pressure.relieving_pressure_pa is None
        or pressure.total_backpressure_pa is None
    ):
        raise PressureReliefRequiredAreaInputError(
            "complete pressure values are required"
        )
    atmosphere: float | None = None
    if pressure.basis_kind is PressureReliefPressureBasisKind.ABSOLUTE:
        p1 = pressure.relieving_pressure_pa
        p2 = pressure.total_backpressure_pa
    else:
        atmosphere = pressure.atmospheric_pressure_absolute_pa
        if atmosphere is None:
            raise PressureReliefRequiredAreaInputError(
                "gauge pressure basis requires an explicit atmosphere"
            )
        p1 = pressure.relieving_pressure_pa + atmosphere
        p2 = pressure.total_backpressure_pa + atmosphere
    try:
        return ResolvedPressureReliefPressureState(
            relieving_pressure_absolute_pa=p1,
            backpressure_absolute_pa=p2,
            driving_pressure_difference_pa=p1 - p2,
            original_basis_kind=pressure.basis_kind,
            atmospheric_pressure_absolute_pa_used=atmosphere,
        )
    except Exception as error:
        raise PressureReliefRequiredAreaInputError(
            "resolved equation pressure state is invalid"
        ) from error


def _select_scenario(
    request: PressureReliefReadinessRequest,
    scenario_id: str,
) -> PressureReliefScenarioBasis:
    """Select exactly one documented scenario without case repair or fallback."""

    matches = tuple(
        scenario for scenario in request.scenarios if scenario.scenario_id == scenario_id
    )
    if len(matches) != 1:
        raise PressureReliefRequiredAreaInputError(
            "scenario_id must resolve exactly once in the readiness request"
        )
    return matches[0]


def _prepare_execution(
    value: CalculationModel,
    *,
    model_type: type[CalculationModel],
    method_id: str,
    method_version: str,
    required_phase: PressureReliefFluidPhase,
) -> tuple[
    CalculationModel,
    PressureReliefScenarioBasis,
    ResolvedPressureReliefPressureState,
    PressureReliefRequiredAreaAuthorization,
]:
    """Run the exact method and Step 103 hard gates before arithmetic."""

    normalized = _revalidate_model(value, model_type)
    metadata = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY.get(
        (method_id, method_version)
    )
    implementation = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS.get(
        (method_id, method_version)
    )
    if (
        metadata is None
        or implementation is None
        or metadata.lifecycle_status is not MethodLifecycleStatus.APPROVED
        or metadata.executable is not True
        or metadata.implementation_name != implementation.__name__
    ):
        raise PressureReliefRequiredAreaInputError(
            "required-area method is not exactly approved and bound"
        )

    request = normalized.case.readiness_request
    gate_result = assess_pressure_relief_readiness(request)
    finding_ids = tuple(
        finding.finding_id for finding in gate_result.blocking_findings
    )
    if finding_ids != (PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,):
        raise PressureReliefRequiredAreaBlockedError(gate_result)

    if (
        request.selected_standards_pack_id is None
        or request.selected_standards_pack_version is None
        or (
            request.selected_standards_pack_id,
            request.selected_standards_pack_version,
        )
        not in PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY
    ):
        raise PressureReliefRequiredAreaInputError(
            "an exact inert standards pack selection is required"
        )
    jurisdiction = request.jurisdiction_basis
    if jurisdiction is None or jurisdiction.exact_edition_and_amendment_reference is None:
        raise PressureReliefRequiredAreaInputError(
            "an exact jurisdiction edition reference is required"
        )
    if normalized.case.method_basis_reference != (
        jurisdiction.exact_edition_and_amendment_reference
    ):
        raise PressureReliefRequiredAreaInputError(
            "method basis must match the readiness jurisdiction edition reference"
        )
    if normalized.coefficients.standards_basis_reference != (
        jurisdiction.exact_edition_and_amendment_reference
    ):
        raise PressureReliefRequiredAreaInputError(
            "coefficient basis must match the readiness jurisdiction edition reference"
        )

    scenario = _select_scenario(request, normalized.case.scenario_id)
    properties = request.fluid_properties
    if properties is None or properties.phase is not required_phase:
        raise PressureReliefRequiredAreaInputError(
            f"method requires the {required_phase.value} readiness phase"
        )
    if scenario.flow_basis is None or not scenario.flow_basis.is_complete:
        raise PressureReliefRequiredAreaInputError(
            "selected scenario requires a complete relieving-flow basis"
        )
    pressure_state = _resolve_pressure_state(request)
    authorization = PressureReliefRequiredAreaAuthorization(
        method_id=method_id,
        method_version=method_version,
        readiness_request_fingerprint=gate_result.request_fingerprint,
        readiness_gate_result=gate_result,
    )
    return normalized, scenario, pressure_state, authorization


def _common_result_values(
    *,
    method_id: str,
    method_version: str,
    normalized_input: CalculationModel,
    scenario: PressureReliefScenarioBasis,
    pressure_state: ResolvedPressureReliefPressureState,
    authorization: PressureReliefRequiredAreaAuthorization,
    flow_regime: PressureReliefRequiredAreaFlowRegime,
    theoretical_mass_flux: float,
    effective_area_coefficient: float,
) -> dict[str, object]:
    """Build checked common result values and deterministic round-trip."""

    flow_basis = scenario.flow_basis
    if flow_basis is None or flow_basis.required_relieving_mass_flow_kg_s is None:
        raise PressureReliefRequiredAreaInputError(
            "selected scenario mass flow is required"
        )
    required_flow = flow_basis.required_relieving_mass_flow_kg_s
    theoretical_flux = _checked_positive(
        theoretical_mass_flux,
        field_name="theoretical mass flux",
    )
    coefficient = _checked_positive(
        effective_area_coefficient,
        field_name="effective area coefficient",
    )
    corrected_flux = _checked_positive(
        theoretical_flux * coefficient,
        field_name="corrected mass flux",
    )
    try:
        required_area = required_flow / corrected_flux
    except (OverflowError, ZeroDivisionError) as error:
        raise PressureReliefRequiredAreaInputError(
            "required area could not be calculated"
        ) from error
    required_area = _checked_positive(required_area, field_name="required area")
    area_mm2 = _checked_positive(
        required_area * 1_000_000.0,
        field_name="required area in square millimetres",
    )
    equivalent_diameter = _checked_positive(
        sqrt(4.0 * required_area / pi),
        field_name="equivalent circular diameter",
    )
    reconstructed = _checked_positive(
        required_area * corrected_flux,
        field_name="reconstructed relieving mass flow",
    )
    residual = abs(reconstructed - required_flow) / required_flow
    if not isfinite(residual) or residual > _ROUND_TRIP_REL_TOL:
        raise PressureReliefRequiredAreaError(
            "required area failed its deterministic mass-flow round-trip"
        )
    input_fingerprint = fingerprint_pressure_relief_readiness(
        build_pressure_relief_required_area_input_fingerprint_payload(
            normalized_input
        )
    )
    return {
        "method_id": method_id,
        "method_version": method_version,
        "calculator_version": PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
        "normalized_input": normalized_input,
        "authorization": authorization,
        "pressure_state": pressure_state,
        "selected_scenario_id": scenario.scenario_id,
        "protected_equipment_reference": scenario.protected_equipment_reference,
        "flow_regime": flow_regime,
        "required_relieving_mass_flow_kg_s": required_flow,
        "theoretical_mass_flux_kg_m2_s": theoretical_flux,
        "effective_area_coefficient": coefficient,
        "corrected_mass_flux_kg_m2_s": corrected_flux,
        "required_area_m2": required_area,
        "required_area_mm2": area_mm2,
        "equivalent_circular_diameter_m": equivalent_diameter,
        "reconstructed_mass_flow_kg_s": reconstructed,
        "relative_round_trip_residual": residual,
        "warnings": _COMMON_WARNINGS,
        "exclusions": _COMMON_EXCLUSIONS,
        "status": CalculationStatus.COMPLETED_WITH_WARNINGS,
        "calculation_performed": True,
        "ready_for_device_selection": False,
        "device_selected": False,
        "manufacturer_selection_performed": False,
        "standards_conformity_claimed": False,
        "preliminary_engineering_decision_support": True,
        "independent_review_required": True,
        "required_reviewer_competency": (
            PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY
        ),
        "input_fingerprint": input_fingerprint,
    }


def _finalize_result(
    result_type: type[CalculationModel],
    values: dict[str, object],
) -> CalculationModel:
    """Fingerprint and validate one complete result model."""

    result_fingerprint = fingerprint_pressure_relief_readiness(
        build_pressure_relief_required_area_result_fingerprint_payload(values)
    )
    return result_type(**values, result_fingerprint=result_fingerprint)


def calculate_liquid_pressure_relief_required_area(
    sizing_input: LiquidPressureReliefRequiredAreaInput,
) -> LiquidPressureReliefRequiredAreaResult:
    """Calculate a generic single-phase nonflashing liquid required area."""

    normalized, scenario, pressure_state, authorization = _prepare_execution(
        sizing_input,
        model_type=LiquidPressureReliefRequiredAreaInput,
        method_id=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        required_phase=PressureReliefFluidPhase.LIQUID,
    )
    properties = normalized.case.readiness_request.fluid_properties
    if properties is None or properties.liquid_density_kg_m3 is None:
        raise PressureReliefRequiredAreaInputError(
            "liquid density at the relieving condition is required"
        )
    applicability = normalized.applicability
    if (
        applicability.vapor_pressure_absolute_pa
        >= pressure_state.backpressure_absolute_pa
    ):
        raise PressureReliefRequiredAreaInputError(
            "liquid method is blocked when backpressure is not above vapor pressure"
        )
    try:
        mass_flux = sqrt(
            2.0
            * properties.liquid_density_kg_m3
            * pressure_state.driving_pressure_difference_pa
        )
    except (OverflowError, ValueError) as error:
        raise PressureReliefRequiredAreaInputError(
            "liquid theoretical mass flux could not be calculated"
        ) from error
    values = _common_result_values(
        method_id=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        normalized_input=normalized,
        scenario=scenario,
        pressure_state=pressure_state,
        authorization=authorization,
        flow_regime=(
            PressureReliefRequiredAreaFlowRegime.LIQUID_INCOMPRESSIBLE
        ),
        theoretical_mass_flux=mass_flux,
        effective_area_coefficient=(
            normalized.coefficients.effective_area_coefficient
        ),
    )
    values["vapor_pressure_absolute_pa"] = (
        applicability.vapor_pressure_absolute_pa
    )
    return _finalize_result(
        LiquidPressureReliefRequiredAreaResult,
        values,
    )  # type: ignore[return-value]


def _gas_mass_flux(
    *,
    pressure_state: ResolvedPressureReliefPressureState,
    temperature_k: float,
    molar_mass_kg_kmol: float,
    compressibility_factor: float,
    isentropic_exponent: float,
) -> tuple[
    float,
    float,
    float,
    float,
    PressureReliefRequiredAreaFlowRegime,
]:
    """Return stable isentropic gas mass flux and exact regime information."""

    k = isentropic_exponent
    if k <= 1.0:
        raise PressureReliefRequiredAreaInputError(
            "isentropic exponent must be greater than one"
        )
    specific_gas_constant = UNIVERSAL_GAS_CONSTANT_J_KMOL_K / molar_mass_kg_kmol
    ratio = (
        pressure_state.backpressure_absolute_pa
        / pressure_state.relieving_pressure_absolute_pa
    )
    try:
        k_minus_one = k - 1.0
        log_choked_base = -log1p(k_minus_one / 2.0)
        critical_ratio = exp((k / k_minus_one) * log_choked_base)
        if ratio <= critical_ratio:
            exponent = (k + 1.0) / (2.0 * k_minus_one)
            mass_flux = (
                pressure_state.relieving_pressure_absolute_pa
                * sqrt(
                    k
                    / (
                        compressibility_factor
                        * specific_gas_constant
                        * temperature_k
                    )
                )
                * exp(exponent * log_choked_base)
            )
            regime = PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_CHOKED
        else:
            log_ratio = log(ratio)
            first_exponent = (2.0 / k) * log_ratio
            exponent_difference = (k_minus_one / k) * log_ratio
            pressure_term = exp(first_exponent) * (-expm1(exponent_difference))
            radicand = (
                (2.0 * k)
                / (
                    compressibility_factor
                    * specific_gas_constant
                    * temperature_k
                    * k_minus_one
                )
                * pressure_term
            )
            mass_flux = pressure_state.relieving_pressure_absolute_pa * sqrt(
                radicand
            )
            regime = PressureReliefRequiredAreaFlowRegime.GAS_VAPOUR_SUBCRITICAL
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise PressureReliefRequiredAreaInputError(
            "gas/vapour mass flux could not be calculated"
        ) from error
    return mass_flux, ratio, critical_ratio, specific_gas_constant, regime


def calculate_gas_vapour_pressure_relief_required_area(
    sizing_input: GasVapourPressureReliefRequiredAreaInput,
) -> GasVapourPressureReliefRequiredAreaResult:
    """Calculate a generic choked or subcritical gas/vapour required area."""

    normalized, scenario, pressure_state, authorization = _prepare_execution(
        sizing_input,
        model_type=GasVapourPressureReliefRequiredAreaInput,
        method_id=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        required_phase=PressureReliefFluidPhase.GAS_VAPOUR,
    )
    properties = normalized.case.readiness_request.fluid_properties
    if properties is None or any(
        value is None
        for value in (
            properties.relieving_temperature_k,
            properties.gas_molar_mass_kg_kmol,
            properties.compressibility_factor,
            properties.isentropic_exponent,
        )
    ):
        raise PressureReliefRequiredAreaInputError(
            "complete gas/vapour relieving properties are required"
        )
    mass_flux, ratio, critical_ratio, gas_constant, regime = _gas_mass_flux(
        pressure_state=pressure_state,
        temperature_k=properties.relieving_temperature_k,
        molar_mass_kg_kmol=properties.gas_molar_mass_kg_kmol,
        compressibility_factor=properties.compressibility_factor,
        isentropic_exponent=properties.isentropic_exponent,
    )
    values = _common_result_values(
        method_id=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        normalized_input=normalized,
        scenario=scenario,
        pressure_state=pressure_state,
        authorization=authorization,
        flow_regime=regime,
        theoretical_mass_flux=mass_flux,
        effective_area_coefficient=(
            normalized.coefficients.effective_area_coefficient
        ),
    )
    values.update(
        {
            "downstream_to_upstream_pressure_ratio": ratio,
            "critical_pressure_ratio": critical_ratio,
            "specific_gas_constant_j_kg_k": gas_constant,
        }
    )
    return _finalize_result(
        GasVapourPressureReliefRequiredAreaResult,
        values,
    )  # type: ignore[return-value]


def calculate_eligible_steam_pressure_relief_required_area(
    sizing_input: EligibleSteamPressureReliefRequiredAreaInput,
) -> EligibleSteamPressureReliefRequiredAreaResult:
    """Calculate a generic eligible dry/superheated choked-steam area."""

    normalized, scenario, pressure_state, authorization = _prepare_execution(
        sizing_input,
        model_type=EligibleSteamPressureReliefRequiredAreaInput,
        method_id=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        required_phase=PressureReliefFluidPhase.STEAM,
    )
    properties = normalized.case.readiness_request.fluid_properties
    if (
        properties is None
        or properties.steam_specific_volume_m3_kg is None
        or properties.dry_or_superheated_steam_confirmed is not True
    ):
        raise PressureReliefRequiredAreaInputError(
            "eligible dry or superheated steam properties are required"
        )
    jurisdiction = normalized.case.readiness_request.jurisdiction_basis
    if jurisdiction is None or jurisdiction.exact_edition_and_amendment_reference is None:
        raise PressureReliefRequiredAreaInputError(
            "exact steam method jurisdiction basis is required"
        )
    steam_flow = normalized.steam_flow
    if steam_flow.standards_basis_reference != (
        jurisdiction.exact_edition_and_amendment_reference
    ):
        raise PressureReliefRequiredAreaInputError(
            "steam coefficient basis must match the jurisdiction edition reference"
        )
    if steam_flow.specific_volume_basis_reference != (
        properties.property_source_reference
    ):
        raise PressureReliefRequiredAreaInputError(
            "steam specific-volume basis must match the readiness property source"
        )
    if pressure_state.relieving_pressure_absolute_pa >= WATER_CRITICAL_PRESSURE_PA:
        raise PressureReliefRequiredAreaInputError(
            "supercritical-water pressure is outside the Step 104 steam method"
        )
    ratio = (
        pressure_state.backpressure_absolute_pa
        / pressure_state.relieving_pressure_absolute_pa
    )
    if ratio > steam_flow.critical_pressure_ratio:
        raise PressureReliefRequiredAreaInputError(
            "subcritical steam flow is outside the Step 104 steam method"
        )
    try:
        base_mass_flux = sqrt(
            pressure_state.relieving_pressure_absolute_pa
            / properties.steam_specific_volume_m3_kg
        )
        theoretical_mass_flux = (
            steam_flow.steam_mass_flux_coefficient * base_mass_flux
        )
    except (OverflowError, ValueError, ZeroDivisionError) as error:
        raise PressureReliefRequiredAreaInputError(
            "steam mass flux could not be calculated"
        ) from error
    values = _common_result_values(
        method_id=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        normalized_input=normalized,
        scenario=scenario,
        pressure_state=pressure_state,
        authorization=authorization,
        flow_regime=(
            PressureReliefRequiredAreaFlowRegime.ELIGIBLE_STEAM_CHOKED
        ),
        theoretical_mass_flux=theoretical_mass_flux,
        effective_area_coefficient=(
            normalized.coefficients.effective_area_coefficient
        ),
    )
    values.update(
        {
            "steam_state": steam_flow.steam_state,
            "downstream_to_upstream_pressure_ratio": ratio,
            "supplied_critical_pressure_ratio": steam_flow.critical_pressure_ratio,
            "supplied_steam_mass_flux_coefficient": (
                steam_flow.steam_mass_flux_coefficient
            ),
            "base_mass_flux_kg_m2_s": base_mass_flux,
        }
    )
    return _finalize_result(
        EligibleSteamPressureReliefRequiredAreaResult,
        values,
    )  # type: ignore[return-value]


LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER: Final = (
    PressureReliefRequiredAreaMethodMetadata(
        method_id=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        title="Generic nonflashing-liquid pressure-relief required area",
        required_phase=PressureReliefFluidPhase.LIQUID,
        implementation_name="calculate_liquid_pressure_relief_required_area",
        applicability_boundary=(
            "One documented single-phase, incompressible, nonflashing, "
            "noncavitating liquid scenario with density at the relieving "
            "condition and explicit device-inlet and backpressure bases."
        ),
        coefficient_policy=(
            "Discharge and combined correction coefficients are caller-supplied, "
            "bounded, traceable, edition-bound, and never derived by this method."
        ),
        public_equation_basis_urls=(
            "https://www1.grc.nasa.gov/beginners-guide-to-aeronautics/bernoullis-equation/",
            "https://www.usbr.gov/tsc/techreferences/mands/wmm/chap14_03.html",
        ),
    )
)

GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER: Final = (
    PressureReliefRequiredAreaMethodMetadata(
        method_id=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        title="Generic gas/vapour pressure-relief required area",
        required_phase=PressureReliefFluidPhase.GAS_VAPOUR,
        implementation_name="calculate_gas_vapour_pressure_relief_required_area",
        applicability_boundary=(
            "One documented homogeneous single-phase gas or noncondensing vapour "
            "scenario using a constant-k, upstream-Z isentropic approximation and "
            "explicit absolute device-inlet and backpressure states."
        ),
        coefficient_policy=(
            "Discharge and combined correction coefficients are caller-supplied, "
            "bounded, traceable, edition-bound, and never derived by this method."
        ),
        public_equation_basis_urls=(
            "https://www1.grc.nasa.gov/beginners-guide-to-aeronautics/mass-flow-rate-equations/",
            "https://pages.nist.gov/teqp-docs/en/main/_static/doxygen/html/constants_8hpp_source.html",
        ),
    )
)

ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER: Final = (
    PressureReliefRequiredAreaMethodMetadata(
        method_id=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        title="Generic eligible choked-steam pressure-relief required area",
        required_phase=PressureReliefFluidPhase.STEAM,
        implementation_name="calculate_eligible_steam_pressure_relief_required_area",
        applicability_boundary=(
            "One documented dry-saturated or superheated, below-critical, "
            "choked-steam scenario with traceable specific volume and a supplied "
            "dimensionless steam mass-flux coefficient."
        ),
        coefficient_policy=(
            "The steam mass-flux, discharge, and combined correction coefficients "
            "and the critical pressure ratio are caller-supplied, bounded, "
            "traceable, edition-bound, and never derived by this method."
        ),
        public_equation_basis_urls=(
            "https://www.nist.gov/srd/nistir-5078",
            "https://www1.grc.nasa.gov/beginners-guide-to-aeronautics/mass-flow-rate-equations/",
        ),
    )
)

PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS: Final = (
    LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER,
    GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER,
    ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER,
)
PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY: Final = MappingProxyType(
    {
        (adapter.method_id, adapter.method_version): adapter
        for adapter in PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS
    }
)
PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        (
            LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        ): calculate_liquid_pressure_relief_required_area,
        (
            GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        ): calculate_gas_vapour_pressure_relief_required_area,
        (
            ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        ): calculate_eligible_steam_pressure_relief_required_area,
    }
)
if len(PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY) != len(
    PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS
):
    raise RuntimeError("duplicate exact-version required-area registration")
if (
    PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY.keys()
    != PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS.keys()
):
    raise RuntimeError("required-area metadata and implementations are inconsistent")
if any(
    adapter.implementation_name
    != PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS[key].__name__
    for key, adapter in PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY.items()
):
    raise RuntimeError("required-area implementation binding is inconsistent")


def execute_pressure_relief_required_area(
    *,
    method_id: str,
    method_version: str,
    sizing_input: CalculationModel,
) -> CalculationModel:
    """Execute one exact allow-listed required-area method without fallback."""

    normalized_method_id = _strict_text(method_id, field_name="method_id")
    normalized_method_version = _strict_text(
        method_version,
        field_name="method_version",
    )
    implementation = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS.get(
        (normalized_method_id, normalized_method_version)
    )
    if implementation is None:
        raise PressureReliefRequiredAreaInputError(
            "unknown exact pressure-relief required-area method"
        )
    return implementation(sizing_input)  # type: ignore[arg-type]


__all__ = [
    "ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER",
    "ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID",
    "ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION",
    "GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER",
    "GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID",
    "GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION",
    "LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_ADAPTER",
    "LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID",
    "LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION",
    "PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION",
    "PRESSURE_RELIEF_REQUIRED_AREA_EXECUTABLE_ADAPTERS",
    "PRESSURE_RELIEF_REQUIRED_AREA_METHOD_IMPLEMENTATIONS",
    "PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY",
    "PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION",
    "UNIVERSAL_GAS_CONSTANT_J_KMOL_K",
    "WATER_CRITICAL_PRESSURE_PA",
    "EligiblePressureReliefSteamState",
    "EligibleSteamPressureReliefRequiredAreaInput",
    "EligibleSteamPressureReliefRequiredAreaResult",
    "GasVapourPressureReliefRequiredAreaInput",
    "GasVapourPressureReliefRequiredAreaResult",
    "LiquidPressureReliefRequiredAreaInput",
    "LiquidPressureReliefRequiredAreaResult",
    "PressureReliefRequiredAreaAuthorization",
    "PressureReliefRequiredAreaBlockedError",
    "PressureReliefRequiredAreaCase",
    "PressureReliefRequiredAreaError",
    "PressureReliefRequiredAreaFlowRegime",
    "PressureReliefRequiredAreaInputError",
    "PressureReliefRequiredAreaMethodMetadata",
    "ResolvedPressureReliefPressureState",
    "TraceableGasVapourReliefApplicability",
    "TraceableLiquidReliefApplicability",
    "TraceableReliefAreaCoefficients",
    "TraceableSteamFlowCoefficient",
    "build_pressure_relief_required_area_input_fingerprint_payload",
    "build_pressure_relief_required_area_result_fingerprint_payload",
    "calculate_eligible_steam_pressure_relief_required_area",
    "calculate_gas_vapour_pressure_relief_required_area",
    "calculate_liquid_pressure_relief_required_area",
    "execute_pressure_relief_required_area",
]
