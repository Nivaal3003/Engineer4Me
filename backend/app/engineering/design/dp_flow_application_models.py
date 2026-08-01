"""Strict vendor-neutral DP primary-element application models.

These models represent auditable screening evidence. They do not execute a
standards correlation, select a manufacturer, rank brands, or make a
conformity claim. Proprietary names are explicit catalogue variants, never
generic technology labels.
"""

from __future__ import annotations

from enum import StrEnum
from math import isfinite
from typing import Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from app.engineering.calculations.models import CalculationModel


DP_FLOW_APPLICATION_MODEL_VERSION = "1.1.0"
FINAL_BRAND_DECISION_NOTICE = (
    "Engineer4Me does not declare a manufacturer or brand to be best. "
    "The user makes the final brand decision after technical, commercial, "
    "legal, availability, support, and project approvals are verified."
)


class DPTriState(StrEnum):
    UNKNOWN = "unknown"
    NO = "no"
    YES = "yes"


class DPFluidPhase(StrEnum):
    UNKNOWN = "unknown"
    LIQUID = "liquid"
    GAS = "gas"
    STEAM = "steam"
    VAPOUR = "vapour"
    SLURRY = "slurry"
    MULTIPHASE = "multiphase"


class DPMeasurementObjective(StrEnum):
    PROCESS_CONTROL = "process_control"
    MONITORING = "monitoring"
    MASS_BALANCE = "mass_balance"
    ENERGY_BALANCE = "energy_balance"
    ALLOCATION = "allocation"
    CUSTODY_TRANSFER = "custody_transfer"
    SAFETY_RELATED = "safety_related"


class DPPrimaryElementFamily(StrEnum):
    ORIFICE_PLATE = "orifice_plate"
    INTEGRAL_ORIFICE = "integral_orifice"
    FLOW_NOZZLE = "flow_nozzle"
    VENTURI_TUBE = "venturi_tube"
    VENTURI_NOZZLE = "venturi_nozzle"
    WEDGE = "wedge"
    AVERAGING_PITOT = "averaging_pitot"
    SINGLE_POINT_PITOT = "single_point_pitot"
    CONE_METER = "cone_meter"
    CONDITIONING_ELEMENT = "conditioning_element"
    LAMINAR_FLOW_ELEMENT = "laminar_flow_element"
    ELBOW_METER = "elbow_meter"


class DPOwnershipType(StrEnum):
    GENERIC_TECHNOLOGY = "generic_technology"
    PROPRIETARY_PRODUCT = "proprietary_product"
    REGISTERED_TRADEMARK_PRODUCT = "registered_trademark_product"


class DPScenarioDisposition(StrEnum):
    VIABLE = "viable"
    CONDITIONAL = "conditional"
    INSUFFICIENT_INFORMATION = "insufficient_information"
    REJECTED = "rejected"


class DPConfidenceBand(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class DPPressureLossClass(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    REQUIRES_CALCULATION = "requires_calculation"


class DPVerificationPriority(StrEnum):
    MANDATORY = "mandatory"
    HIGH = "high"
    NORMAL = "normal"


class DPCalculationReadiness(StrEnum):
    STEP97_GENERIC_SUPPLIED_COEFFICIENTS = "step97_generic_supplied_coefficients"
    STEP98_GENERIC_SUPPLIED_COEFFICIENTS = "step98_generic_supplied_coefficients"
    REVIEWED_STANDARD_METHOD_REQUIRED = "reviewed_standard_method_required"
    MANUFACTURER_SIZING_REQUIRED = "manufacturer_sizing_required"
    DEVICE_SPECIFIC_CALIBRATION_REQUIRED = "device_specific_calibration_required"
    UNSUPPORTED = "unsupported"


class DPOfficialSource(CalculationModel):
    source_id: str = Field(min_length=3, max_length=120)
    owner: str = Field(min_length=2, max_length=160)
    title: str = Field(min_length=3, max_length=300)
    public_url: str = Field(pattern=r"^https://", max_length=1000)
    reviewed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    usage_boundary: str = Field(min_length=10, max_length=1000)


class DPProprietaryNotice(CalculationModel):
    name: str = Field(min_length=2, max_length=200)
    owner: str = Field(min_length=2, max_length=200)
    ownership_type: DPOwnershipType
    notice: str = Field(min_length=10, max_length=1000)
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=8)


class DPPrimaryElementDefinition(CalculationModel):
    option_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]+$", max_length=120)
    family: DPPrimaryElementFamily
    title: str = Field(min_length=3, max_length=200)
    variant: str = Field(min_length=3, max_length=300)
    ownership_type: DPOwnershipType
    owner: str | None = Field(default=None, max_length=200)
    generic_alternative_id: str | None = Field(default=None, max_length=120)
    typical_pressure_loss: DPPressureLossClass
    calculation_readiness: DPCalculationReadiness
    coefficient_basis: str = Field(min_length=10, max_length=1000)
    calculation_basis: str = Field(min_length=10, max_length=1000)
    strengths_to_verify: tuple[str, ...] = Field(min_length=1, max_length=12)
    limitations_to_verify: tuple[str, ...] = Field(min_length=1, max_length=12)
    source_ids: tuple[str, ...] = Field(default=(), max_length=8)
    proprietary_notice: DPProprietaryNotice | None = None

    @model_validator(mode="after")
    def validate_ownership(self) -> "DPPrimaryElementDefinition":
        proprietary = self.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY
        if proprietary and (self.owner is None or self.proprietary_notice is None):
            raise ValueError("proprietary options require an owner and notice")
        if not proprietary and (self.owner is not None or self.proprietary_notice is not None):
            raise ValueError("generic options cannot claim a proprietary owner")
        return self


class DPFlowApplicationRequest(CalculationModel):
    assessment_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$", max_length=120)
    fluid_phase: DPFluidPhase
    objective: DPMeasurementObjective
    pipe_inside_diameter_m: float | None = Field(default=None, gt=0.0, le=20.0)
    minimum_mass_flow_kg_s: float | None = Field(default=None, ge=0.0, le=1.0e12)
    normal_mass_flow_kg_s: float | None = Field(default=None, gt=0.0, le=1.0e12)
    maximum_mass_flow_kg_s: float | None = Field(default=None, gt=0.0, le=1.0e12)
    flowing_density_kg_m3: float | None = Field(default=None, ge=1.0e-12, le=1.0e7)
    flowing_viscosity_pa_s: float | None = Field(default=None, ge=1.0e-18, le=1.0e6)
    flowing_absolute_pressure_pa: float | None = Field(default=None, ge=1.0, le=1.0e12)
    flowing_temperature_k: float | None = Field(default=None, ge=1.0, le=1.0e6)
    available_upstream_straight_run_d: float | None = Field(default=None, ge=0.0, le=1000.0)
    available_downstream_straight_run_d: float | None = Field(default=None, ge=0.0, le=1000.0)
    maximum_permanent_pressure_loss_pa: float | None = Field(
        default=None,
        gt=0.0,
        le=1.0e12,
    )
    required_total_uncertainty_percent: float | None = Field(default=None, gt=0.0, le=100.0)
    dirty_or_solids_bearing: DPTriState = DPTriState.UNKNOWN
    erosive: DPTriState = DPTriState.UNKNOWN
    corrosive: DPTriState = DPTriState.UNKNOWN
    pulsating_flow: DPTriState = DPTriState.UNKNOWN
    bidirectional_flow: DPTriState = DPTriState.UNKNOWN
    wet_gas_or_condensing: DPTriState = DPTriState.UNKNOWN
    full_pipe_confirmed: DPTriState = DPTriState.UNKNOWN
    flashing_or_cavitation_risk: DPTriState = DPTriState.UNKNOWN
    sonic_or_choked_flow_risk: DPTriState = DPTriState.UNKNOWN
    intrusive_element_allowed: DPTriState = DPTriState.UNKNOWN
    shutdown_available_for_installation: DPTriState = DPTriState.UNKNOWN
    online_insertion_or_hot_tap_requested: DPTriState = DPTriState.UNKNOWN
    hazardous_area: DPTriState = DPTriState.UNKNOWN
    sour_or_toxic_service: DPTriState = DPTriState.UNKNOWN
    oxygen_or_high_purity_service: DPTriState = DPTriState.UNKNOWN
    approved_standard_or_oem_method_available: DPTriState = DPTriState.UNKNOWN
    traceable_coefficient_available: DPTriState = DPTriState.UNKNOWN
    include_proprietary_variants: StrictBool = True
    project_notes: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator(
        "pipe_inside_diameter_m", "minimum_mass_flow_kg_s", "normal_mass_flow_kg_s",
        "maximum_mass_flow_kg_s", "flowing_density_kg_m3", "flowing_viscosity_pa_s",
        "flowing_absolute_pressure_pa", "flowing_temperature_k",
        "available_upstream_straight_run_d", "available_downstream_straight_run_d",
        "maximum_permanent_pressure_loss_pa", "required_total_uncertainty_percent",
        mode="before",
    )
    @classmethod
    def finite_optional(cls, value: object) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("numeric application inputs must be explicit real values")
        try:
            normalized = float(value)
        except (OverflowError, TypeError, ValueError) as error:
            raise ValueError("numeric application inputs must be explicit real values") from error
        if not isfinite(normalized):
            raise ValueError("numeric application inputs must be finite")
        return 0.0 if normalized == 0.0 else normalized

    @model_validator(mode="after")
    def validate_flow_order(self) -> "DPFlowApplicationRequest":
        ordered = (
            self.minimum_mass_flow_kg_s,
            self.normal_mass_flow_kg_s,
            self.maximum_mass_flow_kg_s,
        )
        present = [value for value in ordered if value is not None]
        if len(present) == 3 and not (present[0] <= present[1] <= present[2]):
            raise ValueError("mass-flow cases must satisfy minimum <= normal <= maximum")
        return self


class DPVerificationStep(CalculationModel):
    verification_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]+$", max_length=120)
    priority: DPVerificationPriority
    action: str = Field(min_length=10, max_length=1000)
    acceptance_criteria: str = Field(min_length=10, max_length=1000)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=12)


class DPPrimaryElementScenario(CalculationModel):
    option: DPPrimaryElementDefinition
    disposition: DPScenarioDisposition
    engineering_score: int = Field(ge=-100, le=100)
    reasons: tuple[str, ...] = Field(min_length=1, max_length=32)
    rejected_reasons: tuple[str, ...] = Field(default=(), max_length=16)
    pressure_loss: DPPressureLossClass
    pressure_loss_output: str = Field(min_length=10, max_length=1000)
    straight_run_output: str = Field(min_length=10, max_length=1000)
    uncertainty_output: str = Field(min_length=10, max_length=1000)
    impulse_line_arrangement: str = Field(min_length=10, max_length=1000)
    calculation_method: str = Field(min_length=10, max_length=1000)
    calculation_readiness: DPCalculationReadiness
    standards_conformity_claimed: Literal[False] = False
    brand_ranked: Literal[False] = False


class DPFlowApplicationAssessment(CalculationModel):
    assessment_id: str
    model_version: str
    ruleset_version: str
    recommended_element: DPPrimaryElementScenario | None
    viable_alternatives: tuple[DPPrimaryElementScenario, ...] = Field(max_length=25)
    rejected_options: tuple[DPPrimaryElementScenario, ...] = Field(max_length=25)
    all_screened_options: tuple[DPPrimaryElementScenario, ...] = Field(
        min_length=1,
        max_length=25,
    )
    missing_information: tuple[str, ...] = Field(max_length=32)
    safety_findings: tuple[str, ...] = Field(min_length=1, max_length=32)
    verification_steps: tuple[DPVerificationStep, ...] = Field(
        min_length=1,
        max_length=16,
    )
    confidence_band: DPConfidenceBand
    confidence_score: int = Field(ge=0, le=100)
    proprietary_notices: tuple[DPProprietaryNotice, ...] = Field(max_length=7)
    official_sources: tuple[DPOfficialSource, ...] = Field(max_length=12)
    final_brand_decision_notice: str
    final_brand_selection: Literal["user_decision_required"] = (
        "user_decision_required"
    )
    manufacturer_declared_best: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    assessment_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_recommendation_boundary(self) -> "DPFlowApplicationAssessment":
        """Keep recommendations generic and catalogue collections coherent."""

        if (
            self.recommended_element is not None
            and self.recommended_element.option.ownership_type
            is not DPOwnershipType.GENERIC_TECHNOLOGY
        ):
            raise ValueError("recommended DP primary element must be generic")
        screened_ids = tuple(
            item.option.option_id for item in self.all_screened_options
        )
        if len(screened_ids) != len(set(screened_ids)):
            raise ValueError("screened DP primary-element identifiers must be unique")
        return self


__all__ = [name for name in globals() if name.startswith("DP") or name in {"DPTriState", "FINAL_BRAND_DECISION_NOTICE"}]
