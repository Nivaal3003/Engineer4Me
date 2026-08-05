"""Strict vendor-neutral models for Phase 7 analyzer application screening.

The contracts capture measurement duty, process and sample conditions,
interferences, response-time contributors, utilities, hazards, confidence, and
verification.  They do not select a manufacturer or model, execute a standard,
certify a hazardous-area installation, establish a protective function, or
grant engineering approval.  Step 107 adds the HTTP and controlled-knowledge
integration around these Step 106 domain contracts.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from enum import StrEnum
from hashlib import sha256
from math import isfinite
from typing import Annotated, Literal, Self

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.engineering.calculations.models import (
    CalculationModel,
    CalculationStatus,
    EngineeringQuantity,
    FindingCategory,
    FindingSeverity,
    FingerprintText,
    Identifier,
    LongText,
    MAX_ABSOLUTE_OPTION_NUMBER,
    ShortText,
    TextItem,
    VersionText,
)
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY, QuantityKind

ANALYZER_APPLICATION_MODEL_VERSION = "1.0.0"

MAX_ANALYZER_ANALYTES = 16
MAX_ANALYZER_OBJECTIVES = 8
MAX_ANALYZER_COMPONENTS = 32
MAX_ANALYZER_INTERFERENCES = 32
MAX_ANALYZER_CONTRIBUTORS = 16
MAX_ANALYZER_UTILITIES = 16
MAX_ANALYZER_ENVIRONMENTS = 16
MAX_ANALYZER_TECHNOLOGIES = 24
MAX_ANALYZER_RULES = 16
MAX_ANALYZER_LINKS = 64
MAX_ANALYZER_FINDINGS = 64
MAX_ANALYZER_MISSING_ITEMS = 64
MAX_ANALYZER_VERIFICATIONS = 64
MAX_ANALYZER_TEXT_ITEMS = 64


AnalyzerUnitText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=False,
        min_length=1,
        max_length=80,
    ),
]


class AnalyzerTriState(StrEnum):
    """Explicit answer where unknown must never be treated as no."""

    UNKNOWN = "unknown"
    NO = "no"
    YES = "yes"


class AnalyzerConditionSeverity(StrEnum):
    """Qualitative process or sample condition severity."""

    UNKNOWN = "unknown"
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class AnalyzerApplicationKind(StrEnum):
    """High-level analyzer workflow requested by the user."""

    UNKNOWN = "unknown"
    LIQUID_PROCESS = "liquid_process"
    PROCESS_GAS = "process_gas"
    GAS_CHROMATOGRAPHY = "gas_chromatography"
    GAS_DETECTION = "gas_detection"


class AnalyzerMeasurementObjective(StrEnum):
    """Technology-neutral measurement purpose."""

    CONTINUOUS_MONITORING = "continuous_monitoring"
    PROCESS_CONTROL = "process_control"
    QUALITY_CONTROL = "quality_control"
    COMPOSITION_ANALYSIS = "composition_analysis"
    ENVIRONMENTAL_REPORTING = "environmental_reporting"
    SAFETY_DETECTION = "safety_detection"
    ALARM_OR_SWITCH = "alarm_or_switch"


class AnalyzerAnalyteFamily(StrEnum):
    """Generic analyte family used for deterministic technology screening."""

    ACIDITY_ALKALINITY = "acidity_alkalinity"
    CONDUCTIVITY = "conductivity"
    DISSOLVED_OXYGEN = "dissolved_oxygen"
    TURBIDITY_SOLIDS = "turbidity_solids"
    ORGANIC_LOAD = "organic_load"
    OXYGEN = "oxygen"
    MOISTURE = "moisture"
    COMBUSTIBLE_GAS = "combustible_gas"
    TOXIC_GAS = "toxic_gas"
    VOLATILE_ORGANIC_COMPOUND = "volatile_organic_compound"
    HYDROCARBON = "hydrocarbon"
    MULTI_COMPONENT_COMPOSITION = "multi_component_composition"
    PHYSICAL_PROPERTY = "physical_property"
    OTHER = "other"


class AnalyzerSamplePhase(StrEnum):
    """Physical phase at the intended measurement point."""

    UNKNOWN = "unknown"
    LIQUID = "liquid"
    GAS = "gas"
    MULTIPHASE = "multiphase"


class AnalyzerSampleApproach(StrEnum):
    """Generic way in which the measurement sees the process."""

    UNKNOWN = "unknown"
    IN_SITU = "in_situ"
    EXTRACTIVE = "extractive"
    FAST_LOOP = "fast_loop"
    GRAB_SAMPLE = "grab_sample"
    POINT_DETECTOR = "point_detector"
    OPEN_PATH = "open_path"
    ASPIRATED_DETECTION = "aspirated_detection"


class AnalyzerSampleDisposition(StrEnum):
    """Declared destination of an extracted sample."""

    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    RETURN_TO_PROCESS = "return_to_process"
    CLOSED_RECOVERY = "closed_recovery"
    SAFE_VENT = "safe_vent"
    FLARE_OR_THERMAL_TREATMENT = "flare_or_thermal_treatment"
    DRAIN_OR_EFFLUENT_TREATMENT = "drain_or_effluent_treatment"


class AnalyzerResponseContributorKind(StrEnum):
    """Traceable contributor to end-to-end response time."""

    PROCESS_LAG = "process_lag"
    PROBE_OR_FILTER = "probe_or_filter"
    TRANSPORT_LINE = "transport_line"
    FAST_LOOP = "fast_loop"
    SAMPLE_CONDITIONING = "sample_conditioning"
    ANALYZER_CELL = "analyzer_cell"
    ANALYSIS_CYCLE = "analysis_cycle"
    MULTIPLEXING = "multiplexing"
    SIGNAL_PROCESSING = "signal_processing"
    CONTROL_SYSTEM = "control_system"


class AnalyzerInterferenceMechanism(StrEnum):
    """Generic way in which another component can bias a measurement."""

    SPECTRAL_OVERLAP = "spectral_overlap"
    CHEMICAL_CROSS_SENSITIVITY = "chemical_cross_sensitivity"
    MATRIX_EFFECT = "matrix_effect"
    MOISTURE_EFFECT = "moisture_effect"
    OXYGEN_EFFECT = "oxygen_effect"
    PRESSURE_OR_FLOW_EFFECT = "pressure_or_flow_effect"
    SENSOR_POISONING = "sensor_poisoning"
    CONDENSATION_OR_PHASE_CHANGE = "condensation_or_phase_change"
    PARTICULATE_OR_FOULING = "particulate_or_fouling"
    OTHER = "other"


class AnalyzerUtility(StrEnum):
    """Generic utility that may be required by an analyzer system."""

    ELECTRICAL_POWER = "electrical_power"
    INSTRUMENT_AIR = "instrument_air"
    NITROGEN = "nitrogen"
    CALIBRATION_GAS = "calibration_gas"
    CARRIER_GAS = "carrier_gas"
    ZERO_GAS = "zero_gas"
    COOLING_WATER = "cooling_water"
    STEAM = "steam"
    DRAIN = "drain"
    SAFE_VENT = "safe_vent"
    SHELTER_OR_HVAC = "shelter_or_hvac"


class AnalyzerEnvironmentCondition(StrEnum):
    """Installation conditions that need explicit design review."""

    INDOOR_CONTROLLED = "indoor_controlled"
    OUTDOOR = "outdoor"
    REMOTE_LOCATION = "remote_location"
    HIGH_VIBRATION = "high_vibration"
    HIGH_DUST = "high_dust"
    WASHDOWN = "washdown"
    CORROSIVE_ATMOSPHERE = "corrosive_atmosphere"
    COASTAL_OR_MARINE = "coastal_or_marine"
    HIGH_ELECTROMAGNETIC_INTERFERENCE = "high_electromagnetic_interference"
    EXTREME_HEAT = "extreme_heat"
    EXTREME_COLD = "extreme_cold"


class AnalyzerTechnology(StrEnum):
    """Vendor-neutral analyzer technology families."""

    PH_ELECTRODE = "ph_electrode"
    CONDUCTIVITY_CELL = "conductivity_cell"
    DISSOLVED_OXYGEN = "dissolved_oxygen"
    TURBIDITY_OPTICAL = "turbidity_optical"
    UV_VIS_LIQUID = "uv_vis_liquid"
    NDIR_GAS = "ndir_gas"
    PARAMAGNETIC_OXYGEN = "paramagnetic_oxygen"
    ZIRCONIA_OXYGEN = "zirconia_oxygen"
    TUNABLE_DIODE_LASER = "tunable_diode_laser"
    FTIR_GAS = "ftir_gas"
    THERMAL_CONDUCTIVITY = "thermal_conductivity"
    GAS_CHROMATOGRAPH = "gas_chromatograph"
    MASS_SPECTROMETRY = "mass_spectrometry"
    FLAME_IONIZATION = "flame_ionization"
    ELECTROCHEMICAL_GAS_DETECTOR = "electrochemical_gas_detector"
    CATALYTIC_BEAD_GAS_DETECTOR = "catalytic_bead_gas_detector"
    INFRARED_POINT_GAS_DETECTOR = "infrared_point_gas_detector"
    OPEN_PATH_INFRARED_GAS_DETECTOR = "open_path_infrared_gas_detector"
    PHOTOIONIZATION_DETECTOR = "photoionization_detector"
    SEMICONDUCTOR_GAS_DETECTOR = "semiconductor_gas_detector"
    ULTRASONIC_GAS_LEAK_DETECTOR = "ultrasonic_gas_leak_detector"


class AnalyzerRuleStatus(StrEnum):
    """Outcome of one deterministic screening rule."""

    PASSED = "passed"
    CAUTION = "caution"
    FAILED = "failed"
    MISSING_INFORMATION = "missing_information"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


class AnalyzerScenarioDisposition(StrEnum):
    """Fail-closed disposition of one generic technology scenario."""

    PLAUSIBLE = "plausible"
    CONDITIONAL = "conditional"
    INSUFFICIENT_INFORMATION = "insufficient_information"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


class AnalyzerConfidenceBand(StrEnum):
    """Fixed qualitative interpretation of evidence completeness."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class AnalyzerVerificationPriority(StrEnum):
    """Priority assigned to a required verification action."""

    ROUTINE = "routine"
    IMPORTANT = "important"
    SAFETY_CRITICAL = "safety_critical"


def _strict_unpadded_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        # Pydantic v2 converts ValueError, but deliberately propagates
        # TypeError beyond its validation boundary.
        raise ValueError(f"{field_name} must be text")  # noqa: TRY004
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be nonblank and unpadded")
    return value


def _canonical_text_tuple(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    normalized = tuple(
        _strict_unpadded_text(value, field_name=field_name) for value in values
    )
    comparisons = tuple(value.casefold() for value in normalized)
    if len(comparisons) != len(set(comparisons)):
        raise ValueError(f"{field_name} values must be unique")
    return tuple(sorted(normalized, key=lambda item: (item.casefold(), item)))


def _canonical_enum_tuple[EnumT: StrEnum](
    values: tuple[EnumT, ...], *, field_name: str
) -> tuple[EnumT, ...]:
    comparisons = tuple(value.value for value in values)
    if len(comparisons) != len(set(comparisons)):
        raise ValueError(f"{field_name} values must be unique")
    return tuple(sorted(values, key=lambda item: item.value))


def _unique_models(
    values: tuple[CalculationModel, ...],
    *,
    attribute: str,
    field_name: str,
) -> None:
    identities = tuple(str(getattr(item, attribute)).casefold() for item in values)
    if len(identities) != len(set(identities)):
        raise ValueError(f"{field_name} {attribute} values must be unique")


def _validate_quantity(
    value: EngineeringQuantity | None,
    *,
    field_name: str,
    quantity_kind: QuantityKind,
    positive: bool = False,
    nonnegative: bool = False,
) -> EngineeringQuantity | None:
    if value is None:
        return None
    validated = DEFAULT_UNIT_REGISTRY.validate_quantity(value)
    if validated.quantity_kind != quantity_kind.value:
        raise ValueError(f"{field_name} must use quantity_kind {quantity_kind.value!r}")
    canonical = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(validated)
    if positive and canonical.value <= 0.0:
        raise ValueError(f"{field_name} must be greater than zero")
    if nonnegative and canonical.value < 0.0:
        raise ValueError(f"{field_name} cannot be negative")
    return value


def canonical_analyzer_quantity_value(
    value: EngineeringQuantity | None,
) -> float | None:
    """Return one validated canonical quantity value for deterministic rules."""

    if value is None:
        return None
    return DEFAULT_UNIT_REGISTRY.canonicalize_quantity(
        DEFAULT_UNIT_REGISTRY.validate_quantity(value)
    ).value


class AnalyzerAnalyteRequirement(CalculationModel):
    """One analyte, range, and performance duty supplied by the caller."""

    analyte_id: Identifier
    display_name: ShortText
    family: AnalyzerAnalyteFamily
    engineering_unit: AnalyzerUnitText
    expected_minimum: StrictFloat
    expected_normal: StrictFloat
    expected_maximum: StrictFloat
    required_detection_limit: StrictFloat | None = Field(default=None, ge=0.0)
    required_accuracy: StrictFloat | None = Field(default=None, gt=0.0)
    source_reference: ShortText

    @field_validator(
        "analyte_id",
        "display_name",
        "engineering_unit",
        "source_reference",
        mode="before",
    )
    @classmethod
    def reject_padded_text(cls, value: object, info) -> str:
        return _strict_unpadded_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if not (self.expected_minimum <= self.expected_normal <= self.expected_maximum):
            raise ValueError(
                "expected analyte values must satisfy minimum <= normal <= maximum"
            )
        if (
            self.required_detection_limit is not None
            and self.required_detection_limit > self.expected_maximum
        ):
            raise ValueError("required_detection_limit cannot exceed expected_maximum")
        return self


class AnalyzerMeasurementRequirements(CalculationModel):
    """Technology-neutral analyzer duty and performance requirements."""

    objectives: tuple[AnalyzerMeasurementObjective, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_OBJECTIVES,
    )
    analytes: tuple[AnalyzerAnalyteRequirement, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_ANALYTES,
    )
    maximum_total_response_time: EngineeringQuantity | None = None
    minimum_availability_percent: StrictFloat | None = Field(
        default=None,
        gt=0.0,
        le=100.0,
    )
    continuous_output_required: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    local_indication_required: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    automatic_calibration_required: AnalyzerTriState = AnalyzerTriState.UNKNOWN

    @field_validator("objectives")
    @classmethod
    def validate_objectives(
        cls,
        values: tuple[AnalyzerMeasurementObjective, ...],
    ) -> tuple[AnalyzerMeasurementObjective, ...]:
        return _canonical_enum_tuple(values, field_name="objectives")

    @field_validator("analytes")
    @classmethod
    def validate_analytes(
        cls,
        values: tuple[AnalyzerAnalyteRequirement, ...],
    ) -> tuple[AnalyzerAnalyteRequirement, ...]:
        _unique_models(values, attribute="analyte_id", field_name="analytes")
        return tuple(sorted(values, key=lambda item: item.analyte_id))

    @model_validator(mode="after")
    def validate_response_time(self) -> Self:
        _validate_quantity(
            self.maximum_total_response_time,
            field_name="maximum_total_response_time",
            quantity_kind=QuantityKind.TIME,
            positive=True,
        )
        return self


class AnalyzerKnownInterference(CalculationModel):
    """Caller-supplied potential interference with traceable provenance."""

    interference_id: Identifier
    component_name: ShortText
    mechanism: AnalyzerInterferenceMechanism
    severity: AnalyzerConditionSeverity
    source_reference: ShortText
    mitigation_basis: LongText | None = None

    @field_validator(
        "interference_id",
        "component_name",
        "source_reference",
        "mitigation_basis",
        mode="before",
    )
    @classmethod
    def reject_padded_text(cls, value: object, info) -> str | None:
        if value is None:
            return None
        return _strict_unpadded_text(value, field_name=info.field_name)


class AnalyzerProcessContext(CalculationModel):
    """Process and sample matrix at the intended measurement location."""

    sample_phase: AnalyzerSamplePhase = AnalyzerSamplePhase.UNKNOWN
    stream_description: ShortText | None = None
    matrix_components: tuple[ShortText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_COMPONENTS,
    )
    minimum_temperature: EngineeringQuantity | None = None
    normal_temperature: EngineeringQuantity | None = None
    maximum_temperature: EngineeringQuantity | None = None
    minimum_absolute_pressure: EngineeringQuantity | None = None
    normal_absolute_pressure: EngineeringQuantity | None = None
    maximum_absolute_pressure: EngineeringQuantity | None = None
    dew_point_temperature: EngineeringQuantity | None = None
    composition_variability: AnalyzerConditionSeverity = (
        AnalyzerConditionSeverity.UNKNOWN
    )
    particulate_loading: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    liquid_droplets: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    wet_sample: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    corrosivity: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    fouling_tendency: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    reactivity: AnalyzerConditionSeverity = AnalyzerConditionSeverity.UNKNOWN
    known_interferences_assessed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    known_interferences: tuple[AnalyzerKnownInterference, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_INTERFERENCES,
    )

    @field_validator("stream_description", mode="before")
    @classmethod
    def reject_padded_description(cls, value: object) -> str | None:
        if value is None:
            return None
        return _strict_unpadded_text(value, field_name="stream_description")

    @field_validator("matrix_components", mode="before")
    @classmethod
    def reject_padded_components(cls, values: object) -> object:
        if isinstance(values, (list, tuple)):
            for value in values:
                _strict_unpadded_text(value, field_name="matrix_components")
        return values

    @field_validator("matrix_components")
    @classmethod
    def validate_components(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name="matrix_components")

    @field_validator("known_interferences")
    @classmethod
    def validate_interferences(
        cls,
        values: tuple[AnalyzerKnownInterference, ...],
    ) -> tuple[AnalyzerKnownInterference, ...]:
        _unique_models(
            values,
            attribute="interference_id",
            field_name="known_interferences",
        )
        return tuple(sorted(values, key=lambda item: item.interference_id))

    @model_validator(mode="after")
    def validate_process_conditions(self) -> Self:
        for field_name in (
            "minimum_temperature",
            "normal_temperature",
            "maximum_temperature",
            "dew_point_temperature",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            )
        for field_name in (
            "minimum_absolute_pressure",
            "normal_absolute_pressure",
            "maximum_absolute_pressure",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
                nonnegative=True,
            )
        temperatures = tuple(
            canonical_analyzer_quantity_value(getattr(self, name))
            for name in (
                "minimum_temperature",
                "normal_temperature",
                "maximum_temperature",
            )
        )
        if any(
            lower is not None and upper is not None and lower > upper
            for lower, upper in (
                (temperatures[0], temperatures[1]),
                (temperatures[0], temperatures[2]),
                (temperatures[1], temperatures[2]),
            )
        ):
            raise ValueError(
                "supplied process temperatures must satisfy minimum <= normal <= maximum"
            )
        pressures = tuple(
            canonical_analyzer_quantity_value(getattr(self, name))
            for name in (
                "minimum_absolute_pressure",
                "normal_absolute_pressure",
                "maximum_absolute_pressure",
            )
        )
        if any(
            lower is not None and upper is not None and lower > upper
            for lower, upper in (
                (pressures[0], pressures[1]),
                (pressures[0], pressures[2]),
                (pressures[1], pressures[2]),
            )
        ):
            raise ValueError(
                "supplied process pressures must satisfy minimum <= normal <= maximum"
            )
        if (
            self.known_interferences_assessed is AnalyzerTriState.NO
            and self.known_interferences
        ):
            raise ValueError(
                "known_interferences cannot be supplied when assessment is no"
            )
        return self


class AnalyzerResponseTimeContributor(CalculationModel):
    """One explicit, traceable end-to-end response-time contribution."""

    contributor_id: Identifier
    kind: AnalyzerResponseContributorKind
    duration: EngineeringQuantity
    basis: LongText
    source_reference: ShortText
    confirmed: StrictBool

    @field_validator(
        "contributor_id",
        "basis",
        "source_reference",
        mode="before",
    )
    @classmethod
    def reject_padded_text(cls, value: object, info) -> str:
        return _strict_unpadded_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_duration(self) -> Self:
        _validate_quantity(
            self.duration,
            field_name="duration",
            quantity_kind=QuantityKind.TIME,
            positive=True,
        )
        return self


class AnalyzerSampleSystemContext(CalculationModel):
    """Sampling, conditioning, transport, and disposal design state."""

    approach: AnalyzerSampleApproach = AnalyzerSampleApproach.UNKNOWN
    delivered_sample_phase: AnalyzerSamplePhase = AnalyzerSamplePhase.UNKNOWN
    phase_conversion_basis_reference: ShortText | None = None
    extraction_location_reference: ShortText | None = None
    representative_sample_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    sample_probe_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    filtration_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    pressure_control_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    temperature_control_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    phase_preservation_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    materials_compatibility_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    calibration_introduction_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    sample_line_length: EngineeringQuantity | None = None
    sample_line_internal_diameter: EngineeringQuantity | None = None
    sample_flow_rate: EngineeringQuantity | None = None
    disposition: AnalyzerSampleDisposition = AnalyzerSampleDisposition.UNKNOWN
    disposition_basis_reference: ShortText | None = None
    return_compatibility_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    response_time_budget_complete: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    gc_separation_and_coelution_verified: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    gc_sample_loop_representative_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    gc_calibration_mixture_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    gc_carrier_gas_quality_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    response_time_contributors: tuple[AnalyzerResponseTimeContributor, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_CONTRIBUTORS,
    )

    @field_validator(
        "extraction_location_reference",
        "phase_conversion_basis_reference",
        "disposition_basis_reference",
        mode="before",
    )
    @classmethod
    def reject_padded_text(cls, value: object, info) -> str | None:
        if value is None:
            return None
        return _strict_unpadded_text(value, field_name=info.field_name)

    @field_validator("response_time_contributors")
    @classmethod
    def validate_contributors(
        cls,
        values: tuple[AnalyzerResponseTimeContributor, ...],
    ) -> tuple[AnalyzerResponseTimeContributor, ...]:
        _unique_models(
            values,
            attribute="contributor_id",
            field_name="response_time_contributors",
        )
        return tuple(sorted(values, key=lambda item: item.contributor_id))

    @model_validator(mode="after")
    def validate_sample_system(self) -> Self:
        _validate_quantity(
            self.sample_line_length,
            field_name="sample_line_length",
            quantity_kind=QuantityKind.LENGTH,
            positive=True,
        )
        _validate_quantity(
            self.sample_line_internal_diameter,
            field_name="sample_line_internal_diameter",
            quantity_kind=QuantityKind.LENGTH,
            positive=True,
        )
        _validate_quantity(
            self.sample_flow_rate,
            field_name="sample_flow_rate",
            quantity_kind=QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
            positive=True,
        )
        if (
            self.disposition is AnalyzerSampleDisposition.RETURN_TO_PROCESS
            and self.return_compatibility_confirmed is AnalyzerTriState.NO
        ):
            raise ValueError(
                "return-to-process disposition conflicts with rejected compatibility"
            )
        if self.approach in {
            AnalyzerSampleApproach.IN_SITU,
            AnalyzerSampleApproach.POINT_DETECTOR,
            AnalyzerSampleApproach.OPEN_PATH,
        } and self.disposition not in {
            AnalyzerSampleDisposition.UNKNOWN,
            AnalyzerSampleDisposition.NOT_APPLICABLE,
        }:
            raise ValueError(
                "non-extractive approaches cannot declare extracted sample disposition"
            )
        if self.approach in {
            AnalyzerSampleApproach.IN_SITU,
            AnalyzerSampleApproach.POINT_DETECTOR,
            AnalyzerSampleApproach.OPEN_PATH,
        } and (
            self.sample_line_length is not None
            or self.sample_line_internal_diameter is not None
            or self.sample_flow_rate is not None
        ):
            raise ValueError(
                "non-extractive approaches cannot declare sample-line transport data"
            )
        if self.approach in {
            AnalyzerSampleApproach.IN_SITU,
            AnalyzerSampleApproach.POINT_DETECTOR,
            AnalyzerSampleApproach.OPEN_PATH,
        } and any(
            item.kind
            in {
                AnalyzerResponseContributorKind.TRANSPORT_LINE,
                AnalyzerResponseContributorKind.FAST_LOOP,
                AnalyzerResponseContributorKind.SAMPLE_CONDITIONING,
            }
            for item in self.response_time_contributors
        ):
            raise ValueError(
                "non-extractive approaches cannot declare extractive response contributors"
            )
        if (
            self.approach
            in {
                AnalyzerSampleApproach.EXTRACTIVE,
                AnalyzerSampleApproach.FAST_LOOP,
                AnalyzerSampleApproach.GRAB_SAMPLE,
                AnalyzerSampleApproach.ASPIRATED_DETECTION,
            }
            and self.disposition is AnalyzerSampleDisposition.NOT_APPLICABLE
        ):
            raise ValueError(
                "extractive approaches require an explicit sample disposition"
            )
        return self


class AnalyzerSafetyContext(CalculationModel):
    """Hazards and protection boundaries that must remain explicit."""

    hazardous_area: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    hazardous_area_classification: ShortText | None = None
    toxic_material: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    flammable_material: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    oxygen_deficiency_or_enrichment: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    high_pressure_sampling: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    high_temperature_sampling: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    sample_containment_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    safe_vent_or_disposal_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    exposure_control_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    gas_detection_safety_function: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    alarm_basis_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    detector_coverage_basis_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    detector_response_basis_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    hazardous_area_equipment_certification_confirmed: AnalyzerTriState = (
        AnalyzerTriState.UNKNOWN
    )
    independence_requirement_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    proof_test_and_bypass_basis_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN

    @field_validator("hazardous_area_classification", mode="before")
    @classmethod
    def reject_padded_classification(cls, value: object) -> str | None:
        if value is None:
            return None
        return _strict_unpadded_text(
            value,
            field_name="hazardous_area_classification",
        )

    @model_validator(mode="after")
    def validate_safety_context(self) -> Self:
        if (
            self.hazardous_area is AnalyzerTriState.NO
            and self.hazardous_area_classification is not None
        ):
            raise ValueError(
                "hazardous-area classification conflicts with hazardous_area=no"
            )
        if (
            self.gas_detection_safety_function is AnalyzerTriState.NO
            and self.proof_test_and_bypass_basis_defined is AnalyzerTriState.YES
        ):
            raise ValueError(
                "proof-test basis cannot establish an undeclared safety function"
            )
        if (
            self.hazardous_area is AnalyzerTriState.NO
            and self.hazardous_area_equipment_certification_confirmed
            is AnalyzerTriState.YES
        ):
            raise ValueError(
                "hazardous-area certification evidence conflicts with hazardous_area=no"
            )
        return self


class AnalyzerInstallationContext(CalculationModel):
    """Utilities, environment, access, and maintainability inputs."""

    available_utilities: tuple[AnalyzerUtility, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_UTILITIES,
    )
    utility_availability_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    environment_conditions: tuple[AnalyzerEnvironmentCondition, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_ENVIRONMENTS,
    )
    minimum_ambient_temperature: EngineeringQuantity | None = None
    maximum_ambient_temperature: EngineeringQuantity | None = None
    maintenance_access_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    calibration_access_confirmed: AnalyzerTriState = AnalyzerTriState.UNKNOWN
    shelter_or_enclosure_basis_defined: AnalyzerTriState = AnalyzerTriState.UNKNOWN

    @field_validator("available_utilities", "environment_conditions")
    @classmethod
    def validate_enum_collections(cls, values: tuple[StrEnum, ...], info):
        return _canonical_enum_tuple(values, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_ambient_conditions(self) -> Self:
        for field_name in (
            "minimum_ambient_temperature",
            "maximum_ambient_temperature",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            )
        minimum = canonical_analyzer_quantity_value(self.minimum_ambient_temperature)
        maximum = canonical_analyzer_quantity_value(self.maximum_ambient_temperature)
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValueError(
                "minimum_ambient_temperature cannot exceed maximum_ambient_temperature"
            )
        return self


class AnalyzerApplicationRequest(CalculationModel):
    """Complete deterministic input to one analyzer application assessment."""

    request_id: Identifier
    application_kind: AnalyzerApplicationKind = AnalyzerApplicationKind.UNKNOWN
    measurement: AnalyzerMeasurementRequirements = Field(
        default_factory=AnalyzerMeasurementRequirements
    )
    process: AnalyzerProcessContext = Field(default_factory=AnalyzerProcessContext)
    sample_system: AnalyzerSampleSystemContext = Field(
        default_factory=AnalyzerSampleSystemContext
    )
    safety: AnalyzerSafetyContext = Field(default_factory=AnalyzerSafetyContext)
    installation: AnalyzerInstallationContext = Field(
        default_factory=AnalyzerInstallationContext
    )
    application_notes: LongText | None = None

    @field_validator("request_id", "application_notes", mode="before")
    @classmethod
    def reject_padded_text(cls, value: object, info) -> str | None:
        if value is None:
            return None
        return _strict_unpadded_text(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_kind_phase(self) -> Self:
        if (
            self.application_kind is AnalyzerApplicationKind.GAS_DETECTION
            and self.sample_system.approach
            in {
                AnalyzerSampleApproach.EXTRACTIVE,
                AnalyzerSampleApproach.FAST_LOOP,
                AnalyzerSampleApproach.GRAB_SAMPLE,
            }
        ):
            raise ValueError(
                "gas-detection screening requires a point or open-path approach"
            )
        if self.sample_system.approach in {
            AnalyzerSampleApproach.IN_SITU,
            AnalyzerSampleApproach.POINT_DETECTOR,
            AnalyzerSampleApproach.OPEN_PATH,
        }:
            if self.sample_system.phase_conversion_basis_reference is not None:
                raise ValueError(
                    "non-extractive approaches cannot declare a phase-conversion basis"
                )
            if (
                self.sample_system.delivered_sample_phase
                is not AnalyzerSamplePhase.UNKNOWN
                and self.sample_system.delivered_sample_phase
                is not self.process.sample_phase
            ):
                raise ValueError(
                    "non-extractive delivered phase must match the process phase"
                )
        return self


class AnalyzerTechnologyDefinition(CalculationModel):
    """Immutable vendor-neutral technology taxonomy entry."""

    technology: AnalyzerTechnology
    title: ShortText
    principle: LongText
    supported_application_kinds: tuple[AnalyzerApplicationKind, ...] = Field(
        min_length=1,
        max_length=4,
    )
    supported_analyte_families: tuple[AnalyzerAnalyteFamily, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_ANALYTES,
    )
    supported_sample_phases: tuple[AnalyzerSamplePhase, ...] = Field(
        min_length=1,
        max_length=3,
    )
    supported_sample_approaches: tuple[AnalyzerSampleApproach, ...] = Field(
        min_length=1,
        max_length=6,
    )
    required_utilities: tuple[AnalyzerUtility, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_UTILITIES,
    )
    extractive_sample_system_required: StrictBool
    cycle_based_measurement: StrictBool
    generic_limitations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )
    vendor_neutral: Literal[True] = True
    manufacturer_model_selected: Literal[False] = False
    final_suitability_claimed: Literal[False] = False

    @field_validator(
        "supported_application_kinds",
        "supported_analyte_families",
        "supported_sample_phases",
        "supported_sample_approaches",
        "required_utilities",
    )
    @classmethod
    def validate_enums(cls, values: tuple[StrEnum, ...], info):
        return _canonical_enum_tuple(values, field_name=info.field_name)

    @field_validator("generic_limitations", mode="before")
    @classmethod
    def reject_padded_limitations(cls, values: object) -> object:
        if isinstance(values, (list, tuple)):
            for value in values:
                _strict_unpadded_text(value, field_name="generic_limitations")
        return values

    @field_validator("generic_limitations")
    @classmethod
    def validate_limitations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name="generic_limitations")


class AnalyzerRuleResult(CalculationModel):
    """Auditable result for one named analyzer screening rule."""

    rule_id: Identifier
    status: AnalyzerRuleStatus
    category: FindingCategory
    weight: StrictFloat = Field(gt=0.0, le=100.0)
    awarded_weight: StrictFloat = Field(ge=0.0, le=100.0)
    explanation: LongText
    missing_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_LINKS,
    )
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )

    @field_validator(
        "missing_field_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_links(cls, values: tuple[str, ...], info) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        if self.awarded_weight > self.weight:
            raise ValueError("awarded_weight cannot exceed weight")
        expected_award = (
            self.weight
            if self.status is AnalyzerRuleStatus.PASSED
            else self.weight * 0.5
            if self.status is AnalyzerRuleStatus.CAUTION
            else 0.0
        )
        if self.awarded_weight != expected_award:
            raise ValueError(
                "awarded_weight must be derived from rule status and weight"
            )
        if (self.status is AnalyzerRuleStatus.MISSING_INFORMATION) != bool(
            self.missing_field_ids
        ):
            raise ValueError(
                "missing_field_ids must exist exactly for missing-information rules"
            )
        return self


class AnalyzerMissingInformation(CalculationModel):
    """One visible unknown input and its affected technology families."""

    field_id: Identifier
    reason: LongText
    safety_critical: StrictBool
    affected_technologies: tuple[AnalyzerTechnology, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TECHNOLOGIES,
    )

    @field_validator("affected_technologies")
    @classmethod
    def validate_technologies(
        cls,
        values: tuple[AnalyzerTechnology, ...],
    ) -> tuple[AnalyzerTechnology, ...]:
        return _canonical_enum_tuple(values, field_name="affected_technologies")


class AnalyzerVerificationStep(CalculationModel):
    """Concrete action required before an analyzer design commitment."""

    verification_id: Identifier
    priority: AnalyzerVerificationPriority
    description: LongText
    acceptance_criteria: LongText
    required_competency: ShortText
    independent: StrictBool
    evidence_required: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )

    @field_validator("evidence_required", mode="before")
    @classmethod
    def reject_padded_evidence(cls, values: object) -> object:
        if isinstance(values, (list, tuple)):
            for value in values:
                _strict_unpadded_text(value, field_name="evidence_required")
        return values

    @field_validator("evidence_required")
    @classmethod
    def validate_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name="evidence_required")


class AnalyzerSafetyFinding(CalculationModel):
    """Safety-leading finding that cannot be suppressed by confidence."""

    finding_id: Identifier
    category: Literal[FindingCategory.SAFETY] = FindingCategory.SAFETY
    severity: FindingSeverity
    title: ShortText
    message: LongText
    blocking: StrictBool
    required_action: LongText
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )
    affected_technologies: tuple[AnalyzerTechnology, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TECHNOLOGIES,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )

    @field_validator("verification_requirement_ids", "reference_ids")
    @classmethod
    def validate_links(cls, values: tuple[str, ...], info) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name=info.field_name)

    @field_validator("affected_technologies")
    @classmethod
    def validate_technologies(
        cls,
        values: tuple[AnalyzerTechnology, ...],
    ) -> tuple[AnalyzerTechnology, ...]:
        return _canonical_enum_tuple(values, field_name="affected_technologies")

    @model_validator(mode="after")
    def validate_blocking_state(self) -> Self:
        if self.severity in {FindingSeverity.ERROR, FindingSeverity.CRITICAL} and (
            not self.blocking
        ):
            raise ValueError("error and critical safety findings must be blocking")
        if self.blocking and self.severity not in {
            FindingSeverity.WARNING,
            FindingSeverity.ERROR,
            FindingSeverity.CRITICAL,
        }:
            raise ValueError("blocking findings require warning or higher severity")
        return self


class AnalyzerTechnologyScenario(CalculationModel):
    """One technology-generic, evidence-based screening scenario."""

    scenario_id: Identifier
    technology: AnalyzerTechnology
    title: ShortText
    disposition: AnalyzerScenarioDisposition
    screening_order: StrictInt | None = Field(
        default=None,
        ge=1,
        le=MAX_ANALYZER_TECHNOLOGIES,
    )
    suitability_score: StrictFloat = Field(ge=0.0, le=100.0)
    confidence_score: StrictFloat = Field(ge=0.0, le=100.0)
    confidence_band: AnalyzerConfidenceBand
    confidence_rationale: LongText
    rule_results: tuple[AnalyzerRuleResult, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_RULES,
    )
    estimated_total_response_time_seconds: StrictFloat | None = Field(
        default=None,
        gt=0.0,
    )
    reasons: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )
    limitations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )
    missing_information_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_LINKS,
    )
    finding_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_LINKS,
    )
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_LINKS,
    )
    vendor_neutral: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    model_selection_performed: Literal[False] = False
    final_suitability_claimed: Literal[False] = False

    @field_validator(
        "reasons",
        "limitations",
        "missing_information_ids",
        "finding_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_text_collections(
        cls,
        values: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        _unique_models(
            self.rule_results,
            attribute="rule_id",
            field_name="rule_results",
        )
        if self.rule_results != tuple(
            sorted(self.rule_results, key=lambda item: item.rule_id)
        ):
            raise ValueError("rule_results must be ordered by rule_id")
        expected_band = analyzer_confidence_band(self.confidence_score)
        if self.confidence_band is not expected_band:
            raise ValueError("confidence_band must match confidence_score")
        statuses = {item.status for item in self.rule_results}
        expected_disposition = (
            AnalyzerScenarioDisposition.BLOCKED
            if AnalyzerRuleStatus.BLOCKED in statuses
            else AnalyzerScenarioDisposition.NOT_APPLICABLE
            if AnalyzerRuleStatus.NOT_APPLICABLE in statuses
            else AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION
            if AnalyzerRuleStatus.MISSING_INFORMATION in statuses
            else AnalyzerScenarioDisposition.CONDITIONAL
            if AnalyzerRuleStatus.FAILED in statuses or self.suitability_score < 65.0
            else AnalyzerScenarioDisposition.PLAUSIBLE
        )
        if self.disposition is not expected_disposition:
            raise ValueError("scenario disposition does not match rule precedence")
        expected_score = (
            0.0
            if self.disposition
            in {
                AnalyzerScenarioDisposition.BLOCKED,
                AnalyzerScenarioDisposition.NOT_APPLICABLE,
            }
            else sum(item.awarded_weight for item in self.rule_results)
        )
        if self.suitability_score != expected_score:
            raise ValueError(
                "suitability_score must equal the rule-derived awarded weight"
            )
        if self.disposition in {
            AnalyzerScenarioDisposition.BLOCKED,
            AnalyzerScenarioDisposition.NOT_APPLICABLE,
        }:
            if self.screening_order is not None or self.suitability_score != 0.0:
                raise ValueError(
                    "blocked and not-applicable scenarios are unranked with zero score"
                )
        elif self.screening_order is None:
            raise ValueError("screenable scenarios require screening_order")
        linked_missing = {
            field_id
            for rule in self.rule_results
            for field_id in rule.missing_field_ids
        }
        if linked_missing != set(self.missing_information_ids):
            raise ValueError(
                "scenario missing_information_ids must exactly match its rules"
            )
        return self


def analyzer_confidence_band(score: float) -> AnalyzerConfidenceBand:
    """Return the fixed confidence band for a bounded score."""

    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise TypeError("analyzer confidence score must be a finite number")
    try:
        score = float(score)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError(
            "analyzer confidence score must be a finite number"
        ) from error
    if not isfinite(score) or not 0.0 <= score <= 100.0:
        raise ValueError("analyzer confidence score must be from zero through 100")
    return (
        AnalyzerConfidenceBand.VERY_LOW
        if score < 20.0
        else AnalyzerConfidenceBand.LOW
        if score < 40.0
        else AnalyzerConfidenceBand.MODERATE
        if score < 60.0
        else AnalyzerConfidenceBand.HIGH
        if score < 80.0
        else AnalyzerConfidenceBand.VERY_HIGH
    )


def fingerprint_analyzer_payload(value: object) -> str:
    """Return lowercase SHA-256 over canonical JSON-safe model content."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="json", round_trip=True, warnings="error")

    active_containers: set[int] = set()

    def canonicalize(item: object, *, depth: int = 0) -> object:
        """Normalize JSON-equivalent values before deterministic hashing."""

        if depth > 64:
            raise ValueError("analyzer fingerprint payload nesting is too deep")
        if item is None or isinstance(item, (str, bool)):
            return item
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > MAX_ABSOLUTE_OPTION_NUMBER:
                raise ValueError(
                    "analyzer fingerprint integer exceeds the supported range"
                )
            return item
        if isinstance(item, float):
            if not isfinite(item) or abs(item) > MAX_ABSOLUTE_OPTION_NUMBER:
                raise ValueError(
                    "analyzer fingerprint number must be finite and bounded"
                )
            return 0.0 if item == 0.0 else item
        if isinstance(item, Mapping):
            if not all(isinstance(key, str) for key in item):
                raise ValueError(
                    "analyzer fingerprint mapping keys must be strings"
                )
            identity = id(item)
            if identity in active_containers:
                raise ValueError("analyzer fingerprint payload cannot be cyclic")
            active_containers.add(identity)
            try:
                return {
                    key: canonicalize(nested, depth=depth + 1)
                    for key, nested in item.items()
                }
            finally:
                active_containers.remove(identity)
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active_containers:
                raise ValueError("analyzer fingerprint payload cannot be cyclic")
            active_containers.add(identity)
            try:
                return [
                    canonicalize(nested, depth=depth + 1) for nested in item
                ]
            finally:
                active_containers.remove(identity)
        raise ValueError(
            "analyzer fingerprint payload contains an unsupported value"
        )

    payload = json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


class AnalyzerApplicationAssessment(CalculationModel):
    """Deterministic safety-first Step 106 analyzer assessment."""

    safety_findings: tuple[AnalyzerSafetyFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_FINDINGS,
    )
    status: CalculationStatus
    model_version: Literal["1.0.0"] = ANALYZER_APPLICATION_MODEL_VERSION
    assistant_version: VersionText
    ruleset_version: VersionText
    assessment_fingerprint: FingerprintText
    request: AnalyzerApplicationRequest
    missing_information: tuple[AnalyzerMissingInformation, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ANALYZER_MISSING_ITEMS,
    )
    scenarios: tuple[AnalyzerTechnologyScenario, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TECHNOLOGIES,
    )
    verification_steps: tuple[AnalyzerVerificationStep, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_VERIFICATIONS,
    )
    observations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )
    limitations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_ANALYZER_TEXT_ITEMS,
    )
    vendor_neutral: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    manufacturer_declared_best: Literal[False] = False
    model_selection_performed: Literal[False] = False
    product_selected: Literal[False] = False
    brand_ranked: Literal[False] = False
    final_brand_selection: Literal["user_decision_required"] = "user_decision_required"
    standards_conformity_claimed: Literal[False] = False
    hazardous_area_certification_performed: Literal[False] = False
    safety_integrity_claimed: Literal[False] = False
    sample_system_approved: Literal[False] = False
    alarm_setpoint_selected: Literal[False] = False
    detector_placement_or_coverage_approved: Literal[False] = False
    final_design_approval_granted: Literal[False] = False
    approved_for_project_use: Literal[False] = False
    disclaimer: LongText = (
        "Engineer4Me provides preliminary, technology-generic analyzer "
        "application decision support only. This assessment does not select "
        "a manufacturer or model, prove measurement performance or fitness "
        "for service, certify hazardous-area or functional-safety compliance, "
        "approve sample containment or disposal, or replace site risk review, "
        "representative testing, current requirements, manufacturer evidence, "
        "and review by competent process, analyzer, safety, and electrical "
        "engineers."
    )

    @field_validator("observations", "limitations")
    @classmethod
    def validate_text_items(
        cls,
        values: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        return _canonical_text_tuple(values, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        _unique_models(
            self.safety_findings,
            attribute="finding_id",
            field_name="safety_findings",
        )
        _unique_models(
            self.missing_information,
            attribute="field_id",
            field_name="missing_information",
        )
        _unique_models(
            self.scenarios,
            attribute="scenario_id",
            field_name="scenarios",
        )
        _unique_models(
            self.verification_steps,
            attribute="verification_id",
            field_name="verification_steps",
        )
        if self.safety_findings != tuple(
            sorted(self.safety_findings, key=lambda item: item.finding_id)
        ):
            raise ValueError("safety_findings must be ordered by finding_id")
        if self.missing_information != tuple(
            sorted(self.missing_information, key=lambda item: item.field_id)
        ):
            raise ValueError("missing_information must be ordered by field_id")
        if self.verification_steps != tuple(
            sorted(self.verification_steps, key=lambda item: item.verification_id)
        ):
            raise ValueError("verification_steps must be ordered by verification_id")
        finding_ids = {item.finding_id for item in self.safety_findings}
        missing_ids = {item.field_id for item in self.missing_information}
        verification_ids = {item.verification_id for item in self.verification_steps}
        used_verifications: set[str] = set()
        finding_usage = {item: set() for item in finding_ids}
        missing_usage = {item: set() for item in missing_ids}
        for scenario in self.scenarios:
            if not set(scenario.finding_ids).issubset(finding_ids):
                raise ValueError("scenario links unknown safety findings")
            if not set(scenario.missing_information_ids).issubset(missing_ids):
                raise ValueError("scenario links unknown missing information")
            if not set(scenario.verification_requirement_ids).issubset(
                verification_ids
            ):
                raise ValueError("scenario links unknown verification steps")
            used_verifications.update(scenario.verification_requirement_ids)
            for rule in scenario.rule_results:
                if not set(rule.verification_requirement_ids).issubset(
                    verification_ids
                ):
                    raise ValueError("rule links unknown verification steps")
                used_verifications.update(rule.verification_requirement_ids)
            for finding_id in scenario.finding_ids:
                finding_usage[finding_id].add(scenario.technology)
            for field_id in scenario.missing_information_ids:
                missing_usage[field_id].add(scenario.technology)
        for finding in self.safety_findings:
            used_verifications.update(finding.verification_requirement_ids)
            if finding_usage[finding.finding_id] != set(finding.affected_technologies):
                raise ValueError(
                    "finding affected_technologies must match scenario links"
                )
        for item in self.missing_information:
            if missing_usage[item.field_id] != set(item.affected_technologies):
                raise ValueError(
                    "missing-information technologies must match scenario links"
                )
        if used_verifications != verification_ids:
            raise ValueError("verification steps must be linked and not orphaned")
        orders = sorted(
            item.screening_order
            for item in self.scenarios
            if item.screening_order is not None
        )
        if orders != list(range(1, len(orders) + 1)):
            raise ValueError("screening_order must be dense and unique from one")
        screenable = tuple(
            item for item in self.scenarios if item.screening_order is not None
        )
        expected_ranks = {
            item.technology: index
            for index, item in enumerate(
                sorted(
                    screenable,
                    key=lambda item: (
                        -item.suitability_score,
                        -item.confidence_score,
                        item.technology.value,
                    ),
                ),
                start=1,
            )
        }
        if any(
            item.screening_order != expected_ranks[item.technology]
            for item in screenable
        ):
            raise ValueError(
                "screening_order must follow score, confidence, and technology"
            )
        expected_scenario_order = tuple(
            sorted(
                self.scenarios,
                key=lambda item: (
                    item.screening_order is None,
                    item.screening_order or MAX_ANALYZER_TECHNOLOGIES + 1,
                    item.technology.value,
                ),
            )
        )
        if self.scenarios != expected_scenario_order:
            raise ValueError("scenarios must be ordered by screening order")
        blocking = any(item.blocking for item in self.safety_findings)
        plausible = any(
            item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
            for item in self.scenarios
        )
        safety_critical_missing = any(
            item.safety_critical for item in self.missing_information
        )
        expected_status = (
            CalculationStatus.BLOCKED
            if blocking
            else CalculationStatus.NOT_APPLICABLE
            if all(
                item.disposition is AnalyzerScenarioDisposition.NOT_APPLICABLE
                for item in self.scenarios
            )
            else CalculationStatus.INSUFFICIENT_INPUT
            if safety_critical_missing
            or (not plausible and bool(self.missing_information))
            else CalculationStatus.FAILED
            if not plausible
            else CalculationStatus.COMPLETED_WITH_WARNINGS
        )
        if self.status is not expected_status:
            raise ValueError("assessment status does not match fail-closed evidence")
        values = self.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
            exclude={"assessment_fingerprint"},
        )
        expected_fingerprint = fingerprint_analyzer_payload(values)
        if self.assessment_fingerprint != expected_fingerprint:
            raise ValueError(
                f"assessment_fingerprint is stale; expected {expected_fingerprint}"
            )
        return self


__all__ = [
    "ANALYZER_APPLICATION_MODEL_VERSION",
    "AnalyzerAnalyteFamily",
    "AnalyzerAnalyteRequirement",
    "AnalyzerApplicationAssessment",
    "AnalyzerApplicationKind",
    "AnalyzerApplicationRequest",
    "AnalyzerConditionSeverity",
    "AnalyzerConfidenceBand",
    "AnalyzerEnvironmentCondition",
    "AnalyzerInstallationContext",
    "AnalyzerInterferenceMechanism",
    "AnalyzerKnownInterference",
    "AnalyzerMeasurementObjective",
    "AnalyzerMeasurementRequirements",
    "AnalyzerMissingInformation",
    "AnalyzerProcessContext",
    "AnalyzerResponseContributorKind",
    "AnalyzerResponseTimeContributor",
    "AnalyzerRuleResult",
    "AnalyzerRuleStatus",
    "AnalyzerSafetyContext",
    "AnalyzerSafetyFinding",
    "AnalyzerSampleApproach",
    "AnalyzerSampleDisposition",
    "AnalyzerSamplePhase",
    "AnalyzerSampleSystemContext",
    "AnalyzerScenarioDisposition",
    "AnalyzerTechnology",
    "AnalyzerTechnologyDefinition",
    "AnalyzerTriState",
    "AnalyzerUnitText",
    "AnalyzerUtility",
    "AnalyzerVerificationPriority",
    "AnalyzerVerificationStep",
    "analyzer_confidence_band",
    "canonical_analyzer_quantity_value",
    "fingerprint_analyzer_payload",
]
