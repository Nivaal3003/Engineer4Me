"""Strict models for the Engineer4Me level-application design wizard.

The models in this module describe an auditable, technology-generic design
assessment.  They deliberately contain no product catalogue, model numbers,
database or network access, calculation execution, dynamic expressions, or
voice functionality.  Calculation method identifiers are links to the
reviewed Step 95 methods; they are never invoked by this domain.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated
from typing import Self

from pydantic import Field
from pydantic import StrictBool
from pydantic import StrictFloat
from pydantic import StrictInt
from pydantic import StringConstraints
from pydantic import field_validator
from pydantic import model_validator

from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import FingerprintText
from app.engineering.calculations.models import Identifier
from app.engineering.calculations.models import LongText
from app.engineering.calculations.models import ShortText
from app.engineering.calculations.models import TextItem
from app.engineering.calculations.models import VersionText
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import QuantityKind


MAX_LEVEL_OBJECTIVES = 8
MAX_LEVEL_ENVIRONMENTS = 24
MAX_LEVEL_APPROVALS = 24
MAX_LEVEL_PROTECTION_FUNCTIONS = 8
MAX_LEVEL_METHOD_LINKS = 9
MAX_LEVEL_RULE_RESULTS = 64
MAX_LEVEL_SCENARIOS = 16
MAX_LEVEL_FINDINGS = 128
MAX_LEVEL_MISSING_INFORMATION = 128
MAX_LEVEL_VERIFICATION_STEPS = 128
MAX_LEVEL_LINKS = 64
MAX_LEVEL_TEXT_ITEMS = 64

LEVEL_APPLICATION_MODEL_VERSION = "1.0.0"


ApprovalText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=120,
    ),
]


SUPPORTED_LEVEL_CALCULATION_METHOD_IDS = (
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

# A concise compatibility alias for code that treats the links generically.
SUPPORTED_LEVEL_METHOD_IDS = SUPPORTED_LEVEL_CALCULATION_METHOD_IDS


class LevelTriState(StrEnum):
    """Explicit three-state answer used where unknown is safety-relevant."""

    UNKNOWN = "unknown"
    NO = "no"
    YES = "yes"


class LevelConditionSeverity(StrEnum):
    """Observed process-condition severity without inventing a default."""

    UNKNOWN = "unknown"
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class LevelMeasurementObjective(StrEnum):
    """Technology-neutral measurement objectives."""

    CONTINUOUS_LEVEL = "continuous_level"
    HIGH_LEVEL_ALARM = "high_level_alarm"
    HIGH_HIGH_LEVEL_TRIP = "high_high_level_trip"
    LOW_LEVEL_ALARM = "low_level_alarm"
    LOW_LOW_LEVEL_TRIP = "low_low_level_trip"
    INTERFACE_LEVEL = "interface_level"
    INVENTORY = "inventory"
    OVERFILL_PREVENTION = "overfill_prevention"


class LevelProcessPhase(StrEnum):
    """Bulk phase relevant to level-technology applicability."""

    UNKNOWN = "unknown"
    LIQUID = "liquid"
    LIQUID_LIQUID_INTERFACE = "liquid_liquid_interface"
    SLURRY = "slurry"
    BULK_SOLID = "bulk_solid"
    MULTIPHASE = "multiphase"


class LevelVesselConfiguration(StrEnum):
    """Pressure boundary configuration of the containing equipment."""

    UNKNOWN = "unknown"
    OPEN = "open"
    CLOSED = "closed"
    PRESSURIZED = "pressurized"
    VACUUM = "vacuum"
    OPEN_CHANNEL_OR_SUMP = "open_channel_or_sump"


class LevelVesselGeometry(StrEnum):
    """Generic geometry used to identify supporting calculations."""

    UNKNOWN = "unknown"
    VERTICAL_CYLINDER = "vertical_cylinder"
    HORIZONTAL_CYLINDER = "horizontal_cylinder"
    SPHERE = "sphere"
    CONE_OR_HOPPER = "cone_or_hopper"
    IRREGULAR = "irregular"


class LevelDpArrangement(StrEnum):
    """Differential-pressure installation arrangement, if applicable."""

    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    OPEN_VESSEL = "open_vessel"
    CLOSED_DRY_LEG = "closed_dry_leg"
    CLOSED_WET_LEG = "closed_wet_leg"
    REMOTE_SEALS = "remote_seals"


class LevelContactPreference(StrEnum):
    """Whether contact with process material is acceptable."""

    UNKNOWN = "unknown"
    CONTACT_ACCEPTABLE = "contact_acceptable"
    NON_CONTACT_PREFERRED = "non_contact_preferred"
    NON_CONTACT_REQUIRED = "non_contact_required"


class LevelMaintenanceAccess(StrEnum):
    """Expected maintenance access at the measurement location."""

    UNKNOWN = "unknown"
    EASY = "easy"
    RESTRICTED = "restricted"
    DIFFICULT = "difficult"
    INACCESSIBLE_DURING_OPERATION = "inaccessible_during_operation"


class LevelIndustrySector(StrEnum):
    """Broad industry context; never a substitute for site requirements."""

    UNKNOWN = "unknown"
    CHEMICAL = "chemical"
    OIL_AND_GAS = "oil_and_gas"
    PETROCHEMICAL = "petrochemical"
    WATER_AND_WASTEWATER = "water_and_wastewater"
    POWER = "power"
    FOOD_AND_BEVERAGE = "food_and_beverage"
    PHARMACEUTICAL = "pharmaceutical"
    MINING_AND_MINERALS = "mining_and_minerals"
    CEMENT = "cement"
    PULP_AND_PAPER = "pulp_and_paper"
    MARINE = "marine"
    GENERAL_MANUFACTURING = "general_manufacturing"


class LevelEnvironmentCondition(StrEnum):
    """Installation conditions considered by the screening rules."""

    INDOOR_CONTROLLED = "indoor_controlled"
    OUTDOOR = "outdoor"
    COASTAL_OR_MARINE = "coastal_or_marine"
    WASHDOWN = "washdown"
    FLOOD_PRONE = "flood_prone"
    HIGH_VIBRATION = "high_vibration"
    HIGH_ELECTROMAGNETIC_INTERFERENCE = "high_electromagnetic_interference"
    CORROSIVE_ATMOSPHERE = "corrosive_atmosphere"
    HIGH_DUST = "high_dust"
    EXTREME_COLD = "extreme_cold"
    EXTREME_HEAT = "extreme_heat"
    LIMITED_CLEARANCE = "limited_clearance"
    REMOTE_LOCATION = "remote_location"


class LevelProtectionFunction(StrEnum):
    """Independent protective functions that need separate assessment."""

    HIGH_HIGH_TRIP = "high_high_trip"
    LOW_LOW_TRIP = "low_low_trip"
    OVERFILL_PREVENTION = "overfill_prevention"
    DRY_RUN_PROTECTION = "dry_run_protection"


class LevelVaporBehavior(StrEnum):
    """Observed vapor-space behavior relevant to signal propagation."""

    UNKNOWN = "unknown"
    STABLE = "stable"
    VARIABLE_COMPOSITION = "variable_composition"
    CONDENSING = "condensing"
    PRESSURIZED = "pressurized"
    STEAM_SERVICE = "steam_service"
    DUST_LADEN = "dust_laden"


class LevelMountingPosition(StrEnum):
    """Generic mounting positions known to be physically available."""

    TOP = "top"
    SIDE = "side"
    BOTTOM = "bottom"
    EXTERNAL_CHAMBER = "external_chamber"
    NON_INTRUSIVE_EXTERNAL = "non_intrusive_external"


class LevelConfidenceBand(StrEnum):
    """Auditable qualitative interpretation of a confidence score."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class LevelTechnology(StrEnum):
    """Generic level-measurement technology families."""

    NON_CONTACT_RADAR = "non_contact_radar"
    GUIDED_WAVE_RADAR = "guided_wave_radar"
    DIFFERENTIAL_PRESSURE = "differential_pressure"
    HYDROSTATIC_PRESSURE = "hydrostatic_pressure"
    ULTRASONIC = "ultrasonic"
    CAPACITANCE = "capacitance"
    DISPLACER = "displacer"
    MAGNETIC_FLOAT = "magnetic_float"
    VIBRATING_FORK = "vibrating_fork"
    ROTARY_PADDLE = "rotary_paddle"
    RADIOMETRIC = "radiometric"
    TANK_GAUGING = "tank_gauging"


class LevelRuleStatus(StrEnum):
    """Outcome of one auditable ruleset check."""

    PASSED = "passed"
    CAUTION = "caution"
    FAILED = "failed"
    MISSING_INFORMATION = "missing_information"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


class LevelScenarioDisposition(StrEnum):
    """Safety-aware disposition of a technology scenario."""

    PREFERRED = "preferred"
    PLAUSIBLE = "plausible"
    CONDITIONAL = "conditional"
    INSUFFICIENT_INFORMATION = "insufficient_information"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


class LevelVerificationPriority(StrEnum):
    """Priority for a site verification or competent-person review."""

    ROUTINE = "routine"
    IMPORTANT = "important"
    SAFETY_CRITICAL = "safety_critical"


def _require_unique_enum_values(
    values: tuple[StrEnum, ...],
    *,
    field_name: str,
) -> tuple[StrEnum, ...]:
    comparison = tuple(value.value for value in values)
    if len(comparison) != len(set(comparison)):
        raise ValueError(f"{field_name} values must be unique.")
    return tuple(sorted(values, key=lambda item: item.value))


def _require_unique_text_values(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    comparison = tuple(value.casefold() for value in values)
    if len(comparison) != len(set(comparison)):
        raise ValueError(f"{field_name} values must be unique.")
    return tuple(sorted(values, key=lambda item: (item.casefold(), item)))


def _require_unique_models(
    values: tuple[CalculationModel, ...],
    *,
    attribute: str,
    field_name: str,
) -> None:
    identifiers = tuple(
        str(getattr(value, attribute)).casefold() for value in values
    )
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(
            f"{field_name} {attribute} values must be unique."
        )


def _validate_quantity(
    quantity: EngineeringQuantity | None,
    *,
    field_name: str,
    quantity_kind: QuantityKind,
    positive: bool = False,
    nonnegative: bool = False,
) -> EngineeringQuantity | None:
    if quantity is None:
        return None

    validated = DEFAULT_UNIT_REGISTRY.validate_quantity(quantity)
    if validated.quantity_kind != quantity_kind.value:
        raise ValueError(
            f"{field_name} must use quantity_kind "
            f"{quantity_kind.value!r}."
        )

    canonical = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(validated)
    if positive and canonical.value <= 0.0:
        raise ValueError(f"{field_name} must be greater than zero.")
    if nonnegative and canonical.value < 0.0:
        raise ValueError(f"{field_name} cannot be negative.")
    return quantity


def canonical_quantity_value(
    quantity: EngineeringQuantity | None,
) -> float | None:
    """Return a validated canonical value for deterministic rule comparison."""

    if quantity is None:
        return None
    return DEFAULT_UNIT_REGISTRY.canonicalize_quantity(quantity).value


class LevelMeasurementRequirements(CalculationModel):
    """Technology-neutral functional requirements for the measurement."""

    objectives: tuple[LevelMeasurementObjective, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_OBJECTIVES,
    )
    measurement_span: EngineeringQuantity | None = None
    upper_dead_zone_allowance: EngineeringQuantity | None = None
    lower_dead_zone_allowance: EngineeringQuantity | None = None
    required_accuracy_percent_of_span: StrictFloat | None = Field(
        default=None,
        gt=0.0,
        le=100.0,
    )
    required_response_time: EngineeringQuantity | None = None
    contact_preference: LevelContactPreference = LevelContactPreference.UNKNOWN
    continuous_output_required: LevelTriState = LevelTriState.UNKNOWN
    local_indication_required: LevelTriState = LevelTriState.UNKNOWN

    @field_validator("objectives")
    @classmethod
    def validate_objectives(
        cls,
        value: tuple[LevelMeasurementObjective, ...],
    ) -> tuple[LevelMeasurementObjective, ...]:
        return _require_unique_enum_values(
            value,
            field_name="objectives",
        )  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_quantities(self) -> Self:
        _validate_quantity(
            self.measurement_span,
            field_name="measurement_span",
            quantity_kind=QuantityKind.LENGTH,
            positive=True,
        )
        _validate_quantity(
            self.required_response_time,
            field_name="required_response_time",
            quantity_kind=QuantityKind.TIME,
            positive=True,
        )
        for field_name in (
            "upper_dead_zone_allowance",
            "lower_dead_zone_allowance",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.LENGTH,
                nonnegative=True,
            )
        span = canonical_quantity_value(self.measurement_span)
        upper_dead_zone = canonical_quantity_value(
            self.upper_dead_zone_allowance
        )
        lower_dead_zone = canonical_quantity_value(
            self.lower_dead_zone_allowance
        )
        if (
            span is not None
            and upper_dead_zone is not None
            and lower_dead_zone is not None
            and upper_dead_zone + lower_dead_zone >= span
        ):
            raise ValueError(
                "The combined upper and lower dead-zone allowances must be "
                "strictly less than measurement_span."
            )
        return self


class LevelProcessContext(CalculationModel):
    """Process properties and disturbances relevant to technology screening."""

    phase: LevelProcessPhase = LevelProcessPhase.UNKNOWN
    medium_description: ShortText | None = None
    vapor_space_composition: ShortText | None = None
    vapor_space_behavior: LevelVaporBehavior = LevelVaporBehavior.UNKNOWN
    minimum_temperature: EngineeringQuantity | None = None
    normal_temperature: EngineeringQuantity | None = None
    maximum_temperature: EngineeringQuantity | None = None
    normal_absolute_pressure: EngineeringQuantity | None = None
    maximum_absolute_pressure: EngineeringQuantity | None = None
    bulk_density: EngineeringQuantity | None = None
    lower_fluid_density: EngineeringQuantity | None = None
    upper_fluid_density: EngineeringQuantity | None = None
    density_variation_percent: StrictFloat | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )
    dielectric_constant: StrictFloat | None = Field(
        default=None,
        gt=0.0,
        le=1.0e6,
    )
    dynamic_viscosity: EngineeringQuantity | None = None
    foam: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    turbulence: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    steam: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    condensation: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    dust: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    buildup: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    slurry: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    sticky_material: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    agitation: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    corrosive_service: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    abrasive_service: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN
    hygienic_service: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN

    @model_validator(mode="after")
    def validate_process_context(self) -> Self:
        for field_name in (
            "minimum_temperature",
            "normal_temperature",
            "maximum_temperature",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            )

        for field_name in (
            "normal_absolute_pressure",
            "maximum_absolute_pressure",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
                nonnegative=True,
            )

        for field_name in (
            "bulk_density",
            "lower_fluid_density",
            "upper_fluid_density",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.DENSITY,
                positive=True,
            )

        _validate_quantity(
            self.dynamic_viscosity,
            field_name="dynamic_viscosity",
            quantity_kind=QuantityKind.DYNAMIC_VISCOSITY,
            nonnegative=True,
        )

        minimum = canonical_quantity_value(self.minimum_temperature)
        normal = canonical_quantity_value(self.normal_temperature)
        maximum = canonical_quantity_value(self.maximum_temperature)
        if minimum is not None and normal is not None and minimum > normal:
            raise ValueError(
                "minimum_temperature cannot exceed normal_temperature."
            )
        if normal is not None and maximum is not None and normal > maximum:
            raise ValueError(
                "normal_temperature cannot exceed maximum_temperature."
            )
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValueError(
                "minimum_temperature cannot exceed maximum_temperature."
            )

        normal_pressure = canonical_quantity_value(
            self.normal_absolute_pressure
        )
        maximum_pressure = canonical_quantity_value(
            self.maximum_absolute_pressure
        )
        if (
            normal_pressure is not None
            and maximum_pressure is not None
            and normal_pressure > maximum_pressure
        ):
            raise ValueError(
                "normal_absolute_pressure cannot exceed "
                "maximum_absolute_pressure."
            )

        lower_density = canonical_quantity_value(self.lower_fluid_density)
        upper_density = canonical_quantity_value(self.upper_fluid_density)
        if (
            lower_density is not None
            and upper_density is not None
            and lower_density <= upper_density
        ):
            raise ValueError(
                "lower_fluid_density must exceed upper_fluid_density for "
                "an interface measurement."
            )
        return self


class LevelVesselContext(CalculationModel):
    """Vessel geometry, connections, and DP arrangement."""

    configuration: LevelVesselConfiguration = LevelVesselConfiguration.UNKNOWN
    geometry: LevelVesselGeometry = LevelVesselGeometry.UNKNOWN
    dp_arrangement: LevelDpArrangement = LevelDpArrangement.UNKNOWN
    internal_diameter: EngineeringQuantity | None = None
    straight_side_height: EngineeringQuantity | None = None
    cylindrical_length: EngineeringQuantity | None = None
    lower_level_elevation: EngineeringQuantity | None = None
    upper_level_elevation: EngineeringQuantity | None = None
    nozzle_diameter: EngineeringQuantity | None = None
    nozzle_height: EngineeringQuantity | None = None
    nozzle_geometry_confirmed: LevelTriState = LevelTriState.UNKNOWN
    available_mounting_positions: tuple[LevelMountingPosition, ...] = Field(
        default_factory=tuple,
        max_length=5,
    )
    mounting_constraints: LongText | None = None
    top_mounting_available: LevelTriState = LevelTriState.UNKNOWN
    side_connection_available: LevelTriState = LevelTriState.UNKNOWN
    internal_obstructions: LevelConditionSeverity = LevelConditionSeverity.UNKNOWN

    @field_validator("available_mounting_positions")
    @classmethod
    def validate_mounting_positions(
        cls,
        value: tuple[LevelMountingPosition, ...],
    ) -> tuple[LevelMountingPosition, ...]:
        return _require_unique_enum_values(
            value,
            field_name="available_mounting_positions",
        )  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_vessel_context(self) -> Self:
        positive_fields = (
            "internal_diameter",
            "straight_side_height",
            "cylindrical_length",
            "nozzle_diameter",
        )
        for field_name in positive_fields:
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.LENGTH,
                positive=True,
            )
        for field_name in (
            "lower_level_elevation",
            "upper_level_elevation",
            "nozzle_height",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.LENGTH,
                nonnegative=True,
            )

        lower = canonical_quantity_value(self.lower_level_elevation)
        upper = canonical_quantity_value(self.upper_level_elevation)
        if lower is not None and upper is not None and lower >= upper:
            raise ValueError(
                "lower_level_elevation must be below upper_level_elevation."
            )

        if (
            self.dp_arrangement is LevelDpArrangement.OPEN_VESSEL
            and self.configuration
            not in (
                LevelVesselConfiguration.UNKNOWN,
                LevelVesselConfiguration.OPEN,
                LevelVesselConfiguration.OPEN_CHANNEL_OR_SUMP,
            )
        ):
            raise ValueError(
                "open_vessel DP arrangement conflicts with vessel "
                "configuration."
            )
        if (
            self.configuration
            in {
                LevelVesselConfiguration.OPEN,
                LevelVesselConfiguration.OPEN_CHANNEL_OR_SUMP,
            }
            and self.dp_arrangement
            in {
                LevelDpArrangement.CLOSED_DRY_LEG,
                LevelDpArrangement.CLOSED_WET_LEG,
                LevelDpArrangement.REMOTE_SEALS,
            }
        ):
            raise ValueError(
                "A closed-vessel or remote-seal DP arrangement conflicts "
                "with an open vessel configuration."
            )
        top_is_listed = (
            LevelMountingPosition.TOP in self.available_mounting_positions
        )
        if (
            self.top_mounting_available is LevelTriState.YES
            and not top_is_listed
        ) or (
            self.top_mounting_available is LevelTriState.NO
            and top_is_listed
        ):
            raise ValueError(
                "top_mounting_available conflicts with "
                "available_mounting_positions."
            )
        side_is_listed = (
            LevelMountingPosition.SIDE in self.available_mounting_positions
            or LevelMountingPosition.EXTERNAL_CHAMBER
            in self.available_mounting_positions
        )
        if (
            self.side_connection_available is LevelTriState.YES
            and not side_is_listed
        ) or (
            self.side_connection_available is LevelTriState.NO
            and side_is_listed
        ):
            raise ValueError(
                "side_connection_available conflicts with "
                "available_mounting_positions."
            )
        return self


class LevelInstallationContext(CalculationModel):
    """Physical installation and ambient environment."""

    environments: tuple[LevelEnvironmentCondition, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_ENVIRONMENTS,
    )
    maintenance_access: LevelMaintenanceAccess = LevelMaintenanceAccess.UNKNOWN
    minimum_ambient_temperature: EngineeringQuantity | None = None
    maximum_ambient_temperature: EngineeringQuantity | None = None
    electrical_power_available: LevelTriState = LevelTriState.UNKNOWN
    instrument_air_available: LevelTriState = LevelTriState.UNKNOWN

    @field_validator("environments")
    @classmethod
    def validate_environments(
        cls,
        value: tuple[LevelEnvironmentCondition, ...],
    ) -> tuple[LevelEnvironmentCondition, ...]:
        return _require_unique_enum_values(
            value,
            field_name="environments",
        )  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_installation_context(self) -> Self:
        for field_name in (
            "minimum_ambient_temperature",
            "maximum_ambient_temperature",
        ):
            _validate_quantity(
                getattr(self, field_name),
                field_name=field_name,
                quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            )
        minimum = canonical_quantity_value(self.minimum_ambient_temperature)
        maximum = canonical_quantity_value(self.maximum_ambient_temperature)
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValueError(
                "minimum_ambient_temperature cannot exceed "
                "maximum_ambient_temperature."
            )
        return self


class LevelSafetyContext(CalculationModel):
    """Safety and regulatory facts kept explicit and tri-state."""

    hazardous_area: LevelTriState = LevelTriState.UNKNOWN
    hazardous_area_classification: ShortText | None = None
    required_approvals: tuple[ApprovalText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_APPROVALS,
    )
    independent_protection_required: LevelTriState = LevelTriState.UNKNOWN
    independent_protection_functions: tuple[
        LevelProtectionFunction,
        ...,
    ] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_PROTECTION_FUNCTIONS,
    )
    radiometric_source_permitted: LevelTriState = LevelTriState.UNKNOWN
    radiation_protection_program_confirmed: LevelTriState = (
        LevelTriState.UNKNOWN
    )
    flammable_material: LevelTriState = LevelTriState.UNKNOWN
    toxic_material: LevelTriState = LevelTriState.UNKNOWN

    @field_validator("required_approvals")
    @classmethod
    def validate_required_approvals(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique_text_values(
            value,
            field_name="required_approvals",
        )

    @field_validator("independent_protection_functions")
    @classmethod
    def validate_protection_functions(
        cls,
        value: tuple[LevelProtectionFunction, ...],
    ) -> tuple[LevelProtectionFunction, ...]:
        return _require_unique_enum_values(
            value,
            field_name="independent_protection_functions",
        )  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_safety_context(self) -> Self:
        if self.hazardous_area is LevelTriState.NO and (
            self.hazardous_area_classification is not None
            or self.required_approvals
        ):
            raise ValueError(
                "hazardous-area classification or approvals conflict with "
                "hazardous_area=no."
            )
        if (
            self.independent_protection_required is not LevelTriState.YES
            and self.independent_protection_functions
        ):
            raise ValueError(
                "independent protection functions conflict with "
                "independent_protection_required unless it is yes."
            )
        if (
            self.radiometric_source_permitted is LevelTriState.NO
            and self.radiation_protection_program_confirmed
            is LevelTriState.YES
        ):
            raise ValueError(
                "A radiation protection program cannot authorise a source "
                "when radiometric_source_permitted=no."
            )
        return self


class LevelApplicationRequest(CalculationModel):
    """Complete deterministic input to one level-application assessment."""

    industry: LevelIndustrySector = LevelIndustrySector.UNKNOWN
    industry_detail: ShortText | None = None
    measurement: LevelMeasurementRequirements = Field(
        default_factory=LevelMeasurementRequirements
    )
    process: LevelProcessContext = Field(default_factory=LevelProcessContext)
    vessel: LevelVesselContext = Field(default_factory=LevelVesselContext)
    installation: LevelInstallationContext = Field(
        default_factory=LevelInstallationContext
    )
    safety: LevelSafetyContext = Field(default_factory=LevelSafetyContext)
    supporting_calculation_method_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_METHOD_LINKS,
    )
    application_notes: LongText | None = None

    @field_validator("supporting_calculation_method_ids")
    @classmethod
    def validate_method_links(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        unique = _require_unique_text_values(
            value,
            field_name="supporting_calculation_method_ids",
        )
        unsupported = tuple(
            method_id
            for method_id in unique
            if method_id not in SUPPORTED_LEVEL_CALCULATION_METHOD_IDS
        )
        if unsupported:
            raise ValueError(
                "Only reviewed Step 95 level method identifiers may be "
                f"linked; unsupported values: {unsupported!r}."
            )
        return unique

    @model_validator(mode="after")
    def validate_objective_phase_consistency(self) -> Self:
        if (
            LevelMeasurementObjective.INTERFACE_LEVEL
            in self.measurement.objectives
            and self.process.phase
            not in {
                LevelProcessPhase.UNKNOWN,
                LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
                LevelProcessPhase.MULTIPHASE,
            }
        ):
            raise ValueError(
                "An interface-level objective requires an interface or "
                "multiphase process phase."
            )
        if (
            self.process.vapor_space_behavior
            is LevelVaporBehavior.PRESSURIZED
            and self.vessel.configuration
            in {
                LevelVesselConfiguration.OPEN,
                LevelVesselConfiguration.OPEN_CHANNEL_OR_SUMP,
            }
        ):
            raise ValueError(
                "Pressurized vapor-space behavior conflicts with an open "
                "vessel configuration."
            )
        span = canonical_quantity_value(self.measurement.measurement_span)
        lower = canonical_quantity_value(self.vessel.lower_level_elevation)
        upper = canonical_quantity_value(self.vessel.upper_level_elevation)
        if (
            span is not None
            and lower is not None
            and upper is not None
            and span > upper - lower
        ):
            raise ValueError(
                "measurement_span cannot exceed the upper-to-lower level "
                "elevation range."
            )
        return self


class LevelMissingInformation(CalculationModel):
    """One explicit data gap; unknown values are never treated as absent."""

    field_id: Identifier
    reason: LongText
    safety_critical: StrictBool = False
    affected_technologies: tuple[LevelTechnology, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_SCENARIOS,
    )

    @field_validator("affected_technologies")
    @classmethod
    def validate_affected_technologies(
        cls,
        value: tuple[LevelTechnology, ...],
    ) -> tuple[LevelTechnology, ...]:
        return _require_unique_enum_values(
            value,
            field_name="affected_technologies",
        )  # type: ignore[return-value]


class LevelVerificationStep(CalculationModel):
    """A concrete verification action required before design commitment."""

    verification_id: Identifier
    priority: LevelVerificationPriority
    description: LongText
    acceptance_criteria: LongText
    required_competency: ShortText
    independent: StrictBool = False
    evidence_required: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )

    @field_validator("evidence_required")
    @classmethod
    def validate_evidence_required(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique_text_values(
            value,
            field_name="evidence_required",
        )


class LevelWizardFinding(CalculationModel):
    """Safety-first finding produced by the level application wizard."""

    finding_id: Identifier
    category: FindingCategory
    severity: FindingSeverity
    title: ShortText
    message: LongText
    blocking: StrictBool = False
    required_action: LongText | None = None
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )
    affected_technologies: tuple[LevelTechnology, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_SCENARIOS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )

    @field_validator("verification_requirement_ids", "reference_ids")
    @classmethod
    def validate_verification_links(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique_text_values(
            value,
            field_name="verification_requirement_ids",
        )

    @field_validator("affected_technologies")
    @classmethod
    def validate_affected_technologies(
        cls,
        value: tuple[LevelTechnology, ...],
    ) -> tuple[LevelTechnology, ...]:
        return _require_unique_enum_values(
            value,
            field_name="affected_technologies",
        )  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_blocking_finding(self) -> Self:
        if self.severity in (
            FindingSeverity.ERROR,
            FindingSeverity.CRITICAL,
        ) and not self.blocking:
            raise ValueError(
                "Error and critical findings must be blocking."
            )
        if self.blocking and self.severity not in (
            FindingSeverity.WARNING,
            FindingSeverity.ERROR,
            FindingSeverity.CRITICAL,
        ):
            raise ValueError(
                "Blocking findings require warning, error, or critical "
                "severity."
            )
        if self.blocking and self.required_action is None:
            raise ValueError("A blocking finding requires required_action.")
        if self.blocking and not self.verification_requirement_ids:
            raise ValueError(
                "A blocking finding requires a verification requirement."
            )
        return self


class LevelScenarioRuleResult(CalculationModel):
    """Auditable result for one named screening rule."""

    rule_id: Identifier
    status: LevelRuleStatus
    category: FindingCategory
    weight: StrictFloat = Field(gt=0.0, le=100.0)
    awarded_weight: StrictFloat = Field(ge=0.0, le=100.0)
    explanation: LongText
    missing_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_LINKS,
    )
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )

    @field_validator(
        "missing_field_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_identifier_links(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique_text_values(
            value,
            field_name="identifier links",
        )

    @model_validator(mode="after")
    def validate_rule_result(self) -> Self:
        if self.awarded_weight > self.weight:
            raise ValueError("awarded_weight cannot exceed weight.")
        if (
            self.status is LevelRuleStatus.MISSING_INFORMATION
            and not self.missing_field_ids
        ):
            raise ValueError(
                "A missing-information rule requires missing_field_ids."
            )
        if (
            self.status is not LevelRuleStatus.MISSING_INFORMATION
            and self.missing_field_ids
        ):
            raise ValueError(
                "missing_field_ids are only valid for missing-information "
                "rules."
            )
        if self.status in (
            LevelRuleStatus.FAILED,
            LevelRuleStatus.MISSING_INFORMATION,
            LevelRuleStatus.NOT_APPLICABLE,
            LevelRuleStatus.BLOCKED,
        ) and self.awarded_weight != 0.0:
            raise ValueError(
                "Failed, missing, inapplicable, or blocked rules cannot "
                "award weight."
            )
        return self


class LevelTechnologyScenario(CalculationModel):
    """One generic technology scenario with evidence and link-only methods."""

    scenario_id: Identifier
    technology: LevelTechnology
    title: ShortText
    summary: LongText
    disposition: LevelScenarioDisposition
    rank: StrictInt | None = Field(default=None, ge=1, le=MAX_LEVEL_SCENARIOS)
    suitability_score: StrictFloat = Field(ge=0.0, le=100.0)
    confidence_score: StrictFloat = Field(ge=0.0, le=100.0)
    confidence_band: LevelConfidenceBand
    confidence_rationale: LongText
    ranking_rationale: LongText
    rule_results: tuple[LevelScenarioRuleResult, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_RULE_RESULTS,
    )
    reasons: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    limitations: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    observations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    assumptions: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    escalation_conditions: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    supporting_calculation_method_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_METHOD_LINKS,
    )
    missing_information_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_LINKS,
    )
    finding_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_LINKS,
    )
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )

    @field_validator(
        "reasons",
        "limitations",
        "observations",
        "assumptions",
        "escalation_conditions",
        "supporting_calculation_method_ids",
        "missing_information_ids",
        "finding_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_text_links(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique_text_values(
            value,
            field_name="scenario links",
        )

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        _require_unique_models(
            self.rule_results,
            attribute="rule_id",
            field_name="rule_results",
        )
        unsupported = tuple(
            method_id
            for method_id in self.supporting_calculation_method_ids
            if method_id not in SUPPORTED_LEVEL_CALCULATION_METHOD_IDS
        )
        if unsupported:
            raise ValueError(
                "Scenario contains unsupported calculation method links."
            )
        expected_confidence_band = (
            LevelConfidenceBand.VERY_LOW
            if self.confidence_score < 20.0
            else LevelConfidenceBand.LOW
            if self.confidence_score < 40.0
            else LevelConfidenceBand.MODERATE
            if self.confidence_score < 60.0
            else LevelConfidenceBand.HIGH
            if self.confidence_score < 80.0
            else LevelConfidenceBand.VERY_HIGH
        )
        if self.confidence_band is not expected_confidence_band:
            raise ValueError(
                "confidence_band must match the fixed confidence score bands."
            )
        if self.disposition in (
            LevelScenarioDisposition.BLOCKED,
            LevelScenarioDisposition.NOT_APPLICABLE,
        ):
            if self.rank is not None:
                raise ValueError(
                    "Blocked and not-applicable scenarios cannot be ranked."
                )
            if self.suitability_score != 0.0:
                raise ValueError(
                    "Blocked and not-applicable scenarios must have zero "
                    "suitability."
                )
        elif self.rank is None:
            raise ValueError("A viable or incomplete scenario requires rank.")

        statuses = {item.status for item in self.rule_results}
        expected_disposition = (
            LevelScenarioDisposition.BLOCKED
            if LevelRuleStatus.BLOCKED in statuses
            else LevelScenarioDisposition.NOT_APPLICABLE
            if LevelRuleStatus.NOT_APPLICABLE in statuses
            else LevelScenarioDisposition.INSUFFICIENT_INFORMATION
            if LevelRuleStatus.MISSING_INFORMATION in statuses
            else LevelScenarioDisposition.CONDITIONAL
            if LevelRuleStatus.FAILED in statuses
            else LevelScenarioDisposition.PREFERRED
            if self.suitability_score >= 75.0
            else LevelScenarioDisposition.PLAUSIBLE
            if self.suitability_score >= 55.0
            else LevelScenarioDisposition.CONDITIONAL
        )
        if self.disposition is not expected_disposition:
            raise ValueError(
                "Scenario disposition must follow blocked, not-applicable, "
                "missing, failed, and score precedence exactly."
            )
        has_missing_or_failed = bool(
            statuses.intersection(
                {
                    LevelRuleStatus.MISSING_INFORMATION,
                    LevelRuleStatus.FAILED,
                }
            )
        )
        if self.disposition is LevelScenarioDisposition.PREFERRED and (
            self.suitability_score < 75.0 or has_missing_or_failed
        ):
            raise ValueError(
                "A preferred scenario requires score at least 75 and no "
                "missing or failed rule."
            )
        if self.disposition is LevelScenarioDisposition.PLAUSIBLE and (
            not 55.0 <= self.suitability_score < 75.0
            or has_missing_or_failed
        ):
            raise ValueError(
                "A plausible scenario requires score from 55 to below 75 and "
                "no missing or failed rule."
            )
        if self.disposition is LevelScenarioDisposition.CONDITIONAL and (
            self.suitability_score >= 55.0
            or LevelRuleStatus.MISSING_INFORMATION in statuses
        ):
            raise ValueError(
                "A conditional scenario requires score below 55 and no "
                "missing-information rule."
            )
        if (
            self.disposition
            is LevelScenarioDisposition.INSUFFICIENT_INFORMATION
            and LevelRuleStatus.MISSING_INFORMATION not in statuses
        ):
            raise ValueError(
                "An insufficient-information scenario requires a missing rule."
            )
        if (
            self.disposition is LevelScenarioDisposition.NOT_APPLICABLE
            and LevelRuleStatus.NOT_APPLICABLE not in statuses
        ):
            raise ValueError(
                "A not-applicable scenario requires a not-applicable rule."
            )
        if (
            self.disposition is LevelScenarioDisposition.BLOCKED
            and LevelRuleStatus.BLOCKED not in statuses
        ):
            raise ValueError("A blocked scenario requires a blocked rule.")
        return self


class LevelApplicationAssessment(CalculationModel):
    """Deterministic, safety-first result of the application wizard."""

    wizard_version: VersionText
    ruleset_version: VersionText
    status: CalculationStatus
    assessment_fingerprint: FingerprintText
    request: LevelApplicationRequest
    safety_findings: tuple[LevelWizardFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_FINDINGS,
    )
    observations: tuple[TextItem, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    missing_information: tuple[LevelMissingInformation, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_MISSING_INFORMATION,
    )
    scenarios: tuple[LevelTechnologyScenario, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_SCENARIOS,
    )
    verification_steps: tuple[LevelVerificationStep, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_VERIFICATION_STEPS,
    )
    references: tuple[CalculationReference, ...] = Field(
        min_length=1,
        max_length=MAX_LEVEL_LINKS,
    )
    limitations: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEVEL_TEXT_ITEMS,
    )
    disclaimer: LongText = Field(
        default=(
            "Engineer4Me provides technology-generic engineering decision "
            "support only. This assessment does not select a product, prove "
            "fitness for service, execute a calculation, establish an "
            "independent protection layer, or replace site-specific risk "
            "assessment, current legislation and standards, manufacturer "
            "documentation, or review by competent engineers."
        )
    )

    @model_validator(mode="after")
    def validate_assessment_graph(self) -> Self:
        _require_unique_models(
            self.safety_findings,
            attribute="finding_id",
            field_name="safety_findings",
        )
        _require_unique_models(
            self.missing_information,
            attribute="field_id",
            field_name="missing_information",
        )
        _require_unique_models(
            self.scenarios,
            attribute="scenario_id",
            field_name="scenarios",
        )
        _require_unique_models(
            self.verification_steps,
            attribute="verification_id",
            field_name="verification_steps",
        )
        _require_unique_models(
            self.references,
            attribute="reference_id",
            field_name="references",
        )

        finding_ids = {item.finding_id for item in self.safety_findings}
        missing_ids = {item.field_id for item in self.missing_information}
        verification_ids = {
            item.verification_id for item in self.verification_steps
        }
        reference_ids = {item.reference_id for item in self.references}

        for finding in self.safety_findings:
            unresolved = set(finding.verification_requirement_ids).difference(
                verification_ids
            )
            if unresolved:
                raise ValueError(
                    "Finding links unknown verification requirements: "
                    f"{sorted(unresolved)!r}."
                )
            unresolved_references = set(finding.reference_ids).difference(
                reference_ids
            )
            if unresolved_references:
                raise ValueError(
                    "Finding links unknown references: "
                    f"{sorted(unresolved_references)!r}."
                )

        ranks = []
        finding_usage: dict[str, set[LevelTechnology]] = {
            finding_id: set() for finding_id in finding_ids
        }
        missing_usage: dict[str, set[LevelTechnology]] = {
            missing_id: set() for missing_id in missing_ids
        }
        used_verification_ids: set[str] = set()
        used_reference_ids: set[str] = set()
        for scenario in self.scenarios:
            if scenario.rank is not None:
                ranks.append(scenario.rank)
            unresolved_findings = set(scenario.finding_ids).difference(
                finding_ids
            )
            unresolved_missing = set(scenario.missing_information_ids).difference(
                missing_ids
            )
            unresolved_verification = set(
                scenario.verification_requirement_ids
            ).difference(verification_ids)
            unresolved_references = set(scenario.reference_ids).difference(
                reference_ids
            )
            for rule in scenario.rule_results:
                unresolved_missing.update(
                    set(rule.missing_field_ids).difference(missing_ids)
                )
                unresolved_verification.update(
                    set(rule.verification_requirement_ids).difference(
                        verification_ids
                    )
                )
                unresolved_references.update(
                    set(rule.reference_ids).difference(reference_ids)
                )
                used_verification_ids.update(
                    rule.verification_requirement_ids
                )
                used_reference_ids.update(rule.reference_ids)
                for missing_id in rule.missing_field_ids:
                    if missing_id in missing_usage:
                        missing_usage[missing_id].add(scenario.technology)
            if (
                unresolved_findings
                or unresolved_missing
                or unresolved_verification
                or unresolved_references
            ):
                raise ValueError(
                    "Scenario links must resolve to assessment evidence."
                )
            used_verification_ids.update(
                scenario.verification_requirement_ids
            )
            used_reference_ids.update(scenario.reference_ids)
            for finding_id in scenario.finding_ids:
                finding_usage[finding_id].add(scenario.technology)
            for missing_id in scenario.missing_information_ids:
                missing_usage[missing_id].add(scenario.technology)

        for finding in self.safety_findings:
            used_verification_ids.update(
                finding.verification_requirement_ids
            )
            used_reference_ids.update(finding.reference_ids)
            if finding_usage[finding.finding_id] != set(
                finding.affected_technologies
            ):
                raise ValueError(
                    "Finding affected_technologies must exactly match "
                    "scenario finding links."
                )
        for missing_item in self.missing_information:
            if missing_usage[missing_item.field_id] != set(
                missing_item.affected_technologies
            ):
                raise ValueError(
                    "Missing-information affected_technologies must exactly "
                    "match scenario and rule links."
                )
        if used_verification_ids != verification_ids:
            raise ValueError(
                "Verification steps must be referenced and cannot be orphaned."
            )
        if used_reference_ids != reference_ids:
            raise ValueError(
                "References must be linked and cannot be orphaned."
            )

        unique_ranks = sorted(set(ranks))
        if unique_ranks != list(range(1, len(unique_ranks) + 1)):
            raise ValueError(
                "Scenario ranks must use dense contiguous values from one; "
                "exact ties share a rank."
            )

        disposition_order = {
            LevelScenarioDisposition.PREFERRED: 0,
            LevelScenarioDisposition.PLAUSIBLE: 1,
            LevelScenarioDisposition.CONDITIONAL: 2,
            LevelScenarioDisposition.INSUFFICIENT_INFORMATION: 3,
        }
        ranked_scenarios = sorted(
            (item for item in self.scenarios if item.rank is not None),
            key=lambda item: (
                disposition_order[item.disposition],
                -item.suitability_score,
                -item.confidence_score,
                item.technology.value,
            ),
        )
        expected_rank = 1
        previous_key: tuple[object, ...] | None = None
        for scenario in ranked_scenarios:
            ranking_key = (
                disposition_order[scenario.disposition],
                scenario.suitability_score,
                scenario.confidence_score,
            )
            if previous_key is not None and ranking_key != previous_key:
                expected_rank += 1
            if scenario.rank != expected_rank:
                raise ValueError(
                    "Scenario ranks must be dense by disposition, suitability, "
                    "and confidence; exact ties share a rank."
                )
            previous_key = ranking_key

        if any(item.blocking for item in self.safety_findings) and (
            self.status is not CalculationStatus.BLOCKED
        ):
            raise ValueError(
                "A blocking safety finding requires blocked assessment status."
            )
        if (
            self.status is CalculationStatus.BLOCKED
            and not any(item.blocking for item in self.safety_findings)
        ):
            raise ValueError(
                "Blocked assessment status requires a blocking safety finding."
            )
        if (
            self.status is CalculationStatus.INSUFFICIENT_INPUT
            and not self.missing_information
        ):
            raise ValueError(
                "Insufficient-input status requires missing information."
            )
        if self.status is CalculationStatus.COMPLETED and (
            self.missing_information or self.safety_findings
        ):
            raise ValueError(
                "A completed assessment cannot contain missing information "
                "or findings."
            )

        blocking_finding = any(
            item.blocking for item in self.safety_findings
        )
        viable_scenario = any(
            item.disposition
            in {
                LevelScenarioDisposition.PREFERRED,
                LevelScenarioDisposition.PLAUSIBLE,
            }
            for item in self.scenarios
        )
        expected_status = (
            CalculationStatus.BLOCKED
            if blocking_finding
            else CalculationStatus.NOT_APPLICABLE
            if all(
                item.disposition is LevelScenarioDisposition.NOT_APPLICABLE
                for item in self.scenarios
            )
            else CalculationStatus.INSUFFICIENT_INPUT
            if any(item.safety_critical for item in self.missing_information)
            or not viable_scenario
            and bool(self.missing_information)
            else CalculationStatus.FAILED
            if not viable_scenario
            else CalculationStatus.COMPLETED_WITH_WARNINGS
            if self.safety_findings
            or self.missing_information
            or any(
                item.disposition is not LevelScenarioDisposition.PREFERRED
                for item in self.scenarios
            )
            else CalculationStatus.COMPLETED
        )
        if self.status is not expected_status:
            raise ValueError(
                "Assessment status must follow blocking findings, "
                "applicability, safety-critical missing information, viable "
                "scenarios, and warning evidence exactly."
            )

        expected_order = tuple(
            sorted(
                self.scenarios,
                key=lambda item: (
                    item.rank is None,
                    item.rank or MAX_LEVEL_SCENARIOS + 1,
                    item.technology.value,
                ),
            )
        )
        if self.scenarios != expected_order:
            raise ValueError(
                "Scenarios must be ordered by rank and then technology."
            )
        return self


__all__ = [
    "ApprovalText",
    "LEVEL_APPLICATION_MODEL_VERSION",
    "LevelApplicationAssessment",
    "LevelApplicationRequest",
    "LevelConditionSeverity",
    "LevelConfidenceBand",
    "LevelContactPreference",
    "LevelDpArrangement",
    "LevelEnvironmentCondition",
    "LevelIndustrySector",
    "LevelInstallationContext",
    "LevelMaintenanceAccess",
    "LevelMountingPosition",
    "LevelMeasurementObjective",
    "LevelMeasurementRequirements",
    "LevelMissingInformation",
    "LevelProcessContext",
    "LevelProcessPhase",
    "LevelProtectionFunction",
    "LevelRuleStatus",
    "LevelSafetyContext",
    "LevelScenarioDisposition",
    "LevelScenarioRuleResult",
    "LevelTechnology",
    "LevelTechnologyScenario",
    "LevelTriState",
    "LevelVerificationPriority",
    "LevelVerificationStep",
    "LevelVaporBehavior",
    "LevelVesselConfiguration",
    "LevelVesselContext",
    "LevelVesselGeometry",
    "LevelWizardFinding",
    "SUPPORTED_LEVEL_CALCULATION_METHOD_IDS",
    "SUPPORTED_LEVEL_METHOD_IDS",
    "canonical_quantity_value",
]
