"""Immutable Step 109 registry of controlled engineering datasheet templates.

The six templates in this module are vendor neutral and deliberately contain
only inert, declarative metadata.  They do not execute calculations, select a
manufacturer, claim standards conformity, persist records, expose an API, or
render workbooks.  Every lookup names an exact template version; there is no
implicit "latest" behavior.
"""

from __future__ import annotations

from collections.abc import Iterable
from re import fullmatch
from types import MappingProxyType
from typing import Any, Final

from app.engineering.design.datasheet_models import (
    DATASHEET_MODEL_VERSION,
    DatasheetConditionOperator,
    DatasheetFieldCondition,
    DatasheetFieldDefinition,
    DatasheetFieldOrigin,
    DatasheetFieldRequirement,
    DatasheetSectionDefinition,
    DatasheetTemplateDefinition,
    DatasheetValueKind,
)

DATASHEET_TEMPLATE_REGISTRY_VERSION: Final = "1.0.0"
DATASHEET_TEMPLATE_VERSION: Final = "1.0.0"
MAX_REGISTERED_DATASHEET_TEMPLATES: Final = 128

PRESSURE_TRANSMITTER_TEMPLATE_ID: Final = "instrument.pressure-transmitter"
LEVEL_TRANSMITTER_TEMPLATE_ID: Final = "instrument.level-transmitter"
DP_FLOW_TEMPLATE_ID: Final = "instrument.dp-flow"
CONTROL_VALVE_TEMPLATE_ID: Final = "valve.control"
PRESSURE_RELIEF_TEMPLATE_ID: Final = "valve.pressure-relief"
PROCESS_ANALYZER_TEMPLATE_ID: Final = "analyzer.process"

_IDENTIFIER_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{1,99}"
_VERSION_PATTERN: Final = (
    r"[0-9]+(?:\.[0-9]+){1,3}"
    r"(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?"
    r"(?:\+[A-Za-z0-9][A-Za-z0-9.-]*)?"
)

TemplateKey = tuple[str, str]


class DatasheetTemplateRegistryError(ValueError):
    """Base class for deterministic datasheet-template registry failures."""

    code = "datasheet_template_registry_error"


class InvalidDatasheetTemplateRegistrationError(DatasheetTemplateRegistryError):
    """A registry entry is not a complete controlled template definition."""

    code = "invalid_datasheet_template_registration"


class DuplicateDatasheetTemplateRegistrationError(DatasheetTemplateRegistryError):
    """Two entries use the same or a case-conflicting exact identity."""

    code = "duplicate_datasheet_template_registration"


class InvalidDatasheetTemplateLookupError(DatasheetTemplateRegistryError):
    """A lookup component is not a bounded controlled identifier."""

    code = "invalid_datasheet_template_lookup"


class UnknownDatasheetTemplateError(DatasheetTemplateRegistryError):
    """The requested permanent template identifier is not registered."""

    code = "unknown_datasheet_template"

    def __init__(self, template_id: str) -> None:
        self.template_id = template_id
        super().__init__(f"Unknown datasheet template ID: {template_id!r}.")


class UnknownDatasheetTemplateVersionError(DatasheetTemplateRegistryError):
    """The requested exact version is not registered for a known template."""

    code = "unknown_datasheet_template_version"

    def __init__(self, template_id: str, template_version: str) -> None:
        self.template_id = template_id
        self.template_version = template_version
        super().__init__(
            f"Unknown version {template_version!r} for datasheet template "
            f"{template_id!r}."
        )


def _section(
    section_id: str,
    title: str,
    description: str,
) -> DatasheetSectionDefinition:
    return DatasheetSectionDefinition(
        section_id=section_id,
        title=title,
        description=description,
    )


def _condition(
    depends_on_field_id: str,
    *expected_values: bool | float | str,
    operator: DatasheetConditionOperator = DatasheetConditionOperator.EQUALS,
) -> DatasheetFieldCondition:
    return DatasheetFieldCondition(
        depends_on_field_id=depends_on_field_id,
        operator=operator,
        expected_values=expected_values,
    )


def _field(
    field_id: str,
    section_id: str,
    label: str,
    description: str,
    value_kind: DatasheetValueKind,
    requirement: DatasheetFieldRequirement,
    *,
    preferred_unit: str | None = None,
    quantity_kind: str | None = None,
    allowed_values: tuple[str, ...] = (),
    condition: DatasheetFieldCondition | None = None,
    safety_critical: bool = False,
    allowed_origins: tuple[DatasheetFieldOrigin, ...] | None = None,
    required_boolean_value: bool | None = None,
    positive_value_required: bool = False,
) -> DatasheetFieldDefinition:
    values: dict[str, Any] = {
        "field_id": field_id,
        "section_id": section_id,
        "label": label,
        "description": description,
        "value_kind": value_kind,
        "requirement": requirement,
        "preferred_unit": preferred_unit,
        "quantity_kind": quantity_kind,
        "allowed_values": allowed_values,
        "condition": condition,
        "safety_critical": safety_critical,
        "required_boolean_value": required_boolean_value,
        "positive_value_required": positive_value_required,
    }
    if allowed_origins is None:
        allowed_origins = (
            DatasheetFieldOrigin.USER_SUPPLIED,
            DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            DatasheetFieldOrigin.SELECTED,
            DatasheetFieldOrigin.DEFAULTED,
        )
        if value_kind is not DatasheetValueKind.NUMBER:
            allowed_origins = (*allowed_origins, DatasheetFieldOrigin.CALCULATED)
    values["allowed_origins"] = allowed_origins
    return DatasheetFieldDefinition(**values)


def _required(
    field_id: str,
    section_id: str,
    label: str,
    description: str,
    value_kind: DatasheetValueKind,
    **kwargs: Any,
) -> DatasheetFieldDefinition:
    return _field(
        field_id,
        section_id,
        label,
        description,
        value_kind,
        DatasheetFieldRequirement.REQUIRED,
        **kwargs,
    )


def _optional(
    field_id: str,
    section_id: str,
    label: str,
    description: str,
    value_kind: DatasheetValueKind,
    **kwargs: Any,
) -> DatasheetFieldDefinition:
    return _field(
        field_id,
        section_id,
        label,
        description,
        value_kind,
        DatasheetFieldRequirement.OPTIONAL,
        **kwargs,
    )


def _conditional(
    field_id: str,
    section_id: str,
    label: str,
    description: str,
    value_kind: DatasheetValueKind,
    condition: DatasheetFieldCondition,
    **kwargs: Any,
) -> DatasheetFieldDefinition:
    return _field(
        field_id,
        section_id,
        label,
        description,
        value_kind,
        DatasheetFieldRequirement.CONDITIONAL,
        condition=condition,
        **kwargs,
    )


def _template(
    *,
    template_id: str,
    title: str,
    sections: tuple[DatasheetSectionDefinition, ...],
    fields: tuple[DatasheetFieldDefinition, ...],
) -> DatasheetTemplateDefinition:
    return DatasheetTemplateDefinition.create(
        template_id=template_id,
        template_version=DATASHEET_TEMPLATE_VERSION,
        title=title,
        discipline="instrumentation-control",
        sections=sections,
        fields=fields,
    )


PRESSURE_TRANSMITTER_TEMPLATE: Final = _template(
    template_id=PRESSURE_TRANSMITTER_TEMPLATE_ID,
    title="Pressure Transmitter Datasheet",
    sections=(
        _section(
            "identification",
            "Identification",
            "Stable tag, service, and installation identity.",
        ),
        _section(
            "process",
            "Process Basis",
            "Controlled process conditions used to define the measurement duty.",
        ),
        _section(
            "measurement",
            "Measurement",
            "Pressure type, calibrated range, and performance requirements.",
        ),
        _section(
            "construction",
            "Construction",
            "Process interface, wetted materials, and optional remote seals.",
        ),
        _section(
            "integration",
            "Integration and Environment",
            "Signal, power, installation, and hazardous-area requirements.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Tag number",
            "Permanent project tag for the pressure transmitter.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "service_description",
            "identification",
            "Service description",
            "Plain-language measurement service without a manufacturer claim.",
            DatasheetValueKind.TEXT,
        ),
        _optional(
            "location",
            "identification",
            "Installation location",
            "Plant, unit, or equipment location reference.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "process_medium",
            "process",
            "Process medium",
            "Controlled identity of the fluid contacting the measurement system.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _required(
            "minimum_process_pressure",
            "process",
            "Minimum process pressure",
            "Minimum absolute pressure for the stated operating envelope.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "maximum_process_pressure",
            "process",
            "Maximum process pressure",
            "Maximum absolute pressure including the reviewed operating case.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "normal_process_temperature",
            "process",
            "Normal temperature",
            "Normal absolute process temperature at the sensing point.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
        ),
        _required(
            "maximum_process_temperature",
            "process",
            "Maximum temperature",
            "Maximum absolute process temperature for material review.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _required(
            "pressure_measurement_type",
            "measurement",
            "Pressure type",
            "Required gauge, sealed-gauge, absolute, or differential measurement.",
            DatasheetValueKind.ENUM,
            allowed_values=("absolute", "differential", "gauge", "sealed_gauge"),
        ),
        _conditional(
            "gauge_lower_range_value",
            "measurement",
            "Gauge lower range value",
            "Calibrated lower endpoint for a gauge or sealed-gauge transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition(
                "pressure_measurement_type",
                "gauge",
                "sealed_gauge",
                operator=DatasheetConditionOperator.IN,
            ),
            preferred_unit="Pa",
            quantity_kind="pressure.gauge",
        ),
        _conditional(
            "gauge_upper_range_value",
            "measurement",
            "Gauge upper range value",
            "Calibrated upper endpoint for a gauge or sealed-gauge transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition(
                "pressure_measurement_type",
                "gauge",
                "sealed_gauge",
                operator=DatasheetConditionOperator.IN,
            ),
            preferred_unit="Pa",
            quantity_kind="pressure.gauge",
        ),
        _conditional(
            "absolute_lower_range_value",
            "measurement",
            "Absolute lower range value",
            "Calibrated lower endpoint for an absolute-pressure transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition("pressure_measurement_type", "absolute"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
        ),
        _conditional(
            "absolute_upper_range_value",
            "measurement",
            "Absolute upper range value",
            "Calibrated upper endpoint for an absolute-pressure transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition("pressure_measurement_type", "absolute"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
        ),
        _conditional(
            "differential_lower_range_value",
            "measurement",
            "DP lower range value",
            "Calibrated lower endpoint for a differential-pressure transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition("pressure_measurement_type", "differential"),
            preferred_unit="Pa",
            quantity_kind="pressure.differential",
        ),
        _conditional(
            "differential_upper_range_value",
            "measurement",
            "DP upper range value",
            "Calibrated upper endpoint for a differential-pressure transmitter.",
            DatasheetValueKind.QUANTITY,
            _condition("pressure_measurement_type", "differential"),
            preferred_unit="Pa",
            quantity_kind="pressure.differential",
        ),
        _optional(
            "required_accuracy_percent",
            "measurement",
            "Required accuracy",
            "Project-required accuracy stated as percent of calibrated span.",
            DatasheetValueKind.NUMBER,
        ),
        _required(
            "process_connection",
            "construction",
            "Process connection",
            "Required generic connection size, type, and pressure class.",
            DatasheetValueKind.TEXT,
        ),
        _optional(
            "wetted_material",
            "construction",
            "Wetted material",
            "Required wetted material pending compatibility verification.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "remote_seal_required",
            "construction",
            "Remote seal required",
            "Whether the measurement duty requires a remote diaphragm seal.",
            DatasheetValueKind.BOOLEAN,
        ),
        _conditional(
            "remote_seal_configuration",
            "construction",
            "Remote seal configuration",
            "Generic seal arrangement, capillary configuration, and connection.",
            DatasheetValueKind.TEXT,
            _condition("remote_seal_required", True),
        ),
        _conditional(
            "remote_seal_fill_fluid",
            "construction",
            "Seal fill fluid",
            "Fill-fluid requirement subject to temperature and compatibility review.",
            DatasheetValueKind.TEXT,
            _condition("remote_seal_required", True),
            safety_critical=True,
        ),
        _required(
            "output_signal",
            "integration",
            "Output signal",
            "Required generic electrical signal or digital protocol family.",
            DatasheetValueKind.ENUM,
            allowed_values=("4-20_ma", "4-20_ma_hart", "fieldbus", "other"),
        ),
        _required(
            "hazardous_area",
            "integration",
            "Hazardous area",
            "Whether the installed location is classified as hazardous.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "hazardous_area_classification",
            "integration",
            "Hazardous-area classification",
            "Site-approved area, gas or dust group, and temperature class.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_area", True),
            safety_critical=True,
        ),
        _optional(
            "mounting_accessories",
            "integration",
            "Mounting accessories",
            "Bracket, manifold, weather protection, or other installation needs.",
            DatasheetValueKind.TEXT,
        ),
    ),
)


LEVEL_TRANSMITTER_TEMPLATE: Final = _template(
    template_id=LEVEL_TRANSMITTER_TEMPLATE_ID,
    title="Level Measurement Datasheet",
    sections=(
        _section(
            "identification", "Identification", "Tag, service, and vessel identity."
        ),
        _section(
            "process", "Process and Vessel", "Fluid, vessel, and operating basis."
        ),
        _section(
            "measurement",
            "Measurement Duty",
            "Technology and calibrated measurement duty.",
        ),
        _section(
            "installation",
            "Installation",
            "Nozzles, taps, seals, and mounting constraints.",
        ),
        _section(
            "integration",
            "Integration and Environment",
            "Output and hazardous-area requirements.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Tag number",
            "Permanent project tag for the level instrument.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "service_description",
            "identification",
            "Service description",
            "Controlled description of the level measurement duty.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "vessel_reference",
            "identification",
            "Vessel reference",
            "Stable reference for the measured vessel or chamber.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "process_medium",
            "process",
            "Process medium",
            "Controlled identity of the measured fluid or interface.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _required(
            "process_phase",
            "process",
            "Process phase",
            "Expected process phase at the measurement location.",
            DatasheetValueKind.ENUM,
            allowed_values=("liquid", "liquid_interface", "slurry", "solids"),
        ),
        _required(
            "minimum_process_pressure",
            "process",
            "Minimum process pressure",
            "Minimum absolute vessel pressure.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "maximum_process_pressure",
            "process",
            "Maximum process pressure",
            "Maximum absolute vessel pressure.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "minimum_process_temperature",
            "process",
            "Minimum temperature",
            "Minimum absolute process temperature.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
        ),
        _required(
            "maximum_process_temperature",
            "process",
            "Maximum temperature",
            "Maximum absolute process temperature.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _optional(
            "vessel_geometry",
            "process",
            "Vessel geometry",
            "Generic geometry relevant to range or volume interpretation.",
            DatasheetValueKind.ENUM,
            allowed_values=("horizontal_cylinder", "other", "vertical_cylinder"),
        ),
        _required(
            "technology_family",
            "measurement",
            "Technology family",
            "Vendor-neutral measurement technology selected for detailed review.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "capacitance",
                "differential_pressure",
                "displacer",
                "guided_wave_radar",
                "non_contact_radar",
                "ultrasonic",
            ),
        ),
        _required(
            "minimum_measured_level",
            "measurement",
            "Minimum measured level",
            "Lower endpoint relative to the controlled datum.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
        ),
        _required(
            "maximum_measured_level",
            "measurement",
            "Maximum measured level",
            "Upper endpoint relative to the controlled datum.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
        ),
        _conditional(
            "bulk_density",
            "measurement",
            "Bulk liquid density",
            "Density required for hydrostatic or displacer interpretation.",
            DatasheetValueKind.QUANTITY,
            _condition(
                "technology_family",
                "differential_pressure",
                "displacer",
                operator=DatasheetConditionOperator.IN,
            ),
            preferred_unit="kg/m3",
            quantity_kind="density",
            safety_critical=True,
        ),
        _required(
            "interface_service",
            "measurement",
            "Interface service",
            "Whether two liquid phases form the measurement interface.",
            DatasheetValueKind.BOOLEAN,
        ),
        _conditional(
            "upper_phase_density",
            "measurement",
            "Upper-phase density",
            "Density of the upper phase at design conditions.",
            DatasheetValueKind.QUANTITY,
            _condition("interface_service", True),
            preferred_unit="kg/m3",
            quantity_kind="density",
            safety_critical=True,
        ),
        _conditional(
            "lower_phase_density",
            "measurement",
            "Lower-phase density",
            "Density of the lower phase at design conditions.",
            DatasheetValueKind.QUANTITY,
            _condition("interface_service", True),
            preferred_unit="kg/m3",
            quantity_kind="density",
            safety_critical=True,
        ),
        _conditional(
            "dp_arrangement",
            "installation",
            "DP arrangement",
            "Open, dry-leg, wet-leg, or remote-seal arrangement.",
            DatasheetValueKind.ENUM,
            _condition("technology_family", "differential_pressure"),
            allowed_values=("dry_leg", "open_vessel", "remote_seal", "wet_leg"),
        ),
        _conditional(
            "lower_tap_elevation",
            "installation",
            "Lower tap elevation",
            "Lower pressure connection elevation relative to datum.",
            DatasheetValueKind.QUANTITY,
            _condition("technology_family", "differential_pressure"),
            preferred_unit="m",
            quantity_kind="length",
        ),
        _conditional(
            "upper_tap_elevation",
            "installation",
            "Upper tap elevation",
            "Upper pressure connection elevation relative to datum.",
            DatasheetValueKind.QUANTITY,
            _condition("technology_family", "differential_pressure"),
            preferred_unit="m",
            quantity_kind="length",
        ),
        _conditional(
            "reference_leg_density",
            "installation",
            "Reference-leg density",
            "Reference leg or seal-system density where the DP arrangement requires it.",
            DatasheetValueKind.QUANTITY,
            _condition(
                "dp_arrangement",
                "dry_leg",
                "remote_seal",
                "wet_leg",
                operator=DatasheetConditionOperator.IN,
            ),
            preferred_unit="kg/m3",
            quantity_kind="density",
        ),
        _optional(
            "process_connection",
            "installation",
            "Process connection",
            "Generic nozzle, flange, chamber, or probe connection requirement.",
            DatasheetValueKind.TEXT,
        ),
        _optional(
            "antenna_or_probe_clearance",
            "installation",
            "Probe or antenna clearance",
            "Required internal and external clearance for the selected technology.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
        ),
        _required(
            "output_signal",
            "integration",
            "Output signal",
            "Required generic signal or digital protocol family.",
            DatasheetValueKind.ENUM,
            allowed_values=("4-20_ma", "4-20_ma_hart", "fieldbus", "other"),
        ),
        _required(
            "hazardous_area",
            "integration",
            "Hazardous area",
            "Whether the installed location is classified as hazardous.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "hazardous_area_classification",
            "integration",
            "Hazardous-area classification",
            "Site-approved area, material group, and temperature class.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_area", True),
            safety_critical=True,
        ),
    ),
)


DP_FLOW_TEMPLATE: Final = _template(
    template_id=DP_FLOW_TEMPLATE_ID,
    title="Differential-Pressure Flow Datasheet",
    sections=(
        _section(
            "identification", "Identification", "Tag, service, and line identity."
        ),
        _section(
            "fluid",
            "Fluid and Operating Cases",
            "Traceable fluid properties and flow cases.",
        ),
        _section(
            "primary_element",
            "Primary Element",
            "Vendor-neutral primary-element geometry and coefficients.",
        ),
        _section(
            "measurement",
            "Measurement and Performance",
            "DP range, pressure loss, and uncertainty requirements.",
        ),
        _section(
            "integration",
            "Integration and Environment",
            "Transmitter output and installation classification.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Tag number",
            "Permanent project tag for the DP flow measurement.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "service_description",
            "identification",
            "Service description",
            "Controlled description of the flow measurement duty.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "line_reference",
            "identification",
            "Line reference",
            "Stable process line identifier.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "fluid_name",
            "fluid",
            "Fluid name",
            "Controlled identity of the flowing fluid.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _required(
            "fluid_phase",
            "fluid",
            "Fluid phase",
            "Phase used for the reviewed sizing basis.",
            DatasheetValueKind.ENUM,
            allowed_values=("gas", "liquid", "steam", "vapour"),
            safety_critical=True,
        ),
        _optional(
            "fluid_composition",
            "fluid",
            "Fluid composition",
            "Composition or mixture basis needed to reproduce properties.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "minimum_mass_flow",
            "fluid",
            "Minimum mass flow",
            "Minimum reviewed mass-flow case.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/s",
            quantity_kind="flow.mass",
        ),
        _required(
            "normal_mass_flow",
            "fluid",
            "Normal mass flow",
            "Normal reviewed mass-flow case.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/s",
            quantity_kind="flow.mass",
        ),
        _required(
            "maximum_mass_flow",
            "fluid",
            "Maximum mass flow",
            "Maximum reviewed mass-flow case.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/s",
            quantity_kind="flow.mass",
            safety_critical=True,
        ),
        _required(
            "operating_pressure",
            "fluid",
            "Operating pressure",
            "Absolute pressure at the primary element.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "operating_temperature",
            "fluid",
            "Operating temperature",
            "Absolute temperature at the primary element.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _required(
            "flowing_density",
            "fluid",
            "Flowing density",
            "Density at the stated pressure, temperature, and composition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/m3",
            quantity_kind="density",
            safety_critical=True,
        ),
        _required(
            "dynamic_viscosity",
            "fluid",
            "Dynamic viscosity",
            "Dynamic viscosity at the flowing condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa*s",
            quantity_kind="viscosity.dynamic",
        ),
        _conditional(
            "compressibility_factor",
            "fluid",
            "Compressibility factor",
            "Compressibility factor for gas or vapour expansion evaluation.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase", "gas", "vapour", operator=DatasheetConditionOperator.IN
            ),
            safety_critical=True,
        ),
        _conditional(
            "isentropic_exponent",
            "fluid",
            "Isentropic exponent",
            "Isentropic exponent for gas or vapour expansion evaluation.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase", "gas", "vapour", operator=DatasheetConditionOperator.IN
            ),
            safety_critical=True,
        ),
        _required(
            "pipe_internal_diameter",
            "primary_element",
            "Pipe internal diameter",
            "Internal diameter at the primary element under stated conditions.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
            safety_critical=True,
        ),
        _required(
            "primary_element_family",
            "primary_element",
            "Primary-element family",
            "Generic primary-element family; no manufacturer is selected.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "averaging_pitot",
                "flow_nozzle",
                "orifice_plate",
                "other_generic",
                "venturi_nozzle",
                "venturi_tube",
            ),
        ),
        _required(
            "bore_or_throat_diameter",
            "primary_element",
            "Bore or throat diameter",
            "Controlled bore or throat diameter for the selected element family.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
            safety_critical=True,
        ),
        _required(
            "discharge_coefficient",
            "primary_element",
            "Discharge coefficient",
            "Supplied or calculated coefficient with explicit field origin.",
            DatasheetValueKind.NUMBER,
            safety_critical=True,
        ),
        _conditional(
            "expansibility_factor",
            "primary_element",
            "Expansibility factor",
            "Supplied or calculated expansion factor for a compressible fluid.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase",
                "gas",
                "steam",
                "vapour",
                operator=DatasheetConditionOperator.IN,
            ),
            safety_critical=True,
        ),
        _conditional(
            "tap_configuration",
            "primary_element",
            "Tap configuration",
            "Generic pressure-tap arrangement for an orifice plate.",
            DatasheetValueKind.ENUM,
            _condition("primary_element_family", "orifice_plate"),
            allowed_values=("corner", "d_and_d_over_2", "flange", "other"),
        ),
        _required(
            "design_differential_pressure",
            "measurement",
            "Design differential pressure",
            "Differential pressure at the stated design flow case.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.differential",
            safety_critical=True,
        ),
        _optional(
            "permanent_pressure_loss",
            "measurement",
            "Permanent pressure loss",
            "Estimated permanent pressure loss linked to its calculation when available.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.differential",
        ),
        _optional(
            "relative_uncertainty_percent",
            "measurement",
            "Relative uncertainty",
            "Combined relative measurement uncertainty in percent.",
            DatasheetValueKind.NUMBER,
        ),
        _required(
            "output_signal",
            "integration",
            "Output signal",
            "Required transmitter signal or digital protocol family.",
            DatasheetValueKind.ENUM,
            allowed_values=("4-20_ma", "4-20_ma_hart", "fieldbus", "other"),
        ),
        _required(
            "hazardous_area",
            "integration",
            "Hazardous area",
            "Whether the transmitter location is classified as hazardous.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "hazardous_area_classification",
            "integration",
            "Hazardous-area classification",
            "Site-approved area and temperature classification.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_area", True),
            safety_critical=True,
        ),
    ),
)


CONTROL_VALVE_TEMPLATE: Final = _template(
    template_id=CONTROL_VALVE_TEMPLATE_ID,
    title="Control Valve Datasheet",
    sections=(
        _section(
            "identification", "Identification", "Tag, service, and line identity."
        ),
        _section("process", "Process Cases", "Phase-specific process and flow cases."),
        _section(
            "sizing",
            "Sizing and Performance",
            "Required capacity and installed-performance basis.",
        ),
        _section(
            "mechanical",
            "Valve and Actuator",
            "Generic construction, action, and actuator requirements.",
        ),
        _section(
            "integration",
            "Integration and Environment",
            "Signal, utilities, and hazardous-area requirements.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Tag number",
            "Permanent project tag for the control valve.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "service_description",
            "identification",
            "Service description",
            "Controlled description of the throttling duty.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "line_reference",
            "identification",
            "Line reference",
            "Stable process line identifier.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "fluid_name",
            "process",
            "Fluid name",
            "Controlled identity of the process fluid.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _required(
            "fluid_phase",
            "process",
            "Fluid phase",
            "Phase used for the selected sizing branch.",
            DatasheetValueKind.ENUM,
            allowed_values=("gas", "liquid", "steam", "vapour"),
            safety_critical=True,
        ),
        _required(
            "minimum_actual_flow",
            "process",
            "Minimum actual flow",
            "Minimum actual volumetric flow at the valve inlet condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m3/s",
            quantity_kind="flow.volumetric.actual",
        ),
        _required(
            "normal_actual_flow",
            "process",
            "Normal actual flow",
            "Normal actual volumetric flow at the valve inlet condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m3/s",
            quantity_kind="flow.volumetric.actual",
        ),
        _required(
            "maximum_actual_flow",
            "process",
            "Maximum actual flow",
            "Maximum actual volumetric flow at the valve inlet condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m3/s",
            quantity_kind="flow.volumetric.actual",
            safety_critical=True,
        ),
        _required(
            "inlet_pressure",
            "process",
            "Inlet pressure",
            "Absolute pressure immediately upstream of the valve.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "outlet_pressure",
            "process",
            "Outlet pressure",
            "Absolute pressure immediately downstream of the valve.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "process_temperature",
            "process",
            "Process temperature",
            "Absolute temperature used for sizing and material review.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _required(
            "fluid_density",
            "process",
            "Fluid density",
            "Density at the stated inlet condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/m3",
            quantity_kind="density",
        ),
        _conditional(
            "vapour_pressure",
            "process",
            "Vapour pressure",
            "Absolute vapour pressure for liquid cavitation and flashing screening.",
            DatasheetValueKind.QUANTITY,
            _condition("fluid_phase", "liquid"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _conditional(
            "critical_pressure",
            "process",
            "Critical pressure",
            "Absolute critical pressure for the liquid pressure-recovery correction.",
            DatasheetValueKind.QUANTITY,
            _condition("fluid_phase", "liquid"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
        ),
        _conditional(
            "compressibility_factor",
            "process",
            "Compressibility factor",
            "Compressibility factor at the gas, steam, or vapour inlet condition.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase",
                "gas",
                "steam",
                "vapour",
                operator=DatasheetConditionOperator.IN,
            ),
            safety_critical=True,
        ),
        _conditional(
            "isentropic_exponent",
            "process",
            "Isentropic exponent",
            "Isentropic exponent for compressible sizing.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase",
                "gas",
                "steam",
                "vapour",
                operator=DatasheetConditionOperator.IN,
            ),
            safety_critical=True,
        ),
        _conditional(
            "molecular_mass",
            "process",
            "Molecular mass",
            "Molecular-mass basis for gas, steam, or vapour sizing.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase",
                "gas",
                "steam",
                "vapour",
                operator=DatasheetConditionOperator.IN,
            ),
        ),
        _conditional(
            "steam_state_basis",
            "process",
            "Steam state basis",
            "Dry-saturated or superheated steam-state basis.",
            DatasheetValueKind.ENUM,
            _condition("fluid_phase", "steam"),
            allowed_values=("dry_saturated", "superheated"),
            safety_critical=True,
        ),
        _conditional(
            "steam_eligibility_confirmed",
            "process",
            "Steam eligibility confirmed",
            "Whether the steam state and property basis are eligible for the reviewed compressible sizing method.",
            DatasheetValueKind.BOOLEAN,
            _condition("fluid_phase", "steam"),
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _required(
            "required_flow_coefficient",
            "sizing",
            "Required flow coefficient",
            "Required generic flow coefficient from a reviewed caller-supplied or externally documented sizing result.",
            DatasheetValueKind.NUMBER,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            positive_value_required=True,
            safety_critical=True,
        ),
        _optional(
            "installed_capacity_ratio",
            "sizing",
            "Installed capacity ratio",
            "Screened installed capacity divided by the required capacity.",
            DatasheetValueKind.NUMBER,
        ),
        _optional(
            "noise_or_cavitation_notes",
            "sizing",
            "Noise or cavitation notes",
            "Open findings and required specialist verification.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "inlet_line_size",
            "mechanical",
            "Inlet line size",
            "Internal diameter of the upstream line.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
        ),
        _required(
            "outlet_line_size",
            "mechanical",
            "Outlet line size",
            "Internal diameter of the downstream line.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m",
            quantity_kind="length",
        ),
        _optional(
            "valve_style",
            "mechanical",
            "Valve style",
            "Vendor-neutral valve body style selected for detailed review.",
            DatasheetValueKind.ENUM,
            allowed_values=("angle", "ball", "butterfly", "globe", "other"),
        ),
        _required(
            "fail_action",
            "mechanical",
            "Fail action",
            "Required safe valve action on loss of motive power or signal.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "fail_closed",
                "fail_in_place",
                "fail_open",
                "project_defined",
            ),
            safety_critical=True,
        ),
        _required(
            "shutoff_differential_pressure",
            "mechanical",
            "Shutoff differential pressure",
            "Maximum differential pressure the actuator must overcome for shutoff.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.differential",
            safety_critical=True,
        ),
        _optional(
            "body_material",
            "mechanical",
            "Body material",
            "Required generic body material and compatibility basis.",
            DatasheetValueKind.TEXT,
        ),
        _optional(
            "end_connection",
            "mechanical",
            "End connection",
            "Generic end connection and pressure class.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "control_signal",
            "integration",
            "Control signal",
            "Required generic control signal or protocol family.",
            DatasheetValueKind.ENUM,
            allowed_values=("4-20_ma", "digital", "fieldbus", "pneumatic"),
        ),
        _optional(
            "actuator_supply",
            "integration",
            "Actuator supply",
            "Available pneumatic, hydraulic, or electrical supply.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "hazardous_area",
            "integration",
            "Hazardous area",
            "Whether valve-mounted electrical equipment is in a hazardous area.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "hazardous_area_classification",
            "integration",
            "Hazardous-area classification",
            "Site-approved area and temperature classification.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_area", True),
            safety_critical=True,
        ),
    ),
)


PRESSURE_RELIEF_TEMPLATE: Final = _template(
    template_id=PRESSURE_RELIEF_TEMPLATE_ID,
    title="Preliminary Pressure-Relief Datasheet",
    sections=(
        _section(
            "identification",
            "Identification",
            "Device, equipment, and scenario identity.",
        ),
        _section(
            "relief_basis",
            "Relief Basis",
            "Scenario, relieving load, and pressure basis.",
        ),
        _section(
            "fluid",
            "Relieving Fluid",
            "Phase-specific properties at relieving conditions.",
        ),
        _section(
            "sizing",
            "Preliminary Sizing",
            "Calculated required area and non-final selection data.",
        ),
        _section(
            "verification",
            "Independent Verification",
            "Piping, disposal, and competent-review requirements.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Device tag",
            "Permanent project tag for the pressure-relief device.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "protected_equipment_reference",
            "identification",
            "Protected equipment",
            "Stable identifier for the protected equipment or system.",
            DatasheetValueKind.IDENTIFIER,
            safety_critical=True,
        ),
        _required(
            "relief_scenario_id",
            "identification",
            "Relief scenario",
            "Stable identifier for the independently reviewed relief scenario.",
            DatasheetValueKind.IDENTIFIER,
            safety_critical=True,
        ),
        _required(
            "scenario_type",
            "relief_basis",
            "Scenario type",
            "Generic initiating scenario; the template does not assert governing status.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "blocked_outlet",
                "external_fire",
                "other_reviewed",
                "thermal_expansion",
                "utility_failure",
            ),
            safety_critical=True,
        ),
        _required(
            "governing_scenario_confirmed",
            "relief_basis",
            "Governing scenario confirmed",
            "Whether a competent pressure-systems review confirmed the governing scenario.",
            DatasheetValueKind.BOOLEAN,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _required(
            "fluid_phase",
            "relief_basis",
            "Relieving phase",
            "Phase supported by the preliminary required-area methods in this controlled template version.",
            DatasheetValueKind.ENUM,
            allowed_values=("gas", "liquid", "steam", "vapour"),
            safety_critical=True,
        ),
        _required(
            "required_relief_mass_flow",
            "relief_basis",
            "Required relief mass flow",
            "Required relieving rate from the controlled scenario basis.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="kg/s",
            quantity_kind="flow.mass",
            safety_critical=True,
        ),
        _required(
            "set_pressure",
            "relief_basis",
            "Set pressure",
            "Gauge set pressure on the controlled pressure basis.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.gauge",
            safety_critical=True,
        ),
        _required(
            "allowable_overpressure_ratio",
            "relief_basis",
            "Allowable overpressure ratio",
            "Project-authorized overpressure or accumulation fraction.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="1",
            quantity_kind="ratio",
            safety_critical=True,
        ),
        _required(
            "backpressure_basis",
            "relief_basis",
            "Backpressure basis",
            "Explicit absolute or gauge basis for the stated backpressure.",
            DatasheetValueKind.ENUM,
            allowed_values=("absolute", "gauge"),
            safety_critical=True,
        ),
        _conditional(
            "backpressure_gauge",
            "relief_basis",
            "Gauge backpressure",
            "Gauge backpressure on the controlled project basis.",
            DatasheetValueKind.QUANTITY,
            _condition("backpressure_basis", "gauge"),
            preferred_unit="Pa",
            quantity_kind="pressure.gauge",
            safety_critical=True,
        ),
        _conditional(
            "backpressure_absolute",
            "relief_basis",
            "Absolute backpressure",
            "Absolute backpressure on the controlled project basis.",
            DatasheetValueKind.QUANTITY,
            _condition("backpressure_basis", "absolute"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _conditional(
            "atmospheric_pressure",
            "relief_basis",
            "Atmospheric pressure",
            "Absolute atmospheric pressure used to reconcile a gauge-pressure basis.",
            DatasheetValueKind.QUANTITY,
            _condition("backpressure_basis", "gauge"),
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "relieving_temperature",
            "fluid",
            "Relieving temperature",
            "Absolute temperature at the relieving condition.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _conditional(
            "relieving_density",
            "fluid",
            "Relieving density",
            "Density at relieving conditions for liquid sizing.",
            DatasheetValueKind.QUANTITY,
            _condition("fluid_phase", "liquid"),
            preferred_unit="kg/m3",
            quantity_kind="density",
            safety_critical=True,
        ),
        _conditional(
            "dynamic_viscosity",
            "fluid",
            "Dynamic viscosity",
            "Dynamic viscosity at relieving conditions for liquid correction review.",
            DatasheetValueKind.QUANTITY,
            _condition("fluid_phase", "liquid"),
            preferred_unit="Pa*s",
            quantity_kind="viscosity.dynamic",
        ),
        _conditional(
            "compressibility_factor",
            "fluid",
            "Compressibility factor",
            "Compressibility factor at the gas or vapour relieving condition.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase", "gas", "vapour", operator=DatasheetConditionOperator.IN
            ),
            safety_critical=True,
        ),
        _conditional(
            "isentropic_exponent",
            "fluid",
            "Isentropic exponent",
            "Isentropic exponent for gas or vapour required-area sizing.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase", "gas", "vapour", operator=DatasheetConditionOperator.IN
            ),
            safety_critical=True,
        ),
        _conditional(
            "molecular_mass",
            "fluid",
            "Molecular mass",
            "Molecular-mass basis for gas or vapour sizing.",
            DatasheetValueKind.NUMBER,
            _condition(
                "fluid_phase", "gas", "vapour", operator=DatasheetConditionOperator.IN
            ),
        ),
        _conditional(
            "steam_specific_volume_m3_kg",
            "fluid",
            "Steam specific volume",
            "Positive relieving specific volume in cubic metres per kilogram for the eligible steam method.",
            DatasheetValueKind.NUMBER,
            _condition("fluid_phase", "steam"),
            positive_value_required=True,
            safety_critical=True,
        ),
        _conditional(
            "steam_specific_volume_basis",
            "fluid",
            "Steam specific-volume basis",
            "Traceable property source and state basis for the relieving specific volume.",
            DatasheetValueKind.TEXT,
            _condition("fluid_phase", "steam"),
            safety_critical=True,
        ),
        _conditional(
            "steam_eligibility_confirmed",
            "fluid",
            "Steam eligibility confirmed",
            "Whether dry-saturated or superheated eligibility evidence was independently confirmed.",
            DatasheetValueKind.BOOLEAN,
            _condition("fluid_phase", "steam"),
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _required(
            "preliminary_required_area",
            "sizing",
            "Preliminary required area",
            "Calculated minimum effective discharge area from a reviewed internal or externally documented run; not a final valve selection.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m2",
            quantity_kind="area",
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
                DatasheetFieldOrigin.CALCULATED,
            ),
            positive_value_required=True,
            safety_critical=True,
        ),
        _required(
            "required_area_basis_verified",
            "sizing",
            "Required-area basis verified",
            "Whether the phase-specific property, pressure, coefficient, and eligibility basis for the preliminary area was independently reviewed.",
            DatasheetValueKind.BOOLEAN,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _optional(
            "selected_nominal_orifice_area",
            "sizing",
            "Selected nominal orifice area",
            "Candidate nominal area pending manufacturer and standards verification.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="m2",
            quantity_kind="area",
        ),
        _optional(
            "candidate_device_reference",
            "sizing",
            "Candidate device reference",
            "User-selected candidate reference; the template makes no manufacturer recommendation.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "inlet_piping_verified",
            "verification",
            "Inlet piping verified",
            "Independent confirmation of inlet pressure-loss and installation constraints.",
            DatasheetValueKind.BOOLEAN,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _required(
            "outlet_piping_verified",
            "verification",
            "Outlet piping verified",
            "Independent confirmation of backpressure, reaction, and discharge constraints.",
            DatasheetValueKind.BOOLEAN,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _required(
            "hazardous_release",
            "verification",
            "Hazardous release",
            "Whether the relieved material presents toxic, flammable, reactive, or environmental hazards.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "disposal_route",
            "verification",
            "Disposal route",
            "Reviewed destination and safeguards for a hazardous release.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_release", True),
            safety_critical=True,
        ),
        _required(
            "competent_review_completed",
            "verification",
            "Competent review completed",
            "Independent review status; it does not grant design approval in Engineer4Me.",
            DatasheetValueKind.BOOLEAN,
            allowed_origins=(
                DatasheetFieldOrigin.USER_SUPPLIED,
                DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
            ),
            required_boolean_value=True,
            safety_critical=True,
        ),
        _optional(
            "open_verification_notes",
            "verification",
            "Open verification notes",
            "Outstanding standards, jurisdiction, manufacturer, or site checks.",
            DatasheetValueKind.TEXT,
        ),
    ),
)


PROCESS_ANALYZER_TEMPLATE: Final = _template(
    template_id=PROCESS_ANALYZER_TEMPLATE_ID,
    title="Process Analyzer Datasheet",
    sections=(
        _section(
            "identification",
            "Identification",
            "Tag, service, and measurement objective.",
        ),
        _section(
            "measurement",
            "Measurement Requirements",
            "Analyte, range, accuracy, and response requirements.",
        ),
        _section(
            "process",
            "Process and Interferences",
            "Process conditions, composition, and known interferences.",
        ),
        _section(
            "sample_system",
            "Sample System",
            "Extractive or in-situ installation and sample disposition.",
        ),
        _section(
            "integration",
            "Integration and Lifecycle",
            "Utilities, signals, calibration, maintenance, and area classification.",
        ),
    ),
    fields=(
        _required(
            "tag_number",
            "identification",
            "Tag number",
            "Permanent project tag for the process analyzer.",
            DatasheetValueKind.IDENTIFIER,
        ),
        _required(
            "service_description",
            "identification",
            "Service description",
            "Controlled description of the analyzer duty.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "measurement_objective",
            "identification",
            "Measurement objective",
            "Operational, quality, environmental, or protective objective.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "environmental",
                "operational_control",
                "process_safety_support",
                "product_quality",
            ),
            safety_critical=True,
        ),
        _required(
            "analyte",
            "measurement",
            "Analyte",
            "Controlled analyte or measurand identity.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _required(
            "minimum_measurement_value",
            "measurement",
            "Minimum measurement value",
            "Lower endpoint of the required measurement range.",
            DatasheetValueKind.NUMBER,
        ),
        _required(
            "maximum_measurement_value",
            "measurement",
            "Maximum measurement value",
            "Upper endpoint of the required measurement range.",
            DatasheetValueKind.NUMBER,
            safety_critical=True,
        ),
        _required(
            "reporting_unit",
            "measurement",
            "Reporting unit",
            "Controlled unit or basis for the analyte result.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "response_time_requirement",
            "measurement",
            "Response-time requirement",
            "Maximum acceptable system response time at the stated criterion.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="s",
            quantity_kind="time",
            safety_critical=True,
        ),
        _optional(
            "accuracy_requirement_percent",
            "measurement",
            "Accuracy requirement",
            "Required accuracy in percent on the controlled reporting basis.",
            DatasheetValueKind.NUMBER,
        ),
        _optional(
            "repeatability_requirement_percent",
            "measurement",
            "Repeatability requirement",
            "Required repeatability in percent on the controlled reporting basis.",
            DatasheetValueKind.NUMBER,
        ),
        _required(
            "sample_phase",
            "process",
            "Sample phase",
            "Expected phase at the measurement or extraction point.",
            DatasheetValueKind.ENUM,
            allowed_values=("gas", "liquid", "mixed", "vapour"),
            safety_critical=True,
        ),
        _required(
            "process_pressure",
            "process",
            "Process pressure",
            "Absolute pressure at the measurement or extraction point.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="Pa",
            quantity_kind="pressure.absolute",
            safety_critical=True,
        ),
        _required(
            "process_temperature",
            "process",
            "Process temperature",
            "Absolute temperature at the measurement or extraction point.",
            DatasheetValueKind.QUANTITY,
            preferred_unit="K",
            quantity_kind="temperature.absolute",
            safety_critical=True,
        ),
        _required(
            "known_interference_present",
            "process",
            "Known interference present",
            "Whether reviewed cross-sensitivities or interferents are known.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "known_interferences",
            "process",
            "Known interferences",
            "Identified interferents, mechanisms, and expected concentration ranges.",
            DatasheetValueKind.TEXT,
            _condition("known_interference_present", True),
            safety_critical=True,
        ),
        _optional(
            "process_composition",
            "process",
            "Process composition",
            "Composition basis relevant to technology and sample-system review.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "technology_family",
            "measurement",
            "Technology family",
            "Vendor-neutral analytical technology selected for detailed verification.",
            DatasheetValueKind.ENUM,
            allowed_values=(
                "chromatography",
                "electrochemical",
                "laser_spectroscopy",
                "mass_spectrometry",
                "optical_spectroscopy",
                "physical_property",
                "wet_chemistry",
            ),
        ),
        _required(
            "extractive_service",
            "sample_system",
            "Extractive service",
            "Whether a sample is transported from the process to the analyzer.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "sample_tap_location",
            "sample_system",
            "Sample tap location",
            "Controlled extraction-point location and orientation.",
            DatasheetValueKind.TEXT,
            _condition("extractive_service", True),
            safety_critical=True,
        ),
        _conditional(
            "sample_transport_length",
            "sample_system",
            "Sample transport length",
            "Approximate transport length used for lag and conditioning review.",
            DatasheetValueKind.QUANTITY,
            _condition("extractive_service", True),
            preferred_unit="m",
            quantity_kind="length",
        ),
        _conditional(
            "sample_conditioning",
            "sample_system",
            "Sample conditioning",
            "Required filtration, pressure, temperature, phase, and moisture conditioning.",
            DatasheetValueKind.TEXT,
            _condition("extractive_service", True),
            safety_critical=True,
        ),
        _conditional(
            "in_situ_mounting",
            "sample_system",
            "In-situ mounting",
            "Probe, optical path, or insertion arrangement for a non-extractive analyzer.",
            DatasheetValueKind.TEXT,
            _condition("extractive_service", False),
            safety_critical=True,
        ),
        _conditional(
            "sample_waste_hazardous",
            "sample_system",
            "Hazardous sample waste",
            "Whether the extractive sample return or disposal stream is hazardous.",
            DatasheetValueKind.BOOLEAN,
            _condition("extractive_service", True),
            safety_critical=True,
        ),
        _conditional(
            "sample_disposal_route",
            "sample_system",
            "Sample disposal route",
            "Reviewed safe return, recovery, treatment, or disposal route.",
            DatasheetValueKind.TEXT,
            _condition("sample_waste_hazardous", True),
            safety_critical=True,
        ),
        _required(
            "calibration_strategy",
            "integration",
            "Calibration strategy",
            "Controlled calibration, validation, and reference-material strategy.",
            DatasheetValueKind.TEXT,
            safety_critical=True,
        ),
        _optional(
            "utility_requirements",
            "integration",
            "Utility requirements",
            "Electrical, instrument air, purge, carrier, cooling, or other utilities.",
            DatasheetValueKind.TEXT,
        ),
        _required(
            "output_signal",
            "integration",
            "Output signal",
            "Required signal, protocol, or data-interface family.",
            DatasheetValueKind.ENUM,
            allowed_values=("4-20_ma", "digital", "fieldbus", "other"),
        ),
        _required(
            "hazardous_area",
            "integration",
            "Hazardous area",
            "Whether the analyzer or sample system is installed in a hazardous area.",
            DatasheetValueKind.BOOLEAN,
            safety_critical=True,
        ),
        _conditional(
            "hazardous_area_classification",
            "integration",
            "Hazardous-area classification",
            "Site-approved area, material group, and temperature classification.",
            DatasheetValueKind.TEXT,
            _condition("hazardous_area", True),
            safety_critical=True,
        ),
        _optional(
            "maintenance_access",
            "integration",
            "Maintenance access",
            "Access, isolation, lifting, shelter, and consumables constraints.",
            DatasheetValueKind.TEXT,
        ),
    ),
)


DATASHEET_TEMPLATES: Final = (
    PRESSURE_TRANSMITTER_TEMPLATE,
    LEVEL_TRANSMITTER_TEMPLATE,
    DP_FLOW_TEMPLATE,
    CONTROL_VALVE_TEMPLATE,
    PRESSURE_RELIEF_TEMPLATE,
    PROCESS_ANALYZER_TEMPLATE,
)


def _normalize_lookup(
    value: object,
    *,
    field_name: str,
    pattern: str,
) -> str:
    if not isinstance(value, str):
        raise InvalidDatasheetTemplateLookupError(f"{field_name} must be a string.")
    normalized = value.strip()
    minimum, maximum = (3, 64) if field_name == "template_version" else (2, 100)
    if (
        len(normalized) < minimum
        or len(normalized) > maximum
        or fullmatch(pattern, normalized) is None
    ):
        raise InvalidDatasheetTemplateLookupError(
            f"{field_name} is not a valid controlled identifier."
        )
    return normalized


class DatasheetTemplateRegistry:
    """Immutable registry supporting only deterministic exact-version lookup."""

    __slots__ = (
        "_entries",
        "_locked",
        "_template_ids",
        "_templates",
        "_versions_by_template",
    )

    def __init__(
        self,
        templates: Iterable[DatasheetTemplateDefinition],
    ) -> None:
        object.__setattr__(self, "_locked", False)
        entries: dict[TemplateKey, DatasheetTemplateDefinition] = {}
        folded_keys: set[TemplateKey] = set()
        canonical_ids: dict[str, str] = {}
        identities: dict[str, tuple[str, str]] = {}
        for index, candidate in enumerate(templates):
            if index >= MAX_REGISTERED_DATASHEET_TEMPLATES:
                raise InvalidDatasheetTemplateRegistrationError(
                    "A datasheet registry exceeds the bounded template count."
                )
            if not isinstance(candidate, DatasheetTemplateDefinition):
                raise InvalidDatasheetTemplateRegistrationError(
                    "Registry entries must be DatasheetTemplateDefinition instances."
                )
            template = DatasheetTemplateDefinition.model_validate(
                candidate.model_dump(
                    mode="python",
                    round_trip=True,
                    warnings="error",
                )
            )
            key = (template.template_id, template.template_version)
            folded_key = (
                template.template_id.casefold(),
                template.template_version.casefold(),
            )
            if key in entries or folded_key in folded_keys:
                raise DuplicateDatasheetTemplateRegistrationError(
                    "Duplicate or case-conflicting datasheet template identity."
                )
            folded_id = template.template_id.casefold()
            canonical_id = canonical_ids.get(folded_id)
            if canonical_id is not None and canonical_id != template.template_id:
                raise DuplicateDatasheetTemplateRegistrationError(
                    "Case-conflicting permanent datasheet template ID."
                )
            existing = identities.get(folded_id)
            identity = (template.title, template.discipline)
            if existing is not None and existing != identity:
                raise InvalidDatasheetTemplateRegistrationError(
                    "Every version of a template must retain its title and discipline."
                )
            entries[key] = template
            folded_keys.add(folded_key)
            canonical_ids[folded_id] = template.template_id
            identities[folded_id] = identity

        if not entries:
            raise InvalidDatasheetTemplateRegistrationError(
                "A datasheet registry requires at least one controlled template."
            )

        ordered_keys = tuple(sorted(entries))
        ordered_entries = {key: entries[key] for key in ordered_keys}
        ordered_templates = tuple(ordered_entries[key] for key in ordered_keys)
        template_ids = tuple(sorted({key[0] for key in ordered_keys}))
        versions = {
            template_id: tuple(key[1] for key in ordered_keys if key[0] == template_id)
            for template_id in template_ids
        }
        object.__setattr__(self, "_entries", MappingProxyType(ordered_entries))
        object.__setattr__(self, "_templates", ordered_templates)
        object.__setattr__(self, "_template_ids", template_ids)
        object.__setattr__(self, "_versions_by_template", MappingProxyType(versions))
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("DatasheetTemplateRegistry instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("DatasheetTemplateRegistry instances are immutable.")
        object.__delattr__(self, name)

    @property
    def templates(self) -> tuple[DatasheetTemplateDefinition, ...]:
        """Return all templates sorted by exact identity."""

        return self._templates

    @property
    def definitions(self) -> tuple[DatasheetTemplateDefinition, ...]:
        """Compatibility name for immutable template metadata discovery."""

        return self._templates

    @property
    def template_ids(self) -> tuple[str, ...]:
        """Return sorted permanent template identifiers."""

        return self._template_ids

    def available_versions(self, template_id: str) -> tuple[str, ...]:
        """Return versions without choosing one implicitly."""

        normalized_id = _normalize_lookup(
            template_id,
            field_name="template_id",
            pattern=_IDENTIFIER_PATTERN,
        )
        versions = self._versions_by_template.get(normalized_id)
        if versions is None:
            raise UnknownDatasheetTemplateError(normalized_id)
        return versions

    def resolve(
        self,
        template_id: str,
        template_version: str,
    ) -> DatasheetTemplateDefinition:
        """Return one exact template; never fall back to another version."""

        normalized_id = _normalize_lookup(
            template_id,
            field_name="template_id",
            pattern=_IDENTIFIER_PATTERN,
        )
        normalized_version = _normalize_lookup(
            template_version,
            field_name="template_version",
            pattern=_VERSION_PATTERN,
        )
        if normalized_id not in self._versions_by_template:
            raise UnknownDatasheetTemplateError(normalized_id)
        template = self._entries.get((normalized_id, normalized_version))
        if template is None:
            raise UnknownDatasheetTemplateVersionError(
                normalized_id,
                normalized_version,
            )
        return template

    def discover(
        self,
        *,
        discipline: str | None = None,
    ) -> tuple[DatasheetTemplateDefinition, ...]:
        """Return deterministic inert metadata, optionally by discipline."""

        if discipline is None:
            return self._templates
        normalized = _normalize_lookup(
            discipline,
            field_name="discipline",
            pattern=_IDENTIFIER_PATTERN,
        )
        return tuple(
            template
            for template in self._templates
            if template.discipline == normalized
        )


DATASHEET_TEMPLATE_REGISTRY: Final = DatasheetTemplateRegistry(DATASHEET_TEMPLATES)
DEFAULT_DATASHEET_TEMPLATE_REGISTRY: Final = DATASHEET_TEMPLATE_REGISTRY

if DATASHEET_MODEL_VERSION != DATASHEET_TEMPLATE_VERSION:
    raise RuntimeError("Step 109 template and datasheet model versions drifted")
if len(DATASHEET_TEMPLATES) != 6:
    raise RuntimeError("Step 109 requires exactly six controlled templates")
if any(
    template.template_version != DATASHEET_TEMPLATE_VERSION
    for template in DATASHEET_TEMPLATES
):
    raise RuntimeError("Every Step 109 template must use exact version 1.0.0")


__all__ = [
    "CONTROL_VALVE_TEMPLATE",
    "CONTROL_VALVE_TEMPLATE_ID",
    "DATASHEET_TEMPLATES",
    "DATASHEET_TEMPLATE_REGISTRY",
    "DATASHEET_TEMPLATE_REGISTRY_VERSION",
    "DATASHEET_TEMPLATE_VERSION",
    "DEFAULT_DATASHEET_TEMPLATE_REGISTRY",
    "DP_FLOW_TEMPLATE",
    "DP_FLOW_TEMPLATE_ID",
    "LEVEL_TRANSMITTER_TEMPLATE",
    "LEVEL_TRANSMITTER_TEMPLATE_ID",
    "MAX_REGISTERED_DATASHEET_TEMPLATES",
    "PRESSURE_RELIEF_TEMPLATE",
    "PRESSURE_RELIEF_TEMPLATE_ID",
    "PRESSURE_TRANSMITTER_TEMPLATE",
    "PRESSURE_TRANSMITTER_TEMPLATE_ID",
    "PROCESS_ANALYZER_TEMPLATE",
    "PROCESS_ANALYZER_TEMPLATE_ID",
    "DatasheetTemplateRegistry",
    "DatasheetTemplateRegistryError",
    "DuplicateDatasheetTemplateRegistrationError",
    "InvalidDatasheetTemplateLookupError",
    "InvalidDatasheetTemplateRegistrationError",
    "UnknownDatasheetTemplateError",
    "UnknownDatasheetTemplateVersionError",
]
