"""Strict Step 109 contracts for controlled engineering datasheets.

The models in this module are immutable, finite, bounded, vendor neutral, and
explicit about unknown information.  They contain no spreadsheet rendering,
database access, API behavior, dynamic expressions, manufacturer selection,
or engineering approval.  Conditional requirements are declarative and are
evaluated only by the allow-listed Step 109 datasheet service.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from math import isfinite
from typing import Annotated, Literal, Self
from uuid import UUID

from app.engineering.calculations.models import (
    CalculationModel,
    CalculationOutput,
    CalculationStatus,
    EngineeringQuantity,
    FingerprintText,
    Identifier,
    LongText,
    ShortText,
    TextItem,
    VersionText,
)
from app.engineering.calculations.units import (
    DEFAULT_UNIT_REGISTRY,
    UnitSystemError,
)
from app.engineering.design.persistence_models import (
    CalculationRunPayload,
    DesignApprovalState,
    EngineeringRunRecord,
    RecordedIdentityOrigin,
    canonical_utc_text,
    fingerprint_persistence_payload,
    normalise_utc,
)
from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

DATASHEET_MODEL_VERSION = "1.0.0"
DATASHEET_TEMPLATE_SCHEMA = "engineer4me.datasheet.template.v1"
DATASHEET_CONTENT_SCHEMA = "engineer4me.datasheet.content.v1"
DATASHEET_COMPLETENESS_SCHEMA = "engineer4me.datasheet.completeness.v1"
DATASHEET_REVISION_SCHEMA = "engineer4me.datasheet.revision.v1"
DATASHEET_CANONICALIZATION = "engineer4me.canonical-json.sha256.v1"
MAX_DATASHEET_SECTIONS = 32
MAX_DATASHEET_FIELDS = 128
MAX_DATASHEET_SOURCES = 128
MAX_DATASHEET_ASSUMPTIONS = 128
MAX_DATASHEET_CALCULATION_LINKS = 32
MAX_DATASHEET_REVISIONS = 100
MAX_CONDITION_VALUES = 32
MAX_DATASHEET_ABSOLUTE_NUMBER = 1.0e300
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,99}$")

UnknownReason = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1_000),
]
SourceLocator = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1_000),
]
DatasheetInteger = Annotated[
    StrictInt,
    Field(ge=-(10**300), le=10**300),
]
DatasheetFloat = Annotated[
    StrictFloat,
    Field(
        ge=-MAX_DATASHEET_ABSOLUTE_NUMBER,
        le=MAX_DATASHEET_ABSOLUTE_NUMBER,
    ),
]
DatasheetTextValue = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4_000),
]
DatasheetConditionValue = (
    StrictBool | DatasheetInteger | DatasheetFloat | DatasheetTextValue
)
DatasheetValue = (
    EngineeringQuantity
    | StrictBool
    | DatasheetInteger
    | DatasheetFloat
    | DatasheetTextValue
)


class DatasheetValueKind(StrEnum):
    """Controlled scalar kinds supported before workbook rendering exists."""

    TEXT = "text"
    IDENTIFIER = "identifier"
    ENUM = "enum"
    BOOLEAN = "boolean"
    NUMBER = "number"
    QUANTITY = "quantity"


class DatasheetFieldRequirement(StrEnum):
    """Presence rule declared by one controlled template field."""

    REQUIRED = "required"
    CONDITIONAL = "conditional"
    OPTIONAL = "optional"


class DatasheetConditionOperator(StrEnum):
    """Allow-listed, non-executable conditional comparison operators."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"


class DatasheetFieldOrigin(StrEnum):
    """Exact Step 109 field-origin vocabulary, including visible unknowns."""

    USER_SUPPLIED = "user_supplied"
    DOCUMENT_EXTRACTED = "document_extracted"
    CALCULATED = "calculated"
    SELECTED = "selected"
    DEFAULTED = "defaulted"
    UNKNOWN = "unknown"


class DatasheetFieldState(StrEnum):
    """Whether a field has a value, is unknown, or is explicitly inapplicable."""

    KNOWN = "known"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class DatasheetLifecycleState(StrEnum):
    """Non-approval lifecycle states available to Step 109 datasheets."""

    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    ON_HOLD = "on_hold"
    ARCHIVED = "archived"


class DatasheetTemplateLifecycleStatus(StrEnum):
    """Controlled lifecycle status for versioned template definitions."""

    CONTROLLED = "controlled"


class DatasheetAssumptionVerificationState(StrEnum):
    """Evidence state for one explicit datasheet assumption."""

    UNRESOLVED = "unresolved"
    VERIFIED = "verified"


class DatasheetFieldDisposition(StrEnum):
    """Derived completeness disposition for one controlled field."""

    SATISFIED = "satisfied"
    REQUIRED_MISSING = "required_missing"
    REQUIRED_UNKNOWN = "required_unknown"
    REQUIRED_VALUE_NOT_CONFIRMED = "required_value_not_confirmed"
    OPTIONAL_MISSING = "optional_missing"
    OPTIONAL_UNKNOWN = "optional_unknown"
    CONDITIONAL_UNRESOLVED = "conditional_unresolved"
    CONDITIONAL_NOT_APPLICABLE = "conditional_not_applicable"
    CONDITIONAL_VALUE_WHEN_NOT_REQUIRED = "conditional_value_when_not_required"


class DatasheetCompletenessState(StrEnum):
    """Derived completeness state; it never represents engineering approval."""

    COMPLETE = "complete"
    COMPLETE_WITH_OPEN_ITEMS = "complete_with_open_items"
    INCOMPLETE = "incomplete"
    BLOCKED = "blocked"


def _canonical_text(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    ordered = tuple(sorted(values, key=str.casefold))
    if len({value.casefold() for value in ordered}) != len(ordered):
        raise ValueError(f"{field_name} values must be unique")
    return ordered


def _canonical_models(values, *, attribute: str):
    ordered = tuple(
        sorted(values, key=lambda item: str(getattr(item, attribute)).casefold())
    )
    identifiers = [str(getattr(item, attribute)).casefold() for item in ordered]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{attribute} values must be unique")
    return ordered


def _condition_value_key(value: DatasheetConditionValue) -> tuple[str, str]:
    return (type(value).__name__, repr(value))


def _is_number(value: object) -> bool:
    return type(value) in {int, float}


class DatasheetFieldCondition(CalculationModel):
    """One declarative dependency used by the bounded completeness engine."""

    depends_on_field_id: Identifier
    operator: DatasheetConditionOperator
    expected_values: tuple[DatasheetConditionValue, ...] = Field(
        min_length=1,
        max_length=MAX_CONDITION_VALUES,
    )

    @model_validator(mode="after")
    def validate_condition(self) -> Self:
        if (
            self.operator
            in {
                DatasheetConditionOperator.EQUALS,
                DatasheetConditionOperator.NOT_EQUALS,
            }
            and len(self.expected_values) != 1
        ):
            raise ValueError("equals conditions require exactly one expected value")
        keys = tuple(_condition_value_key(value) for value in self.expected_values)
        if len(keys) != len(set(keys)):
            raise ValueError("condition expected_values must be unique")
        return self


class DatasheetSectionDefinition(CalculationModel):
    """One ordered section in a controlled template."""

    section_id: Identifier
    title: ShortText
    description: LongText | None = None


class DatasheetFieldDefinition(CalculationModel):
    """One stable field definition in a controlled template."""

    field_id: Identifier
    section_id: Identifier
    label: ShortText
    description: LongText
    value_kind: DatasheetValueKind
    requirement: DatasheetFieldRequirement
    preferred_unit: ShortText | None = None
    quantity_kind: Identifier | None = None
    allowed_values: tuple[ShortText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_CONDITION_VALUES,
    )
    condition: DatasheetFieldCondition | None = None
    safety_critical: StrictBool = False
    allowed_origins: tuple[DatasheetFieldOrigin, ...] = (
        DatasheetFieldOrigin.USER_SUPPLIED,
        DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
        DatasheetFieldOrigin.SELECTED,
        DatasheetFieldOrigin.DEFAULTED,
    )
    required_boolean_value: StrictBool | None = None
    positive_value_required: StrictBool = False

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "allowed_values",
            _canonical_text(self.allowed_values, field_name="allowed_values"),
        )
        ordered_origins = tuple(
            sorted(self.allowed_origins, key=lambda item: item.value)
        )
        if len(ordered_origins) != len(set(ordered_origins)):
            raise ValueError("allowed_origins values must be unique")
        object.__setattr__(self, "allowed_origins", ordered_origins)

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        if (self.requirement is DatasheetFieldRequirement.CONDITIONAL) != (
            self.condition is not None
        ):
            raise ValueError("only conditional fields may declare a condition")
        if (
            self.condition is not None
            and self.condition.depends_on_field_id.casefold()
            == self.field_id.casefold()
        ):
            raise ValueError("a field cannot condition itself")
        if self.value_kind is DatasheetValueKind.QUANTITY:
            if self.preferred_unit is None or self.quantity_kind is None:
                raise ValueError(
                    "quantity fields require preferred_unit and quantity_kind"
                )
            try:
                expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(
                    self.quantity_kind
                )
                preferred = DEFAULT_UNIT_REGISTRY.resolve_unit(self.preferred_unit)
            except UnitSystemError as exc:
                raise ValueError(
                    "quantity field preferred-unit metadata is unsupported"
                ) from exc
            if preferred.dimension is not expected_dimension:
                raise ValueError(
                    "quantity field preferred unit has an incompatible dimension"
                )
        elif self.preferred_unit is not None or self.quantity_kind is not None:
            raise ValueError("only quantity fields may declare quantity metadata")
        if self.value_kind is DatasheetValueKind.ENUM:
            if len(self.allowed_values) < 2:
                raise ValueError("enum fields require at least two allowed values")
        elif self.allowed_values:
            raise ValueError("only enum fields may declare allowed_values")
        if not self.allowed_origins:
            raise ValueError("a field requires at least one allowed origin")
        if DatasheetFieldOrigin.UNKNOWN in self.allowed_origins:
            raise ValueError("unknown is a state, not an allowed known-value origin")
        if (
            self.value_kind is DatasheetValueKind.NUMBER
            and DatasheetFieldOrigin.CALCULATED in self.allowed_origins
        ):
            raise ValueError(
                "number fields cannot use calculated origin before typed scalar "
                "calculation outputs exist"
            )
        if self.required_boolean_value is not None:
            if self.value_kind is not DatasheetValueKind.BOOLEAN:
                raise ValueError("only Boolean fields may require a confirmed value")
            if self.requirement is DatasheetFieldRequirement.OPTIONAL:
                raise ValueError("optional Boolean fields cannot require confirmation")
        if self.requirement is DatasheetFieldRequirement.OPTIONAL and (
            self.safety_critical
        ):
            raise ValueError("optional fields cannot be safety critical")
        if self.positive_value_required and self.value_kind not in {
            DatasheetValueKind.NUMBER,
            DatasheetValueKind.QUANTITY,
        }:
            raise ValueError("only numeric fields may require a positive value")
        return self


def build_datasheet_template_fingerprint(
    *,
    template_id: str,
    template_version: str,
    title: str,
    discipline: str,
    sections: tuple[DatasheetSectionDefinition, ...],
    fields: tuple[DatasheetFieldDefinition, ...],
) -> str:
    """Fingerprint every controlled template definition field."""

    return fingerprint_persistence_payload(
        {
            "schema": DATASHEET_TEMPLATE_SCHEMA,
            "schema_version": DATASHEET_MODEL_VERSION,
            "template_id": template_id,
            "template_version": template_version,
            "title": title,
            "discipline": discipline,
            "sections": [
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in sections
            ],
            "fields": [
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in fields
            ],
            "lifecycle_status": DatasheetTemplateLifecycleStatus.CONTROLLED.value,
            "vendor_neutral": True,
            "standards_conformity_claimed": False,
            "final_design_approval_granted": False,
        }
    )


class DatasheetTemplateDefinition(CalculationModel):
    """One fingerprinted, immutable, vendor-neutral datasheet template."""

    schema_id: Literal["engineer4me.datasheet.template.v1"] = DATASHEET_TEMPLATE_SCHEMA
    schema_version: Literal["1.0.0"] = DATASHEET_MODEL_VERSION
    template_id: Identifier
    template_version: VersionText
    template_fingerprint: FingerprintText
    title: ShortText
    discipline: Identifier
    sections: tuple[DatasheetSectionDefinition, ...] = Field(
        min_length=1,
        max_length=MAX_DATASHEET_SECTIONS,
    )
    fields: tuple[DatasheetFieldDefinition, ...] = Field(
        min_length=1,
        max_length=MAX_DATASHEET_FIELDS,
    )
    lifecycle_status: Literal[DatasheetTemplateLifecycleStatus.CONTROLLED] = (
        DatasheetTemplateLifecycleStatus.CONTROLLED
    )
    vendor_neutral: Literal[True] = True
    standards_conformity_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False

    @classmethod
    def create(
        cls,
        *,
        template_id: str,
        template_version: str,
        title: str,
        discipline: str,
        sections: tuple[DatasheetSectionDefinition, ...],
        fields: tuple[DatasheetFieldDefinition, ...],
    ) -> DatasheetTemplateDefinition:
        fingerprint = build_datasheet_template_fingerprint(
            template_id=template_id,
            template_version=template_version,
            title=title,
            discipline=discipline,
            sections=sections,
            fields=fields,
        )
        return cls(
            template_id=template_id,
            template_version=template_version,
            template_fingerprint=fingerprint,
            title=title,
            discipline=discipline,
            sections=sections,
            fields=fields,
        )

    @model_validator(mode="after")
    def validate_template(self) -> Self:
        section_ids = [item.section_id.casefold() for item in self.sections]
        field_ids = [item.field_id.casefold() for item in self.fields]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("template section IDs must be unique")
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("template field IDs must be unique")
        section_map = {
            item.section_id.casefold(): item.section_id for item in self.sections
        }
        field_map = {item.field_id.casefold(): item for item in self.fields}
        for field in self.fields:
            canonical_section_id = section_map.get(field.section_id.casefold())
            if canonical_section_id is None:
                raise ValueError("template field links an unknown section")
            if field.section_id != canonical_section_id:
                raise ValueError("template field section ID capitalization drifted")
            if field.condition is None:
                continue
            dependency_id = field.condition.depends_on_field_id.casefold()
            if dependency_id not in field_map:
                raise ValueError("conditional field links an unknown field")
            dependency = field_map[dependency_id]
            if field.condition.depends_on_field_id != dependency.field_id:
                raise ValueError("conditional dependency capitalization drifted")
            self._validate_condition_type(field.condition, dependency)
        self._validate_acyclic_conditions(field_map)
        expected = build_datasheet_template_fingerprint(
            template_id=self.template_id,
            template_version=self.template_version,
            title=self.title,
            discipline=self.discipline,
            sections=self.sections,
            fields=self.fields,
        )
        if self.template_fingerprint != expected:
            raise ValueError("template_fingerprint is stale")
        return self

    @staticmethod
    def _validate_condition_type(
        condition: DatasheetFieldCondition,
        dependency: DatasheetFieldDefinition,
    ) -> None:
        values = condition.expected_values
        if dependency.value_kind is DatasheetValueKind.BOOLEAN:
            valid = all(type(value) is bool for value in values)
        elif dependency.value_kind in {
            DatasheetValueKind.TEXT,
            DatasheetValueKind.IDENTIFIER,
            DatasheetValueKind.ENUM,
        }:
            valid = all(type(value) is str for value in values)
        elif dependency.value_kind is DatasheetValueKind.NUMBER:
            valid = all(_is_number(value) for value in values)
        else:
            valid = False
        if not valid:
            raise ValueError("condition values do not match the dependency kind")
        if dependency.value_kind is DatasheetValueKind.ENUM:
            allowed = set(dependency.allowed_values)
            if any(value not in allowed for value in values):
                raise ValueError("condition uses a value outside the dependency enum")

    @staticmethod
    def _validate_acyclic_conditions(
        field_map: dict[str, DatasheetFieldDefinition],
    ) -> None:
        graph = {
            field_id: (
                field.condition.depends_on_field_id.casefold()
                if field.condition is not None
                else None
            )
            for field_id, field in field_map.items()
        }
        for start in graph:
            seen: set[str] = set()
            current: str | None = start
            while current is not None:
                if current in seen:
                    raise ValueError("conditional field dependencies must be acyclic")
                seen.add(current)
                current = graph.get(current)


class DatasheetSourceReference(CalculationModel):
    """One bounded source used by fields or assumptions."""

    source_id: Identifier
    origin: DatasheetFieldOrigin
    description: LongText
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_SOURCES,
    )
    source_revision: ShortText | None = None
    location: SourceLocator | None = None

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "reference_ids",
            _canonical_text(self.reference_ids, field_name="reference_ids"),
        )

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.origin in {
            DatasheetFieldOrigin.UNKNOWN,
            DatasheetFieldOrigin.CALCULATED,
        }:
            raise ValueError("unknown and calculated values use dedicated trace")
        if not self.reference_ids and self.location is None:
            raise ValueError("a source requires a reference ID or location")
        return self


class DatasheetAssumption(CalculationModel):
    """One explicit, traceable assumption retained in a datasheet revision."""

    assumption_id: Identifier
    statement: LongText
    required_verification: LongText
    source_reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_DATASHEET_SOURCES,
    )
    verification_state: DatasheetAssumptionVerificationState = (
        DatasheetAssumptionVerificationState.UNRESOLVED
    )
    verification_evidence_source_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_SOURCES,
    )
    safety_critical: StrictBool = False

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "source_reference_ids",
            _canonical_text(
                self.source_reference_ids,
                field_name="source_reference_ids",
            ),
        )
        object.__setattr__(
            self,
            "verification_evidence_source_ids",
            _canonical_text(
                self.verification_evidence_source_ids,
                field_name="verification_evidence_source_ids",
            ),
        )

    @model_validator(mode="after")
    def validate_verification(self) -> Self:
        verified = (
            self.verification_state is DatasheetAssumptionVerificationState.VERIFIED
        )
        if verified != bool(self.verification_evidence_source_ids):
            raise ValueError(
                "verified assumptions require evidence; unresolved assumptions "
                "must not claim evidence"
            )
        return self


class DatasheetCalculationLink(CalculationModel):
    """Bounded historical reference to one Step 108 calculation output.

    Stateless Step 109 callers create only unverified links.  Step 110 may set
    ``repository_provenance_verified`` only after its persistence service has
    rebuilt and compared every field against the append-only calculation run.
    A supplied flag never establishes trust: the persistence boundary ignores
    it and independently reconstructs the complete link from stored evidence.
    """

    link_id: Identifier
    run_id: UUID
    run_fingerprint: FingerprintText
    result_fingerprint: FingerprintText
    design_case_id: UUID
    design_revision_id: UUID
    design_revision_number: StrictInt = Field(ge=1, le=1_000_000)
    design_revision_fingerprint: FingerprintText
    calculation_type: Identifier
    method_id: Identifier
    method_version: VersionText
    result_status: CalculationStatus
    output: CalculationOutput
    repository_provenance_verified: StrictBool = False
    source_record_embedded: Literal[False] = False
    historical_link_rewritten: Literal[False] = False

    @classmethod
    def from_engineering_run(
        cls,
        *,
        link_id: str,
        run: EngineeringRunRecord,
        output_id: str,
    ) -> DatasheetCalculationLink:
        """Copy structural run evidence without claiming repository proof."""

        structural_record = EngineeringRunRecord.model_validate(
            run.model_dump(mode="python", round_trip=True)
        )
        if not isinstance(structural_record.payload, CalculationRunPayload):
            raise ValueError("datasheet calculated fields require a calculation run")
        if structural_record.execution_metadata.status not in {
            CalculationStatus.COMPLETED,
            CalculationStatus.COMPLETED_WITH_WARNINGS,
        }:
            raise ValueError("only completed calculation outputs may be linked")
        design_values = (
            structural_record.design_case_id,
            structural_record.design_revision_id,
            structural_record.design_revision_number,
            structural_record.design_revision_fingerprint,
        )
        if any(value is None for value in design_values):
            raise ValueError("a datasheet calculation link requires design linkage")
        matches = tuple(
            output
            for output in structural_record.payload.result.outputs
            if output.output_id == output_id
        )
        if len(matches) != 1:
            raise ValueError("the calculation output ID must resolve exactly once")
        return cls(
            link_id=link_id,
            run_id=structural_record.run_id,
            run_fingerprint=structural_record.run_fingerprint,
            result_fingerprint=structural_record.result_fingerprint,
            design_case_id=structural_record.design_case_id,
            design_revision_id=structural_record.design_revision_id,
            design_revision_number=structural_record.design_revision_number,
            design_revision_fingerprint=(structural_record.design_revision_fingerprint),
            calculation_type=structural_record.execution_metadata.calculation_type,
            method_id=structural_record.execution_metadata.method_id,
            method_version=structural_record.execution_metadata.method_version,
            result_status=structural_record.execution_metadata.status,
            output=matches[0],
            repository_provenance_verified=False,
        )

    @classmethod
    def _from_repository_run(
        cls,
        *,
        link_id: str,
        run: EngineeringRunRecord,
        output_id: str,
    ) -> DatasheetCalculationLink:
        """Build server-owned evidence after the caller reaches persistence."""

        structural = cls.from_engineering_run(
            link_id=link_id,
            run=run,
            output_id=output_id,
        )
        return structural.model_copy(update={"repository_provenance_verified": True})

    @model_validator(mode="after")
    def validate_link(self) -> Self:
        if self.result_status not in {
            CalculationStatus.COMPLETED,
            CalculationStatus.COMPLETED_WITH_WARNINGS,
        }:
            raise ValueError("only completed calculation outputs may be linked")
        if (self.output.quantity is None) == (self.output.categorical_value is None):
            raise ValueError("a calculation link requires exactly one output value")
        return self


class DatasheetFieldValue(CalculationModel):
    """One explicit datasheet field value with origin and trace metadata."""

    field_id: Identifier
    state: DatasheetFieldState
    origin: DatasheetFieldOrigin
    value: DatasheetValue | None = None
    source_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_SOURCES,
    )
    assumption_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_ASSUMPTIONS,
    )
    calculation_link_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=1,
    )
    unknown_reason: UnknownReason | None = None

    def model_post_init(self, __context: object) -> None:
        for field_name in (
            "source_reference_ids",
            "assumption_ids",
            "calculation_link_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_text(getattr(self, field_name), field_name=field_name),
            )

    @model_validator(mode="after")
    def validate_value_state(self) -> Self:
        if self.state is DatasheetFieldState.KNOWN:
            if self.value is None or self.origin is DatasheetFieldOrigin.UNKNOWN:
                raise ValueError("known fields require a non-unknown value and origin")
            if self.unknown_reason is not None:
                raise ValueError("known fields cannot declare an unknown reason")
            if self.origin is DatasheetFieldOrigin.CALCULATED:
                if len(self.calculation_link_ids) != 1:
                    raise ValueError("calculated fields require one calculation link")
                if self.source_reference_ids or self.assumption_ids:
                    raise ValueError(
                        "calculated fields use their calculation link as trace"
                    )
            else:
                if self.calculation_link_ids:
                    raise ValueError(
                        "non-calculated fields cannot carry calculation links"
                    )
                if not self.source_reference_ids:
                    raise ValueError("known non-calculated fields require source trace")
                if self.origin is DatasheetFieldOrigin.DEFAULTED:
                    if not self.assumption_ids:
                        raise ValueError("defaulted fields require an assumption")
                elif self.assumption_ids:
                    raise ValueError("only defaulted known fields use assumptions")
        else:
            if (
                self.value is not None
                or self.origin is not DatasheetFieldOrigin.UNKNOWN
            ):
                raise ValueError(
                    "unknown or inapplicable fields cannot contain a value"
                )
            if self.unknown_reason is None:
                raise ValueError("unknown or inapplicable fields require a reason")
            if self.calculation_link_ids:
                raise ValueError("unknown fields cannot claim a calculation result")
            if self.state is DatasheetFieldState.NOT_APPLICABLE and self.assumption_ids:
                raise ValueError("inapplicable fields cannot depend on assumptions")
        return self


class DatasheetContent(CalculationModel):
    """Complete immutable content snapshot for one datasheet revision."""

    schema_id: Literal["engineer4me.datasheet.content.v1"] = DATASHEET_CONTENT_SCHEMA
    schema_version: Literal["1.0.0"] = DATASHEET_MODEL_VERSION
    datasheet_id: UUID
    design_case_id: UUID
    design_revision_id: UUID
    design_revision_number: StrictInt = Field(ge=1, le=1_000_000)
    design_revision_fingerprint: FingerprintText
    template_id: Identifier
    template_version: VersionText
    template_fingerprint: FingerprintText
    title: ShortText
    lifecycle_state: DatasheetLifecycleState = DatasheetLifecycleState.DRAFT
    field_values: tuple[DatasheetFieldValue, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    source_references: tuple[DatasheetSourceReference, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_SOURCES,
    )
    assumptions: tuple[DatasheetAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_ASSUMPTIONS,
    )
    calculation_links: tuple[DatasheetCalculationLink, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_CALCULATION_LINKS,
    )
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    def model_post_init(self, __context: object) -> None:
        for field_name, attribute in (
            ("field_values", "field_id"),
            ("source_references", "source_id"),
            ("assumptions", "assumption_id"),
            ("calculation_links", "link_id"),
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_models(getattr(self, field_name), attribute=attribute),
            )

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        sources = {item.source_id: item for item in self.source_references}
        assumptions = {item.assumption_id: item for item in self.assumptions}
        links = {item.link_id: item for item in self.calculation_links}
        used_assumptions: set[str] = set()
        used_links: set[str] = set()
        for assumption in self.assumptions:
            if not set(assumption.source_reference_ids).issubset(sources):
                raise ValueError("assumption links an unknown source reference")
            if not set(assumption.verification_evidence_source_ids).issubset(sources):
                raise ValueError("assumption evidence links an unknown source")
        for field in self.field_values:
            if not set(field.source_reference_ids).issubset(sources):
                raise ValueError("field links an unknown source reference")
            if not set(field.assumption_ids).issubset(assumptions):
                raise ValueError("field links an unknown assumption")
            if not set(field.calculation_link_ids).issubset(links):
                raise ValueError("field links an unknown calculation")
            used_assumptions.update(field.assumption_ids)
            used_links.update(field.calculation_link_ids)
            if field.state is not DatasheetFieldState.KNOWN:
                continue
            if field.origin is DatasheetFieldOrigin.CALCULATED:
                link = links[field.calculation_link_ids[0]]
                if (
                    link.design_case_id != self.design_case_id
                    or link.design_revision_id != self.design_revision_id
                    or link.design_revision_number != self.design_revision_number
                    or link.design_revision_fingerprint
                    != self.design_revision_fingerprint
                ):
                    raise ValueError(
                        "calculation link belongs to another design revision"
                    )
                expected_value = (
                    link.output.quantity
                    if link.output.quantity is not None
                    else link.output.categorical_value
                )
                if field.value != expected_value:
                    raise ValueError("calculated field value drifted from its output")
            else:
                source_origins = {
                    sources[source_id].origin.value
                    for source_id in field.source_reference_ids
                }
                if field.origin.value not in source_origins:
                    raise ValueError("field origin is not supported by its sources")
        if used_assumptions != set(assumptions):
            raise ValueError("every assumption must be linked to a field")
        if used_links != set(links):
            raise ValueError("every calculation link must be linked to a field")
        return self


def fingerprint_datasheet_content(content: DatasheetContent) -> str:
    """Return the deterministic hash of one complete datasheet snapshot."""

    return fingerprint_persistence_payload(
        {
            "schema": DATASHEET_CONTENT_SCHEMA,
            "content": content.model_dump(
                mode="json",
                round_trip=True,
                warnings="error",
            ),
            "canonicalization": DATASHEET_CANONICALIZATION,
        }
    )


class DatasheetFieldAssessment(CalculationModel):
    """One derived, countable field-completeness outcome."""

    field_id: Identifier
    requirement: DatasheetFieldRequirement
    required_now: StrictBool | None
    disposition: DatasheetFieldDisposition
    blocking: StrictBool
    message: LongText


def validate_datasheet_field_value(
    definition: DatasheetFieldDefinition,
    value: DatasheetFieldValue,
) -> None:
    """Validate one known value against its exact controlled definition."""

    if value.state is not DatasheetFieldState.KNOWN:
        return
    if value.origin not in definition.allowed_origins:
        raise ValueError(
            f"field {definition.field_id} uses an origin forbidden by the template"
        )
    candidate = value.value
    if definition.value_kind is DatasheetValueKind.QUANTITY:
        if not isinstance(candidate, EngineeringQuantity):
            raise ValueError(
                f"field {definition.field_id} requires an engineering quantity"
            )
        if candidate.quantity_kind != definition.quantity_kind:
            raise ValueError(
                f"field {definition.field_id} uses the wrong quantity kind"
            )
        try:
            expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(
                definition.quantity_kind
            )
            actual_unit = DEFAULT_UNIT_REGISTRY.resolve_unit(candidate.unit)
        except UnitSystemError as exc:
            raise ValueError(
                f"field {definition.field_id} has unsupported unit metadata"
            ) from exc
        if actual_unit.dimension is not expected_dimension:
            raise ValueError(
                f"field {definition.field_id} uses an incompatible engineering unit"
            )
        if definition.positive_value_required and candidate.value <= 0:
            raise ValueError(f"field {definition.field_id} must be positive")
        return
    if isinstance(candidate, EngineeringQuantity):
        raise ValueError(
            f"field {definition.field_id} does not accept an engineering quantity"
        )
    if definition.value_kind is DatasheetValueKind.BOOLEAN:
        valid = type(candidate) is bool
    elif definition.value_kind is DatasheetValueKind.NUMBER:
        try:
            valid = type(candidate) in {int, float} and isfinite(
                float(candidate)
            )
        except (OverflowError, TypeError, ValueError):
            valid = False
    elif definition.value_kind in {
        DatasheetValueKind.TEXT,
        DatasheetValueKind.IDENTIFIER,
        DatasheetValueKind.ENUM,
    }:
        valid = type(candidate) is str and bool(candidate.strip())
    else:
        valid = False
    if not valid:
        raise ValueError(f"field {definition.field_id} value kind is invalid")
    if definition.value_kind is DatasheetValueKind.IDENTIFIER and not (
        isinstance(candidate, str) and _IDENTIFIER_PATTERN.fullmatch(candidate)
    ):
        raise ValueError(f"field {definition.field_id} identifier format is invalid")
    if (
        definition.value_kind is DatasheetValueKind.ENUM
        and candidate not in definition.allowed_values
    ):
        raise ValueError(
            f"field {definition.field_id} value is outside the controlled choices"
        )
    if isinstance(candidate, str) and len(candidate) > 4_000:
        raise ValueError(
            f"field {definition.field_id} text exceeds the supported length"
        )
    if definition.positive_value_required:
        try:
            normalized_candidate = float(candidate)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError(
                f"field {definition.field_id} value kind is invalid"
            ) from exc
        if normalized_candidate <= 0:
            raise ValueError(f"field {definition.field_id} must be positive")


def evaluate_datasheet_condition(
    *,
    definition: DatasheetFieldDefinition,
    all_values: dict[str, DatasheetFieldValue],
    all_definitions: dict[str, DatasheetFieldDefinition],
    evaluating: frozenset[str] = frozenset(),
) -> bool | None:
    """Evaluate one acyclic condition using explicit three-valued logic."""

    if definition.condition is None:
        raise ValueError("a datasheet condition is required for evaluation")
    if definition.field_id in evaluating:
        raise ValueError("conditional dependency cycle reached the evaluator")
    dependency_id = definition.condition.depends_on_field_id
    dependency = all_values.get(dependency_id)
    dependency_definition = all_definitions.get(dependency_id)
    if dependency_definition is None:
        raise ValueError("conditional dependency is absent from the template")
    if dependency_definition.condition is not None:
        dependency_applicable = evaluate_datasheet_condition(
            definition=dependency_definition,
            all_values=all_values,
            all_definitions=all_definitions,
            evaluating=evaluating | {definition.field_id},
        )
        if dependency_applicable is not True:
            return dependency_applicable
    if dependency is None or dependency.state is DatasheetFieldState.UNKNOWN:
        return None
    if dependency.state is DatasheetFieldState.NOT_APPLICABLE:
        return False
    candidate = dependency.value
    expected = definition.condition.expected_values
    if definition.condition.operator is DatasheetConditionOperator.EQUALS:
        return candidate == expected[0]
    if definition.condition.operator is DatasheetConditionOperator.NOT_EQUALS:
        return candidate != expected[0]
    return candidate in expected


def derive_datasheet_field_assessment(
    *,
    definition: DatasheetFieldDefinition,
    value: DatasheetFieldValue,
    all_values: dict[str, DatasheetFieldValue],
    all_definitions: dict[str, DatasheetFieldDefinition],
) -> DatasheetFieldAssessment:
    """Derive the only valid assessment for one template/content field pair."""

    known = value.state is DatasheetFieldState.KNOWN
    confirmed = known and (
        definition.required_boolean_value is None
        or value.value is definition.required_boolean_value
    )
    calculated_unverified = known and (value.origin is DatasheetFieldOrigin.CALCULATED)

    def required_assessment(*, conditional: bool) -> DatasheetFieldAssessment:
        if confirmed:
            disposition = DatasheetFieldDisposition.SATISFIED
            blocking = calculated_unverified
            message = (
                "Active conditional field is known and traceable."
                if conditional
                else "Required field is known and traceable."
            )
        elif known:
            disposition = DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
            blocking = definition.safety_critical or calculated_unverified
            message = (
                "Active value does not match its confirmation rule."
                if conditional
                else "Required value does not match its confirmation rule."
            )
        else:
            disposition = DatasheetFieldDisposition.REQUIRED_UNKNOWN
            blocking = definition.safety_critical or calculated_unverified
            message = (
                "Active conditional field remains explicitly unknown."
                if conditional
                else "Required field remains explicitly unknown."
            )
        return DatasheetFieldAssessment(
            field_id=definition.field_id,
            requirement=definition.requirement,
            required_now=True,
            disposition=disposition,
            blocking=blocking,
            message=message,
        )

    if definition.requirement is DatasheetFieldRequirement.REQUIRED:
        return required_assessment(conditional=False)
    if definition.requirement is DatasheetFieldRequirement.OPTIONAL:
        if known:
            disposition = DatasheetFieldDisposition.SATISFIED
            blocking = calculated_unverified
            message = "Optional field is known and traceable."
        else:
            disposition = DatasheetFieldDisposition.OPTIONAL_UNKNOWN
            blocking = definition.safety_critical or calculated_unverified
            message = "Optional field remains visibly open."
        return DatasheetFieldAssessment(
            field_id=definition.field_id,
            requirement=definition.requirement,
            required_now=False,
            disposition=disposition,
            blocking=blocking,
            message=message,
        )
    condition_result = evaluate_datasheet_condition(
        definition=definition,
        all_values=all_values,
        all_definitions=all_definitions,
    )
    if condition_result is None:
        return DatasheetFieldAssessment(
            field_id=definition.field_id,
            requirement=definition.requirement,
            required_now=None,
            disposition=DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED,
            blocking=definition.safety_critical,
            message="Conditional requirement cannot be resolved safely.",
        )
    if condition_result:
        return required_assessment(conditional=True)
    if value.state is DatasheetFieldState.NOT_APPLICABLE:
        disposition = DatasheetFieldDisposition.CONDITIONAL_NOT_APPLICABLE
        message = "Inactive conditional field is explicitly not applicable."
    elif known:
        disposition = DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED
        message = "Conditional field has a value although its rule is inactive."
    else:
        disposition = DatasheetFieldDisposition.OPTIONAL_UNKNOWN
        message = "Inactive conditional field should be marked not applicable."
    return DatasheetFieldAssessment(
        field_id=definition.field_id,
        requirement=definition.requirement,
        required_now=False,
        disposition=disposition,
        blocking=calculated_unverified,
        message=message,
    )


def derive_blocking_assumption_ids(
    *,
    template: DatasheetTemplateDefinition,
    content: DatasheetContent,
    assessments: tuple[DatasheetFieldAssessment, ...],
) -> tuple[str, ...]:
    """Derive blockers from caller flags and active safety-critical defaults."""

    unresolved = {
        item.assumption_id
        for item in content.assumptions
        if item.verification_state is DatasheetAssumptionVerificationState.UNRESOLVED
    }
    blocking = {
        item.assumption_id
        for item in content.assumptions
        if item.assumption_id in unresolved and item.safety_critical
    }
    values = {item.field_id: item for item in content.field_values}
    assessment_map = {item.field_id: item for item in assessments}
    for definition in template.fields:
        assessment = assessment_map[definition.field_id]
        value = values[definition.field_id]
        if (
            definition.safety_critical
            and assessment.required_now is True
            and value.state is DatasheetFieldState.KNOWN
            and value.origin is DatasheetFieldOrigin.DEFAULTED
        ):
            blocking.update(set(value.assumption_ids) & unresolved)
    return _canonical_text(tuple(blocking), field_name="blocking_assumption_ids")


def build_datasheet_completeness_fingerprint(
    *,
    template_id: str,
    template_version: str,
    template_fingerprint: str,
    content_fingerprint: str,
    state: DatasheetCompletenessState,
    assessments: tuple[DatasheetFieldAssessment, ...],
    missing_required_field_ids: tuple[str, ...],
    unknown_required_field_ids: tuple[str, ...],
    unconfirmed_required_field_ids: tuple[str, ...],
    unverified_calculation_field_ids: tuple[str, ...],
    unresolved_conditional_field_ids: tuple[str, ...],
    optional_open_field_ids: tuple[str, ...],
    not_applicable_field_ids: tuple[str, ...],
    unresolved_assumption_ids: tuple[str, ...],
    blocking_assumption_ids: tuple[str, ...],
    ready_for_review: bool,
) -> str:
    """Fingerprint the derived completeness outcome."""

    assessments = _canonical_models(assessments, attribute="field_id")
    missing_required_field_ids = _canonical_text(
        missing_required_field_ids,
        field_name="missing_required_field_ids",
    )
    unknown_required_field_ids = _canonical_text(
        unknown_required_field_ids,
        field_name="unknown_required_field_ids",
    )
    unconfirmed_required_field_ids = _canonical_text(
        unconfirmed_required_field_ids,
        field_name="unconfirmed_required_field_ids",
    )
    unresolved_conditional_field_ids = _canonical_text(
        unresolved_conditional_field_ids,
        field_name="unresolved_conditional_field_ids",
    )
    optional_open_field_ids = _canonical_text(
        optional_open_field_ids,
        field_name="optional_open_field_ids",
    )
    not_applicable_field_ids = _canonical_text(
        not_applicable_field_ids,
        field_name="not_applicable_field_ids",
    )
    unresolved_assumption_ids = _canonical_text(
        unresolved_assumption_ids,
        field_name="unresolved_assumption_ids",
    )
    blocking_assumption_ids = _canonical_text(
        blocking_assumption_ids,
        field_name="blocking_assumption_ids",
    )
    return fingerprint_persistence_payload(
        {
            "schema": DATASHEET_COMPLETENESS_SCHEMA,
            "schema_version": DATASHEET_MODEL_VERSION,
            "template_id": template_id,
            "template_version": template_version,
            "template_fingerprint": template_fingerprint,
            "content_fingerprint": content_fingerprint,
            "state": state.value,
            "assessments": [
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in assessments
            ],
            "missing_required_field_ids": missing_required_field_ids,
            "unknown_required_field_ids": unknown_required_field_ids,
            "unconfirmed_required_field_ids": unconfirmed_required_field_ids,
            "unverified_calculation_field_ids": _canonical_text(
                unverified_calculation_field_ids,
                field_name="unverified_calculation_field_ids",
            ),
            "unresolved_conditional_field_ids": (unresolved_conditional_field_ids),
            "optional_open_field_ids": optional_open_field_ids,
            "not_applicable_field_ids": not_applicable_field_ids,
            "unresolved_assumption_ids": unresolved_assumption_ids,
            "blocking_assumption_ids": blocking_assumption_ids,
            "ready_for_review": ready_for_review,
            "approval_state": DesignApprovalState.UNAPPROVED.value,
            "final_design_approval_granted": False,
        }
    )


class DatasheetCompletenessReport(CalculationModel):
    """Derived completeness report that cannot imply engineering approval."""

    schema_id: Literal["engineer4me.datasheet.completeness.v1"] = (
        DATASHEET_COMPLETENESS_SCHEMA
    )
    schema_version: Literal["1.0.0"] = DATASHEET_MODEL_VERSION
    template_id: Identifier
    template_version: VersionText
    template_fingerprint: FingerprintText
    content_fingerprint: FingerprintText
    completeness_fingerprint: FingerprintText
    state: DatasheetCompletenessState
    assessments: tuple[DatasheetFieldAssessment, ...] = Field(
        min_length=1,
        max_length=MAX_DATASHEET_FIELDS,
    )
    missing_required_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    unknown_required_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    unconfirmed_required_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    unverified_calculation_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    unresolved_conditional_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    optional_open_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    not_applicable_field_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_FIELDS,
    )
    unresolved_assumption_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_ASSUMPTIONS,
    )
    blocking_assumption_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_ASSUMPTIONS,
    )
    ready_for_review: StrictBool
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "assessments",
            _canonical_models(self.assessments, attribute="field_id"),
        )
        for field_name in (
            "missing_required_field_ids",
            "unknown_required_field_ids",
            "unconfirmed_required_field_ids",
            "unverified_calculation_field_ids",
            "unresolved_conditional_field_ids",
            "optional_open_field_ids",
            "not_applicable_field_ids",
            "unresolved_assumption_ids",
            "blocking_assumption_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_text(getattr(self, field_name), field_name=field_name),
            )

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        assessments = {item.field_id: item for item in self.assessments}
        expected_missing = {
            item.field_id
            for item in self.assessments
            if item.disposition is DatasheetFieldDisposition.REQUIRED_MISSING
        }
        expected_unknown = {
            item.field_id
            for item in self.assessments
            if item.disposition is DatasheetFieldDisposition.REQUIRED_UNKNOWN
        }
        expected_unconfirmed = {
            item.field_id
            for item in self.assessments
            if item.disposition
            is DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
        }
        expected_unresolved = {
            item.field_id
            for item in self.assessments
            if item.disposition is DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED
        }
        expected_optional = {
            item.field_id
            for item in self.assessments
            if item.disposition
            in {
                DatasheetFieldDisposition.OPTIONAL_MISSING,
                DatasheetFieldDisposition.OPTIONAL_UNKNOWN,
                DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED,
            }
        }
        expected_na = {
            item.field_id
            for item in self.assessments
            if item.disposition is DatasheetFieldDisposition.CONDITIONAL_NOT_APPLICABLE
        }
        for actual, expected, name in (
            (self.missing_required_field_ids, expected_missing, "missing"),
            (self.unknown_required_field_ids, expected_unknown, "unknown"),
            (
                self.unconfirmed_required_field_ids,
                expected_unconfirmed,
                "unconfirmed",
            ),
            (
                self.unresolved_conditional_field_ids,
                expected_unresolved,
                "conditional",
            ),
            (self.optional_open_field_ids, expected_optional, "optional"),
            (self.not_applicable_field_ids, expected_na, "not applicable"),
        ):
            if set(actual) != expected:
                raise ValueError(f"{name} completeness IDs are inconsistent")
        if not set(self.blocking_assumption_ids).issubset(
            self.unresolved_assumption_ids
        ):
            raise ValueError("blocking assumptions must remain unresolved")
        if not set(self.unverified_calculation_field_ids).issubset(assessments):
            raise ValueError("unverified calculation fields must have assessments")
        blockers = (
            any(item.blocking for item in assessments.values())
            or bool(self.blocking_assumption_ids)
            or bool(self.unverified_calculation_field_ids)
        )
        incomplete = bool(
            expected_missing
            | expected_unknown
            | expected_unconfirmed
            | expected_unresolved
        )
        open_items = bool(expected_optional | set(self.unresolved_assumption_ids))
        expected_state = (
            DatasheetCompletenessState.BLOCKED
            if blockers
            else DatasheetCompletenessState.INCOMPLETE
            if incomplete
            else DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS
            if open_items
            else DatasheetCompletenessState.COMPLETE
        )
        if self.state is not expected_state:
            raise ValueError("completeness state is inconsistent")
        if self.ready_for_review != (
            expected_state
            in {
                DatasheetCompletenessState.COMPLETE,
                DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS,
            }
        ):
            raise ValueError("ready_for_review is inconsistent")
        expected_fingerprint = build_datasheet_completeness_fingerprint(
            template_id=self.template_id,
            template_version=self.template_version,
            template_fingerprint=self.template_fingerprint,
            content_fingerprint=self.content_fingerprint,
            state=self.state,
            assessments=self.assessments,
            missing_required_field_ids=self.missing_required_field_ids,
            unknown_required_field_ids=self.unknown_required_field_ids,
            unconfirmed_required_field_ids=(self.unconfirmed_required_field_ids),
            unverified_calculation_field_ids=(self.unverified_calculation_field_ids),
            unresolved_conditional_field_ids=(self.unresolved_conditional_field_ids),
            optional_open_field_ids=self.optional_open_field_ids,
            not_applicable_field_ids=self.not_applicable_field_ids,
            unresolved_assumption_ids=self.unresolved_assumption_ids,
            blocking_assumption_ids=self.blocking_assumption_ids,
            ready_for_review=self.ready_for_review,
        )
        if self.completeness_fingerprint != expected_fingerprint:
            raise ValueError("completeness_fingerprint is stale")
        return self


class DatasheetRevisionSnapshot(CalculationModel):
    """One complete content and derived-completeness pair."""

    template: DatasheetTemplateDefinition
    content: DatasheetContent
    completeness: DatasheetCompletenessReport

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if (
            self.template.template_id != self.content.template_id
            or self.template.template_version != self.content.template_version
            or self.template.template_fingerprint != self.content.template_fingerprint
            or self.completeness.template_id != self.content.template_id
            or self.completeness.template_version != self.content.template_version
            or self.completeness.template_fingerprint
            != self.content.template_fingerprint
        ):
            raise ValueError("completeness report template identity drifted")
        if self.completeness.content_fingerprint != fingerprint_datasheet_content(
            self.content
        ):
            raise ValueError("completeness report content fingerprint drifted")
        template_fields = {item.field_id: item for item in self.template.fields}
        content_fields = {item.field_id: item for item in self.content.field_values}
        assessments = {item.field_id: item for item in self.completeness.assessments}
        if set(content_fields) != set(template_fields):
            raise ValueError("datasheet snapshot does not contain every template field")
        if set(assessments) != set(template_fields):
            raise ValueError("completeness assessments do not cover the template")
        for field_id, assessment in assessments.items():
            definition = template_fields[field_id]
            value = content_fields[field_id]
            validate_datasheet_field_value(definition, value)
            expected_assessment = derive_datasheet_field_assessment(
                definition=definition,
                value=value,
                all_values=content_fields,
                all_definitions=template_fields,
            )
            if assessment != expected_assessment:
                raise ValueError(
                    "assessment drifted from deterministic template evaluation"
                )
        expected_unresolved = {
            item.assumption_id
            for item in self.content.assumptions
            if item.verification_state
            is DatasheetAssumptionVerificationState.UNRESOLVED
        }
        expected_blocking = set(
            derive_blocking_assumption_ids(
                template=self.template,
                content=self.content,
                assessments=self.completeness.assessments,
            )
        )
        if set(self.completeness.unresolved_assumption_ids) != expected_unresolved:
            raise ValueError("unresolved assumptions drifted from datasheet content")
        if set(self.completeness.blocking_assumption_ids) != expected_blocking:
            raise ValueError("blocking assumptions drifted from datasheet content")
        calculation_links = {
            item.link_id: item for item in self.content.calculation_links
        }
        expected_unverified_calculations = {
            item.field_id
            for item in self.content.field_values
            if item.state is DatasheetFieldState.KNOWN
            and item.origin is DatasheetFieldOrigin.CALCULATED
            and not calculation_links[
                item.calculation_link_ids[0]
            ].repository_provenance_verified
        }
        if (
            set(self.completeness.unverified_calculation_field_ids)
            != expected_unverified_calculations
        ):
            raise ValueError(
                "unverified calculation fields drifted from datasheet content"
            )
        return self


class DatasheetCreateCommand(CalculationModel):
    """Create the first immutable revision of one datasheet identity."""

    content: DatasheetContent
    change_reason: TextItem
    created_by: ShortText
    creator_origin: Literal[RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED] = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )


class DatasheetRevisionCreate(CalculationModel):
    """Append a complete replacement snapshot using optimistic concurrency."""

    expected_current_revision: StrictInt = Field(ge=1, le=MAX_DATASHEET_REVISIONS)
    expected_current_fingerprint: FingerprintText
    content: DatasheetContent
    change_reason: TextItem
    created_by: ShortText
    creator_origin: Literal[RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED] = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )


def build_datasheet_revision_fingerprint(
    *,
    revision_id: UUID,
    datasheet_id: UUID,
    revision_number: int,
    supersedes_revision_id: UUID | None,
    supersedes_revision_fingerprint: str | None,
    snapshot: DatasheetRevisionSnapshot,
    change_reason: str,
    created_by: str,
    creator_origin: RecordedIdentityOrigin,
    created_at: datetime,
) -> str:
    """Fingerprint every immutable datasheet revision field."""

    return fingerprint_persistence_payload(
        {
            "schema": DATASHEET_REVISION_SCHEMA,
            "schema_version": DATASHEET_MODEL_VERSION,
            "revision_id": str(revision_id),
            "datasheet_id": str(datasheet_id),
            "revision_number": revision_number,
            "supersedes_revision_id": (
                str(supersedes_revision_id)
                if supersedes_revision_id is not None
                else None
            ),
            "supersedes_revision_fingerprint": supersedes_revision_fingerprint,
            "snapshot": snapshot.model_dump(
                mode="json",
                round_trip=True,
                warnings="error",
            ),
            "change_reason": change_reason,
            "created_by": created_by,
            "creator_origin": creator_origin.value,
            "created_at": canonical_utc_text(created_at),
            "canonicalization": DATASHEET_CANONICALIZATION,
        }
    )


class DatasheetRevisionRecord(CalculationModel):
    """One immutable, fingerprinted, complete datasheet revision."""

    revision_id: UUID
    datasheet_id: UUID
    revision_number: StrictInt = Field(ge=1, le=MAX_DATASHEET_REVISIONS)
    supersedes_revision_id: UUID | None = None
    supersedes_revision_fingerprint: FingerprintText | None = None
    snapshot: DatasheetRevisionSnapshot
    revision_fingerprint: FingerprintText
    change_reason: TextItem
    created_by: ShortText
    creator_origin: Literal[RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED] = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )
    created_at: AwareDatetime
    append_only: Literal[True] = True
    deletion_supported: Literal[False] = False
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False

    @classmethod
    def create(
        cls,
        *,
        revision_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
        supersedes_revision_id: UUID | None,
        supersedes_revision_fingerprint: str | None,
        snapshot: DatasheetRevisionSnapshot,
        change_reason: str,
        created_by: str,
        creator_origin: RecordedIdentityOrigin,
        created_at: datetime,
    ) -> DatasheetRevisionRecord:
        fingerprint = build_datasheet_revision_fingerprint(
            revision_id=revision_id,
            datasheet_id=datasheet_id,
            revision_number=revision_number,
            supersedes_revision_id=supersedes_revision_id,
            supersedes_revision_fingerprint=supersedes_revision_fingerprint,
            snapshot=snapshot,
            change_reason=change_reason,
            created_by=created_by,
            creator_origin=creator_origin,
            created_at=created_at,
        )
        return cls(
            revision_id=revision_id,
            datasheet_id=datasheet_id,
            revision_number=revision_number,
            supersedes_revision_id=supersedes_revision_id,
            supersedes_revision_fingerprint=supersedes_revision_fingerprint,
            snapshot=snapshot,
            revision_fingerprint=fingerprint,
            change_reason=change_reason,
            created_by=created_by,
            creator_origin=creator_origin,
            created_at=created_at,
        )

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        predecessor = (
            self.supersedes_revision_id,
            self.supersedes_revision_fingerprint,
        )
        if any(value is None for value in predecessor) and any(
            value is not None for value in predecessor
        ):
            raise ValueError("revision predecessor linkage must be complete")
        if (self.revision_number == 1) is not all(
            value is None for value in predecessor
        ):
            raise ValueError("only revision one may omit a predecessor")
        if self.snapshot.content.datasheet_id != self.datasheet_id:
            raise ValueError("revision snapshot belongs to another datasheet")
        normalized = normalise_utc(self.created_at)
        expected = build_datasheet_revision_fingerprint(
            revision_id=self.revision_id,
            datasheet_id=self.datasheet_id,
            revision_number=self.revision_number,
            supersedes_revision_id=self.supersedes_revision_id,
            supersedes_revision_fingerprint=self.supersedes_revision_fingerprint,
            snapshot=self.snapshot,
            change_reason=self.change_reason,
            created_by=self.created_by,
            creator_origin=self.creator_origin,
            created_at=normalized,
        )
        if self.revision_fingerprint != expected:
            raise ValueError("revision_fingerprint is stale")
        object.__setattr__(self, "created_at", normalized)
        return self


class DatasheetHistory(CalculationModel):
    """Dense append-only revision history for one stable datasheet identity."""

    datasheet_id: UUID
    design_case_id: UUID
    template_id: Identifier
    template_version: VersionText
    template_fingerprint: FingerprintText
    current_revision: StrictInt = Field(ge=1, le=MAX_DATASHEET_REVISIONS)
    current_revision_fingerprint: FingerprintText
    revisions: tuple[DatasheetRevisionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_DATASHEET_REVISIONS,
    )
    append_only: Literal[True] = True
    deletion_supported: Literal[False] = False
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_history(self) -> Self:
        revision_ids = tuple(item.revision_id for item in self.revisions)
        if len(revision_ids) != len(set(revision_ids)):
            raise ValueError("datasheet revision IDs must be unique")
        revision_fingerprints = tuple(
            item.revision_fingerprint for item in self.revisions
        )
        if len(revision_fingerprints) != len(set(revision_fingerprints)):
            raise ValueError("datasheet revision fingerprints must be unique")
        expected_number = 1
        predecessor: DatasheetRevisionRecord | None = None
        previous_design_revision = 0
        design_revision_by_number: dict[int, tuple[UUID, str]] = {}
        design_revision_by_id: dict[UUID, tuple[int, str]] = {}
        design_revision_by_fingerprint: dict[str, tuple[int, UUID]] = {}
        previous_time: datetime | None = None
        for revision in self.revisions:
            content = revision.snapshot.content
            if revision.datasheet_id != self.datasheet_id:
                raise ValueError("history contains another datasheet identity")
            if content.design_case_id != self.design_case_id:
                raise ValueError("history crosses design-case identities")
            if (
                content.template_id != self.template_id
                or content.template_version != self.template_version
                or content.template_fingerprint != self.template_fingerprint
            ):
                raise ValueError("history changes its controlled template")
            if revision.revision_number != expected_number:
                raise ValueError("datasheet revisions must be dense and ordered")
            if content.design_revision_number < previous_design_revision:
                raise ValueError("design revision linkage cannot move backwards")
            identity = (
                content.design_revision_id,
                content.design_revision_fingerprint,
            )
            numbered_identity = design_revision_by_number.setdefault(
                content.design_revision_number,
                identity,
            )
            if numbered_identity != identity:
                raise ValueError("a design revision number changed identity")
            id_identity = design_revision_by_id.setdefault(
                content.design_revision_id,
                (
                    content.design_revision_number,
                    content.design_revision_fingerprint,
                ),
            )
            if id_identity != (
                content.design_revision_number,
                content.design_revision_fingerprint,
            ):
                raise ValueError("a design revision ID was remapped")
            fingerprint_identity = design_revision_by_fingerprint.setdefault(
                content.design_revision_fingerprint,
                (content.design_revision_number, content.design_revision_id),
            )
            if fingerprint_identity != (
                content.design_revision_number,
                content.design_revision_id,
            ):
                raise ValueError("a design revision fingerprint was remapped")
            if predecessor is not None and (
                revision.supersedes_revision_id != predecessor.revision_id
                or revision.supersedes_revision_fingerprint
                != predecessor.revision_fingerprint
            ):
                raise ValueError("datasheet revision chain is broken")
            if previous_time is not None and revision.created_at < previous_time:
                raise ValueError("datasheet revision timestamps cannot move backwards")
            predecessor = revision
            previous_design_revision = content.design_revision_number
            previous_time = revision.created_at
            expected_number += 1
        head = self.revisions[-1]
        if self.current_revision != head.revision_number:
            raise ValueError("current revision number drifted")
        if self.current_revision_fingerprint != head.revision_fingerprint:
            raise ValueError("current revision fingerprint drifted")
        return self


__all__ = [
    "DATASHEET_CANONICALIZATION",
    "DATASHEET_COMPLETENESS_SCHEMA",
    "DATASHEET_CONTENT_SCHEMA",
    "DATASHEET_MODEL_VERSION",
    "DATASHEET_REVISION_SCHEMA",
    "DATASHEET_TEMPLATE_SCHEMA",
    "DatasheetAssumption",
    "DatasheetAssumptionVerificationState",
    "DatasheetCalculationLink",
    "DatasheetCompletenessReport",
    "DatasheetCompletenessState",
    "DatasheetConditionOperator",
    "DatasheetContent",
    "DatasheetCreateCommand",
    "DatasheetFieldAssessment",
    "DatasheetFieldCondition",
    "DatasheetFieldDefinition",
    "DatasheetFieldDisposition",
    "DatasheetFieldOrigin",
    "DatasheetFieldRequirement",
    "DatasheetFieldState",
    "DatasheetFieldValue",
    "DatasheetHistory",
    "DatasheetLifecycleState",
    "DatasheetRevisionCreate",
    "DatasheetRevisionRecord",
    "DatasheetRevisionSnapshot",
    "DatasheetSectionDefinition",
    "DatasheetSourceReference",
    "DatasheetTemplateDefinition",
    "DatasheetTemplateLifecycleStatus",
    "DatasheetValueKind",
    "build_datasheet_completeness_fingerprint",
    "build_datasheet_revision_fingerprint",
    "build_datasheet_template_fingerprint",
    "fingerprint_datasheet_content",
]
