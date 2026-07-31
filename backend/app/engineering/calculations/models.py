"""Strict shared models for Engineer4Me engineering calculations.

This module defines the Phase 7 calculation data contract. It deliberately
contains no calculation formulas, unit-conversion logic, method registry,
dynamic expression execution, persistence, API code, or voice functionality.

The models are frozen and tuple-backed so a validated request or result cannot
be mutated accidentally after construction. All numerical values are finite,
collection sizes are bounded, identifiers are explicit, and cross-field
validators prevent unsafe result-state combinations.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC
from datetime import datetime
from enum import StrEnum
from math import isfinite
from typing import Annotated
from typing import Any
from typing import Self
from typing import get_origin
from uuid import UUID
from uuid import uuid4

from pydantic import AwareDatetime
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import StrictBool
from pydantic import StrictFloat
from pydantic import StrictInt
from pydantic import StrictStr
from pydantic import StringConstraints
from pydantic import field_validator
from pydantic import model_validator


MAX_ABSOLUTE_OPTION_NUMBER = 1.0e300
MAX_INPUTS = 256
MAX_OPTIONS = 128
MAX_ASSUMPTIONS = 128
MAX_MISSING_INPUTS = 256
MAX_FINDINGS = 256
MAX_TRACE_STEPS = 1_024
MAX_OUTPUTS = 256
MAX_REFERENCES = 256
MAX_VERIFICATION_REQUIREMENTS = 256
MAX_TEXT_ITEMS = 256


Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    ),
]

VersionText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=64,
        pattern=(
            r"^[0-9]+(?:\.[0-9]+){1,3}"
            r"(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?"
            r"(?:\+[A-Za-z0-9][A-Za-z0-9.-]*)?$"
        ),
    ),
]

FingerprintText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9A-Fa-f]{64}$",
    ),
]

UnitSymbol = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=40,
    ),
]

ShortText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=300,
    ),
]

LongText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=4_000,
    ),
]

TextItem = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=1_000,
    ),
]

OptionScalar = StrictBool | StrictInt | StrictFloat | StrictStr
CategoricalValue = StrictBool | StrictStr


class InputOrigin(StrEnum):
    """Origin of an engineering value or assumption."""

    USER_SUPPLIED = "user_supplied"
    DOCUMENT_EXTRACTED = "document_extracted"
    DEFAULTED = "defaulted"
    SYSTEM_DERIVED = "system_derived"
    CALCULATED = "calculated"
    SELECTED = "selected"
    IMPORTED = "imported"


class CalculationStatus(StrEnum):
    """Overall state of a calculation attempt."""

    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    BLOCKED = "blocked"
    INSUFFICIENT_INPUT = "insufficient_input"
    NOT_APPLICABLE = "not_applicable"
    FAILED = "failed"


class MethodLifecycleStatus(StrEnum):
    """Controlled lifecycle state of an executable calculation method."""

    DRAFT = "draft"
    TECHNICAL_REVIEW = "technical_review"
    SAFETY_REVIEW = "safety_review"
    STANDARDS_REVIEW = "standards_review"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    DISABLED = "disabled"


class FindingCategory(StrEnum):
    """Category assigned to a calculation finding."""

    VALIDATION = "validation"
    APPLICABILITY = "applicability"
    SAFETY = "safety"
    DATA_QUALITY = "data_quality"
    STANDARDS = "standards"
    LEGAL_COMPLIANCE = "legal_compliance"
    NUMERICAL = "numerical"
    GENERAL = "general"


class FindingSeverity(StrEnum):
    """Severity assigned to a calculation finding."""

    INFORMATION = "information"
    CAUTION = "caution"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class TraceStepKind(StrEnum):
    """Purpose of one explainable calculation trace step."""

    VALIDATION = "validation"
    NORMALIZATION = "normalization"
    ASSUMPTION = "assumption"
    CALCULATION = "calculation"
    ITERATION = "iteration"
    DECISION = "decision"
    OUTPUT = "output"


class TraceStepStatus(StrEnum):
    """Execution state of one calculation trace step."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class ReferenceType(StrEnum):
    """Supported reference types for calculation traceability."""

    ENGINEERING_KNOWLEDGE = "engineering_knowledge"
    INTERNATIONAL_STANDARD = "international_standard"
    NATIONAL_STANDARD = "national_standard"
    COMPANY_STANDARD = "company_standard"
    REGULATION = "regulation"
    OEM_MANUAL = "oem_manual"
    OEM_DATASHEET = "oem_datasheet"
    ENGINEERING_TEXTBOOK = "engineering_textbook"
    PEER_REVIEWED_PAPER = "peer_reviewed_paper"
    TECHNICAL_REPORT = "technical_report"
    TEST_VECTOR = "test_vector"
    CALCULATION_RECORD = "calculation_record"
    USER_DOCUMENT = "user_document"
    OTHER = "other"


class CalculationModel(BaseModel):
    """Base configuration shared by all calculation-domain models."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
        use_enum_values=False,
        allow_inf_nan=False,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def validate_ordered_collections(
        cls,
        value: Any,
    ) -> Any:
        """Accept JSON-style arrays but reject unordered tuple inputs."""

        if not isinstance(value, Mapping):
            return value

        normalized_value = dict(value)

        for field_name, field_info in cls.model_fields.items():
            if (
                field_name not in normalized_value
                or get_origin(field_info.annotation) is not tuple
            ):
                continue

            collection_value = normalized_value[field_name]

            if isinstance(collection_value, list):
                normalized_value[field_name] = tuple(collection_value)
                continue

            if not isinstance(collection_value, tuple):
                raise ValueError(
                    f"{field_name} must be an ordered list or tuple."
                )

        return normalized_value

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a copy while preserving validation for every update."""

        if not update:
            return super().model_copy(deep=deep)

        copied_value = self.model_dump(
            mode="python",
            round_trip=True,
        )
        copied_value.update(update)

        return type(self).model_validate(copied_value)


def _casefold_identifier(value: str) -> str:
    """Return the comparison form used for identifiers and labels."""

    return value.casefold()


def _require_unique_text(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    """Require non-ambiguous, case-insensitively unique text values."""

    comparison_values = [
        _casefold_identifier(value)
        for value in values
    ]

    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(f"{field_name} values must be unique.")

    return values


def _require_unique_model_values(
    values: tuple[CalculationModel, ...],
    *,
    attribute_name: str,
    field_name: str,
) -> None:
    """Require unique model attributes using case-insensitive comparison."""

    comparison_values = [
        _casefold_identifier(
            str(getattr(value, attribute_name))
        )
        for value in values
    ]

    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(
            f"{field_name} {attribute_name} values must be unique."
        )


def _normalise_utc(value: datetime) -> datetime:
    """Normalize an already-aware timestamp to UTC."""

    return value.astimezone(UTC)


class EngineeringQuantity(CalculationModel):
    """Finite numerical value with an explicit engineering unit."""

    quantity_kind: Identifier
    value: StrictFloat = Field(
        ge=-MAX_ABSOLUTE_OPTION_NUMBER,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    unit: UnitSymbol
    uncertainty: StrictFloat | None = Field(
        default=None,
        ge=0.0,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    uncertainty_basis: LongText | None = None
    significant_figures: StrictInt | None = Field(
        default=None,
        ge=1,
        le=15,
    )
    decimal_places: StrictInt | None = Field(
        default=None,
        ge=0,
        le=15,
    )

    @model_validator(mode="after")
    def validate_presentation_precision(self) -> "EngineeringQuantity":
        """Require one unambiguous presentation-precision rule."""

        if (
            self.significant_figures is not None
            and self.decimal_places is not None
        ):
            raise ValueError(
                "significant_figures and decimal_places cannot both be set."
            )

        if (
            self.uncertainty is not None
            and self.uncertainty_basis is None
        ):
            raise ValueError(
                "An uncertainty value requires uncertainty_basis."
            )

        if (
            self.uncertainty is None
            and self.uncertainty_basis is not None
        ):
            raise ValueError(
                "uncertainty_basis requires an uncertainty value."
            )

        return self


class CalculationInput(CalculationModel):
    """One supplied or normalized calculation input."""

    input_id: Identifier
    name: ShortText
    origin: InputOrigin
    quantity: EngineeringQuantity | None = None
    categorical_value: CategoricalValue | None = None
    assumption_id: Identifier | None = None
    source_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    source_trace_step_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    notes: LongText | None = None

    @field_validator("categorical_value")
    @classmethod
    def validate_categorical_value(
        cls,
        value: bool | str | None,
    ) -> bool | str | None:
        """Reject blank or oversized categorical text."""

        if isinstance(value, str):
            cleaned_value = value.strip()

            if not cleaned_value:
                raise ValueError("Categorical input text cannot be blank.")

            if len(cleaned_value) > 1_000:
                raise ValueError(
                    "Categorical input text cannot exceed 1000 characters."
                )

            return cleaned_value

        return value

    @field_validator(
        "source_reference_ids",
        "source_trace_step_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject ambiguous duplicate input references."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_value_choice(self) -> "CalculationInput":
        """Require exactly one numeric quantity or categorical value."""

        populated_values = sum(
            item is not None
            for item in (self.quantity, self.categorical_value)
        )

        if populated_values != 1:
            raise ValueError(
                "Exactly one of quantity or categorical_value must be "
                "supplied."
            )

        if (
            self.origin
            in {
                InputOrigin.DOCUMENT_EXTRACTED,
                InputOrigin.IMPORTED,
                InputOrigin.SELECTED,
            }
            and not self.source_reference_ids
        ):
            raise ValueError(
                "Document-extracted, imported, and selected inputs require "
                "a source reference."
            )

        if self.origin == InputOrigin.DEFAULTED:
            if self.assumption_id is None:
                raise ValueError(
                    "A defaulted input must link a named assumption."
                )
        elif self.assumption_id is not None:
            raise ValueError(
                "assumption_id is only valid for a defaulted input."
            )

        if (
            self.origin
            in {
                InputOrigin.SYSTEM_DERIVED,
                InputOrigin.CALCULATED,
            }
            and not self.source_trace_step_ids
        ):
            raise ValueError(
                "Derived and calculated inputs require a source trace step."
            )

        return self


class CalculationOption(CalculationModel):
    """Bounded non-dimensional execution option."""

    option_id: Identifier
    value: OptionScalar
    description: ShortText | None = None

    @field_validator("value")
    @classmethod
    def validate_option_value(
        cls,
        value: bool | int | float | str,
    ) -> bool | int | float | str:
        """Reject non-finite, excessive, blank, or oversized option values."""

        if isinstance(value, bool):
            return value

        if isinstance(value, int):
            if abs(value) > MAX_ABSOLUTE_OPTION_NUMBER:
                raise ValueError(
                    "Numeric option magnitude exceeds the supported limit."
                )

            return value

        if isinstance(value, float):
            if (
                not isfinite(value)
                or abs(value) > MAX_ABSOLUTE_OPTION_NUMBER
            ):
                raise ValueError(
                    "Numeric option must be finite and within bounds."
                )

            return value

        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Text option cannot be blank.")

        if len(cleaned_value) > 1_000:
            raise ValueError(
                "Text option cannot exceed 1000 characters."
            )

        return cleaned_value


class CalculationAssumption(CalculationModel):
    """Explicit assumption used by a calculation."""

    assumption_id: Identifier
    statement: LongText
    origin: InputOrigin
    affects_result: StrictBool = True
    safety_critical: StrictBool = False
    requires_verification: StrictBool = False
    verification_completed: StrictBool = False
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    source_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    verified_by: ShortText | None = None
    verified_at: AwareDatetime | None = None

    @field_validator("verified_at")
    @classmethod
    def normalise_verified_at(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        """Normalize an assumption verification timestamp to UTC."""

        if value is None:
            return None

        return _normalise_utc(value)

    @field_validator(
        "verification_requirement_ids",
        "source_reference_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Require unique assumption links."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_verification_state(self) -> "CalculationAssumption":
        """Keep the verification flag and linked requirements consistent."""

        if (
            self.requires_verification
            and not self.verification_requirement_ids
        ):
            raise ValueError(
                "An assumption requiring verification must link at least "
                "one verification requirement."
            )

        if (
            self.verification_requirement_ids
            and not self.requires_verification
        ):
            raise ValueError(
                "verification_requirement_ids require "
                "requires_verification=true."
            )

        if self.safety_critical and not self.requires_verification:
            raise ValueError(
                "A safety-critical assumption requires verification."
            )

        verification_details_present = (
            self.verified_by is not None
            or self.verified_at is not None
        )

        if self.verification_completed:
            if not self.requires_verification:
                raise ValueError(
                    "verification_completed requires "
                    "requires_verification=true."
                )

            if self.verified_by is None or self.verified_at is None:
                raise ValueError(
                    "A completed assumption verification requires "
                    "verified_by and verified_at."
                )
        elif verification_details_present:
            raise ValueError(
                "Verification details require verification_completed=true."
            )

        if (
            self.origin
            in {
                InputOrigin.DOCUMENT_EXTRACTED,
                InputOrigin.IMPORTED,
            }
            and not self.source_reference_ids
        ):
            raise ValueError(
                "Document-extracted and imported assumptions require a "
                "source reference."
            )

        return self


class MissingCalculationInput(CalculationModel):
    """Input that was unavailable when execution was attempted."""

    input_id: Identifier
    name: ShortText
    reason: LongText
    required_for_execution: StrictBool = True
    safety_critical: StrictBool = False
    expected_unit: UnitSymbol | None = None

    @model_validator(mode="after")
    def validate_safety_critical_state(self) -> "MissingCalculationInput":
        """A safety-critical input cannot be classified as optional."""

        if self.safety_critical and not self.required_for_execution:
            raise ValueError(
                "A safety-critical missing input must be required for "
                "execution."
            )

        return self


class CalculationFinding(CalculationModel):
    """Validation, applicability, safety, or quality finding."""

    finding_id: Identifier
    category: FindingCategory
    severity: FindingSeverity
    title: ShortText
    message: LongText
    blocking: StrictBool = False
    required_action: LongText | None = None
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @field_validator(
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Require unique finding links."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_blocking_finding(self) -> "CalculationFinding":
        """Require actionable, reviewable blocking findings."""

        if (
            self.severity
            in {
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }
            and not self.blocking
        ):
            raise ValueError(
                "An error or critical finding must block execution."
            )

        if self.blocking:
            if self.severity not in {
                FindingSeverity.WARNING,
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }:
                raise ValueError(
                    "A blocking finding must have warning, error, or "
                    "critical severity."
                )

            if self.required_action is None:
                raise ValueError(
                    "A blocking finding must define a required action."
                )

            if not self.verification_requirement_ids:
                raise ValueError(
                    "A blocking finding must link at least one verification "
                    "requirement."
                )

        return self


class CalculationReference(CalculationModel):
    """Traceable engineering, standards, OEM, or test reference."""

    reference_id: Identifier
    reference_type: ReferenceType
    title: ShortText
    publisher_or_owner: ShortText | None = None
    document_number: ShortText | None = None
    edition_or_revision: ShortText | None = None
    part: ShortText | None = None
    corrigenda_status: ShortText | None = None
    relevant_section: ShortText | None = None
    implementation_basis: LongText | None = None
    applicability: LongText | None = None
    source_location: LongText | None = None
    verified: StrictBool = False
    verified_by: ShortText | None = None
    verified_at: AwareDatetime | None = None

    @field_validator("verified_at")
    @classmethod
    def normalise_verified_at(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        """Normalize a verification timestamp to UTC."""

        if value is None:
            return None

        return _normalise_utc(value)

    @model_validator(mode="after")
    def validate_verification_details(self) -> "CalculationReference":
        """Keep verification status and reviewer evidence consistent."""

        controlled_reference_types = {
            ReferenceType.INTERNATIONAL_STANDARD,
            ReferenceType.NATIONAL_STANDARD,
            ReferenceType.COMPANY_STANDARD,
            ReferenceType.REGULATION,
        }

        if self.reference_type in controlled_reference_types:
            required_control_fields = (
                self.publisher_or_owner,
                self.document_number,
                self.edition_or_revision,
                self.part,
                self.corrigenda_status,
                self.relevant_section,
                self.implementation_basis,
            )

            if any(value is None for value in required_control_fields):
                raise ValueError(
                    "A controlled standards or regulation reference requires "
                    "publisher_or_owner, document_number, "
                    "edition_or_revision, part, corrigenda_status, "
                    "relevant_section, and implementation_basis."
                )

            if not self.verified:
                raise ValueError(
                    "A controlled standards or regulation reference must be "
                    "verified."
                )

        oem_reference_types = {
            ReferenceType.OEM_MANUAL,
            ReferenceType.OEM_DATASHEET,
        }

        if self.reference_type in oem_reference_types:
            required_oem_fields = (
                self.publisher_or_owner,
                self.document_number,
                self.edition_or_revision,
                self.relevant_section,
                self.applicability,
            )

            if any(value is None for value in required_oem_fields):
                raise ValueError(
                    "An OEM reference requires publisher_or_owner, "
                    "document_number, edition_or_revision, "
                    "relevant_section, and applicability."
                )

            if not self.verified:
                raise ValueError("An OEM reference must be verified.")

        verification_details_present = (
            self.verified_by is not None
            or self.verified_at is not None
        )

        if self.verified:
            if self.verified_by is None or self.verified_at is None:
                raise ValueError(
                    "A verified reference requires verified_by and "
                    "verified_at."
                )
        elif verification_details_present:
            raise ValueError(
                "Verification details require verified=true."
            )

        return self


class VerificationRequirement(CalculationModel):
    """Required action for independently checking a calculation."""

    verification_id: Identifier
    description: LongText
    method: LongText
    expected_result: LongText
    acceptance_criteria: LongText | None = None
    required_competency: ShortText
    verifier_role: ShortText | None = None
    independent_verification_required: StrictBool = False
    evidence_required: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @field_validator("evidence_required")
    @classmethod
    def validate_evidence_required(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate verification evidence descriptions."""

        return _require_unique_text(
            value,
            field_name="evidence_required",
        )

    @model_validator(mode="after")
    def validate_independent_verifier(self) -> "VerificationRequirement":
        """Require a role when independent verification is mandatory."""

        if (
            self.independent_verification_required
            and self.verifier_role is None
        ):
            raise ValueError(
                "Independent verification requires a verifier_role."
            )

        return self


class CalculationTraceValue(CalculationModel):
    """One immutable intermediate value produced by a trace step."""

    value_id: Identifier
    name: ShortText
    quantity: EngineeringQuantity | None = None
    categorical_value: CategoricalValue | None = None
    source_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    description: LongText | None = None

    @field_validator("categorical_value")
    @classmethod
    def validate_categorical_value(
        cls,
        value: bool | str | None,
    ) -> bool | str | None:
        """Reject blank or oversized categorical intermediate text."""

        if isinstance(value, str):
            cleaned_value = value.strip()

            if not cleaned_value:
                raise ValueError(
                    "Categorical trace text cannot be blank."
                )

            if len(cleaned_value) > 1_000:
                raise ValueError(
                    "Categorical trace text cannot exceed 1000 characters."
                )

            return cleaned_value

        return value

    @field_validator("source_reference_ids")
    @classmethod
    def validate_source_reference_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject ambiguous duplicate trace-value references."""

        return _require_unique_text(
            value,
            field_name="source_reference_ids",
        )

    @model_validator(mode="after")
    def validate_value_choice(self) -> "CalculationTraceValue":
        """Require exactly one numerical or categorical intermediate."""

        populated_values = sum(
            item is not None
            for item in (self.quantity, self.categorical_value)
        )

        if populated_values != 1:
            raise ValueError(
                "Exactly one of quantity or categorical_value must be "
                "supplied."
            )

        return self


class CalculationTraceStep(CalculationModel):
    """One explainable non-executable step in a calculation trace."""

    step_id: Identifier
    sequence: StrictInt = Field(ge=1, le=MAX_TRACE_STEPS)
    kind: TraceStepKind
    status: TraceStepStatus = TraceStepStatus.COMPLETED
    title: ShortText
    description: LongText
    formula_identifier: Identifier | None = Field(
        default=None,
        description=(
            "Identifier only. Executable expression text is prohibited."
        ),
    )
    input_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    output_values: tuple[CalculationTraceValue, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    dependency_step_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    iteration_number: StrictInt | None = Field(
        default=None,
        ge=1,
        le=1_000_000,
    )

    @field_validator(
        "input_ids",
        "dependency_step_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Require unique trace links."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_trace_step(self) -> "CalculationTraceStep":
        """Prevent invalid dependencies and iteration metadata."""

        dependency_keys = {
            _casefold_identifier(value)
            for value in self.dependency_step_ids
        }

        if _casefold_identifier(self.step_id) in dependency_keys:
            raise ValueError("A trace step cannot depend on itself.")

        if (
            self.kind == TraceStepKind.ITERATION
            and self.iteration_number is None
        ):
            raise ValueError(
                "An iteration trace step requires iteration_number."
            )

        if (
            self.kind != TraceStepKind.ITERATION
            and self.iteration_number is not None
        ):
            raise ValueError(
                "iteration_number is only valid for iteration trace steps."
            )

        if (
            self.kind
            in {
                TraceStepKind.CALCULATION,
                TraceStepKind.ITERATION,
            }
            and self.formula_identifier is None
        ):
            raise ValueError(
                "Calculation and iteration trace steps require a "
                "formula_identifier."
            )

        if (
            self.status == TraceStepStatus.COMPLETED
            and self.kind
            in {
                TraceStepKind.CALCULATION,
                TraceStepKind.ITERATION,
            }
            and not self.output_values
        ):
            raise ValueError(
                "A completed calculation or iteration trace step must "
                "record an intermediate output value."
            )

        _require_unique_model_values(
            self.output_values,
            attribute_name="value_id",
            field_name="output_values",
        )

        _require_unique_model_values(
            self.output_values,
            attribute_name="name",
            field_name="output_values",
        )

        return self


class CalculationOutput(CalculationModel):
    """One final numerical or categorical calculation output."""

    output_id: Identifier
    name: ShortText
    quantity: EngineeringQuantity | None = None
    categorical_value: CategoricalValue | None = None
    source_step_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=32,
    )
    source_value_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=32,
    )
    source_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    description: LongText | None = None

    @field_validator("categorical_value")
    @classmethod
    def validate_categorical_value(
        cls,
        value: bool | str | None,
    ) -> bool | str | None:
        """Reject blank or oversized categorical output text."""

        if isinstance(value, str):
            cleaned_value = value.strip()

            if not cleaned_value:
                raise ValueError("Categorical output text cannot be blank.")

            if len(cleaned_value) > 1_000:
                raise ValueError(
                    "Categorical output text cannot exceed 1000 characters."
                )

            return cleaned_value

        return value

    @field_validator(
        "source_step_ids",
        "source_value_ids",
        "source_reference_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Require unique output links."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_value_choice(self) -> "CalculationOutput":
        """Require exactly one numerical quantity or categorical value."""

        populated_values = sum(
            item is not None
            for item in (self.quantity, self.categorical_value)
        )

        if populated_values != 1:
            raise ValueError(
                "Exactly one of quantity or categorical_value must be "
                "supplied."
            )

        return self


class CalculationRequest(CalculationModel):
    """Versioned request accepted by the future calculation engine."""

    request_id: UUID = Field(default_factory=uuid4)
    calculation_type: Identifier
    method_id: Identifier
    method_version: VersionText
    requested_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    requested_by: ShortText | None = None
    design_case_id: UUID | None = None
    correlation_id: Identifier | None = None
    inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    assumptions: tuple[CalculationAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ASSUMPTIONS,
    )
    options: tuple[CalculationOption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OPTIONS,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REFERENCES,
    )

    @field_validator("requested_at")
    @classmethod
    def normalise_requested_at(
        cls,
        value: datetime,
    ) -> datetime:
        """Normalize request timestamps to UTC."""

        return _normalise_utc(value)

    @field_validator("reference_ids")
    @classmethod
    def validate_reference_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate request references."""

        return _require_unique_text(
            value,
            field_name="reference_ids",
        )

    @model_validator(mode="after")
    def validate_request_collections(self) -> "CalculationRequest":
        """Require unambiguous input, assumption, and option identifiers."""

        prohibited_supplied_origins = {
            InputOrigin.DEFAULTED,
            InputOrigin.SYSTEM_DERIVED,
            InputOrigin.CALCULATED,
        }

        if any(
            value.origin in prohibited_supplied_origins
            for value in self.inputs
        ):
            raise ValueError(
                "Request inputs cannot be defaulted, system-derived, or "
                "calculated."
            )

        if any(value.source_trace_step_ids for value in self.inputs):
            raise ValueError(
                "Request inputs cannot link calculation trace steps."
            )

        _require_unique_model_values(
            self.inputs,
            attribute_name="input_id",
            field_name="inputs",
        )
        _require_unique_model_values(
            self.inputs,
            attribute_name="name",
            field_name="inputs",
        )
        _require_unique_model_values(
            self.assumptions,
            attribute_name="assumption_id",
            field_name="assumptions",
        )
        _require_unique_model_values(
            self.options,
            attribute_name="option_id",
            field_name="options",
        )

        request_reference_ids = {
            _casefold_identifier(value)
            for value in self.reference_ids
        }

        for input_value in self.inputs:
            linked_reference_ids = {
                _casefold_identifier(value)
                for value in input_value.source_reference_ids
            }

            if not linked_reference_ids.issubset(
                request_reference_ids
            ):
                raise ValueError(
                    "A request input contains a source reference that is "
                    "not declared in reference_ids."
                )

        for assumption in self.assumptions:
            linked_reference_ids = {
                _casefold_identifier(value)
                for value in assumption.source_reference_ids
            }

            if not linked_reference_ids.issubset(
                request_reference_ids
            ):
                raise ValueError(
                    "A request assumption contains a source reference that "
                    "is not declared in reference_ids."
                )

        return self


class CalculationResult(CalculationModel):
    """Complete explainable result returned by the calculation engine."""

    calculation_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    calculation_type: Identifier
    method_id: Identifier
    method_version: VersionText
    method_lifecycle_status: MethodLifecycleStatus
    engine_version: VersionText
    executed_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    status: CalculationStatus
    result_fingerprint: FingerprintText
    supplied_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    normalized_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    defaulted_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    effective_options: tuple[CalculationOption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OPTIONS,
    )
    assumptions: tuple[CalculationAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ASSUMPTIONS,
    )
    missing_inputs: tuple[MissingCalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MISSING_INPUTS,
    )
    findings: tuple[CalculationFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_FINDINGS,
    )
    trace_steps: tuple[CalculationTraceStep, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACE_STEPS,
    )
    outputs: tuple[CalculationOutput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OUTPUTS,
    )
    references: tuple[CalculationReference, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REFERENCES,
    )
    verification_requirements: tuple[
        VerificationRequirement,
        ...
    ] = Field(
        default_factory=tuple,
        max_length=MAX_VERIFICATION_REQUIREMENTS,
    )
    limitations: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )
    exclusions: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )
    required_reviewer_competency: ShortText
    disclaimer: LongText = Field(
        default=(
            "Engineer4Me provides engineering decision support and does not "
            "replace site-specific risk assessment, applicable legislation, "
            "current standards, manufacturer documentation, authorised plant "
            "procedures, or review by a competent engineer."
        )
    )

    @field_validator("executed_at")
    @classmethod
    def normalise_executed_at(
        cls,
        value: datetime,
    ) -> datetime:
        """Normalize execution timestamps to UTC."""

        return _normalise_utc(value)

    @field_validator("result_fingerprint")
    @classmethod
    def normalise_result_fingerprint(
        cls,
        value: str,
    ) -> str:
        """Use one canonical lower-case SHA-256 representation."""

        return value.lower()

    @field_validator("limitations", "exclusions")
    @classmethod
    def validate_text_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject duplicate limitations or exclusions."""

        return _require_unique_text(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_result(self) -> "CalculationResult":
        """Enforce traceability, references, and safe result-state rules."""

        self._validate_unique_collections()
        self._validate_trace_order()
        self._validate_links()
        self._validate_status()

        return self

    def _validate_unique_collections(self) -> None:
        """Require unique identifiers inside every result collection."""

        collection_identifiers = (
            (self.supplied_inputs, "input_id", "supplied_inputs"),
            (self.normalized_inputs, "input_id", "normalized_inputs"),
            (self.defaulted_inputs, "input_id", "defaulted_inputs"),
            (
                self.effective_options,
                "option_id",
                "effective_options",
            ),
            (self.assumptions, "assumption_id", "assumptions"),
            (self.missing_inputs, "input_id", "missing_inputs"),
            (self.findings, "finding_id", "findings"),
            (self.trace_steps, "step_id", "trace_steps"),
            (self.outputs, "output_id", "outputs"),
            (self.references, "reference_id", "references"),
            (
                self.verification_requirements,
                "verification_id",
                "verification_requirements",
            ),
        )

        for values, attribute_name, field_name in collection_identifiers:
            _require_unique_model_values(
                values,
                attribute_name=attribute_name,
                field_name=field_name,
            )

        supplied_names = tuple(
            value.name
            for value in self.supplied_inputs
        )
        normalized_names = tuple(
            value.name
            for value in self.normalized_inputs
        )
        defaulted_names = tuple(
            value.name
            for value in self.defaulted_inputs
        )
        output_names = tuple(
            value.name
            for value in self.outputs
        )
        trace_values = tuple(
            trace_value
            for step in self.trace_steps
            for trace_value in step.output_values
        )

        _require_unique_text(
            supplied_names,
            field_name="supplied input names",
        )
        _require_unique_text(
            normalized_names,
            field_name="normalized input names",
        )
        _require_unique_text(
            defaulted_names,
            field_name="defaulted input names",
        )
        _require_unique_text(
            output_names,
            field_name="output names",
        )
        _require_unique_model_values(
            trace_values,
            attribute_name="value_id",
            field_name="trace values",
        )

        external_value_ids = {
            _casefold_identifier(value.input_id)
            for value in (
                *self.supplied_inputs,
                *self.normalized_inputs,
                *self.defaulted_inputs,
                *self.missing_inputs,
            )
        }
        trace_value_ids = {
            _casefold_identifier(value.value_id)
            for value in trace_values
        }
        output_ids = {
            _casefold_identifier(value.output_id)
            for value in self.outputs
        }

        if external_value_ids.intersection(trace_value_ids):
            raise ValueError(
                "Trace value identifiers must not collide with input "
                "identifiers."
            )

        if output_ids.intersection(
            external_value_ids.union(trace_value_ids)
        ):
            raise ValueError(
                "Output identifiers must not collide with input or trace "
                "value identifiers."
            )

    def _validate_trace_order(self) -> None:
        """Require contiguous trace order and backward-only dependencies."""

        if not self.trace_steps:
            return

        expected_sequences = list(
            range(1, len(self.trace_steps) + 1)
        )
        actual_sequences = [
            step.sequence
            for step in self.trace_steps
        ]

        if actual_sequences != expected_sequences:
            raise ValueError(
                "trace_steps must be ordered contiguously from sequence 1."
            )

        prior_step_ids: set[str] = set()
        available_value_ids = {
            _casefold_identifier(value.input_id)
            for value in (
                *self.supplied_inputs,
                *self.defaulted_inputs,
            )
        }
        available_value_ids.update(
            _casefold_identifier(value.input_id)
            for value in self.normalized_inputs
            if value.origin
            not in {
                InputOrigin.SYSTEM_DERIVED,
                InputOrigin.CALCULATED,
            }
        )
        derived_normalized_inputs = tuple(
            value
            for value in self.normalized_inputs
            if value.origin
            in {
                InputOrigin.SYSTEM_DERIVED,
                InputOrigin.CALCULATED,
            }
        )

        for step in self.trace_steps:
            dependency_ids = {
                _casefold_identifier(value)
                for value in step.dependency_step_ids
            }

            if not dependency_ids.issubset(prior_step_ids):
                raise ValueError(
                    "A trace step may depend only on earlier trace steps."
                )

            input_ids = {
                _casefold_identifier(value)
                for value in step.input_ids
            }

            if not input_ids.issubset(available_value_ids):
                raise ValueError(
                    "A trace step contains an unresolved or forward input "
                    "value."
                )

            prior_step_ids.add(
                _casefold_identifier(step.step_id)
            )

            if step.status == TraceStepStatus.COMPLETED:
                available_value_ids.update(
                    _casefold_identifier(value.value_id)
                    for value in step.output_values
                )

                for value in derived_normalized_inputs:
                    source_step_ids = {
                        _casefold_identifier(source_step_id)
                        for source_step_id
                        in value.source_trace_step_ids
                    }

                    if source_step_ids.issubset(prior_step_ids):
                        available_value_ids.add(
                            _casefold_identifier(value.input_id)
                        )

    def _validate_links(self) -> None:
        """Require all internal result links to resolve."""

        reference_ids = {
            _casefold_identifier(value.reference_id)
            for value in self.references
        }
        verification_ids = {
            _casefold_identifier(value.verification_id)
            for value in self.verification_requirements
        }
        trace_step_ids = {
            _casefold_identifier(value.step_id)
            for value in self.trace_steps
        }
        completed_trace_step_ids = {
            _casefold_identifier(value.step_id)
            for value in self.trace_steps
            if value.status == TraceStepStatus.COMPLETED
        }
        trace_values_by_id = {
            _casefold_identifier(trace_value.value_id): (
                trace_step,
                trace_value,
            )
            for trace_step in self.trace_steps
            for trace_value in trace_step.output_values
        }
        assumption_ids = {
            _casefold_identifier(value.assumption_id)
            for value in self.assumptions
        }
        supplied_inputs_by_id = {
            _casefold_identifier(value.input_id): value
            for value in self.supplied_inputs
        }
        normalized_inputs_by_id = {
            _casefold_identifier(value.input_id): value
            for value in self.normalized_inputs
        }
        defaulted_inputs_by_id = {
            _casefold_identifier(value.input_id): value
            for value in self.defaulted_inputs
        }

        for collection_name, values in (
            ("supplied_inputs", self.supplied_inputs),
            ("normalized_inputs", self.normalized_inputs),
            ("defaulted_inputs", self.defaulted_inputs),
        ):
            for value in values:
                linked_reference_ids = {
                    _casefold_identifier(item)
                    for item in value.source_reference_ids
                }
                linked_trace_step_ids = {
                    _casefold_identifier(item)
                    for item in value.source_trace_step_ids
                }

                if not linked_reference_ids.issubset(reference_ids):
                    raise ValueError(
                        f"{collection_name} contains an unresolved "
                        "source reference."
                    )

                if not linked_trace_step_ids.issubset(
                    completed_trace_step_ids
                ):
                    raise ValueError(
                        f"{collection_name} contains an unresolved or "
                        "incomplete source trace step."
                    )

                if (
                    value.assumption_id is not None
                    and _casefold_identifier(value.assumption_id)
                    not in assumption_ids
                ):
                    raise ValueError(
                        f"{collection_name} contains an unresolved "
                        "assumption."
                    )

        supplied_origin_values = {
            InputOrigin.USER_SUPPLIED,
            InputOrigin.DOCUMENT_EXTRACTED,
            InputOrigin.SELECTED,
            InputOrigin.IMPORTED,
        }

        if any(
            value.origin not in supplied_origin_values
            for value in self.supplied_inputs
        ):
            raise ValueError(
                "supplied_inputs may contain only user-supplied, "
                "document-extracted, selected, or imported origins."
            )

        if any(
            value.source_trace_step_ids
            for value in self.supplied_inputs
        ):
            raise ValueError(
                "supplied_inputs cannot link calculation trace steps."
            )

        if any(
            value.origin != InputOrigin.DEFAULTED
            for value in self.defaulted_inputs
        ):
            raise ValueError(
                "defaulted_inputs must contain only defaulted origins."
            )

        supplied_input_ids = set(supplied_inputs_by_id)
        normalized_input_ids = set(normalized_inputs_by_id)
        defaulted_input_ids = set(defaulted_inputs_by_id)
        missing_input_ids = {
            _casefold_identifier(value.input_id)
            for value in self.missing_inputs
        }

        if not defaulted_input_ids.issubset(normalized_input_ids):
            raise ValueError(
                "Every defaulted input must have a normalized counterpart."
            )

        if (
            supplied_input_ids.intersection(defaulted_input_ids)
            or supplied_input_ids.intersection(missing_input_ids)
        ):
            raise ValueError(
                "A supplied input cannot also be defaulted or missing."
            )

        fallback_input_ids = defaulted_input_ids.intersection(
            missing_input_ids
        )
        normalized_missing_input_ids = normalized_input_ids.intersection(
            missing_input_ids
        )

        if not normalized_missing_input_ids.issubset(
            fallback_input_ids
        ):
            raise ValueError(
                "A missing input may be normalized only through an explicit "
                "default fallback."
            )

        missing_inputs_by_id = {
            _casefold_identifier(value.input_id): value
            for value in self.missing_inputs
        }

        for input_key in fallback_input_ids:
            missing_value = missing_inputs_by_id[input_key]
            defaulted_value = defaulted_inputs_by_id[input_key]

            if (
                missing_value.required_for_execution
                or missing_value.safety_critical
            ):
                raise ValueError(
                    "A required or safety-critical missing input cannot be "
                    "replaced by a default fallback."
                )

            if missing_value.name != defaulted_value.name:
                raise ValueError(
                    "A default fallback must preserve the missing input "
                    "name."
                )

        for input_key, value in normalized_inputs_by_id.items():
            source_value = supplied_inputs_by_id.get(input_key)

            if source_value is None:
                source_value = defaulted_inputs_by_id.get(input_key)

            if source_value is not None:
                if (
                    value.name != source_value.name
                    or value.origin != source_value.origin
                    or value.assumption_id != source_value.assumption_id
                    or value.source_reference_ids
                    != source_value.source_reference_ids
                ):
                    raise ValueError(
                        "A normalized counterpart must preserve its input "
                        "name, origin, assumption, and source references."
                    )

                quantity_types_match = (
                    (value.quantity is None)
                    == (source_value.quantity is None)
                )

                if not quantity_types_match:
                    raise ValueError(
                        "A normalized counterpart cannot change between "
                        "quantity and categorical input types."
                    )

                if (
                    value.quantity is not None
                    and source_value.quantity is not None
                    and value.quantity.quantity_kind
                    != source_value.quantity.quantity_kind
                ):
                    raise ValueError(
                        "A normalized quantity must preserve quantity_kind."
                    )

                if (
                    value.categorical_value
                    != source_value.categorical_value
                ):
                    raise ValueError(
                        "A normalized categorical value must preserve its "
                        "supplied value."
                    )

                continue

            if (
                value.origin
                not in {
                    InputOrigin.SYSTEM_DERIVED,
                    InputOrigin.CALCULATED,
                }
            ):
                raise ValueError(
                    "A normalized input without a supplied or defaulted "
                    "counterpart must be system-derived or calculated."
                )

        for assumption in self.assumptions:
            linked_verification_ids = {
                _casefold_identifier(value)
                for value in assumption.verification_requirement_ids
            }
            linked_reference_ids = {
                _casefold_identifier(value)
                for value in assumption.source_reference_ids
            }

            if not linked_verification_ids.issubset(verification_ids):
                raise ValueError(
                    "An assumption contains an unresolved verification "
                    "requirement."
                )

            if not linked_reference_ids.issubset(reference_ids):
                raise ValueError(
                    "An assumption contains an unresolved source reference."
                )

        for trace_step in self.trace_steps:
            for trace_value in trace_step.output_values:
                linked_reference_ids = {
                    _casefold_identifier(value)
                    for value in trace_value.source_reference_ids
                }

                if not linked_reference_ids.issubset(reference_ids):
                    raise ValueError(
                        "A trace value contains an unresolved source "
                        "reference."
                    )

        for finding in self.findings:
            linked_verification_ids = {
                _casefold_identifier(value)
                for value in finding.verification_requirement_ids
            }
            linked_reference_ids = {
                _casefold_identifier(value)
                for value in finding.reference_ids
            }

            if not linked_verification_ids.issubset(verification_ids):
                raise ValueError(
                    "A finding contains an unresolved verification "
                    "requirement."
                )

            if not linked_reference_ids.issubset(reference_ids):
                raise ValueError(
                    "A finding contains an unresolved reference."
                )

        for output in self.outputs:
            linked_step_ids = {
                _casefold_identifier(value)
                for value in output.source_step_ids
            }
            linked_value_ids = {
                _casefold_identifier(value)
                for value in output.source_value_ids
            }
            linked_reference_ids = {
                _casefold_identifier(value)
                for value in output.source_reference_ids
            }

            if not linked_step_ids.issubset(trace_step_ids):
                raise ValueError(
                    "An output contains an unresolved source trace step."
                )

            if not linked_step_ids.issubset(completed_trace_step_ids):
                raise ValueError(
                    "An output may reference only completed trace steps."
                )

            if not linked_value_ids.issubset(trace_values_by_id):
                raise ValueError(
                    "An output contains an unresolved source trace value."
                )

            source_trace_values = tuple(
                trace_values_by_id[value_id]
                for value_id in linked_value_ids
            )
            source_value_step_ids = {
                _casefold_identifier(trace_step.step_id)
                for trace_step, _ in source_trace_values
            }
            valid_output_source_kinds = {
                TraceStepKind.CALCULATION,
                TraceStepKind.ITERATION,
            }

            if not source_value_step_ids.issubset(linked_step_ids):
                raise ValueError(
                    "Every output source trace value must be produced by a "
                    "declared source step."
                )

            if any(
                trace_step.kind not in valid_output_source_kinds
                for trace_step, _ in source_trace_values
            ):
                raise ValueError(
                    "A final output must be sourced from a calculation, "
                    "or iteration trace step."
                )

            matching_value_present = any(
                (
                    output.quantity == trace_value.quantity
                    and output.categorical_value
                    == trace_value.categorical_value
                )
                for _, trace_value in source_trace_values
            )

            if not matching_value_present:
                raise ValueError(
                    "A final output must match at least one declared source "
                    "trace value."
                )

            source_value_reference_ids = {
                _casefold_identifier(reference_id)
                for _, trace_value in source_trace_values
                for reference_id in trace_value.source_reference_ids
            }

            if not source_value_reference_ids.issubset(
                linked_reference_ids
            ):
                raise ValueError(
                    "A final output must preserve its source trace-value "
                    "references."
                )

            if not linked_reference_ids.issubset(reference_ids):
                raise ValueError(
                    "An output contains an unresolved source reference."
                )

    def _validate_status(self) -> None:
        """Prevent contradictory or unsafe result states."""

        blocking_findings = tuple(
            finding
            for finding in self.findings
            if finding.blocking
        )
        warning_findings = tuple(
            finding
            for finding in self.findings
            if finding.severity
            in {
                FindingSeverity.CAUTION,
                FindingSeverity.WARNING,
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }
        )
        required_missing_inputs = tuple(
            value
            for value in self.missing_inputs
            if value.required_for_execution
        )
        safety_critical_missing_inputs = tuple(
            value
            for value in self.missing_inputs
            if value.safety_critical
        )
        assumptions_awaiting_verification = tuple(
            value
            for value in self.assumptions
            if (
                value.requires_verification
                and not value.verification_completed
            )
        )
        safety_critical_assumptions_awaiting_verification = tuple(
            value
            for value in assumptions_awaiting_verification
            if value.safety_critical
        )
        unverified_references = tuple(
            value
            for value in self.references
            if not value.verified
        )

        completed_states = {
            CalculationStatus.COMPLETED,
            CalculationStatus.COMPLETED_WITH_WARNINGS,
        }

        if self.status in completed_states:
            if (
                self.method_lifecycle_status
                != MethodLifecycleStatus.APPROVED
            ):
                raise ValueError(
                    "A completed result requires an approved method "
                    "lifecycle status."
                )

            if not self.outputs:
                raise ValueError(
                    "A completed result must contain at least one output."
                )

            if not self.trace_steps:
                raise ValueError(
                    "A completed result must contain a calculation trace."
                )

            if blocking_findings:
                raise ValueError(
                    "A result with a blocking finding cannot be completed."
                )

            if required_missing_inputs:
                raise ValueError(
                    "A result with a required missing input cannot be "
                    "completed."
                )

            if any(
                step.status == TraceStepStatus.FAILED
                for step in self.trace_steps
            ):
                raise ValueError(
                    "A completed result cannot contain a failed trace step."
                )

            normalized_input_ids = {
                _casefold_identifier(value.input_id)
                for value in self.normalized_inputs
            }
            source_input_ids = {
                _casefold_identifier(value.input_id)
                for value in (
                    *self.supplied_inputs,
                    *self.defaulted_inputs,
                )
            }

            if not source_input_ids.issubset(normalized_input_ids):
                raise ValueError(
                    "A completed result must normalize every supplied and "
                    "defaulted input."
                )

        if self.status == CalculationStatus.COMPLETED:
            if warning_findings:
                raise ValueError(
                    "A completed result cannot contain caution, warning, "
                    "or critical findings."
                )

            if self.missing_inputs:
                raise ValueError(
                    "A completed result cannot contain missing inputs."
                )

            if assumptions_awaiting_verification:
                raise ValueError(
                    "A completed result cannot contain an assumption still "
                    "requiring verification."
                )

            if unverified_references:
                raise ValueError(
                    "A completed result cannot contain an unverified "
                    "reference."
                )

        if self.status == CalculationStatus.COMPLETED_WITH_WARNINGS:
            warning_context_present = bool(
                warning_findings
                or self.missing_inputs
                or assumptions_awaiting_verification
                or unverified_references
            )

            if not warning_context_present:
                raise ValueError(
                    "completed_with_warnings requires at least one warning, "
                    "missing optional input, unverified assumption, or "
                    "unverified reference."
                )

        if self.status not in completed_states and self.outputs:
            raise ValueError(
                "A non-completed result cannot contain final outputs."
            )

        if (
            self.status == CalculationStatus.BLOCKED
            and not blocking_findings
        ):
            raise ValueError(
                "A blocked result requires at least one blocking finding."
            )

        if (
            self.status == CalculationStatus.INSUFFICIENT_INPUT
            and not required_missing_inputs
        ):
            raise ValueError(
                "An insufficient_input result requires at least one "
                "required missing input."
            )

        if self.status == CalculationStatus.NOT_APPLICABLE:
            applicability_findings = tuple(
                finding
                for finding in self.findings
                if (
                    finding.category == FindingCategory.APPLICABILITY
                    and finding.blocking
                )
            )

            if not applicability_findings:
                raise ValueError(
                    "A not_applicable result requires a blocking "
                    "applicability finding."
                )

        if self.status == CalculationStatus.FAILED:
            failure_findings = tuple(
                finding
                for finding in self.findings
                if finding.severity
                in {
                    FindingSeverity.ERROR,
                    FindingSeverity.CRITICAL,
                }
            )

            if not failure_findings:
                raise ValueError(
                    "A failed result requires an error or critical finding."
                )

        if safety_critical_missing_inputs:
            blocking_safety_findings = tuple(
                finding
                for finding in blocking_findings
                if finding.category == FindingCategory.SAFETY
            )

            if (
                self.status != CalculationStatus.BLOCKED
                or not blocking_safety_findings
            ):
                raise ValueError(
                    "A safety-critical missing input requires blocked status "
                    "and a blocking safety finding."
                )

        blocking_safety_findings = tuple(
            finding
            for finding in blocking_findings
            if finding.category == FindingCategory.SAFETY
        )

        if (
            blocking_safety_findings
            and self.status != CalculationStatus.BLOCKED
        ):
            raise ValueError(
                "A blocking safety finding requires blocked status."
            )

        if safety_critical_assumptions_awaiting_verification:
            if (
                self.status != CalculationStatus.BLOCKED
                or not blocking_safety_findings
            ):
                raise ValueError(
                    "An unverified safety-critical assumption requires "
                    "blocked status and a blocking safety finding."
                )


__all__ = [
    "CalculationAssumption",
    "CalculationFinding",
    "CalculationInput",
    "CalculationModel",
    "CalculationOption",
    "CalculationOutput",
    "CalculationReference",
    "CalculationRequest",
    "CalculationResult",
    "CalculationStatus",
    "CalculationTraceStep",
    "CalculationTraceValue",
    "EngineeringQuantity",
    "FindingCategory",
    "FindingSeverity",
    "InputOrigin",
    "MethodLifecycleStatus",
    "MissingCalculationInput",
    "ReferenceType",
    "TraceStepKind",
    "TraceStepStatus",
    "VerificationRequirement",
]
