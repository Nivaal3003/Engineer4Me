"""Strict metadata and execution-boundary models for calculation methods.

The models in this module describe reviewed calculation methods without
containing executable formulas, import paths, expression text, or callable
names.  A separate immutable registry binds one validated definition directly
to reviewed application code.  Requests, documents, database values, and AI
output therefore cannot select or construct executable Python.

All models are frozen, extra-forbid, bounded, finite, and revalidated at trust
boundaries through :class:`~app.engineering.calculations.models.CalculationModel`.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from enum import StrEnum
from math import isfinite
import re
from typing import Any
from typing import Self

from pydantic import AwareDatetime
from pydantic import Field
from pydantic import StrictBool
from pydantic import StrictFloat
from pydantic import StrictInt
from pydantic import field_validator
from pydantic import model_validator

from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CategoricalValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import Identifier
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import LongText
from app.engineering.calculations.models import MAX_ABSOLUTE_OPTION_NUMBER
from app.engineering.calculations.models import MAX_ASSUMPTIONS
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MAX_OUTPUTS
from app.engineering.calculations.models import MAX_REFERENCES
from app.engineering.calculations.models import MAX_TEXT_ITEMS
from app.engineering.calculations.models import MAX_TRACE_STEPS
from app.engineering.calculations.models import (
    MAX_VERIFICATION_REQUIREMENTS,
)
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import OptionScalar
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import ShortText
from app.engineering.calculations.models import TextItem
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import UnitSymbol
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.models import VersionText
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import PhysicalDimension
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import UnitSystemError


MAX_METHOD_FORMULAS = 256
MAX_METHOD_REVIEWS = 16
MAX_METHOD_RULES = 256
MAX_ENGINE_ITERATIONS = 1_000

_PRERELEASE_IDENTIFIER_PATTERN = (
    r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
)
CANONICAL_METHOD_VERSION_PATTERN = (
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    rf"(?:-{_PRERELEASE_IDENTIFIER_PATTERN}"
    rf"(?:\.{_PRERELEASE_IDENTIFIER_PATTERN})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_CANONICAL_VERSION_PATTERN = re.compile(
    rf"^{CANONICAL_METHOD_VERSION_PATTERN}$"
)
_STABLE_VERSION_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)


def _comparison_text(value: str) -> str:
    """Return the case-insensitive identifier comparison form."""

    return value.casefold()


def _require_unique_strings(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    """Require case-insensitively unique text."""

    comparison_values = tuple(
        _comparison_text(value)
        for value in values
    )

    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(f"{field_name} values must be unique.")

    return values


def _require_unique_attributes(
    values: tuple[CalculationModel, ...],
    *,
    attribute_name: str,
    field_name: str,
) -> None:
    """Require case-insensitively unique identifiers on nested models."""

    comparison_values = tuple(
        _comparison_text(str(getattr(value, attribute_name)))
        for value in values
    )

    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(
            f"{field_name} {attribute_name} values must be unique."
        )


def _parse_stable_version(value: str) -> tuple[int, int, int]:
    """Parse one canonical stable ``X.Y.Z`` version."""

    if not isinstance(value, str) or not _STABLE_VERSION_PATTERN.fullmatch(
        value
    ):
        raise ValueError(
            "Engine versions must use canonical stable X.Y.Z form."
        )

    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _semantic_version_key(
    value: str,
) -> tuple[
    tuple[int, int, int],
    int,
    tuple[tuple[int, int | str], ...],
]:
    """Return a SemVer-compatible precedence key; build data is ignored."""

    without_build = value.split("+", 1)[0]
    core_text, separator, prerelease_text = without_build.partition("-")
    core = tuple(
        int(part)
        for part in core_text.split(".")
    )

    if not separator:
        return (
            core,  # type: ignore[arg-type]
            1,
            (),
        )

    prerelease_key: list[tuple[int, int | str]] = []

    for identifier in prerelease_text.split("."):
        if identifier.isdigit():
            prerelease_key.append((0, int(identifier)))
        else:
            prerelease_key.append((1, identifier))

    return (
        core,  # type: ignore[arg-type]
        0,
        tuple(prerelease_key),
    )


def _option_type_key(value: OptionScalar) -> tuple[str, object]:
    """Return a strict, non-coercing uniqueness key for an option value."""

    if isinstance(value, bool):
        return ("boolean", value)

    if isinstance(value, int):
        return ("integer", value)

    if isinstance(value, float):
        return ("float", value)

    return ("text", value.casefold())


class InputPresence(StrEnum):
    """How an input participates in a method request."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    DEFAULTED = "defaulted"


class InputValueType(StrEnum):
    """Supported strict input representations."""

    QUANTITY = "quantity"
    CATEGORICAL_BOOLEAN = "categorical_boolean"
    CATEGORICAL_TEXT = "categorical_text"


class InputNormalizationMode(StrEnum):
    """Controlled input-normalization path."""

    NONE = "none"
    UNIT_REGISTRY = "unit_registry"
    METHOD_SPECIFIC = "method_specific"


class MethodOptionValueType(StrEnum):
    """Strict scalar type accepted by a method option."""

    BOOLEAN = "boolean"
    INTEGER = "integer"
    FLOAT = "float"
    TEXT = "text"


class MethodReviewType(StrEnum):
    """Independent review stages required before approval."""

    TECHNICAL = "technical"
    SAFETY = "safety"
    STANDARDS = "standards"
    LEGAL_COMPLIANCE = "legal_compliance"
    SOFTWARE = "software"
    FINAL_APPROVAL = "final_approval"


class IterationTerminationReason(StrEnum):
    """Deterministic reason an iterative implementation stopped."""

    CONVERGED = "converged"
    MAXIMUM_ITERATIONS = "maximum_iterations"
    DIVERGED = "diverged"
    NON_FINITE_VALUE = "non_finite_value"


class NumericApplicabilityRange(CalculationModel):
    """Finite normalized numerical range used by reviewed validation."""

    minimum: StrictFloat | None = Field(
        default=None,
        ge=-MAX_ABSOLUTE_OPTION_NUMBER,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    maximum: StrictFloat | None = Field(
        default=None,
        ge=-MAX_ABSOLUTE_OPTION_NUMBER,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    minimum_inclusive: StrictBool = True
    maximum_inclusive: StrictBool = True

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        """Require a useful, non-contradictory bounded interval."""

        if self.minimum is None and self.maximum is None:
            raise ValueError(
                "At least one numerical applicability bound is required."
            )

        if self.minimum is None and not self.minimum_inclusive:
            raise ValueError(
                "minimum_inclusive is only meaningful with minimum."
            )

        if self.maximum is None and not self.maximum_inclusive:
            raise ValueError(
                "maximum_inclusive is only meaningful with maximum."
            )

        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError("minimum cannot exceed maximum.")

            if (
                self.minimum == self.maximum
                and not (
                    self.minimum_inclusive
                    and self.maximum_inclusive
                )
            ):
                raise ValueError(
                    "Equal bounds must both be inclusive."
                )

        return self

    def contains(self, value: int | float) -> bool:
        """Return whether a finite non-boolean value is inside the range."""

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            numeric_value = float(value)
        except (OverflowError, TypeError, ValueError):
            return False
        if not isfinite(numeric_value):
            return False

        if self.minimum is not None:
            if self.minimum_inclusive:
                if numeric_value < self.minimum:
                    return False
            elif numeric_value <= self.minimum:
                return False

        if self.maximum is not None:
            if self.maximum_inclusive:
                if numeric_value > self.maximum:
                    return False
            elif numeric_value >= self.maximum:
                return False

        return True


class MethodInputSpecification(CalculationModel):
    """Reviewed schema and normalization policy for one method input."""

    input_id: Identifier
    name: ShortText
    description: LongText
    presence: InputPresence
    value_type: InputValueType
    normalization_mode: InputNormalizationMode
    quantity_kind: QuantityKind | None = None
    canonical_unit: UnitSymbol | None = None
    numeric_range: NumericApplicabilityRange | None = None
    allowed_categorical_values: tuple[CategoricalValue, ...] = Field(
        default_factory=tuple,
        max_length=128,
    )
    categorical_case_sensitive: StrictBool = False
    safety_critical: StrictBool = False
    default_input: CalculationInput | None = None
    default_assumption: CalculationAssumption | None = None
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @field_validator(
        "reference_ids",
        "verification_requirement_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject ambiguous duplicate method-input links."""

        return _require_unique_strings(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_specification(self) -> Self:
        """Enforce value-type, default, and safety invariants."""

        if self.value_type is InputValueType.QUANTITY:
            if self.quantity_kind is None or self.canonical_unit is None:
                raise ValueError(
                    "A quantity input requires quantity_kind and "
                    "canonical_unit."
                )

            if self.normalization_mode is InputNormalizationMode.NONE:
                raise ValueError(
                    "A quantity input requires a controlled normalization "
                    "mode."
                )

            if self.allowed_categorical_values:
                raise ValueError(
                    "A quantity input cannot define categorical values."
                )

            self._validate_quantity_unit()
        else:
            if (
                self.quantity_kind is not None
                or self.canonical_unit is not None
                or self.numeric_range is not None
            ):
                raise ValueError(
                    "A categorical input cannot define quantity metadata."
                )

            if self.normalization_mode is not InputNormalizationMode.NONE:
                raise ValueError(
                    "A categorical input must use normalization mode 'none'."
                )

            self._validate_categorical_values()

        if self.safety_critical:
            if self.presence is not InputPresence.REQUIRED:
                raise ValueError(
                    "A safety-critical input must be required."
                )

            if not self.verification_requirement_ids:
                raise ValueError(
                    "A safety-critical input requires a verification "
                    "requirement."
                )

        if self.presence is InputPresence.DEFAULTED:
            if self.default_input is None or self.default_assumption is None:
                raise ValueError(
                    "A defaulted input requires default_input and "
                    "default_assumption."
                )

            if (
                self.normalization_mode
                is InputNormalizationMode.METHOD_SPECIFIC
            ):
                raise ValueError(
                    "Method-specific inputs cannot be silently defaulted."
                )

            self._validate_default()
        elif (
            self.default_input is not None
            or self.default_assumption is not None
        ):
            raise ValueError(
                "Default values are valid only when presence is 'defaulted'."
            )

        return self

    def _validate_quantity_unit(self) -> None:
        """Require a dimensionally compatible normalization unit."""

        if self.quantity_kind is None or self.canonical_unit is None:
            return

        try:
            expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(
                self.quantity_kind
            )
            unit_definition = DEFAULT_UNIT_REGISTRY.resolve_unit(
                self.canonical_unit
            )
        except UnitSystemError as exc:
            raise ValueError(
                "Quantity input metadata uses an unsupported kind or unit."
            ) from exc

        if unit_definition.dimension is not expected_dimension:
            raise ValueError(
                "canonical_unit is incompatible with quantity_kind."
            )

        expected_canonical_unit = DEFAULT_UNIT_REGISTRY.canonical_unit_for(
            self.quantity_kind
        )

        if unit_definition.symbol != expected_canonical_unit:
            raise ValueError(
                "canonical_unit must be the controlled registry canonical "
                "symbol."
            )

    def _validate_categorical_values(self) -> None:
        """Require strict, unambiguous categorical allow-list values."""

        if self.value_type is InputValueType.CATEGORICAL_BOOLEAN:
            if any(
                not isinstance(value, bool)
                for value in self.allowed_categorical_values
            ):
                raise ValueError(
                    "Boolean input allow-list values must be booleans."
                )
        elif any(
            not isinstance(value, str)
            for value in self.allowed_categorical_values
        ):
            raise ValueError(
                "Text input allow-list values must be strings."
            )

        comparison_values: list[tuple[str, object]] = []

        for value in self.allowed_categorical_values:
            if isinstance(value, bool):
                comparison_values.append(("boolean", value))
            elif self.categorical_case_sensitive:
                comparison_values.append(("text", value))
            else:
                comparison_values.append(("text", value.casefold()))

        if len(comparison_values) != len(set(comparison_values)):
            raise ValueError(
                "allowed_categorical_values must be unique."
            )

        if (
            self.value_type is InputValueType.CATEGORICAL_BOOLEAN
            and self.categorical_case_sensitive
        ):
            raise ValueError(
                "categorical_case_sensitive is not valid for booleans."
            )

    def _validate_default(self) -> None:
        """Require a default matching this specification and assumption."""

        if self.default_input is None or self.default_assumption is None:
            return

        default_input = self.default_input
        default_assumption = self.default_assumption

        if (
            _comparison_text(default_input.input_id)
            != _comparison_text(self.input_id)
            or default_input.name != self.name
        ):
            raise ValueError(
                "default_input must preserve the specification ID and name."
            )

        if default_input.origin is not InputOrigin.DEFAULTED:
            raise ValueError("default_input must use origin 'defaulted'.")

        if (
            default_input.assumption_id is None
            or _comparison_text(default_input.assumption_id)
            != _comparison_text(default_assumption.assumption_id)
        ):
            raise ValueError(
                "default_input must link default_assumption."
            )

        if default_assumption.origin is not InputOrigin.DEFAULTED:
            raise ValueError(
                "default_assumption must use origin 'defaulted'."
            )

        if self.value_type is InputValueType.QUANTITY:
            if (
                default_input.quantity is None
                or default_input.categorical_value is not None
                or default_input.quantity.quantity_kind
                != self.quantity_kind.value  # type: ignore[union-attr]
            ):
                raise ValueError(
                    "Default quantity does not match the input "
                    "specification."
                )

            try:
                normalized_default = (
                    DEFAULT_UNIT_REGISTRY.convert_quantity(
                        default_input.quantity,
                        self.canonical_unit,  # type: ignore[arg-type]
                    )
                )
            except UnitSystemError as exc:
                raise ValueError(
                    "Default quantity cannot be normalized."
                ) from exc

            if (
                self.numeric_range is not None
                and not self.numeric_range.contains(
                    normalized_default.value
                )
            ):
                raise ValueError(
                    "Default quantity is outside numeric_range."
                )
        else:
            if (
                default_input.quantity is not None
                or default_input.categorical_value is None
            ):
                raise ValueError(
                    "Default categorical value does not match the input "
                    "specification."
                )

            if not self.accepts_categorical_value(
                default_input.categorical_value
            ):
                raise ValueError(
                    "Default categorical value is not allowed."
                )

    def accepts_categorical_value(
        self,
        value: bool | str,
    ) -> bool:
        """Return whether a strict categorical value satisfies the schema."""

        if self.value_type is InputValueType.QUANTITY:
            return False

        if self.value_type is InputValueType.CATEGORICAL_BOOLEAN:
            if not isinstance(value, bool):
                return False
        elif not isinstance(value, str):
            return False

        if not self.allowed_categorical_values:
            return True

        if isinstance(value, bool):
            return value in self.allowed_categorical_values

        if self.categorical_case_sensitive:
            return value in self.allowed_categorical_values

        comparison_value = value.casefold()
        return any(
            isinstance(allowed, str)
            and allowed.casefold() == comparison_value
            for allowed in self.allowed_categorical_values
        )


class MethodOptionSpecification(CalculationModel):
    """Reviewed strict scalar option accepted by a calculation method."""

    option_id: Identifier
    description: LongText
    value_type: MethodOptionValueType
    required: StrictBool = False
    default_option: CalculationOption | None = None
    allowed_values: tuple[OptionScalar, ...] = Field(
        default_factory=tuple,
        max_length=128,
    )
    numeric_range: NumericApplicabilityRange | None = None
    material_for_fingerprint: StrictBool = True

    @model_validator(mode="after")
    def validate_specification(self) -> Self:
        """Require strict option typing, bounds, and deterministic defaults."""

        if not self.material_for_fingerprint:
            raise ValueError(
                "Every Step 92 execution option must be material to the "
                "result fingerprint."
            )

        if self.required and self.default_option is not None:
            raise ValueError(
                "A required option cannot also define a default."
            )

        if (
            self.value_type
            not in {
                MethodOptionValueType.INTEGER,
                MethodOptionValueType.FLOAT,
            }
            and self.numeric_range is not None
        ):
            raise ValueError(
                "numeric_range is valid only for integer or float options."
            )

        comparison_values: list[tuple[str, object]] = []

        for value in self.allowed_values:
            if not self.accepts_type(value):
                raise ValueError(
                    "allowed_values contains a value of the wrong strict "
                    "type."
                )

            if (
                self.numeric_range is not None
                and not self.numeric_range.contains(value)  # type: ignore[arg-type]
            ):
                raise ValueError(
                    "allowed_values contains a value outside numeric_range."
                )

            comparison_values.append(_option_type_key(value))

        if len(comparison_values) != len(set(comparison_values)):
            raise ValueError("allowed_values must be unique.")

        if self.default_option is not None:
            if (
                _comparison_text(self.default_option.option_id)
                != _comparison_text(self.option_id)
            ):
                raise ValueError(
                    "default_option must preserve option_id."
                )

            if not self.accepts_value(self.default_option.value):
                raise ValueError(
                    "default_option does not satisfy the option schema."
                )

        return self

    def accepts_type(self, value: OptionScalar) -> bool:
        """Return whether a scalar has exactly the configured type."""

        if self.value_type is MethodOptionValueType.BOOLEAN:
            return isinstance(value, bool)

        if self.value_type is MethodOptionValueType.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)

        if self.value_type is MethodOptionValueType.FLOAT:
            return isinstance(value, float)

        return isinstance(value, str)

    def accepts_value(self, value: OptionScalar) -> bool:
        """Return whether a scalar satisfies type, range, and allow-list."""

        if not self.accepts_type(value):
            return False

        if (
            self.numeric_range is not None
            and not self.numeric_range.contains(value)  # type: ignore[arg-type]
        ):
            return False

        if not self.allowed_values:
            return True

        value_key = _option_type_key(value)
        return any(
            _option_type_key(allowed) == value_key
            for allowed in self.allowed_values
        )


class FormulaMetadata(CalculationModel):
    """Traceable formula identifier with no executable expression text."""

    formula_identifier: Identifier
    title: ShortText
    description: LongText
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @field_validator("reference_ids")
    @classmethod
    def validate_reference_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate formula references."""

        return _require_unique_strings(
            value,
            field_name="reference_ids",
        )


class ApplicabilityRule(CalculationModel):
    """Declarative applicability requirement evaluated by reviewed code."""

    rule_id: Identifier
    title: ShortText
    description: LongText
    input_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=64,
    )
    severity: FindingSeverity = FindingSeverity.ERROR
    blocking: StrictBool = True
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
        "input_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject duplicate rule links."""

        return _require_unique_strings(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        """Keep severity, blocking state, and required action consistent."""

        if self.severity in {
            FindingSeverity.ERROR,
            FindingSeverity.CRITICAL,
        } and not self.blocking:
            raise ValueError(
                "Error and critical applicability rules must block."
            )

        if self.blocking:
            if self.severity not in {
                FindingSeverity.WARNING,
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }:
                raise ValueError(
                    "A blocking applicability rule requires warning, error, "
                    "or critical severity."
                )

            if self.required_action is None:
                raise ValueError(
                    "A blocking applicability rule requires an action."
                )

            if not self.verification_requirement_ids:
                raise ValueError(
                    "A blocking applicability rule requires verification."
                )

        return self


class SafetyRequirement(CalculationModel):
    """Declarative safety requirement evaluated before method execution."""

    requirement_id: Identifier
    title: ShortText
    hazard: LongText
    required_input_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    severity: FindingSeverity = FindingSeverity.CRITICAL
    blocking: StrictBool = True
    required_action: LongText | None = None
    verification_requirement_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    required_competency: ShortText

    @field_validator(
        "required_input_ids",
        "verification_requirement_ids",
        "reference_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject duplicate safety links."""

        return _require_unique_strings(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_requirement(self) -> Self:
        """Require actionable safety severity and verification."""

        if self.severity in {
            FindingSeverity.ERROR,
            FindingSeverity.CRITICAL,
        } and not self.blocking:
            raise ValueError(
                "Error and critical safety requirements must block."
            )

        if self.blocking:
            if self.severity not in {
                FindingSeverity.WARNING,
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }:
                raise ValueError(
                    "A blocking safety requirement requires warning, error, "
                    "or critical severity."
                )

            if self.required_action is None:
                raise ValueError(
                    "A blocking safety requirement requires an action."
                )

            if not self.verification_requirement_ids:
                raise ValueError(
                    "A blocking safety requirement requires verification."
                )

        return self


class MethodReviewRecord(CalculationModel):
    """Immutable evidence for one required method-review stage."""

    review_id: Identifier
    review_type: MethodReviewType
    approved: StrictBool
    reviewer: ShortText
    reviewer_competency: ShortText
    reviewed_at: AwareDatetime
    evidence_reference_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=32,
    )
    notes: LongText | None = None

    @field_validator("reviewed_at")
    @classmethod
    def normalise_reviewed_at(cls, value: datetime) -> datetime:
        """Normalize review timestamps to UTC."""

        return value.astimezone(UTC)

    @field_validator("evidence_reference_ids")
    @classmethod
    def validate_evidence_reference_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate review evidence links."""

        return _require_unique_strings(
            value,
            field_name="evidence_reference_ids",
        )


class EngineCompatibility(CalculationModel):
    """Inclusive-minimum, exclusive-maximum stable engine range."""

    minimum_version: VersionText
    maximum_exclusive_version: VersionText

    @field_validator(
        "minimum_version",
        "maximum_exclusive_version",
    )
    @classmethod
    def validate_stable_version(cls, value: str) -> str:
        """Require canonical stable ``X.Y.Z`` versions."""

        _parse_stable_version(value)
        return value

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        """Require a non-empty ordered compatibility interval."""

        if _parse_stable_version(
            self.minimum_version
        ) >= _parse_stable_version(self.maximum_exclusive_version):
            raise ValueError(
                "minimum_version must be below maximum_exclusive_version."
            )

        return self

    def supports(self, engine_version: str) -> bool:
        """Return whether a canonical stable engine version is supported."""

        try:
            parsed_version = _parse_stable_version(engine_version)
        except ValueError:
            return False

        return (
            _parse_stable_version(self.minimum_version)
            <= parsed_version
            < _parse_stable_version(self.maximum_exclusive_version)
        )


class IterationLimits(CalculationModel):
    """Hard reviewed bounds for one iterative calculation method."""

    maximum_iterations: StrictInt = Field(
        ge=1,
        le=MAX_ENGINE_ITERATIONS,
    )
    absolute_tolerance: StrictFloat = Field(
        default=0.0,
        ge=0.0,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    relative_tolerance: StrictFloat = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    divergence_limit: StrictFloat | None = Field(
        default=None,
        gt=0.0,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    convergence_value_id: Identifier
    convergence_description: LongText

    @model_validator(mode="after")
    def validate_tolerances(self) -> Self:
        """Require at least one positive convergence tolerance."""

        if self.absolute_tolerance == 0.0 and self.relative_tolerance == 0.0:
            raise ValueError(
                "At least one iteration tolerance must be greater than zero."
            )

        return self


class IterationOutcome(CalculationModel):
    """Bounded, finite outcome reported by an iterative implementation."""

    iterations_used: StrictInt = Field(
        ge=0,
        le=MAX_ENGINE_ITERATIONS,
    )
    converged: StrictBool
    termination_reason: IterationTerminationReason
    final_residual: StrictFloat = Field(
        ge=0.0,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )
    description: LongText

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        """Keep convergence state and termination reason consistent."""

        if self.converged:
            if (
                self.termination_reason
                is not IterationTerminationReason.CONVERGED
            ):
                raise ValueError(
                    "A converged iteration requires reason 'converged'."
                )

            if self.iterations_used < 1:
                raise ValueError(
                    "A converged iteration requires at least one iteration."
                )
        elif (
            self.termination_reason
            is IterationTerminationReason.CONVERGED
        ):
            raise ValueError(
                "A non-converged iteration cannot use reason 'converged'."
            )

        if (
            self.termination_reason
            is IterationTerminationReason.MAXIMUM_ITERATIONS
            and self.iterations_used < 1
        ):
            raise ValueError(
                "Maximum-iteration termination requires an iteration."
            )

        return self


class CalculationMethodDefinition(CalculationModel):
    """Complete immutable metadata for one exact calculation-method version."""

    method_id: Identifier
    method_version: VersionText
    calculation_type: Identifier
    title: ShortText
    description: LongText
    implementation_owner: ShortText
    lifecycle_status: MethodLifecycleStatus
    engine_compatibility: EngineCompatibility
    input_specifications: tuple[MethodInputSpecification, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    option_specifications: tuple[MethodOptionSpecification, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OPTIONS,
    )
    applicability_rules: tuple[ApplicabilityRule, ...] = Field(
        default_factory=tuple,
        max_length=MAX_METHOD_RULES,
    )
    safety_requirements: tuple[SafetyRequirement, ...] = Field(
        default_factory=tuple,
        max_length=MAX_METHOD_RULES,
    )
    formulas: tuple[FormulaMetadata, ...] = Field(
        default_factory=tuple,
        max_length=MAX_METHOD_FORMULAS,
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
    reviews: tuple[MethodReviewRecord, ...] = Field(
        default_factory=tuple,
        max_length=MAX_METHOD_REVIEWS,
    )
    test_vector_reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    iteration_limits: IterationLimits | None = None
    superseded_by_version: VersionText | None = None
    disabled_reason: LongText | None = None
    limitations: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )
    exclusions: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )
    required_reviewer_competency: ShortText
    disclaimer: LongText

    @field_validator("method_version")
    @classmethod
    def validate_method_version(cls, value: str) -> str:
        """Require one canonical semantic method-version spelling."""

        if not _CANONICAL_VERSION_PATTERN.fullmatch(value):
            raise ValueError(
                "method_version must use canonical X.Y.Z semantic form."
            )

        return value

    @field_validator("superseded_by_version")
    @classmethod
    def validate_superseded_version(
        cls,
        value: str | None,
    ) -> str | None:
        """Require a canonical semantic successor version when supplied."""

        if (
            value is not None
            and not _CANONICAL_VERSION_PATTERN.fullmatch(value)
        ):
            raise ValueError(
                "superseded_by_version must use canonical X.Y.Z semantic "
                "form."
            )

        return value

    @field_validator(
        "test_vector_reference_ids",
        "limitations",
        "exclusions",
    )
    @classmethod
    def validate_text_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject duplicate method metadata values."""

        return _require_unique_strings(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        """Enforce link integrity and approved-method review gates."""

        collection_identifiers = (
            (
                self.input_specifications,
                "input_id",
                "input_specifications",
            ),
            (
                self.option_specifications,
                "option_id",
                "option_specifications",
            ),
            (
                self.applicability_rules,
                "rule_id",
                "applicability_rules",
            ),
            (
                self.safety_requirements,
                "requirement_id",
                "safety_requirements",
            ),
            (self.formulas, "formula_identifier", "formulas"),
            (self.references, "reference_id", "references"),
            (
                self.verification_requirements,
                "verification_id",
                "verification_requirements",
            ),
            (self.reviews, "review_id", "reviews"),
        )

        for values, attribute_name, field_name in collection_identifiers:
            _require_unique_attributes(
                values,
                attribute_name=attribute_name,
                field_name=field_name,
            )

        review_types = tuple(
            review.review_type.value
            for review in self.reviews
        )
        _require_unique_strings(
            review_types,
            field_name="review types",
        )

        input_ids = {
            _comparison_text(value.input_id)
            for value in self.input_specifications
        }
        option_ids = {
            _comparison_text(value.option_id)
            for value in self.option_specifications
        }

        if input_ids.intersection(option_ids):
            raise ValueError(
                "Input and option identifiers must not collide."
            )

        reserved_option_ids = {
            "absolute_tolerance",
            "engine_version",
            "maximum_iterations",
            "method_id",
            "method_version",
            "relative_tolerance",
        }

        if option_ids.intersection(reserved_option_ids):
            raise ValueError(
                "Engine and method identity controls cannot be request "
                "options."
            )

        reference_ids = {
            _comparison_text(value.reference_id)
            for value in self.references
        }
        verification_ids = {
            _comparison_text(value.verification_id)
            for value in self.verification_requirements
        }

        self._validate_links(
            input_ids=input_ids,
            reference_ids=reference_ids,
            verification_ids=verification_ids,
        )

        self._validate_lifecycle_metadata()

        if self.lifecycle_status is MethodLifecycleStatus.APPROVED:
            self._validate_approved(reference_ids)

        return self

    def _validate_lifecycle_metadata(self) -> None:
        """Require explicit, non-contradictory terminal lifecycle metadata."""

        if self.lifecycle_status is MethodLifecycleStatus.SUPERSEDED:
            if self.superseded_by_version is None:
                raise ValueError(
                    "A superseded method requires superseded_by_version."
                )

            if self.disabled_reason is not None:
                raise ValueError(
                    "A superseded method cannot define disabled_reason."
                )

            if _semantic_version_key(
                self.superseded_by_version
            ) <= _semantic_version_key(self.method_version):
                raise ValueError(
                    "superseded_by_version must be newer than "
                    "method_version."
                )

            return

        if self.lifecycle_status is MethodLifecycleStatus.DISABLED:
            if self.disabled_reason is None:
                raise ValueError(
                    "A disabled method requires disabled_reason."
                )

            if self.superseded_by_version is not None:
                raise ValueError(
                    "A disabled method cannot define "
                    "superseded_by_version."
                )

            return

        if (
            self.superseded_by_version is not None
            or self.disabled_reason is not None
        ):
            raise ValueError(
                "superseded_by_version and disabled_reason are valid only "
                "for their matching terminal lifecycle states."
            )

    def _validate_links(
        self,
        *,
        input_ids: set[str],
        reference_ids: set[str],
        verification_ids: set[str],
    ) -> None:
        """Require every nested metadata link to resolve."""

        for specification in self.input_specifications:
            linked_reference_ids = {
                _comparison_text(value)
                for value in specification.reference_ids
            }
            linked_verification_ids = {
                _comparison_text(value)
                for value in specification.verification_requirement_ids
            }

            if not linked_reference_ids.issubset(reference_ids):
                raise ValueError(
                    "An input specification has an unresolved reference."
                )

            if not linked_verification_ids.issubset(verification_ids):
                raise ValueError(
                    "An input specification has an unresolved verification "
                    "requirement."
                )

            if specification.default_input is not None:
                default_reference_ids = {
                    _comparison_text(value)
                    for value
                    in specification.default_input.source_reference_ids
                }

                if not default_reference_ids.issubset(reference_ids):
                    raise ValueError(
                        "A default input has an unresolved reference."
                    )

            if specification.default_assumption is not None:
                assumption_reference_ids = {
                    _comparison_text(value)
                    for value
                    in specification.default_assumption.source_reference_ids
                }
                assumption_verification_ids = {
                    _comparison_text(value)
                    for value in specification.default_assumption
                    .verification_requirement_ids
                }

                if not assumption_reference_ids.issubset(reference_ids):
                    raise ValueError(
                        "A default assumption has an unresolved reference."
                    )

                if not assumption_verification_ids.issubset(
                    verification_ids
                ):
                    raise ValueError(
                        "A default assumption has an unresolved verification "
                        "requirement."
                    )

        for rule in self.applicability_rules:
            if not {
                _comparison_text(value)
                for value in rule.input_ids
            }.issubset(input_ids):
                raise ValueError(
                    "An applicability rule has an unresolved input."
                )

            if not {
                _comparison_text(value)
                for value in rule.reference_ids
            }.issubset(reference_ids):
                raise ValueError(
                    "An applicability rule has an unresolved reference."
                )

            if not {
                _comparison_text(value)
                for value in rule.verification_requirement_ids
            }.issubset(verification_ids):
                raise ValueError(
                    "An applicability rule has an unresolved verification "
                    "requirement."
                )

        for requirement in self.safety_requirements:
            if not {
                _comparison_text(value)
                for value in requirement.required_input_ids
            }.issubset(input_ids):
                raise ValueError(
                    "A safety requirement has an unresolved input."
                )

            if not {
                _comparison_text(value)
                for value in requirement.reference_ids
            }.issubset(reference_ids):
                raise ValueError(
                    "A safety requirement has an unresolved reference."
                )

            if not {
                _comparison_text(value)
                for value in requirement.verification_requirement_ids
            }.issubset(verification_ids):
                raise ValueError(
                    "A safety requirement has an unresolved verification "
                    "requirement."
                )

        for formula in self.formulas:
            if not {
                _comparison_text(value)
                for value in formula.reference_ids
            }.issubset(reference_ids):
                raise ValueError(
                    "A formula has an unresolved reference."
                )

        for review in self.reviews:
            if not {
                _comparison_text(value)
                for value in review.evidence_reference_ids
            }.issubset(reference_ids):
                raise ValueError(
                    "A review has an unresolved evidence reference."
                )

        if not {
            _comparison_text(value)
            for value in self.test_vector_reference_ids
        }.issubset(reference_ids):
            raise ValueError(
                "test_vector_reference_ids contains an unresolved reference."
            )

    def _validate_approved(self, reference_ids: set[str]) -> None:
        """Require complete independent evidence before approval."""

        if not self.input_specifications:
            raise ValueError(
                "An approved method requires at least one input "
                "specification."
            )

        if not self.formulas:
            raise ValueError(
                "An approved method requires formula metadata."
            )

        if not self.references or any(
            not reference.verified
            for reference in self.references
        ):
            raise ValueError(
                "Every approved-method reference must be verified."
            )

        if not self.test_vector_reference_ids:
            raise ValueError(
                "An approved method requires verified test-vector "
                "provenance."
            )

        references_by_id = {
            _comparison_text(value.reference_id): value
            for value in self.references
        }

        for reference_id in self.test_vector_reference_ids:
            reference_key = _comparison_text(reference_id)
            reference = references_by_id[reference_key]

            if (
                reference.reference_type is not ReferenceType.TEST_VECTOR
                or not reference.verified
            ):
                raise ValueError(
                    "Approved test vectors must resolve to verified "
                    "TEST_VECTOR references."
                )

        required_review_types = set(MethodReviewType)
        reviews_by_type = {
            review.review_type: review
            for review in self.reviews
        }

        if set(reviews_by_type) != required_review_types:
            raise ValueError(
                "An approved method requires technical, safety, standards, "
                "legal-compliance, software, and final-approval reviews."
            )

        if any(not review.approved for review in self.reviews):
            raise ValueError(
                "Every review must approve an approved method."
            )

        final_review = reviews_by_type[
            MethodReviewType.FINAL_APPROVAL
        ]
        preceding_reviews = tuple(
            review
            for review in self.reviews
            if review.review_type
            is not MethodReviewType.FINAL_APPROVAL
        )

        if any(
            final_review.reviewed_at < review.reviewed_at
            for review in preceding_reviews
        ):
            raise ValueError(
                "Final approval cannot precede another required review."
            )

        formula_reference_ids = {
            _comparison_text(reference_id)
            for formula in self.formulas
            for reference_id in formula.reference_ids
        }

        if not formula_reference_ids:
            raise ValueError(
                "Approved formula metadata requires source references."
            )

        if not formula_reference_ids.issubset(reference_ids):
            raise ValueError(
                "Approved formula references must resolve."
            )

    @property
    def is_executable(self) -> bool:
        """Return whether lifecycle metadata permits execution."""

        return self.lifecycle_status is MethodLifecycleStatus.APPROVED


class TrustedExecutionEvidence(CalculationModel):
    """Server-resolved evidence supplied to the execution boundary."""

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

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        """Require unique trusted evidence identifiers."""

        _require_unique_attributes(
            self.references,
            attribute_name="reference_id",
            field_name="references",
        )
        _require_unique_attributes(
            self.verification_requirements,
            attribute_name="verification_id",
            field_name="verification_requirements",
        )

        return self


class MethodExecutionContext(CalculationModel):
    """Immutable validated data visible to one reviewed implementation.

    Rich request and provenance metadata is available for trace construction
    only.  A reviewed implementation must not branch numerical behavior on
    request IDs, timestamps, actors, design/correlation IDs, aliases, notes,
    presentation precision, input origin, option descriptions, or engine
    version.  Numerical branches are limited to the exact method version,
    canonical normalized values, material option values, assumptions, and
    resolved evidence represented by the result fingerprint.  This is a
    reviewed trusted-code boundary, not an in-process sandbox.
    """

    request: CalculationRequest
    definition: CalculationMethodDefinition
    engine_version: VersionText
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
    evidence: TrustedExecutionEvidence = Field(
        default_factory=TrustedExecutionEvidence
    )

    @field_validator("engine_version")
    @classmethod
    def validate_engine_version(cls, value: str) -> str:
        """Require the same canonical stable form used by compatibility."""

        _parse_stable_version(value)
        return value

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        """Require approved identity, compatibility, and normalized inputs."""

        if (
            _comparison_text(self.request.method_id)
            != _comparison_text(self.definition.method_id)
            or self.request.method_version
            != self.definition.method_version
            or _comparison_text(self.request.calculation_type)
            != _comparison_text(self.definition.calculation_type)
        ):
            raise ValueError(
                "Request identity does not match the method definition."
            )

        if not self.definition.is_executable:
            raise ValueError(
                "An execution context requires an approved method."
            )

        if not self.definition.engine_compatibility.supports(
            self.engine_version
        ):
            raise ValueError(
                "The method is incompatible with this engine version."
            )

        for values, attribute_name, field_name in (
            (self.normalized_inputs, "input_id", "normalized_inputs"),
            (self.defaulted_inputs, "input_id", "defaulted_inputs"),
            (self.effective_options, "option_id", "effective_options"),
            (self.assumptions, "assumption_id", "assumptions"),
        ):
            _require_unique_attributes(
                values,
                attribute_name=attribute_name,
                field_name=field_name,
            )

        specifications_by_id = {
            _comparison_text(value.input_id): value
            for value in self.definition.input_specifications
        }
        normalized_by_id = {
            _comparison_text(value.input_id): value
            for value in self.normalized_inputs
        }
        defaulted_by_id = {
            _comparison_text(value.input_id): value
            for value in self.defaulted_inputs
        }

        if not set(normalized_by_id).issubset(specifications_by_id):
            raise ValueError(
                "normalized_inputs contains an unknown input."
            )

        if not set(defaulted_by_id).issubset(normalized_by_id):
            raise ValueError(
                "Every defaulted input requires a normalized counterpart."
            )

        request_input_ids = {
            _comparison_text(value.input_id)
            for value in self.request.inputs
        }

        if not request_input_ids.issubset(normalized_by_id):
            raise ValueError(
                "Every supplied request input must be normalized."
            )

        for specification_key, specification in specifications_by_id.items():
            if (
                specification.presence is InputPresence.REQUIRED
                and specification_key not in normalized_by_id
            ):
                raise ValueError(
                    "Every required input must be normalized."
                )

            if (
                specification.presence is InputPresence.DEFAULTED
                and specification_key not in normalized_by_id
            ):
                raise ValueError(
                    "Every controlled default must be normalized."
                )

        for input_key, value in normalized_by_id.items():
            self._validate_normalized_input(
                specifications_by_id[input_key],
                value,
            )

        option_specs_by_id = {
            _comparison_text(value.option_id): value
            for value in self.definition.option_specifications
        }
        effective_options_by_id = {
            _comparison_text(value.option_id): value
            for value in self.effective_options
        }

        if not set(effective_options_by_id).issubset(option_specs_by_id):
            raise ValueError(
                "effective_options contains an unknown option."
            )

        for option_key, specification in option_specs_by_id.items():
            if (
                (
                    specification.required
                    or specification.default_option is not None
                )
                and option_key not in effective_options_by_id
            ):
                raise ValueError(
                    "Every required or defaulted option must be effective."
                )

        for option_key, option in effective_options_by_id.items():
            if not option_specs_by_id[option_key].accepts_value(option.value):
                raise ValueError(
                    "An effective option does not satisfy its schema."
                )

        return self

    @staticmethod
    def _validate_normalized_input(
        specification: MethodInputSpecification,
        value: CalculationInput,
    ) -> None:
        """Validate one normalized value without private unit bypasses."""

        if value.name != specification.name:
            raise ValueError(
                "A normalized input must preserve its specified name."
            )

        if specification.value_type is InputValueType.QUANTITY:
            if (
                value.quantity is None
                or value.categorical_value is not None
                or value.quantity.quantity_kind
                != specification.quantity_kind.value  # type: ignore[union-attr]
                or value.quantity.unit != specification.canonical_unit
            ):
                raise ValueError(
                    "A normalized quantity does not match its specification."
                )

            if (
                specification.normalization_mode
                is InputNormalizationMode.UNIT_REGISTRY
            ):
                try:
                    DEFAULT_UNIT_REGISTRY.validate_quantity(value.quantity)
                except UnitSystemError as exc:
                    raise ValueError(
                        "A normalized quantity failed registry validation."
                    ) from exc
            else:
                try:
                    expected_dimension = (
                        DEFAULT_UNIT_REGISTRY.dimension_for(
                            specification.quantity_kind  # type: ignore[arg-type]
                        )
                    )
                    actual_dimension = (
                        DEFAULT_UNIT_REGISTRY.resolve_unit(
                            value.quantity.unit
                        ).dimension
                    )
                except UnitSystemError as exc:
                    raise ValueError(
                        "A method-specific quantity has invalid unit "
                        "metadata."
                    ) from exc

                if actual_dimension is not expected_dimension:
                    raise ValueError(
                        "A method-specific quantity has the wrong dimension."
                    )

            if (
                specification.numeric_range is not None
                and not specification.numeric_range.contains(
                    value.quantity.value
                )
            ):
                raise ValueError(
                    "A normalized quantity is outside its allowed range."
                )
        else:
            if (
                value.quantity is not None
                or value.categorical_value is None
                or not specification.accepts_categorical_value(
                    value.categorical_value
                )
            ):
                raise ValueError(
                    "A normalized categorical input does not match its "
                    "specification."
                )


class MethodExecutionOutcome(CalculationModel):
    """Bounded computation data returned by reviewed implementation code.

    Method identity, lifecycle, final status, run identifiers, timestamps, and
    the result fingerprint are intentionally absent.  Only the engine may set
    those fields.
    """

    trace_steps: tuple[CalculationTraceStep, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_STEPS,
    )
    outputs: tuple[CalculationOutput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OUTPUTS,
    )
    findings: tuple[CalculationFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_FINDINGS,
    )
    assumptions: tuple[CalculationAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ASSUMPTIONS,
    )
    iteration_outcome: IterationOutcome | None = None
    limitations: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )
    exclusions: tuple[TextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TEXT_ITEMS,
    )

    @field_validator("limitations", "exclusions")
    @classmethod
    def validate_text_collections(
        cls,
        value: tuple[str, ...],
        info,
    ) -> tuple[str, ...]:
        """Reject duplicate outcome limitations or exclusions."""

        return _require_unique_strings(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        """Require bounded trace order and safe output disposition."""

        for values, attribute_name, field_name in (
            (self.trace_steps, "step_id", "trace_steps"),
            (self.outputs, "output_id", "outputs"),
            (self.findings, "finding_id", "findings"),
            (self.assumptions, "assumption_id", "assumptions"),
        ):
            _require_unique_attributes(
                values,
                attribute_name=attribute_name,
                field_name=field_name,
            )

        expected_sequences = list(range(1, len(self.trace_steps) + 1))
        actual_sequences = [
            step.sequence
            for step in self.trace_steps
        ]

        if actual_sequences != expected_sequences:
            raise ValueError(
                "trace_steps must be contiguous and ordered from 1."
            )

        blocking_findings = tuple(
            finding
            for finding in self.findings
            if finding.blocking
        )
        failed_steps = tuple(
            step
            for step in self.trace_steps
            if step.status is TraceStepStatus.FAILED
        )

        if self.outputs and (blocking_findings or failed_steps):
            raise ValueError(
                "Outputs cannot accompany blocking findings or failed trace "
                "steps."
            )

        iteration_steps = tuple(
            step
            for step in self.trace_steps
            if step.kind is TraceStepKind.ITERATION
        )

        if iteration_steps:
            if self.iteration_outcome is None:
                raise ValueError(
                    "Iteration trace steps require iteration_outcome."
                )

            iteration_numbers = [
                step.iteration_number
                for step in iteration_steps
            ]
            expected_iterations = list(
                range(1, len(iteration_steps) + 1)
            )

            if iteration_numbers != expected_iterations:
                raise ValueError(
                    "Iteration trace numbers must be contiguous from 1."
                )

            if (
                self.iteration_outcome.iterations_used
                != len(iteration_steps)
            ):
                raise ValueError(
                    "iteration_outcome must match the iteration trace count."
                )
        elif (
            self.iteration_outcome is not None
            and self.iteration_outcome.iterations_used != 0
        ):
            raise ValueError(
                "An iteration outcome reporting work requires iteration "
                "trace steps."
            )

        if self.iteration_outcome is not None:
            if self.iteration_outcome.converged:
                if not self.outputs:
                    raise ValueError(
                        "A converged outcome requires at least one output."
                    )
            elif self.outputs:
                raise ValueError(
                    "A non-converged outcome cannot contain outputs."
                )
        elif not self.outputs:
            raise ValueError(
                "A non-iterative successful outcome requires an output."
            )

        return self


__all__ = [
    "ApplicabilityRule",
    "CalculationMethodDefinition",
    "EngineCompatibility",
    "FormulaMetadata",
    "InputNormalizationMode",
    "InputPresence",
    "InputValueType",
    "IterationLimits",
    "IterationOutcome",
    "IterationTerminationReason",
    "MAX_ENGINE_ITERATIONS",
    "MethodExecutionContext",
    "MethodExecutionOutcome",
    "MethodInputSpecification",
    "MethodOptionSpecification",
    "MethodOptionValueType",
    "MethodReviewRecord",
    "MethodReviewType",
    "NumericApplicabilityRange",
    "SafetyRequirement",
    "TrustedExecutionEvidence",
]
