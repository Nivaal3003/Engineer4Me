"""Tests for strict Phase 7 calculation-method metadata models."""

from __future__ import annotations

import ast
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import app.engineering.calculations.method_models as method_models_module
from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.method_models import FormulaMetadata
from app.engineering.calculations.method_models import (
    InputNormalizationMode,
)
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import IterationLimits
from app.engineering.calculations.method_models import IterationOutcome
from app.engineering.calculations.method_models import (
    IterationTerminationReason,
)
from app.engineering.calculations.method_models import (
    MAX_ENGINE_ITERATIONS,
)
from app.engineering.calculations.method_models import (
    MethodExecutionContext,
)
from app.engineering.calculations.method_models import (
    MethodExecutionOutcome,
)
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import (
    MethodOptionSpecification,
)
from app.engineering.calculations.method_models import (
    MethodOptionValueType,
)
from app.engineering.calculations.method_models import MethodReviewRecord
from app.engineering.calculations.method_models import MethodReviewType
from app.engineering.calculations.method_models import (
    NumericApplicabilityRange,
)
from app.engineering.calculations.method_models import SafetyRequirement
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.units import QuantityKind


REVIEW_TIME = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    """Build one strict quantity."""

    return EngineeringQuantity(
        quantity_kind=kind.value,
        value=value,
        unit=unit,
    )


def verification(
    verification_id: str = "verify.method",
) -> VerificationRequirement:
    """Build one controlled verification requirement."""

    return VerificationRequirement(
        verification_id=verification_id,
        description="Independently verify the method input and result.",
        method="Repeat with an independently reviewed implementation.",
        expected_result="The independently calculated value agrees.",
        acceptance_criteria="Agreement is within the reviewed tolerance.",
        required_competency="Competent engineering reviewer",
    )


def reference(
    reference_id: str = "ref.vector",
    *,
    reference_type: ReferenceType = ReferenceType.TEST_VECTOR,
    verified: bool = True,
) -> CalculationReference:
    """Build one reference suitable for method metadata."""

    return CalculationReference(
        reference_id=reference_id,
        reference_type=reference_type,
        title=f"Reference {reference_id}",
        verified=verified,
        verified_by="Independent reviewer" if verified else None,
        verified_at=REVIEW_TIME if verified else None,
    )


def reviews(
    *,
    approved: bool = True,
    final_offset_days: int = 1,
) -> tuple[MethodReviewRecord, ...]:
    """Build all six ENG-070 review records."""

    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=approved,
            reviewer=f"{review_type.value} reviewer",
            reviewer_competency="Competent independent reviewer",
            reviewed_at=(
                REVIEW_TIME + timedelta(days=final_offset_days)
                if review_type is MethodReviewType.FINAL_APPROVAL
                else REVIEW_TIME
            ),
            evidence_reference_ids=("ref.vector",),
        )
        for review_type in MethodReviewType
    )


def length_input_specification(
    **changes: Any,
) -> MethodInputSpecification:
    """Build a required registry-normalized length input."""

    values: dict[str, Any] = {
        "input_id": "length-in",
        "name": "Length",
        "description": "Finite length supplied to the fixture method.",
        "presence": InputPresence.REQUIRED,
        "value_type": InputValueType.QUANTITY,
        "normalization_mode": InputNormalizationMode.UNIT_REGISTRY,
        "quantity_kind": QuantityKind.LENGTH,
        "canonical_unit": "m",
        "numeric_range": NumericApplicabilityRange(
            minimum=0.0,
            maximum=100.0,
        ),
    }
    values.update(changes)
    return MethodInputSpecification(**values)


def supplied_length_input(
    *,
    value: float = 1.0,
    unit: str = "m",
) -> CalculationInput:
    """Build one supplied length request input."""

    return CalculationInput(
        input_id="length-in",
        name="Length",
        origin=InputOrigin.USER_SUPPLIED,
        quantity=quantity(QuantityKind.LENGTH, value, unit),
    )


def defaulted_length_specification(
    *,
    value: float = 1.0,
    unit: str = "m",
) -> MethodInputSpecification:
    """Build a controlled default and its linked assumption."""

    assumption = CalculationAssumption(
        assumption_id="assumption.length-default",
        statement="Use the controlled default length.",
        origin=InputOrigin.DEFAULTED,
    )
    default_input = CalculationInput(
        input_id="length-in",
        name="Length",
        origin=InputOrigin.DEFAULTED,
        quantity=quantity(QuantityKind.LENGTH, value, unit),
        assumption_id=assumption.assumption_id,
    )
    return length_input_specification(
        presence=InputPresence.DEFAULTED,
        default_input=default_input,
        default_assumption=assumption,
    )


def approved_definition(
    **changes: Any,
) -> CalculationMethodDefinition:
    """Build one complete approved fixture method definition."""

    values: dict[str, Any] = {
        "method_id": "method.identity",
        "method_version": "1.0.0",
        "calculation_type": "general.identity",
        "title": "Identity fixture method",
        "description": "A deterministic reviewed method fixture.",
        "implementation_owner": "Engineer4Me",
        "lifecycle_status": MethodLifecycleStatus.APPROVED,
        "engine_compatibility": EngineCompatibility(
            minimum_version="0.4.0",
            maximum_exclusive_version="0.5.0",
        ),
        "input_specifications": (length_input_specification(),),
        "option_specifications": (),
        "applicability_rules": (),
        "safety_requirements": (),
        "formulas": (
            FormulaMetadata(
                formula_identifier="formula.identity",
                title="Identity",
                description="Return the normalized input value.",
                reference_ids=("ref.vector",),
            ),
        ),
        "references": (reference(),),
        "verification_requirements": (),
        "reviews": reviews(),
        "test_vector_reference_ids": ("ref.vector",),
        "iteration_limits": None,
        "limitations": ("Fixture use only.",),
        "exclusions": ("No physical design conclusion.",),
        "required_reviewer_competency": "Competent engineer",
        "disclaimer": "Engineering decision support only.",
    }
    values.update(changes)
    return CalculationMethodDefinition(**values)


def valid_request(
    *,
    supplied_input: CalculationInput | None = None,
    **changes: Any,
) -> CalculationRequest:
    """Build a request matching the approved fixture definition."""

    values: dict[str, Any] = {
        "calculation_type": "general.identity",
        "method_id": "method.identity",
        "method_version": "1.0.0",
        "inputs": (
            supplied_length_input()
            if supplied_input is None
            else supplied_input,
        ),
    }
    values.update(changes)
    return CalculationRequest(**values)


def valid_context(
    **changes: Any,
) -> MethodExecutionContext:
    """Build one approved, compatible execution context."""

    supplied = supplied_length_input()
    values: dict[str, Any] = {
        "request": valid_request(supplied_input=supplied),
        "definition": approved_definition(),
        "engine_version": "0.4.0",
        "normalized_inputs": (supplied,),
    }
    values.update(changes)
    return MethodExecutionContext(**values)


def trace_value() -> CalculationTraceValue:
    """Build the fixture trace value."""

    return CalculationTraceValue(
        value_id="value.result",
        name="Result",
        quantity=quantity(QuantityKind.LENGTH, 1.0, "m"),
    )


def calculation_trace_step(
    *,
    sequence: int = 1,
    status: TraceStepStatus = TraceStepStatus.COMPLETED,
) -> CalculationTraceStep:
    """Build one non-iterative calculation trace step."""

    return CalculationTraceStep(
        step_id="step.calculate",
        sequence=sequence,
        kind=TraceStepKind.CALCULATION,
        status=status,
        title="Calculate result",
        description="Return the normalized length.",
        formula_identifier="formula.identity",
        input_ids=("length-in",),
        output_values=(
            (trace_value(),)
            if status is TraceStepStatus.COMPLETED
            else ()
        ),
    )


def calculation_output() -> CalculationOutput:
    """Build a final output linked to the fixture trace."""

    return CalculationOutput(
        output_id="output.result",
        name="Result",
        quantity=quantity(QuantityKind.LENGTH, 1.0, "m"),
        source_step_ids=("step.calculate",),
        source_value_ids=("value.result",),
    )


def successful_outcome() -> MethodExecutionOutcome:
    """Build one successful non-iterative implementation outcome."""

    return MethodExecutionOutcome(
        trace_steps=(calculation_trace_step(),),
        outputs=(calculation_output(),),
    )


def blocking_finding() -> CalculationFinding:
    """Build one structurally complete blocking finding."""

    return CalculationFinding(
        finding_id="finding.blocked",
        category=FindingCategory.VALIDATION,
        severity=FindingSeverity.ERROR,
        title="Blocked",
        message="The calculation cannot safely continue.",
        blocking=True,
        required_action="Correct and independently verify the input.",
        verification_requirement_ids=("verify.method",),
    )


def test_public_enums_have_exact_values() -> None:
    assert {value.value for value in InputPresence} == {
        "required",
        "optional",
        "defaulted",
    }
    assert {value.value for value in InputValueType} == {
        "quantity",
        "categorical_boolean",
        "categorical_text",
    }
    assert {value.value for value in InputNormalizationMode} == {
        "none",
        "unit_registry",
        "method_specific",
    }
    assert {value.value for value in MethodReviewType} == {
        "technical",
        "safety",
        "standards",
        "legal_compliance",
        "software",
        "final_approval",
    }


@pytest.mark.parametrize(
    (
        "minimum",
        "maximum",
        "minimum_inclusive",
        "maximum_inclusive",
        "value",
        "expected",
    ),
    (
        (0.0, 10.0, True, True, 0.0, True),
        (0.0, 10.0, True, True, 10.0, True),
        (0.0, 10.0, False, True, 0.0, False),
        (0.0, 10.0, True, False, 10.0, False),
        (None, 10.0, True, True, -1.0e100, True),
        (0.0, None, True, True, 1.0e100, True),
        (-1.0, 1.0, True, True, -1.0001, False),
        (-1.0, 1.0, True, True, 1.0001, False),
    ),
)
def test_numeric_range_boundaries(
    minimum: float | None,
    maximum: float | None,
    minimum_inclusive: bool,
    maximum_inclusive: bool,
    value: float,
    expected: bool,
) -> None:
    range_value = NumericApplicabilityRange(
        minimum=minimum,
        maximum=maximum,
        minimum_inclusive=minimum_inclusive,
        maximum_inclusive=maximum_inclusive,
    )
    assert range_value.contains(value) is expected


@pytest.mark.parametrize(
    "value",
    (True, False, float("nan"), float("inf"), -float("inf"), "1", None),
)
def test_numeric_range_contains_rejects_non_finite_or_non_numeric(
    value: object,
) -> None:
    range_value = NumericApplicabilityRange(
        minimum=0.0,
        maximum=10.0,
    )
    assert range_value.contains(value) is False  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    (
        {},
        {"minimum": 2.0, "maximum": 1.0},
        {
            "minimum": 1.0,
            "maximum": 1.0,
            "minimum_inclusive": False,
        },
        {"maximum": 1.0, "minimum_inclusive": False},
        {"minimum": 1.0, "maximum_inclusive": False},
    ),
)
def test_numeric_range_rejects_invalid_intervals(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        NumericApplicabilityRange(**changes)


def test_valid_quantity_input_specification() -> None:
    specification = length_input_specification()
    assert specification.quantity_kind is QuantityKind.LENGTH
    assert specification.canonical_unit == "m"
    assert specification.numeric_range is not None
    assert specification.numeric_range.contains(50.0)


def test_method_specific_reference_flow_specification_is_declarative() -> None:
    specification = MethodInputSpecification(
        input_id="standard-flow",
        name="Standard volumetric flow",
        description="Flow bound to separately validated reference data.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.METHOD_SPECIFIC,
        quantity_kind=QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        canonical_unit="m3/s",
    )
    assert (
        specification.normalization_mode
        is InputNormalizationMode.METHOD_SPECIFIC
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"quantity_kind": None},
        {"canonical_unit": None},
        {"normalization_mode": InputNormalizationMode.NONE},
        {"canonical_unit": "kg"},
        {"canonical_unit": "cm"},
        {"allowed_categorical_values": ("x",)},
    ),
)
def test_quantity_input_specification_rejects_inconsistent_metadata(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        length_input_specification(**changes)


@pytest.mark.parametrize(
    ("value_type", "allowed", "case_sensitive"),
    (
        (InputValueType.CATEGORICAL_BOOLEAN, (), False),
        (InputValueType.CATEGORICAL_BOOLEAN, (True, False), False),
        (InputValueType.CATEGORICAL_TEXT, (), False),
        (InputValueType.CATEGORICAL_TEXT, ("Open", "Closed"), False),
        (InputValueType.CATEGORICAL_TEXT, ("Open", "open"), True),
    ),
)
def test_valid_categorical_input_specifications(
    value_type: InputValueType,
    allowed: tuple[bool | str, ...],
    case_sensitive: bool,
) -> None:
    specification = MethodInputSpecification(
        input_id="mode-in",
        name="Mode",
        description="Controlled categorical mode.",
        presence=InputPresence.OPTIONAL,
        value_type=value_type,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=allowed,
        categorical_case_sensitive=case_sensitive,
    )
    assert specification.allowed_categorical_values == allowed


@pytest.mark.parametrize(
    "changes",
    (
        {"quantity_kind": QuantityKind.LENGTH},
        {"canonical_unit": "m"},
        {
            "numeric_range": NumericApplicabilityRange(
                minimum=0.0,
                maximum=1.0,
            )
        },
        {"normalization_mode": InputNormalizationMode.UNIT_REGISTRY},
    ),
)
def test_categorical_input_rejects_quantity_metadata(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "input_id": "mode-in",
        "name": "Mode",
        "description": "Controlled mode.",
        "presence": InputPresence.OPTIONAL,
        "value_type": InputValueType.CATEGORICAL_TEXT,
        "normalization_mode": InputNormalizationMode.NONE,
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        MethodInputSpecification(**values)


@pytest.mark.parametrize(
    ("value_type", "allowed", "case_sensitive"),
    (
        (InputValueType.CATEGORICAL_BOOLEAN, ("true",), False),
        (InputValueType.CATEGORICAL_TEXT, (True,), False),
        (InputValueType.CATEGORICAL_BOOLEAN, (True,), True),
        (InputValueType.CATEGORICAL_TEXT, ("Open", "open"), False),
        (InputValueType.CATEGORICAL_BOOLEAN, (True, True), False),
    ),
)
def test_categorical_allow_list_is_strict_and_unambiguous(
    value_type: InputValueType,
    allowed: tuple[bool | str, ...],
    case_sensitive: bool,
) -> None:
    with pytest.raises(ValidationError):
        MethodInputSpecification(
            input_id="mode-in",
            name="Mode",
            description="Controlled mode.",
            presence=InputPresence.OPTIONAL,
            value_type=value_type,
            normalization_mode=InputNormalizationMode.NONE,
            allowed_categorical_values=allowed,
            categorical_case_sensitive=case_sensitive,
        )


def test_categorical_value_membership_honours_case_policy() -> None:
    insensitive = MethodInputSpecification(
        input_id="mode-in",
        name="Mode",
        description="Controlled mode.",
        presence=InputPresence.OPTIONAL,
        value_type=InputValueType.CATEGORICAL_TEXT,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=("Open", "Closed"),
    )
    sensitive = insensitive.model_copy(
        update={"categorical_case_sensitive": True}
    )
    assert insensitive.accepts_categorical_value("open")
    assert not sensitive.accepts_categorical_value("open")
    assert sensitive.accepts_categorical_value("Open")
    assert not insensitive.accepts_categorical_value(True)


def test_defaulted_input_and_assumption_are_linked_and_normalized() -> None:
    specification = defaulted_length_specification(
        value=100.0,
        unit="cm",
    )
    assert specification.default_input is not None
    assert specification.default_assumption is not None
    assert specification.default_input.assumption_id == (
        specification.default_assumption.assumption_id
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"default_input": None},
        {"default_assumption": None},
        {"presence": InputPresence.REQUIRED},
        {"normalization_mode": InputNormalizationMode.METHOD_SPECIFIC},
        {"safety_critical": True},
    ),
)
def test_defaulted_input_rejects_incomplete_or_unsafe_configuration(
    changes: dict[str, object],
) -> None:
    specification = defaulted_length_specification()
    values = specification.model_dump(mode="python", round_trip=True)
    values.update(changes)

    with pytest.raises(ValidationError):
        MethodInputSpecification.model_validate(values)


def test_defaulted_quantity_must_be_in_range() -> None:
    with pytest.raises(ValidationError, match="outside"):
        defaulted_length_specification(value=101.0)


def test_safety_critical_input_is_required_and_verified() -> None:
    specification = length_input_specification(
        safety_critical=True,
        verification_requirement_ids=("verify.method",),
    )
    assert specification.presence is InputPresence.REQUIRED

    for changes in (
        {"presence": InputPresence.OPTIONAL},
        {"verification_requirement_ids": ()},
    ):
        with pytest.raises(ValidationError):
            length_input_specification(
                safety_critical=True,
                **changes,
            )


@pytest.mark.parametrize(
    ("value_type", "valid", "invalid"),
    (
        (MethodOptionValueType.BOOLEAN, True, 1),
        (MethodOptionValueType.INTEGER, 1, True),
        (MethodOptionValueType.FLOAT, 1.0, 1),
        (MethodOptionValueType.TEXT, "safe", 1.0),
    ),
)
def test_option_strict_scalar_types(
    value_type: MethodOptionValueType,
    valid: bool | int | float | str,
    invalid: bool | int | float | str,
) -> None:
    specification = MethodOptionSpecification(
        option_id="fixture-option",
        description="Strict fixture option.",
        value_type=value_type,
    )
    assert specification.accepts_type(valid)
    assert not specification.accepts_type(invalid)


def test_numeric_option_range_and_default() -> None:
    specification = MethodOptionSpecification(
        option_id="iteration-count",
        description="A bounded method-owned count.",
        value_type=MethodOptionValueType.INTEGER,
        default_option=CalculationOption(
            option_id="iteration-count",
            value=10,
        ),
        allowed_values=(5, 10, 20),
        numeric_range=NumericApplicabilityRange(
            minimum=1.0,
            maximum=100.0,
        ),
    )
    assert specification.accepts_value(10)
    assert not specification.accepts_value(11)
    assert not specification.accepts_value(True)


@pytest.mark.parametrize(
    "changes",
    (
        {"required": True, "default_option": CalculationOption(
            option_id="fixture-option",
            value=1,
        )},
        {"material_for_fingerprint": False},
        {"allowed_values": (1, True)},
        {"allowed_values": (1, 1)},
        {"numeric_range": NumericApplicabilityRange(
            minimum=0.0,
            maximum=2.0,
        ), "allowed_values": (3,)},
        {"default_option": CalculationOption(
            option_id="wrong-option",
            value=1,
        )},
    ),
)
def test_option_specification_rejects_unsafe_configuration(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "option_id": "fixture-option",
        "description": "Strict fixture option.",
        "value_type": MethodOptionValueType.INTEGER,
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        MethodOptionSpecification(**values)


def test_non_numeric_option_cannot_have_numeric_range() -> None:
    with pytest.raises(ValidationError):
        MethodOptionSpecification(
            option_id="text-option",
            description="Text option.",
            value_type=MethodOptionValueType.TEXT,
            numeric_range=NumericApplicabilityRange(
                minimum=0.0,
                maximum=1.0,
            ),
        )


def test_formula_metadata_is_identifier_only_and_inert() -> None:
    malicious_text = "__import__('os').system('unsafe')"
    formula = FormulaMetadata(
        formula_identifier="formula.inert",
        title="Inert metadata",
        description=malicious_text,
        reference_ids=("ref.vector",),
    )
    assert formula.description == malicious_text
    assert set(type(formula).model_fields) == {
        "formula_identifier",
        "title",
        "description",
        "reference_ids",
    }

    with pytest.raises(ValidationError):
        FormulaMetadata(
            formula_identifier="formula.inert",
            title="Inert metadata",
            description="No expression.",
            expression="value * 2",  # type: ignore[call-arg]
        )


def test_valid_applicability_and_safety_metadata() -> None:
    applicability = ApplicabilityRule(
        rule_id="applicability.length",
        title="Length applicability",
        description="Length must remain inside the reviewed domain.",
        input_ids=("length-in",),
        severity=FindingSeverity.ERROR,
        blocking=True,
        required_action="Verify the length and method applicability.",
        verification_requirement_ids=("verify.method",),
        reference_ids=("ref.vector",),
    )
    safety = SafetyRequirement(
        requirement_id="safety.length",
        title="Length safety check",
        hazard="Unsafe geometry could invalidate the design.",
        required_input_ids=("length-in",),
        severity=FindingSeverity.CRITICAL,
        blocking=True,
        required_action="Stop and obtain competent review.",
        verification_requirement_ids=("verify.method",),
        reference_ids=("ref.vector",),
        required_competency="Competent engineer",
    )
    assert applicability.blocking
    assert safety.blocking


@pytest.mark.parametrize(
    "model_class, values",
    (
        (
            ApplicabilityRule,
            {
                "rule_id": "applicability.length",
                "title": "Length applicability",
                "description": "Reviewed applicability.",
                "input_ids": ("length-in",),
                "severity": FindingSeverity.ERROR,
                "blocking": False,
            },
        ),
        (
            ApplicabilityRule,
            {
                "rule_id": "applicability.length",
                "title": "Length applicability",
                "description": "Reviewed applicability.",
                "input_ids": ("length-in",),
                "severity": FindingSeverity.WARNING,
                "blocking": True,
                "verification_requirement_ids": ("verify.method",),
            },
        ),
        (
            SafetyRequirement,
            {
                "requirement_id": "safety.length",
                "title": "Length safety",
                "hazard": "Unsafe geometry.",
                "severity": FindingSeverity.CRITICAL,
                "blocking": False,
                "required_competency": "Competent engineer",
            },
        ),
        (
            SafetyRequirement,
            {
                "requirement_id": "safety.length",
                "title": "Length safety",
                "hazard": "Unsafe geometry.",
                "severity": FindingSeverity.WARNING,
                "blocking": True,
                "required_action": "Stop.",
                "required_competency": "Competent engineer",
            },
        ),
    ),
)
def test_blocking_rule_metadata_must_be_actionable(
    model_class: type[CalculationModelForTest],
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model_class(**values)


class CalculationModelForTest:
    """Typing-only stand-in for heterogeneous parametrized constructors."""


def test_review_timestamp_normalizes_to_utc() -> None:
    offset_time = datetime.fromisoformat("2026-07-30T14:00:00+02:00")
    review = MethodReviewRecord(
        review_id="review.technical",
        review_type=MethodReviewType.TECHNICAL,
        approved=True,
        reviewer="Reviewer",
        reviewer_competency="Competent reviewer",
        reviewed_at=offset_time,
        evidence_reference_ids=("ref.vector",),
    )
    assert review.reviewed_at == REVIEW_TIME
    assert review.reviewed_at.tzinfo is UTC


@pytest.mark.parametrize(
    ("minimum", "maximum", "supported", "unsupported"),
    (
        ("0.4.0", "0.5.0", ("0.4.0", "0.4.99"), ("0.3.99", "0.5.0")),
        ("1.2.3", "2.0.0", ("1.2.3", "1.9.9"), ("1.2.2", "2.0.0")),
    ),
)
def test_engine_compatibility_exact_boundaries(
    minimum: str,
    maximum: str,
    supported: tuple[str, ...],
    unsupported: tuple[str, ...],
) -> None:
    compatibility = EngineCompatibility(
        minimum_version=minimum,
        maximum_exclusive_version=maximum,
    )

    for version in supported:
        assert compatibility.supports(version)

    for version in (*unsupported, "1.0", "latest", "1.0.0-alpha"):
        assert not compatibility.supports(version)


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    (
        ("0.5.0", "0.5.0"),
        ("0.5.1", "0.5.0"),
        ("00.4.0", "0.5.0"),
        ("0.4", "0.5.0"),
        ("0.4.0-alpha", "0.5.0"),
    ),
)
def test_engine_compatibility_rejects_invalid_ranges(
    minimum: str,
    maximum: str,
) -> None:
    with pytest.raises(ValidationError):
        EngineCompatibility(
            minimum_version=minimum,
            maximum_exclusive_version=maximum,
        )


def test_iteration_limits_accept_absolute_relative_or_both() -> None:
    for absolute, relative in (
        (0.001, 0.0),
        (0.0, 0.001),
        (0.001, 0.001),
    ):
        limits = IterationLimits(
            maximum_iterations=25,
            absolute_tolerance=absolute,
            relative_tolerance=relative,
            convergence_value_id="residual",
            convergence_description="Converge the normalized residual.",
        )
        assert limits.maximum_iterations == 25


@pytest.mark.parametrize(
    "changes",
    (
        {"maximum_iterations": 0},
        {"maximum_iterations": MAX_ENGINE_ITERATIONS + 1},
        {"absolute_tolerance": 0.0, "relative_tolerance": 0.0},
        {"absolute_tolerance": -1.0},
        {"relative_tolerance": -1.0},
        {"relative_tolerance": 1.0001},
        {"divergence_limit": 0.0},
    ),
)
def test_iteration_limits_reject_invalid_bounds(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "maximum_iterations": 25,
        "absolute_tolerance": 0.001,
        "relative_tolerance": 0.0,
        "convergence_value_id": "residual",
        "convergence_description": "Converge the residual.",
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        IterationLimits(**values)


@pytest.mark.parametrize(
    ("iterations", "converged", "reason", "valid"),
    (
        (1, True, IterationTerminationReason.CONVERGED, True),
        (0, True, IterationTerminationReason.CONVERGED, False),
        (1, False, IterationTerminationReason.CONVERGED, False),
        (
            25,
            False,
            IterationTerminationReason.MAXIMUM_ITERATIONS,
            True,
        ),
        (
            0,
            False,
            IterationTerminationReason.MAXIMUM_ITERATIONS,
            False,
        ),
        (0, False, IterationTerminationReason.NON_FINITE_VALUE, True),
        (3, False, IterationTerminationReason.DIVERGED, True),
    ),
)
def test_iteration_outcome_state_invariants(
    iterations: int,
    converged: bool,
    reason: IterationTerminationReason,
    valid: bool,
) -> None:
    values = {
        "iterations_used": iterations,
        "converged": converged,
        "termination_reason": reason,
        "final_residual": 0.001,
        "description": "Deterministic iteration termination.",
    }

    if valid:
        assert IterationOutcome(**values).iterations_used == iterations
    else:
        with pytest.raises(ValidationError):
            IterationOutcome(**values)


def test_complete_approved_definition_is_executable() -> None:
    definition = approved_definition()
    assert definition.is_executable
    assert definition.lifecycle_status is MethodLifecycleStatus.APPROVED
    assert {review.review_type for review in definition.reviews} == set(
        MethodReviewType
    )
    assert definition.test_vector_reference_ids == ("ref.vector",)


@pytest.mark.parametrize(
    "version",
    (
        "1.0",
        "01.0.0",
        "1.00.0",
        "1.0.00",
        "v1.0.0",
        "latest",
        "1.0.0-01",
        "1.0.0-alpha..1",
        "1.0.0-alpha.",
        "1.0.0+build..1",
        "1.0.0+build.",
    ),
)
def test_method_version_requires_canonical_semver(version: str) -> None:
    with pytest.raises(ValidationError):
        approved_definition(method_version=version)


@pytest.mark.parametrize(
    "version",
    (
        "0.0.0",
        "1.0.0-0",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-01a",
        "1.0.0+build.01",
        "1.0.0-alpha.1+build.5",
    ),
)
def test_method_version_accepts_canonical_semver(version: str) -> None:
    assert approved_definition(method_version=version).method_version == version


@pytest.mark.parametrize(
    "lifecycle",
    (
        MethodLifecycleStatus.DRAFT,
        MethodLifecycleStatus.TECHNICAL_REVIEW,
        MethodLifecycleStatus.SAFETY_REVIEW,
        MethodLifecycleStatus.STANDARDS_REVIEW,
    ),
)
def test_nonapproved_review_lifecycle_is_not_executable(
    lifecycle: MethodLifecycleStatus,
) -> None:
    definition = approved_definition(lifecycle_status=lifecycle)
    assert not definition.is_executable


@pytest.mark.parametrize(
    ("current", "target"),
    (
        ("1.0.0", "1.0.1"),
        ("1.0.0", "1.1.0"),
        ("1.0.0-alpha", "1.0.0"),
        ("1.0.0-alpha.1", "1.0.0-alpha.2"),
    ),
)
def test_superseded_method_requires_newer_semver(
    current: str,
    target: str,
) -> None:
    definition = approved_definition(
        method_version=current,
        lifecycle_status=MethodLifecycleStatus.SUPERSEDED,
        superseded_by_version=target,
    )
    assert not definition.is_executable
    assert definition.superseded_by_version == target


@pytest.mark.parametrize(
    "target",
    (
        None,
        "0.9.9",
        "1.0.0",
        "1.0.0+metadata",
        "01.1.0",
    ),
)
def test_superseded_method_rejects_missing_or_non_newer_version(
    target: str | None,
) -> None:
    with pytest.raises(ValidationError):
        approved_definition(
            lifecycle_status=MethodLifecycleStatus.SUPERSEDED,
            superseded_by_version=target,
        )


def test_disabled_method_requires_reason() -> None:
    disabled = approved_definition(
        lifecycle_status=MethodLifecycleStatus.DISABLED,
        disabled_reason="Disabled after a controlled engineering review.",
    )
    assert not disabled.is_executable

    with pytest.raises(ValidationError):
        approved_definition(
            lifecycle_status=MethodLifecycleStatus.DISABLED,
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"disabled_reason": "Not valid for approved."},
        {"superseded_by_version": "1.0.1"},
        {
            "lifecycle_status": MethodLifecycleStatus.DISABLED,
            "disabled_reason": "Disabled.",
            "superseded_by_version": "1.0.1",
        },
        {
            "lifecycle_status": MethodLifecycleStatus.SUPERSEDED,
            "superseded_by_version": "1.0.1",
            "disabled_reason": "Contradictory.",
        },
    ),
)
def test_terminal_lifecycle_metadata_cannot_be_contradictory(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        approved_definition(**changes)


@pytest.mark.parametrize(
    "changes",
    (
        {"input_specifications": ()},
        {"formulas": ()},
        {"references": ()},
        {"test_vector_reference_ids": ()},
        {"reviews": reviews()[:-1]},
        {
            "reviews": tuple(
                review.model_copy(update={"approved": False})
                if review.review_type is MethodReviewType.SOFTWARE
                else review
                for review in reviews()
            )
        },
        {"reviews": reviews(final_offset_days=-1)},
    ),
)
def test_approved_method_requires_complete_review_evidence(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        approved_definition(**changes)


def test_approved_method_requires_verified_test_vector_reference() -> None:
    with pytest.raises(ValidationError):
        approved_definition(
            references=(reference(verified=False),),
        )

    with pytest.raises(ValidationError):
        approved_definition(
            references=(
                reference(
                    reference_type=ReferenceType.ENGINEERING_TEXTBOOK,
                ),
            ),
        )


def test_approved_formula_requires_source_reference() -> None:
    formula = FormulaMetadata(
        formula_identifier="formula.identity",
        title="Identity",
        description="Identity formula.",
    )

    with pytest.raises(ValidationError, match="source references"):
        approved_definition(formulas=(formula,))


@pytest.mark.parametrize(
    "collection_name, replacement",
    (
        (
            "input_specifications",
            (
                length_input_specification(),
                length_input_specification(name="Length duplicate"),
            ),
        ),
        (
            "formulas",
            (
                FormulaMetadata(
                    formula_identifier="formula.identity",
                    title="Identity",
                    description="Identity formula.",
                    reference_ids=("ref.vector",),
                ),
                FormulaMetadata(
                    formula_identifier="FORMULA.IDENTITY",
                    title="Duplicate",
                    description="Duplicate identity formula.",
                    reference_ids=("ref.vector",),
                ),
            ),
        ),
        (
            "references",
            (
                reference(),
                reference("REF.VECTOR"),
            ),
        ),
        (
            "reviews",
            (
                *reviews(),
                MethodReviewRecord(
                    review_id="review.duplicate",
                    review_type=MethodReviewType.TECHNICAL,
                    approved=True,
                    reviewer="Duplicate reviewer",
                    reviewer_competency="Competent reviewer",
                    reviewed_at=REVIEW_TIME,
                    evidence_reference_ids=("ref.vector",),
                ),
            ),
        ),
    ),
)
def test_definition_rejects_casefold_duplicate_nested_ids(
    collection_name: str,
    replacement: tuple[object, ...],
) -> None:
    with pytest.raises(ValidationError):
        approved_definition(**{collection_name: replacement})


def test_input_and_option_ids_cannot_collide() -> None:
    option = MethodOptionSpecification(
        option_id="LENGTH-IN",
        description="Colliding option.",
        value_type=MethodOptionValueType.BOOLEAN,
    )

    with pytest.raises(ValidationError, match="must not collide"):
        approved_definition(option_specifications=(option,))


@pytest.mark.parametrize(
    "option_id",
    (
        "maximum_iterations",
        "absolute_tolerance",
        "relative_tolerance",
        "method_id",
        "method_version",
        "engine_version",
    ),
)
def test_request_options_cannot_override_engine_controls(
    option_id: str,
) -> None:
    option = MethodOptionSpecification(
        option_id=option_id,
        description="Prohibited engine control.",
        value_type=MethodOptionValueType.INTEGER,
    )

    with pytest.raises(ValidationError, match="cannot be request options"):
        approved_definition(option_specifications=(option,))


def test_definition_resolves_input_rule_and_safety_links() -> None:
    requirement = verification()
    specification = length_input_specification(
        safety_critical=True,
        verification_requirement_ids=(requirement.verification_id,),
        reference_ids=("ref.vector",),
    )
    applicability = ApplicabilityRule(
        rule_id="applicability.length",
        title="Length applicability",
        description="Length must remain applicable.",
        input_ids=(specification.input_id,),
        required_action="Verify method applicability.",
        verification_requirement_ids=(requirement.verification_id,),
        reference_ids=("ref.vector",),
    )
    safety = SafetyRequirement(
        requirement_id="safety.length",
        title="Length hazard",
        hazard="Invalid geometry could be unsafe.",
        required_input_ids=(specification.input_id,),
        required_action="Stop and verify geometry.",
        verification_requirement_ids=(requirement.verification_id,),
        reference_ids=("ref.vector",),
        required_competency="Competent engineer",
    )
    definition = approved_definition(
        input_specifications=(specification,),
        applicability_rules=(applicability,),
        safety_requirements=(safety,),
        verification_requirements=(requirement,),
    )
    assert definition.applicability_rules == (applicability,)
    assert definition.safety_requirements == (safety,)


@pytest.mark.parametrize(
    "change",
    (
        {
            "input_specifications": (
                length_input_specification(
                    reference_ids=("missing.reference",)
                ),
            )
        },
        {
            "input_specifications": (
                length_input_specification(
                    safety_critical=True,
                    verification_requirement_ids=("missing.verify",),
                ),
            )
        },
        {
            "applicability_rules": (
                ApplicabilityRule(
                    rule_id="applicability.unknown",
                    title="Unknown input",
                    description="References an unknown input.",
                    input_ids=("unknown-input",),
                    required_action="Verify.",
                    verification_requirement_ids=("verify.method",),
                ),
            ),
            "verification_requirements": (verification(),),
        },
        {
            "formulas": (
                FormulaMetadata(
                    formula_identifier="formula.identity",
                    title="Identity",
                    description="Identity formula.",
                    reference_ids=("missing.reference",),
                ),
            )
        },
        {"test_vector_reference_ids": ("missing.reference",)},
    ),
)
def test_definition_rejects_unresolved_links(
    change: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        approved_definition(**change)


def test_definition_and_nested_models_round_trip_json() -> None:
    definition = approved_definition()
    restored = CalculationMethodDefinition.model_validate_json(
        definition.model_dump_json()
    )
    assert restored == definition
    assert restored.model_dump(mode="json") == definition.model_dump(
        mode="json"
    )


@pytest.mark.parametrize(
    "model",
    (
        NumericApplicabilityRange(minimum=0.0, maximum=1.0),
        length_input_specification(),
        MethodOptionSpecification(
            option_id="fixture-option",
            description="Fixture option.",
            value_type=MethodOptionValueType.BOOLEAN,
        ),
        EngineCompatibility(
            minimum_version="0.4.0",
            maximum_exclusive_version="0.5.0",
        ),
        IterationLimits(
            maximum_iterations=10,
            absolute_tolerance=0.001,
            convergence_value_id="residual",
            convergence_description="Converge residual.",
        ),
        approved_definition(),
    ),
)
def test_models_are_frozen_and_delete_safe(model: object) -> None:
    first_field = next(iter(type(model).model_fields))  # type: ignore[attr-defined]

    with pytest.raises(ValidationError):
        setattr(model, first_field, None)

    with pytest.raises(ValidationError):
        delattr(model, first_field)


def test_validated_model_copy_rejects_invalid_update() -> None:
    definition = approved_definition()

    with pytest.raises(ValidationError):
        definition.model_copy(
            update={"method_version": "latest"}
        )

    with pytest.raises(ValidationError):
        length_input_specification().model_copy(
            update={"canonical_unit": "kg"}
        )


def test_tuple_fields_reject_unordered_sets() -> None:
    values = approved_definition().model_dump(
        mode="python",
        round_trip=True,
    )
    values["test_vector_reference_ids"] = {"ref.vector"}

    with pytest.raises(ValidationError):
        CalculationMethodDefinition.model_validate(values)


def test_trusted_evidence_requires_unique_ids_and_round_trips() -> None:
    evidence = TrustedExecutionEvidence(
        references=(reference(),),
        verification_requirements=(verification(),),
    )
    restored = TrustedExecutionEvidence.model_validate_json(
        evidence.model_dump_json()
    )
    assert restored == evidence

    with pytest.raises(ValidationError):
        TrustedExecutionEvidence(
            references=(reference(), reference("REF.VECTOR")),
        )


def test_valid_execution_context() -> None:
    context = valid_context()
    assert context.definition.is_executable
    assert context.engine_version == "0.4.0"
    assert context.normalized_inputs[0].quantity is not None
    assert context.normalized_inputs[0].quantity.unit == "m"


@pytest.mark.parametrize(
    "request_changes",
    (
        {"method_id": "method.other"},
        {"method_version": "1.0.1"},
        {"calculation_type": "general.other"},
    ),
)
def test_context_requires_exact_request_identity(
    request_changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="identity"):
        valid_context(request=valid_request(**request_changes))


def test_context_requires_approved_compatible_definition() -> None:
    with pytest.raises(ValidationError, match="approved"):
        valid_context(
            definition=approved_definition(
                lifecycle_status=MethodLifecycleStatus.DRAFT
            )
        )

    with pytest.raises(ValidationError, match="incompatible"):
        valid_context(engine_version="0.5.0")


def test_context_requires_every_supplied_and_required_input_normalized() -> None:
    with pytest.raises(ValidationError):
        valid_context(normalized_inputs=())

    unknown = CalculationInput(
        input_id="unknown-input",
        name="Unknown input",
        origin=InputOrigin.SYSTEM_DERIVED,
        quantity=quantity(QuantityKind.LENGTH, 1.0, "m"),
        source_trace_step_ids=("step.source",),
    )

    with pytest.raises(ValidationError, match="unknown"):
        valid_context(
            normalized_inputs=(
                supplied_length_input(),
                unknown,
            )
        )


@pytest.mark.parametrize(
    "normalized",
    (
        CalculationInput(
            input_id="length-in",
            name="Wrong name",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=quantity(QuantityKind.LENGTH, 1.0, "m"),
        ),
        CalculationInput(
            input_id="length-in",
            name="Length",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=quantity(QuantityKind.MASS, 1.0, "kg"),
        ),
        CalculationInput(
            input_id="length-in",
            name="Length",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=quantity(QuantityKind.LENGTH, 100.0, "cm"),
        ),
        CalculationInput(
            input_id="length-in",
            name="Length",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=quantity(QuantityKind.LENGTH, 101.0, "m"),
        ),
    ),
)
def test_context_rejects_noncanonical_or_out_of_range_input(
    normalized: CalculationInput,
) -> None:
    with pytest.raises(ValidationError):
        valid_context(normalized_inputs=(normalized,))


def test_context_allows_method_specific_reference_flow_without_private_bypass(
) -> None:
    specification = MethodInputSpecification(
        input_id="standard-flow",
        name="Standard flow",
        description="Flow validated with explicit reference conditions.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.METHOD_SPECIFIC,
        quantity_kind=QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        canonical_unit="m3/s",
    )
    flow_input = CalculationInput(
        input_id="standard-flow",
        name="Standard flow",
        origin=InputOrigin.USER_SUPPLIED,
        quantity=quantity(
            QuantityKind.STANDARD_VOLUMETRIC_FLOW,
            1.0,
            "m3/s",
        ),
    )
    definition = approved_definition(
        input_specifications=(specification,),
    )
    request = valid_request(
        inputs=(flow_input,),
    )
    context = MethodExecutionContext(
        request=request,
        definition=definition,
        engine_version="0.4.0",
        normalized_inputs=(flow_input,),
    )
    assert context.normalized_inputs == (flow_input,)


def test_context_validates_effective_option_schema() -> None:
    option_specification = MethodOptionSpecification(
        option_id="solver-pass",
        description="Reviewed fixture solver pass.",
        value_type=MethodOptionValueType.INTEGER,
        required=True,
        allowed_values=(1, 2),
    )
    definition = approved_definition(
        option_specifications=(option_specification,),
    )
    supplied = supplied_length_input()
    request = valid_request(
        supplied_input=supplied,
        options=(
            CalculationOption(
                option_id="solver-pass",
                value=1,
            ),
        ),
    )
    context = MethodExecutionContext(
        request=request,
        definition=definition,
        engine_version="0.4.0",
        normalized_inputs=(supplied,),
        effective_options=request.options,
    )
    assert context.effective_options[0].value == 1

    with pytest.raises(ValidationError):
        MethodExecutionContext(
            request=request,
            definition=definition,
            engine_version="0.4.0",
            normalized_inputs=(supplied,),
            effective_options=(
                CalculationOption(
                    option_id="solver-pass",
                    value=3,
                ),
            ),
        )


def test_context_round_trips_json() -> None:
    context = valid_context()
    restored = MethodExecutionContext.model_validate_json(
        context.model_dump_json()
    )
    assert restored == context


def test_successful_noniterative_outcome() -> None:
    outcome = successful_outcome()
    assert len(outcome.trace_steps) == 1
    assert len(outcome.outputs) == 1
    assert outcome.iteration_outcome is None


def iteration_trace_step(
    iteration_number: int,
    *,
    status: TraceStepStatus = TraceStepStatus.COMPLETED,
) -> CalculationTraceStep:
    """Build one contiguous iteration trace step."""

    value = CalculationTraceValue(
        value_id=f"value.iteration-{iteration_number}",
        name=f"Iteration {iteration_number}",
        quantity=quantity(
            QuantityKind.DIMENSIONLESS,
            1.0 / iteration_number,
            "1",
        ),
    )
    return CalculationTraceStep(
        step_id=f"step.iteration-{iteration_number}",
        sequence=iteration_number,
        kind=TraceStepKind.ITERATION,
        status=status,
        title=f"Iteration {iteration_number}",
        description="One deterministic bounded iteration.",
        formula_identifier="formula.identity",
        output_values=(
            (value,)
            if status is TraceStepStatus.COMPLETED
            else ()
        ),
        iteration_number=iteration_number,
    )


def iteration_output(iteration_number: int) -> CalculationOutput:
    """Build output linked to a completed iteration."""

    return CalculationOutput(
        output_id="output.iteration",
        name="Iteration result",
        quantity=quantity(
            QuantityKind.DIMENSIONLESS,
            1.0 / iteration_number,
            "1",
        ),
        source_step_ids=(f"step.iteration-{iteration_number}",),
        source_value_ids=(f"value.iteration-{iteration_number}",),
    )


def test_converged_iteration_outcome_matches_trace() -> None:
    outcome = MethodExecutionOutcome(
        trace_steps=(
            iteration_trace_step(1),
            iteration_trace_step(2),
        ),
        outputs=(iteration_output(2),),
        iteration_outcome=IterationOutcome(
            iterations_used=2,
            converged=True,
            termination_reason=IterationTerminationReason.CONVERGED,
            final_residual=0.001,
            description="Converged on the second iteration.",
        ),
    )
    assert outcome.iteration_outcome is not None
    assert outcome.iteration_outcome.iterations_used == 2


def test_nonconverged_iteration_has_no_outputs() -> None:
    outcome = MethodExecutionOutcome(
        trace_steps=(
            iteration_trace_step(
                1,
                status=TraceStepStatus.FAILED,
            ),
        ),
        iteration_outcome=IterationOutcome(
            iterations_used=1,
            converged=False,
            termination_reason=(
                IterationTerminationReason.MAXIMUM_ITERATIONS
            ),
            final_residual=1.0,
            description="The reviewed iteration limit was reached.",
        ),
    )
    assert not outcome.outputs


@pytest.mark.parametrize(
    "changes",
    (
        {"trace_steps": (calculation_trace_step(sequence=2),)},
        {"outputs": ()},
        {
            "trace_steps": (
                calculation_trace_step(
                    status=TraceStepStatus.FAILED
                ),
            )
        },
        {"findings": (blocking_finding(),)},
    ),
)
def test_noniterative_outcome_rejects_invalid_success_state(
    changes: dict[str, object],
) -> None:
    values = successful_outcome().model_dump(
        mode="python",
        round_trip=True,
    )
    values.update(changes)

    with pytest.raises(ValidationError):
        MethodExecutionOutcome.model_validate(values)


def test_iteration_trace_requires_matching_outcome_and_count() -> None:
    with pytest.raises(ValidationError, match="iteration_outcome"):
        MethodExecutionOutcome(
            trace_steps=(iteration_trace_step(1),),
            outputs=(iteration_output(1),),
        )

    with pytest.raises(ValidationError, match="trace count"):
        MethodExecutionOutcome(
            trace_steps=(iteration_trace_step(1),),
            outputs=(iteration_output(1),),
            iteration_outcome=IterationOutcome(
                iterations_used=2,
                converged=True,
                termination_reason=IterationTerminationReason.CONVERGED,
                final_residual=0.0,
                description="Inconsistent iteration count.",
            ),
        )


def test_iteration_numbers_must_be_contiguous() -> None:
    second = iteration_trace_step(2).model_copy(
        update={"sequence": 1}
    )

    with pytest.raises(ValidationError, match="Iteration trace numbers"):
        MethodExecutionOutcome(
            trace_steps=(second,),
            outputs=(iteration_output(2),),
            iteration_outcome=IterationOutcome(
                iterations_used=1,
                converged=True,
                termination_reason=IterationTerminationReason.CONVERGED,
                final_residual=0.0,
                description="Invalid first iteration number.",
            ),
        )


def test_outcome_has_no_identity_status_or_fingerprint_fields() -> None:
    prohibited_fields = {
        "calculation_id",
        "request_id",
        "method_id",
        "method_version",
        "lifecycle_status",
        "status",
        "result_fingerprint",
        "executed_at",
    }
    assert prohibited_fields.isdisjoint(
        MethodExecutionOutcome.model_fields
    )

    with pytest.raises(ValidationError):
        MethodExecutionOutcome(
            trace_steps=(calculation_trace_step(),),
            outputs=(calculation_output(),),
            status="completed",  # type: ignore[call-arg]
        )


def test_bypass_constructed_nested_definition_is_revalidated() -> None:
    bypassed = CalculationMethodDefinition.model_construct(
        **{
            **approved_definition().model_dump(
                mode="python",
                round_trip=True,
                warnings="none",
            ),
            "method_version": "latest",
        }
    )

    with pytest.raises(ValidationError):
        CalculationMethodDefinition.model_validate(
            bypassed.model_dump(
                mode="python",
                round_trip=True,
                warnings="none",
            )
        )


def test_method_model_source_has_no_dynamic_execution_path() -> None:
    source_path = Path(method_models_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    prohibited_calls = {
        "__import__",
        "compile",
        "eval",
        "exec",
    }
    prohibited_import_roots = {
        "importlib",
        "subprocess",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in prohibited_calls

        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".", 1)[0]
                not in prohibited_import_roots
                for alias in node.names
            )

        if isinstance(node, ast.ImportFrom) and node.module is not None:
            assert (
                node.module.split(".", 1)[0]
                not in prohibited_import_roots
            )


def test_public_models_have_no_dynamic_dispatch_fields() -> None:
    prohibited_field_names = {
        "callable",
        "callable_name",
        "code",
        "entry_point",
        "expression",
        "formula_text",
        "module",
        "module_path",
        "script",
    }

    for public_name in method_models_module.__all__:
        public_value = getattr(method_models_module, public_name)
        model_fields = getattr(public_value, "model_fields", {})
        assert prohibited_field_names.isdisjoint(model_fields)


def test_public_exports_are_exact_and_unique() -> None:
    expected = {
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
    }
    assert set(method_models_module.__all__) == expected
    assert len(method_models_module.__all__) == len(
        set(method_models_module.__all__)
    )

    for public_name in expected:
        assert hasattr(method_models_module, public_name)
