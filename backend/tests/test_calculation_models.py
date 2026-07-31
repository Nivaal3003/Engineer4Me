"""Independent substantive review tests for Phase 7 Step 90 models.

This draft intentionally lives outside the Step 90 payload.  It validates the
locked ``models.py`` contract as an independent review artifact.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

import app.engineering.calculations as calculations_package
import app.engineering.calculations.models as calculation_models
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement


FIXED_TIME = datetime(2026, 7, 30, 12, 0, 0, tzinfo=UTC)
FIXED_REQUEST_ID = UUID("00000000-0000-0000-0000-000000000001")
FIXED_CALCULATION_ID = UUID("00000000-0000-0000-0000-000000000002")
VALID_FINGERPRINT = "a" * 64
MAX_NUMBER = calculation_models.MAX_ABSOLUTE_OPTION_NUMBER


def make_quantity(**changes: Any) -> EngineeringQuantity:
    """Create a valid quantity with deterministic defaults."""

    values: dict[str, Any] = {
        "quantity_kind": "pressure-gauge",
        "value": 10.0,
        "unit": "bar",
    }
    values.update(changes)
    return EngineeringQuantity(**values)


def make_input(**changes: Any) -> CalculationInput:
    """Create a valid user-supplied quantitative input."""

    values: dict[str, Any] = {
        "input_id": "pressure-in",
        "name": "Pressure input",
        "origin": InputOrigin.USER_SUPPLIED,
        "quantity": make_quantity(),
    }
    values.update(changes)
    return CalculationInput(**values)


def make_option(**changes: Any) -> CalculationOption:
    """Create a valid bounded execution option."""

    values: dict[str, Any] = {
        "option_id": "iteration-limit",
        "value": 25,
        "description": "Maximum controlled iterations.",
    }
    values.update(changes)
    return CalculationOption(**values)


def make_verification(**changes: Any) -> VerificationRequirement:
    """Create a valid verification requirement."""

    values: dict[str, Any] = {
        "verification_id": "verify-1",
        "description": "Independently check the source data.",
        "method": "Compare the value with the approved source.",
        "expected_result": "The values agree within the stated tolerance.",
        "required_competency": "Competent instrumentation engineer",
    }
    values.update(changes)
    return VerificationRequirement(**values)


def make_assumption(**changes: Any) -> CalculationAssumption:
    """Create a valid non-critical assumption."""

    values: dict[str, Any] = {
        "assumption_id": "assumption-1",
        "statement": "The process is at steady state.",
        "origin": InputOrigin.USER_SUPPLIED,
    }
    values.update(changes)
    return CalculationAssumption(**values)


def make_missing_input(**changes: Any) -> MissingCalculationInput:
    """Create one valid required missing input."""

    values: dict[str, Any] = {
        "input_id": "density-in",
        "name": "Fluid density",
        "reason": "Fluid density was not supplied.",
        "required_for_execution": True,
        "safety_critical": False,
        "expected_unit": "kg/m3",
    }
    values.update(changes)
    return MissingCalculationInput(**values)


def make_reference(**changes: Any) -> CalculationReference:
    """Create one valid uncontrolled user-document reference."""

    values: dict[str, Any] = {
        "reference_id": "reference-1",
        "reference_type": ReferenceType.USER_DOCUMENT,
        "title": "Approved process datasheet",
        "source_location": "Controlled document repository",
    }
    values.update(changes)
    return CalculationReference(**values)


def make_trace_value(**changes: Any) -> CalculationTraceValue:
    """Create one valid numerical trace value."""

    values: dict[str, Any] = {
        "value_id": "trace-pressure",
        "name": "Calculated pressure",
        "quantity": make_quantity(),
    }
    values.update(changes)
    return CalculationTraceValue(**values)


def make_trace_step(**changes: Any) -> CalculationTraceStep:
    """Create one valid completed calculation trace step."""

    values: dict[str, Any] = {
        "step_id": "step-1",
        "sequence": 1,
        "kind": TraceStepKind.CALCULATION,
        "status": TraceStepStatus.COMPLETED,
        "title": "Calculate pressure",
        "description": "Apply the reviewed pressure calculation.",
        "formula_identifier": "formula.pressure-1",
        "input_ids": ("pressure-in",),
        "output_values": (make_trace_value(),),
    }
    values.update(changes)
    return CalculationTraceStep(**values)


def make_output(**changes: Any) -> CalculationOutput:
    """Create one valid numerical result output."""

    values: dict[str, Any] = {
        "output_id": "pressure-out",
        "name": "Pressure output",
        "quantity": make_quantity(),
        "source_step_ids": ("step-1",),
        "source_value_ids": ("trace-pressure",),
    }
    values.update(changes)
    return CalculationOutput(**values)


def make_finding(**changes: Any) -> CalculationFinding:
    """Create one valid non-blocking warning finding."""

    values: dict[str, Any] = {
        "finding_id": "finding-1",
        "category": FindingCategory.GENERAL,
        "severity": FindingSeverity.WARNING,
        "title": "Review recommended",
        "message": "The result should be independently reviewed.",
        "blocking": False,
    }
    values.update(changes)
    return CalculationFinding(**values)


def make_blocking_finding(
    *,
    category: FindingCategory = FindingCategory.SAFETY,
    severity: FindingSeverity = FindingSeverity.WARNING,
    finding_id: str = "blocking-1",
) -> CalculationFinding:
    """Create a valid actionable blocking finding."""

    return CalculationFinding(
        finding_id=finding_id,
        category=category,
        severity=severity,
        title="Execution blocked",
        message="A required engineering condition has not been satisfied.",
        blocking=True,
        required_action="Resolve the condition before using a result.",
        verification_requirement_ids=("verify-1",),
    )


def make_request(**changes: Any) -> CalculationRequest:
    """Create a deterministic valid request."""

    values: dict[str, Any] = {
        "request_id": FIXED_REQUEST_ID,
        "calculation_type": "pressure-test",
        "method_id": "method.pressure",
        "method_version": "1.0.0",
        "requested_at": FIXED_TIME,
    }
    values.update(changes)
    return CalculationRequest(**values)


def make_completed_graph() -> dict[str, tuple[Any, ...]]:
    """Return the valid supplied/normalized/trace/output result graph."""

    supplied_input = make_input()
    normalized_input = make_input()
    trace_step = make_trace_step()
    output = make_output()
    return {
        "supplied_inputs": (supplied_input,),
        "normalized_inputs": (normalized_input,),
        "trace_steps": (trace_step,),
        "outputs": (output,),
    }


def make_result(
    status: CalculationStatus = CalculationStatus.COMPLETED,
    **changes: Any,
) -> CalculationResult:
    """Create a valid deterministic result for any supported status."""

    values: dict[str, Any] = {
        "calculation_id": FIXED_CALCULATION_ID,
        "request_id": FIXED_REQUEST_ID,
        "calculation_type": "pressure-test",
        "method_id": "method.pressure",
        "method_version": "1.0.0",
        "method_lifecycle_status": MethodLifecycleStatus.APPROVED,
        "engine_version": "1.0.0",
        "executed_at": FIXED_TIME,
        "status": status,
        "result_fingerprint": VALID_FINGERPRINT,
        "required_reviewer_competency": (
            "Competent instrumentation engineer"
        ),
    }

    if status in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }:
        values.update(make_completed_graph())

    if status == CalculationStatus.COMPLETED_WITH_WARNINGS:
        values["findings"] = (make_finding(),)
    elif status == CalculationStatus.BLOCKED:
        values["findings"] = (make_blocking_finding(),)
        values["verification_requirements"] = (make_verification(),)
    elif status == CalculationStatus.INSUFFICIENT_INPUT:
        values["missing_inputs"] = (make_missing_input(),)
    elif status == CalculationStatus.NOT_APPLICABLE:
        values["findings"] = (
            make_blocking_finding(
                category=FindingCategory.APPLICABILITY,
            ),
        )
        values["verification_requirements"] = (make_verification(),)
    elif status == CalculationStatus.FAILED:
        values["findings"] = (
            make_blocking_finding(
                category=FindingCategory.NUMERICAL,
                severity=FindingSeverity.ERROR,
            ),
        )
        values["verification_requirements"] = (make_verification(),)

    values.update(changes)
    return CalculationResult(**values)


def assert_validation_error(factory) -> ValidationError:
    """Run a factory and return its expected Pydantic validation error."""

    with pytest.raises(ValidationError) as error_info:
        factory()

    return error_info.value


# ---------------------------------------------------------------------------
# A. Public contracts and valid result object graphs: 16 collected cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("enum_type", "expected_values"),
    [
        pytest.param(
            InputOrigin,
            {
                "user_supplied",
                "document_extracted",
                "defaulted",
                "system_derived",
                "calculated",
                "selected",
                "imported",
            },
            id="input-origin",
        ),
        pytest.param(
            CalculationStatus,
            {
                "completed",
                "completed_with_warnings",
                "blocked",
                "insufficient_input",
                "not_applicable",
                "failed",
            },
            id="calculation-status",
        ),
        pytest.param(
            MethodLifecycleStatus,
            {
                "draft",
                "technical_review",
                "safety_review",
                "standards_review",
                "approved",
                "superseded",
                "disabled",
            },
            id="method-lifecycle",
        ),
        pytest.param(
            FindingCategory,
            {
                "validation",
                "applicability",
                "safety",
                "data_quality",
                "standards",
                "legal_compliance",
                "numerical",
                "general",
            },
            id="finding-category",
        ),
        pytest.param(
            FindingSeverity,
            {"information", "caution", "warning", "error", "critical"},
            id="finding-severity",
        ),
        pytest.param(
            TraceStepKind,
            {
                "validation",
                "normalization",
                "assumption",
                "calculation",
                "iteration",
                "decision",
                "output",
            },
            id="trace-kind",
        ),
        pytest.param(
            TraceStepStatus,
            {"completed", "skipped", "failed"},
            id="trace-status",
        ),
        pytest.param(
            ReferenceType,
            {
                "engineering_knowledge",
                "international_standard",
                "national_standard",
                "company_standard",
                "regulation",
                "oem_manual",
                "oem_datasheet",
                "engineering_textbook",
                "peer_reviewed_paper",
                "technical_report",
                "test_vector",
                "calculation_record",
                "user_document",
                "other",
            },
            id="reference-type",
        ),
    ],
)
def test_enum_contracts(enum_type, expected_values: set[str]) -> None:
    """Each public enum should expose exactly its controlled values."""

    assert {member.value for member in enum_type} == expected_values


def test_package_exports_the_complete_step_90_contract() -> None:
    """The package and model module should expose the canonical trace name."""

    required_exports = {
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
    }

    assert set(calculation_models.__all__) == required_exports
    assert required_exports.issubset(set(calculations_package.__all__))
    assert calculations_package.CalculationTraceStep is CalculationTraceStep
    result_schema = CalculationResult.model_json_schema()
    assert "required_reviewer_competency" in result_schema["required"]


@pytest.mark.parametrize(
    "status",
    list(CalculationStatus),
    ids=lambda status: status.value,
)
def test_each_result_status_has_a_valid_evidence_shape(
    status: CalculationStatus,
) -> None:
    """Every declared state should be constructible with proper evidence."""

    if status == CalculationStatus.COMPLETED_WITH_WARNINGS:
        result = _completed_result_with_optional_default_fallback()
    else:
        result = make_result(status)

    assert result.status == status
    assert result.required_reviewer_competency
    if status in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }:
        assert result.outputs
        assert result.trace_steps
    else:
        assert result.outputs == ()


def test_request_can_be_empty_for_insufficient_input_resolution() -> None:
    """The engine layer must be able to receive an all-inputs-missing request."""

    request = make_request()

    assert request.inputs == ()
    assert request.assumptions == ()
    assert request.options == ()


# ---------------------------------------------------------------------------
# B. Immutability, tuple handling, strict scalars, and extras: 24 cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("instance", "field_name", "replacement"),
    [
        pytest.param(
            make_quantity(),
            "value",
            20.0,
            id="quantity-value",
        ),
        pytest.param(
            make_input(),
            "name",
            "Changed input",
            id="input-name",
        ),
        pytest.param(
            make_assumption(),
            "statement",
            "Changed assumption",
            id="assumption-statement",
        ),
        pytest.param(
            make_trace_step(),
            "sequence",
            2,
            id="trace-sequence",
        ),
        pytest.param(
            make_request(),
            "method_version",
            "2.0.0",
            id="request-version",
        ),
        pytest.param(
            make_result(),
            "status",
            CalculationStatus.FAILED,
            id="result-status",
        ),
    ],
)
def test_public_models_reject_assignment(
    instance: CalculationModel,
    field_name: str,
    replacement: Any,
) -> None:
    """Validated model instances should be frozen."""

    with pytest.raises(ValidationError) as error_info:
        setattr(instance, field_name, replacement)

    assert error_info.value.errors()[0]["type"] == "frozen_instance"


def test_frozen_deletion_and_validated_model_copy_are_enforced() -> None:
    """Deletion and unvalidated copy updates must not bypass invariants."""

    quantity = make_quantity()

    with pytest.raises(ValidationError) as error_info:
        del quantity.unit

    assert error_info.value.errors()[0]["type"] == "frozen_instance"
    assert_validation_error(
        lambda: quantity.model_copy(update={"value": float("nan")})
    )

    bypassed_quantity = EngineeringQuantity.model_construct(
        quantity_kind="pressure-gauge",
        value=float("nan"),
        unit="bar",
    )
    assert_validation_error(
        lambda: make_input(quantity=bypassed_quantity)
    )


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: CalculationInput(
                input_id="pressure-in",
                name="Pressure",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                quantity=make_quantity(),
                source_reference_ids=["reference-1"],
            ),
            id="input-references",
        ),
        pytest.param(
            lambda: CalculationAssumption(
                assumption_id="assumption-1",
                statement="Verify density.",
                origin=InputOrigin.USER_SUPPLIED,
                requires_verification=True,
                verification_requirement_ids=["verify-1"],
            ),
            id="assumption-verifications",
        ),
        pytest.param(
            lambda: make_trace_step(input_ids=["pressure-in"]),
            id="trace-inputs",
        ),
        pytest.param(
            lambda: make_request(inputs=[make_input()]),
            id="request-inputs",
        ),
        pytest.param(
            lambda: make_result(limitations=["Preliminary result."]),
            id="result-limitations",
        ),
        pytest.param(
            lambda: make_verification(
                evidence_required=["Signed check sheet"]
            ),
            id="verification-evidence",
        ),
    ],
)
def test_json_style_lists_are_normalized_to_tuples(factory) -> None:
    """Ordered Python lists should become immutable tuple-backed fields."""

    model = factory()
    tuple_fields = [
        value
        for field_name, value in model
        if isinstance(value, tuple)
    ]

    assert tuple_fields
    assert all(isinstance(value, tuple) for value in tuple_fields)


@pytest.mark.parametrize(
    "unordered_value",
    [
        pytest.param({"reference-1"}, id="set"),
        pytest.param(
            (item for item in ("reference-1",)),
            id="generator",
        ),
        pytest.param("reference-1", id="string"),
        pytest.param(b"reference-1", id="bytes"),
    ],
)
def test_unordered_or_ambiguous_collection_inputs_are_rejected(
    unordered_value: Any,
) -> None:
    """Only lists and tuples may populate ordered collection fields."""

    assert_validation_error(
        lambda: make_request(reference_ids=unordered_value)
    )


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: EngineeringQuantity(
                quantity_kind="pressure",
                value=1.0,
                unit="bar",
                voice_note="unexpected",
            ),
            id="quantity-top-level",
        ),
        pytest.param(
            lambda: CalculationInput.model_validate(
                {
                    "input_id": "pressure-in",
                    "name": "Pressure",
                    "origin": InputOrigin.USER_SUPPLIED,
                    "quantity": {
                        "quantity_kind": "pressure",
                        "value": 1.0,
                        "unit": "bar",
                        "unexpected": True,
                    },
                }
            ),
            id="nested-quantity",
        ),
        pytest.param(
            lambda: CalculationRequest(
                request_id=FIXED_REQUEST_ID,
                calculation_type="pressure-test",
                method_id="method.pressure",
                method_version="1.0.0",
                unsupported_option=True,
            ),
            id="request-top-level",
        ),
        pytest.param(
            lambda: CalculationResult.model_validate(
                _result_payload_with_nested_extra()
            ),
            id="nested-result-output",
        ),
    ],
)
def test_unknown_fields_are_rejected_at_all_model_depths(factory) -> None:
    """Unknown public input must never be silently ignored."""

    error = assert_validation_error(factory)

    assert any(
        item["type"] == "extra_forbidden"
        for item in error.errors()
    )


@pytest.mark.parametrize(
    "categorical_value",
    [
        pytest.param(1, id="integer"),
        pytest.param(1.0, id="float"),
    ],
)
def test_categorical_input_rejects_numeric_scalars(
    categorical_value: Any,
) -> None:
    """Numeric engineering values must use an explicit quantity and unit."""

    assert_validation_error(
        lambda: make_input(
            quantity=None,
            categorical_value=categorical_value,
        )
    )


def test_default_collection_fields_are_all_immutable_tuples() -> None:
    """Every shared collection default should be tuple-backed."""

    request = make_request()
    result = make_result(CalculationStatus.INSUFFICIENT_INPUT)

    assert all(
        isinstance(getattr(request, field_name), tuple)
        for field_name in (
            "inputs",
            "assumptions",
            "options",
            "reference_ids",
        )
    )
    assert all(
        isinstance(getattr(result, field_name), tuple)
        for field_name in (
            "supplied_inputs",
            "normalized_inputs",
            "defaulted_inputs",
            "effective_options",
            "assumptions",
            "missing_inputs",
            "findings",
            "trace_steps",
            "outputs",
            "references",
            "verification_requirements",
            "limitations",
            "exclusions",
        )
    )


# ---------------------------------------------------------------------------
# C. Finite values, numerical bounds, and precision: 34 cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param(True, id="boolean"),
        pytest.param("1.0", id="numeric-string"),
        pytest.param(1.0000000000000002e300, id="above-upper-bound"),
        pytest.param(-1.0000000000000002e300, id="below-lower-bound"),
    ],
)
def test_quantity_value_rejects_invalid_or_unbounded_numbers(
    invalid_value: Any,
) -> None:
    """A public engineering quantity must contain one finite bounded number."""

    assert_validation_error(
        lambda: make_quantity(value=invalid_value)
    )


@pytest.mark.parametrize(
    "invalid_uncertainty",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param(-0.1, id="negative"),
        pytest.param(1.0000000000000002e300, id="above-bound"),
        pytest.param(True, id="boolean"),
        pytest.param("0.1", id="numeric-string"),
    ],
)
def test_quantity_uncertainty_is_finite_nonnegative_and_bounded(
    invalid_uncertainty: Any,
) -> None:
    """Absolute uncertainty must be valid in the quantity's own unit."""

    assert_validation_error(
        lambda: make_quantity(
            uncertainty=invalid_uncertainty,
            uncertainty_basis="Manufacturer accuracy statement.",
        )
    )


@pytest.mark.parametrize(
    "invalid_option",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param(1.0000000000000002e300, id="float-above-bound"),
        pytest.param(10**301, id="integer-above-bound"),
        pytest.param("   ", id="blank-text"),
        pytest.param("x" * 1_001, id="text-over-bound"),
    ],
)
def test_option_values_are_strict_finite_and_bounded(
    invalid_option: Any,
) -> None:
    """Execution options must not create an unbounded public payload."""

    assert_validation_error(
        lambda: make_option(value=invalid_option)
    )


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: CalculationInput.model_validate(
                {
                    "input_id": "pressure-in",
                    "name": "Pressure",
                    "origin": InputOrigin.USER_SUPPLIED,
                    "quantity": {
                        "quantity_kind": "pressure",
                        "value": float("nan"),
                        "unit": "bar",
                    },
                }
            ),
            id="input-quantity",
        ),
        pytest.param(
            lambda: CalculationTraceValue.model_validate(
                {
                    "value_id": "trace-value",
                    "name": "Trace value",
                    "quantity": {
                        "quantity_kind": "pressure",
                        "value": float("inf"),
                        "unit": "bar",
                    },
                }
            ),
            id="trace-value",
        ),
        pytest.param(
            lambda: CalculationOutput.model_validate(
                {
                    "output_id": "pressure-out",
                    "name": "Pressure",
                    "quantity": {
                        "quantity_kind": "pressure",
                        "value": float("-inf"),
                        "unit": "bar",
                    },
                    "source_step_ids": ["step-1"],
                }
            ),
            id="output-quantity",
        ),
        pytest.param(
            lambda: CalculationRequest.model_validate(
                {
                    "calculation_type": "pressure-test",
                    "method_id": "method.pressure",
                    "method_version": "1.0.0",
                    "inputs": [
                        {
                            "input_id": "pressure-in",
                            "name": "Pressure",
                            "origin": InputOrigin.USER_SUPPLIED,
                            "quantity": {
                                "quantity_kind": "pressure",
                                "value": float("nan"),
                                "unit": "bar",
                            },
                        }
                    ],
                }
            ),
            id="request-input",
        ),
        pytest.param(
            lambda: CalculationResult.model_validate(
                _result_payload_with_nonfinite_supplied_input()
            ),
            id="result-supplied-input",
        ),
        pytest.param(
            lambda: CalculationResult.model_validate(
                _result_payload_with_nonfinite_trace_value()
            ),
            id="result-trace-output",
        ),
    ],
)
def test_nonfinite_values_are_rejected_through_nested_structures(
    factory,
) -> None:
    """Nested dictionaries must not bypass finite-number validation."""

    assert_validation_error(factory)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: make_quantity(value=MAX_NUMBER),
            id="quantity-positive-limit",
        ),
        pytest.param(
            lambda: make_quantity(value=-MAX_NUMBER),
            id="quantity-negative-limit",
        ),
        pytest.param(
            lambda: make_quantity(
                uncertainty=0.0,
                uncertainty_basis="Zero reference uncertainty.",
            ),
            id="zero-uncertainty",
        ),
        pytest.param(
            lambda: make_quantity(
                uncertainty=MAX_NUMBER,
                uncertainty_basis="Bounded stress-test uncertainty.",
            ),
            id="uncertainty-limit",
        ),
        pytest.param(
            lambda: make_quantity(significant_figures=1),
            id="one-significant-figure",
        ),
        pytest.param(
            lambda: make_quantity(significant_figures=15),
            id="fifteen-significant-figures",
        ),
        pytest.param(
            lambda: (
                make_quantity(decimal_places=0),
                make_quantity(decimal_places=15),
            ),
            id="decimal-place-boundaries",
        ),
    ],
)
def test_valid_numeric_boundaries_are_accepted(factory) -> None:
    """Declared inclusive numerical limits should remain usable."""

    value = factory()

    assert value is not None


# ---------------------------------------------------------------------------
# D. Local cross-field state validation: 35 cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"significant_figures": 0}, id="zero-significant-figures"),
        pytest.param({"significant_figures": 16}, id="too-many-significant-figures"),
        pytest.param({"decimal_places": -1}, id="negative-decimal-places"),
        pytest.param({"decimal_places": 16}, id="too-many-decimal-places"),
        pytest.param(
            {"significant_figures": 3, "decimal_places": 2},
            id="ambiguous-presentation",
        ),
        pytest.param(
            {"uncertainty": 0.1},
            id="uncertainty-without-basis",
        ),
        pytest.param(
            {"uncertainty_basis": "Unsupported standalone basis."},
            id="basis-without-uncertainty",
        ),
    ],
)
def test_quantity_rejects_inconsistent_precision_or_uncertainty(
    changes: dict[str, Any],
) -> None:
    """Quantity presentation and uncertainty metadata must be unambiguous."""

    assert_validation_error(lambda: make_quantity(**changes))


@pytest.mark.parametrize(
    ("factory", "valid", "expected_categorical"),
    [
        pytest.param(
            lambda: make_input(),
            True,
            None,
            id="quantity",
        ),
        pytest.param(
            lambda: make_input(
                quantity=None,
                categorical_value="  liquid  ",
            ),
            True,
            "liquid",
            id="categorical-text",
        ),
        pytest.param(
            lambda: make_input(
                quantity=None,
                categorical_value=True,
            ),
            True,
            True,
            id="categorical-boolean",
        ),
        pytest.param(
            lambda: make_input(categorical_value="liquid"),
            False,
            None,
            id="both-value-types",
        ),
        pytest.param(
            lambda: make_input(quantity=None),
            False,
            None,
            id="neither-value-type",
        ),
        pytest.param(
            lambda: make_input(
                origin=InputOrigin.DOCUMENT_EXTRACTED
            ),
            False,
            None,
            id="document-without-reference",
        ),
        pytest.param(
            lambda: make_input(origin=InputOrigin.IMPORTED),
            False,
            None,
            id="import-without-reference",
        ),
        pytest.param(
            lambda: make_input(origin=InputOrigin.SELECTED),
            False,
            None,
            id="selection-without-reference",
        ),
        pytest.param(
            lambda: make_input(origin=InputOrigin.DEFAULTED),
            False,
            None,
            id="default-without-assumption",
        ),
        pytest.param(
            lambda: make_input(assumption_id="assumption-1"),
            False,
            None,
            id="nondefault-with-assumption",
        ),
        pytest.param(
            lambda: make_input(origin=InputOrigin.CALCULATED),
            False,
            None,
            id="calculated-without-trace",
        ),
        pytest.param(
            lambda: make_input(origin=InputOrigin.SYSTEM_DERIVED),
            False,
            None,
            id="derived-without-trace",
        ),
    ],
)
def test_calculation_input_cross_field_states(
    factory,
    valid: bool,
    expected_categorical: bool | str | None,
) -> None:
    """Input value type, origin, and provenance must agree."""

    if valid:
        value = factory()
        assert value.categorical_value == expected_categorical
    else:
        assert_validation_error(factory)


@pytest.mark.parametrize(
    ("factory", "valid"),
    [
        pytest.param(
            lambda: make_assumption(
                requires_verification=True,
                verification_requirement_ids=("verify-1",),
            ),
            True,
            id="pending-verification",
        ),
        pytest.param(
            lambda: make_assumption(
                requires_verification=True,
                verification_requirement_ids=("verify-1",),
                verification_completed=True,
                verified_by="A. Engineer",
                verified_at=FIXED_TIME,
            ),
            True,
            id="completed-verification",
        ),
        pytest.param(
            lambda: make_assumption(requires_verification=True),
            False,
            id="verification-without-requirement",
        ),
        pytest.param(
            lambda: make_assumption(
                verification_requirement_ids=("verify-1",)
            ),
            False,
            id="requirement-without-flag",
        ),
        pytest.param(
            lambda: make_assumption(safety_critical=True),
            False,
            id="safety-critical-without-verification",
        ),
        pytest.param(
            lambda: make_assumption(
                requires_verification=True,
                verification_requirement_ids=("verify-1",),
                verification_completed=True,
            ),
            False,
            id="completed-without-reviewer-details",
        ),
        pytest.param(
            lambda: make_assumption(verified_by="A. Engineer"),
            False,
            id="details-without-completion",
        ),
        pytest.param(
            lambda: make_assumption(
                origin=InputOrigin.DOCUMENT_EXTRACTED
            ),
            False,
            id="document-assumption-without-reference",
        ),
    ],
)
def test_assumption_verification_states(factory, valid: bool) -> None:
    """Assumption verification must be traceable and internally consistent."""

    if valid:
        assert isinstance(factory(), CalculationAssumption)
    else:
        assert_validation_error(factory)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: make_finding(
                severity=FindingSeverity.ERROR,
                blocking=False,
            ),
            id="error-not-blocking",
        ),
        pytest.param(
            lambda: make_finding(
                severity=FindingSeverity.CRITICAL,
                blocking=False,
            ),
            id="critical-not-blocking",
        ),
        pytest.param(
            lambda: make_finding(
                severity=FindingSeverity.INFORMATION,
                blocking=True,
                required_action="Stop.",
                verification_requirement_ids=("verify-1",),
            ),
            id="information-blocker",
        ),
        pytest.param(
            lambda: make_finding(
                severity=FindingSeverity.CAUTION,
                blocking=True,
                required_action="Stop.",
                verification_requirement_ids=("verify-1",),
            ),
            id="caution-blocker",
        ),
        pytest.param(
            lambda: make_finding(
                blocking=True,
                verification_requirement_ids=("verify-1",),
            ),
            id="blocker-without-action",
        ),
        pytest.param(
            lambda: make_finding(
                blocking=True,
                required_action="Stop.",
            ),
            id="blocker-without-verification",
        ),
    ],
)
def test_finding_blocking_states_are_actionable(factory) -> None:
    """Blocking and severe findings must carry actionable review evidence."""

    assert_validation_error(factory)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: CalculationReference(
                reference_id="standard-1",
                reference_type=ReferenceType.INTERNATIONAL_STANDARD,
                title="Controlled international standard",
            ),
            id="controlled-reference-without-control-fields",
        ),
        pytest.param(
            lambda: make_verification(
                independent_verification_required=True
            ),
            id="independent-check-without-role",
        ),
    ],
)
def test_reference_and_verification_require_required_control_data(
    factory,
) -> None:
    """Controlled references and independent checks need their key metadata."""

    assert_validation_error(factory)


# ---------------------------------------------------------------------------
# E. Trace, output, request, and declared bounds: 28 cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("factory", "valid"),
    [
        pytest.param(
            lambda: make_trace_step(
                kind=TraceStepKind.ITERATION,
                iteration_number=1,
            ),
            True,
            id="valid-iteration",
        ),
        pytest.param(
            lambda: make_trace_step(formula_identifier=None),
            False,
            id="calculation-without-formula-id",
        ),
        pytest.param(
            lambda: make_trace_step(
                kind=TraceStepKind.ITERATION,
                iteration_number=None,
            ),
            False,
            id="iteration-without-number",
        ),
        pytest.param(
            lambda: make_trace_step(iteration_number=1),
            False,
            id="noniteration-with-number",
        ),
        pytest.param(
            lambda: make_trace_step(output_values=()),
            False,
            id="completed-calculation-without-output",
        ),
        pytest.param(
            lambda: make_trace_step(
                dependency_step_ids=("step-1",)
            ),
            False,
            id="self-dependency",
        ),
        pytest.param(
            lambda: make_trace_step(
                input_ids=("pressure-in", "PRESSURE-IN")
            ),
            False,
            id="duplicate-input-id",
        ),
        pytest.param(
            lambda: make_trace_step(
                dependency_step_ids=("step-0", "STEP-0")
            ),
            False,
            id="duplicate-dependency-id",
        ),
        pytest.param(
            lambda: make_trace_step(
                output_values=(
                    make_trace_value(value_id="trace-1", name="Value 1"),
                    make_trace_value(value_id="TRACE-1", name="Value 2"),
                )
            ),
            False,
            id="duplicate-trace-value-id",
        ),
        pytest.param(
            lambda: make_trace_step(
                output_values=(
                    make_trace_value(value_id="trace-1", name="Same"),
                    make_trace_value(value_id="trace-2", name="same"),
                )
            ),
            False,
            id="duplicate-trace-value-name",
        ),
    ],
)
def test_trace_step_local_states(factory, valid: bool) -> None:
    """A trace step should be non-executable metadata with coherent state."""

    if valid:
        assert isinstance(factory(), CalculationTraceStep)
    else:
        assert_validation_error(factory)


@pytest.mark.parametrize(
    ("factory", "valid", "expected_value"),
    [
        pytest.param(
            lambda: make_output(
                quantity=None,
                categorical_value="  acceptable  ",
            ),
            True,
            "acceptable",
            id="categorical-output",
        ),
        pytest.param(
            lambda: make_output(categorical_value="acceptable"),
            False,
            None,
            id="both-value-types",
        ),
        pytest.param(
            lambda: make_output(quantity=None),
            False,
            None,
            id="neither-value-type",
        ),
        pytest.param(
            lambda: make_output(source_step_ids=()),
            False,
            None,
            id="missing-source-step",
        ),
    ],
)
def test_output_value_and_source_states(
    factory,
    valid: bool,
    expected_value: str | None,
) -> None:
    """A final output requires one typed value and at least one source step."""

    if valid:
        assert factory().categorical_value == expected_value
    else:
        assert_validation_error(factory)


@pytest.mark.parametrize(
    ("factory", "valid"),
    [
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        source_reference_ids=("reference-1",),
                    ),
                ),
                reference_ids=("reference-1",),
            ),
            True,
            id="document-input",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        origin=InputOrigin.DEFAULTED,
                        assumption_id="assumption-1",
                    ),
                )
            ),
            False,
            id="defaulted-input",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        origin=InputOrigin.SYSTEM_DERIVED,
                        source_trace_step_ids=("step-1",),
                    ),
                )
            ),
            False,
            id="derived-input",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        origin=InputOrigin.CALCULATED,
                        source_trace_step_ids=("step-1",),
                    ),
                )
            ),
            False,
            id="calculated-input",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        source_trace_step_ids=("step-1",)
                    ),
                )
            ),
            False,
            id="trace-linked-supplied-input",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(),
                    make_input(input_id="PRESSURE-IN", name="Other"),
                )
            ),
            False,
            id="duplicate-input-id",
        ),
        pytest.param(
            lambda: make_request(
                inputs=(
                    make_input(
                        input_id="document-in",
                        name="Document input",
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        source_reference_ids=("missing-reference",),
                    ),
                )
            ),
            False,
            id="undeclared-input-reference",
        ),
        pytest.param(
            lambda: make_request(
                options=(
                    make_option(),
                    make_option(option_id="ITERATION-LIMIT", value=30),
                )
            ),
            False,
            id="duplicate-option-id",
        ),
    ],
)
def test_request_collection_states(factory, valid: bool) -> None:
    """A request may contain only external, uniquely identified values."""

    if valid:
        assert isinstance(factory(), CalculationRequest)
    else:
        assert_validation_error(factory)


@pytest.mark.parametrize(
    ("valid_factory", "invalid_factory"),
    [
        pytest.param(
            lambda: make_quantity(quantity_kind="q" * 100),
            lambda: make_quantity(quantity_kind="q" * 101),
            id="identifier-length",
        ),
        pytest.param(
            lambda: make_quantity(unit="u" * 40),
            lambda: make_quantity(unit="u" * 41),
            id="unit-length",
        ),
        pytest.param(
            lambda: make_input(
                source_reference_ids=tuple(
                    f"ref-{index}"
                    for index in range(32)
                )
            ),
            lambda: make_input(
                source_reference_ids=tuple(
                    f"ref-{index}"
                    for index in range(33)
                )
            ),
            id="link-count-32",
        ),
        pytest.param(
            lambda: make_trace_step(
                input_ids=tuple(
                    f"input-{index}"
                    for index in range(64)
                )
            ),
            lambda: make_trace_step(
                input_ids=tuple(
                    f"input-{index}"
                    for index in range(65)
                )
            ),
            id="trace-link-count-64",
        ),
        pytest.param(
            lambda: make_request(
                options=tuple(
                    make_option(
                        option_id=f"option-{index}",
                        value=index,
                    )
                    for index in range(128)
                )
            ),
            lambda: make_request(
                options=tuple(
                    make_option(
                        option_id=f"option-{index}",
                        value=index,
                    )
                    for index in range(129)
                )
            ),
            id="option-count-128",
        ),
        pytest.param(
            lambda: make_request(
                inputs=tuple(
                    make_input(
                        input_id=f"input-{index}",
                        name=f"Input {index}",
                    )
                    for index in range(256)
                )
            ),
            lambda: make_request(
                inputs=tuple(
                    make_input(
                        input_id=f"input-{index}",
                        name=f"Input {index}",
                    )
                    for index in range(257)
                )
            ),
            id="input-count-256",
        ),
    ],
)
def test_declared_text_and_collection_boundaries(
    valid_factory,
    invalid_factory,
) -> None:
    """Exact public limits should pass and the next value should fail."""

    assert valid_factory() is not None
    assert_validation_error(invalid_factory)


# ---------------------------------------------------------------------------
# F. Result state, links, ordering, and uniqueness: 31 cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: make_result(outputs=()),
            id="completed-without-output",
        ),
        pytest.param(
            lambda: make_result(trace_steps=()),
            id="completed-without-trace",
        ),
        pytest.param(
            lambda: make_result(
                findings=(
                    make_blocking_finding(
                        category=FindingCategory.APPLICABILITY
                    ),
                ),
                verification_requirements=(make_verification(),),
            ),
            id="completed-with-blocker",
        ),
        pytest.param(
            lambda: make_result(references=(make_reference(),)),
            id="completed-with-unverified-reference",
        ),
        pytest.param(
            lambda: make_result(
                method_lifecycle_status=MethodLifecycleStatus.DRAFT,
            ),
            id="completed-with-unapproved-method",
        ),
        pytest.param(
            lambda: make_result(
                assumptions=(
                    make_assumption(
                        requires_verification=True,
                        verification_requirement_ids=("verify-1",),
                    ),
                ),
                verification_requirements=(make_verification(),),
            ),
            id="completed-with-unverified-assumption",
        ),
        pytest.param(
            lambda: _completed_result_with_failed_prior_trace(),
            id="completed-with-failed-trace",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.COMPLETED_WITH_WARNINGS,
                findings=(),
            ),
            id="warning-status-without-context",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.COMPLETED_WITH_WARNINGS,
                findings=(
                    make_blocking_finding(
                        category=FindingCategory.APPLICABILITY
                    ),
                ),
                verification_requirements=(make_verification(),),
            ),
            id="warning-status-with-blocker",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.BLOCKED,
                findings=(),
            ),
            id="blocked-without-blocker",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.INSUFFICIENT_INPUT,
                missing_inputs=(),
            ),
            id="insufficient-without-required-input",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.NOT_APPLICABLE,
                findings=(make_finding(),),
                verification_requirements=(),
            ),
            id="not-applicable-without-applicability-blocker",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.FAILED,
                findings=(make_finding(),),
                verification_requirements=(),
            ),
            id="failed-without-error",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.BLOCKED,
                trace_steps=(make_trace_step(),),
                outputs=(make_output(),),
            ),
            id="noncompleted-status-with-output",
        ),
        pytest.param(
            lambda: make_result(
                CalculationStatus.FAILED,
                findings=(make_blocking_finding(),),
                verification_requirements=(make_verification(),),
            ),
            id="safety-blocker-with-failed-status",
        ),
    ],
)
def test_result_status_rejects_contradictory_evidence(factory) -> None:
    """Result status is derived from evidence and cannot hide unsafe states."""

    assert_validation_error(factory)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: _result_with_unresolved_supplied_reference(),
            id="supplied-input-reference",
        ),
        pytest.param(
            lambda: _result_with_unresolved_calculated_trace(),
            id="calculated-input-trace",
        ),
        pytest.param(
            lambda: _result_with_unresolved_default_assumption(),
            id="default-assumption",
        ),
        pytest.param(
            lambda: _completed_result_without_normalized_counterpart(),
            id="missing-normalized-counterpart",
        ),
        pytest.param(
            lambda: _result_with_mismatched_normalized_name(),
            id="normalized-name-mismatch",
        ),
        pytest.param(
            lambda: _result_with_unresolved_assumption_verification(),
            id="assumption-verification",
        ),
        pytest.param(
            lambda: _result_with_unresolved_finding_reference(),
            id="finding-reference",
        ),
        pytest.param(
            lambda: _result_with_unresolved_output_step(),
            id="output-step",
        ),
    ],
)
def test_result_rejects_unresolved_or_inconsistent_links(factory) -> None:
    """Every reference, assumption, trace, and output link must resolve."""

    assert_validation_error(factory)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: make_result(
                trace_steps=(
                    make_trace_step(sequence=2),
                )
            ),
            id="trace-starts-at-two",
        ),
        pytest.param(
            lambda: _result_with_trace_gap(),
            id="trace-sequence-gap",
        ),
        pytest.param(
            lambda: _result_with_forward_dependency(),
            id="forward-dependency",
        ),
        pytest.param(
            lambda: _result_using_derived_input_before_source_step(),
            id="forward-derived-input",
        ),
        pytest.param(
            lambda: _result_with_duplicate_step_ids(),
            id="duplicate-step-id",
        ),
        pytest.param(
            lambda: _result_using_missing_input_in_trace(),
            id="missing-input-used-by-trace",
        ),
        pytest.param(
            lambda: _result_with_trace_input_id_collision(),
            id="trace-input-id-collision",
        ),
        pytest.param(
            lambda: _result_with_output_value_mismatch(),
            id="output-value-mismatch",
        ),
    ],
)
def test_result_rejects_invalid_order_or_identifier_collisions(
    factory,
) -> None:
    """The result graph must be contiguous, backward-only, and unambiguous."""

    assert_validation_error(factory)


# ---------------------------------------------------------------------------
# G. Serialization, UTC timestamps, and excluded execution/voice scope: 10.
# ---------------------------------------------------------------------------


def test_request_json_round_trip_preserves_the_strict_contract() -> None:
    """A request should survive its public JSON representation."""

    original = make_request(inputs=(make_input(),))
    restored = CalculationRequest.model_validate_json(
        original.model_dump_json()
    )

    assert restored == original
    assert isinstance(restored.inputs, tuple)


def test_result_json_round_trip_preserves_the_complete_graph() -> None:
    """A complete result should survive JSON serialization without loss."""

    original = make_result()
    restored = CalculationResult.model_validate_json(
        original.model_dump_json()
    )

    assert restored == original
    assert isinstance(restored.trace_steps, tuple)
    assert isinstance(restored.outputs, tuple)


@pytest.mark.parametrize(
    ("factory", "field_name"),
    [
        pytest.param(
            lambda value: make_request(requested_at=value),
            "requested_at",
            id="request",
        ),
        pytest.param(
            lambda value: make_result(executed_at=value),
            "executed_at",
            id="result",
        ),
    ],
)
def test_aware_timestamps_are_normalized_to_utc(
    factory,
    field_name: str,
) -> None:
    """Aware non-UTC timestamps should be stored canonically in UTC."""

    source = datetime(
        2026,
        7,
        30,
        14,
        0,
        tzinfo=timezone(timedelta(hours=2)),
    )
    model = factory(source)
    stored = getattr(model, field_name)

    assert stored == FIXED_TIME
    assert stored.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: make_request(
                requested_at=datetime(2026, 7, 30, 12, 0)
            ),
            id="request",
        ),
        pytest.param(
            lambda: make_result(
                executed_at=datetime(2026, 7, 30, 12, 0)
            ),
            id="result",
        ),
    ],
)
def test_naive_timestamps_are_rejected(factory) -> None:
    """A timestamp without an explicit offset is not auditable."""

    assert_validation_error(factory)


def test_json_output_uses_public_primitives_and_canonical_values() -> None:
    """JSON output should contain arrays, enum strings, UUIDs, and UTC time."""

    result = make_result(result_fingerprint="A" * 64)
    payload = json.loads(result.model_dump_json())
    encoded = result.model_dump_json()

    assert payload["result_fingerprint"] == VALID_FINGERPRINT
    assert payload["status"] == "completed"
    assert payload["request_id"] == str(FIXED_REQUEST_ID)
    assert payload["executed_at"].endswith("Z")
    assert isinstance(payload["supplied_inputs"], list)
    assert "NaN" not in encoded
    assert "Infinity" not in encoded


def test_models_module_has_no_dynamic_execution_path() -> None:
    """The data-contract module must not execute user formula text."""

    source_path = Path(calculation_models.__file__)
    parsed = ast.parse(source_path.read_text(encoding="utf-8"))
    prohibited_names = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "system",
        "popen",
    }
    prohibited_modules = {"subprocess", "importlib"}

    called_names = {
        node.func.id
        for node in ast.walk(parsed)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
    }
    imported_modules = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(parsed)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (
            node.names
            if isinstance(node, ast.Import)
            else [ast.alias(name=node.module or "")]
        )
    }

    assert called_names.isdisjoint(prohibited_names)
    assert imported_modules.isdisjoint(prohibited_modules)


def test_formula_text_fields_are_not_part_of_the_contract() -> None:
    """Only a reviewed formula identifier may appear in trace metadata."""

    prohibited_fields = (
        "formula_expression",
        "formula_code",
        "executable_formula",
        "script",
    )

    for field_name in prohibited_fields:
        assert_validation_error(
            lambda field_name=field_name: CalculationTraceStep(
                step_id="step-1",
                sequence=1,
                kind=TraceStepKind.VALIDATION,
                title="Validate",
                description="Validate the input.",
                **{field_name: "__import__('os').system('unsafe')"},
            )
        )


def test_voice_phase_fields_are_absent_and_extra_forbidden() -> None:
    """Voice, audio, and transcript fields remain reserved for Phase 10."""

    prohibited_terms = {
        "voice",
        "audio",
        "speech",
        "transcript",
        "microphone",
    }
    public_model_types = (
        EngineeringQuantity,
        CalculationInput,
        CalculationOption,
        CalculationAssumption,
        MissingCalculationInput,
        CalculationFinding,
        CalculationReference,
        VerificationRequirement,
        CalculationTraceValue,
        CalculationTraceStep,
        CalculationOutput,
        CalculationRequest,
        CalculationResult,
    )

    for model_type in public_model_types:
        assert not any(
            term in field_name.casefold()
            for field_name in model_type.model_fields
            for term in prohibited_terms
        )

    for field_name in prohibited_terms:
        assert_validation_error(
            lambda field_name=field_name: make_request(
                **{field_name: "reserved"}
            )
        )


# ---------------------------------------------------------------------------
# Payload mutation and result-graph factories used by parametrized tests.
# They are intentionally defined after tests to keep the public scenarios
# readable; names resolve when pytest executes each case.
# ---------------------------------------------------------------------------


def _result_payload_with_nested_extra() -> dict[str, Any]:
    payload = make_result().model_dump(mode="python")
    payload["outputs"][0]["unexpected"] = True
    return payload


def _result_payload_with_nonfinite_supplied_input() -> dict[str, Any]:
    payload = make_result().model_dump(mode="python")
    payload["supplied_inputs"][0]["quantity"]["value"] = float("nan")
    return payload


def _result_payload_with_nonfinite_trace_value() -> dict[str, Any]:
    payload = make_result().model_dump(mode="python")
    payload["trace_steps"][0]["output_values"][0]["quantity"]["value"] = (
        float("inf")
    )
    return payload


def _completed_result_with_optional_default_fallback() -> CalculationResult:
    """Create the supported optional-missing-to-approved-default state."""

    missing_density = make_missing_input(
        input_id="density-in",
        name="Fluid density",
        required_for_execution=False,
    )
    density_assumption = make_assumption(
        assumption_id="density-assumption",
        statement="Use the approved fallback density.",
    )
    density_quantity = make_quantity(
        quantity_kind="density",
        value=1_000.0,
        unit="kg/m3",
    )
    defaulted_density = make_input(
        input_id="density-in",
        name="Fluid density",
        origin=InputOrigin.DEFAULTED,
        quantity=density_quantity,
        assumption_id="density-assumption",
    )
    normalized_density = make_input(
        input_id="density-in",
        name="Fluid density",
        origin=InputOrigin.DEFAULTED,
        quantity=density_quantity,
        assumption_id="density-assumption",
    )
    graph = make_completed_graph()
    graph["normalized_inputs"] = (
        *graph["normalized_inputs"],
        normalized_density,
    )

    return make_result(
        CalculationStatus.COMPLETED_WITH_WARNINGS,
        **graph,
        defaulted_inputs=(defaulted_density,),
        assumptions=(density_assumption,),
        missing_inputs=(missing_density,),
        findings=(),
    )


def _completed_result_with_failed_prior_trace() -> CalculationResult:
    failed_step = CalculationTraceStep(
        step_id="step-1",
        sequence=1,
        kind=TraceStepKind.VALIDATION,
        status=TraceStepStatus.FAILED,
        title="Validation failed",
        description="The validation step failed.",
    )
    completed_step = make_trace_step(
        step_id="step-2",
        sequence=2,
        input_ids=("pressure-in",),
    )
    output = make_output(source_step_ids=("step-2",))
    graph = make_completed_graph()
    graph["trace_steps"] = (failed_step, completed_step)
    graph["outputs"] = (output,)
    return make_result(**graph)


def _result_with_unresolved_supplied_reference() -> CalculationResult:
    supplied = make_input(
        origin=InputOrigin.DOCUMENT_EXTRACTED,
        source_reference_ids=("missing-reference",),
    )
    normalized = make_input(
        origin=InputOrigin.DOCUMENT_EXTRACTED,
        source_reference_ids=("missing-reference",),
    )
    graph = make_completed_graph()
    graph["supplied_inputs"] = (supplied,)
    graph["normalized_inputs"] = (normalized,)
    return make_result(**graph)


def _result_with_unresolved_calculated_trace() -> CalculationResult:
    calculated = make_input(
        input_id="calculated-in",
        name="Calculated input",
        origin=InputOrigin.CALCULATED,
        source_trace_step_ids=("missing-step",),
    )
    return make_result(
        CalculationStatus.INSUFFICIENT_INPUT,
        normalized_inputs=(calculated,),
        missing_inputs=(make_missing_input(),),
    )


def _result_with_unresolved_default_assumption() -> CalculationResult:
    defaulted = make_input(
        input_id="default-in",
        name="Default input",
        origin=InputOrigin.DEFAULTED,
        assumption_id="missing-assumption",
    )
    normalized = make_input(
        input_id="default-in",
        name="Default input",
        origin=InputOrigin.DEFAULTED,
        assumption_id="missing-assumption",
    )
    return make_result(
        CalculationStatus.INSUFFICIENT_INPUT,
        defaulted_inputs=(defaulted,),
        normalized_inputs=(normalized,),
        missing_inputs=(make_missing_input(),),
    )


def _completed_result_without_normalized_counterpart() -> CalculationResult:
    graph = make_completed_graph()
    graph["normalized_inputs"] = ()
    return make_result(**graph)


def _result_with_mismatched_normalized_name() -> CalculationResult:
    graph = make_completed_graph()
    graph["normalized_inputs"] = (
        make_input(name="Different normalized name"),
    )
    return make_result(**graph)


def _result_with_unresolved_assumption_verification() -> CalculationResult:
    assumption = make_assumption(
        requires_verification=True,
        verification_requirement_ids=("missing-verification",),
    )
    return make_result(
        CalculationStatus.COMPLETED_WITH_WARNINGS,
        assumptions=(assumption,),
        findings=(),
    )


def _result_with_unresolved_finding_reference() -> CalculationResult:
    finding = make_finding(reference_ids=("missing-reference",))
    return make_result(
        CalculationStatus.COMPLETED_WITH_WARNINGS,
        findings=(finding,),
    )


def _result_with_unresolved_output_step() -> CalculationResult:
    graph = make_completed_graph()
    graph["outputs"] = (
        make_output(source_step_ids=("missing-step",)),
    )
    return make_result(**graph)


def _validation_step(
    *,
    step_id: str,
    sequence: int,
    dependency_step_ids: tuple[str, ...] = (),
) -> CalculationTraceStep:
    return CalculationTraceStep(
        step_id=step_id,
        sequence=sequence,
        kind=TraceStepKind.VALIDATION,
        status=TraceStepStatus.COMPLETED,
        title=f"Validation {sequence}",
        description="Validate one controlled condition.",
        dependency_step_ids=dependency_step_ids,
    )


def _result_with_trace_gap() -> CalculationResult:
    step_1 = _validation_step(step_id="step-1", sequence=1)
    step_3 = make_trace_step(
        step_id="step-3",
        sequence=3,
        input_ids=("pressure-in",),
    )
    graph = make_completed_graph()
    graph["trace_steps"] = (step_1, step_3)
    graph["outputs"] = (
        make_output(source_step_ids=("step-3",)),
    )
    return make_result(**graph)


def _result_with_forward_dependency() -> CalculationResult:
    step_1 = _validation_step(
        step_id="step-1",
        sequence=1,
        dependency_step_ids=("step-2",),
    )
    step_2 = make_trace_step(
        step_id="step-2",
        sequence=2,
        input_ids=("pressure-in",),
    )
    graph = make_completed_graph()
    graph["trace_steps"] = (step_1, step_2)
    graph["outputs"] = (
        make_output(source_step_ids=("step-2",)),
    )
    return make_result(**graph)


def _result_with_duplicate_step_ids() -> CalculationResult:
    step_1 = _validation_step(step_id="step-1", sequence=1)
    step_2 = make_trace_step(
        step_id="STEP-1",
        sequence=2,
        input_ids=("pressure-in",),
    )
    graph = make_completed_graph()
    graph["trace_steps"] = (step_1, step_2)
    graph["outputs"] = (
        make_output(source_step_ids=("step-1",)),
    )
    return make_result(**graph)


def _result_using_derived_input_before_source_step() -> CalculationResult:
    """Build a trace that consumes a derived value before its source step."""

    derived_input = make_input(
        input_id="derived-in",
        name="Derived input",
        origin=InputOrigin.CALCULATED,
        source_trace_step_ids=("step-2",),
    )
    early_value = make_trace_value(
        value_id="early-value",
        name="Early value",
    )
    derived_value = make_trace_value(
        value_id="derived-value",
        name="Derived value",
    )
    step_1 = make_trace_step(
        step_id="step-1",
        sequence=1,
        input_ids=("derived-in",),
        output_values=(early_value,),
    )
    step_2 = make_trace_step(
        step_id="step-2",
        sequence=2,
        input_ids=("pressure-in",),
        output_values=(derived_value,),
    )
    graph = make_completed_graph()
    graph["normalized_inputs"] = (
        *graph["normalized_inputs"],
        derived_input,
    )
    graph["trace_steps"] = (step_1, step_2)
    graph["outputs"] = (
        make_output(
            source_step_ids=("step-2",),
            source_value_ids=("derived-value",),
        ),
    )
    return make_result(**graph)


def _result_using_missing_input_in_trace() -> CalculationResult:
    """Build a trace that incorrectly consumes an unavailable input."""

    trace_step = make_trace_step(
        input_ids=("density-in",),
    )
    return make_result(
        CalculationStatus.INSUFFICIENT_INPUT,
        missing_inputs=(make_missing_input(),),
        trace_steps=(trace_step,),
    )


def _result_with_trace_input_id_collision() -> CalculationResult:
    colliding_value = make_trace_value(
        value_id="PRESSURE-IN",
        name="Colliding trace value",
    )
    graph = make_completed_graph()
    graph["trace_steps"] = (
        make_trace_step(output_values=(colliding_value,)),
    )
    return make_result(**graph)


def _result_with_output_value_mismatch() -> CalculationResult:
    """Build an output whose value does not match its cited trace value."""

    graph = make_completed_graph()
    graph["outputs"] = (
        make_output(
            quantity=make_quantity(value=99.0),
            source_step_ids=("step-1",),
            source_value_ids=("trace-pressure",),
        ),
    )
    return make_result(**graph)
