"""Deterministic integration tests for the Step 92 calculation engine."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC
from datetime import datetime
from hashlib import sha256
import inspect
from math import inf
from math import nan
from threading import Lock
from typing import Any
from uuid import UUID
from uuid import uuid4

from pydantic import ValidationError
import pytest

from app.engineering.calculations.engine import (
    ATTEMPT_FINGERPRINT_SCHEMA,
)
from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.engine import CalculationEvidenceError
from app.engineering.calculations.engine import (
    CalculationExecutionContractError,
)
from app.engineering.calculations.engine import DEFAULT_CALCULATION_ENGINE
from app.engineering.calculations.engine import (
    ENGINE_COMPATIBILITY_FINDING_ID,
)
from app.engineering.calculations.engine import (
    ENGINE_EXECUTION_FINDING_ID,
)
from app.engineering.calculations.engine import (
    ENGINE_LIFECYCLE_FINDING_ID,
)
from app.engineering.calculations.engine import (
    ENGINE_NONCONVERGENCE_FINDING_ID,
)
from app.engineering.calculations.engine import (
    ENGINE_PRE_EXECUTION_RESULT_FINDING_ID,
)
from app.engineering.calculations.engine import ENGINE_RESULT_FINDING_ID
from app.engineering.calculations.engine import ENGINE_VERSION
from app.engineering.calculations.engine import FINGERPRINT_SCHEMA
from app.engineering.calculations.engine import IterationController
from app.engineering.calculations.engine import IterationStateError
from app.engineering.calculations.engine import NonFiniteIterationError
from app.engineering.calculations.engine import (
    build_attempt_fingerprint_payload,
)
from app.engineering.calculations.engine import build_fingerprint_payload
from app.engineering.calculations.engine import (
    canonical_fingerprint_bytes,
)
from app.engineering.calculations.engine import fingerprint_payload
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
from app.engineering.calculations.method_models import (
    IterationTerminationReason,
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
from app.engineering.calculations.method_models import MethodOptionValueType
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
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MAX_ASSUMPTIONS
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_MISSING_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MAX_REFERENCES
from app.engineering.calculations.models import (
    MAX_VERIFICATION_REQUIREMENTS,
)
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
)
from app.engineering.calculations.registry import (
    MethodCalculationTypeError,
)
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.registry import UnknownMethodError
from app.engineering.calculations.registry import (
    UnknownMethodVersionError,
)
from app.engineering.calculations.safety import MethodSafetyExtension
from app.engineering.calculations.safety import SafetyEvaluationContext
from app.engineering.calculations.safety import SafetyTrigger
from app.engineering.calculations.units import QuantityKind


FIXED_TIME = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
SECOND_TIME = datetime(2035, 1, 2, 3, 4, tzinfo=UTC)
FIXED_CALCULATION_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
FIXED_REQUEST_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SECOND_REQUEST_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
FIXED_DESIGN_CASE_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

_EXECUTOR_CALLS: dict[str, int] = {}
_CALL_LOCK = Lock()


def _record_executor_call(name: str) -> None:
    """Record one implementation call without racing concurrency tests."""

    with _CALL_LOCK:
        _EXECUTOR_CALLS[name] = _EXECUTOR_CALLS.get(name, 0) + 1


def _executor_call_count() -> int:
    """Return the total calls across every test implementation."""

    with _CALL_LOCK:
        return sum(_EXECUTOR_CALLS.values())


@pytest.fixture(autouse=True)
def reset_executor_calls() -> None:
    """Isolate executor invocation assertions."""

    with _CALL_LOCK:
        _EXECUTOR_CALLS.clear()


def fixed_clock() -> datetime:
    """Return one deterministic aware engine timestamp."""

    return FIXED_TIME


def fixed_id_factory() -> UUID:
    """Return one deterministic engine-owned calculation ID."""

    return FIXED_CALCULATION_ID


def invalid_id_factory() -> str:
    """Return an invalid trusted calculation identifier."""

    return "not-a-uuid"


def raising_id_factory() -> UUID:
    """Raise a trusted infrastructure identity failure."""

    raise RuntimeError("trusted id factory is unavailable")


def naive_clock() -> datetime:
    """Return a datetime without the required timezone."""

    return datetime(2026, 7, 30, 12, 0)


def invalid_clock() -> str:
    """Return a non-datetime trusted clock value."""

    return "not-a-datetime"


def raising_clock() -> datetime:
    """Raise a trusted infrastructure clock failure."""

    raise RuntimeError("trusted clock is unavailable")


def make_reference(
    reference_id: str,
    reference_type: ReferenceType,
    *,
    verified: bool = True,
    title: str | None = None,
) -> CalculationReference:
    """Build a compact calculation reference."""

    return CalculationReference(
        reference_id=reference_id,
        reference_type=reference_type,
        title=title or f"Reference {reference_id}",
        verified=verified,
        verified_by=(
            "Independent engine test reviewer"
            if verified
            else None
        ),
        verified_at=FIXED_TIME if verified else None,
    )


def make_verification(
    verification_id: str = "verify.review",
) -> VerificationRequirement:
    """Build one stable independent-verification requirement."""

    return VerificationRequirement(
        verification_id=verification_id,
        description="Independently verify the fixture calculation.",
        method="Reproduce the fixture using an approved reference vector.",
        expected_result="The independently reproduced value agrees.",
        acceptance_criteria="Agreement is within the reviewed tolerance.",
        required_competency="Competent test engineer",
        verifier_role="Independent competent test engineer",
        independent_verification_required=True,
        evidence_required=("Independent calculation record",),
    )


def make_reviews() -> tuple[MethodReviewRecord, ...]:
    """Build every review stage required by an approved definition."""

    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=True,
            reviewer=f"{review_type.value} reviewer",
            reviewer_competency="Independent competent test engineer",
            reviewed_at=FIXED_TIME,
            evidence_reference_ids=("ref.source",),
        )
        for review_type in MethodReviewType
    )


def make_quantity_input(
    input_id: str,
    name: str,
    value: float,
    *,
    unit: str = "m",
    origin: InputOrigin = InputOrigin.USER_SUPPLIED,
    source_reference_ids: tuple[str, ...] = (),
    decimal_places: int | None = None,
    notes: str | None = None,
) -> CalculationInput:
    """Build one finite length input."""

    return CalculationInput(
        input_id=input_id,
        name=name,
        origin=origin,
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.LENGTH.value,
            value=value,
            unit=unit,
            decimal_places=decimal_places,
        ),
        source_reference_ids=source_reference_ids,
        notes=notes,
    )


def make_mode_input(value: str = "standard") -> CalculationInput:
    """Build the optional categorical fixture input."""

    return CalculationInput(
        input_id="mode",
        name="Calculation mode",
        origin=InputOrigin.USER_SUPPLIED,
        categorical_value=value,
    )


def make_request(
    *,
    method_id: str = "fixture.area",
    method_version: str = "1.0.0",
    calculation_type: str = "fixture.area-calculation",
    request_id: UUID = FIXED_REQUEST_ID,
    requested_at: datetime = FIXED_TIME,
    requested_by: str | None = "Engine test caller",
    design_case_id: UUID | None = FIXED_DESIGN_CASE_ID,
    correlation_id: str | None = "correlation.engine-test",
    inputs: tuple[CalculationInput, ...] | None = None,
    options: tuple[CalculationOption, ...] | None = None,
    assumptions: tuple[CalculationAssumption, ...] = (),
    reference_ids: tuple[str, ...] = (),
) -> CalculationRequest:
    """Build one complete request for the fixture area method."""

    if inputs is None:
        inputs = (
            make_quantity_input("length", "Length", 2.0),
            make_quantity_input("width", "Width", 3.0),
            make_mode_input(),
        )
    if options is None:
        options = (
            CalculationOption(
                option_id="scale",
                value=1.5,
                description="Fixture material scale.",
            ),
        )

    return CalculationRequest(
        request_id=request_id,
        calculation_type=calculation_type,
        method_id=method_id,
        method_version=method_version,
        requested_at=requested_at,
        requested_by=requested_by,
        design_case_id=design_case_id,
        correlation_id=correlation_id,
        inputs=inputs,
        assumptions=assumptions,
        options=options,
        reference_ids=reference_ids,
    )


def make_applicability_rule() -> ApplicabilityRule:
    """Build one blocking reviewed applicability rule."""

    return ApplicabilityRule(
        rule_id="rule.positive-area",
        title="Inputs are outside the method applicability",
        description="The reviewed area method does not accept these inputs.",
        input_ids=("length", "width"),
        severity=FindingSeverity.ERROR,
        blocking=True,
        required_action="Select a reviewed method that covers the inputs.",
        verification_requirement_ids=("verify.review",),
        reference_ids=("ref.source",),
    )


def make_safety_requirement() -> SafetyRequirement:
    """Build one blocking reviewed safety requirement."""

    return SafetyRequirement(
        requirement_id="confirm-length-basis",
        title="Confirm the length basis",
        hazard="An incorrect length basis can invalidate the design result.",
        required_input_ids=("length",),
        severity=FindingSeverity.CRITICAL,
        blocking=True,
        required_action="Confirm the length using approved source data.",
        verification_requirement_ids=("verify.review",),
        reference_ids=("ref.source",),
        required_competency="Competent test engineer",
    )


def make_definition(
    *,
    method_id: str = "fixture.area",
    method_version: str = "1.0.0",
    calculation_type: str = "fixture.area-calculation",
    lifecycle_status: MethodLifecycleStatus = (
        MethodLifecycleStatus.APPROVED
    ),
    compatibility: EngineCompatibility | None = None,
    applicability: bool = False,
    safety: bool = False,
    safety_critical_length: bool = False,
    iteration_limits: IterationLimits | None = None,
) -> CalculationMethodDefinition:
    """Build a complete reviewed fixture definition."""

    if compatibility is None:
        compatibility = EngineCompatibility(
            minimum_version="1.0.0",
            maximum_exclusive_version="2.0.0",
        )

    length_specification = MethodInputSpecification(
        input_id="length",
        name="Length",
        description="First controlled length used by the area fixture.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
        quantity_kind=QuantityKind.LENGTH,
        canonical_unit="m",
        numeric_range=NumericApplicabilityRange(
            minimum=0.0,
            maximum=100.0,
        ),
        safety_critical=safety_critical_length,
        reference_ids=("ref.source",),
        verification_requirement_ids=(
            ("verify.review",)
            if safety_critical_length
            else ()
        ),
    )
    width_specification = MethodInputSpecification(
        input_id="width",
        name="Width",
        description="Second controlled length used by the area fixture.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
        quantity_kind=QuantityKind.LENGTH,
        canonical_unit="m",
        numeric_range=NumericApplicabilityRange(
            minimum=0.0,
            maximum=100.0,
        ),
        reference_ids=("ref.source",),
    )
    mode_specification = MethodInputSpecification(
        input_id="mode",
        name="Calculation mode",
        description="Optional reviewed categorical mode.",
        presence=InputPresence.OPTIONAL,
        value_type=InputValueType.CATEGORICAL_TEXT,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=("standard", "alternate"),
    )

    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=method_version,
        calculation_type=calculation_type,
        title="Area calculation fixture",
        description=(
            "Reviewed deterministic method used only for engine tests."
        ),
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=lifecycle_status,
        engine_compatibility=compatibility,
        input_specifications=(
            length_specification,
            width_specification,
            mode_specification,
        ),
        option_specifications=(
            MethodOptionSpecification(
                option_id="scale",
                description="Material scale applied to fixture area.",
                value_type=MethodOptionValueType.FLOAT,
                required=True,
                numeric_range=NumericApplicabilityRange(
                    minimum=0.1,
                    maximum=10.0,
                ),
            ),
        ),
        applicability_rules=(
            (make_applicability_rule(),)
            if applicability
            else ()
        ),
        safety_requirements=(
            (make_safety_requirement(),)
            if safety
            else ()
        ),
        formulas=(
            FormulaMetadata(
                formula_identifier="formula.area",
                title="Scaled rectangular area",
                description="Multiply length, width, and reviewed scale.",
                reference_ids=("ref.source",),
            ),
        ),
        references=(
            make_reference(
                "ref.source",
                ReferenceType.ENGINEERING_TEXTBOOK,
            ),
            make_reference(
                "ref.vector",
                ReferenceType.TEST_VECTOR,
            ),
        ),
        verification_requirements=(make_verification(),),
        reviews=make_reviews(),
        test_vector_reference_ids=("ref.vector",),
        iteration_limits=iteration_limits,
        superseded_by_version=(
            "2.0.0"
            if lifecycle_status is MethodLifecycleStatus.SUPERSEDED
            else None
        ),
        disabled_reason=(
            "The fixture method has been administratively disabled."
            if lifecycle_status is MethodLifecycleStatus.DISABLED
            else None
        ),
        limitations=("Fixture method; not for real design.",),
        exclusions=("No product selection.",),
        required_reviewer_competency="Competent test engineer",
        disclaimer="Engineering decision support requires review.",
    )


def make_max_verification_definition(
    *,
    safety: bool = False,
) -> CalculationMethodDefinition:
    """Fill the reviewed verification collection to its hard limit."""

    definition = make_definition(safety=safety)
    requirements = (
        make_verification(),
        *(
            make_verification(f"verify.capacity.{index}")
            for index in range(1, MAX_VERIFICATION_REQUIREMENTS)
        ),
    )
    return CalculationMethodDefinition.model_validate(
        {
            **definition.model_dump(mode="python", round_trip=True),
            "verification_requirements": requirements,
        }
    )


def _context_inputs(
    context: MethodExecutionContext,
) -> tuple[CalculationInput, CalculationInput]:
    """Return the normalized length and width inputs."""

    values = {
        value.input_id: value
        for value in context.normalized_inputs
    }
    return values["length"], values["width"]


def _area_quantity(
    context: MethodExecutionContext,
) -> EngineeringQuantity:
    """Calculate the fixture output from normalized immutable context."""

    length, width = _context_inputs(context)
    assert length.quantity is not None
    assert width.quantity is not None
    scale_option = next(
        option
        for option in context.effective_options
        if option.option_id == "scale"
    )
    assert isinstance(scale_option.value, float)
    return EngineeringQuantity(
        quantity_kind=QuantityKind.AREA.value,
        value=(
            length.quantity.value
            * width.quantity.value
            * scale_option.value
        ),
        unit="m2",
    )


def _success_outcome(
    context: MethodExecutionContext,
) -> MethodExecutionOutcome:
    """Return a fully linked non-iterative fixture outcome."""

    quantity = _area_quantity(context)
    trace_step = CalculationTraceStep(
        step_id="execution.area",
        sequence=1,
        kind=TraceStepKind.CALCULATION,
        status=TraceStepStatus.COMPLETED,
        title="Calculate scaled area",
        description="Apply the reviewed scaled-area formula.",
        formula_identifier="formula.area",
        input_ids=("length", "width"),
        output_values=(
            CalculationTraceValue(
                value_id="value.area",
                name="Scaled area",
                quantity=quantity,
                source_reference_ids=("ref.source",),
            ),
        ),
    )
    output = CalculationOutput(
        output_id="output.area",
        name="Scaled area",
        quantity=quantity,
        source_step_ids=("execution.area",),
        source_value_ids=("value.area",),
        source_reference_ids=("ref.source",),
        description="Final scaled area from the reviewed fixture.",
    )
    return MethodExecutionOutcome(
        trace_steps=(trace_step,),
        outputs=(output,),
        limitations=("Execution fixture limitation.",),
        exclusions=("Execution fixture exclusion.",),
    )


def execute_success(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Execute the valid non-iterative fixture."""

    _record_executor_call("success")
    assert iteration_controller is None
    return _success_outcome(context)


def execute_warning(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a valid outcome with one visible non-blocking warning."""

    _record_executor_call("warning")
    assert iteration_controller is None
    warning = CalculationFinding(
        finding_id="execution.input-quality-warning",
        category=FindingCategory.DATA_QUALITY,
        severity=FindingSeverity.WARNING,
        title="Input quality review advised",
        message="The result is valid but warrants an additional review.",
        blocking=False,
        verification_requirement_ids=("verify.review",),
        reference_ids=("ref.source",),
    )
    return _success_outcome(context).model_copy(
        update={"findings": (warning,)}
    )


def execute_unverified_assumption(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a valid result-affecting assumption awaiting verification."""

    _record_executor_call("assumption")
    assert iteration_controller is None
    assumption = CalculationAssumption(
        assumption_id="assumption.fixture-factor",
        statement="The fixture scale remains representative.",
        origin=InputOrigin.SYSTEM_DERIVED,
        affects_result=True,
        requires_verification=True,
        verification_completed=False,
        verification_requirement_ids=("verify.review",),
        source_reference_ids=("ref.source",),
    )
    return _success_outcome(context).model_copy(
        update={"assumptions": (assumption,)}
    )


def execute_raises_secret(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Raise an internal exception whose details must remain private."""

    del context, iteration_controller
    _record_executor_call("raises")
    raise RuntimeError("secret-executor-token=never-render")


def execute_keyboard_interrupt(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Raise process-control flow that the engine must not swallow."""

    del context, iteration_controller
    _record_executor_call("keyboard-interrupt")
    raise KeyboardInterrupt


def execute_context_attribute_tamper(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Attempt to replace immutable engine-owned execution context."""

    del iteration_controller
    _record_executor_call("context-attribute-tamper")
    context.engine_version = "9.9.9"  # type: ignore[misc]
    raise AssertionError("Execution context mutation was accepted.")


def execute_wrong_type(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return an object outside the reviewed outcome contract."""

    del context, iteration_controller
    _record_executor_call("wrong-type")
    return object()  # type: ignore[return-value]


def execute_invalid_constructed(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a bypass-constructed invalid outcome."""

    del context, iteration_controller
    _record_executor_call("constructed-invalid")
    return MethodExecutionOutcome.model_construct(
        trace_steps=(),
        outputs=(),
        findings=(),
        assumptions=(),
        iteration_outcome=None,
        limitations=(),
        exclusions=(),
    )


def execute_undeclared_formula(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a valid model that names an undeclared formula."""

    _record_executor_call("undeclared-formula")
    assert iteration_controller is None
    outcome = _success_outcome(context)
    bad_step = outcome.trace_steps[0].model_copy(
        update={"formula_identifier": "formula.undeclared"}
    )
    return outcome.model_copy(update={"trace_steps": (bad_step,)})


def execute_unresolved_trace_reference(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a trace value linked to absent trusted evidence."""

    _record_executor_call("bad-trace-reference")
    assert iteration_controller is None
    outcome = _success_outcome(context)
    trace_value = outcome.trace_steps[0].output_values[0].model_copy(
        update={"source_reference_ids": ("ref.unresolved",)}
    )
    trace_step = outcome.trace_steps[0].model_copy(
        update={"output_values": (trace_value,)}
    )
    return outcome.model_copy(update={"trace_steps": (trace_step,)})


def execute_unresolved_output_reference(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return an output linked to absent trusted evidence."""

    _record_executor_call("bad-output-reference")
    assert iteration_controller is None
    outcome = _success_outcome(context)
    output = outcome.outputs[0].model_copy(
        update={"source_reference_ids": ("ref.unresolved",)}
    )
    return outcome.model_copy(update={"outputs": (output,)})


def execute_unresolved_finding_reference(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a finding linked to absent trusted evidence."""

    _record_executor_call("bad-finding-reference")
    assert iteration_controller is None
    finding = CalculationFinding(
        finding_id="execution.unresolved-reference",
        category=FindingCategory.DATA_QUALITY,
        severity=FindingSeverity.CAUTION,
        title="Unresolved evidence fixture",
        message="This finding intentionally names absent evidence.",
        reference_ids=("ref.unresolved",),
    )
    return _success_outcome(context).model_copy(
        update={"findings": (finding,)}
    )


def execute_unresolved_finding_verification(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a finding linked to absent verification evidence."""

    _record_executor_call("bad-finding-verification")
    assert iteration_controller is None
    finding = CalculationFinding(
        finding_id="execution.unresolved-verification",
        category=FindingCategory.DATA_QUALITY,
        severity=FindingSeverity.CAUTION,
        title="Unresolved verification fixture",
        message="This finding intentionally names absent verification.",
        verification_requirement_ids=("verify.unresolved",),
    )
    return _success_outcome(context).model_copy(
        update={"findings": (finding,)}
    )


def execute_output_value_tamper(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return an output that does not match its source trace value."""

    _record_executor_call("output-tamper")
    assert iteration_controller is None
    outcome = _success_outcome(context)
    assert outcome.outputs[0].quantity is not None
    tampered_quantity = outcome.outputs[0].quantity.model_copy(
        update={"value": outcome.outputs[0].quantity.value + 1.0}
    )
    tampered_output = outcome.outputs[0].model_copy(
        update={"quantity": tampered_quantity}
    )
    return outcome.model_copy(update={"outputs": (tampered_output,)})


def execute_sequence_tamper(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return a bypass-constructed outcome with a forged trace sequence."""

    _record_executor_call("sequence-tamper")
    assert iteration_controller is None
    outcome = _success_outcome(context)
    bad_step = CalculationTraceStep.model_construct(
        **{
            **outcome.trace_steps[0].model_dump(
                mode="python",
                round_trip=True,
            ),
            "sequence": 99,
        }
    )
    return MethodExecutionOutcome.model_construct(
        trace_steps=(bad_step,),
        outputs=outcome.outputs,
        findings=(),
        assumptions=(),
        iteration_outcome=None,
        limitations=(),
        exclusions=(),
    )


def applicability_accept(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    """Accept the reviewed fixture applicability rule."""

    return (
        rule.rule_id == "rule.positive-area"
        and tuple(value.input_id for value in linked_inputs)
        == rule.input_ids
    )


def applicability_reject(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    """Reject the reviewed fixture applicability rule."""

    del rule, linked_inputs
    return False


def applicability_raises_secret(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    """Raise internal applicability details that must remain private."""

    del rule, linked_inputs
    raise RuntimeError("secret-applicability-token=never-render")


def applicability_keyboard_interrupt(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    """Raise process-control flow that validation must not swallow."""

    del rule, linked_inputs
    raise KeyboardInterrupt


def safety_trigger(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Trigger the fixture definition's declared safety requirement."""

    del context
    return MethodSafetyExtension(
        triggers=(
            SafetyTrigger(
                requirement_id="confirm-length-basis",
                message="The length basis requires independent review.",
            ),
        )
    )


def safety_raises_secret(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Raise internal safety details that must remain private."""

    del context
    raise RuntimeError("secret-safety-token=never-render")


def safety_keyboard_interrupt(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Raise process-control flow that safety evaluation must not swallow."""

    del context
    raise KeyboardInterrupt


def _iterative_outcome(
    context: MethodExecutionContext,
    iteration_controller: IterationController,
    residuals: tuple[float, ...],
) -> MethodExecutionOutcome:
    """Record residuals and return state matching the engine controller."""

    trace_steps: list[CalculationTraceStep] = []
    for iteration_number, residual in enumerate(residuals, start=1):
        iteration_controller.record(
            residual,
            reference_magnitude=10.0,
        )
        quantity = EngineeringQuantity(
            quantity_kind=QuantityKind.AREA.value,
            value=_area_quantity(context).value + abs(residual),
            unit="m2",
        )
        step_id = f"iteration.{iteration_number}"
        value_id = f"iteration-value.{iteration_number}"
        trace_steps.append(
            CalculationTraceStep(
                step_id=step_id,
                sequence=iteration_number,
                kind=TraceStepKind.ITERATION,
                status=TraceStepStatus.COMPLETED,
                title=f"Fixture iteration {iteration_number}",
                description="Record one reviewed fixture residual.",
                formula_identifier="formula.area",
                input_ids=("length", "width"),
                output_values=(
                    CalculationTraceValue(
                        value_id=value_id,
                        name=f"Iterated area {iteration_number}",
                        quantity=quantity,
                        source_reference_ids=("ref.source",),
                    ),
                ),
                dependency_step_ids=(
                    ()
                    if iteration_number == 1
                    else (f"iteration.{iteration_number - 1}",)
                ),
                iteration_number=iteration_number,
            )
        )
        if iteration_controller.terminated:
            break

    assert iteration_controller.outcome is not None
    outputs: tuple[CalculationOutput, ...] = ()
    if iteration_controller.outcome.converged:
        final_step = trace_steps[-1]
        final_value = final_step.output_values[0]
        outputs = (
            CalculationOutput(
                output_id="output.area",
                name="Scaled area",
                quantity=final_value.quantity,
                source_step_ids=(final_step.step_id,),
                source_value_ids=(final_value.value_id,),
                source_reference_ids=("ref.source",),
            ),
        )

    return MethodExecutionOutcome(
        trace_steps=tuple(trace_steps),
        outputs=outputs,
        iteration_outcome=iteration_controller.outcome,
    )


def execute_iterative_converged(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Converge inside the reviewed iterative budget."""

    _record_executor_call("iterative-converged")
    assert isinstance(iteration_controller, IterationController)
    return _iterative_outcome(
        context,
        iteration_controller,
        (1.0, 0.05),
    )


def execute_iterative_maximum(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Use the complete reviewed budget without convergence."""

    _record_executor_call("iterative-maximum")
    assert isinstance(iteration_controller, IterationController)
    return _iterative_outcome(
        context,
        iteration_controller,
        (1.0, 0.5, 0.2),
    )


def execute_iterative_diverged(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Report a residual beyond the reviewed divergence limit."""

    _record_executor_call("iterative-diverged")
    assert isinstance(iteration_controller, IterationController)
    return _iterative_outcome(
        context,
        iteration_controller,
        (11.0,),
    )


def execute_iterative_nonfinite(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Report a non-finite residual and fail through the controller."""

    del context
    _record_executor_call("iterative-nonfinite")
    assert isinstance(iteration_controller, IterationController)
    iteration_controller.record(nan)
    raise AssertionError("Non-finite residual was unexpectedly accepted.")


def execute_iterative_unused_controller(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Ignore a required controller to test fail-closed enforcement."""

    _record_executor_call("iterative-unused")
    assert isinstance(iteration_controller, IterationController)
    return _success_outcome(context)


def execute_iterative_forged_outcome(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Return iteration metadata different from controller-owned state."""

    _record_executor_call("iterative-forged")
    assert isinstance(iteration_controller, IterationController)
    outcome = _iterative_outcome(
        context,
        iteration_controller,
        (0.05,),
    )
    assert outcome.iteration_outcome is not None
    forged = outcome.iteration_outcome.model_copy(
        update={"final_residual": 0.04}
    )
    return outcome.model_copy(update={"iteration_outcome": forged})


def execute_iterative_attribute_tamper(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Attempt to replace engine-owned iteration state."""

    del context
    _record_executor_call("iterative-attribute-tamper")
    assert isinstance(iteration_controller, IterationController)
    iteration_controller._iteration_count = 99  # type: ignore[attr-defined]
    raise AssertionError("Iteration controller mutation was accepted.")


def make_iteration_limits(
    *,
    maximum_iterations: int = 3,
    absolute_tolerance: float = 0.1,
    relative_tolerance: float = 0.0,
    divergence_limit: float | None = 10.0,
) -> IterationLimits:
    """Build reviewed limits for controller and engine tests."""

    return IterationLimits(
        maximum_iterations=maximum_iterations,
        absolute_tolerance=absolute_tolerance,
        relative_tolerance=relative_tolerance,
        divergence_limit=divergence_limit,
        convergence_value_id="value.area",
        convergence_description="Converge the fixture area residual.",
    )


def make_engine(
    *,
    definition: CalculationMethodDefinition | None = None,
    implementation=execute_success,
    applicability_evaluator=None,
    safety_evaluator=None,
    deterministic_identity: bool = True,
) -> CalculationEngine:
    """Build one immutable single-registration calculation engine."""

    if definition is None:
        definition = make_definition()

    applicability_evaluators = {}
    if definition.applicability_rules:
        assert applicability_evaluator is not None
        applicability_evaluators = {
            definition.applicability_rules[0].rule_id:
                applicability_evaluator,
        }

    registration = MethodRegistration(
        definition=definition,
        implementation=implementation,
        applicability_evaluators=applicability_evaluators,
        safety_evaluator=safety_evaluator,
    )
    registry = CalculationMethodRegistry((registration,))
    if deterministic_identity:
        return CalculationEngine(
            registry=registry,
            clock=fixed_clock,
            id_factory=fixed_id_factory,
        )
    return CalculationEngine(
        registry=registry,
        clock=fixed_clock,
    )


def make_external_evidence(
    reference_id: str = "ref.external",
    *,
    verified: bool = False,
    verification_id: str | None = None,
) -> TrustedExecutionEvidence:
    """Build exact server-resolved external evidence."""

    requirements = (
        ()
        if verification_id is None
        else (make_verification(verification_id),)
    )
    return TrustedExecutionEvidence(
        references=(
            make_reference(
                reference_id,
                ReferenceType.USER_DOCUMENT,
                verified=verified,
            ),
        ),
        verification_requirements=requirements,
    )


def test_canonical_fingerprint_has_frozen_golden_bytes_and_hash() -> None:
    """The schema serialization must remain byte-for-byte stable."""

    payload = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(
            make_quantity_input("width", "Width alias", 3.0),
            make_quantity_input(
                "length",
                "Length alias",
                2.0,
                decimal_places=4,
                notes="Presentation-only metadata.",
            ),
        ),
        effective_options=(
            CalculationOption(
                option_id="scale",
                value=1.5,
                description="Presentation-only option description.",
            ),
        ),
    )
    expected = (
        b'{"fingerprint_schema":"e4m.calc.v1","inputs":['
        b'{"input_id":"length","quantity":{"quantity_kind":"length",'
        b'"uncertainty":null,"uncertainty_basis":null,"unit":"m",'
        b'"value":"2"}},{"input_id":"width","quantity":{'
        b'"quantity_kind":"length","uncertainty":null,'
        b'"uncertainty_basis":null,"unit":"m","value":"3"}}],'
        b'"method":{"method_id":"fixture.area","method_version":"1.0.0"},'
        b'"options":[{"option_id":"scale","type":"float","value":"1.5"}]}'
    )

    canonical = canonical_fingerprint_bytes(payload)
    assert payload["fingerprint_schema"] == FINGERPRINT_SCHEMA
    assert canonical == expected
    assert fingerprint_payload(payload) == sha256(expected).hexdigest()
    assert fingerprint_payload(payload) == (
        "92b959caaa87ac8b8719408febbb9312"
        "cf3e1e9de8f68289a6034f8bba9534c5"
    )


def test_canonical_fingerprint_sorts_inputs_options_and_identifiers() -> None:
    """Caller collection order cannot affect canonical bytes."""

    length = make_quantity_input("length", "Length", 2.0)
    width = make_quantity_input("width", "Width", 3.0)
    first = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(width, length),
        effective_options=(
            CalculationOption(option_id="z-option", value=True),
            CalculationOption(option_id="a-option", value=2),
        ),
        status=CalculationStatus.COMPLETED_WITH_WARNINGS,
        finding_ids=("finding.z", "finding.a"),
        missing_input_ids=("width", "length"),
    )
    second = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(length, width),
        effective_options=(
            CalculationOption(option_id="a-option", value=2),
            CalculationOption(option_id="z-option", value=True),
        ),
        status=CalculationStatus.COMPLETED_WITH_WARNINGS,
        finding_ids=("finding.a", "finding.z"),
        missing_input_ids=("length", "width"),
    )

    assert canonical_fingerprint_bytes(first) == canonical_fingerprint_bytes(
        second
    )
    assert fingerprint_payload(first) == fingerprint_payload(second)


def test_canonical_fingerprint_sorts_resolved_evidence() -> None:
    """Resolved reference and verification order is non-material."""

    first_reference = make_reference(
        "ref.external-a",
        ReferenceType.USER_DOCUMENT,
        verified=True,
    )
    second_reference = make_reference(
        "ref.external-b",
        ReferenceType.USER_DOCUMENT,
        verified=True,
    )
    first_verification = make_verification("verify.external-a")
    second_verification = make_verification("verify.external-b")
    common: dict[str, Any] = {
        "method_id": "fixture.area",
        "method_version": "1.0.0",
        "normalized_inputs": (),
        "effective_options": (),
    }
    first = build_fingerprint_payload(
        **common,
        references=(second_reference, first_reference),
        verification_requirements=(
            second_verification,
            first_verification,
        ),
    )
    second = build_fingerprint_payload(
        **common,
        references=(first_reference, second_reference),
        verification_requirements=(
            first_verification,
            second_verification,
        ),
    )

    assert first == second
    assert fingerprint_payload(first) == fingerprint_payload(second)


def test_presentation_and_alias_metadata_are_fingerprint_ephemeral() -> None:
    """Names, notes, precision, and option descriptions are not material."""

    first_input = make_quantity_input(
        "length",
        "Length",
        2.0,
        decimal_places=2,
        notes="First note.",
    )
    second_input = make_quantity_input(
        "length",
        "Renamed presentation label",
        2.0,
        notes="Different note.",
    )
    first = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(first_input,),
        effective_options=(
            CalculationOption(
                option_id="scale",
                value=1.5,
                description="First description.",
            ),
        ),
    )
    second = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(second_input,),
        effective_options=(
            CalculationOption(
                option_id="scale",
                value=1.5,
                description="Second description.",
            ),
        ),
    )

    assert fingerprint_payload(first) == fingerprint_payload(second)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param("input", id="normalized-input"),
        pytest.param("option", id="material-option"),
        pytest.param("method", id="method-version"),
        pytest.param("assumption", id="assumption-content"),
        pytest.param("status", id="result-disposition"),
    ],
)
def test_material_fingerprint_mutations_change_hash(mutation: str) -> None:
    """Every substantive execution input changes the fingerprint."""

    assumption = CalculationAssumption(
        assumption_id="assumption.material",
        statement="The material assumption is one.",
        origin=InputOrigin.USER_SUPPLIED,
    )
    values: dict[str, Any] = {
        "method_id": "fixture.area",
        "method_version": "1.0.0",
        "normalized_inputs": (
            make_quantity_input("length", "Length", 2.0),
        ),
        "effective_options": (
            CalculationOption(option_id="scale", value=1.5),
        ),
        "assumptions": (assumption,),
        "status": CalculationStatus.COMPLETED,
    }
    baseline = fingerprint_payload(build_fingerprint_payload(**values))

    if mutation == "input":
        values["normalized_inputs"] = (
            make_quantity_input("length", "Length", 2.1),
        )
    elif mutation == "option":
        values["effective_options"] = (
            CalculationOption(option_id="scale", value=1.6),
        )
    elif mutation == "method":
        values["method_version"] = "1.0.1"
    elif mutation == "assumption":
        values["assumptions"] = (
            assumption.model_copy(
                update={"statement": "The material assumption is two."}
            ),
        )
    else:
        values["status"] = CalculationStatus.COMPLETED_WITH_WARNINGS
        values["finding_ids"] = ("finding.material",)

    assert fingerprint_payload(build_fingerprint_payload(**values)) != baseline


def test_canonical_numbers_normalize_signed_zero_and_exponent_forms() -> None:
    """Equivalent finite numbers receive one decimal representation."""

    first = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(
            make_quantity_input("length", "Length", -0.0),
            make_quantity_input("width", "Width", 1e-06),
        ),
        effective_options=(),
    )
    second = build_fingerprint_payload(
        method_id="fixture.area",
        method_version="1.0.0",
        normalized_inputs=(
            make_quantity_input("length", "Length", 0.0),
            make_quantity_input("width", "Width", 0.000001),
        ),
        effective_options=(),
    )

    assert first == second
    rendered = canonical_fingerprint_bytes(first)
    assert b'"value":"0"' in rendered
    assert b'"value":"0.000001"' in rendered
    assert b"e-" not in rendered.lower()


@pytest.mark.parametrize(
    ("inputs", "options", "assumptions", "finding_ids"),
    [
        pytest.param(
            (
                make_quantity_input("length", "Length", 1.0),
                make_quantity_input("LENGTH", "Other", 2.0),
            ),
            (),
            (),
            (),
            id="duplicate-input",
        ),
        pytest.param(
            (),
            (
                CalculationOption(option_id="scale", value=1.0),
                CalculationOption(option_id="SCALE", value=2.0),
            ),
            (),
            (),
            id="duplicate-option",
        ),
        pytest.param(
            (),
            (),
            (
                CalculationAssumption(
                    assumption_id="assumption.one",
                    statement="First assumption.",
                    origin=InputOrigin.USER_SUPPLIED,
                ),
                CalculationAssumption(
                    assumption_id="ASSUMPTION.ONE",
                    statement="Second assumption.",
                    origin=InputOrigin.USER_SUPPLIED,
                ),
            ),
            (),
            id="duplicate-assumption",
        ),
        pytest.param(
            (),
            (),
            (),
            ("finding.one", "FINDING.ONE"),
            id="duplicate-finding",
        ),
    ],
)
def test_fingerprint_builder_rejects_ambiguous_identifiers(
    inputs: tuple[CalculationInput, ...],
    options: tuple[CalculationOption, ...],
    assumptions: tuple[CalculationAssumption, ...],
    finding_ids: tuple[str, ...],
) -> None:
    """Case-colliding canonical identifiers fail closed."""

    with pytest.raises(CalculationExecutionContractError):
        build_fingerprint_payload(
            method_id="fixture.area",
            method_version="1.0.0",
            normalized_inputs=inputs,
            effective_options=options,
            assumptions=assumptions,
            status=(
                CalculationStatus.COMPLETED_WITH_WARNINGS
                if finding_ids
                else CalculationStatus.COMPLETED
            ),
            finding_ids=finding_ids,
        )


@pytest.mark.parametrize(
    ("method_id", "method_version"),
    [
        pytest.param("!", "1.0.0", id="invalid-method"),
        pytest.param("fixture.area", "1.0", id="invalid-version"),
        pytest.param("fixture.area", "1.0.0-", id="malformed-prerelease"),
    ],
)
def test_fingerprint_builder_rejects_noncanonical_method_identity(
    method_id: str,
    method_version: str,
) -> None:
    """Only stable controlled method identities reach hashing."""

    with pytest.raises(CalculationExecutionContractError):
        build_fingerprint_payload(
            method_id=method_id,
            method_version=method_version,
            normalized_inputs=(),
            effective_options=(),
        )


@pytest.mark.parametrize(
    "method_version",
    [
        "1.0.0-alpha.1",
        "1.0.0+build.7",
        "1.0.0-rc.2+build.7",
    ],
)
def test_fingerprint_builder_accepts_canonical_semantic_versions(
    method_version: str,
) -> None:
    """Canonical prerelease and build versions remain exact identities."""

    payload = build_fingerprint_payload(
        method_id="fixture.area",
        method_version=method_version,
        normalized_inputs=(),
        effective_options=(),
    )
    assert payload["method"]["method_version"] == method_version


def test_canonical_serializer_rejects_unsupported_or_nonfinite_data() -> None:
    """The generic byte boundary never emits NaN or object repr strings."""

    with pytest.raises(CalculationExecutionContractError):
        canonical_fingerprint_bytes({"value": nan})
    with pytest.raises(CalculationExecutionContractError):
        canonical_fingerprint_bytes({"value": object()})


@pytest.mark.parametrize(
    ("field_name", "oversized_value"),
    [
        pytest.param(
            "normalized_inputs",
            tuple(
                make_quantity_input("length", "Length", 1.0)
                for _ in range(MAX_INPUTS + 1)
            ),
            id="inputs",
        ),
        pytest.param(
            "effective_options",
            tuple(
                CalculationOption(option_id="scale", value=1.0)
                for _ in range(MAX_OPTIONS + 1)
            ),
            id="options",
        ),
        pytest.param(
            "assumptions",
            tuple(
                CalculationAssumption(
                    assumption_id="assumption.bound",
                    statement="Bounded assumption fixture.",
                    origin=InputOrigin.USER_SUPPLIED,
                )
                for _ in range(MAX_ASSUMPTIONS + 1)
            ),
            id="assumptions",
        ),
        pytest.param(
            "references",
            tuple(
                make_reference(
                    "ref.bound",
                    ReferenceType.USER_DOCUMENT,
                    verified=False,
                )
                for _ in range(MAX_REFERENCES + 1)
            ),
            id="references",
        ),
        pytest.param(
            "verification_requirements",
            tuple(
                make_verification("verify.bound")
                for _ in range(MAX_VERIFICATION_REQUIREMENTS + 1)
            ),
            id="verification-requirements",
        ),
        pytest.param(
            "finding_ids",
            tuple(
                f"finding.bound.{index}"
                for index in range(MAX_FINDINGS + 1)
            ),
            id="finding-identifiers",
        ),
        pytest.param(
            "missing_input_ids",
            tuple(
                f"input.bound.{index}"
                for index in range(MAX_MISSING_INPUTS + 1)
            ),
            id="missing-identifiers",
        ),
    ],
)
def test_fingerprint_collections_are_hard_bounded(
    field_name: str,
    oversized_value: tuple[Any, ...],
) -> None:
    """Fingerprint construction rejects oversized caller collections early."""

    values: dict[str, Any] = {
        "method_id": "fixture.area",
        "method_version": "1.0.0",
        "normalized_inputs": (),
        "effective_options": (),
        "status": CalculationStatus.COMPLETED_WITH_WARNINGS,
    }
    values[field_name] = oversized_value
    with pytest.raises(
        CalculationExecutionContractError,
        match="exceeds the controlled collection limit",
    ):
        build_fingerprint_payload(**values)


def test_attempt_payload_preserves_typed_unvalidated_provenance() -> None:
    """Failed-attempt hashing retains source and missing-state distinctions."""

    definition = make_definition()
    imported = make_quantity_input(
        "length",
        "Length",
        2.0,
        origin=InputOrigin.IMPORTED,
        source_reference_ids=("ref.external",),
        notes="Attempt note is intentionally not fingerprinted.",
    )
    unknown = make_quantity_input(
        "unknown-length",
        "Unknown length",
        9.0,
    )
    assumption = CalculationAssumption(
        assumption_id="assumption.attempt",
        statement="Attempt-specific assumption.",
        origin=InputOrigin.IMPORTED,
        source_reference_ids=("ref.external",),
        requires_verification=True,
        verification_requirement_ids=("verify.external",),
    )
    request = make_request(
        inputs=(unknown, imported),
        assumptions=(assumption,),
        options=(
            CalculationOption(option_id="scale", value=2.0),
        ),
        reference_ids=("ref.external",),
    )

    payload = build_attempt_fingerprint_payload(
        definition=definition,
        request=request,
        disposition="blocked",
        finding_ids=("finding.blocked",),
    )
    records = {
        value["input_id"]: value
        for value in payload["inputs"]
    }

    assert payload["fingerprint_schema"] == ATTEMPT_FINGERPRINT_SCHEMA
    assert records["length"]["state"] == "supplied_unvalidated"
    assert records["length"]["origin"] == InputOrigin.IMPORTED.value
    assert records["length"]["source_reference_ids"] == ["ref.external"]
    assert records["width"] == {
        "input_id": "width",
        "state": "missing",
    }
    assert records["mode"] == {
        "input_id": "mode",
        "state": "missing",
    }
    assert records["unknown-length"]["state"] == "unknown"
    assert payload["reference_ids"] == ["ref.external"]
    assert payload["assumptions"][0]["assumption_id"] == (
        "assumption.attempt"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param("provenance", id="input-provenance"),
        pytest.param("assumption", id="request-assumption"),
        pytest.param("reference", id="request-reference"),
        pytest.param("missing", id="missing-input-state"),
        pytest.param("notes", id="unvalidated-input-notes"),
    ],
)
def test_attempt_fingerprint_separates_material_failure_state(
    mutation: str,
) -> None:
    """Distinct invalid attempts cannot collapse onto one provenance hash."""

    definition = make_definition()
    base_assumption = CalculationAssumption(
        assumption_id="assumption.attempt",
        statement="First failed-attempt assumption.",
        origin=InputOrigin.USER_SUPPLIED,
    )
    first = make_request(
        inputs=(
            make_quantity_input("length", "Length", 2.0),
        ),
        assumptions=(base_assumption,),
        reference_ids=("ref.source",),
    )
    changes: dict[str, Any] = {}
    if mutation == "provenance":
        changes["inputs"] = (
            make_quantity_input(
                "length",
                "Length",
                2.0,
                origin=InputOrigin.IMPORTED,
                source_reference_ids=("ref.source",),
            ),
        )
    elif mutation == "assumption":
        changes["assumptions"] = (
            base_assumption.model_copy(
                update={
                    "statement": "Second failed-attempt assumption."
                }
            ),
        )
    elif mutation == "reference":
        changes["reference_ids"] = ("ref.vector",)
    elif mutation == "notes":
        changes["inputs"] = (
            make_quantity_input(
                "length",
                "Length",
                2.0,
                notes="Material failed-attempt context.",
            ),
        )
    else:
        changes["inputs"] = (
            make_quantity_input("width", "Width", 3.0),
        )
    second = first.model_copy(update=changes)

    first_hash = fingerprint_payload(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=first,
            disposition="blocked",
        )
    )
    second_hash = fingerprint_payload(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=second,
            disposition="blocked",
        )
    )
    assert first_hash != second_hash


def test_attempt_and_success_namespaces_do_not_collide() -> None:
    """A blocked attempt and completed normalization use different schemas."""

    definition = make_definition()
    request = make_request()
    attempt = fingerprint_payload(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=request,
            disposition="blocked",
        )
    )
    success = fingerprint_payload(
        build_fingerprint_payload(
            method_id=definition.method_id,
            method_version=definition.method_version,
            normalized_inputs=request.inputs,
            effective_options=request.options,
        )
    )
    assert attempt != success


def test_attempt_fingerprint_is_reordering_and_ephemera_stable() -> None:
    """Failed-attempt order, IDs, timestamps, and precision are ephemeral."""

    definition = make_definition()
    first_inputs = (
        make_quantity_input(
            "length",
            "Length",
            2.0,
            notes="Shared material attempt note.",
        ),
        make_quantity_input("width", "Width", 3.0),
    )
    second_inputs = (
        make_quantity_input("width", "Width", 3.0),
        make_quantity_input(
            "length",
            "Length",
            2.0,
            decimal_places=8,
            notes="Shared material attempt note.",
        ),
    )
    first = make_request(
        request_id=FIXED_REQUEST_ID,
        requested_at=FIXED_TIME,
        inputs=first_inputs,
    )
    second = make_request(
        request_id=SECOND_REQUEST_ID,
        requested_at=SECOND_TIME,
        requested_by="Different failed-attempt caller",
        design_case_id=None,
        correlation_id="correlation.failed-attempt",
        inputs=second_inputs,
    )

    first_hash = fingerprint_payload(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=first,
            disposition="blocked",
        )
    )
    second_hash = fingerprint_payload(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=second,
            disposition="blocked",
        )
    )
    assert first_hash == second_hash


def test_attempt_builder_revalidates_constructed_models_and_disposition(
) -> None:
    """Bypassed models and malformed disposition are rejected."""

    request = make_request()
    invalid_request = CalculationRequest.model_construct(
        **{
            **request.model_dump(mode="python", round_trip=True),
            "method_id": "!",
        }
    )
    with pytest.raises(ValidationError):
        build_attempt_fingerprint_payload(
            definition=make_definition(),
            request=invalid_request,
            disposition="blocked",
        )
    with pytest.raises(CalculationExecutionContractError):
        build_attempt_fingerprint_payload(
            definition=make_definition(),
            request=request,
            disposition="!",
        )


def test_iteration_controller_uses_absolute_tolerance_inclusively() -> None:
    """A residual exactly on the absolute boundary converges."""

    controller = IterationController(
        make_iteration_limits(absolute_tolerance=0.1)
    )

    assert controller.record(0.1) is True
    assert controller.terminated is True
    assert controller.outcome is not None
    assert controller.outcome.converged is True
    assert controller.outcome.iterations_used == 1
    assert controller.outcome.final_residual == 0.1


def test_iteration_controller_uses_relative_tolerance() -> None:
    """Relative tolerance scales against the supplied reference magnitude."""

    controller = IterationController(
        make_iteration_limits(
            absolute_tolerance=0.001,
            relative_tolerance=0.01,
        )
    )

    assert controller.record(0.5, reference_magnitude=100.0) is True
    assert controller.outcome is not None
    assert (
        controller.outcome.termination_reason
        is IterationTerminationReason.CONVERGED
    )


def test_iteration_controller_stops_at_exact_maximum() -> None:
    """The controller records no state beyond its reviewed finite budget."""

    controller = IterationController(
        make_iteration_limits(
            maximum_iterations=2,
            absolute_tolerance=0.01,
        )
    )

    assert controller.record(1.0) is False
    assert controller.record(0.5) is False
    assert controller.outcome is not None
    assert controller.outcome.iterations_used == 2
    assert (
        controller.outcome.termination_reason
        is IterationTerminationReason.MAXIMUM_ITERATIONS
    )
    with pytest.raises(IterationStateError):
        controller.record(0.0)


@pytest.mark.parametrize("value", [nan, inf, -inf])
def test_iteration_controller_rejects_nonfinite_residuals(
    value: float,
) -> None:
    """Non-finite iteration state terminates and raises deterministically."""

    controller = IterationController(make_iteration_limits())

    with pytest.raises(NonFiniteIterationError):
        controller.record(value)
    assert controller.outcome is not None
    assert controller.outcome.iterations_used == 1
    assert (
        controller.outcome.termination_reason
        is IterationTerminationReason.NON_FINITE_VALUE
    )


def test_iteration_controller_rejects_nonfinite_reference() -> None:
    """Reference magnitudes share the same finite-number boundary."""

    controller = IterationController(make_iteration_limits())
    with pytest.raises(NonFiniteIterationError):
        controller.record(1.0, reference_magnitude=inf)
    assert controller.terminated is True


def test_iteration_controller_records_divergence() -> None:
    """A residual beyond the reviewed limit terminates as diverged."""

    controller = IterationController(
        make_iteration_limits(divergence_limit=10.0)
    )

    assert controller.record(10.0001) is False
    assert controller.outcome is not None
    assert (
        controller.outcome.termination_reason
        is IterationTerminationReason.DIVERGED
    )


@pytest.mark.parametrize(
    ("residual", "reference"),
    [
        pytest.param(True, 1.0, id="boolean-residual"),
        pytest.param(1.0, False, id="boolean-reference"),
        pytest.param("1", 1.0, id="text-residual"),
    ],
)
def test_iteration_controller_rejects_non_numeric_values(
    residual: Any,
    reference: Any,
) -> None:
    """Strict iteration state rejects booleans and coercible text."""

    controller = IterationController(make_iteration_limits())
    with pytest.raises(NonFiniteIterationError):
        controller.record(residual, reference_magnitude=reference)
    assert controller.iterations_used == 0
    assert controller.outcome is None


def test_iteration_controller_is_immutable_and_revalidates_limits() -> None:
    """Limits cannot be bypass-constructed or replaced after construction."""

    bypassed = IterationLimits.model_construct(
        maximum_iterations=0,
        absolute_tolerance=0.0,
        relative_tolerance=0.0,
        divergence_limit=None,
        convergence_value_id="value.area",
        convergence_description="Invalid bypassed limits.",
    )
    with pytest.raises(ValidationError):
        IterationController(bypassed)

    controller = IterationController(make_iteration_limits())
    with pytest.raises(AttributeError):
        controller._iteration_count = 2  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        del controller._limits  # type: ignore[attr-defined]


def test_successful_execution_builds_complete_traceable_result() -> None:
    """A reviewed outcome is normalized, executed, and assembled once."""

    engine = make_engine()
    result = engine.execute(make_request())

    assert result.calculation_id == FIXED_CALCULATION_ID
    assert result.request_id == FIXED_REQUEST_ID
    assert result.executed_at == FIXED_TIME
    assert result.engine_version == ENGINE_VERSION
    assert result.method_lifecycle_status is MethodLifecycleStatus.APPROVED
    assert result.status is CalculationStatus.COMPLETED
    assert result.result_fingerprint == (
        "da70b6e3769f7d3ae0fa4702861ad8ea"
        "372af1ba03224d9936ed06591e7bf8e7"
    )
    assert _executor_call_count() == 1
    assert tuple(value.input_id for value in result.normalized_inputs) == (
        "length",
        "width",
        "mode",
    )
    assert tuple(value.sequence for value in result.trace_steps) == (
        1,
        2,
        3,
        4,
    )
    assert result.trace_steps[-1].step_id == "execution.area"
    assert result.outputs[0].quantity is not None
    assert result.outputs[0].quantity.value == 9.0
    assert tuple(value.reference_id for value in result.references) == (
        "ref.source",
        "ref.vector",
    )
    assert result.limitations == (
        "Fixture method; not for real design.",
        "Execution fixture limitation.",
    )
    assert result.exclusions == (
        "No product selection.",
        "Execution fixture exclusion.",
    )


def test_result_is_immutable_and_source_models_are_not_mutated() -> None:
    """Execution copies boundary state without retaining mutable mutation."""

    request = make_request()
    definition = make_definition()
    request_before = request.model_dump_json()
    definition_before = definition.model_dump_json()

    result = make_engine(definition=definition).execute(request)

    assert request.model_dump_json() == request_before
    assert definition.model_dump_json() == definition_before
    with pytest.raises(ValidationError):
        result.status = CalculationStatus.FAILED  # type: ignore[misc]


def test_engine_fingerprint_ignores_request_ephemera_and_input_order() -> None:
    """IDs, timestamps, actors, aliases, and request order are non-material."""

    engine = make_engine()
    first = engine.execute(make_request())
    reordered_inputs = (
        make_mode_input(),
        make_quantity_input(
            "width",
            "Width",
            3.0,
            decimal_places=8,
            notes="Second request metadata.",
        ),
        make_quantity_input(
            "length",
            "Length",
            2.0,
            notes="Another note.",
        ),
    )
    second = engine.execute(
        make_request(
            request_id=SECOND_REQUEST_ID,
            requested_at=SECOND_TIME,
            requested_by="Different caller",
            design_case_id=None,
            correlation_id="correlation.different",
            inputs=reordered_inputs,
            options=(
                CalculationOption(
                    option_id="scale",
                    value=1.5,
                    description="Different request description.",
                ),
            ),
        )
    )

    assert first.request_id != second.request_id
    assert first.result_fingerprint == second.result_fingerprint
    assert first.outputs == second.outputs


@pytest.mark.parametrize(
    "version",
    [
        "1.0.0-rc.2",
        "1.0.0+build.7",
    ],
)
def test_engine_executes_exact_canonical_prerelease_and_build_version(
    version: str,
) -> None:
    """Registry and fingerprinting preserve the complete semantic version."""

    definition = make_definition(method_version=version)
    result = make_engine(definition=definition).execute(
        make_request(method_version=version)
    )

    assert result.status is CalculationStatus.COMPLETED
    assert result.method_version == version
    assert _executor_call_count() == 1


@pytest.mark.parametrize(
    ("calculation_request", "error_type"),
    [
        pytest.param(
            make_request(method_id="fixture.unknown"),
            UnknownMethodError,
            id="unknown-method",
        ),
        pytest.param(
            make_request(method_version="9.9.9"),
            UnknownMethodVersionError,
            id="unknown-version",
        ),
        pytest.param(
            make_request(calculation_type="fixture.wrong-type"),
            MethodCalculationTypeError,
            id="wrong-calculation-type",
        ),
    ],
)
def test_exact_registry_lookup_gates_before_executor(
    calculation_request: CalculationRequest,
    error_type: type[Exception],
) -> None:
    """No fallback or type coercion can reach an implementation."""

    engine = make_engine()
    with pytest.raises(error_type):
        engine.execute(calculation_request)
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    "lifecycle_status",
    [
        MethodLifecycleStatus.DRAFT,
        MethodLifecycleStatus.TECHNICAL_REVIEW,
        MethodLifecycleStatus.SAFETY_REVIEW,
        MethodLifecycleStatus.STANDARDS_REVIEW,
        MethodLifecycleStatus.SUPERSEDED,
        MethodLifecycleStatus.DISABLED,
    ],
)
def test_nonapproved_lifecycle_returns_visible_block_without_execution(
    lifecycle_status: MethodLifecycleStatus,
) -> None:
    """Every non-approved exact version returns a traceable blocked result."""

    definition = make_definition(lifecycle_status=lifecycle_status)
    result = make_engine(definition=definition).execute(make_request())

    assert result.status is CalculationStatus.BLOCKED
    assert result.method_lifecycle_status is lifecycle_status
    assert result.findings[0].finding_id == ENGINE_LIFECYCLE_FINDING_ID
    assert result.outputs == ()
    assert _executor_call_count() == 0


def test_engine_incompatibility_returns_visible_block_without_execution(
) -> None:
    """Compatibility is checked before resolving an executable callback."""

    definition = make_definition(
        compatibility=EngineCompatibility(
            minimum_version="2.0.0",
            maximum_exclusive_version="3.0.0",
        )
    )
    result = make_engine(definition=definition).execute(make_request())

    assert result.status is CalculationStatus.BLOCKED
    assert result.findings[0].finding_id == (
        ENGINE_COMPATIBILITY_FINDING_ID
    )
    assert result.outputs == ()
    assert _executor_call_count() == 0


def test_lifecycle_and_compatibility_attempts_have_distinct_fingerprints(
) -> None:
    """Blocked dispositions remain distinct even for identical request data."""

    lifecycle_result = make_engine(
        definition=make_definition(
            lifecycle_status=MethodLifecycleStatus.DRAFT
        )
    ).execute(make_request())
    compatibility_result = make_engine(
        definition=make_definition(
            compatibility=EngineCompatibility(
                minimum_version="2.0.0",
                maximum_exclusive_version="3.0.0",
            )
        )
    ).execute(make_request())

    assert lifecycle_result.result_fingerprint != (
        compatibility_result.result_fingerprint
    )
    assert _executor_call_count() == 0


def test_unknown_input_blocks_without_executor_call() -> None:
    """Validation rejects request inputs absent from reviewed metadata."""

    request = make_request(
        inputs=(
            *make_request().inputs,
            make_quantity_input(
                "unknown-input",
                "Unknown input",
                4.0,
            ),
        )
    )
    result = make_engine().execute(request)

    assert result.status is CalculationStatus.BLOCKED
    assert any(
        finding.title == "Unknown calculation input"
        for finding in result.findings
    )
    assert result.outputs == ()
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    "option",
    [
        pytest.param(
            CalculationOption(option_id="scale", value=2),
            id="wrong-strict-type",
        ),
        pytest.param(
            CalculationOption(option_id="scale", value=11.0),
            id="outside-range",
        ),
        pytest.param(
            CalculationOption(option_id="unknown-option", value=1.0),
            id="unknown-option",
        ),
    ],
)
def test_invalid_option_blocks_without_executor_call(
    option: CalculationOption,
) -> None:
    """Strict option schema failures remain pre-execution blocks."""

    result = make_engine().execute(
        make_request(options=(option,))
    )

    assert result.status is CalculationStatus.BLOCKED
    assert result.outputs == ()
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    "missing_input_id",
    ["length", "width"],
)
def test_required_missing_input_is_insufficient_without_execution(
    missing_input_id: str,
) -> None:
    """A non-safety required input maps to insufficient_input."""

    inputs = tuple(
        value
        for value in make_request().inputs
        if value.input_id != missing_input_id
    )
    result = make_engine().execute(make_request(inputs=inputs))

    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert tuple(value.input_id for value in result.missing_inputs) == (
        missing_input_id,
    )
    assert any(
        finding.title == "Required input is missing"
        for finding in result.findings
    )
    assert _executor_call_count() == 0


def test_applicability_rejection_is_not_applicable_without_execution() -> None:
    """A reviewed blocking applicability result owns status precedence."""

    definition = make_definition(applicability=True)
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_reject,
    )
    result = engine.execute(make_request())

    assert result.status is CalculationStatus.NOT_APPLICABLE
    assert any(
        finding.finding_id.startswith("validation.finding.")
        and finding.category is FindingCategory.APPLICABILITY
        for finding in result.findings
    )
    assert _executor_call_count() == 0


def test_applicability_acceptance_reaches_executor_once() -> None:
    """An accepted reviewed rule permits normal controlled execution."""

    definition = make_definition(applicability=True)
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_accept,
    )
    result = engine.execute(make_request())

    assert result.status is CalculationStatus.COMPLETED
    assert _executor_call_count() == 1


def test_applicability_block_precedes_required_input_insufficiency() -> None:
    """Unavailable applicability input owns the disposition."""

    definition = make_definition(applicability=True)
    inputs = tuple(
        value
        for value in make_request().inputs
        if value.input_id != "length"
    )
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_accept,
    )
    result = engine.execute(make_request(inputs=inputs))

    assert result.status is CalculationStatus.NOT_APPLICABLE
    assert any(
        finding.title == "Applicability could not be evaluated"
        for finding in result.findings
    )
    assert any(
        value.input_id == "length"
        and value.required_for_execution
        for value in result.missing_inputs
    )
    assert _executor_call_count() == 0


def test_applicability_exception_is_sanitized_and_fail_closed() -> None:
    """Evaluator implementation details never leak into public results."""

    definition = make_definition(applicability=True)
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_raises_secret,
    )
    result = engine.execute(make_request())
    rendered = result.model_dump_json()

    assert result.status is CalculationStatus.NOT_APPLICABLE
    assert _executor_call_count() == 0
    assert "secret-applicability-token" not in rendered
    assert "RuntimeError" not in rendered


def test_applicability_process_control_is_not_swallowed() -> None:
    """Keyboard interruption remains outside sanitized callback failures."""

    definition = make_definition(applicability=True)
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_keyboard_interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        engine.execute(make_request())
    assert _executor_call_count() == 0


def test_declared_safety_trigger_blocks_without_executor_call() -> None:
    """A conditional declared safety trigger has highest precedence."""

    definition = make_definition(safety=True)
    result = make_engine(
        definition=definition,
        safety_evaluator=safety_trigger,
    ).execute(make_request())

    assert result.status is CalculationStatus.BLOCKED
    assert any(
        finding.finding_id == "safety.confirm-length-basis"
        for finding in result.findings
    )
    assert all(
        finding.category is FindingCategory.SAFETY
        for finding in result.findings
    )
    assert _executor_call_count() == 0


def test_missing_safety_critical_input_blocks_without_executor_call() -> None:
    """Safety-critical absence blocks rather than returning insufficiency."""

    definition = make_definition(
        safety=True,
        safety_critical_length=True,
    )
    inputs = tuple(
        value
        for value in make_request().inputs
        if value.input_id != "length"
    )
    result = make_engine(definition=definition).execute(
        make_request(inputs=inputs)
    )

    assert result.status is CalculationStatus.BLOCKED
    assert any(
        finding.category is FindingCategory.SAFETY
        and finding.blocking
        for finding in result.findings
    )
    assert any(
        missing.input_id == "length"
        and missing.safety_critical
        for missing in result.missing_inputs
    )
    assert _executor_call_count() == 0


def test_safety_block_precedes_applicability_and_missing_statuses() -> None:
    """Safety remains the highest deterministic pre-execution precedence."""

    definition = make_definition(
        applicability=True,
        safety=True,
        safety_critical_length=True,
    )
    inputs = tuple(
        value
        for value in make_request().inputs
        if value.input_id != "length"
    )
    engine = make_engine(
        definition=definition,
        applicability_evaluator=applicability_accept,
    )
    result = engine.execute(make_request(inputs=inputs))

    assert result.status is CalculationStatus.BLOCKED
    assert any(
        finding.category is FindingCategory.SAFETY
        and finding.blocking
        for finding in result.findings
    )
    assert any(
        finding.category is FindingCategory.APPLICABILITY
        and finding.blocking
        for finding in result.findings
    )
    assert _executor_call_count() == 0


def test_safety_exception_is_sanitized_and_fail_closed() -> None:
    """A safety callback failure produces fixed controlled findings."""

    definition = make_definition(safety=True)
    result = make_engine(
        definition=definition,
        safety_evaluator=safety_raises_secret,
    ).execute(make_request())
    rendered = result.model_dump_json()

    assert result.status is CalculationStatus.BLOCKED
    assert any(
        finding.finding_id == "safety.evaluation-failed"
        for finding in result.findings
    )
    assert "secret-safety-token" not in rendered
    assert "RuntimeError" not in rendered
    assert _executor_call_count() == 0


def test_safety_failure_preserves_linked_evidence_at_capacity() -> None:
    """A full method-evidence set cannot erase fail-closed provenance."""

    definition = make_max_verification_definition(safety=True)
    result = make_engine(
        definition=definition,
        safety_evaluator=safety_raises_secret,
    ).execute(make_request())

    failure = next(
        finding
        for finding in result.findings
        if finding.finding_id.startswith("safety.evaluation-failed")
    )
    result_verification_ids = {
        value.verification_id
        for value in result.verification_requirements
    }

    assert result.status is CalculationStatus.BLOCKED
    assert len(result.verification_requirements) == (
        MAX_VERIFICATION_REQUIREMENTS
    )
    assert set(failure.verification_requirement_ids).issubset(
        result_verification_ids
    )
    assert result.outputs == ()
    assert _executor_call_count() == 0


def test_executor_failure_preserves_linked_evidence_at_capacity() -> None:
    """Engine failure evidence displaces only unlinked method metadata."""

    definition = make_max_verification_definition()
    execution_result = make_engine(
        definition=definition,
        implementation=execute_raises_secret,
    ).execute(make_request())
    safety_definition = make_max_verification_definition(safety=True)
    safety_result = make_engine(
        definition=safety_definition,
        safety_evaluator=safety_raises_secret,
    ).execute(make_request())

    failure = next(
        finding
        for finding in execution_result.findings
        if finding.finding_id.startswith(ENGINE_EXECUTION_FINDING_ID)
    )
    result_verification_ids = {
        value.verification_id
        for value in execution_result.verification_requirements
    }

    assert execution_result.status is CalculationStatus.FAILED
    assert len(execution_result.verification_requirements) == (
        MAX_VERIFICATION_REQUIREMENTS
    )
    assert set(failure.verification_requirement_ids).issubset(
        result_verification_ids
    )
    assert execution_result.outputs == ()
    assert execution_result.result_fingerprint != (
        safety_result.result_fingerprint
    )
    assert _executor_call_count() == 1


def test_safety_process_control_is_not_swallowed() -> None:
    """Keyboard interruption remains outside fail-closed safety reports."""

    definition = make_definition(safety=True)
    engine = make_engine(
        definition=definition,
        safety_evaluator=safety_keyboard_interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        engine.execute(make_request())
    assert _executor_call_count() == 0


def test_optional_missing_input_executes_with_warning_status() -> None:
    """Optional absence is visible but does not prevent execution."""

    inputs = tuple(
        value
        for value in make_request().inputs
        if value.input_id != "mode"
    )
    result = make_engine().execute(make_request(inputs=inputs))

    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert tuple(value.input_id for value in result.missing_inputs) == (
        "mode",
    )
    assert result.outputs
    assert _executor_call_count() == 1


def test_outcome_warning_is_completed_with_warnings() -> None:
    """Non-blocking implementation findings remain visible and traceable."""

    result = make_engine(implementation=execute_warning).execute(
        make_request()
    )

    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert any(
        finding.finding_id == "execution.input-quality-warning"
        for finding in result.findings
    )
    assert result.outputs
    assert _executor_call_count() == 1


def test_unverified_outcome_assumption_is_completed_with_warnings() -> None:
    """Pending result-affecting assumptions prevent a clean completed state."""

    result = make_engine(
        implementation=execute_unverified_assumption
    ).execute(make_request())

    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert tuple(
        value.assumption_id
        for value in result.assumptions
    ) == ("assumption.fixture-factor",)
    assert result.assumptions[0].verification_completed is False
    assert _executor_call_count() == 1


def test_unverified_external_reference_is_completed_with_warnings() -> None:
    """Exact external evidence is merged and affects completed status."""

    request = make_request(reference_ids=("ref.external",))
    evidence = make_external_evidence()
    result = make_engine().execute(request, evidence=evidence)

    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert tuple(value.reference_id for value in result.references) == (
        "ref.source",
        "ref.vector",
        "ref.external",
    )
    assert result.references[-1].verified is False
    assert _executor_call_count() == 1


def test_verified_external_reference_preserves_clean_completion() -> None:
    """Verified exact external evidence can accompany a clean result."""

    request = make_request(reference_ids=("ref.external",))
    evidence = make_external_evidence(verified=True)
    result = make_engine().execute(request, evidence=evidence)

    assert result.status is CalculationStatus.COMPLETED
    assert result.references[-1].verified is True
    assert _executor_call_count() == 1


def test_material_resolved_evidence_changes_engine_result_fingerprint(
) -> None:
    """A changed trusted evidence record changes the actual result identity."""

    request = make_request(reference_ids=("ref.external",))
    first_evidence = TrustedExecutionEvidence(
        references=(
            make_reference(
                "ref.external",
                ReferenceType.USER_DOCUMENT,
                verified=True,
                title="External material basis A",
            ),
        )
    )
    second_evidence = TrustedExecutionEvidence(
        references=(
            make_reference(
                "ref.external",
                ReferenceType.USER_DOCUMENT,
                verified=True,
                title="External material basis B",
            ),
        )
    )
    engine = make_engine()

    first = engine.execute(request, evidence=first_evidence)
    second = engine.execute(request, evidence=second_evidence)

    assert first.status is CalculationStatus.COMPLETED
    assert second.status is CalculationStatus.COMPLETED
    assert first.references != second.references
    assert first.result_fingerprint != second.result_fingerprint
    assert _executor_call_count() == 2


@pytest.mark.parametrize(
    "implementation",
    [
        pytest.param(execute_raises_secret, id="exception"),
        pytest.param(execute_wrong_type, id="wrong-return-type"),
        pytest.param(
            execute_invalid_constructed,
            id="model-construct-bypass",
        ),
        pytest.param(execute_sequence_tamper, id="sequence-tamper"),
        pytest.param(
            execute_context_attribute_tamper,
            id="immutable-context-tamper",
        ),
    ],
)
def test_invalid_executor_outcomes_return_sanitized_failure(
    implementation,
) -> None:
    """Callback exceptions and invalid return models fail as public results."""

    result = make_engine(implementation=implementation).execute(
        make_request()
    )
    rendered = result.model_dump_json()

    assert result.status is CalculationStatus.FAILED
    assert result.outputs == ()
    assert any(
        finding.finding_id.startswith(ENGINE_EXECUTION_FINDING_ID)
        for finding in result.findings
    )
    assert "secret-executor-token" not in rendered
    assert "RuntimeError" not in rendered
    assert _executor_call_count() == 1


def test_executor_process_control_is_not_sanitized() -> None:
    """Keyboard interruption is not converted into a numerical result."""

    engine = make_engine(implementation=execute_keyboard_interrupt)
    with pytest.raises(KeyboardInterrupt):
        engine.execute(make_request())
    assert _executor_call_count() == 1


@pytest.mark.parametrize(
    "implementation",
    [
        pytest.param(
            execute_undeclared_formula,
            id="undeclared-formula",
        ),
        pytest.param(
            execute_unresolved_trace_reference,
            id="trace-reference",
        ),
        pytest.param(
            execute_unresolved_output_reference,
            id="output-reference",
        ),
        pytest.param(
            execute_unresolved_finding_reference,
            id="finding-reference",
        ),
        pytest.param(
            execute_unresolved_finding_verification,
            id="finding-verification",
        ),
        pytest.param(
            execute_output_value_tamper,
            id="output-trace-mismatch",
        ),
    ],
)
def test_undeclared_formula_evidence_and_graph_tampering_fail_closed(
    implementation,
) -> None:
    """An executor cannot invent provenance or break output trace links."""

    result = make_engine(implementation=implementation).execute(
        make_request()
    )

    assert result.status is CalculationStatus.FAILED
    assert result.outputs == ()
    assert any(
        finding.title
        in {
            "Calculation execution failed",
            "Calculation result validation failed",
        }
        for finding in result.findings
    )
    assert _executor_call_count() == 1


def test_failed_execution_fingerprint_is_stable_but_materially_sensitive(
) -> None:
    """Failure hashing is deterministic and still binds normalized inputs."""

    engine = make_engine(implementation=execute_raises_secret)
    first = engine.execute(make_request())
    second = engine.execute(
        make_request(
            request_id=SECOND_REQUEST_ID,
            requested_at=SECOND_TIME,
        )
    )
    changed = engine.execute(
        make_request(
            inputs=(
                make_quantity_input("length", "Length", 2.1),
                make_quantity_input("width", "Width", 3.0),
                make_mode_input(),
            )
        )
    )

    assert first.result_fingerprint == second.result_fingerprint
    assert changed.result_fingerprint != first.result_fingerprint
    assert _executor_call_count() == 3


def test_model_constructed_request_is_revalidated_before_lookup() -> None:
    """Bypass-constructed request state cannot reach registry resolution."""

    request = make_request()
    bypassed = CalculationRequest.model_construct(
        **{
            **request.model_dump(mode="python", round_trip=True),
            "method_id": "!",
        }
    )
    engine = make_engine()

    with pytest.raises(ValidationError):
        engine.execute(bypassed)
    assert _executor_call_count() == 0


def test_mutated_nested_request_input_is_revalidated_before_execution(
) -> None:
    """Post-construction object mutation is rejected at the engine boundary."""

    request = make_request()
    invalid_quantity = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.LENGTH.value,
        value=nan,
        unit="m",
        uncertainty=None,
        uncertainty_basis=None,
        significant_figures=None,
        decimal_places=None,
    )
    object.__setattr__(
        request.inputs[0],
        "quantity",
        invalid_quantity,
    )

    with pytest.raises(ValidationError):
        make_engine().execute(request)
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    ("evidence", "message"),
    [
        pytest.param(
            TrustedExecutionEvidence(),
            "exactly resolve request links",
            id="missing-external-reference",
        ),
        pytest.param(
            make_external_evidence("ref.extra"),
            "exactly resolve request links",
            id="wrong-external-reference",
        ),
        pytest.param(
            TrustedExecutionEvidence(
                references=(
                    make_reference(
                        "ref.external",
                        ReferenceType.USER_DOCUMENT,
                        verified=False,
                    ),
                    make_reference(
                        "ref.extra",
                        ReferenceType.USER_DOCUMENT,
                        verified=False,
                    ),
                )
            ),
            "exactly resolve request links",
            id="oversupplied-reference",
        ),
    ],
)
def test_external_reference_evidence_must_match_request_exactly(
    evidence: TrustedExecutionEvidence,
    message: str,
) -> None:
    """Server-resolved evidence cannot be omitted, substituted, or widened."""

    request = make_request(reference_ids=("ref.external",))
    with pytest.raises(CalculationEvidenceError, match=message):
        make_engine().execute(request, evidence=evidence)
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    "definition",
    [
        pytest.param(
            make_definition(
                lifecycle_status=MethodLifecycleStatus.DRAFT,
            ),
            id="lifecycle",
        ),
        pytest.param(
            make_definition(
                compatibility=EngineCompatibility(
                    minimum_version="2.0.0",
                    maximum_exclusive_version="3.0.0",
                ),
            ),
            id="compatibility",
        ),
    ],
)
def test_evidence_integrity_precedes_nonexecution_gates(
    definition: CalculationMethodDefinition,
) -> None:
    """A blocked lifecycle never permits unresolved result provenance."""

    request = make_request(reference_ids=("ref.external",))
    with pytest.raises(
        CalculationEvidenceError,
        match="exactly resolve request links",
    ):
        make_engine(definition=definition).execute(request)
    assert _executor_call_count() == 0


@pytest.mark.parametrize(
    "falsy_evidence",
    [
        False,
        0,
        "",
        (),
        {},
    ],
)
def test_falsy_non_none_evidence_is_rejected(
    falsy_evidence: Any,
) -> None:
    """Only None receives the empty trusted-evidence default."""

    with pytest.raises(
        CalculationEvidenceError,
        match="evidence failed validation",
    ):
        make_engine().execute(
            make_request(),
            evidence=falsy_evidence,  # type: ignore[arg-type]
        )
    assert _executor_call_count() == 0


def test_external_assumption_verification_must_match_exactly() -> None:
    """Request assumptions require exact server-resolved verification data."""

    assumption = CalculationAssumption(
        assumption_id="assumption.external",
        statement="External assumption requiring independent verification.",
        origin=InputOrigin.USER_SUPPLIED,
        requires_verification=True,
        verification_completed=False,
        verification_requirement_ids=("verify.external",),
    )
    request = make_request(assumptions=(assumption,))

    with pytest.raises(
        CalculationEvidenceError,
        match="exactly resolve request assumptions",
    ):
        make_engine().execute(request)

    evidence = TrustedExecutionEvidence(
        verification_requirements=(
            make_verification("verify.external"),
        )
    )
    result = make_engine().execute(request, evidence=evidence)
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert any(
        value.verification_id == "verify.external"
        for value in result.verification_requirements
    )


def test_method_owned_evidence_must_not_be_resupplied() -> None:
    """Trusted evidence accepts external records, not method duplicates."""

    evidence = TrustedExecutionEvidence(
        references=(
            make_reference(
                "ref.source",
                ReferenceType.ENGINEERING_TEXTBOOK,
            ),
        ),
        verification_requirements=(make_verification(),),
    )
    with pytest.raises(CalculationEvidenceError):
        make_engine().execute(make_request(), evidence=evidence)
    assert _executor_call_count() == 0


def test_iterative_method_converges_with_controller_owned_outcome() -> None:
    """A matching finite convergence record returns a completed result."""

    definition = make_definition(
        iteration_limits=make_iteration_limits()
    )
    result = make_engine(
        definition=definition,
        implementation=execute_iterative_converged,
    ).execute(make_request())

    assert result.status is CalculationStatus.COMPLETED
    assert len(
        tuple(
            step
            for step in result.trace_steps
            if step.kind is TraceStepKind.ITERATION
        )
    ) == 2
    assert result.outputs
    assert _executor_call_count() == 1


@pytest.mark.parametrize(
    ("implementation", "reason"),
    [
        pytest.param(
            execute_iterative_maximum,
            IterationTerminationReason.MAXIMUM_ITERATIONS,
            id="maximum-iterations",
        ),
        pytest.param(
            execute_iterative_diverged,
            IterationTerminationReason.DIVERGED,
            id="divergence-limit",
        ),
    ],
)
def test_nonconverged_iterative_method_returns_controlled_failure(
    implementation,
    reason: IterationTerminationReason,
) -> None:
    """Reviewed hard stops return a nonconvergence finding and no output."""

    definition = make_definition(
        iteration_limits=make_iteration_limits()
    )
    result = make_engine(
        definition=definition,
        implementation=implementation,
    ).execute(make_request())

    assert result.status is CalculationStatus.FAILED
    assert result.outputs == ()
    assert any(
        finding.finding_id.startswith(
            ENGINE_NONCONVERGENCE_FINDING_ID
        )
        for finding in result.findings
    )
    assert any(
        step.kind is TraceStepKind.ITERATION
        for step in result.trace_steps
    )
    assert reason.value in {
        "maximum_iterations",
        "diverged",
    }
    assert _executor_call_count() == 1


def test_nonfinite_iterative_callback_returns_sanitized_failure() -> None:
    """A controller rejection cannot leak float or exception internals."""

    definition = make_definition(
        iteration_limits=make_iteration_limits()
    )
    result = make_engine(
        definition=definition,
        implementation=execute_iterative_nonfinite,
    ).execute(make_request())
    rendered = result.model_dump_json()

    assert result.status is CalculationStatus.FAILED
    assert ENGINE_EXECUTION_FINDING_ID in rendered
    assert "nan" not in rendered.lower()
    assert "NonFiniteIterationError" not in rendered
    assert _executor_call_count() == 1


@pytest.mark.parametrize(
    "implementation",
    [
        pytest.param(
            execute_iterative_unused_controller,
            id="unused-controller",
        ),
        pytest.param(
            execute_iterative_forged_outcome,
            id="forged-controller-outcome",
        ),
        pytest.param(
            execute_iterative_attribute_tamper,
            id="controller-attribute-tamper",
        ),
    ],
)
def test_iterative_state_tampering_returns_controlled_failure(
    implementation,
) -> None:
    """Implementations cannot replace or omit controller-owned state."""

    definition = make_definition(
        iteration_limits=make_iteration_limits()
    )
    result = make_engine(
        definition=definition,
        implementation=implementation,
    ).execute(make_request())

    assert result.status is CalculationStatus.FAILED
    assert result.outputs == ()
    assert any(
        finding.finding_id.startswith(ENGINE_EXECUTION_FINDING_ID)
        for finding in result.findings
    )
    assert _executor_call_count() == 1


def test_concurrent_execution_is_isolated_and_deterministic() -> None:
    """One immutable engine safely serves concurrent independent attempts."""

    engine = make_engine(deterministic_identity=False)
    requests = tuple(
        make_request(request_id=uuid4())
        for _ in range(32)
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(engine.execute, requests))

    assert all(
        result.status is CalculationStatus.COMPLETED
        for result in results
    )
    assert len(
        {
            result.calculation_id
            for result in results
        }
    ) == len(results)
    assert len(
        {
            result.result_fingerprint
            for result in results
        }
    ) == 1
    assert _executor_call_count() == len(results)


def test_repeated_execution_has_no_shared_iteration_state() -> None:
    """Each iterative attempt receives a fresh controller and full budget."""

    definition = make_definition(
        iteration_limits=make_iteration_limits()
    )
    engine = make_engine(
        definition=definition,
        implementation=execute_iterative_converged,
    )

    first = engine.execute(make_request())
    second = engine.execute(
        make_request(request_id=SECOND_REQUEST_ID)
    )

    for result in (first, second):
        iteration_numbers = tuple(
            step.iteration_number
            for step in result.trace_steps
            if step.kind is TraceStepKind.ITERATION
        )
        assert iteration_numbers == (1, 2)
    assert first.result_fingerprint == second.result_fingerprint
    assert _executor_call_count() == 2


def test_engine_dependencies_and_version_are_immutable() -> None:
    """Registry and execution dependencies cannot be replaced after binding."""

    engine = make_engine()
    assert engine.engine_version == ENGINE_VERSION
    assert len(engine.registry.definitions) == 1
    with pytest.raises(AttributeError):
        engine._engine_version = "9.9.9"  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        del engine._registry  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("keyword", "value", "error_type"),
    [
        pytest.param("registry", object(), TypeError, id="registry"),
        pytest.param(
            "validation_engine",
            object(),
            TypeError,
            id="validation-engine",
        ),
        pytest.param(
            "safety_engine",
            object(),
            TypeError,
            id="safety-engine",
        ),
        pytest.param(
            "engine_version",
            "1.0",
            ValueError,
            id="engine-version",
        ),
        pytest.param("clock", 1, TypeError, id="clock"),
        pytest.param("id_factory", 1, TypeError, id="id-factory"),
    ],
)
def test_engine_constructor_rejects_invalid_dependencies(
    keyword: str,
    value: Any,
    error_type: type[Exception],
) -> None:
    """Application-owned dependency injection remains strict."""

    values: dict[str, Any] = {
        "registry": CalculationMethodRegistry(()),
    }
    values[keyword] = value
    with pytest.raises(error_type):
        CalculationEngine(**values)


@pytest.mark.parametrize(
    ("dependency_name", "dependency", "error_type", "message"),
    [
        pytest.param(
            "id_factory",
            invalid_id_factory,
            CalculationExecutionContractError,
            "id_factory must return UUID",
            id="invalid-id",
        ),
        pytest.param(
            "id_factory",
            raising_id_factory,
            RuntimeError,
            "trusted id factory is unavailable",
            id="raising-id",
        ),
        pytest.param(
            "clock",
            naive_clock,
            CalculationExecutionContractError,
            "clock must return an aware datetime",
            id="naive-clock",
        ),
        pytest.param(
            "clock",
            invalid_clock,
            CalculationExecutionContractError,
            "clock must return an aware datetime",
            id="invalid-clock",
        ),
        pytest.param(
            "clock",
            raising_clock,
            RuntimeError,
            "trusted clock is unavailable",
            id="raising-clock",
        ),
    ],
)
def test_trusted_identity_and_clock_failures_propagate(
    dependency_name: str,
    dependency: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    """Broken engine infrastructure is not mislabeled as method failure."""

    registered_engine = make_engine()
    values: dict[str, Any] = {
        "registry": registered_engine.registry,
        "clock": fixed_clock,
        "id_factory": fixed_id_factory,
    }
    values[dependency_name] = dependency
    engine = CalculationEngine(**values)

    with pytest.raises(error_type, match=message):
        engine.execute(make_request())
    assert _executor_call_count() == 1


def test_one_shot_invalid_identity_is_not_retried_as_method_failure() -> None:
    """A transiently invalid trusted ID cannot be hidden by fallback retry."""

    values = iter(("not-a-uuid", FIXED_CALCULATION_ID))
    registered_engine = make_engine()
    engine = CalculationEngine(
        registry=registered_engine.registry,
        clock=fixed_clock,
        id_factory=values.__next__,  # type: ignore[arg-type]
    )

    with pytest.raises(
        CalculationExecutionContractError,
        match="id_factory must return UUID",
    ):
        engine.execute(make_request())

    assert next(values) == FIXED_CALCULATION_ID
    assert _executor_call_count() == 1


def test_one_shot_invalid_clock_is_not_retried_as_method_failure() -> None:
    """A transiently invalid trusted time cannot become a generic failure."""

    values = iter(("not-a-datetime", FIXED_TIME))
    registered_engine = make_engine()
    engine = CalculationEngine(
        registry=registered_engine.registry,
        clock=values.__next__,  # type: ignore[arg-type]
        id_factory=fixed_id_factory,
    )

    with pytest.raises(
        CalculationExecutionContractError,
        match="clock must return an aware datetime",
    ):
        engine.execute(make_request())

    assert next(values) == FIXED_TIME
    assert _executor_call_count() == 1


def test_default_engine_uses_empty_production_registry() -> None:
    """No production calculation method is enabled merely by importing."""

    assert DEFAULT_CALCULATION_ENGINE.registry.definitions == ()
    assert DEFAULT_CALCULATION_ENGINE.registry.method_ids == ()
    with pytest.raises(UnknownMethodError):
        DEFAULT_CALCULATION_ENGINE.execute(make_request())


def test_empty_engine_is_not_a_request_controlled_kill_switch() -> None:
    """A constructed reviewed registry executes despite package flag state."""

    result = make_engine().execute(make_request())
    assert result.status is CalculationStatus.COMPLETED
    assert _executor_call_count() == 1


def test_engine_source_has_no_dynamic_execution_or_voice_surface() -> None:
    """The engine contains no expression, import, shell, or voice path."""

    import app.engineering.calculations.engine as engine_module

    source = inspect.getsource(engine_module)
    tree = ast.parse(source)
    prohibited_calls = {"compile", "eval", "exec"}
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in prohibited_calls
        for node in ast.walk(tree)
    )
    prohibited_modules = {"importlib", "subprocess"}
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(
                alias.name.split(".", maxsplit=1)[0]
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module.split(".", maxsplit=1)[0])
    assert imported_modules.isdisjoint(prohibited_modules)
    assert "voice" not in source.casefold()


def test_public_engine_exports_resolve() -> None:
    """Every declared engine export is present and directly accessible."""

    import app.engineering.calculations.engine as engine_module

    assert engine_module.__all__
    assert len(engine_module.__all__) == len(set(engine_module.__all__))
    for name in engine_module.__all__:
        assert getattr(engine_module, name) is not None


def test_phase7_package_boundary_exports_engine_and_level_contract() -> None:
    """The package preserves the engine surface and exports Step 95."""

    import app.engineering.calculations as calculations

    expected_exports = {
        "ApplicabilityRule",
        "CalculationEngine",
        "CalculationMethodDefinition",
        "CalculationMethodRegistry",
        "CalculationSafetyEngine",
        "CalculationValidationEngine",
        "DEFAULT_CALCULATION_ENGINE",
        "DEFAULT_METHOD_REGISTRY",
        "DEFAULT_SAFETY_ENGINE",
        "DEFAULT_VALIDATION_ENGINE",
        "ENGINEERING_CALCULATION_ENGINE",
        "ENGINEERING_METHOD_IDS",
        "ENGINEERING_METHOD_REGISTRATIONS",
        "ENGINEERING_METHOD_REGISTRY",
        "EngineCompatibility",
        "IterationController",
        "IterationLimits",
        "LEVEL_CALCULATION_ENGINE",
        "LEVEL_CALCULATORS_VERSION",
        "LEVEL_METHOD_IDS",
        "LEVEL_METHOD_REGISTRATIONS",
        "LEVEL_METHOD_REGISTRY",
        "LEVEL_METHOD_VERSION",
        "LevelRangeResult",
        "LevelTransmitterRangeResult",
        "MethodExecutionContext",
        "MethodExecutionOutcome",
        "MethodInputSpecification",
        "MethodOptionSpecification",
        "MethodRegistration",
        "SafetyEvaluationContext",
        "SafetyRequirement",
        "TankVolumeResult",
        "TrustedExecutionEvidence",
        "build_attempt_fingerprint_payload",
        "build_fingerprint_payload",
        "canonical_fingerprint_bytes",
        "fingerprint_payload",
    }
    assert calculations.FOUNDATION_VERSION == "0.6.0"
    assert calculations.EXECUTABLE_METHODS_ENABLED is True
    assert expected_exports.issubset(set(calculations.__all__))
    assert len(calculations.__all__) == len(set(calculations.__all__))
    for name in calculations.__all__:
        assert getattr(calculations, name) is not None
    assert all(
        "voice" not in name.casefold()
        for name in calculations.__all__
    )


def test_package_enabled_flag_reflects_separate_general_registry(
) -> None:
    """Enablement does not mutate the intentionally empty base registry."""

    import app.engineering.calculations as calculations

    assert calculations.EXECUTABLE_METHODS_ENABLED is True
    assert calculations.DEFAULT_METHOD_REGISTRY.definitions == ()
    assert len(calculations.GENERAL_METHOD_REGISTRY.definitions) == 17
    assert len(calculations.LEVEL_METHOD_REGISTRY.definitions) == 9
    assert len(calculations.ENGINEERING_METHOD_REGISTRY.definitions) == 26
    assert make_engine().execute(make_request()).status is (
        CalculationStatus.COMPLETED
    )
