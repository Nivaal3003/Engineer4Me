"""Phase 7 Step 92 tests for fail-closed calculation safety evaluation."""

from __future__ import annotations

import ast
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

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
from app.engineering.calculations.method_models import MethodInputSpecification
from app.engineering.calculations.method_models import (
    MethodOptionSpecification,
)
from app.engineering.calculations.method_models import MethodOptionValueType
from app.engineering.calculations.method_models import MethodReviewRecord
from app.engineering.calculations.method_models import MethodReviewType
from app.engineering.calculations.method_models import SafetyRequirement
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.safety import CalculationSafetyEngine
from app.engineering.calculations.safety import MethodSafetyExtension
from app.engineering.calculations.safety import (
    SAFETY_EVALUATION_FAILED_FINDING_ID,
)
from app.engineering.calculations.safety import (
    SAFETY_EVALUATION_FAILED_VERIFICATION_ID,
)
from app.engineering.calculations.safety import SafetyEvaluationContext
from app.engineering.calculations.safety import SafetyEvaluationError
from app.engineering.calculations.safety import SafetyReport
from app.engineering.calculations.safety import SafetyTrigger
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.validation import (
    CalculationValidationEngine,
)


FIXED_TIME = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
SAFETY_PATH = (
    Path(__file__).parents[1]
    / "app"
    / "engineering"
    / "calculations"
    / "safety.py"
)


def make_verification(
    verification_id: str = "verify.pressure",
    **changes: Any,
) -> VerificationRequirement:
    """Return one deterministic verification requirement."""

    values: dict[str, Any] = {
        "verification_id": verification_id,
        "description": "Verify the pressure input independently.",
        "method": "Compare against the approved process datasheet.",
        "expected_result": "The values agree within approved tolerance.",
        "required_competency": "Competent instrumentation engineer",
    }
    values.update(changes)
    return VerificationRequirement(**values)


def make_reference(
    reference_id: str = "vector.pressure",
    **changes: Any,
) -> CalculationReference:
    """Return one verified test-vector reference."""

    values: dict[str, Any] = {
        "reference_id": reference_id,
        "reference_type": ReferenceType.TEST_VECTOR,
        "title": "Independently checked pressure identity vector",
        "verified": True,
        "verified_by": "Independent technical reviewer",
        "verified_at": FIXED_TIME,
    }
    values.update(changes)
    return CalculationReference(**values)


def make_input(**changes: Any) -> CalculationInput:
    """Return one valid absolute-pressure input."""

    values: dict[str, Any] = {
        "input_id": "pressure-in",
        "name": "Absolute pressure",
        "origin": InputOrigin.USER_SUPPLIED,
        "quantity": EngineeringQuantity(
            quantity_kind=QuantityKind.ABSOLUTE_PRESSURE.value,
            value=100_000.0,
            unit="Pa",
        ),
    }
    values.update(changes)
    return CalculationInput(**values)


def make_input_specification(
    *,
    safety_critical: bool = True,
) -> MethodInputSpecification:
    """Return the reviewed pressure input schema."""

    return MethodInputSpecification(
        input_id="pressure-in",
        name="Absolute pressure",
        description="Absolute process pressure used by the fixture method.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
        quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
        canonical_unit="Pa",
        safety_critical=safety_critical,
        reference_ids=("vector.pressure",),
        verification_requirement_ids=(
            ("verify.pressure",)
            if safety_critical
            else ()
        ),
    )


def make_safety_requirement(
    requirement_id: str = "pressure-confirmed",
    **changes: Any,
) -> SafetyRequirement:
    """Return one blocking declared safety requirement."""

    values: dict[str, Any] = {
        "requirement_id": requirement_id,
        "title": "Confirm the pressure basis",
        "hazard": (
            "An incorrect pressure basis can invalidate the engineering "
            "result."
        ),
        "required_input_ids": ("pressure-in",),
        "severity": FindingSeverity.CRITICAL,
        "blocking": True,
        "required_action": (
            "Confirm the absolute pressure from approved process data."
        ),
        "verification_requirement_ids": ("verify.pressure",),
        "reference_ids": ("vector.pressure",),
        "required_competency": "Competent instrumentation engineer",
    }
    values.update(changes)
    return SafetyRequirement(**values)


def make_reviews() -> tuple[MethodReviewRecord, ...]:
    """Return an approved record for every required review type."""

    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=True,
            reviewer=f"{review_type.value} reviewer",
            reviewer_competency="Independent competent reviewer",
            reviewed_at=FIXED_TIME,
            evidence_reference_ids=("vector.pressure",),
        )
        for review_type in MethodReviewType
    )


def make_definition(
    *,
    safety_requirements: tuple[SafetyRequirement, ...] | None = None,
    option_specifications: tuple[
        MethodOptionSpecification,
        ...,
    ] = (),
    safety_critical: bool = True,
) -> CalculationMethodDefinition:
    """Return one fully approved deterministic method definition."""

    if safety_requirements is None:
        safety_requirements = (make_safety_requirement(),)

    return CalculationMethodDefinition(
        method_id="fixture.pressure-identity",
        method_version="1.0.0",
        calculation_type="fixture.pressure",
        title="Pressure identity fixture",
        description="Reviewed fixture used to verify Step 92 boundaries.",
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=MethodLifecycleStatus.APPROVED,
        engine_compatibility=EngineCompatibility(
            minimum_version="1.0.0",
            maximum_exclusive_version="2.0.0",
        ),
        input_specifications=(
            make_input_specification(
                safety_critical=safety_critical,
            ),
        ),
        option_specifications=option_specifications,
        safety_requirements=safety_requirements,
        formulas=(
            FormulaMetadata(
                formula_identifier="formula.pressure-identity",
                title="Pressure identity",
                description="Return normalized pressure unchanged.",
                reference_ids=("vector.pressure",),
            ),
        ),
        references=(make_reference(),),
        verification_requirements=(make_verification(),),
        reviews=make_reviews(),
        test_vector_reference_ids=("vector.pressure",),
        limitations=("Fixture method; not for plant design.",),
        exclusions=("No product recommendation.",),
        required_reviewer_competency=(
            "Competent instrumentation engineer"
        ),
        disclaimer=(
            "Engineering decision support requires independent review."
        ),
    )


def make_request(
    *,
    inputs: tuple[CalculationInput, ...] | None = None,
    assumptions: tuple[CalculationAssumption, ...] = (),
    options: tuple[CalculationOption, ...] = (),
    reference_ids: tuple[str, ...] = (),
) -> CalculationRequest:
    """Return a request matching the fixture method."""

    if inputs is None:
        inputs = (make_input(),)

    return CalculationRequest(
        calculation_type="fixture.pressure",
        method_id="fixture.pressure-identity",
        method_version="1.0.0",
        requested_at=FIXED_TIME,
        inputs=inputs,
        assumptions=assumptions,
        options=options,
        reference_ids=reference_ids,
    )


def make_context(
    *,
    definition: CalculationMethodDefinition | None = None,
    request: CalculationRequest | None = None,
    missing_inputs: tuple[MissingCalculationInput, ...] = (),
    evidence: TrustedExecutionEvidence | None = None,
) -> SafetyEvaluationContext:
    """Return a valid safety context for supplied or missing input."""

    if definition is None:
        definition = make_definition()

    if request is None:
        request = make_request(
            inputs=()
            if missing_inputs
            else None
        )

    supplied_inputs = request.inputs
    normalized_inputs = (
        ()
        if missing_inputs
        else request.inputs
    )

    return SafetyEvaluationContext(
        request=request,
        definition=definition,
        supplied_inputs=supplied_inputs,
        normalized_inputs=normalized_inputs,
        missing_inputs=missing_inputs,
        evidence=evidence or TrustedExecutionEvidence(),
    )


def trigger_pressure(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Trigger the declared pressure safety requirement."""

    del context
    return MethodSafetyExtension(
        triggers=(
            SafetyTrigger(
                requirement_id="pressure-confirmed",
            ),
        )
    )


def trigger_pressure_with_message(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Trigger the requirement with a bounded observed-condition message."""

    del context
    return MethodSafetyExtension(
        triggers=(
            SafetyTrigger(
                requirement_id="pressure-confirmed",
                message="The pressure source has not been independently checked.",
            ),
        )
    )


def trigger_unknown(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Return an undeclared requirement to exercise fail-closed handling."""

    del context
    return MethodSafetyExtension(
        triggers=(SafetyTrigger(requirement_id="unknown-safety-rule"),)
    )


def trigger_in_reverse_order(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Return two valid triggers in reverse definition order."""

    del context
    return MethodSafetyExtension(
        triggers=(
            SafetyTrigger(requirement_id="second-requirement"),
            SafetyTrigger(requirement_id="pressure-confirmed"),
        )
    )


def evaluator_raises_secret(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Raise an internal message that must never leak into a report."""

    del context
    raise RuntimeError("secret-token=never-expose-this")


def evaluator_raises_keyboard_interrupt(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Raise process-control flow that must not be swallowed."""

    del context
    raise KeyboardInterrupt


def evaluator_returns_constructed_invalid(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Return bypass-constructed invalid nested data."""

    del context
    invalid_trigger = SafetyTrigger.model_construct(
        requirement_id=1,
        message=None,
    )
    return MethodSafetyExtension.model_construct(
        triggers=(invalid_trigger,),
    )


def evaluator_returns_duplicate(
    context: SafetyEvaluationContext,
) -> MethodSafetyExtension:
    """Return case-colliding triggers through model construction."""

    del context
    return MethodSafetyExtension.model_construct(
        triggers=(
            SafetyTrigger(requirement_id="pressure-confirmed"),
            SafetyTrigger(requirement_id="PRESSURE-CONFIRMED"),
        )
    )


def test_no_trigger_returns_empty_nonblocking_report() -> None:
    """A safe context without conditional triggers remains executable."""

    report = CalculationSafetyEngine().evaluate(make_context())

    assert report == SafetyReport()
    assert report.blocked is False


@pytest.mark.parametrize(
    "evaluator",
    [
        pytest.param(trigger_pressure, id="default-message"),
        pytest.param(
            trigger_pressure_with_message,
            id="observed-message",
        ),
    ],
)
def test_declared_trigger_preserves_controlled_metadata(evaluator) -> None:
    """Hooks can report a condition but cannot weaken its controls."""

    report = CalculationSafetyEngine().evaluate(
        make_context(),
        evaluator,
    )

    assert report.blocked is True
    assert report.evaluator_failed is False
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.finding_id == "safety.pressure-confirmed"
    assert finding.category is FindingCategory.SAFETY
    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.blocking is True
    assert finding.required_action == (
        "Confirm the absolute pressure from approved process data."
    )
    assert finding.verification_requirement_ids == (
        "verify.pressure",
    )
    assert report.verification_requirements == (
        make_verification(),
    )


def test_trigger_message_is_bounded_observation_only() -> None:
    """A hook message may add context without changing metadata."""

    report = CalculationSafetyEngine().evaluate(
        make_context(),
        trigger_pressure_with_message,
    )

    assert report.findings[0].message == (
        "The pressure source has not been independently checked."
    )
    assert report.findings[0].title == "Confirm the pressure basis"


def test_missing_requirement_input_triggers_without_callback() -> None:
    """A declared required safety input fails closed automatically."""

    missing = MissingCalculationInput(
        input_id="pressure-in",
        name="Absolute pressure",
        reason="Absolute pressure was not supplied.",
        required_for_execution=True,
        safety_critical=True,
        expected_unit="Pa",
    )
    report = CalculationSafetyEngine().evaluate(
        make_context(missing_inputs=(missing,))
    )

    assert report.blocked is True
    assert tuple(value.finding_id for value in report.findings) == (
        "safety.pressure-confirmed",
    )
    assert "missing" in report.findings[0].message.casefold()


def test_uncovered_safety_critical_input_gets_synthetic_block() -> None:
    """Safety-critical metadata blocks even without a named safety rule."""

    definition = make_definition(safety_requirements=())
    missing = MissingCalculationInput(
        input_id="pressure-in",
        name="Absolute pressure",
        reason="The pressure is unknown.",
        required_for_execution=True,
        safety_critical=True,
        expected_unit="Pa",
    )
    report = CalculationSafetyEngine().evaluate(
        make_context(
            definition=definition,
            request=make_request(inputs=()),
            missing_inputs=(missing,),
        )
    )

    assert report.blocked is True
    assert report.findings[0].finding_id == (
        "safety.missing.pressure-in"
    )
    assert report.findings[0].severity is FindingSeverity.CRITICAL


def test_non_safety_missing_input_does_not_create_safety_finding() -> None:
    """Ordinary completeness remains the validation engine's concern."""

    definition = make_definition(
        safety_requirements=(),
        safety_critical=False,
    )
    missing = MissingCalculationInput(
        input_id="pressure-in",
        name="Absolute pressure",
        reason="The pressure is unknown.",
        required_for_execution=True,
        safety_critical=False,
        expected_unit="Pa",
    )
    report = CalculationSafetyEngine().evaluate(
        make_context(
            definition=definition,
            request=make_request(inputs=()),
            missing_inputs=(missing,),
        )
    )

    assert report.findings == ()
    assert report.blocked is False


def test_unreported_absent_safety_input_still_fails_closed() -> None:
    """Normalized coverage, not caller bookkeeping, establishes absence."""

    definition = make_definition(safety_requirements=())
    request = make_request(inputs=())
    context = SafetyEvaluationContext(
        request=request,
        definition=definition,
        supplied_inputs=(),
        normalized_inputs=(),
        missing_inputs=(),
    )

    report = CalculationSafetyEngine().evaluate(context)

    assert report.blocked is True
    assert report.evaluator_failed is False
    assert tuple(value.finding_id for value in report.findings) == (
        "safety.missing.pressure-in",
    )


def test_nonblocking_rule_cannot_cover_missing_safety_input() -> None:
    """A nonblocking declaration cannot suppress the synthetic hard block."""

    requirement = make_safety_requirement(
        severity=FindingSeverity.WARNING,
        blocking=False,
        required_action=None,
        verification_requirement_ids=(),
    )
    definition = make_definition(
        safety_requirements=(requirement,),
    )
    missing = MissingCalculationInput(
        input_id="pressure-in",
        name="Absolute pressure",
        reason="The pressure is unknown.",
        required_for_execution=True,
        safety_critical=True,
        expected_unit="Pa",
    )
    request = make_request(inputs=())
    report = CalculationSafetyEngine().evaluate(
        make_context(
            definition=definition,
            request=request,
            missing_inputs=(missing,),
        )
    )

    assert report.blocked is True
    assert tuple(value.blocking for value in report.findings) == (
        False,
        True,
    )
    assert tuple(value.finding_id for value in report.findings) == (
        "safety.pressure-confirmed",
        "safety.missing.pressure-in",
    )


def test_unverified_safety_assumption_gets_blocking_finding() -> None:
    """Pending safety-critical assumptions satisfy result-state invariants."""

    assumption = CalculationAssumption(
        assumption_id="assumption.pressure-source",
        statement="The pressure source is accurate.",
        origin=InputOrigin.USER_SUPPLIED,
        safety_critical=True,
        requires_verification=True,
        verification_completed=False,
        verification_requirement_ids=("verify.pressure",),
    )
    request = make_request(assumptions=(assumption,))
    context = SafetyEvaluationContext(
        request=request,
        definition=make_definition(),
        supplied_inputs=request.inputs,
        normalized_inputs=request.inputs,
        assumptions=request.assumptions,
    )

    report = CalculationSafetyEngine().evaluate(context)

    assert report.blocked is True
    assert report.findings[0].finding_id == (
        "safety.assumption.assumption.pressure-source"
    )
    assert report.findings[0].verification_requirement_ids == (
        "verify.pressure",
    )
    result = CalculationResult(
        request_id=request.request_id,
        calculation_type=request.calculation_type,
        method_id=request.method_id,
        method_version=request.method_version,
        method_lifecycle_status=MethodLifecycleStatus.APPROVED,
        engine_version="1.0.0",
        executed_at=FIXED_TIME,
        status=CalculationStatus.BLOCKED,
        result_fingerprint="a" * 64,
        supplied_inputs=context.supplied_inputs,
        normalized_inputs=context.normalized_inputs,
        assumptions=context.assumptions,
        findings=report.findings,
        references=context.definition.references,
        verification_requirements=report.verification_requirements,
        required_reviewer_competency=(
            context.definition.required_reviewer_competency
        ),
    )
    assert result.status is CalculationStatus.BLOCKED


@pytest.mark.parametrize(
    "evaluator",
    [
        pytest.param(trigger_unknown, id="unknown-trigger"),
        pytest.param(
            evaluator_returns_constructed_invalid,
            id="constructed-invalid",
        ),
        pytest.param(
            evaluator_returns_duplicate,
            id="duplicate-trigger",
        ),
        pytest.param(evaluator_raises_secret, id="exception"),
    ],
)
def test_invalid_or_failed_evaluator_fails_closed(evaluator) -> None:
    """Every ordinary evaluator failure produces one sanitized block."""

    report = CalculationSafetyEngine().evaluate(
        make_context(),
        evaluator,
    )

    assert report.evaluator_failed is True
    assert report.blocked is True
    assert tuple(value.finding_id for value in report.findings) == (
        SAFETY_EVALUATION_FAILED_FINDING_ID,
    )
    assert tuple(
        value.verification_id
        for value in report.verification_requirements
    ) == (SAFETY_EVALUATION_FAILED_VERIFICATION_ID,)
    serialized = report.model_dump_json()
    assert "secret-token" not in serialized
    assert "RuntimeError" not in serialized


def test_process_control_exception_is_not_swallowed() -> None:
    """The engine catches Exception, not process-control BaseException."""

    with pytest.raises(KeyboardInterrupt):
        CalculationSafetyEngine().evaluate(
            make_context(),
            evaluator_raises_keyboard_interrupt,
        )


def test_conflicting_trusted_verification_fails_closed() -> None:
    """Conflicting server evidence cannot replace method-owned evidence."""

    conflicting = make_verification(
        description="Conflicting verification instructions.",
    )
    context = make_context(
        evidence=TrustedExecutionEvidence(
            verification_requirements=(conflicting,),
        )
    )
    report = CalculationSafetyEngine().evaluate(
        context,
        trigger_pressure,
    )

    assert report.evaluator_failed is True
    assert report.blocked is True
    assert report.findings[0].finding_id == (
        SAFETY_EVALUATION_FAILED_FINDING_ID
    )


def test_identical_trusted_verification_is_deduplicated() -> None:
    """Identical trusted evidence does not create duplicate records."""

    context = make_context(
        evidence=TrustedExecutionEvidence(
            verification_requirements=(make_verification(),),
        )
    )
    report = CalculationSafetyEngine().evaluate(
        context,
        trigger_pressure,
    )

    assert report.verification_requirements == (
        make_verification(),
    )


def test_conflicting_trusted_reference_fails_closed() -> None:
    """Ambiguous reference payloads cannot reach a safety callback."""

    conflicting = make_reference(
        title="Conflicting pressure vector title",
    )
    context = make_context(
        evidence=TrustedExecutionEvidence(
            references=(conflicting,),
        )
    )
    callback_called = False

    def callback(
        safety_context: SafetyEvaluationContext,
    ) -> MethodSafetyExtension:
        nonlocal callback_called
        del safety_context
        callback_called = True
        return MethodSafetyExtension()

    report = CalculationSafetyEngine().evaluate(
        context,
        callback,
    )

    assert callback_called is False
    assert report.evaluator_failed is True
    assert report.blocked is True


def test_nonblocking_declared_safety_warning_does_not_block() -> None:
    """Reviewed nonblocking caution remains visible without blocking."""

    requirement = make_safety_requirement(
        severity=FindingSeverity.WARNING,
        blocking=False,
        required_action=None,
        verification_requirement_ids=(),
    )
    definition = make_definition(
        safety_requirements=(requirement,),
        safety_critical=False,
    )
    report = CalculationSafetyEngine().evaluate(
        make_context(definition=definition),
        trigger_pressure,
    )

    assert report.blocked is False
    assert report.findings[0].severity is FindingSeverity.WARNING
    assert report.verification_requirements == ()


def test_finding_order_follows_definition_not_callback_order() -> None:
    """Safety ordering is stable and independent of callback tuple order."""

    second = make_safety_requirement(
        requirement_id="second-requirement",
        title="Second controlled requirement",
    )
    definition = make_definition(
        safety_requirements=(
            make_safety_requirement(),
            second,
        )
    )
    report = CalculationSafetyEngine().evaluate(
        make_context(definition=definition),
        trigger_in_reverse_order,
    )

    assert tuple(value.finding_id for value in report.findings) == (
        "safety.pressure-confirmed",
        "safety.second-requirement",
    )


def test_maximum_requirement_id_produces_bounded_finding_id() -> None:
    """Valid source IDs cannot break generated finding validation."""

    requirement_id = "r" * 100
    definition = make_definition(
        safety_requirements=(
            make_safety_requirement(
                requirement_id=requirement_id,
            ),
        )
    )

    def trigger_long_requirement(
        context: SafetyEvaluationContext,
    ) -> MethodSafetyExtension:
        del context
        return MethodSafetyExtension(
            triggers=(
                SafetyTrigger(requirement_id=requirement_id),
            )
        )

    report = CalculationSafetyEngine().evaluate(
        make_context(definition=definition),
        trigger_long_requirement,
    )

    assert report.evaluator_failed is False
    assert report.blocked is True
    assert len(report.findings[0].finding_id) == 100


def test_reserved_requirement_id_and_callback_failure_do_not_collide() -> None:
    """Declared metadata cannot collide with internal failure evidence."""

    requirement = make_safety_requirement(
        requirement_id="evaluation-failed",
    )
    definition = make_definition(
        safety_requirements=(requirement,),
    )
    missing = MissingCalculationInput(
        input_id="pressure-in",
        name="Absolute pressure",
        reason="The pressure is unknown.",
        required_for_execution=True,
        safety_critical=True,
        expected_unit="Pa",
    )
    context = make_context(
        definition=definition,
        request=make_request(inputs=()),
        missing_inputs=(missing,),
    )

    report = CalculationSafetyEngine().evaluate(
        context,
        evaluator_raises_secret,
    )

    finding_ids = tuple(
        value.finding_id
        for value in report.findings
    )
    assert report.evaluator_failed is True
    assert report.blocked is True
    assert len(finding_ids) == len(set(finding_ids)) == 2
    assert SAFETY_EVALUATION_FAILED_FINDING_ID in finding_ids


def test_existing_finding_collision_is_derived_and_result_compatible() -> None:
    """Safety output merges into CalculationResult without ID conflicts."""

    existing = CalculationFinding(
        finding_id="safety.pressure-confirmed",
        category=FindingCategory.DATA_QUALITY,
        severity=FindingSeverity.WARNING,
        title="Earlier data-quality warning",
        message="The validation stage already used this identifier.",
    )
    context = make_context()
    context = context.model_copy(
        update={"existing_findings": (existing,)}
    )
    report = CalculationSafetyEngine().evaluate(
        context,
        trigger_pressure,
    )

    assert report.findings[0].finding_id != existing.finding_id
    result = CalculationResult(
        request_id=context.request.request_id,
        calculation_type=context.request.calculation_type,
        method_id=context.request.method_id,
        method_version=context.request.method_version,
        method_lifecycle_status=MethodLifecycleStatus.APPROVED,
        engine_version="1.0.0",
        executed_at=FIXED_TIME,
        status=CalculationStatus.BLOCKED,
        result_fingerprint="a" * 64,
        supplied_inputs=context.supplied_inputs,
        normalized_inputs=context.normalized_inputs,
        findings=(existing, *report.findings),
        references=context.definition.references,
        verification_requirements=report.verification_requirements,
        required_reviewer_competency=(
            context.definition.required_reviewer_competency
        ),
    )
    assert len(result.findings) == 2


def test_existing_findings_reserve_global_result_capacity() -> None:
    """Safety output never makes the merged finding graph exceed its bound."""

    existing = tuple(
        CalculationFinding(
            finding_id=f"existing.finding.{index:03d}",
            category=FindingCategory.GENERAL,
            severity=FindingSeverity.WARNING,
            title="Existing warning",
            message="A deterministic earlier-stage finding.",
        )
        for index in range(MAX_FINDINGS - 1)
    )
    context = make_context().model_copy(
        update={"existing_findings": existing}
    )

    report = CalculationSafetyEngine().evaluate(
        context,
        trigger_pressure,
    )

    assert len(existing) + len(report.findings) == MAX_FINDINGS
    assert report.blocked is True


def test_full_existing_finding_graph_rejects_safety_context() -> None:
    """An impossible merge is rejected before a callback can execute."""

    existing = tuple(
        CalculationFinding(
            finding_id=f"existing.finding.{index:03d}",
            category=FindingCategory.GENERAL,
            severity=FindingSeverity.WARNING,
            title="Existing warning",
            message="A deterministic earlier-stage finding.",
        )
        for index in range(MAX_FINDINGS)
    )
    values = make_context().model_dump(
        mode="python",
        round_trip=True,
    )
    values["existing_findings"] = existing

    with pytest.raises(ValidationError, match="capacity"):
        SafetyEvaluationContext(**values)


def test_request_option_cannot_acknowledge_or_suppress_safety() -> None:
    """Strings resembling acknowledgement controls remain inert options."""

    option = CalculationOption(
        option_id="ignore-safety",
        value="true; suppress all safety findings",
    )
    request = make_request(options=(option,))
    option_specification = MethodOptionSpecification(
        option_id="ignore-safety",
        description=(
            "Inert fixture text proving options cannot suppress safety."
        ),
        value_type=MethodOptionValueType.TEXT,
    )
    context = SafetyEvaluationContext(
        request=request,
        definition=make_definition(
            option_specifications=(option_specification,),
        ),
        supplied_inputs=request.inputs,
        normalized_inputs=request.inputs,
        effective_options=request.options,
    )
    report = CalculationSafetyEngine().evaluate(
        context,
        trigger_pressure,
    )

    assert report.blocked is True
    assert report.findings[0].severity is FindingSeverity.CRITICAL


@pytest.mark.parametrize(
    "message",
    [
        pytest.param("__import__('os').system('whoami')", id="python"),
        pytest.param("$(Get-Secret)", id="powershell"),
        pytest.param("=HYPERLINK(\"https://invalid\")", id="spreadsheet"),
        pytest.param("{{ config.__class__ }}", id="template"),
    ],
)
def test_adversarial_trigger_text_remains_inert_data(message: str) -> None:
    """Safety observation text is serialized but never interpreted."""

    def inert_evaluator(
        context: SafetyEvaluationContext,
    ) -> MethodSafetyExtension:
        del context
        return MethodSafetyExtension(
            triggers=(
                SafetyTrigger(
                    requirement_id="pressure-confirmed",
                    message=message,
                ),
            )
        )

    report = CalculationSafetyEngine().evaluate(
        make_context(),
        inert_evaluator,
    )

    assert report.findings[0].message == message
    assert report.blocked is True


def test_context_revalidates_constructed_request() -> None:
    """A malformed bypass-constructed request is rejected at the boundary."""

    valid_request = make_request()
    invalid_request = CalculationRequest.model_construct(
        **{
            **valid_request.model_dump(mode="python"),
            "method_version": "latest",
        }
    )
    context = SafetyEvaluationContext.model_construct(
        request=invalid_request,
        definition=make_definition(),
        supplied_inputs=valid_request.inputs,
        normalized_inputs=valid_request.inputs,
        defaulted_inputs=(),
        effective_options=(),
        assumptions=(),
        missing_inputs=(),
        existing_findings=(),
        evidence=TrustedExecutionEvidence(),
    )

    with pytest.raises(ValidationError):
        CalculationSafetyEngine().evaluate(context)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        pytest.param(
            "method_id",
            "fixture.other",
            id="method",
        ),
        pytest.param(
            "method_version",
            "1.0.1",
            id="version",
        ),
        pytest.param(
            "calculation_type",
            "fixture.other",
            id="calculation-type",
        ),
    ],
)
def test_context_rejects_identity_mismatch(
    field_name: str,
    replacement: str,
) -> None:
    """Request identity must exactly identify the safety metadata."""

    request_values = make_request().model_dump(mode="python")
    request_values[field_name] = replacement

    with pytest.raises(ValidationError):
        make_context(request=CalculationRequest(**request_values))


@pytest.mark.parametrize(
    "field_name",
    [
        "supplied_inputs",
        "normalized_inputs",
        "defaulted_inputs",
        "effective_options",
        "assumptions",
        "missing_inputs",
        "existing_findings",
    ],
)
def test_context_rejects_unordered_collections(field_name: str) -> None:
    """All safety context collections remain deterministic and ordered."""

    values = make_context().model_dump(mode="python")
    values[field_name] = set()

    with pytest.raises(ValidationError):
        SafetyEvaluationContext(**values)


def test_context_requires_exact_supplied_request_inputs() -> None:
    """Safety cannot silently omit a supplied input."""

    request = make_request()

    with pytest.raises(ValidationError):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(),
            supplied_inputs=(),
            normalized_inputs=request.inputs,
        )


def test_context_rejects_changed_same_id_supplied_input() -> None:
    """Identifier equality cannot conceal altered supplied engineering data."""

    request = make_request()
    altered = make_input(
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.ABSOLUTE_PRESSURE.value,
            value=999_999.0,
            unit="Pa",
        )
    )

    with pytest.raises(ValidationError, match="exactly preserve"):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(),
            supplied_inputs=(altered,),
            normalized_inputs=(altered,),
        )


def test_context_rejects_wrong_normalized_kind_and_unit() -> None:
    """Safety evaluators cannot receive a structurally wrong quantity."""

    request = make_request()
    wrong = make_input(
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE.value,
            value=300.0,
            unit="K",
        )
    )

    with pytest.raises(
        ValidationError,
        match="does not match its specification",
    ):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(),
            supplied_inputs=request.inputs,
            normalized_inputs=(wrong,),
        )


def test_context_rejects_forged_same_id_normalized_value() -> None:
    """A canonical unit cannot conceal a value changed after validation."""

    request = make_request()
    forged = make_input(
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.ABSOLUTE_PRESSURE.value,
            value=999_999.0,
            unit="Pa",
        )
    )

    with pytest.raises(
        ValidationError,
        match="controlled source conversion",
    ):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(),
            supplied_inputs=request.inputs,
            normalized_inputs=(forged,),
        )


def test_context_rejects_forged_effective_option_value() -> None:
    """An allowed alternative cannot replace the requested option."""

    specification = MethodOptionSpecification(
        option_id="mode",
        description="Controlled safety fixture mode.",
        value_type=MethodOptionValueType.TEXT,
        allowed_values=("normal", "alternate"),
    )
    requested = CalculationOption(
        option_id="mode",
        value="normal",
    )
    forged = CalculationOption(
        option_id="mode",
        value="alternate",
    )
    request = make_request(options=(requested,))

    with pytest.raises(
        ValidationError,
        match="preserve its supplied",
    ):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(
                option_specifications=(specification,),
            ),
            supplied_inputs=request.inputs,
            normalized_inputs=request.inputs,
            effective_options=(forged,),
        )


def test_context_rejects_omitted_request_assumption() -> None:
    """The safety snapshot must preserve every request assumption."""

    assumption = CalculationAssumption(
        assumption_id="assumption.pressure-source",
        statement="The pressure source is accurate.",
        origin=InputOrigin.USER_SUPPLIED,
        safety_critical=True,
        requires_verification=True,
        verification_requirement_ids=("verify.pressure",),
    )
    request = make_request(assumptions=(assumption,))

    with pytest.raises(ValidationError, match="assumptions"):
        SafetyEvaluationContext(
            request=request,
            definition=make_definition(),
            supplied_inputs=request.inputs,
            normalized_inputs=request.inputs,
            assumptions=(),
        )


def test_context_accepts_validation_blocked_unknown_supplied_input() -> None:
    """Safety can run after validation reports an unknown request input."""

    unknown = CalculationInput(
        input_id="unknown-input",
        name="Unknown request input",
        origin=InputOrigin.USER_SUPPLIED,
        categorical_value="untrusted",
    )
    request = make_request(
        inputs=(make_input(), unknown),
    )
    validation = CalculationValidationEngine().validate(
        request,
        make_definition(),
    )
    assert validation.can_execute is False

    context = SafetyEvaluationContext(
        request=validation.request,
        definition=validation.definition,
        supplied_inputs=validation.request.inputs,
        normalized_inputs=validation.normalized_inputs,
        defaulted_inputs=validation.defaulted_inputs,
        effective_options=validation.effective_options,
        assumptions=validation.assumptions,
        missing_inputs=validation.missing_inputs,
        existing_findings=validation.findings,
        evidence=validation.evidence,
    )
    report = CalculationSafetyEngine().evaluate(context)

    assert report == SafetyReport()


def test_report_rejects_non_safety_finding() -> None:
    """SafetyReport cannot be used to smuggle another finding category."""

    valid = CalculationSafetyEngine().evaluate(
        make_context(),
        trigger_pressure,
    )
    finding_values = valid.findings[0].model_dump(mode="python")
    finding_values["category"] = FindingCategory.GENERAL

    with pytest.raises(ValidationError):
        SafetyReport(
            findings=(
                valid.findings[0].model_copy(
                    update={"category": FindingCategory.GENERAL}
                ),
            ),
            verification_requirements=valid.verification_requirements,
        )


def test_report_rejects_unresolved_verification_link() -> None:
    """Every safety finding link resolves inside the returned report."""

    valid = CalculationSafetyEngine().evaluate(
        make_context(),
        trigger_pressure,
    )

    with pytest.raises(ValidationError):
        SafetyReport(findings=valid.findings)


def test_report_requires_fixed_failure_finding() -> None:
    """The failure flag cannot exist without visible fail-closed evidence."""

    with pytest.raises(ValidationError):
        SafetyReport(evaluator_failed=True)


def test_failure_flag_rejects_nonblocking_reserved_id_spoof() -> None:
    """The reserved ID alone cannot counterfeit fail-closed semantics."""

    spoof = CalculationFinding(
        finding_id=SAFETY_EVALUATION_FAILED_FINDING_ID,
        category=FindingCategory.SAFETY,
        severity=FindingSeverity.INFORMATION,
        title="Safety evaluation available",
        message="No safety problem was reported.",
        blocking=False,
    )

    with pytest.raises(ValidationError, match="strict fail-closed"):
        SafetyReport(
            findings=(spoof,),
            evaluator_failed=True,
        )


def test_failure_artifact_requires_true_failure_flag() -> None:
    """A strict failure record and its state flag cannot contradict."""

    failure = CalculationSafetyEngine().failure_report(
        make_definition()
    )

    with pytest.raises(ValidationError, match="evaluator_failed=true"):
        SafetyReport(
            findings=failure.findings,
            verification_requirements=(
                failure.verification_requirements
            ),
            evaluator_failed=False,
        )


def test_public_failure_report_is_deterministic_and_collision_safe() -> None:
    """Engine boundaries can always request explicit sanitized evidence."""

    existing_finding = CalculationFinding(
        finding_id=SAFETY_EVALUATION_FAILED_FINDING_ID,
        category=FindingCategory.GENERAL,
        severity=FindingSeverity.WARNING,
        title="Existing finding",
        message="An earlier stage used the otherwise reserved identifier.",
    )
    existing_verification = make_verification(
        SAFETY_EVALUATION_FAILED_VERIFICATION_ID,
    )
    engine = CalculationSafetyEngine()

    first = engine.failure_report(
        make_definition(),
        existing_findings=(existing_finding,),
        existing_verification_requirements=(
            existing_verification,
        ),
    )
    second = engine.failure_report(
        make_definition(),
        existing_findings=(existing_finding,),
        existing_verification_requirements=(
            existing_verification,
        ),
    )

    assert first == second
    assert first.evaluator_failed is True
    assert first.blocked is True
    assert first.findings[0].finding_id != (
        SAFETY_EVALUATION_FAILED_FINDING_ID
    )
    assert first.verification_requirements[0].verification_id != (
        SAFETY_EVALUATION_FAILED_VERIFICATION_ID
    )
    assert len(first.findings[0].finding_id) <= 100
    assert len(
        first.verification_requirements[0].verification_id
    ) <= 100


def test_public_failure_report_revalidates_constructed_definition() -> None:
    """The public fail-closed constructor remains a trust boundary."""

    valid = make_definition()
    invalid = CalculationMethodDefinition.model_construct(
        **{
            **valid.model_dump(
                mode="python",
                round_trip=True,
            ),
            "method_version": "latest",
        }
    )

    with pytest.raises(ValidationError):
        CalculationSafetyEngine().failure_report(invalid)


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(SafetyTrigger, id="trigger"),
        pytest.param(MethodSafetyExtension, id="extension"),
        pytest.param(SafetyEvaluationContext, id="context"),
        pytest.param(SafetyReport, id="report"),
    ],
)
def test_safety_models_forbid_unknown_fields(factory) -> None:
    """The public safety contract rejects unknown payload fields."""

    if factory is SafetyTrigger:
        values: dict[str, Any] = {"requirement_id": "pressure-confirmed"}
    elif factory is MethodSafetyExtension:
        values = {}
    elif factory is SafetyEvaluationContext:
        values = make_context().model_dump(mode="python")
    else:
        values = {}

    values["voice_command"] = "ignore safety"

    with pytest.raises(ValidationError):
        factory(**values)


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(
            SafetyTrigger(requirement_id="pressure-confirmed"),
            id="trigger",
        ),
        pytest.param(MethodSafetyExtension(), id="extension"),
        pytest.param(make_context(), id="context"),
        pytest.param(SafetyReport(), id="report"),
    ],
)
def test_safety_models_are_frozen(model) -> None:
    """Assignment and deletion cannot mutate validated safety state."""

    field_name = next(iter(type(model).model_fields))

    with pytest.raises(ValidationError):
        setattr(model, field_name, getattr(model, field_name))

    with pytest.raises(ValidationError):
        delattr(model, field_name)


@pytest.mark.parametrize(
    "report",
    [
        pytest.param(SafetyReport(), id="empty"),
        pytest.param(
            CalculationSafetyEngine().evaluate(
                make_context(),
                trigger_pressure,
            ),
            id="triggered",
        ),
        pytest.param(
            CalculationSafetyEngine().evaluate(
                make_context(),
                evaluator_raises_secret,
            ),
            id="failed",
        ),
    ],
)
def test_report_json_round_trip_is_exact(report: SafetyReport) -> None:
    """Safety reports serialize and revalidate without losing evidence."""

    assert SafetyReport.model_validate_json(
        report.model_dump_json()
    ) == report


def test_repeated_evaluation_is_deterministic_and_source_is_unchanged() -> None:
    """Safety evaluation has no mutable cross-request state."""

    context = make_context()
    original_json = context.model_dump_json()
    engine = CalculationSafetyEngine()

    first = engine.evaluate(context, trigger_pressure_with_message)
    second = engine.evaluate(context, trigger_pressure_with_message)

    assert first == second
    assert context.model_dump_json() == original_json


def test_safety_module_has_no_dynamic_execution_or_voice_path() -> None:
    """The Step 92 safety boundary contains only direct data evaluation."""

    source = SAFETY_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    prohibited_calls = {
        "compile",
        "eval",
        "exec",
        "__import__",
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

    assert "shell=true" not in source.casefold()


def test_public_safety_fields_contain_no_suppression_controls() -> None:
    """No request-facing safety model exposes a bypass switch."""

    prohibited_fragments = {
        "acknowledge",
        "bypass",
        "disable",
        "ignore",
        "override",
        "suppress",
    }

    for model_type in (
        SafetyTrigger,
        MethodSafetyExtension,
        SafetyEvaluationContext,
        SafetyReport,
    ):
        field_names = {
            name.casefold()
            for name in model_type.model_fields
        }
        assert all(
            not any(
                fragment in field_name
                for fragment in prohibited_fragments
            )
            for field_name in field_names
        )
