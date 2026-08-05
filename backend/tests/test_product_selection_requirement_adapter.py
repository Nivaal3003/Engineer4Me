"""Fail-closed tests for Step 111 calculated selection requirements."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from math import inf, nan
from pathlib import Path
from uuid import UUID

import pytest
from app.engineering.calculations import ENGINE_VERSION, ENGINEERING_METHOD_REGISTRY
from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    CalculationResult,
    CalculationStatus,
    EngineeringQuantity,
    InputOrigin,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.knowledge_calculation_adapter import (
    ControlledCalculationKnowledgeAdapter,
    KnowledgeMethodBinding,
    fingerprint_knowledge,
    fingerprint_method_definition,
)
from app.engineering.knowledge_models import (
    EngineeringCalculationReference,
    EngineeringDiscipline,
    EngineeringKnowledge,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
    StandardApplicability,
    StandardReference,
    VerificationRequirement,
)
from app.engineering.product_selection_requirement_adapter import (
    MAX_REQUIREMENT_COLLECTION_ITEMS,
    InvalidEngineeringRequirementsError,
    ProductRequirementField,
    ProductSelectionRequirementAdapter,
    RequirementDecision,
    SelectionRequirementBinding,
)
from app.engineering.recommendation_models import EngineeringRequirements

FIXED_TIME = datetime(2026, 8, 2, 12, 30, tzinfo=UTC)
FIXED_REQUEST_ID = UUID("11100000-0000-4000-8000-000000000001")
FIXED_CALCULATION_ID = UUID("11100000-0000-4000-8000-000000000002")
KNOWLEDGE_ID = "knowledge.pressure-selection"
KNOWLEDGE_REVISION = "1.0"
CALCULATION_REFERENCE_ID = "knowledge.calculation.absolute-pressure"
METHOD_ID = "general.pressure.gauge-to-absolute"
METHOD_VERSION = "1.0.0"
CALCULATION_TYPE = "general.pressure.gauge-to-absolute"
KNOWLEDGE_BINDING_ID = "binding.knowledge.absolute-pressure"
REQUIREMENT_BINDING_ID = "binding.requirement.process-pressure"
OUTPUT_ID = "absolute-pressure"


def approved_review(review_type: ReviewType) -> KnowledgeReview:
    """Return one approved knowledge-review record."""

    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Step 111 reviewer",
        reviewer_role="Competent engineering reviewer",
        reviewed_at=FIXED_TIME,
    )


def published_knowledge(*, blocking_safety: bool = False) -> EngineeringKnowledge:
    """Return the exact published knowledge linked by the adapter."""

    return EngineeringKnowledge(
        knowledge_id=KNOWLEDGE_ID,
        title="Absolute-pressure candidate requirement knowledge",
        subject="Pressure requirement derivation",
        summary=(
            "Controlled knowledge allowing one approved calculation output "
            "to become a candidate product-selection requirement."
        ),
        detailed_guidance=(
            "Preserve the user requirement whenever it differs from the "
            "calculated candidate and expose the conflict for decision."
        ),
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[
            KnowledgeCategory.CALCULATION,
            KnowledgeCategory.SELECTION,
        ],
        status=KnowledgeStatus.PUBLISHED,
        safety=SafetyGuidance(
            safety_summary="Verify the explicit absolute-pressure basis.",
            severity=SafetySeverity.WARNING,
            required_site_risk_assessment=True,
            blocks_work_until_resolved=blocking_safety,
        ),
        standards=[
            StandardReference(
                organisation="BIPM",
                standard_number="SI Brochure",
                title="The International System of Units",
                edition="9",
                publication_year=2019,
                clause="Pressure units",
                applicability=StandardApplicability.INFORMATIVE,
            )
        ],
        evidence=[
            EvidenceReference(
                evidence_id="evidence.pressure-selection",
                evidence_type=EvidenceType.ENGINEERING_TEXTBOOK,
                title="Pressure-basis selection reference",
                strength=EvidenceStrength.HIGH,
                verified=True,
                verified_by="Step 111 reviewer",
                verified_at=FIXED_TIME,
            )
        ],
        calculations=[
            EngineeringCalculationReference(
                calculation_id=CALCULATION_REFERENCE_ID,
                title="Approved absolute-pressure candidate calculation",
                purpose=(
                    "Link an exact approved method without embedding an "
                    "executable formula."
                ),
                required_inputs=[
                    "Gauge pressure",
                    "Atmospheric absolute pressure",
                ],
                required_units={
                    "Gauge pressure": "pressure",
                    "Atmospheric absolute pressure": "pressure",
                },
                validation_rules=["Both pressure bases must be explicit."],
                safety_warnings=["Confirm the atmospheric pressure input."],
                verification_requirements=[
                    VerificationRequirement(
                        verification_id="verify.pressure-selection",
                        description="Verify pressure basis and units.",
                        method="Independent calculation review",
                        expected_result="The output is absolute pressure.",
                    )
                ],
            )
        ],
        reviews=[
            approved_review(ReviewType.TECHNICAL),
            approved_review(ReviewType.SAFETY),
            approved_review(ReviewType.STANDARDS),
            approved_review(ReviewType.FINAL_APPROVAL),
        ],
        revision_metadata=RevisionMetadata(
            revision=KNOWLEDGE_REVISION,
            created_by="Step 111 test suite",
            created_at=FIXED_TIME,
        ),
        confidence_score=95.0,
    )


def knowledge_binding(
    *,
    knowledge: EngineeringKnowledge | None = None,
) -> KnowledgeMethodBinding:
    """Return the exact knowledge-to-method allow-list entry."""

    bound_knowledge = published_knowledge() if knowledge is None else knowledge
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        METHOD_ID,
        METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
    )
    return KnowledgeMethodBinding(
        binding_id=KNOWLEDGE_BINDING_ID,
        knowledge_id=KNOWLEDGE_ID,
        knowledge_revision=KNOWLEDGE_REVISION,
        calculation_reference_id=CALCULATION_REFERENCE_ID,
        method_id=METHOD_ID,
        method_version=METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
        engine_version=ENGINE_VERSION,
        knowledge_fingerprint=fingerprint_knowledge(bound_knowledge),
        method_definition_fingerprint=fingerprint_method_definition(definition),
    )


def controlled_knowledge_adapter(
    *,
    knowledge: EngineeringKnowledge | None = None,
) -> ControlledCalculationKnowledgeAdapter:
    """Return the exact immutable knowledge/calculation adapter."""

    return ControlledCalculationKnowledgeAdapter(
        registry=ENGINEERING_METHOD_REGISTRY,
        bindings=(knowledge_binding(knowledge=knowledge),),
    )


def requirement_binding(**updates: object) -> SelectionRequirementBinding:
    """Return the approved output-to-requirement mapping."""

    values: dict[str, object] = {
        "binding_id": REQUIREMENT_BINDING_ID,
        "knowledge_method_binding_id": KNOWLEDGE_BINDING_ID,
        "output_id": OUTPUT_ID,
        "quantity_kind": QuantityKind.ABSOLUTE_PRESSURE,
        "output_unit": "Pa",
        "target_field": ProductRequirementField.PROCESS_PRESSURE_BAR,
        "target_unit": "bar",
    }
    values.update(updates)
    return SelectionRequirementBinding(**values)


def requirement_adapter(
    *,
    bindings: tuple[SelectionRequirementBinding, ...] | None = None,
    knowledge: EngineeringKnowledge | None = None,
) -> ProductSelectionRequirementAdapter:
    """Return a requirement adapter using only reviewed mappings."""

    return ProductSelectionRequirementAdapter(
        knowledge_adapter=controlled_knowledge_adapter(knowledge=knowledge),
        bindings=(requirement_binding(),) if bindings is None else bindings,
    )


def quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    """Return one strict engineering quantity."""

    return EngineeringQuantity(
        quantity_kind=kind,
        value=value,
        unit=unit,
    )


def completed_pressure_result() -> CalculationResult:
    """Execute the real approved pressure method through the production engine."""

    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        METHOD_ID,
        METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
    )
    supplied = {
        "gauge-pressure": quantity(
            QuantityKind.GAUGE_PRESSURE,
            250.0,
            "kPa",
        ),
        "atmospheric-pressure": quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            101.325,
            "kPa",
        ),
    }
    inputs = tuple(
        CalculationInput(
            input_id=specification.input_id,
            name=specification.name,
            origin=InputOrigin.USER_SUPPLIED,
            quantity=supplied[specification.input_id],
        )
        for specification in definition.input_specifications
    )
    request = CalculationRequest(
        request_id=FIXED_REQUEST_ID,
        calculation_type=CALCULATION_TYPE,
        method_id=METHOD_ID,
        method_version=METHOD_VERSION,
        requested_at=FIXED_TIME,
        inputs=inputs,
    )
    engine = CalculationEngine(
        registry=ENGINEERING_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )

    result = engine.execute(request)
    assert result.status is CalculationStatus.COMPLETED
    return result


def uncertain_pressure_result() -> CalculationResult:
    """Return a valid result whose mapped quantity carries uncertainty."""

    result = completed_pressure_result()
    output = next(item for item in result.outputs if item.output_id == OUTPUT_ID)
    assert output.quantity is not None
    uncertain_quantity = output.quantity.model_copy(
        update={
            "uncertainty": 1_000.0,
            "uncertainty_basis": "One standard uncertainty in pascals.",
        }
    )
    updated_output = output.model_copy(update={"quantity": uncertain_quantity})
    updated_steps = tuple(
        step.model_copy(
            update={
                "output_values": tuple(
                    trace_value.model_copy(update={"quantity": uncertain_quantity})
                    if trace_value.value_id in output.source_value_ids
                    else trace_value
                    for trace_value in step.output_values
                )
            }
        )
        for step in result.trace_steps
    )
    return result.model_copy(
        update={
            "outputs": (updated_output,),
            "trace_steps": updated_steps,
        }
    )


def tampered_pressure_result() -> CalculationResult:
    """Change a result output and matching trace without updating its legacy hash."""

    result = completed_pressure_result()
    output = next(item for item in result.outputs if item.output_id == OUTPUT_ID)
    assert output.quantity is not None
    tampered_quantity = output.quantity.model_copy(
        update={"value": output.quantity.value + 10_000.0}
    )
    updated_output = output.model_copy(update={"quantity": tampered_quantity})
    updated_steps = tuple(
        step.model_copy(
            update={
                "output_values": tuple(
                    trace_value.model_copy(update={"quantity": tampered_quantity})
                    if trace_value.value_id in output.source_value_ids
                    else trace_value
                    for trace_value in step.output_values
                )
            }
        )
        for step in result.trace_steps
    )
    tampered = result.model_copy(
        update={
            "outputs": (updated_output,),
            "trace_steps": updated_steps,
        }
    )
    assert tampered.result_fingerprint == result.result_fingerprint
    return tampered


def adapt(
    requirements: EngineeringRequirements,
    *,
    knowledge: EngineeringKnowledge | None = None,
    result: CalculationResult | None = None,
):
    """Run the explicit Step 111 requirement adaptation."""

    resolved_knowledge = published_knowledge() if knowledge is None else knowledge
    return requirement_adapter(knowledge=resolved_knowledge).adapt(
        knowledge=resolved_knowledge,
        calculation_id=CALCULATION_REFERENCE_ID,
        result=completed_pressure_result() if result is None else result,
        user_requirements=requirements,
    )


def only_decision(adaptation):
    """Return the single decision produced by the fixture mapping."""

    assert len(adaptation.decisions) == 1
    return adaptation.decisions[0]


def test_missing_user_requirement_is_populated_only_in_candidate() -> None:
    """A calculated output may fill a missing candidate requirement explicitly."""

    user = EngineeringRequirements(measurement_type="pressure")
    before = user.model_dump(mode="python")

    adaptation = adapt(user)
    decision = only_decision(adaptation)

    assert user.model_dump(mode="python") == before
    assert user.process_pressure_bar is None
    assert adaptation.user_requirements.process_pressure_bar is None
    assert adaptation.candidate_requirements.process_pressure_bar == pytest.approx(
        3.51325
    )
    assert adaptation.has_conflicts is False
    assert decision.decision is RequirementDecision.APPLIED_TO_MISSING
    assert decision.conflict is False
    assert decision.calculated_value == pytest.approx(3.51325)
    assert decision.effective_value == pytest.approx(3.51325)
    assert (
        adaptation.result_fingerprint == completed_pressure_result().result_fingerprint
    )


def test_conflicting_user_value_is_retained_and_reported() -> None:
    """A differing calculated candidate cannot overwrite the user value."""

    user = EngineeringRequirements(
        measurement_type="pressure",
        process_pressure_bar=4.0,
    )

    adaptation = adapt(user)
    decision = only_decision(adaptation)

    assert adaptation.user_requirements.process_pressure_bar == 4.0
    assert adaptation.candidate_requirements.process_pressure_bar == 4.0
    assert adaptation.has_conflicts is True
    assert decision.decision is RequirementDecision.USER_VALUE_RETAINED
    assert decision.conflict is True
    assert decision.user_value == 4.0
    assert decision.calculated_value == pytest.approx(3.51325)
    assert decision.effective_value == 4.0


def test_equal_user_value_is_confirmed_without_replacement() -> None:
    """An equal user value is confirmed while preserving its ownership."""

    user = EngineeringRequirements(process_pressure_bar=3.51325)

    adaptation = adapt(user)
    decision = only_decision(adaptation)

    assert adaptation.candidate_requirements.process_pressure_bar == 3.51325
    assert adaptation.has_conflicts is False
    assert decision.decision is RequirementDecision.USER_VALUE_CONFIRMED
    assert decision.conflict is False
    assert decision.user_value == 3.51325


def test_near_but_different_user_value_is_retained() -> None:
    """The adapter does not hide a conflict behind an implicit tolerance."""

    user_value = 3.513250000000001
    adaptation = adapt(EngineeringRequirements(process_pressure_bar=user_value))
    decision = only_decision(adaptation)

    assert decision.decision is RequirementDecision.USER_VALUE_RETAINED
    assert decision.conflict is True
    assert decision.user_value == user_value
    assert decision.effective_value == user_value
    assert adaptation.candidate_requirements.process_pressure_bar == user_value


def test_zero_is_a_user_value_not_a_missing_value() -> None:
    """The adapter distinguishes an explicit zero from a missing None."""

    adaptation = adapt(EngineeringRequirements(process_pressure_bar=0.0))
    decision = only_decision(adaptation)

    assert adaptation.candidate_requirements.process_pressure_bar == 0.0
    assert adaptation.has_conflicts is True
    assert decision.decision is RequirementDecision.USER_VALUE_RETAINED
    assert decision.conflict is True
    assert decision.user_value == 0.0


def test_adaptation_is_deterministic_and_provenance_bound() -> None:
    """Identical inputs produce identical ordered decisions and link hashes."""

    first = adapt(EngineeringRequirements())
    second = adapt(EngineeringRequirements())

    assert first == second
    assert (
        first.knowledge_link.link_fingerprint == second.knowledge_link.link_fingerprint
    )
    decision = only_decision(first)
    assert first.knowledge_link.method_id == METHOD_ID
    assert first.knowledge_link.method_version == METHOD_VERSION
    assert decision.method_id == METHOD_ID
    assert decision.method_version == METHOD_VERSION
    assert first.source_result_fingerprint == second.source_result_fingerprint
    assert decision.source_result_fingerprint == first.source_result_fingerprint
    assert first.source_result_fingerprint != first.result_fingerprint
    assert decision.output_id == OUTPUT_ID
    assert decision.output_ids == (OUTPUT_ID,)
    assert decision.source_quantity_kind == QuantityKind.ABSOLUTE_PRESSURE
    assert decision.source_unit == "Pa"
    assert decision.source_units == ("Pa",)
    assert decision.target_unit == "bar"


def test_blocking_knowledge_safety_prevents_requirement_adaptation() -> None:
    """A published stop-work condition blocks downstream selection use."""

    with pytest.raises(ValueError, match="block|safety"):
        adapt(
            EngineeringRequirements(),
            knowledge=published_knowledge(blocking_safety=True),
        )


@pytest.mark.parametrize(
    "status",
    tuple(
        status
        for status in CalculationStatus
        if status
        not in {
            CalculationStatus.COMPLETED,
            CalculationStatus.COMPLETED_WITH_WARNINGS,
        }
    ),
)
def test_noncompleted_result_states_cannot_feed_requirements(
    status: CalculationStatus,
) -> None:
    """Only completed, nonblocking calculation attempts are candidates."""

    valid = completed_pressure_result()
    payload = valid.model_dump(mode="python", round_trip=True)
    payload["status"] = status
    forged = CalculationResult.model_construct(**payload)

    with pytest.raises((TypeError, ValueError)):
        adapt(EngineeringRequirements(), result=forged)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("method_id", "general.pressure.absolute-to-gauge"),
        ("method_version", "9.9.9"),
        ("calculation_type", "general.pressure.wrong-type"),
    ),
)
def test_result_identity_mismatch_cannot_feed_requirements(
    field_name: str,
    replacement: str,
) -> None:
    """The result must match the exact linked method identity."""

    valid = completed_pressure_result()
    mismatched = valid.model_copy(update={field_name: replacement})

    with pytest.raises(ValueError, match="match|identity|method|version|type"):
        adapt(EngineeringRequirements(), result=mismatched)


def test_unconfigured_output_id_is_rejected() -> None:
    """A binding cannot silently fall back to another result output."""

    adapter = requirement_adapter(
        bindings=(requirement_binding(output_id="unconfigured-output"),)
    )

    with pytest.raises(ValueError, match="output"):
        adapter.adapt(
            knowledge=published_knowledge(),
            calculation_id=CALCULATION_REFERENCE_ID,
            result=completed_pressure_result(),
            user_requirements=EngineeringRequirements(),
        )


def test_wrong_declared_output_unit_is_rejected() -> None:
    """A reviewed binding must name the exact result output unit."""

    adapter = requirement_adapter(bindings=(requirement_binding(output_unit="kPa"),))

    with pytest.raises(ValueError, match="unit"):
        adapter.adapt(
            knowledge=published_knowledge(),
            calculation_id=CALCULATION_REFERENCE_ID,
            result=completed_pressure_result(),
            user_requirements=EngineeringRequirements(),
        )


def test_uncertainty_cannot_be_silently_dropped() -> None:
    """An uncertain output cannot become a definitive selection threshold."""

    with pytest.raises(ValueError, match="uncertain|uncertainty"):
        adapt(
            EngineeringRequirements(),
            result=uncertain_pressure_result(),
        )


def test_tampered_output_and_matching_trace_fail_exact_replay() -> None:
    """The legacy result hash cannot authorize consistently forged result data."""

    with pytest.raises(ValueError, match="replay|output|trace"):
        adapt(
            EngineeringRequirements(),
            result=tampered_pressure_result(),
        )


def test_wrong_quantity_kind_and_target_policy_are_rejected() -> None:
    """Application bindings cannot pair a field with an unsafe quantity kind."""

    with pytest.raises(ValueError, match="quantity|policy|pressure"):
        requirement_binding(quantity_kind=QuantityKind.GAUGE_PRESSURE)


@pytest.mark.parametrize(
    ("target_field", "quantity_kind", "output_unit", "target_unit"),
    (
        (
            ProductRequirementField.PROCESS_TEMPERATURE_C,
            QuantityKind.ABSOLUTE_TEMPERATURE,
            "K",
            "degC",
        ),
        (
            ProductRequirementField.PROCESS_PRESSURE_BAR,
            QuantityKind.ABSOLUTE_PRESSURE,
            "Pa",
            "bar",
        ),
        (
            ProductRequirementField.AMBIENT_TEMPERATURE_C,
            QuantityKind.ABSOLUTE_TEMPERATURE,
            "K",
            "degC",
        ),
        (
            ProductRequirementField.REQUIRED_ACCURACY_PERCENT,
            QuantityKind.RATIO,
            "1",
            "%",
        ),
    ),
)
def test_only_the_four_fixed_semantic_policies_validate(
    target_field: ProductRequirementField,
    quantity_kind: QuantityKind,
    output_unit: str,
    target_unit: str,
) -> None:
    """Every supported target has one explicit kind and target unit."""

    binding = requirement_binding(
        target_field=target_field,
        quantity_kind=quantity_kind,
        output_unit=output_unit,
        target_unit=target_unit,
    )

    assert binding.target_field is target_field
    assert binding.quantity_kind is quantity_kind
    assert binding.target_unit == target_unit


@pytest.mark.parametrize(
    "target_field",
    (
        "process_pressure_importance",
        "required_protocols",
        "application_notes",
        "hazardous_area_required",
    ),
)
def test_nonallowlisted_requirement_targets_are_rejected(
    target_field: str,
) -> None:
    """Importance, collection, notes, and safety flags cannot be calculated."""

    with pytest.raises(ValueError):
        requirement_binding(target_field=target_field)


def test_duplicate_target_binding_is_rejected_at_construction() -> None:
    """Two outputs cannot race to populate the same candidate field."""

    duplicate = requirement_binding(
        binding_id="binding.requirement.process-pressure.duplicate",
    )

    with pytest.raises(ValueError, match="duplicate|target|binding"):
        requirement_adapter(bindings=(requirement_binding(), duplicate))


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("process_pressure_bar", nan),
        ("process_pressure_bar", inf),
        ("process_pressure_bar", -inf),
        ("process_temperature_c", inf),
        ("ambient_temperature_c", inf),
        ("required_accuracy_percent", inf),
    ),
)
def test_nonfinite_user_numeric_requirements_fail_closed(
    field_name: str,
    value: float,
) -> None:
    """Legacy model gaps cannot let NaN or infinity cross the adapter."""

    requirements = EngineeringRequirements(**{field_name: value})

    with pytest.raises(ValueError, match="finite"):
        adapt(requirements)


@pytest.mark.parametrize(
    "required_protocols",
    (
        pytest.param(
            [
                f"protocol-{index}"
                for index in range(MAX_REQUIREMENT_COLLECTION_ITEMS + 1)
            ],
            id="too-many-items",
        ),
        pytest.param(["x" * 501], id="item-too-long"),
    ),
)
def test_oversized_requirement_collections_fail_before_knowledge_resolution(
    required_protocols: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound legacy collections before knowledge resolution or exact replay."""

    adapter = requirement_adapter()
    knowledge = published_knowledge()
    result = completed_pressure_result()
    requirements = EngineeringRequirements(required_protocols=required_protocols)

    def unexpected_trusted_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("oversized requirements reached trusted resolution")

    monkeypatch.setattr(
        ControlledCalculationKnowledgeAdapter,
        "resolve_link",
        unexpected_trusted_resolution,
    )
    monkeypatch.setattr(
        ControlledCalculationKnowledgeAdapter,
        "validate_result",
        unexpected_trusted_resolution,
    )

    with pytest.raises(InvalidEngineeringRequirementsError, match="bound"):
        adapter.adapt(
            knowledge=knowledge,
            calculation_id=CALCULATION_REFERENCE_ID,
            result=result,
            user_requirements=requirements,
        )


def test_post_construction_invalid_user_mutation_is_revalidated() -> None:
    """Mutable legacy requirements are reconstructed at the trust boundary."""

    requirements = EngineeringRequirements(
        hazardous_area_required=True,
        required_hazardous_area_approvals=["IECEx"],
    )
    requirements.hazardous_area_required = False

    with pytest.raises(ValueError, match="deep validation|hazardous_area_required"):
        adapt(requirements)


def test_unrelated_user_fields_are_deep_copied_and_preserved() -> None:
    """Adapting one scalar does not alias or alter unrelated user fields."""

    requirements = EngineeringRequirements(
        measurement_type="pressure",
        required_protocols=["HART"],
        required_wetted_materials=["316L stainless steel"],
    )
    adaptation = adapt(requirements)

    assert adaptation.user_requirements.required_protocols == ("HART",)
    assert adaptation.candidate_requirements.required_protocols == ("HART",)
    assert adaptation.candidate_requirements.required_wetted_materials == (
        "316L stainless steel",
    )
    requirements.required_protocols.append("FOUNDATION Fieldbus")
    assert adaptation.user_requirements.required_protocols == ("HART",)
    assert adaptation.candidate_requirements.required_protocols == ("HART",)


def test_adaptation_snapshots_reject_scalar_and_collection_mutation() -> None:
    """Returned provenance snapshots are immutable at every exposed level."""

    adaptation = adapt(
        EngineeringRequirements(
            required_protocols=["HART"],
            required_wetted_materials=["316L stainless steel"],
        )
    )

    with pytest.raises((AttributeError, TypeError, ValueError)):
        adaptation.candidate_requirements.process_pressure_bar = 9.0  # type: ignore[misc]

    protocols = adaptation.candidate_requirements.required_protocols
    with pytest.raises(TypeError):
        protocols[0] = "Modbus"  # type: ignore[index]

    with pytest.raises(AttributeError):
        adaptation.user_requirements.required_wetted_materials.append("Hastelloy")


def test_snapshot_copy_normalizes_mutable_collection_updates() -> None:
    """A copy update cannot reintroduce a mutable list into a snapshot."""

    adaptation = adapt(EngineeringRequirements(required_protocols=["HART"]))
    copied = adaptation.candidate_requirements.model_copy(
        update={"required_protocols": ["mutable"]}
    )

    assert copied.required_protocols == ("mutable",)
    assert adaptation.candidate_requirements.required_protocols == ("HART",)
    with pytest.raises(TypeError):
        copied.required_protocols[0] = "changed"  # type: ignore[index]
    with pytest.raises(AttributeError):
        copied.required_protocols.append("changed")


def test_adaptation_copy_rejects_candidate_decision_mismatch() -> None:
    """Copy updates must preserve the candidate values recorded by decisions."""

    adaptation = adapt(EngineeringRequirements())
    changed_candidate = adaptation.candidate_requirements.model_copy(
        update={"process_pressure_bar": 9.0}
    )

    with pytest.raises(ValueError, match="decision|provenance|snapshot"):
        adaptation.model_copy(update={"candidate_requirements": changed_candidate})


def test_build_selection_requirements_returns_fresh_independent_handoffs() -> None:
    """Mutable selection inputs exist only through an explicit fresh conversion."""

    adaptation = adapt(
        EngineeringRequirements(
            required_protocols=["HART"],
            required_wetted_materials=["316L stainless steel"],
        )
    )

    first = adaptation.build_selection_requirements()
    second = adaptation.build_selection_requirements()

    assert isinstance(first, EngineeringRequirements)
    assert isinstance(second, EngineeringRequirements)
    assert first is not second
    assert first.required_protocols is not second.required_protocols
    assert first.process_pressure_bar == pytest.approx(3.51325)
    assert first.required_protocols == ["HART"]

    first.process_pressure_bar = 99.0
    first.required_protocols.append("FOUNDATION Fieldbus")
    first.required_wetted_materials.append("Hastelloy")

    assert second.process_pressure_bar == pytest.approx(3.51325)
    assert second.required_protocols == ["HART"]
    assert second.required_wetted_materials == ["316L stainless steel"]
    assert adaptation.candidate_requirements.process_pressure_bar == pytest.approx(
        3.51325
    )
    assert adaptation.candidate_requirements.required_protocols == ("HART",)
    assert adaptation.candidate_requirements.required_wetted_materials == (
        "316L stainless steel",
    )


def test_adapter_does_not_call_the_recommendation_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Product ranking occurs only after an explicit caller handoff."""

    from app.engineering.engineering_recommendation_engine import (
        EngineeringRecommendationEngine,
    )

    def unexpected_recommendation(*args: object, **kwargs: object) -> None:
        raise AssertionError("requirement adapter invoked product selection")

    monkeypatch.setattr(
        EngineeringRecommendationEngine,
        "recommend_products",
        unexpected_recommendation,
    )

    adaptation = adapt(EngineeringRequirements())

    assert adaptation.candidate_requirements.process_pressure_bar == pytest.approx(
        3.51325
    )


def test_adapter_and_adaptation_are_immutable() -> None:
    """Reviewed mappings and provenance decisions cannot be replaced."""

    adapter = requirement_adapter()
    adaptation = adapter.adapt(
        knowledge=published_knowledge(),
        calculation_id=CALCULATION_REFERENCE_ID,
        result=completed_pressure_result(),
        user_requirements=EngineeringRequirements(),
    )

    with pytest.raises((AttributeError, TypeError, ValueError)):
        adapter.bindings = ()  # type: ignore[attr-defined]

    with pytest.raises((AttributeError, TypeError, ValueError)):
        adaptation.decisions = ()  # type: ignore[misc]


def test_adapter_source_has_no_formula_or_selection_execution_path() -> None:
    """The adapter uses fixed conversion policy, not dynamic expressions."""

    import app.engineering.product_selection_requirement_adapter as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection({"eval", "exec", "compile", "__import__"})

    assert forbidden_calls == set()
    assert "importlib" not in source
    assert "engineering_recommendation_engine" not in source
