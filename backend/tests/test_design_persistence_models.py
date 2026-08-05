"""Focused contract tests for Phase 7 design persistence models."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.level import (
    ENGINEERING_METHOD_REGISTRATIONS,
    ENGINEERING_METHOD_REGISTRY,
)
from app.engineering.calculations.method_models import TrustedExecutionEvidence
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    EngineeringQuantity,
    InputOrigin,
    MethodLifecycleStatus,
)
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
    MethodRegistration,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_models import AnalyzerApplicationRequest
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    AnalyzerAssessmentEnvelope,
)
from app.engineering.design.persistence_models import (
    AnalyzerRunPayload,
    CalculationRunPayload,
    DesignAnalyzerAssessmentCommand,
    DesignAssumption,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignCaseRevisionCreate,
    DesignCaseRevisionRecord,
    DesignCaseSummary,
    DesignContextItem,
    DesignLifecycleState,
    DesignRevisionPayload,
    DesignRevisionSummary,
    DesignSourceOrigin,
    DesignVerification,
    EngineeringRunKind,
    EngineeringRunRecord,
    EngineeringRunSummary,
    PersistedAnalyzerAssessment,
    RecordedIdentityOrigin,
    build_calculation_fingerprint_basis,
    build_engineering_run_fingerprint,
    calculation_input_fingerprint,
    engineering_execution_metadata,
    verify_calculation_result_fingerprint,
)
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
)
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE


FIXED_TIME = datetime(2026, 8, 2, 8, 30, tzinfo=UTC)


def _design_payload() -> DesignRevisionPayload:
    """Build deliberately unordered content to exercise canonicalization."""

    return DesignRevisionPayload(
        title="Process analyzer application",
        discipline="process-instrumentation",
        industry="Minerals processing",
        lifecycle_state=DesignLifecycleState.UNDER_REVIEW,
        source_origins=(
            DesignSourceOrigin(
                source_id="source-b",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                description="Reviewed process datasheet",
                reference_ids=("ref-z", "ref-a"),
            ),
            DesignSourceOrigin(
                source_id="source-a",
                origin=InputOrigin.USER_SUPPLIED,
                description="Site engineer observation",
            ),
        ),
        plant_context=(
            DesignContextItem(
                field_id="process-pressure",
                label="Normal process pressure",
                value="5.2",
                unit="bar(a)",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                source_origin_ids=("source-b", "source-a"),
            ),
            DesignContextItem(
                field_id="ambient-temperature",
                label="Maximum ambient temperature",
                value="45",
                unit="degC",
                origin=InputOrigin.USER_SUPPLIED,
                source_origin_ids=("source-a",),
            ),
        ),
        equipment_context=(
            DesignContextItem(
                field_id="sample-point",
                label="Sample point",
                value="Reactor outlet",
                origin=InputOrigin.USER_SUPPLIED,
                source_origin_ids=("source-a",),
            ),
        ),
        open_assumptions=(
            DesignAssumption(
                assumption_id="assumption-material",
                statement="Final wetted-material compatibility remains open.",
                source_origin_ids=("source-a",),
            ),
        ),
        required_verifications=(
            DesignVerification(
                verification_id="verify-material",
                action="Confirm materials against the complete stream composition.",
                responsible_discipline="Process engineering",
                safety_critical=True,
                source_origin_ids=("source-b", "source-a"),
            ),
        ),
    )


def _revision_record(
    *,
    revision_number: int = 1,
    supersedes_revision_id: UUID | None = None,
    supersedes_revision_fingerprint: str | None = None,
) -> DesignCaseRevisionRecord:
    return DesignCaseRevisionRecord.create(
        revision_id=uuid4(),
        design_case_id=uuid4(),
        case_reference="design-case-108",
        case_type="analyzer-application",
        revision_number=revision_number,
        supersedes_revision_id=supersedes_revision_id,
        supersedes_revision_fingerprint=supersedes_revision_fingerprint,
        payload=_design_payload(),
        change_reason="Create the controlled design record.",
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        created_at=FIXED_TIME,
    )


def _analyzer_envelope() -> AnalyzerAssessmentEnvelope:
    example = ANALYZER_DESIGN_CASE_EXAMPLES[0]
    return DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(example.request)


def _analyzer_run_record(
    *,
    linked: bool = True,
    predecessor: bool = False,
) -> EngineeringRunRecord:
    envelope = _analyzer_envelope()
    payload = AnalyzerRunPayload(
        envelope=envelope,
        execution_fingerprint=envelope.integration_fingerprint,
    )
    run_id = uuid4()
    design_case_id = uuid4() if linked else None
    design_revision_id = uuid4() if linked else None
    design_revision_number = 2 if linked else None
    design_revision_fingerprint = "d" * 64 if linked else None
    supersedes_run_id = uuid4() if predecessor else None
    supersedes_run_fingerprint = "e" * 64 if predecessor else None
    execution_metadata = engineering_execution_metadata(payload)
    input_fingerprint = envelope.request_fingerprint
    result_fingerprint = envelope.integration_fingerprint
    recorded_at = FIXED_TIME
    run_fingerprint = build_engineering_run_fingerprint(
        run_id=run_id,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
        supersedes_run_id=supersedes_run_id,
        supersedes_run_fingerprint=supersedes_run_fingerprint,
        payload=payload,
        execution_metadata=execution_metadata,
        input_fingerprint=input_fingerprint,
        result_fingerprint=result_fingerprint,
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        recorded_at=recorded_at,
    )
    return EngineeringRunRecord(
        run_id=run_id,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
        supersedes_run_id=supersedes_run_id,
        supersedes_run_fingerprint=supersedes_run_fingerprint,
        payload=payload,
        execution_metadata=execution_metadata,
        input_fingerprint=input_fingerprint,
        result_fingerprint=result_fingerprint,
        run_fingerprint=run_fingerprint,
        created_by="Test engineer",
        recorded_at=recorded_at,
    )


def _calculation_execution(
    *,
    design_case_id: UUID | None = None,
) -> tuple[object, CalculationRequest, object, TrustedExecutionEvidence, str]:
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        "level.hydrostatic.column-pressure",
        "1.0.0",
    )
    specifications = {
        item.input_id: item for item in definition.input_specifications
    }
    values = (
        ("density", QuantityKind.DENSITY, 998.2, "kg/m3"),
        ("vertical-height", QuantityKind.LENGTH, 3.5, "m"),
        (
            "gravitational-acceleration",
            QuantityKind.ACCELERATION,
            9.80665,
            "m/s2",
        ),
    )
    request = CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        requested_by="Test engineer",
        design_case_id=design_case_id,
        inputs=tuple(
            CalculationInput(
                input_id=input_id,
                name=specifications[input_id].name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=EngineeringQuantity(
                    quantity_kind=kind.value,
                    value=value,
                    unit=unit,
                ),
            )
            for input_id, kind, value, unit in values
        ),
    )
    result = DEFAULT_CALCULATION_SERVICE.execute(request)
    evidence = TrustedExecutionEvidence(
        references=definition.references,
        verification_requirements=definition.verification_requirements,
    )
    fingerprint_basis_json = build_calculation_fingerprint_basis(
        definition=definition,
        request=request,
        result=result,
        evidence=evidence,
    )
    return definition, request, result, evidence, fingerprint_basis_json


def test_revision_payload_canonicalizes_all_identity_collections() -> None:
    payload = _design_payload()

    assert tuple(item.source_id for item in payload.source_origins) == (
        "source-a",
        "source-b",
    )
    assert tuple(item.field_id for item in payload.plant_context) == (
        "ambient-temperature",
        "process-pressure",
    )
    pressure = next(
        item for item in payload.plant_context if item.field_id == "process-pressure"
    )
    assert pressure.source_origin_ids == ("source-a", "source-b")
    assert payload.source_origins[1].reference_ids == ("ref-a", "ref-z")
    assert payload.required_verifications[0].source_origin_ids == (
        "source-a",
        "source-b",
    )


def test_revision_payload_rejects_unknown_links_duplicates_and_extra_fields() -> None:
    with pytest.raises(ValidationError, match="unknown source origin"):
        DesignRevisionPayload(
            title="Invalid linked design",
            discipline="instrumentation",
            plant_context=(
                DesignContextItem(
                    field_id="pressure",
                    label="Pressure",
                    value="5",
                    origin=InputOrigin.USER_SUPPLIED,
                    source_origin_ids=("missing-source",),
                ),
            ),
        )

    with pytest.raises(ValidationError, match="source_id values must be unique"):
        DesignRevisionPayload(
            title="Duplicate sources",
            discipline="instrumentation",
            source_origins=(
                DesignSourceOrigin(
                    source_id="Source-A",
                    origin=InputOrigin.USER_SUPPLIED,
                    description="First source",
                ),
                DesignSourceOrigin(
                    source_id="source-a",
                    origin=InputOrigin.USER_SUPPLIED,
                    description="Duplicate source",
                ),
            ),
        )

    valid = DesignCaseCreate(
        case_reference="case-108",
        case_type="generic-design",
        payload=_design_payload(),
        change_reason="Create the case.",
        created_by="Test engineer",
    ).model_dump(mode="python", round_trip=True)
    valid["caller_result"] = {"forged": True}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DesignCaseCreate.model_validate(valid)


def test_revision_create_uses_strict_integer_and_fingerprint_contracts() -> None:
    with pytest.raises(ValidationError):
        DesignCaseRevisionCreate(
            expected_current_revision=True,
            expected_current_fingerprint="a" * 64,
            payload=_design_payload(),
            change_reason="Invalid Boolean revision.",
            created_by="Test engineer",
        )

    command = DesignCaseRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint="A" * 64,
        payload=_design_payload(),
        change_reason="Append a complete replacement snapshot.",
        created_by="Test engineer",
    )
    assert command.expected_current_fingerprint == "A" * 64
    assert command.creator_origin is (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )


def test_revision_record_normalizes_utc_and_detects_tampering() -> None:
    offset_time = FIXED_TIME.astimezone(timezone(timedelta(hours=2)))
    record = DesignCaseRevisionRecord.create(
        revision_id=uuid4(),
        design_case_id=uuid4(),
        case_reference="design-case-utc",
        case_type="generic-design",
        revision_number=1,
        supersedes_revision_id=None,
        supersedes_revision_fingerprint=None,
        payload=_design_payload(),
        change_reason="Create the design.",
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        created_at=offset_time,
    )

    assert record.created_at == FIXED_TIME
    assert record.created_at.tzinfo is UTC

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["change_reason"] = "Secretly altered without a new fingerprint."
    with pytest.raises(ValidationError, match="revision_fingerprint is stale"):
        DesignCaseRevisionRecord.model_validate(tampered)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["revision_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="revision_fingerprint is stale"):
        DesignCaseRevisionRecord.model_validate(tampered)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["created_at"] = record.created_at + timedelta(seconds=1)
    with pytest.raises(ValidationError, match="revision_fingerprint is stale"):
        DesignCaseRevisionRecord.model_validate(tampered)


@pytest.mark.parametrize(
    (
        "revision_number",
        "supersedes_revision_id",
        "supersedes_revision_fingerprint",
        "message",
    ),
    (
        (1, uuid4(), None, "revision predecessor linkage must be complete"),
        (1, uuid4(), "a" * 64, "only revision one"),
        (2, None, None, "only revision one"),
        (2, None, "a" * 64, "revision predecessor linkage must be complete"),
    ),
)
def test_revision_predecessor_contract_is_fail_closed(
    revision_number: int,
    supersedes_revision_id: UUID | None,
    supersedes_revision_fingerprint: str | None,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _revision_record(
            revision_number=revision_number,
            supersedes_revision_id=supersedes_revision_id,
            supersedes_revision_fingerprint=(
                supersedes_revision_fingerprint
            ),
        )


def test_revision_predecessor_fingerprint_is_part_of_revision_hash() -> None:
    record = _revision_record(
        revision_number=2,
        supersedes_revision_id=uuid4(),
        supersedes_revision_fingerprint="a" * 64,
    )

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["supersedes_revision_fingerprint"] = "b" * 64
    with pytest.raises(ValidationError, match="revision_fingerprint is stale"):
        DesignCaseRevisionRecord.model_validate(tampered)


def test_design_and_revision_summaries_do_not_leak_payloads() -> None:
    record = _revision_record()
    design_summary = DesignCaseSummary(
        design_case_id=record.design_case_id,
        case_reference=record.case_reference,
        case_type=record.case_type,
        title=record.payload.title,
        lifecycle_state=record.payload.lifecycle_state,
        current_revision=record.revision_number,
        current_revision_fingerprint=record.revision_fingerprint,
        concurrency_version=1,
        updated_at=record.created_at,
    )
    revision_summary = DesignRevisionSummary(
        revision_id=record.revision_id,
        design_case_id=record.design_case_id,
        revision_number=record.revision_number,
        supersedes_revision_id=record.supersedes_revision_id,
        supersedes_revision_fingerprint=(
            record.supersedes_revision_fingerprint
        ),
        title=record.payload.title,
        lifecycle_state=record.payload.lifecycle_state,
        revision_fingerprint=record.revision_fingerprint,
        change_reason=record.change_reason,
        created_by=record.created_by,
        creator_origin=record.creator_origin,
        created_at=record.created_at,
    )

    for summary in (design_summary, revision_summary):
        body = summary.model_dump(mode="json")
        serialized = str(body)
        assert "payload" not in body
        assert "plant_context" not in serialized
        assert "equipment_context" not in serialized
        assert "source_origins" not in serialized
        assert "open_assumptions" not in serialized


def test_valid_calculation_result_fingerprint_is_reproducible() -> None:
    definition, request, result, evidence, fingerprint_basis_json = (
        _calculation_execution()
    )

    verify_calculation_result_fingerprint(
        definition=definition,
        request=request,
        result=result,
        evidence=evidence,
        fingerprint_basis_json=fingerprint_basis_json,
    )

    payload = CalculationRunPayload(
        request=request,
        method_definition=definition,
        result=result,
        execution_fingerprint=result.result_fingerprint,
        fingerprint_basis_json=fingerprint_basis_json,
    )
    assert payload.execution_fingerprint == result.result_fingerprint
    assert payload.fingerprint_basis_json == fingerprint_basis_json


def test_calculation_result_fingerprint_tampering_is_detected() -> None:
    definition, request, result, evidence, fingerprint_basis_json = (
        _calculation_execution()
    )
    tampered_result = result.model_copy(
        update={"result_fingerprint": "0" * 64}
    )

    with pytest.raises(
        ValueError,
        match="calculation result fingerprint cannot be reproduced",
    ):
        verify_calculation_result_fingerprint(
            definition=definition,
            request=request,
            result=tampered_result,
            evidence=evidence,
            fingerprint_basis_json=fingerprint_basis_json,
        )


def test_calculation_payload_rejects_noncanonical_or_stale_fingerprint_basis() -> None:
    definition, request, result, evidence, fingerprint_basis_json = (
        _calculation_execution()
    )
    decoded = json.loads(fingerprint_basis_json)
    noncanonical = json.dumps(decoded, sort_keys=False, separators=(", ", ": "))

    with pytest.raises(
        ValidationError,
        match="calculation fingerprint basis is not canonical",
    ):
        CalculationRunPayload(
            request=request,
            method_definition=definition,
            result=result,
            execution_fingerprint=result.result_fingerprint,
            fingerprint_basis_json=noncanonical,
        )

    with pytest.raises(
        ValueError,
        match="stored calculation fingerprint basis drifted",
    ):
        verify_calculation_result_fingerprint(
            definition=definition,
            request=request,
            result=result,
            evidence=evidence,
            fingerprint_basis_json=noncanonical,
        )


def test_lifecycle_blocked_run_retains_exact_attempt_fingerprint_basis() -> None:
    _, request, _, _, _ = _calculation_execution()
    registration = next(
        item
        for item in ENGINEERING_METHOD_REGISTRATIONS
        if item.method_id == request.method_id
        and item.method_version == request.method_version
    )
    blocked_definition = registration.definition.model_copy(
        update={"lifecycle_status": MethodLifecycleStatus.DRAFT}
    )
    blocked_registration = MethodRegistration(
        definition=blocked_definition,
        implementation=registration.implementation,
        input_normalizers=registration.input_normalizers,
        applicability_evaluators=registration.applicability_evaluators,
        safety_evaluator=registration.safety_evaluator,
    )
    blocked_engine = CalculationEngine(
        registry=CalculationMethodRegistry((blocked_registration,)),
    )
    blocked_result = blocked_engine.execute(
        request,
        evidence=TrustedExecutionEvidence(),
    )
    evidence = TrustedExecutionEvidence(
        references=blocked_definition.references,
        verification_requirements=(
            blocked_definition.verification_requirements
        ),
    )

    fingerprint_basis_json = build_calculation_fingerprint_basis(
        definition=blocked_definition,
        request=request,
        result=blocked_result,
        evidence=evidence,
    )
    basis = json.loads(fingerprint_basis_json)

    assert blocked_result.status.value == "blocked"
    assert basis["fingerprint_schema"].endswith("attempt.v1")
    assert basis["disposition"] == "lifecycle_blocked"
    verify_calculation_result_fingerprint(
        definition=blocked_definition,
        request=request,
        result=blocked_result,
        evidence=evidence,
        fingerprint_basis_json=fingerprint_basis_json,
    )
    payload = CalculationRunPayload(
        request=request,
        method_definition=blocked_definition,
        result=blocked_result,
        execution_fingerprint=blocked_result.result_fingerprint,
        fingerprint_basis_json=fingerprint_basis_json,
    )
    assert payload.fingerprint_basis_json == fingerprint_basis_json


def test_outer_run_fingerprint_detects_actor_timestamp_and_predecessor_tampering() -> None:
    record = _analyzer_run_record(predecessor=True)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["run_fingerprint"] = "f" * 64
    with pytest.raises(ValidationError, match="run_fingerprint is stale"):
        EngineeringRunRecord.model_validate(tampered)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["created_by"] = "Different unverified actor"
    with pytest.raises(ValidationError, match="run_fingerprint is stale"):
        EngineeringRunRecord.model_validate(tampered)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["recorded_at"] = record.recorded_at + timedelta(microseconds=1)
    with pytest.raises(ValidationError, match="run_fingerprint is stale"):
        EngineeringRunRecord.model_validate(tampered)

    tampered = record.model_dump(mode="python", round_trip=True)
    tampered["supersedes_run_fingerprint"] = "f" * 64
    with pytest.raises(ValidationError, match="run_fingerprint is stale"):
        EngineeringRunRecord.model_validate(tampered)


@pytest.mark.parametrize(
    "link_update",
    (
        {"design_case_id": uuid4()},
        {"design_revision_id": uuid4()},
        {"design_revision_number": 1},
        {"design_revision_fingerprint": "a" * 64},
        {"design_case_id": uuid4(), "design_revision_id": uuid4()},
    ),
)
def test_design_run_linkage_is_all_or_none(
    link_update: dict[str, object],
) -> None:
    record = _analyzer_run_record(linked=False)
    invalid = record.model_dump(mode="python", round_trip=True)
    invalid.update(link_update)

    with pytest.raises(
        ValidationError,
        match="design run linkage must be complete or absent",
    ):
        EngineeringRunRecord.model_validate(invalid)


def test_calculation_run_requires_request_and_outer_design_identity_to_match() -> None:
    request_design_id = uuid4()
    definition, request, result, _, fingerprint_basis_json = (
        _calculation_execution(design_case_id=request_design_id)
    )
    payload = CalculationRunPayload(
        request=request,
        method_definition=definition,
        result=result,
        execution_fingerprint=result.result_fingerprint,
        fingerprint_basis_json=fingerprint_basis_json,
    )
    run_id = uuid4()
    outer_design_id = uuid4()
    outer_revision_id = uuid4()
    outer_revision_fingerprint = "c" * 64
    execution_metadata = engineering_execution_metadata(payload)
    input_fingerprint = calculation_input_fingerprint(request)
    run_fingerprint = build_engineering_run_fingerprint(
        run_id=run_id,
        design_case_id=outer_design_id,
        design_revision_id=outer_revision_id,
        design_revision_number=1,
        design_revision_fingerprint=outer_revision_fingerprint,
        supersedes_run_id=None,
        supersedes_run_fingerprint=None,
        payload=payload,
        execution_metadata=execution_metadata,
        input_fingerprint=input_fingerprint,
        result_fingerprint=result.result_fingerprint,
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        recorded_at=FIXED_TIME,
    )

    with pytest.raises(
        ValidationError,
        match="calculation request design_case_id drifted",
    ):
        EngineeringRunRecord(
            run_id=run_id,
            design_case_id=outer_design_id,
            design_revision_id=outer_revision_id,
            design_revision_number=1,
            design_revision_fingerprint=outer_revision_fingerprint,
            payload=payload,
            execution_metadata=execution_metadata,
            input_fingerprint=input_fingerprint,
            result_fingerprint=result.result_fingerprint,
            run_fingerprint=run_fingerprint,
            created_by="Test engineer",
            recorded_at=FIXED_TIME,
        )


def test_analyzer_stateless_envelope_remains_false_inside_persisted_outer_record() -> None:
    envelope = _analyzer_envelope()
    record = _analyzer_run_record()
    persisted = PersistedAnalyzerAssessment(
        assessment=envelope,
        run=record,
    )

    assert persisted.assessment.persistence_performed is False
    assert isinstance(persisted.run.payload, AnalyzerRunPayload)
    assert persisted.run.payload.envelope.persistence_performed is False
    assert persisted.run.persistence_performed is True
    assert persisted.persistence_performed is True
    assert persisted.run.append_only is True
    assert persisted.run.final_design_approval_granted is False


def test_analyzer_payload_rejects_rewritten_inner_persistence_semantics() -> None:
    envelope = _analyzer_envelope()
    forged = envelope.model_dump(mode="python", round_trip=True)
    forged["persistence_performed"] = True

    with pytest.raises(ValidationError):
        AnalyzerAssessmentEnvelope.model_validate(forged)


def test_run_summary_does_not_expose_request_result_or_analyzer_envelope() -> None:
    record = _analyzer_run_record()
    summary = EngineeringRunSummary(
        run_id=record.run_id,
        run_kind=EngineeringRunKind.ANALYZER_ASSESSMENT,
        design_case_id=record.design_case_id,
        design_revision_number=record.design_revision_number,
        design_revision_fingerprint=record.design_revision_fingerprint,
        supersedes_run_id=record.supersedes_run_id,
        supersedes_run_fingerprint=record.supersedes_run_fingerprint,
        calculation_type=record.execution_metadata.calculation_type,
        method_id=record.execution_metadata.method_id,
        method_version=record.execution_metadata.method_version,
        executor_id=record.execution_metadata.executor_id,
        executor_version=record.execution_metadata.executor_version,
        status=record.execution_metadata.status,
        input_fingerprint=record.input_fingerprint,
        result_fingerprint=record.result_fingerprint,
        run_fingerprint=record.run_fingerprint,
        created_by=record.created_by,
        creator_origin=record.creator_origin,
        recorded_at=record.recorded_at,
    )

    body = summary.model_dump(mode="json")
    assert set(body).isdisjoint({"payload", "request", "result", "envelope"})
    serialized = str(body)
    assert "application_notes" not in serialized
    assert "knowledge_links" not in serialized
    assert "scenarios" not in serialized


def test_public_creation_commands_cannot_accept_caller_supplied_results() -> None:
    creation_contracts = (
        DesignCaseCreate,
        DesignCaseRevisionCreate,
        DesignCalculationExecutionCommand,
        DesignAnalyzerAssessmentCommand,
    )
    prohibited_fields = {
        "result",
        "results",
        "assessment",
        "envelope",
        "run",
        "run_fingerprint",
        "result_fingerprint",
    }

    for contract in creation_contracts:
        assert set(contract.model_fields).isdisjoint(prohibited_fields)
        schema = str(contract.model_json_schema())
        assert "CalculationResult" not in schema
        assert "AnalyzerAssessmentEnvelope" not in schema
        assert "EngineeringRunRecord" not in schema

    assert (
        DesignCalculationExecutionCommand.model_fields["calculation"].annotation
        is CalculationRequest
    )
    assert (
        DesignAnalyzerAssessmentCommand.model_fields["request"].annotation
        is AnalyzerApplicationRequest
    )
