"""Focused contract tests for the Step 109 controlled datasheet models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from app.engineering.calculations.level import ENGINEERING_METHOD_REGISTRY
from app.engineering.calculations.method_models import TrustedExecutionEvidence
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    CalculationStatus,
    EngineeringQuantity,
    InputOrigin,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.datasheet_models import (
    MAX_CONDITION_VALUES,
    MAX_DATASHEET_CALCULATION_LINKS,
    MAX_DATASHEET_FIELDS,
    MAX_DATASHEET_REVISIONS,
    MAX_DATASHEET_SECTIONS,
    MAX_DATASHEET_SOURCES,
    DatasheetAssumption,
    DatasheetAssumptionVerificationState,
    DatasheetCalculationLink,
    DatasheetCompletenessReport,
    DatasheetCompletenessState,
    DatasheetConditionOperator,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetFieldAssessment,
    DatasheetFieldCondition,
    DatasheetFieldDefinition,
    DatasheetFieldDisposition,
    DatasheetFieldOrigin,
    DatasheetFieldRequirement,
    DatasheetFieldState,
    DatasheetFieldValue,
    DatasheetHistory,
    DatasheetRevisionCreate,
    DatasheetRevisionRecord,
    DatasheetRevisionSnapshot,
    DatasheetSectionDefinition,
    DatasheetSourceReference,
    DatasheetTemplateDefinition,
    DatasheetValueKind,
    build_datasheet_completeness_fingerprint,
    build_datasheet_revision_fingerprint,
    build_datasheet_template_fingerprint,
    fingerprint_datasheet_content,
)
from app.engineering.design.persistence_models import (
    CalculationRunPayload,
    DesignApprovalState,
    EngineeringRunRecord,
    RecordedIdentityOrigin,
    build_calculation_fingerprint_basis,
    build_engineering_run_fingerprint,
    calculation_input_fingerprint,
    engineering_execution_metadata,
)
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE
from pydantic import ValidationError

FIXED_TIME = datetime(2026, 8, 2, 8, 30, 0, 123456, tzinfo=UTC)
DATASHEET_ID = UUID("10000000-0000-4000-8000-000000000001")
DESIGN_CASE_ID = UUID("20000000-0000-4000-8000-000000000002")
DESIGN_REVISION_ID = UUID("30000000-0000-4000-8000-000000000003")
SECOND_DESIGN_REVISION_ID = UUID("30000000-0000-4000-8000-000000000004")
FIRST_DATASHEET_REVISION_ID = UUID("40000000-0000-4000-8000-000000000005")
SECOND_DATASHEET_REVISION_ID = UUID("40000000-0000-4000-8000-000000000006")
DESIGN_FINGERPRINT = "d" * 64
SECOND_DESIGN_FINGERPRINT = "e" * 64


def _section(
    section_id: str = "general",
    *,
    title: str = "General",
) -> DatasheetSectionDefinition:
    return DatasheetSectionDefinition(section_id=section_id, title=title)


def _field(
    field_id: str = "tag-number",
    *,
    section_id: str = "general",
    value_kind: DatasheetValueKind = DatasheetValueKind.IDENTIFIER,
    requirement: DatasheetFieldRequirement = DatasheetFieldRequirement.REQUIRED,
    condition: DatasheetFieldCondition | None = None,
    preferred_unit: str | None = None,
    quantity_kind: str | None = None,
    allowed_values: tuple[str, ...] = (),
    safety_critical: bool = False,
    allowed_origins: tuple[DatasheetFieldOrigin, ...] | None = None,
    required_boolean_value: bool | None = None,
    positive_value_required: bool = False,
) -> DatasheetFieldDefinition:
    values: dict[str, object] = {
        "field_id": field_id,
        "section_id": section_id,
        "label": field_id.replace("-", " ").title(),
        "description": f"Controlled definition for {field_id}.",
        "value_kind": value_kind,
        "requirement": requirement,
        "condition": condition,
        "preferred_unit": preferred_unit,
        "quantity_kind": quantity_kind,
        "allowed_values": allowed_values,
        "safety_critical": safety_critical,
        "required_boolean_value": required_boolean_value,
        "positive_value_required": positive_value_required,
    }
    if allowed_origins is not None:
        values["allowed_origins"] = allowed_origins
    return DatasheetFieldDefinition.model_validate(values)


def _template(
    *,
    sections: tuple[DatasheetSectionDefinition, ...] | None = None,
    fields: tuple[DatasheetFieldDefinition, ...] | None = None,
    title: str = "Pressure transmitter datasheet",
) -> DatasheetTemplateDefinition:
    return DatasheetTemplateDefinition.create(
        template_id="pressure-transmitter",
        template_version="1.0.0",
        title=title,
        discipline="instrumentation",
        sections=sections or (_section(),),
        fields=fields or (_field(),),
    )


def _source(
    source_id: str = "source-user",
    *,
    origin: DatasheetFieldOrigin = DatasheetFieldOrigin.USER_SUPPLIED,
    reference_ids: tuple[str, ...] = ("record-001",),
    location: str | None = None,
) -> DatasheetSourceReference:
    return DatasheetSourceReference(
        source_id=source_id,
        origin=origin,
        description=f"Trace for {source_id}.",
        reference_ids=reference_ids,
        location=location,
    )


def _assumption(
    assumption_id: str = "assumption-default",
    *,
    source_reference_ids: tuple[str, ...] = ("source-default",),
    verification_state: DatasheetAssumptionVerificationState = (
        DatasheetAssumptionVerificationState.UNRESOLVED
    ),
    verification_evidence_source_ids: tuple[str, ...] = (),
    safety_critical: bool = False,
) -> DatasheetAssumption:
    return DatasheetAssumption(
        assumption_id=assumption_id,
        statement="A provisional value is used until verified.",
        required_verification="Confirm the value against the design basis.",
        source_reference_ids=source_reference_ids,
        verification_state=verification_state,
        verification_evidence_source_ids=verification_evidence_source_ids,
        safety_critical=safety_critical,
    )


def _known_field(
    field_id: str = "tag-number",
    *,
    origin: DatasheetFieldOrigin = DatasheetFieldOrigin.USER_SUPPLIED,
    value: object = "PT-101",
    source_reference_ids: tuple[str, ...] = ("source-user",),
    assumption_ids: tuple[str, ...] = (),
    calculation_link_ids: tuple[str, ...] = (),
) -> DatasheetFieldValue:
    return DatasheetFieldValue(
        field_id=field_id,
        state=DatasheetFieldState.KNOWN,
        origin=origin,
        value=value,
        source_reference_ids=source_reference_ids,
        assumption_ids=assumption_ids,
        calculation_link_ids=calculation_link_ids,
    )


def _unknown_field(
    field_id: str = "tag-number",
    *,
    state: DatasheetFieldState = DatasheetFieldState.UNKNOWN,
) -> DatasheetFieldValue:
    return DatasheetFieldValue(
        field_id=field_id,
        state=state,
        origin=DatasheetFieldOrigin.UNKNOWN,
        unknown_reason="Value has not yet been confirmed.",
    )


def _calculation_run(
    *,
    design_case_id: UUID = DESIGN_CASE_ID,
    design_revision_id: UUID = DESIGN_REVISION_ID,
    design_revision_number: int = 1,
    design_revision_fingerprint: str = DESIGN_FINGERPRINT,
    complete: bool = True,
) -> EngineeringRunRecord:
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        "level.hydrostatic.column-pressure",
        "1.0.0",
    )
    specifications = {item.input_id: item for item in definition.input_specifications}
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
        inputs=(
            tuple(
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
            )
            if complete
            else ()
        ),
    )
    result = DEFAULT_CALCULATION_SERVICE.execute(request)
    evidence = TrustedExecutionEvidence(
        references=definition.references,
        verification_requirements=definition.verification_requirements,
    )
    basis = build_calculation_fingerprint_basis(
        definition=definition,
        request=request,
        result=result,
        evidence=evidence,
    )
    payload = CalculationRunPayload(
        request=request,
        method_definition=definition,
        result=result,
        execution_fingerprint=result.result_fingerprint,
        fingerprint_basis_json=basis,
    )
    run_id = UUID("50000000-0000-4000-8000-000000000007")
    metadata = engineering_execution_metadata(payload)
    input_fingerprint = calculation_input_fingerprint(request)
    run_fingerprint = build_engineering_run_fingerprint(
        run_id=run_id,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
        supersedes_run_id=None,
        supersedes_run_fingerprint=None,
        payload=payload,
        execution_metadata=metadata,
        input_fingerprint=input_fingerprint,
        result_fingerprint=result.result_fingerprint,
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        recorded_at=FIXED_TIME,
    )
    return EngineeringRunRecord(
        run_id=run_id,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
        payload=payload,
        execution_metadata=metadata,
        input_fingerprint=input_fingerprint,
        result_fingerprint=result.result_fingerprint,
        run_fingerprint=run_fingerprint,
        created_by="Test engineer",
        recorded_at=FIXED_TIME,
    )


def _calculation_link(
    *,
    link_id: str = "link-pressure",
    design_case_id: UUID = DESIGN_CASE_ID,
    design_revision_id: UUID = DESIGN_REVISION_ID,
    design_revision_number: int = 1,
    design_revision_fingerprint: str = DESIGN_FINGERPRINT,
    result_status: CalculationStatus = CalculationStatus.COMPLETED,
) -> DatasheetCalculationLink:
    if result_status not in {
        CalculationStatus.COMPLETED,
        CalculationStatus.COMPLETED_WITH_WARNINGS,
    }:
        rejected_run = _calculation_run(
            design_case_id=design_case_id,
            design_revision_id=design_revision_id,
            design_revision_number=design_revision_number,
            design_revision_fingerprint=design_revision_fingerprint,
            complete=False,
        )
        return DatasheetCalculationLink.from_engineering_run(
            link_id=link_id,
            run=rejected_run,
            output_id="differential-pressure",
        )
    run = _calculation_run(
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
    )
    link = DatasheetCalculationLink.from_engineering_run(
        link_id=link_id,
        run=run,
        output_id=run.payload.result.outputs[0].output_id,
    )
    return link


def _content(
    *,
    template: DatasheetTemplateDefinition | None = None,
    datasheet_id: UUID = DATASHEET_ID,
    design_case_id: UUID = DESIGN_CASE_ID,
    design_revision_id: UUID = DESIGN_REVISION_ID,
    design_revision_number: int = 1,
    design_revision_fingerprint: str = DESIGN_FINGERPRINT,
    title: str = "PT-101 controlled datasheet",
    field_values: tuple[DatasheetFieldValue, ...] | None = None,
    source_references: tuple[DatasheetSourceReference, ...] | None = None,
    assumptions: tuple[DatasheetAssumption, ...] = (),
    calculation_links: tuple[DatasheetCalculationLink, ...] = (),
) -> DatasheetContent:
    resolved_template = template or _template()
    return DatasheetContent(
        datasheet_id=datasheet_id,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=design_revision_number,
        design_revision_fingerprint=design_revision_fingerprint,
        template_id=resolved_template.template_id,
        template_version=resolved_template.template_version,
        template_fingerprint=resolved_template.template_fingerprint,
        title=title,
        field_values=((_known_field(),) if field_values is None else field_values),
        source_references=(
            (_source(),) if source_references is None else source_references
        ),
        assumptions=assumptions,
        calculation_links=calculation_links,
    )


def _assessment(
    field_id: str = "tag-number",
    *,
    requirement: DatasheetFieldRequirement = DatasheetFieldRequirement.REQUIRED,
    required_now: bool | None = True,
    disposition: DatasheetFieldDisposition = DatasheetFieldDisposition.SATISFIED,
    blocking: bool = False,
    message: str = "Required field is known and traceable.",
) -> DatasheetFieldAssessment:
    return DatasheetFieldAssessment(
        field_id=field_id,
        requirement=requirement,
        required_now=required_now,
        disposition=disposition,
        blocking=blocking,
        message=message,
    )


def _report(
    content: DatasheetContent,
    *,
    assessments: tuple[DatasheetFieldAssessment, ...] | None = None,
    unresolved_assumption_ids: tuple[str, ...] = (),
    blocking_assumption_ids: tuple[str, ...] = (),
    unverified_calculation_field_ids: tuple[str, ...] = (),
) -> DatasheetCompletenessReport:
    resolved_assessments = (_assessment(),) if assessments is None else assessments
    missing = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition is DatasheetFieldDisposition.REQUIRED_MISSING
    )
    unknown = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition is DatasheetFieldDisposition.REQUIRED_UNKNOWN
    )
    unconfirmed = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition is DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
    )
    unresolved = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition is DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED
    )
    optional = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition
        in {
            DatasheetFieldDisposition.OPTIONAL_MISSING,
            DatasheetFieldDisposition.OPTIONAL_UNKNOWN,
            DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED,
        }
    )
    not_applicable = tuple(
        item.field_id
        for item in resolved_assessments
        if item.disposition is DatasheetFieldDisposition.CONDITIONAL_NOT_APPLICABLE
    )
    blockers = (
        any(item.blocking for item in resolved_assessments)
        or bool(blocking_assumption_ids)
        or bool(unverified_calculation_field_ids)
    )
    incomplete = bool(missing or unknown or unconfirmed or unresolved)
    open_items = bool(optional or unresolved_assumption_ids)
    state = (
        DatasheetCompletenessState.BLOCKED
        if blockers
        else DatasheetCompletenessState.INCOMPLETE
        if incomplete
        else DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS
        if open_items
        else DatasheetCompletenessState.COMPLETE
    )
    ready_for_review = state in {
        DatasheetCompletenessState.COMPLETE,
        DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS,
    }
    content_fingerprint = fingerprint_datasheet_content(content)
    fingerprint = build_datasheet_completeness_fingerprint(
        template_id=content.template_id,
        template_version=content.template_version,
        template_fingerprint=content.template_fingerprint,
        content_fingerprint=content_fingerprint,
        state=state,
        assessments=resolved_assessments,
        missing_required_field_ids=missing,
        unknown_required_field_ids=unknown,
        unconfirmed_required_field_ids=unconfirmed,
        unverified_calculation_field_ids=unverified_calculation_field_ids,
        unresolved_conditional_field_ids=unresolved,
        optional_open_field_ids=optional,
        not_applicable_field_ids=not_applicable,
        unresolved_assumption_ids=unresolved_assumption_ids,
        blocking_assumption_ids=blocking_assumption_ids,
        ready_for_review=ready_for_review,
    )
    return DatasheetCompletenessReport(
        template_id=content.template_id,
        template_version=content.template_version,
        template_fingerprint=content.template_fingerprint,
        content_fingerprint=content_fingerprint,
        completeness_fingerprint=fingerprint,
        state=state,
        assessments=resolved_assessments,
        missing_required_field_ids=missing,
        unknown_required_field_ids=unknown,
        unconfirmed_required_field_ids=unconfirmed,
        unverified_calculation_field_ids=unverified_calculation_field_ids,
        unresolved_conditional_field_ids=unresolved,
        optional_open_field_ids=optional,
        not_applicable_field_ids=not_applicable,
        unresolved_assumption_ids=unresolved_assumption_ids,
        blocking_assumption_ids=blocking_assumption_ids,
        ready_for_review=ready_for_review,
    )


def _snapshot(
    content: DatasheetContent | None = None,
) -> DatasheetRevisionSnapshot:
    resolved_content = content or _content()
    return DatasheetRevisionSnapshot(
        template=_template(),
        content=resolved_content,
        completeness=_report(resolved_content),
    )


def _revision(
    *,
    revision_id: UUID = FIRST_DATASHEET_REVISION_ID,
    revision_number: int = 1,
    predecessor: DatasheetRevisionRecord | None = None,
    content: DatasheetContent | None = None,
    created_at: datetime = FIXED_TIME,
) -> DatasheetRevisionRecord:
    return DatasheetRevisionRecord.create(
        revision_id=revision_id,
        datasheet_id=(content or _content()).datasheet_id,
        revision_number=revision_number,
        supersedes_revision_id=(
            predecessor.revision_id if predecessor is not None else None
        ),
        supersedes_revision_fingerprint=(
            predecessor.revision_fingerprint if predecessor is not None else None
        ),
        snapshot=_snapshot(content),
        change_reason="Create or replace the complete datasheet snapshot.",
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        created_at=created_at,
    )


def _two_revision_history() -> DatasheetHistory:
    first = _revision()
    second_content = _content(
        design_revision_id=SECOND_DESIGN_REVISION_ID,
        design_revision_number=2,
        design_revision_fingerprint=SECOND_DESIGN_FINGERPRINT,
        title="PT-101 controlled datasheet, revision two",
    )
    second = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=2,
        predecessor=first,
        content=second_content,
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    return DatasheetHistory(
        datasheet_id=DATASHEET_ID,
        design_case_id=DESIGN_CASE_ID,
        template_id=second_content.template_id,
        template_version=second_content.template_version,
        template_fingerprint=second_content.template_fingerprint,
        current_revision=2,
        current_revision_fingerprint=second.revision_fingerprint,
        revisions=(first, second),
    )


def test_models_are_frozen_extra_forbid_and_revalidate_copies() -> None:
    source = _source()

    with pytest.raises(ValidationError, match="frozen"):
        source.source_id = "changed"  # type: ignore[misc]

    payload = source.model_dump(mode="python", round_trip=True)
    payload["forged_approval"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DatasheetSourceReference.model_validate(payload)

    with pytest.raises(ValidationError):
        source.model_copy(update={"origin": DatasheetFieldOrigin.UNKNOWN})


def test_ordered_collections_are_required_and_canonicalized() -> None:
    source = _source(reference_ids=("record-z", "Record-A"))
    assert source.reference_ids == ("Record-A", "record-z")

    with pytest.raises(ValidationError, match="ordered list or tuple"):
        DatasheetSourceReference(
            source_id="source-user",
            origin=DatasheetFieldOrigin.USER_SUPPLIED,
            description="Unordered references are not reproducible.",
            reference_ids={"record-a", "record-b"},  # type: ignore[arg-type]
        )

    with pytest.raises(ValidationError, match="reference_ids values must be unique"):
        _source(reference_ids=("Record-A", "record-a"))


def test_strict_booleans_and_revision_integers_reject_coercion() -> None:
    field_payload = _field().model_dump(mode="python", round_trip=True)
    field_payload["safety_critical"] = 1
    with pytest.raises(ValidationError):
        DatasheetFieldDefinition.model_validate(field_payload)

    for invalid_revision in (True, 1.0, "1"):
        with pytest.raises(ValidationError):
            DatasheetRevisionCreate(
                expected_current_revision=invalid_revision,  # type: ignore[arg-type]
                expected_current_fingerprint="a" * 64,
                content=_content(),
                change_reason="Reject a coerced concurrency token.",
                created_by="Test engineer",
            )


@pytest.mark.parametrize("invalid_number", (float("nan"), float("inf"), -float("inf")))
def test_non_finite_scalars_are_rejected_everywhere(invalid_number: float) -> None:
    with pytest.raises(ValidationError):
        DatasheetFieldCondition(
            depends_on_field_id="numeric-driver",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=(invalid_number,),
        )

    with pytest.raises(ValidationError):
        _known_field(value=invalid_number)

    with pytest.raises(ValidationError):
        EngineeringQuantity(
            quantity_kind="pressure",
            value=invalid_number,
            unit="Pa",
        )


def test_bool_cannot_impersonate_a_number_condition_or_quantity() -> None:
    numeric_driver = _field(
        "numeric-driver",
        value_kind=DatasheetValueKind.NUMBER,
    )
    bool_condition = DatasheetFieldCondition(
        depends_on_field_id="numeric-driver",
        operator=DatasheetConditionOperator.EQUALS,
        expected_values=(True,),
    )
    dependent = _field(
        "dependent-field",
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=bool_condition,
    )

    with pytest.raises(ValidationError, match="condition values do not match"):
        _template(fields=(numeric_driver, dependent))

    with pytest.raises(ValidationError):
        EngineeringQuantity(
            quantity_kind="pressure",
            value=True,  # type: ignore[arg-type]
            unit="Pa",
        )


@pytest.mark.parametrize(
    "oversized_value",
    (
        1.0e301,
        10**400,
        "x" * 4_001,
    ),
)
def test_datasheet_scalar_values_are_bounded(oversized_value: object) -> None:
    with pytest.raises(ValidationError):
        _known_field(value=oversized_value)


def test_collection_and_reason_bounds_fail_closed() -> None:
    with pytest.raises(ValidationError):
        DatasheetFieldCondition(
            depends_on_field_id="driver-field",
            operator=DatasheetConditionOperator.IN,
            expected_values=tuple(range(MAX_CONDITION_VALUES + 1)),
        )

    with pytest.raises(ValidationError):
        DatasheetTemplateDefinition.create(
            template_id="oversized-template",
            template_version="1.0.0",
            title="Oversized template",
            discipline="instrumentation",
            sections=tuple(
                _section(f"section-{index}")
                for index in range(MAX_DATASHEET_SECTIONS + 1)
            ),
            fields=(_field(),),
        )

    field = _unknown_field()
    content_payload = _content(field_values=(), source_references=()).model_dump(
        mode="python",
        round_trip=True,
    )
    content_payload["field_values"] = tuple(
        field.model_copy(update={"field_id": f"field-{index}"})
        for index in range(MAX_DATASHEET_FIELDS + 1)
    )
    with pytest.raises(ValidationError):
        DatasheetContent.model_validate(content_payload)

    with pytest.raises(ValidationError):
        DatasheetFieldValue(
            field_id="unknown-field",
            state=DatasheetFieldState.UNKNOWN,
            origin=DatasheetFieldOrigin.UNKNOWN,
            unknown_reason="x" * 1_001,
        )


@pytest.mark.parametrize(
    ("origin", "source_id", "assumption_ids"),
    (
        (DatasheetFieldOrigin.USER_SUPPLIED, "source-user", ()),
        (DatasheetFieldOrigin.DOCUMENT_EXTRACTED, "source-document", ()),
        (DatasheetFieldOrigin.SELECTED, "source-selected", ()),
        (DatasheetFieldOrigin.DEFAULTED, "source-default", ("assumption-default",)),
    ),
)
def test_known_noncalculated_origin_matrix_is_traceable(
    origin: DatasheetFieldOrigin,
    source_id: str,
    assumption_ids: tuple[str, ...],
) -> None:
    source = _source(source_id, origin=origin)
    assumptions = (
        (_assumption(source_reference_ids=(source_id,)),) if assumption_ids else ()
    )
    field = _known_field(
        origin=origin,
        source_reference_ids=(source_id,),
        assumption_ids=assumption_ids,
    )

    content = _content(
        field_values=(field,),
        source_references=(source,),
        assumptions=assumptions,
    )

    assert content.field_values[0].origin is origin


@pytest.mark.parametrize(
    "update",
    (
        {"value": None},
        {"origin": DatasheetFieldOrigin.UNKNOWN},
        {"unknown_reason": "Contradictory reason."},
        {"source_reference_ids": ()},
        {"calculation_link_ids": ("link-pressure",)},
        {
            "origin": DatasheetFieldOrigin.DEFAULTED,
            "source_reference_ids": ("source-default",),
        },
        {"assumption_ids": ("assumption-default",)},
        {
            "origin": DatasheetFieldOrigin.CALCULATED,
            "calculation_link_ids": ("link-pressure",),
        },
    ),
)
def test_known_field_rejects_incoherent_origin_trace_matrix(
    update: dict[str, object],
) -> None:
    payload = _known_field().model_dump(mode="python", round_trip=True)
    payload.update(update)

    with pytest.raises(ValidationError):
        DatasheetFieldValue.model_validate(payload)


@pytest.mark.parametrize(
    "update",
    (
        {"origin": DatasheetFieldOrigin.USER_SUPPLIED},
        {"value": "invented"},
        {"unknown_reason": None},
        {"calculation_link_ids": ("link-pressure",)},
    ),
)
def test_unknown_field_rejects_hidden_value_or_false_trace(
    update: dict[str, object],
) -> None:
    payload = _unknown_field().model_dump(mode="python", round_trip=True)
    payload.update(update)

    with pytest.raises(ValidationError):
        DatasheetFieldValue.model_validate(payload)


def test_not_applicable_field_is_explicit_and_cannot_use_assumptions() -> None:
    field = _unknown_field(state=DatasheetFieldState.NOT_APPLICABLE)
    assert field.value is None
    assert field.origin is DatasheetFieldOrigin.UNKNOWN

    payload = field.model_dump(mode="python", round_trip=True)
    payload["assumption_ids"] = ("assumption-default",)
    with pytest.raises(ValidationError, match="inapplicable fields"):
        DatasheetFieldValue.model_validate(payload)


def test_source_reference_contract_and_canonical_identity() -> None:
    for invalid_origin in (
        DatasheetFieldOrigin.UNKNOWN,
        DatasheetFieldOrigin.CALCULATED,
    ):
        with pytest.raises(ValidationError, match="dedicated trace"):
            _source(origin=invalid_origin)

    with pytest.raises(ValidationError, match="requires a reference ID or location"):
        _source(reference_ids=(), location=None)

    located = _source(reference_ids=(), location="Document 17, page 4")
    assert located.location == "Document 17, page 4"


def test_assumption_verification_evidence_matrix() -> None:
    unresolved = _assumption()
    assert (
        unresolved.verification_state is DatasheetAssumptionVerificationState.UNRESOLVED
    )

    with pytest.raises(ValidationError, match="unresolved assumptions"):
        _assumption(verification_evidence_source_ids=("source-evidence",))

    with pytest.raises(ValidationError, match="verified assumptions require evidence"):
        _assumption(
            verification_state=DatasheetAssumptionVerificationState.VERIFIED,
        )

    verified = _assumption(
        source_reference_ids=("source-default",),
        verification_state=DatasheetAssumptionVerificationState.VERIFIED,
        verification_evidence_source_ids=("source-evidence",),
    )
    assert verified.verification_evidence_source_ids == ("source-evidence",)


def test_content_rejects_source_origin_mismatch() -> None:
    field = _known_field(origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED)

    with pytest.raises(ValidationError, match="origin is not supported"):
        _content(field_values=(field,), source_references=(_source(),))


@pytest.mark.parametrize(
    "invalid_content",
    (
        lambda: _content(
            field_values=(_known_field(source_reference_ids=("missing-source",)),),
        ),
        lambda: _content(
            field_values=(
                _known_field(
                    origin=DatasheetFieldOrigin.DEFAULTED,
                    source_reference_ids=("source-default",),
                    assumption_ids=("missing-assumption",),
                ),
            ),
            source_references=(
                _source("source-default", origin=DatasheetFieldOrigin.DEFAULTED),
            ),
        ),
        lambda: _content(
            assumptions=(_assumption(source_reference_ids=("missing-source",)),),
        ),
    ),
)
def test_content_rejects_dangling_source_and_assumption_links(
    invalid_content,
) -> None:
    with pytest.raises(ValidationError, match="unknown"):
        invalid_content()


def test_content_requires_every_assumption_and_calculation_link_to_be_used() -> None:
    default_source = _source(
        "source-default",
        origin=DatasheetFieldOrigin.DEFAULTED,
    )
    with pytest.raises(ValidationError, match="every assumption"):
        _content(
            source_references=(_source(), default_source),
            assumptions=(_assumption(),),
        )

    with pytest.raises(ValidationError, match="every calculation link"):
        _content(calculation_links=(_calculation_link(),))


def test_template_fingerprint_is_deterministic_and_closed_over_definition() -> None:
    first = _template()
    second = _template()
    changed = _template(title="Changed controlled title")

    assert first.template_fingerprint == second.template_fingerprint
    assert first.template_fingerprint != changed.template_fingerprint
    assert first.template_fingerprint == build_datasheet_template_fingerprint(
        template_id=first.template_id,
        template_version=first.template_version,
        title=first.title,
        discipline=first.discipline,
        sections=first.sections,
        fields=first.fields,
    )

    payload = first.model_dump(mode="python", round_trip=True)
    payload["title"] = "Tampered without re-fingerprinting"
    with pytest.raises(ValidationError, match="template_fingerprint is stale"):
        DatasheetTemplateDefinition.model_validate(payload)


def test_template_rejects_unknown_sections_dependencies_and_self_reference() -> None:
    with pytest.raises(ValidationError, match="unknown section"):
        _template(fields=(_field(section_id="missing-section"),))

    missing_dependency = DatasheetFieldCondition(
        depends_on_field_id="missing-field",
        operator=DatasheetConditionOperator.EQUALS,
        expected_values=(True,),
    )
    with pytest.raises(ValidationError, match="unknown field"):
        _template(
            fields=(
                _field(
                    "dependent-field",
                    requirement=DatasheetFieldRequirement.CONDITIONAL,
                    condition=missing_dependency,
                ),
            ),
        )

    with pytest.raises(ValidationError, match="cannot condition itself"):
        _field(
            "self-dependent",
            requirement=DatasheetFieldRequirement.CONDITIONAL,
            condition=DatasheetFieldCondition(
                depends_on_field_id="SELF-DEPENDENT",
                operator=DatasheetConditionOperator.EQUALS,
                expected_values=(True,),
            ),
        )


def test_template_rejects_condition_cycles_and_wrong_dependency_values() -> None:
    first = _field(
        "field-a",
        value_kind=DatasheetValueKind.TEXT,
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=DatasheetFieldCondition(
            depends_on_field_id="field-b",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=("yes",),
        ),
    )
    second = _field(
        "field-b",
        value_kind=DatasheetValueKind.TEXT,
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=DatasheetFieldCondition(
            depends_on_field_id="field-a",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=("yes",),
        ),
    )
    with pytest.raises(ValidationError, match="must be acyclic"):
        _template(fields=(first, second))

    enum_driver = _field(
        "service-state",
        value_kind=DatasheetValueKind.ENUM,
        allowed_values=("normal", "standby"),
    )
    dependent = _field(
        "standby-detail",
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=DatasheetFieldCondition(
            depends_on_field_id="service-state",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=("shutdown",),
        ),
    )
    with pytest.raises(ValidationError, match="outside the dependency enum"):
        _template(fields=(enum_driver, dependent))


def test_condition_and_field_definition_cardinality_rules() -> None:
    with pytest.raises(ValidationError, match="exactly one expected value"):
        DatasheetFieldCondition(
            depends_on_field_id="driver-field",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=("one", "two"),
        )

    with pytest.raises(ValidationError, match="expected_values must be unique"):
        DatasheetFieldCondition(
            depends_on_field_id="driver-field",
            operator=DatasheetConditionOperator.IN,
            expected_values=("duplicate", "duplicate"),
        )

    with pytest.raises(ValidationError, match="only conditional fields"):
        _field(
            condition=DatasheetFieldCondition(
                depends_on_field_id="driver-field",
                operator=DatasheetConditionOperator.EQUALS,
                expected_values=(True,),
            ),
        )

    with pytest.raises(ValidationError, match="quantity fields require"):
        _field(value_kind=DatasheetValueKind.QUANTITY)

    with pytest.raises(ValidationError, match="enum fields require"):
        _field(
            value_kind=DatasheetValueKind.ENUM,
            allowed_values=("only-choice",),
        )


@pytest.mark.parametrize(
    "values",
    (
        {"allowed_origins": ()},
        {"allowed_origins": (DatasheetFieldOrigin.UNKNOWN,)},
        {
            "value_kind": DatasheetValueKind.TEXT,
            "required_boolean_value": True,
        },
        {
            "value_kind": DatasheetValueKind.BOOLEAN,
            "requirement": DatasheetFieldRequirement.OPTIONAL,
            "required_boolean_value": True,
        },
        {
            "value_kind": DatasheetValueKind.TEXT,
            "positive_value_required": True,
        },
        {
            "value_kind": DatasheetValueKind.NUMBER,
            "allowed_origins": (DatasheetFieldOrigin.CALCULATED,),
        },
        {
            "requirement": DatasheetFieldRequirement.OPTIONAL,
            "safety_critical": True,
        },
    ),
)
def test_field_origin_confirmation_and_positive_metadata_are_fail_closed(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _field(**values)


def test_quantity_fields_can_retain_unverified_calculation_trace() -> None:
    field = _field(
        value_kind=DatasheetValueKind.QUANTITY,
        preferred_unit="Pa",
        quantity_kind="pressure.absolute",
        allowed_origins=(DatasheetFieldOrigin.CALCULATED,),
    )
    assert field.allowed_origins == (DatasheetFieldOrigin.CALCULATED,)


@pytest.mark.parametrize(
    ("preferred_unit", "quantity_kind"),
    (("BOGUS", "pressure.absolute"), ("m", "pressure.absolute")),
)
def test_quantity_definition_rejects_invalid_preferred_unit_metadata(
    preferred_unit: str,
    quantity_kind: str,
) -> None:
    with pytest.raises(ValidationError, match="preferred.?unit"):
        _field(
            value_kind=DatasheetValueKind.QUANTITY,
            preferred_unit=preferred_unit,
            quantity_kind=quantity_kind,
        )


def test_template_rejects_case_insensitive_duplicate_ids() -> None:
    with pytest.raises(ValidationError, match="section IDs must be unique"):
        _template(sections=(_section("General"), _section("general")))

    with pytest.raises(ValidationError, match="field IDs must be unique"):
        _template(fields=(_field("Tag-Number"), _field("tag-number")))


def test_template_rejects_case_drift_in_internal_references() -> None:
    with pytest.raises(ValidationError, match="section ID capitalization drifted"):
        _template(fields=(_field(section_id="General"),))

    driver = _field("Mode-Field", value_kind=DatasheetValueKind.BOOLEAN)
    dependent = _field(
        "dependent-field",
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=DatasheetFieldCondition(
            depends_on_field_id="mode-field",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=(True,),
        ),
    )
    with pytest.raises(ValidationError, match="dependency capitalization drifted"):
        _template(fields=(driver, dependent))

    enum_driver = _field(
        "mode-field",
        value_kind=DatasheetValueKind.ENUM,
        allowed_values=("normal", "shutdown"),
    )
    enum_dependent = _field(
        "dependent-field",
        requirement=DatasheetFieldRequirement.CONDITIONAL,
        condition=DatasheetFieldCondition(
            depends_on_field_id="mode-field",
            operator=DatasheetConditionOperator.EQUALS,
            expected_values=("NORMAL",),
        ),
    )
    with pytest.raises(ValidationError, match="outside the dependency enum"):
        _template(fields=(enum_driver, enum_dependent))


def test_completed_calculation_link_binds_exact_output_and_design_revision() -> None:
    link = _calculation_link()
    calculated = _known_field(
        field_id="calculated-pressure",
        origin=DatasheetFieldOrigin.CALCULATED,
        value=link.output.quantity,
        source_reference_ids=(),
        calculation_link_ids=(link.link_id,),
    )
    content = _content(
        field_values=(calculated,),
        source_references=(),
        calculation_links=(link,),
    )

    assert content.calculation_links[0].output == link.output


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
def test_calculation_link_rejects_noncompleted_results(
    status: CalculationStatus,
) -> None:
    with pytest.raises(ValueError, match="only completed"):
        _calculation_link(result_status=status)


@pytest.mark.parametrize(
    "link_update",
    (
        {"design_case_id": uuid4()},
        {"design_revision_id": uuid4()},
        {"design_revision_number": 2},
        {"design_revision_fingerprint": "f" * 64},
    ),
)
def test_content_rejects_calculation_link_from_another_design_revision(
    link_update: dict[str, object],
) -> None:
    link = _calculation_link(**link_update)
    calculated = _known_field(
        field_id="calculated-pressure",
        origin=DatasheetFieldOrigin.CALCULATED,
        value=link.output.quantity,
        source_reference_ids=(),
        calculation_link_ids=(link.link_id,),
    )

    with pytest.raises(ValidationError, match="another design revision"):
        _content(
            field_values=(calculated,),
            source_references=(),
            calculation_links=(link,),
        )


def test_content_rejects_calculated_value_drift_and_unknown_link() -> None:
    link = _calculation_link()
    drifted = _known_field(
        field_id="calculated-pressure",
        origin=DatasheetFieldOrigin.CALCULATED,
        value=EngineeringQuantity(
            quantity_kind="pressure",
            value=41.0,
            unit="Pa",
        ),
        source_reference_ids=(),
        calculation_link_ids=(link.link_id,),
    )
    with pytest.raises(ValidationError, match="drifted from its output"):
        _content(
            field_values=(drifted,),
            source_references=(),
            calculation_links=(link,),
        )

    missing = drifted.model_copy(
        update={
            "value": link.output.quantity,
            "calculation_link_ids": ("missing-link",),
        }
    )
    with pytest.raises(ValidationError, match="unknown calculation"):
        _content(
            field_values=(missing,),
            source_references=(),
            calculation_links=(link,),
        )


def test_calculation_link_literal_and_fingerprint_boundaries() -> None:
    link = _calculation_link()
    payload = link.model_dump(mode="python", round_trip=True)
    payload["run_fingerprint"] = "not-a-fingerprint"
    with pytest.raises(ValidationError):
        DatasheetCalculationLink.model_validate(payload)

    payload = link.model_dump(mode="python", round_trip=True)
    payload["repository_provenance_verified"] = True
    verified = DatasheetCalculationLink.model_validate(payload)
    assert verified.repository_provenance_verified is True

    payload["repository_provenance_verified"] = "true"
    with pytest.raises(ValidationError):
        DatasheetCalculationLink.model_validate(payload)

    payload = link.model_dump(mode="python", round_trip=True)
    payload["source_record_embedded"] = True
    with pytest.raises(ValidationError):
        DatasheetCalculationLink.model_validate(payload)

    payload = link.model_dump(mode="python", round_trip=True)
    payload["historical_link_rewritten"] = True
    with pytest.raises(ValidationError):
        DatasheetCalculationLink.model_validate(payload)


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    (
        ("method_id", "level.geometry.tank-volume"),
        ("method_version", "9.9.9"),
        ("result_fingerprint", "f" * 64),
        ("design_revision_number", 2),
    ),
)
def test_calculation_link_remains_explicitly_unverified_without_repository(
    field_name: str,
    forged_value: object,
) -> None:
    payload = _calculation_link().model_dump(mode="python", round_trip=True)
    payload[field_name] = forged_value
    reference = DatasheetCalculationLink.model_validate(payload)

    assert reference.repository_provenance_verified is False
    assert reference.source_record_embedded is False


def test_content_canonicalization_makes_fingerprint_order_independent() -> None:
    first_source = _source("source-a")
    second_source = _source(
        "source-b",
        origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
        reference_ids=("document-b",),
    )
    first_field = _known_field(
        "field-a",
        source_reference_ids=("source-a",),
    )
    second_field = _known_field(
        "field-b",
        origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
        value="document-value",
        source_reference_ids=("source-b",),
    )
    first = _content(
        field_values=(second_field, first_field),
        source_references=(second_source, first_source),
    )
    second = _content(
        field_values=(first_field, second_field),
        source_references=(first_source, second_source),
    )

    assert tuple(item.field_id for item in first.field_values) == (
        "field-a",
        "field-b",
    )
    assert fingerprint_datasheet_content(first) == fingerprint_datasheet_content(second)
    assert fingerprint_datasheet_content(first) != fingerprint_datasheet_content(
        first.model_copy(update={"title": "Changed title"})
    )


def test_content_rejects_case_insensitive_duplicate_trace_identities() -> None:
    with pytest.raises(ValidationError, match="field_id values must be unique"):
        _content(
            field_values=(
                _known_field("Tag-Number"),
                _known_field("tag-number"),
            ),
        )

    with pytest.raises(ValidationError, match="source_id values must be unique"):
        _content(
            source_references=(
                _source("Source-User"),
                _source("source-user"),
            ),
        )


def test_completeness_report_derives_lists_state_and_fingerprint() -> None:
    content = _content()
    assessment = _assessment(
        disposition=DatasheetFieldDisposition.REQUIRED_UNKNOWN,
        blocking=True,
        message="Safety-critical required field remains unknown.",
    )
    report = _report(content, assessments=(assessment,))

    assert report.state is DatasheetCompletenessState.BLOCKED
    assert report.unknown_required_field_ids == ("tag-number",)
    assert report.ready_for_review is False
    assert report.approval_state is DesignApprovalState.UNAPPROVED
    assert report.final_design_approval_granted is False


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("missing_required_field_ids", ("tag-number",)),
        ("state", DatasheetCompletenessState.INCOMPLETE),
        ("ready_for_review", False),
        ("completeness_fingerprint", "0" * 64),
    ),
)
def test_completeness_report_rejects_inconsistent_or_stale_derived_state(
    field_name: str,
    replacement: object,
) -> None:
    report = _report(_content())
    payload = report.model_dump(mode="python", round_trip=True)
    payload[field_name] = replacement

    with pytest.raises(ValidationError):
        DatasheetCompletenessReport.model_validate(payload)


def test_completeness_fingerprint_closes_over_assessment_content() -> None:
    content = _content()
    original = _assessment()
    changed = original.model_copy(update={"message": "Changed assessment message."})
    content_fingerprint = fingerprint_datasheet_content(content)

    def fingerprint(assessment: DatasheetFieldAssessment) -> str:
        return build_datasheet_completeness_fingerprint(
            template_id=content.template_id,
            template_version=content.template_version,
            template_fingerprint=content.template_fingerprint,
            content_fingerprint=content_fingerprint,
            state=DatasheetCompletenessState.COMPLETE,
            assessments=(assessment,),
            missing_required_field_ids=(),
            unknown_required_field_ids=(),
            unconfirmed_required_field_ids=(),
            unverified_calculation_field_ids=(),
            unresolved_conditional_field_ids=(),
            optional_open_field_ids=(),
            not_applicable_field_ids=(),
            unresolved_assumption_ids=(),
            blocking_assumption_ids=(),
            ready_for_review=True,
        )

    assert fingerprint(original) != fingerprint(changed)


def test_revision_snapshot_rejects_template_or_content_fingerprint_drift() -> None:
    content = _content()
    report = _report(content)
    payload = report.model_dump(mode="python", round_trip=True)
    payload["content_fingerprint"] = "f" * 64
    payload["completeness_fingerprint"] = build_datasheet_completeness_fingerprint(
        template_id=report.template_id,
        template_version=report.template_version,
        template_fingerprint=report.template_fingerprint,
        content_fingerprint="f" * 64,
        state=report.state,
        assessments=report.assessments,
        missing_required_field_ids=report.missing_required_field_ids,
        unknown_required_field_ids=report.unknown_required_field_ids,
        unconfirmed_required_field_ids=(report.unconfirmed_required_field_ids),
        unverified_calculation_field_ids=(report.unverified_calculation_field_ids),
        unresolved_conditional_field_ids=report.unresolved_conditional_field_ids,
        optional_open_field_ids=report.optional_open_field_ids,
        not_applicable_field_ids=report.not_applicable_field_ids,
        unresolved_assumption_ids=report.unresolved_assumption_ids,
        blocking_assumption_ids=report.blocking_assumption_ids,
        ready_for_review=report.ready_for_review,
    )
    drifted_report = DatasheetCompletenessReport.model_validate(payload)

    with pytest.raises(ValidationError, match="content fingerprint drifted"):
        DatasheetRevisionSnapshot(
            template=_template(),
            content=content,
            completeness=drifted_report,
        )


def test_revision_snapshot_binds_completeness_to_fields_and_assumptions() -> None:
    unknown_content = _content(
        field_values=(_unknown_field(),),
        source_references=(),
    )
    with pytest.raises(ValidationError, match="deterministic template evaluation"):
        DatasheetRevisionSnapshot(
            template=_template(),
            content=unknown_content,
            completeness=_report(unknown_content),
        )

    known_content = _content()
    with pytest.raises(ValidationError, match="at least 1"):
        DatasheetRevisionSnapshot(
            template=_template(),
            content=known_content,
            completeness=_report(known_content, assessments=()),
        )

    default_source = _source(
        "source-default",
        origin=DatasheetFieldOrigin.DEFAULTED,
    )
    assumption = _assumption()
    assumed_content = _content(
        field_values=(
            _known_field(
                origin=DatasheetFieldOrigin.DEFAULTED,
                source_reference_ids=(default_source.source_id,),
                assumption_ids=(assumption.assumption_id,),
            ),
        ),
        source_references=(default_source,),
        assumptions=(assumption,),
    )
    with pytest.raises(ValidationError, match="unresolved assumptions drifted"):
        DatasheetRevisionSnapshot(
            template=_template(),
            content=assumed_content,
            completeness=_report(assumed_content),
        )


def test_revision_snapshot_rejects_fingerprint_consistent_forged_disposition() -> None:
    content = _content(
        field_values=(_unknown_field(),),
        source_references=(),
    )
    forged = _assessment(
        requirement=DatasheetFieldRequirement.REQUIRED,
        required_now=False,
        disposition=DatasheetFieldDisposition.OPTIONAL_UNKNOWN,
        blocking=False,
        message="Caller-forged optional disposition.",
    )
    report = _report(content, assessments=(forged,))
    assert report.ready_for_review is True

    with pytest.raises(ValidationError, match="deterministic template evaluation"):
        DatasheetRevisionSnapshot(
            template=_template(),
            content=content,
            completeness=report,
        )


def test_direct_snapshot_revalidates_template_value_constraints() -> None:
    number_field = _field(
        value_kind=DatasheetValueKind.NUMBER,
        positive_value_required=True,
        allowed_origins=(DatasheetFieldOrigin.USER_SUPPLIED,),
    )
    number_template = _template(fields=(number_field,))
    negative = _content(
        template=number_template,
        field_values=(_known_field(value=-1.0),),
    )
    with pytest.raises(ValidationError, match="must be positive"):
        DatasheetRevisionSnapshot(
            template=number_template,
            content=negative,
            completeness=_report(negative),
        )

    document_source = _source(
        "source-document",
        origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
    )
    user_only_field = _field(
        allowed_origins=(DatasheetFieldOrigin.USER_SUPPLIED,),
    )
    user_only_template = _template(fields=(user_only_field,))
    forbidden = _content(
        template=user_only_template,
        field_values=(
            _known_field(
                origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
                source_reference_ids=(document_source.source_id,),
            ),
        ),
        source_references=(document_source,),
    )
    with pytest.raises(ValidationError, match="origin forbidden"):
        DatasheetRevisionSnapshot(
            template=user_only_template,
            content=forbidden,
            completeness=_report(forbidden),
        )

    enum_field = _field(
        value_kind=DatasheetValueKind.ENUM,
        allowed_values=("first", "second"),
    )
    enum_template = _template(fields=(enum_field,))
    enum_drift = _content(
        template=enum_template,
        field_values=(_known_field(value="third"),),
    )
    with pytest.raises(ValidationError, match="controlled choices"):
        DatasheetRevisionSnapshot(
            template=enum_template,
            content=enum_drift,
            completeness=_report(enum_drift),
        )

    quantity_field = _field(
        value_kind=DatasheetValueKind.QUANTITY,
        preferred_unit="Pa",
        quantity_kind="pressure.absolute",
    )
    quantity_template = _template(fields=(quantity_field,))
    unit_drift = _content(
        template=quantity_template,
        field_values=(
            _known_field(
                value=EngineeringQuantity(
                    quantity_kind="length",
                    value=1.0,
                    unit="m",
                )
            ),
        ),
    )
    with pytest.raises(ValidationError, match="wrong quantity kind"):
        DatasheetRevisionSnapshot(
            template=quantity_template,
            content=unit_drift,
            completeness=_report(unit_drift),
        )


def test_completeness_blockers_must_be_unresolved_assumptions() -> None:
    with pytest.raises(ValidationError, match="must remain unresolved"):
        _report(
            _content(),
            unresolved_assumption_ids=(),
            blocking_assumption_ids=("assumption-closed",),
        )


def test_revision_fingerprint_is_deterministic_and_closed_over_actor_and_time() -> None:
    record = _revision()
    duplicate = _revision()
    assert record.revision_fingerprint == duplicate.revision_fingerprint
    assert record.revision_fingerprint == build_datasheet_revision_fingerprint(
        revision_id=record.revision_id,
        datasheet_id=record.datasheet_id,
        revision_number=record.revision_number,
        supersedes_revision_id=record.supersedes_revision_id,
        supersedes_revision_fingerprint=record.supersedes_revision_fingerprint,
        snapshot=record.snapshot,
        change_reason=record.change_reason,
        created_by=record.created_by,
        creator_origin=record.creator_origin,
        created_at=record.created_at,
    )

    for update in (
        {"created_by": "Different unverified actor"},
        {"change_reason": "Different change reason."},
        {"created_at": record.created_at + timedelta(microseconds=1)},
    ):
        payload = record.model_dump(mode="python", round_trip=True)
        payload.update(update)
        with pytest.raises(ValidationError, match="revision_fingerprint is stale"):
            DatasheetRevisionRecord.model_validate(payload)


def test_revision_timestamp_requires_awareness_and_normalizes_to_utc() -> None:
    local_zone = timezone(timedelta(hours=5, minutes=30))
    local_time = FIXED_TIME.astimezone(local_zone)
    local_record = _revision(created_at=local_time)
    utc_record = _revision(created_at=FIXED_TIME)

    assert local_record.created_at == FIXED_TIME
    assert local_record.created_at.tzinfo is UTC
    assert local_record.revision_fingerprint == utc_record.revision_fingerprint

    with pytest.raises(ValueError, match="timestamps must include a UTC offset"):
        _revision(created_at=FIXED_TIME.replace(tzinfo=None))


def test_revision_predecessor_and_snapshot_identity_are_fail_closed() -> None:
    first = _revision()
    with pytest.raises(ValidationError, match="predecessor linkage must be complete"):
        DatasheetRevisionRecord.create(
            revision_id=SECOND_DATASHEET_REVISION_ID,
            datasheet_id=DATASHEET_ID,
            revision_number=2,
            supersedes_revision_id=first.revision_id,
            supersedes_revision_fingerprint=None,
            snapshot=_snapshot(),
            change_reason="Incomplete predecessor evidence.",
            created_by="Test engineer",
            creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
            created_at=FIXED_TIME,
        )

    with pytest.raises(ValidationError, match="only revision one"):
        DatasheetRevisionRecord.create(
            revision_id=SECOND_DATASHEET_REVISION_ID,
            datasheet_id=DATASHEET_ID,
            revision_number=2,
            supersedes_revision_id=None,
            supersedes_revision_fingerprint=None,
            snapshot=_snapshot(),
            change_reason="Missing predecessor evidence.",
            created_by="Test engineer",
            creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
            created_at=FIXED_TIME,
        )

    with pytest.raises(ValidationError, match="another datasheet"):
        DatasheetRevisionRecord.create(
            revision_id=FIRST_DATASHEET_REVISION_ID,
            datasheet_id=uuid4(),
            revision_number=1,
            supersedes_revision_id=None,
            supersedes_revision_fingerprint=None,
            snapshot=_snapshot(),
            change_reason="Cross-identity snapshot.",
            created_by="Test engineer",
            creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
            created_at=FIXED_TIME,
        )


def test_history_accepts_one_dense_forward_append_chain() -> None:
    history = _two_revision_history()

    assert history.current_revision == 2
    assert (
        history.current_revision_fingerprint
        == history.revisions[-1].revision_fingerprint
    )
    assert (
        history.revisions[1].supersedes_revision_id == history.revisions[0].revision_id
    )
    assert history.append_only is True
    assert history.deletion_supported is False


def test_history_rejects_gap_broken_chain_and_head_drift() -> None:
    first = _revision()
    second_content = _content(
        design_revision_id=SECOND_DESIGN_REVISION_ID,
        design_revision_number=2,
        design_revision_fingerprint=SECOND_DESIGN_FINGERPRINT,
    )
    gap = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=3,
        predecessor=first,
        content=second_content,
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    common = {
        "datasheet_id": DATASHEET_ID,
        "design_case_id": DESIGN_CASE_ID,
        "template_id": second_content.template_id,
        "template_version": second_content.template_version,
        "template_fingerprint": second_content.template_fingerprint,
    }
    with pytest.raises(ValidationError, match="dense and ordered"):
        DatasheetHistory(
            **common,
            current_revision=3,
            current_revision_fingerprint=gap.revision_fingerprint,
            revisions=(first, gap),
        )

    broken = DatasheetRevisionRecord.create(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        datasheet_id=DATASHEET_ID,
        revision_number=2,
        supersedes_revision_id=uuid4(),
        supersedes_revision_fingerprint="f" * 64,
        snapshot=_snapshot(second_content),
        change_reason="Forge another predecessor.",
        created_by="Test engineer",
        creator_origin=RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED,
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError, match="revision chain is broken"):
        DatasheetHistory(
            **common,
            current_revision=2,
            current_revision_fingerprint=broken.revision_fingerprint,
            revisions=(first, broken),
        )

    history = _two_revision_history()
    payload = history.model_dump(mode="python", round_trip=True)
    payload["current_revision_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="current revision fingerprint drifted"):
        DatasheetHistory.model_validate(payload)


def test_history_rejects_backward_design_revision_and_timestamp() -> None:
    first_content = _content(
        design_revision_id=SECOND_DESIGN_REVISION_ID,
        design_revision_number=2,
        design_revision_fingerprint=SECOND_DESIGN_FINGERPRINT,
    )
    first = _revision(content=first_content)
    backward_content = _content(design_revision_number=1)
    backward = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=2,
        predecessor=first,
        content=backward_content,
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError, match="cannot move backwards"):
        DatasheetHistory(
            datasheet_id=DATASHEET_ID,
            design_case_id=DESIGN_CASE_ID,
            template_id=first_content.template_id,
            template_version=first_content.template_version,
            template_fingerprint=first_content.template_fingerprint,
            current_revision=2,
            current_revision_fingerprint=backward.revision_fingerprint,
            revisions=(first, backward),
        )

    first = _revision(created_at=FIXED_TIME + timedelta(minutes=1))
    second = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=2,
        predecessor=first,
        content=_content(
            design_revision_id=SECOND_DESIGN_REVISION_ID,
            design_revision_number=2,
            design_revision_fingerprint=SECOND_DESIGN_FINGERPRINT,
        ),
        created_at=FIXED_TIME,
    )
    with pytest.raises(ValidationError, match="timestamps cannot move backwards"):
        DatasheetHistory(
            datasheet_id=DATASHEET_ID,
            design_case_id=DESIGN_CASE_ID,
            template_id=second.snapshot.content.template_id,
            template_version=second.snapshot.content.template_version,
            template_fingerprint=second.snapshot.content.template_fingerprint,
            current_revision=2,
            current_revision_fingerprint=second.revision_fingerprint,
            revisions=(first, second),
        )


def test_history_rejects_duplicate_revision_identity() -> None:
    first = _revision()
    second_content = _content(design_revision_number=2)
    second = _revision(
        revision_id=first.revision_id,
        revision_number=2,
        predecessor=first,
        content=second_content,
        created_at=FIXED_TIME + timedelta(minutes=1),
    )

    with pytest.raises(ValidationError, match="revision IDs must be unique"):
        DatasheetHistory(
            datasheet_id=DATASHEET_ID,
            design_case_id=DESIGN_CASE_ID,
            template_id=second_content.template_id,
            template_version=second_content.template_version,
            template_fingerprint=second_content.template_fingerprint,
            current_revision=2,
            current_revision_fingerprint=second.revision_fingerprint,
            revisions=(first, second),
        )


def test_history_preserves_exact_design_revision_identity_mapping() -> None:
    first = _revision()
    same_number_different_identity = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=2,
        predecessor=first,
        content=_content(
            design_revision_id=SECOND_DESIGN_REVISION_ID,
            design_revision_number=1,
            design_revision_fingerprint=SECOND_DESIGN_FINGERPRINT,
        ),
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError, match="number changed identity"):
        DatasheetHistory(
            datasheet_id=DATASHEET_ID,
            design_case_id=DESIGN_CASE_ID,
            template_id=first.snapshot.content.template_id,
            template_version=first.snapshot.content.template_version,
            template_fingerprint=first.snapshot.content.template_fingerprint,
            current_revision=2,
            current_revision_fingerprint=(
                same_number_different_identity.revision_fingerprint
            ),
            revisions=(first, same_number_different_identity),
        )

    same_identity_different_number = _revision(
        revision_id=SECOND_DATASHEET_REVISION_ID,
        revision_number=2,
        predecessor=first,
        content=_content(design_revision_number=2),
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError, match="ID was remapped"):
        DatasheetHistory(
            datasheet_id=DATASHEET_ID,
            design_case_id=DESIGN_CASE_ID,
            template_id=first.snapshot.content.template_id,
            template_version=first.snapshot.content.template_version,
            template_fingerprint=first.snapshot.content.template_fingerprint,
            current_revision=2,
            current_revision_fingerprint=(
                same_identity_different_number.revision_fingerprint
            ),
            revisions=(first, same_identity_different_number),
        )


@pytest.mark.parametrize(
    ("factory", "field_name", "forged_value"),
    (
        (_template, "final_design_approval_granted", True),
        (_template, "standards_conformity_claimed", True),
        (_content, "approval_state", "approved"),
        (_content, "final_design_approval_granted", True),
        (_content, "standards_conformity_claimed", True),
        (lambda: _report(_content()), "approval_state", "approved"),
        (lambda: _report(_content()), "final_design_approval_granted", True),
        (_revision, "approval_state", "approved"),
        (_revision, "final_design_approval_granted", True),
        (_two_revision_history, "approval_state", "approved"),
        (_two_revision_history, "final_design_approval_granted", True),
    ),
)
def test_all_datasheet_surfaces_reject_approval_or_conformity_forgery(
    factory,
    field_name: str,
    forged_value: object,
) -> None:
    model = factory()
    payload = model.model_dump(mode="python", round_trip=True)
    payload[field_name] = forged_value

    with pytest.raises(ValidationError):
        type(model).model_validate(payload)


def test_commands_retain_unverified_actor_origin_and_no_result_fields() -> None:
    create = DatasheetCreateCommand(
        content=_content(),
        change_reason="Create controlled datasheet.",
        created_by="Test engineer",
    )
    revise = DatasheetRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint="a" * 64,
        content=_content(),
        change_reason="Replace complete snapshot.",
        created_by="Test engineer",
    )
    assert create.creator_origin is RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    assert revise.creator_origin is RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED

    payload = create.model_dump(mode="python", round_trip=True)
    payload["approval_state"] = "approved"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DatasheetCreateCommand.model_validate(payload)


def test_history_revision_collection_is_bounded() -> None:
    history = _two_revision_history()
    payload = history.model_dump(mode="python", round_trip=True)
    payload["revisions"] = tuple(
        history.revisions[0] for _ in range(MAX_DATASHEET_REVISIONS + 1)
    )

    with pytest.raises(ValidationError):
        DatasheetHistory.model_validate(payload)


def test_source_collection_is_bounded_before_trace_resolution() -> None:
    payload = _content(field_values=(), source_references=()).model_dump(
        mode="python",
        round_trip=True,
    )
    payload["source_references"] = tuple(
        _source(f"source-{index}") for index in range(MAX_DATASHEET_SOURCES + 1)
    )

    with pytest.raises(ValidationError):
        DatasheetContent.model_validate(payload)


def test_calculation_links_are_compact_bounded_unverified_references() -> None:
    link = _calculation_link()
    serialized = link.model_dump_json()
    assert "source_run_record" not in serialized
    assert "fingerprint_basis_json" not in serialized
    assert DatasheetCalculationLink.model_validate_json(serialized) == link

    payload = _content(field_values=(), source_references=()).model_dump(
        mode="python",
        round_trip=True,
    )
    payload["calculation_links"] = tuple(
        link.model_copy(update={"link_id": f"calculation-link-{index}"})
        for index in range(MAX_DATASHEET_CALCULATION_LINKS + 1)
    )
    with pytest.raises(ValidationError):
        DatasheetContent.model_validate(payload)
