"""Step 109 completeness and append-only datasheet service tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from app.engineering.calculations.models import (
    CalculationOutput,
    CalculationStatus,
    EngineeringQuantity,
)
from app.engineering.design.datasheet_models import (
    DatasheetAssumption,
    DatasheetAssumptionVerificationState,
    DatasheetCalculationLink,
    DatasheetCompletenessState,
    DatasheetConditionOperator,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetFieldDefinition,
    DatasheetFieldDisposition,
    DatasheetFieldOrigin,
    DatasheetFieldRequirement,
    DatasheetFieldState,
    DatasheetFieldValue,
    DatasheetHistory,
    DatasheetLifecycleState,
    DatasheetRevisionCreate,
    DatasheetSectionDefinition,
    DatasheetSourceReference,
    DatasheetTemplateDefinition,
    DatasheetValueKind,
)
from app.engineering.design.datasheet_registry import (
    DATASHEET_TEMPLATES,
    DEFAULT_DATASHEET_TEMPLATE_REGISTRY,
    DatasheetTemplateRegistry,
)
from app.engineering.design.datasheet_service import (
    DATASHEET_LIFECYCLE_TRANSITIONS,
    DEFAULT_DATASHEET_SERVICE,
    DatasheetConcurrencyError,
    DatasheetFieldValidationError,
    DatasheetLifecycleError,
    DatasheetService,
    DatasheetTemplateMismatchError,
)
from pydantic import ValidationError

SERVICE = DEFAULT_DATASHEET_SERVICE
SOURCE_ID = "controlled-test-source"
SOURCE = DatasheetSourceReference(
    source_id=SOURCE_ID,
    origin=DatasheetFieldOrigin.USER_SUPPLIED,
    description="Controlled caller-supplied test evidence.",
    reference_ids=("test-reference",),
)
DOCUMENT_SOURCE_ID = "controlled-document-source"
DOCUMENT_SOURCE = DatasheetSourceReference(
    source_id=DOCUMENT_SOURCE_ID,
    origin=DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
    description="Controlled externally documented calculation evidence.",
    reference_ids=("documented-calculation",),
)
SELECTED_SOURCE_ID = "controlled-selection-source"
SELECTED_SOURCE = DatasheetSourceReference(
    source_id=SELECTED_SOURCE_ID,
    origin=DatasheetFieldOrigin.SELECTED,
    description="Controlled selection trace used for rejection tests.",
    reference_ids=("selection-record",),
)
DATASHEET_ID = UUID("10000000-0000-0000-0000-000000000001")
DESIGN_CASE_ID = UUID("20000000-0000-0000-0000-000000000001")
CREATED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
TEMPLATES = {template.template_id: template for template in DATASHEET_TEMPLATES}
PRESSURE_TEMPLATE = TEMPLATES["instrument.pressure-transmitter"]


class _DerivedDatasheetTemplateRegistry(DatasheetTemplateRegistry):
    """A subtype that must not cross the exact dependency boundary."""


def test_service_requires_exact_registry_and_policy_types() -> None:
    """Subclassed registries and truthy policy coercions fail at construction."""

    derived_registry = _DerivedDatasheetTemplateRegistry((PRESSURE_TEMPLATE,))
    for invalid_registry in (object(), derived_registry):
        with pytest.raises(
            TypeError,
            match="registry must be a DatasheetTemplateRegistry",
        ):
            DatasheetService(registry=invalid_registry)  # type: ignore[arg-type]

    for invalid_policy in (None, 0, 1, "false", object()):
        with pytest.raises(
            TypeError,
            match="_allow_repository_provenance must be a boolean",
        ):
            DatasheetService(  # type: ignore[arg-type]
                _allow_repository_provenance=invalid_policy
            )


def test_service_dependencies_are_permanently_immutable() -> None:
    """Shared registry and provenance policy cannot be replaced or deleted."""

    service = DatasheetService()
    original_registry = service.registry
    assert not hasattr(service, "__dict__")

    for attribute, replacement in (
        ("_registry", DatasheetTemplateRegistry((PRESSURE_TEMPLATE,))),
        ("_allow_repository_provenance", True),
        ("_locked", False),
    ):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(service, attribute, replacement)
        with pytest.raises(AttributeError, match="immutable"):
            delattr(service, attribute)

    assert service.registry is original_registry


def test_service_revalidates_constructed_numeric_content_without_overflow() -> None:
    """Bypass-constructed huge numbers fail closed at the service boundary."""

    definition = next(
        item
        for item in PRESSURE_TEMPLATE.fields
        if item.field_id == "required_accuracy_percent"
    )
    valid_value = DatasheetFieldValue(
        field_id=definition.field_id,
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.USER_SUPPLIED,
        value=1.0,
        source_reference_ids=(SOURCE_ID,),
    )
    invalid_value = DatasheetFieldValue.model_construct(
        **(
            valid_value.model_dump(mode="python", round_trip=True)
            | {"value": 10**400}
        )
    )
    base_content = _content()
    invalid_content = DatasheetContent.model_construct(
        **(
            {
                name: getattr(base_content, name)
                for name in type(base_content).model_fields
            }
            | {"field_values": (invalid_value,)}
        )
    )

    with pytest.raises(
        DatasheetFieldValidationError,
        match="controlled model validation",
    ):
        SERVICE.evaluate(invalid_content)


def _definition(
    template: DatasheetTemplateDefinition,
    field_id: str,
) -> DatasheetFieldDefinition:
    return next(field for field in template.fields if field.field_id == field_id)


def _candidate(definition: DatasheetFieldDefinition) -> object:
    if definition.value_kind is DatasheetValueKind.QUANTITY:
        assert definition.quantity_kind is not None
        assert definition.preferred_unit is not None
        return EngineeringQuantity(
            quantity_kind=definition.quantity_kind,
            value=1.0,
            unit=definition.preferred_unit,
        )
    if definition.value_kind is DatasheetValueKind.BOOLEAN:
        return (
            definition.required_boolean_value
            if definition.required_boolean_value is not None
            else False
        )
    if definition.value_kind is DatasheetValueKind.NUMBER:
        return 1.0
    if definition.value_kind is DatasheetValueKind.ENUM:
        return definition.allowed_values[0]
    if definition.value_kind is DatasheetValueKind.IDENTIFIER:
        return f"test-{definition.field_id}"
    return f"Controlled value for {definition.field_id}."


def _known(
    definition: DatasheetFieldDefinition,
    value: object | None = None,
) -> DatasheetFieldValue:
    origin = (
        DatasheetFieldOrigin.USER_SUPPLIED
        if DatasheetFieldOrigin.USER_SUPPLIED in definition.allowed_origins
        else DatasheetFieldOrigin.DOCUMENT_EXTRACTED
    )
    source_id = (
        SOURCE_ID
        if origin is DatasheetFieldOrigin.USER_SUPPLIED
        else DOCUMENT_SOURCE_ID
    )
    return DatasheetFieldValue(
        field_id=definition.field_id,
        state=DatasheetFieldState.KNOWN,
        origin=origin,
        value=_candidate(definition) if value is None else value,
        source_reference_ids=(source_id,),
    )


def _not_applicable(definition: DatasheetFieldDefinition) -> DatasheetFieldValue:
    return DatasheetFieldValue(
        field_id=definition.field_id,
        state=DatasheetFieldState.NOT_APPLICABLE,
        origin=DatasheetFieldOrigin.UNKNOWN,
        unknown_reason="The controlling condition is not active.",
    )


def _calculated(
    definition: DatasheetFieldDefinition,
    value: EngineeringQuantity | bool | str,
    *,
    link_id: str,
) -> tuple[DatasheetFieldValue, DatasheetCalculationLink]:
    output = CalculationOutput(
        output_id=f"output-{link_id}",
        name=f"Output for {definition.field_id}",
        quantity=value if isinstance(value, EngineeringQuantity) else None,
        categorical_value=(value if isinstance(value, (bool, str)) else None),
        source_step_ids=("step-109-test",),
        source_value_ids=("value-109-test",),
    )
    link = DatasheetCalculationLink(
        link_id=link_id,
        run_id=UUID(int=20_000 + len(link_id)),
        run_fingerprint="a" * 64,
        result_fingerprint="b" * 64,
        design_case_id=DESIGN_CASE_ID,
        design_revision_id=UUID(int=10_001),
        design_revision_number=1,
        design_revision_fingerprint=f"{1:064x}",
        calculation_type="step109.test.calculation",
        method_id="step109.test.method",
        method_version="1.0.0",
        result_status=CalculationStatus.COMPLETED,
        output=output,
    )
    field = DatasheetFieldValue(
        field_id=definition.field_id,
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.CALCULATED,
        value=value,
        calculation_link_ids=(link_id,),
    )
    return field, link


def _condition_matches(
    definition: DatasheetFieldDefinition,
    dependency: DatasheetFieldValue,
) -> bool:
    assert definition.condition is not None
    if dependency.state is not DatasheetFieldState.KNOWN:
        return False
    expected = definition.condition.expected_values
    if definition.condition.operator is DatasheetConditionOperator.EQUALS:
        return dependency.value == expected[0]
    if definition.condition.operator is DatasheetConditionOperator.NOT_EQUALS:
        return dependency.value != expected[0]
    return dependency.value in expected


def _minimally_complete_values(
    template: DatasheetTemplateDefinition,
) -> tuple[DatasheetFieldValue, ...]:
    """Supply only fields needed to resolve every mandatory decision."""

    definitions = {field.field_id: field for field in template.fields}
    dependency_ids = {
        field.condition.depends_on_field_id
        for field in template.fields
        if field.condition is not None
    }
    values: dict[str, DatasheetFieldValue] = {}

    def resolve(field_id: str) -> DatasheetFieldValue | None:
        if field_id in values:
            return values[field_id]
        definition = definitions[field_id]
        if definition.requirement is DatasheetFieldRequirement.REQUIRED:
            value = _known(definition)
        elif definition.requirement is DatasheetFieldRequirement.OPTIONAL:
            value = _known(definition) if field_id in dependency_ids else None
        else:
            assert definition.condition is not None
            dependency = resolve(definition.condition.depends_on_field_id)
            if dependency is not None and _condition_matches(
                definition,
                dependency,
            ):
                value = _known(definition)
            elif field_id in dependency_ids:
                value = _not_applicable(definition)
            else:
                value = None
        if value is not None:
            values[field_id] = value
        return value

    for field in template.fields:
        resolve(field.field_id)
    return tuple(values.values())


def _content(
    template: DatasheetTemplateDefinition = PRESSURE_TEMPLATE,
    *,
    field_values: tuple[DatasheetFieldValue, ...] = (),
    assumptions: tuple[DatasheetAssumption, ...] = (),
    calculation_links: tuple[DatasheetCalculationLink, ...] = (),
    source_references: tuple[DatasheetSourceReference, ...] = (
        SOURCE,
        DOCUMENT_SOURCE,
        SELECTED_SOURCE,
    ),
    lifecycle_state: DatasheetLifecycleState = DatasheetLifecycleState.DRAFT,
    datasheet_id: UUID = DATASHEET_ID,
    design_case_id: UUID = DESIGN_CASE_ID,
    design_revision_number: int = 1,
) -> DatasheetContent:
    return DatasheetContent(
        datasheet_id=datasheet_id,
        design_case_id=design_case_id,
        design_revision_id=UUID(int=10_000 + design_revision_number),
        design_revision_number=design_revision_number,
        design_revision_fingerprint=f"{design_revision_number:064x}",
        template_id=template.template_id,
        template_version=template.template_version,
        template_fingerprint=template.template_fingerprint,
        title=f"Test {template.title}",
        lifecycle_state=lifecycle_state,
        field_values=field_values,
        source_references=source_references,
        assumptions=assumptions,
        calculation_links=calculation_links,
    )


def _create_history(
    template: DatasheetTemplateDefinition = PRESSURE_TEMPLATE,
    *,
    lifecycle_state: DatasheetLifecycleState = DatasheetLifecycleState.DRAFT,
) -> DatasheetHistory:
    return SERVICE.create_history(
        DatasheetCreateCommand(
            content=_content(
                template,
                field_values=_minimally_complete_values(template),
                lifecycle_state=lifecycle_state,
            ),
            change_reason="Create controlled datasheet history.",
            created_by="step-109-test",
        ),
        revision_id=UUID("30000000-0000-0000-0000-000000000001"),
        created_at=CREATED_AT,
    )


def _append(
    history: DatasheetHistory,
    *,
    design_revision_number: int,
    revision_id: UUID,
) -> DatasheetHistory:
    template = DEFAULT_DATASHEET_TEMPLATE_REGISTRY.resolve(
        template_id=history.template_id,
        template_version=history.template_version,
    )
    return SERVICE.append_revision(
        history,
        DatasheetRevisionCreate(
            expected_current_revision=history.current_revision,
            expected_current_fingerprint=history.current_revision_fingerprint,
            content=_content(
                template,
                field_values=_minimally_complete_values(template),
                design_revision_number=design_revision_number,
            ),
            change_reason=f"Append design revision {design_revision_number}.",
            created_by="step-109-test",
        ),
        revision_id=revision_id,
        created_at=CREATED_AT + timedelta(minutes=design_revision_number),
    )


@pytest.mark.parametrize(
    "template",
    DATASHEET_TEMPLATES,
    ids=lambda template: template.template_id,
)
def test_sparse_content_materializes_every_template_field_as_visible_unknown(
    template: DatasheetTemplateDefinition,
) -> None:
    normalized = SERVICE.materialize_unknown_fields(_content(template))

    assert tuple(value.field_id for value in normalized.field_values) == tuple(
        sorted((field.field_id for field in template.fields), key=str.casefold)
    )
    assert len(normalized.field_values) == len(template.fields)
    assert all(
        value.state is DatasheetFieldState.UNKNOWN
        and value.origin is DatasheetFieldOrigin.UNKNOWN
        and value.value is None
        and value.unknown_reason == "Not supplied for this datasheet revision."
        for value in normalized.field_values
    )


@pytest.mark.parametrize(
    "template",
    DATASHEET_TEMPLATES,
    ids=lambda template: template.template_id,
)
def test_minimally_complete_vector_is_review_ready_for_every_template(
    template: DatasheetTemplateDefinition,
) -> None:
    supplied = _minimally_complete_values(template)
    snapshot = SERVICE.evaluate(_content(template, field_values=supplied))

    assert len(supplied) < len(template.fields)
    assert snapshot.completeness.ready_for_review is True
    assert snapshot.completeness.state in {
        DatasheetCompletenessState.COMPLETE,
        DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS,
    }
    assert snapshot.completeness.unknown_required_field_ids == ()
    assert snapshot.completeness.unresolved_conditional_field_ids == ()
    assert snapshot.content.approval_state.value == "unapproved"
    assert snapshot.completeness.approval_state.value == "unapproved"
    assert snapshot.content.final_design_approval_granted is False
    assert snapshot.completeness.final_design_approval_granted is False
    assert snapshot.content.standards_conformity_claimed is False
    assert template.final_design_approval_granted is False
    assert template.standards_conformity_claimed is False


def test_required_and_optional_fields_distinguish_known_from_unknown() -> None:
    tag = _definition(PRESSURE_TEMPLATE, "tag_number")
    location = _definition(PRESSURE_TEMPLATE, "location")

    sparse = SERVICE.evaluate(_content())
    sparse_assessments = {
        item.field_id: item for item in sparse.completeness.assessments
    }
    assert sparse_assessments[tag.field_id].disposition is (
        DatasheetFieldDisposition.REQUIRED_UNKNOWN
    )
    assert sparse_assessments[tag.field_id].required_now is True
    assert sparse_assessments[location.field_id].disposition is (
        DatasheetFieldDisposition.OPTIONAL_UNKNOWN
    )
    assert sparse_assessments[location.field_id].required_now is False

    known = SERVICE.evaluate(_content(field_values=(_known(tag), _known(location))))
    known_assessments = {item.field_id: item for item in known.completeness.assessments}
    assert known_assessments[tag.field_id].disposition is (
        DatasheetFieldDisposition.SATISFIED
    )
    assert known_assessments[location.field_id].disposition is (
        DatasheetFieldDisposition.SATISFIED
    )


def test_conditional_field_distinguishes_true_false_and_unknown_rules() -> None:
    dependency = _definition(PRESSURE_TEMPLATE, "pressure_measurement_type")
    target = _definition(PRESSURE_TEMPLATE, "absolute_lower_range_value")

    active = SERVICE.evaluate(
        _content(
            field_values=(
                _known(dependency, "absolute"),
                _known(target),
            )
        )
    )
    inactive = SERVICE.evaluate(
        _content(
            field_values=(
                _known(dependency, "gauge"),
                _not_applicable(target),
            )
        )
    )
    unresolved = SERVICE.evaluate(_content())
    inactive_known = SERVICE.evaluate(
        _content(
            field_values=(
                _known(dependency, "gauge"),
                _known(target),
            )
        )
    )

    active_assessment = next(
        item
        for item in active.completeness.assessments
        if item.field_id == target.field_id
    )
    inactive_assessment = next(
        item
        for item in inactive.completeness.assessments
        if item.field_id == target.field_id
    )
    unresolved_assessment = next(
        item
        for item in unresolved.completeness.assessments
        if item.field_id == target.field_id
    )
    inactive_known_assessment = next(
        item
        for item in inactive_known.completeness.assessments
        if item.field_id == target.field_id
    )
    assert (
        active_assessment.required_now,
        active_assessment.disposition,
    ) == (True, DatasheetFieldDisposition.SATISFIED)
    assert (
        inactive_assessment.required_now,
        inactive_assessment.disposition,
    ) == (False, DatasheetFieldDisposition.CONDITIONAL_NOT_APPLICABLE)
    assert (
        unresolved_assessment.required_now,
        unresolved_assessment.disposition,
    ) == (None, DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED)
    assert inactive_known_assessment.disposition is (
        DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED
    )


def test_nested_condition_inherits_inactive_parent_without_false_block() -> None:
    analyzer = TEMPLATES["analyzer.process"]
    extractive = _definition(analyzer, "extractive_service")
    snapshot = SERVICE.evaluate(
        _content(
            analyzer,
            field_values=(_known(extractive, False),),
        )
    )
    assessments = {item.field_id: item for item in snapshot.completeness.assessments}

    assert assessments["sample_disposal_route"].required_now is False
    assert assessments["sample_disposal_route"].disposition is (
        DatasheetFieldDisposition.OPTIONAL_UNKNOWN
    )
    assert assessments["sample_disposal_route"].blocking is False


def test_unknown_safety_critical_fields_block_review_readiness() -> None:
    snapshot = SERVICE.evaluate(_content())
    assessments = {item.field_id: item for item in snapshot.completeness.assessments}

    assert snapshot.completeness.state is DatasheetCompletenessState.BLOCKED
    assert snapshot.completeness.ready_for_review is False
    assert assessments["process_medium"].blocking is True
    assert assessments["process_medium"].disposition is (
        DatasheetFieldDisposition.REQUIRED_UNKNOWN
    )
    assert assessments["hazardous_area_classification"].blocking is True
    assert assessments["hazardous_area_classification"].disposition is (
        DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED
    )


def test_required_affirmative_safety_evidence_cannot_claim_completeness() -> None:
    relief = TEMPLATES["valve.pressure-relief"]
    confirmation_ids = {
        "governing_scenario_confirmed",
        "inlet_piping_verified",
        "outlet_piping_verified",
        "competent_review_completed",
    }
    values = {item.field_id: item for item in _minimally_complete_values(relief)}
    for field_id in confirmation_ids:
        values[field_id] = _known(_definition(relief, field_id), False)

    snapshot = SERVICE.evaluate(_content(relief, field_values=tuple(values.values())))

    assert snapshot.completeness.state is DatasheetCompletenessState.BLOCKED
    assert snapshot.completeness.ready_for_review is False
    assert set(snapshot.completeness.unconfirmed_required_field_ids) == (
        confirmation_ids
    )
    assessments = {item.field_id: item for item in snapshot.completeness.assessments}
    assert all(
        assessments[field_id].disposition
        is DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
        and assessments[field_id].blocking
        for field_id in confirmation_ids
    )


@pytest.mark.parametrize(
    ("field_id", "value", "dependency_value", "expected_disposition"),
    (
        (
            "tag_number",
            "calculated-tag",
            None,
            DatasheetFieldDisposition.SATISFIED,
        ),
        (
            "location",
            "Calculated optional location",
            None,
            DatasheetFieldDisposition.SATISFIED,
        ),
        (
            "hazardous_area_classification",
            "Calculated classification",
            True,
            DatasheetFieldDisposition.SATISFIED,
        ),
        (
            "hazardous_area_classification",
            "Calculated inactive classification",
            False,
            DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED,
        ),
    ),
)
def test_every_calculated_field_blocks_until_repository_provenance_exists(
    field_id: str,
    value: str,
    dependency_value: bool | None,
    expected_disposition: DatasheetFieldDisposition,
) -> None:
    definition = _definition(PRESSURE_TEMPLATE, field_id)
    calculated, link = _calculated(
        definition,
        value,
        link_id=f"link-{field_id}",
    )
    values = [calculated]
    if dependency_value is not None:
        dependency = _definition(PRESSURE_TEMPLATE, "hazardous_area")
        values.append(_known(dependency, dependency_value))

    snapshot = SERVICE.evaluate(
        _content(
            field_values=tuple(values),
            calculation_links=(link,),
        )
    )
    assessment = next(
        item for item in snapshot.completeness.assessments if item.field_id == field_id
    )

    assert assessment.disposition is expected_disposition
    assert assessment.blocking is True
    assert snapshot.completeness.unverified_calculation_field_ids == (field_id,)
    assert snapshot.completeness.state is DatasheetCompletenessState.BLOCKED
    assert snapshot.completeness.ready_for_review is False
    assert link.repository_provenance_verified is False
    assert link.source_record_embedded is False


def test_calculated_false_confirmation_is_unconfirmed_and_provenance_blocked() -> None:
    definition = DatasheetFieldDefinition(
        field_id="eligibility-confirmed",
        section_id="review",
        label="Eligibility confirmed",
        description="Affirmative confirmation required for review.",
        value_kind=DatasheetValueKind.BOOLEAN,
        requirement=DatasheetFieldRequirement.REQUIRED,
        required_boolean_value=True,
        safety_critical=True,
        allowed_origins=(DatasheetFieldOrigin.CALCULATED,),
    )
    template = DatasheetTemplateDefinition.create(
        template_id="test.calculated-boolean",
        template_version="1.0.0",
        title="Calculated Boolean Test",
        discipline="test",
        sections=(
            DatasheetSectionDefinition(
                section_id="review",
                title="Review",
            ),
        ),
        fields=(definition,),
    )
    service = DatasheetService(registry=DatasheetTemplateRegistry((template,)))
    calculated, link = _calculated(
        definition,
        False,
        link_id="link-false-confirmation",
    )

    snapshot = service.evaluate(
        _content(
            template,
            field_values=(calculated,),
            calculation_links=(link,),
        )
    )
    assessment = snapshot.completeness.assessments[0]
    assert assessment.disposition is (
        DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
    )
    assert assessment.blocking is True
    assert snapshot.completeness.unconfirmed_required_field_ids == (
        definition.field_id,
    )
    assert snapshot.completeness.unverified_calculation_field_ids == (
        definition.field_id,
    )
    assert snapshot.completeness.state is DatasheetCompletenessState.BLOCKED


def test_active_safety_default_derives_blocker_from_template_not_caller_flag() -> None:
    definition = _definition(PRESSURE_TEMPLATE, "process_medium")
    default_source = DatasheetSourceReference(
        source_id="default-source",
        origin=DatasheetFieldOrigin.DEFAULTED,
        description="Explicit default under verification.",
        reference_ids=("default-record",),
    )
    assumption = DatasheetAssumption(
        assumption_id="default-assumption",
        statement="Temporary process-medium default.",
        required_verification="Verify the actual process medium.",
        source_reference_ids=(default_source.source_id,),
        safety_critical=False,
    )
    values = {
        item.field_id: item for item in _minimally_complete_values(PRESSURE_TEMPLATE)
    }
    values[definition.field_id] = DatasheetFieldValue(
        field_id=definition.field_id,
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.DEFAULTED,
        value="temporary-medium",
        source_reference_ids=(default_source.source_id,),
        assumption_ids=(assumption.assumption_id,),
    )

    blocked = SERVICE.evaluate(
        _content(
            field_values=tuple(values.values()),
            assumptions=(assumption,),
            source_references=(*_content().source_references, default_source),
        )
    )
    assert blocked.completeness.blocking_assumption_ids == (assumption.assumption_id,)
    assert blocked.completeness.state is DatasheetCompletenessState.BLOCKED
    assert blocked.completeness.ready_for_review is False

    verified = DatasheetAssumption(
        assumption_id=assumption.assumption_id,
        statement=assumption.statement,
        required_verification=assumption.required_verification,
        source_reference_ids=assumption.source_reference_ids,
        verification_state=DatasheetAssumptionVerificationState.VERIFIED,
        verification_evidence_source_ids=(default_source.source_id,),
        safety_critical=False,
    )
    ready = SERVICE.evaluate(
        _content(
            field_values=tuple(values.values()),
            assumptions=(verified,),
            source_references=(*_content().source_references, default_source),
        )
    )
    assert ready.completeness.blocking_assumption_ids == ()
    assert ready.completeness.ready_for_review is True


def test_inactive_safety_default_is_open_but_not_promoted_to_blocker() -> None:
    target = _definition(PRESSURE_TEMPLATE, "hazardous_area_classification")
    dependency = _definition(PRESSURE_TEMPLATE, "hazardous_area")
    default_source = DatasheetSourceReference(
        source_id="inactive-default-source",
        origin=DatasheetFieldOrigin.DEFAULTED,
        description="Inactive conditional default evidence.",
        reference_ids=("inactive-default",),
    )
    assumption = DatasheetAssumption(
        assumption_id="inactive-default-assumption",
        statement="Default retained only while the condition is inactive.",
        required_verification="Verify if the condition becomes active.",
        source_reference_ids=(default_source.source_id,),
        safety_critical=False,
    )
    values = {
        item.field_id: item for item in _minimally_complete_values(PRESSURE_TEMPLATE)
    }
    values[dependency.field_id] = _known(dependency, False)
    values[target.field_id] = DatasheetFieldValue(
        field_id=target.field_id,
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.DEFAULTED,
        value="inactive-default",
        source_reference_ids=(default_source.source_id,),
        assumption_ids=(assumption.assumption_id,),
    )

    snapshot = SERVICE.evaluate(
        _content(
            field_values=tuple(values.values()),
            assumptions=(assumption,),
            source_references=(*_content().source_references, default_source),
        )
    )
    assert snapshot.completeness.blocking_assumption_ids == ()
    assert snapshot.completeness.ready_for_review is True


def test_sizing_result_fields_reject_uncontrolled_selected_origin() -> None:
    valve = TEMPLATES["valve.control"]
    coefficient = _definition(valve, "required_flow_coefficient")
    assert DatasheetFieldOrigin.SELECTED not in coefficient.allowed_origins

    with pytest.raises(DatasheetFieldValidationError, match="origin forbidden"):
        SERVICE.evaluate(
            _content(
                valve,
                field_values=(
                    DatasheetFieldValue(
                        field_id=coefficient.field_id,
                        state=DatasheetFieldState.KNOWN,
                        origin=DatasheetFieldOrigin.SELECTED,
                        value=1.0,
                        source_reference_ids=(SELECTED_SOURCE_ID,),
                    ),
                ),
            )
        )

    with pytest.raises(DatasheetFieldValidationError, match="must be positive"):
        SERVICE.evaluate(
            _content(
                valve,
                field_values=(_known(coefficient, -1.0),),
            )
        )


@pytest.mark.parametrize("steam_state", ("dry_saturated", "superheated"))
def test_control_valve_accepts_only_verified_steam_state_choices(
    steam_state: str,
) -> None:
    valve = TEMPLATES["valve.control"]
    fields = {item.field_id: item for item in valve.fields}
    values = {item.field_id: item for item in _minimally_complete_values(valve)}
    values["fluid_phase"] = _known(fields["fluid_phase"], "steam")
    values["steam_state_basis"] = _known(
        fields["steam_state_basis"],
        steam_state,
    )
    values["steam_eligibility_confirmed"] = _known(
        fields["steam_eligibility_confirmed"],
        True,
    )

    ready = SERVICE.evaluate(_content(valve, field_values=tuple(values.values())))
    assert ready.completeness.ready_for_review is True

    values["steam_eligibility_confirmed"] = _known(
        fields["steam_eligibility_confirmed"],
        False,
    )
    blocked = SERVICE.evaluate(_content(valve, field_values=tuple(values.values())))
    assert blocked.completeness.ready_for_review is False
    assert "steam_eligibility_confirmed" in (
        blocked.completeness.unconfirmed_required_field_ids
    )

    with pytest.raises(DatasheetFieldValidationError, match="controlled choices"):
        SERVICE.evaluate(
            _content(
                valve,
                field_values=(
                    _known(fields["fluid_phase"], "steam"),
                    _known(fields["steam_state_basis"], "other_unverified"),
                ),
            )
        )


@pytest.mark.parametrize(
    ("field_id", "candidate", "message"),
    (
        (
            "minimum_process_pressure",
            EngineeringQuantity(quantity_kind="length", value=1.0, unit="m"),
            "wrong quantity kind",
        ),
        (
            "minimum_process_pressure",
            EngineeringQuantity(
                quantity_kind="pressure.absolute",
                value=1.0,
                unit="m",
            ),
            "incompatible engineering unit",
        ),
        ("pressure_measurement_type", "unsupported", "controlled choices"),
        ("tag_number", True, "value kind is invalid"),
    ),
)
def test_known_values_enforce_quantity_unit_enum_and_scalar_kind(
    field_id: str,
    candidate: object,
    message: str,
) -> None:
    definition = _definition(PRESSURE_TEMPLATE, field_id)

    with pytest.raises(DatasheetFieldValidationError, match=message):
        SERVICE.evaluate(_content(field_values=(_known(definition, candidate),)))


def test_exact_template_identity_and_field_spelling_are_fail_closed() -> None:
    wrong_version = _content().model_copy(update={"template_version": "9.9.9"})
    wrong_fingerprint = _content().model_copy(update={"template_fingerprint": "f" * 64})
    tag = _definition(PRESSURE_TEMPLATE, "tag_number")
    wrong_capitalization = _content(
        field_values=(_known(tag).model_copy(update={"field_id": "Tag_number"}),)
    )
    unexpected = _content(
        field_values=(
            DatasheetFieldValue(
                field_id="unexpected_field",
                state=DatasheetFieldState.KNOWN,
                origin=DatasheetFieldOrigin.USER_SUPPLIED,
                value="unexpected",
                source_reference_ids=(SOURCE_ID,),
            ),
        )
    )

    for content in (
        wrong_version,
        wrong_fingerprint,
        wrong_capitalization,
        unexpected,
    ):
        with pytest.raises(DatasheetTemplateMismatchError):
            SERVICE.evaluate(content)


def test_under_review_lifecycle_rejects_blocked_and_accepts_ready_content() -> None:
    blocked_command = DatasheetCreateCommand(
        content=_content(lifecycle_state=DatasheetLifecycleState.UNDER_REVIEW),
        change_reason="Attempt review with unresolved safety inputs.",
        created_by="step-109-test",
    )

    with pytest.raises(DatasheetLifecycleError, match="cannot enter review"):
        SERVICE.create_history(blocked_command, created_at=CREATED_AT)

    history = _create_history(lifecycle_state=DatasheetLifecycleState.UNDER_REVIEW)
    assert history.revisions[0].snapshot.completeness.ready_for_review is True
    assert history.revisions[0].snapshot.content.lifecycle_state is (
        DatasheetLifecycleState.UNDER_REVIEW
    )


def test_archived_lifecycle_is_not_an_initial_or_reopenable_state() -> None:
    with pytest.raises(DatasheetLifecycleError, match="created directly"):
        _create_history(lifecycle_state=DatasheetLifecycleState.ARCHIVED)

    active = _create_history()
    archived_content = _content(
        field_values=_minimally_complete_values(PRESSURE_TEMPLATE),
        lifecycle_state=DatasheetLifecycleState.ARCHIVED,
        design_revision_number=2,
    )
    archived = SERVICE.append_revision(
        active,
        DatasheetRevisionCreate(
            expected_current_revision=active.current_revision,
            expected_current_fingerprint=active.current_revision_fingerprint,
            content=archived_content,
            change_reason="Archive the controlled datasheet.",
            created_by="step-109-test",
        ),
        revision_id=UUID("30000000-0000-0000-0000-000000000020"),
        created_at=CREATED_AT + timedelta(minutes=2),
    )
    reopen_content = _content(
        field_values=_minimally_complete_values(PRESSURE_TEMPLATE),
        lifecycle_state=DatasheetLifecycleState.DRAFT,
        design_revision_number=3,
    )
    with pytest.raises(DatasheetLifecycleError, match="not permitted"):
        SERVICE.append_revision(
            archived,
            DatasheetRevisionCreate(
                expected_current_revision=archived.current_revision,
                expected_current_fingerprint=(archived.current_revision_fingerprint),
                content=reopen_content,
                change_reason="Attempt to reopen an archived datasheet.",
                created_by="step-109-test",
            ),
            revision_id=UUID("30000000-0000-0000-0000-000000000021"),
            created_at=CREATED_AT + timedelta(minutes=3),
        )

    all_states = frozenset(DatasheetLifecycleState)
    assert DATASHEET_LIFECYCLE_TRANSITIONS == {
        DatasheetLifecycleState.DRAFT: all_states,
        DatasheetLifecycleState.UNDER_REVIEW: all_states,
        DatasheetLifecycleState.ON_HOLD: all_states,
        DatasheetLifecycleState.ARCHIVED: frozenset({DatasheetLifecycleState.ARCHIVED}),
    }


def test_create_and_append_bind_dense_revision_and_cas_evidence() -> None:
    created = _create_history()
    appended = _append(
        created,
        design_revision_number=2,
        revision_id=UUID("30000000-0000-0000-0000-000000000002"),
    )

    first, second = appended.revisions
    assert created.current_revision == 1
    assert appended.current_revision == 2
    assert tuple(item.revision_number for item in appended.revisions) == (1, 2)
    assert second.supersedes_revision_id == first.revision_id
    assert second.supersedes_revision_fingerprint == first.revision_fingerprint
    assert appended.current_revision_fingerprint == second.revision_fingerprint
    assert first == created.revisions[0]
    assert second.snapshot.completeness.content_fingerprint != (
        first.snapshot.completeness.content_fingerprint
    )
    for protected in (appended, first, second):
        assert protected.approval_state.value == "unapproved"
        assert protected.final_design_approval_granted is False


def test_two_writers_using_one_head_make_the_second_append_stale() -> None:
    original = _create_history()
    command = DatasheetRevisionCreate(
        expected_current_revision=original.current_revision,
        expected_current_fingerprint=original.current_revision_fingerprint,
        content=_content(
            field_values=_minimally_complete_values(PRESSURE_TEMPLATE),
            design_revision_number=2,
        ),
        change_reason="Concurrent replacement revision.",
        created_by="step-109-test",
    )
    winner = SERVICE.append_revision(
        original,
        command,
        revision_id=UUID("30000000-0000-0000-0000-000000000010"),
        created_at=CREATED_AT + timedelta(minutes=2),
    )

    with pytest.raises(DatasheetConcurrencyError, match="head changed"):
        SERVICE.append_revision(
            winner,
            command,
            revision_id=UUID("30000000-0000-0000-0000-000000000011"),
            created_at=CREATED_AT + timedelta(minutes=3),
        )
    assert winner.current_revision == 2
    assert len(winner.revisions) == 2


def test_append_rejects_design_case_and_controlled_template_drift() -> None:
    history = _create_history()
    case_drift = _content(
        field_values=_minimally_complete_values(PRESSURE_TEMPLATE),
        design_case_id=UUID("20000000-0000-0000-0000-000000000099"),
        design_revision_number=2,
    )
    other_template = TEMPLATES["instrument.level-transmitter"]
    template_drift = _content(
        other_template,
        field_values=_minimally_complete_values(other_template),
        design_revision_number=2,
    )

    for content, message in (
        (case_drift, "another design case"),
        (template_drift, "cannot change its controlled template"),
    ):
        command = DatasheetRevisionCreate(
            expected_current_revision=history.current_revision,
            expected_current_fingerprint=history.current_revision_fingerprint,
            content=content,
            change_reason="Attempt identity drift.",
            created_by="step-109-test",
        )
        with pytest.raises(DatasheetTemplateMismatchError, match=message):
            SERVICE.append_revision(history, command, created_at=CREATED_AT)


def test_history_validation_rejects_a_gap_in_dense_revisions() -> None:
    first = _create_history()
    second = _append(
        first,
        design_revision_number=2,
        revision_id=UUID("30000000-0000-0000-0000-000000000020"),
    )
    third = _append(
        second,
        design_revision_number=3,
        revision_id=UUID("30000000-0000-0000-0000-000000000021"),
    )
    payload = third.model_dump(mode="python", round_trip=True)
    payload["revisions"] = (third.revisions[0], third.revisions[2])

    with pytest.raises(ValidationError, match="dense and ordered"):
        DatasheetHistory.model_validate(payload)
