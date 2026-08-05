"""Step 110 datasheet persistence, provenance, and export service tests."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import UUID

import pytest
from openpyxl import load_workbook
from sqlalchemy import Engine, create_engine, event, func, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    EngineeringQuantity,
    InputOrigin,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.datasheet_models import (
    DatasheetCalculationLink,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetFieldOrigin,
    DatasheetFieldState,
    DatasheetFieldValue,
    DatasheetRevisionCreate,
)
from app.engineering.design.datasheet_registry import (
    PRESSURE_TRANSMITTER_TEMPLATE,
)
from app.engineering.design.persistence_models import (
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignRevisionPayload,
)
from app.engineering.design.datasheet_service import (
    DatasheetFieldValidationError,
    DatasheetService,
)
from app.models.calculation_run import CalculationRun
from app.models.design_case import (
    AppendOnlyRecordMutationError,
    DesignCase,
    DesignCaseRevision,
)
from app.models.engineering_datasheet import (
    EngineeringDatasheet,
    EngineeringDatasheetCalculationLink,
    EngineeringDatasheetRevision,
)
from app.repositories.datasheet_repository import (
    DatasheetNotFoundError,
    DatasheetPersistenceConflictError,
    DatasheetPersistenceCorruptionError,
    DatasheetRepository,
)
from app.repositories.design_repository import DesignRepository
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE
from app.services.datasheet_persistence_service import (
    DatasheetPersistenceInputError,
    DatasheetPersistenceIntegrityError,
    DatasheetPersistenceService,
)
from app.services.design_service import DesignPersistenceService


CASE_ID = UUID("10000000-0000-4000-8000-000000000001")
DESIGN_REVISION_ID = UUID("10000000-0000-4000-8000-000000000002")
DATASHEET_ID = UUID("10000000-0000-4000-8000-000000000003")
DATASHEET_REVISION_1_ID = UUID("10000000-0000-4000-8000-000000000004")
DATASHEET_REVISION_2_ID = UUID("10000000-0000-4000-8000-000000000005")
RUN_ID = UUID("10000000-0000-4000-8000-000000000006")
DATASHEET_REVISION_3_ID = UUID("10000000-0000-4000-8000-000000000007")
DATASHEET_REVISION_4_ID = UUID("10000000-0000-4000-8000-000000000008")
FIXED_TIME = datetime(2026, 8, 2, 14, 0, tzinfo=UTC)


class _Ids:
    def __init__(self, *values: UUID) -> None:
        self._values = iter(values)

    def __call__(self) -> UUID:
        return next(self._values)


@dataclass
class _Context:
    engine: Engine
    session: Session
    design_service: DesignPersistenceService
    service: DatasheetPersistenceService
    design_record: object


@pytest.fixture
def context() -> Iterator[_Context]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(
        engine,
        tables=(
            DesignCase.__table__,
            DesignCaseRevision.__table__,
            CalculationRun.__table__,
            EngineeringDatasheet.__table__,
            EngineeringDatasheetRevision.__table__,
            EngineeringDatasheetCalculationLink.__table__,
        ),
    )
    with Session(engine) as session:
        design_repository = DesignRepository(session)
        design_service = DesignPersistenceService(
            repository=design_repository,
            clock=lambda: FIXED_TIME,
            id_factory=_Ids(CASE_ID, DESIGN_REVISION_ID, RUN_ID),
        )
        design_record = design_service.create_case(
            DesignCaseCreate(
                case_reference="E4M-DATASHEET-110",
                case_type="pressure-transmitter",
                payload=DesignRevisionPayload(
                    title="Step 110 pressure transmitter design",
                    discipline="process-instrumentation",
                ),
                change_reason="Create the Step 110 design fixture.",
                created_by="Persistence test engineer",
            )
        )
        service = DatasheetPersistenceService(
            repository=DatasheetRepository(session),
            design_repository=design_repository,
            clock=lambda: FIXED_TIME,
            id_factory=_Ids(
                DATASHEET_REVISION_1_ID,
                DATASHEET_REVISION_2_ID,
                DATASHEET_REVISION_3_ID,
                DATASHEET_REVISION_4_ID,
            ),
        )
        yield _Context(
            engine=engine,
            session=session,
            design_service=design_service,
            service=service,
            design_record=design_record,
        )
    engine.dispose()


def _content(
    context: _Context,
    *,
    title: str = "PT-110 controlled datasheet",
    fields: tuple[DatasheetFieldValue, ...] = (),
    links: tuple[DatasheetCalculationLink, ...] = (),
    design_case_id: UUID = CASE_ID,
    design_revision_id: UUID = DESIGN_REVISION_ID,
    design_revision_fingerprint: str | None = None,
) -> DatasheetContent:
    template = PRESSURE_TRANSMITTER_TEMPLATE
    return DatasheetContent(
        datasheet_id=DATASHEET_ID,
        design_case_id=design_case_id,
        design_revision_id=design_revision_id,
        design_revision_number=1,
        design_revision_fingerprint=(
            design_revision_fingerprint
            or context.design_record.current_revision_fingerprint
        ),
        template_id=template.template_id,
        template_version=template.template_version,
        template_fingerprint=template.template_fingerprint,
        title=title,
        field_values=fields,
        calculation_links=links,
    )


def _create(context: _Context, **kwargs):
    return context.service.create(
        CASE_ID,
        DatasheetCreateCommand(
            content=_content(context, **kwargs),
            change_reason="Create the controlled datasheet.",
            created_by="Persistence test engineer",
        ),
    )


def _calculation_request() -> CalculationRequest:
    definition = DEFAULT_CALCULATION_SERVICE.get_method(
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
    return CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        requested_by="Persistence test engineer",
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


def test_create_read_list_and_dense_revision(context: _Context) -> None:
    created = _create(context)
    assert created.datasheet_id == DATASHEET_ID
    assert created.design_case_id == CASE_ID
    assert created.current_revision == created.concurrency_version == 1
    assert created.current.revision.revision_id == DATASHEET_REVISION_1_ID
    assert created.current.revision.snapshot.completeness.state.value == "blocked"
    assert created.current.export.workbook_size_bytes > 0
    assert not created.final_design_approval_granted

    assert context.service.get(CASE_ID, DATASHEET_ID) == created
    page = context.service.list(CASE_ID, offset=0, limit=20)
    assert page.total == 1
    assert page.items[0].datasheet_id == DATASHEET_ID
    assert page.items[0].workbook_sha256 == created.current.export.workbook_sha256

    command = DatasheetRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint=created.current_revision_fingerprint,
        content=created.current.revision.snapshot.content.model_copy(
            update={"title": "PT-110 controlled datasheet revision two"}
        ),
        change_reason="Record a controlled title correction.",
        created_by="Persistence test engineer",
    )
    context.service._clock = lambda: FIXED_TIME + timedelta(minutes=1)
    revised = context.service.revise(CASE_ID, DATASHEET_ID, command)
    assert revised.current_revision == revised.concurrency_version == 2
    assert revised.current.revision.revision_id == DATASHEET_REVISION_2_ID
    assert (
        revised.current.revision.supersedes_revision_fingerprint
        == created.current_revision_fingerprint
    )
    assert revised.current.export.json_sha256 != created.current.export.json_sha256
    assert context.service.get_revision(CASE_ID, DATASHEET_ID, 1) == created.current
    history = context.service.list_revisions(
        CASE_ID,
        DATASHEET_ID,
        offset=0,
        limit=20,
    )
    assert history.total == 2
    assert tuple(item.revision_number for item in history.items) == (2, 1)


def test_stale_revision_and_duplicate_identity_are_rejected(context: _Context) -> None:
    created = _create(context)
    with pytest.raises(DatasheetPersistenceConflictError):
        _create(context)
    command = DatasheetRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint="0" * 64,
        content=created.current.revision.snapshot.content,
        change_reason="Attempt a stale append.",
        created_by="Persistence test engineer",
    )
    with pytest.raises(Exception, match="changed before this append"):
        context.service.revise(CASE_ID, DATASHEET_ID, command)


def test_path_and_design_revision_mismatches_are_rejected(context: _Context) -> None:
    other_case = UUID("20000000-0000-4000-8000-000000000001")
    with pytest.raises(DatasheetPersistenceInputError, match="another design case"):
        context.service.create(
            CASE_ID,
            DatasheetCreateCommand(
                content=_content(context, design_case_id=other_case),
                change_reason="Reject foreign case.",
                created_by="Persistence test engineer",
            ),
        )
    with pytest.raises(DatasheetPersistenceInputError, match="stale"):
        context.service.create(
            CASE_ID,
            DatasheetCreateCommand(
                content=_content(
                    context,
                    design_revision_fingerprint="9" * 64,
                ),
                change_reason="Reject stale revision.",
                created_by="Persistence test engineer",
            ),
        )


def test_exact_historical_export_is_deterministic(context: _Context) -> None:
    created = _create(context, title='=HYPERLINK("x","y")')
    first = context.service.export(CASE_ID, DATASHEET_ID, 1)
    second = context.service.export(CASE_ID, DATASHEET_ID, 1)
    assert first.json_bytes == second.json_bytes
    assert first.workbook_bytes == second.workbook_bytes
    assert first.descriptor == created.current.export
    assert first.descriptor.datasheet_revision_number == 1


def test_calculation_link_is_rebuilt_from_trusted_run(context: _Context) -> None:
    execution = context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Persistence test engineer",
        ),
    )
    output = execution.result.outputs[0]
    link = DatasheetCalculationLink.from_engineering_run(
        link_id="link-pressure",
        run=execution.run,
        output_id=output.output_id,
    )
    field = DatasheetFieldValue(
        field_id="differential_upper_range_value",
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.CALCULATED,
        value=output.quantity,
        calculation_link_ids=(link.link_id,),
    )
    created = _create(context, fields=(field,), links=(link,))
    stored_link = created.current.revision.snapshot.content.calculation_links[0]
    assert stored_link.repository_provenance_verified
    assert (
        created.current.revision.snapshot.completeness.unverified_calculation_field_ids
        == ()
    )
    projection = context.session.scalar(select(EngineeringDatasheetCalculationLink))
    assert projection is not None
    assert projection.run_id == execution.run.run_id
    assert projection.output_id == output.output_id
    workbook = load_workbook(
        BytesIO(
            context.service.export_workbook(
                CASE_ID,
                DATASHEET_ID,
                1,
            ).content
        ),
        data_only=False,
    )
    try:
        sheet = workbook["Calculations"]
        assert tuple(cell.value for cell in sheet[1]) == (
            "Link ID",
            "Run ID",
            "Calculation type",
            "Method ID",
            "Method version",
            "Result status",
            "Design case ID",
            "Design revision ID",
            "Design revision number",
            "Design revision fingerprint",
            "Output ID",
            "Output name",
            "Output value",
            "Output unit",
            "Output source step IDs",
            "Output source value IDs",
            "Output source reference IDs",
            "Output description",
            "Repository provenance verified",
            "Source record embedded",
            "Historical link rewritten",
            "Run fingerprint",
            "Result fingerprint",
        )
        row = tuple(cell.value for cell in sheet[2])
        assert row[0] == "link-pressure"
        assert row[6] == str(CASE_ID)
        assert row[7] == str(DESIGN_REVISION_ID)
        assert row[8] == 1
        assert row[10] == output.output_id
        assert row[18] is True
        assert row[19] is False
        assert row[20] is False
    finally:
        workbook.close()


def test_round_tripped_provenance_is_independently_reverified(
    context: _Context,
) -> None:
    execution = context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Persistence test engineer",
        ),
    )
    output = execution.result.outputs[0]
    supplied = DatasheetCalculationLink.from_engineering_run(
        link_id="link-pressure",
        run=execution.run,
        output_id=output.output_id,
    )
    field = DatasheetFieldValue(
        field_id="differential_upper_range_value",
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.CALCULATED,
        value=output.quantity,
        calculation_link_ids=(supplied.link_id,),
    )
    created = _create(context, fields=(field,), links=(supplied,))
    returned = created.current.revision.snapshot.content
    assert returned.calculation_links[0].repository_provenance_verified
    command = DatasheetRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint=created.current_revision_fingerprint,
        content=returned.model_copy(update={"title": "Round-tripped revision"}),
        change_reason="Round-trip the server-verified calculation evidence.",
        created_by="Persistence test engineer",
    )
    context.service._clock = lambda: FIXED_TIME + timedelta(minutes=1)
    revised = context.service.revise(CASE_ID, DATASHEET_ID, command)
    assert revised.current_revision == 2
    assert (
        revised.current.revision.snapshot.content.calculation_links[0]
        == (returned.calculation_links[0])
    )


def test_stateless_service_rejects_self_asserted_repository_provenance(
    context: _Context,
) -> None:
    execution = context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Persistence test engineer",
        ),
    )
    output = execution.result.outputs[0]
    forged = DatasheetCalculationLink._from_repository_run(
        link_id="link-pressure",
        run=execution.run,
        output_id=output.output_id,
    )
    field = DatasheetFieldValue(
        field_id="differential_upper_range_value",
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.CALCULATED,
        value=output.quantity,
        calculation_link_ids=(forged.link_id,),
    )
    command = DatasheetCreateCommand(
        content=_content(context, fields=(field,), links=(forged,)),
        change_reason="Reject stateless provenance.",
        created_by="Persistence test engineer",
    )
    with pytest.raises(
        DatasheetFieldValidationError,
        match="persistent service boundary",
    ):
        DatasheetService().create_history(command)


def test_cross_case_lookup_is_indistinguishable_from_missing(context: _Context) -> None:
    _create(context)
    other_case = UUID("20000000-0000-4000-8000-000000000001")
    with pytest.raises(DatasheetNotFoundError):
        context.service.get(other_case, DATASHEET_ID)


def test_orm_guards_identity_revision_link_and_delete(context: _Context) -> None:
    _create(context)
    head = context.session.get(EngineeringDatasheet, DATASHEET_ID)
    assert head is not None
    head.template_id = "forged-template"
    with pytest.raises(AppendOnlyRecordMutationError):
        context.session.commit()
    context.session.rollback()

    revision = context.session.get(
        EngineeringDatasheetRevision,
        DATASHEET_REVISION_1_ID,
    )
    assert revision is not None
    revision.change_reason = "Forged mutation"
    with pytest.raises(AppendOnlyRecordMutationError):
        context.session.commit()
    context.session.rollback()

    head = context.session.get(EngineeringDatasheet, DATASHEET_ID)
    context.session.delete(head)
    with pytest.raises(AppendOnlyRecordMutationError):
        context.session.commit()
    context.session.rollback()


def test_corrupt_projection_fails_closed(context: _Context) -> None:
    _create(context)
    context.session.execute(
        EngineeringDatasheetRevision.__table__.update()
        .where(EngineeringDatasheetRevision.id == DATASHEET_REVISION_1_ID)
        .values(completeness_state="complete")
    )
    context.session.commit()
    with pytest.raises(DatasheetPersistenceCorruptionError):
        context.service.get(CASE_ID, DATASHEET_ID)


def test_export_descriptor_is_durable_and_corruption_fails_closed(
    context: _Context,
) -> None:
    created = _create(context)
    row = context.session.get(
        EngineeringDatasheetRevision,
        DATASHEET_REVISION_1_ID,
    )
    assert row is not None
    assert row.export_descriptor["workbook_sha256"] == (
        created.current.export.workbook_sha256
    )
    forged = dict(row.export_descriptor)
    forged["workbook_sha256"] = "0" * 64
    context.session.execute(
        EngineeringDatasheetRevision.__table__.update()
        .where(EngineeringDatasheetRevision.id == DATASHEET_REVISION_1_ID)
        .values(export_descriptor=forged)
    )
    context.session.commit()
    with pytest.raises(
        DatasheetPersistenceIntegrityError,
        match="stored exact datasheet artifact failed",
    ):
        context.service.export_workbook(CASE_ID, DATASHEET_ID, 1)


def test_persisted_artifact_byte_corruption_fails_closed(context: _Context) -> None:
    _create(context)
    context.session.execute(
        EngineeringDatasheetRevision.__table__.update()
        .where(EngineeringDatasheetRevision.id == DATASHEET_REVISION_1_ID)
        .values(workbook_artifact=b"PK-forged-artifact")
    )
    context.session.commit()
    with pytest.raises(
        DatasheetPersistenceIntegrityError,
        match="stored exact datasheet artifact failed",
    ):
        context.service.export_workbook(CASE_ID, DATASHEET_ID, 1)


def test_post_flush_verification_failure_rolls_back_all_rows(
    context: _Context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail_verification(*_args: object, **_kwargs: object) -> None:
        raise DatasheetPersistenceIntegrityError("forced verification failure")

    monkeypatch.setattr(
        DatasheetPersistenceService,
        "_verify_persisted_revision",
        _fail_verification,
    )
    with pytest.raises(DatasheetPersistenceIntegrityError):
        _create(context)
    assert context.session.scalar(select(func.count(EngineeringDatasheet.id))) == 0
    assert (
        context.session.scalar(select(func.count(EngineeringDatasheetRevision.id))) == 0
    )


def test_renderer_rejection_occurs_before_persistence(context: _Context) -> None:
    with pytest.raises(Exception, match="illegal XML control"):
        _create(context, title="unsafe\x0btitle")
    assert context.session.scalar(select(func.count(EngineeringDatasheet.id))) == 0


def test_reads_and_json_export_do_not_regenerate_artifacts(
    context: _Context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _create(context)
    original_json = context.service.export_json(CASE_ID, DATASHEET_ID, 1).content

    def _unexpected(*_args: object, **_kwargs: object):
        raise AssertionError("workbook rendering was not requested")

    monkeypatch.setattr(
        "app.repositories.datasheet_repository.build_datasheet_export_bundle",
        _unexpected,
    )
    monkeypatch.setattr(
        "app.engineering.design.xlsx_renderer.canonical_datasheet_json",
        _unexpected,
    )
    assert context.service.get(CASE_ID, DATASHEET_ID).datasheet_id == DATASHEET_ID
    assert context.service.list(CASE_ID, offset=0, limit=20).total == 1
    assert (
        context.service.list_revisions(
            CASE_ID,
            DATASHEET_ID,
            offset=0,
            limit=20,
        ).total
        == 1
    )
    artifact = context.service.export_json(CASE_ID, DATASHEET_ID, 1)
    assert artifact.format == "json"
    assert artifact.content == original_json


def test_metadata_lists_defer_large_artifacts_until_exact_export(
    context: _Context,
) -> None:
    _create(context)
    context.session.expire_all()
    assert context.service.list(CASE_ID, offset=0, limit=20).total == 1
    row = context.session.get(
        EngineeringDatasheetRevision,
        DATASHEET_REVISION_1_ID,
    )
    assert row is not None
    assert {"json_artifact", "workbook_artifact"}.issubset(inspect(row).unloaded)
    context.service.export_json(CASE_ID, DATASHEET_ID, 1)
    assert not ({"json_artifact", "workbook_artifact"} & inspect(row).unloaded)


def test_direct_repository_rejects_forged_calculation_output(
    context: _Context,
) -> None:
    execution = context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Persistence test engineer",
        ),
    )
    output = execution.result.outputs[0]
    trusted = DatasheetCalculationLink._from_repository_run(
        link_id="link-pressure",
        run=execution.run,
        output_id=output.output_id,
    )
    assert output.quantity is not None
    forged_quantity = output.quantity.model_copy(
        update={"value": output.quantity.value + 1.0}
    )
    forged = trusted.model_copy(
        update={"output": output.model_copy(update={"quantity": forged_quantity})}
    )
    field = DatasheetFieldValue(
        field_id="differential_upper_range_value",
        state=DatasheetFieldState.KNOWN,
        origin=DatasheetFieldOrigin.CALCULATED,
        value=forged_quantity,
        calculation_link_ids=(forged.link_id,),
    )
    command = DatasheetCreateCommand(
        content=_content(context, fields=(field,), links=(forged,)),
        change_reason="Attempt forged calculation evidence.",
        created_by="Persistence test engineer",
    )
    history = DatasheetService(_allow_repository_provenance=True).create_history(
        command,
        revision_id=DATASHEET_REVISION_1_ID,
        created_at=FIXED_TIME,
    )
    with pytest.raises(
        DatasheetPersistenceConflictError,
        match="does not match trusted persistence",
    ):
        DatasheetRepository(context.session).create(history)
