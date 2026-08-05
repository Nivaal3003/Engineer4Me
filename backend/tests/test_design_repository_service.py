"""Focused Step 108 repository and service persistence contracts.

SQLite is used here only to exercise SQLAlchemy mappings, repository
transactions, and service orchestration.  PostgreSQL migration and trigger
behavior remain separate deployment concerns.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import count
import json
from uuid import UUID

import pytest
from sqlalchemy import Engine, create_engine, event, func, select, update
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
from app.engineering.design.analyzer_models import AnalyzerApplicationRequest
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
)
from app.engineering.design.persistence_models import (
    CalculationRunPayload,
    DesignAnalyzerAssessmentCommand,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignCaseRevisionCreate,
    DesignContextItem,
    DesignRevisionPayload,
    DesignSourceOrigin,
    EngineeringRunKind,
)
from app.models.calculation_run import CalculationRun
from app.models.design_case import (
    AppendOnlyRecordMutationError,
    DesignCase,
    DesignCaseRevision,
)
from app.repositories.design_repository import (
    DesignPersistenceConflictError,
    DesignPersistenceCorruptionError,
    DesignRepository,
)
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE
from app.services.design_service import (
    DesignPersistenceInputError,
    DesignPersistenceService,
)


FIXED_TIME = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


class _SequenceClock:
    """Return deterministic, strictly increasing UTC timestamps."""

    def __init__(self) -> None:
        self._values = count()

    def __call__(self) -> datetime:
        return FIXED_TIME + timedelta(seconds=next(self._values))


class _SequenceIds:
    """Return deterministic UUIDs without coupling assertions to randomness."""

    def __init__(self) -> None:
        self._values = count(10_000)

    def __call__(self) -> UUID:
        return UUID(int=next(self._values))


@dataclass(frozen=True)
class _PersistenceContext:
    engine: Engine
    session: Session
    repository: DesignRepository
    service: DesignPersistenceService


@pytest.fixture
def persistence() -> Iterator[_PersistenceContext]:
    """Create an isolated in-memory SQLAlchemy persistence boundary."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(
        engine,
        tables=(
            DesignCase.__table__,
            DesignCaseRevision.__table__,
            CalculationRun.__table__,
        ),
    )
    session = Session(engine)
    repository = DesignRepository(session)
    service = DesignPersistenceService(
        repository=repository,
        clock=_SequenceClock(),
        id_factory=_SequenceIds(),
    )
    try:
        yield _PersistenceContext(
            engine=engine,
            session=session,
            repository=repository,
            service=service,
        )
    finally:
        session.close()
        # Every fixture owns a private in-memory connection, so disposing it
        # removes the database without issuing DDL against self-referential
        # revision and run foreign keys.
        engine.dispose()


def _revision_payload(*, title: str = "Analyzer design case") -> DesignRevisionPayload:
    return DesignRevisionPayload(
        title=title,
        discipline="process-instrumentation",
        industry="Minerals processing",
        source_origins=(
            DesignSourceOrigin(
                source_id="source-process-datasheet",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                description="Reviewed process datasheet revision B",
                reference_ids=("process-datasheet-b",),
            ),
        ),
        plant_context=(
            DesignContextItem(
                field_id="normal-pressure",
                label="Normal process pressure",
                value="5.2",
                unit="bar(a)",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                source_origin_ids=("source-process-datasheet",),
            ),
        ),
    )


def _create_command(
    *,
    case_reference: str = "E4M-DESIGN-108",
) -> DesignCaseCreate:
    return DesignCaseCreate(
        case_reference=case_reference,
        case_type="analyzer-application",
        payload=_revision_payload(),
        change_reason="Create the controlled design case.",
        created_by="Test engineer",
    )


def _calculation_request() -> CalculationRequest:
    # Use the same exact-version registry exposed by the controlled service.
    # The request remains caller-owned; the result never does.
    definition = DEFAULT_CALCULATION_SERVICE.get_method(
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
    return CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        requested_by="Test engineer",
        inputs=tuple(
            CalculationInput(
                input_id=input_id,
                name=specifications[input_id].name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=EngineeringQuantity(
                    quantity_kind=quantity_kind.value,
                    value=value,
                    unit=unit,
                ),
            )
            for input_id, quantity_kind, value, unit in values
        ),
    )


def _vertical_tank_request() -> CalculationRequest:
    """Build a second valid calculation with a different method identity."""

    definition = DEFAULT_CALCULATION_SERVICE.get_method(
        "level.tank.vertical-cylinder",
        "1.0.0",
    )
    specifications = {
        item.input_id: item for item in definition.input_specifications
    }
    values: tuple[
        tuple[str, QuantityKind, float, str] | tuple[str, bool], ...
    ] = (
        ("internal-diameter", QuantityKind.LENGTH, 4.0, "m"),
        ("straight-side-height", QuantityKind.LENGTH, 8.0, "m"),
        ("liquid-height", QuantityKind.LENGTH, 3.0, "m"),
        ("flat-end-internal-geometry-confirmed", True),
        ("liquid-level-within-cylinder-confirmed", True),
    )
    inputs: list[CalculationInput] = []
    for value in values:
        input_id = value[0]
        if len(value) == 2:
            inputs.append(
                CalculationInput(
                    input_id=input_id,
                    name=specifications[input_id].name,
                    origin=InputOrigin.USER_SUPPLIED,
                    categorical_value=value[1],
                )
            )
        else:
            _, quantity_kind, magnitude, unit = value
            inputs.append(
                CalculationInput(
                    input_id=input_id,
                    name=specifications[input_id].name,
                    origin=InputOrigin.USER_SUPPLIED,
                    quantity=EngineeringQuantity(
                        quantity_kind=quantity_kind.value,
                        value=magnitude,
                        unit=unit,
                    ),
                )
            )
    return CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=FIXED_TIME,
        requested_by="Test engineer",
        inputs=tuple(inputs),
    )


def _analyzer_request(*, request_id: str) -> AnalyzerApplicationRequest:
    document = ANALYZER_DESIGN_CASE_EXAMPLES[0].request.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    document["request_id"] = request_id
    return AnalyzerApplicationRequest.model_validate(document)


def _create_case(context: _PersistenceContext):
    return context.service.create_case(_create_command())


def _record_analyzer(
    context: _PersistenceContext,
    *,
    design_case_id: UUID,
    request_id: str,
    supersedes_run_id: UUID | None = None,
):
    return context.service.assess_analyzer(
        design_case_id,
        DesignAnalyzerAssessmentCommand(
            design_revision_number=1,
            request=_analyzer_request(request_id=request_id),
            created_by="Test engineer",
            supersedes_run_id=supersedes_run_id,
        ),
    )


def test_create_read_and_list_case_and_revision(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)

    fetched = persistence.service.get_case(created.design_case_id)
    cases = persistence.service.list_cases(offset=0, limit=10)
    revision = persistence.service.get_revision(created.design_case_id, 1)
    revisions = persistence.service.list_revisions(
        created.design_case_id,
        offset=0,
        limit=10,
    )

    assert fetched == created
    assert cases.total == 1
    assert tuple(item.design_case_id for item in cases.items) == (
        created.design_case_id,
    )
    assert revision == created.revision
    assert revisions.total == 1
    assert tuple(item.revision_number for item in revisions.items) == (1,)
    assert revisions.items[0].supersedes_revision_id is None
    assert revisions.items[0].supersedes_revision_fingerprint is None


def test_case_create_hydration_failure_rolls_back_flushed_rows(
    persistence: _PersistenceContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed post-flush read cannot leave an unverified case behind."""

    def reject_hydration(
        _repository: DesignRepository,
        _design_case_id: UUID,
    ) -> object:
        raise DesignPersistenceCorruptionError(
            "Injected post-flush case hydration failure."
        )

    monkeypatch.setattr(DesignRepository, "get_case", reject_hydration)

    with pytest.raises(
        DesignPersistenceCorruptionError,
        match="post-flush case hydration failure",
    ):
        persistence.service.create_case(_create_command())

    assert persistence.session.scalar(select(func.count(DesignCase.id))) == 0
    assert (
        persistence.session.scalar(select(func.count(DesignCaseRevision.id)))
        == 0
    )


def test_revision_hydration_failure_rolls_back_flushed_successor(
    persistence: _PersistenceContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed hydrated response preserves the previously committed head."""

    created = _create_case(persistence)
    original_get_case = DesignRepository.get_case
    hydration_count = 0

    def fail_second_hydration(
        repository: DesignRepository,
        design_case_id: UUID,
    ):
        nonlocal hydration_count
        hydration_count += 1
        if hydration_count == 2:
            raise DesignPersistenceCorruptionError(
                "Injected post-flush revision hydration failure."
            )
        return original_get_case(repository, design_case_id)

    monkeypatch.setattr(DesignRepository, "get_case", fail_second_hydration)

    with pytest.raises(
        DesignPersistenceCorruptionError,
        match="post-flush revision hydration failure",
    ):
        persistence.service.revise_case(
            created.design_case_id,
            DesignCaseRevisionCreate(
                expected_current_revision=created.current_revision,
                expected_current_fingerprint=(
                    created.current_revision_fingerprint
                ),
                payload=_revision_payload(title="Uncommitted successor"),
                change_reason="Exercise post-flush rollback.",
                created_by="Test engineer",
            ),
        )

    assert hydration_count == 2
    head = persistence.session.get(DesignCase, created.design_case_id)
    assert head is not None
    assert head.current_revision == head.concurrency_version == 1
    assert head.current_revision_fingerprint == (
        created.current_revision_fingerprint
    )
    assert (
        persistence.session.scalar(
            select(func.count(DesignCaseRevision.id)).where(
                DesignCaseRevision.design_case_id == created.design_case_id
            )
        )
        == 1
    )


def test_run_hydration_failure_rolls_back_flushed_run(
    persistence: _PersistenceContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unverified hydrated run is never committed as durable evidence."""

    created = _create_case(persistence)

    def reject_hydration(
        _repository: DesignRepository,
        _run_id: UUID,
    ) -> object:
        raise DesignPersistenceCorruptionError(
            "Injected post-flush run hydration failure."
        )

    monkeypatch.setattr(DesignRepository, "get_run", reject_hydration)

    with pytest.raises(
        DesignPersistenceCorruptionError,
        match="post-flush run hydration failure",
    ):
        persistence.service.execute_calculation(
            created.design_case_id,
            DesignCalculationExecutionCommand(
                design_revision_number=1,
                calculation=_calculation_request(),
                created_by="Test engineer",
            ),
        )

    assert (
        persistence.session.scalar(select(func.count(CalculationRun.id)))
        == 0
    )
    assert persistence.session.scalar(select(func.count(DesignCase.id))) == 1
    assert (
        persistence.session.scalar(select(func.count(DesignCaseRevision.id)))
        == 1
    )


def test_current_case_hydration_is_bounded_for_get_list_and_append(
    persistence: _PersistenceContext,
) -> None:
    """Current-head reads never materialize an unbounded revision history."""

    current = _create_case(persistence)
    for revision_number in range(2, 6):
        current = persistence.service.revise_case(
            current.design_case_id,
            DesignCaseRevisionCreate(
                expected_current_revision=current.current_revision,
                expected_current_fingerprint=(
                    current.current_revision_fingerprint
                ),
                payload=_revision_payload(
                    title=f"Analyzer design case revision {revision_number}"
                ),
                change_reason=f"Create revision {revision_number}.",
                created_by="Test engineer",
            ),
        )

    persistence.session.expunge_all()
    statements: list[str] = []

    def _capture_statement(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        statements.append(" ".join(statement.lower().split()))

    event.listen(
        persistence.engine,
        "before_cursor_execute",
        _capture_statement,
    )
    try:
        appended = persistence.service.revise_case(
            current.design_case_id,
            DesignCaseRevisionCreate(
                expected_current_revision=current.current_revision,
                expected_current_fingerprint=(
                    current.current_revision_fingerprint
                ),
                payload=_revision_payload(
                    title="Analyzer design case revision 6"
                ),
                change_reason="Create revision 6.",
                created_by="Test engineer",
            ),
        )
        fetched = persistence.service.get_case(current.design_case_id)
        listed = persistence.service.list_cases(offset=0, limit=10)
    finally:
        event.remove(
            persistence.engine,
            "before_cursor_execute",
            _capture_statement,
        )

    revision_reads = [
        statement
        for statement in statements
        if statement.startswith("select")
        and "design_case_revisions" in statement
    ]
    assert revision_reads
    assert all(
        "design_case_revisions.revision_number" in statement
        for statement in revision_reads
    )
    assert not any(
        "design_case_revisions.design_case_id in" in statement
        for statement in revision_reads
    )
    assert appended.current_revision == 6
    assert fetched == appended
    assert listed.total == 1
    assert listed.items[0].current_revision == 6


def test_case_reference_uniqueness_is_case_insensitive(
    persistence: _PersistenceContext,
) -> None:
    persistence.service.create_case(
        _create_command(case_reference="E4M-Case-Insensitive")
    )

    with pytest.raises(DesignPersistenceConflictError):
        persistence.service.create_case(
            _create_command(case_reference="e4m-case-insensitive")
        )

    assert persistence.session.scalar(select(func.count(DesignCase.id))) == 1
    assert (
        persistence.session.scalar(select(func.count(DesignCaseRevision.id)))
        == 1
    )


def test_revisions_are_dense_and_retain_predecessor_identity(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    revised = persistence.service.revise_case(
        created.design_case_id,
        DesignCaseRevisionCreate(
            expected_current_revision=1,
            expected_current_fingerprint=created.current_revision_fingerprint,
            payload=_revision_payload(title="Analyzer design case revision 2"),
            change_reason="Add the confirmed installation context.",
            created_by="Test engineer",
        ),
    )

    history = persistence.service.list_revisions(
        created.design_case_id,
        offset=0,
        limit=10,
    )
    assert revised.current_revision == 2
    assert revised.concurrency_version == 2
    assert revised.revision.supersedes_revision_id == created.revision.revision_id
    assert (
        revised.revision.supersedes_revision_fingerprint
        == created.revision.revision_fingerprint
    )
    assert tuple(item.revision_number for item in history.items) == (2, 1)


def test_stale_revision_compare_and_swap_creates_no_orphan(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    stale = DesignCaseRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint=created.current_revision_fingerprint,
        payload=_revision_payload(title="First competing revision"),
        change_reason="First competing revision wins.",
        created_by="Test engineer",
    )
    persistence.service.revise_case(created.design_case_id, stale)

    losing = DesignCaseRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint=created.current_revision_fingerprint,
        payload=_revision_payload(title="Second competing revision"),
        change_reason="This stale write must fail.",
        created_by="Test engineer",
    )
    with pytest.raises(DesignPersistenceConflictError):
        persistence.service.revise_case(created.design_case_id, losing)

    revision_count = persistence.session.scalar(
        select(func.count(DesignCaseRevision.id)).where(
            DesignCaseRevision.design_case_id == created.design_case_id
        )
    )
    assert revision_count == 2
    assert persistence.service.get_case(created.design_case_id).current_revision == 2


@pytest.mark.parametrize(
    ("attribute", "replacement"),
    (
        ("id", UUID(int=999_999)),
        ("case_reference", "FORGED-CASE-IDENTITY"),
        ("case_type", "forged-case-type"),
        ("created_by", "Forged creator"),
        ("creator_origin", "forged_origin"),
        ("created_at", FIXED_TIME + timedelta(days=1)),
    ),
)
def test_design_case_identity_is_immutable_at_orm_boundary(
    persistence: _PersistenceContext,
    attribute: str,
    replacement: object,
) -> None:
    created = _create_case(persistence)
    row = persistence.session.get(DesignCase, created.design_case_id)
    assert row is not None
    setattr(row, attribute, replacement)

    with pytest.raises(
        AppendOnlyRecordMutationError,
        match="Design-case identity is immutable",
    ):
        persistence.session.commit()
    persistence.session.rollback()

    preserved = persistence.service.get_case(created.design_case_id)
    assert preserved.case_reference == created.case_reference
    assert preserved.case_type == created.case_type
    assert preserved.created_by == created.created_by
    assert preserved.created_at == created.created_at


def test_append_only_orm_guards_reject_revision_and_run_mutation(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    persisted = _record_analyzer(
        persistence,
        design_case_id=created.design_case_id,
        request_id="analyzer-append-only",
    )

    revision_row = persistence.session.get(
        DesignCaseRevision,
        created.revision.revision_id,
    )
    assert revision_row is not None
    revision_row.change_reason = "Attempted in-place edit"
    with pytest.raises(AppendOnlyRecordMutationError):
        persistence.session.commit()
    persistence.session.rollback()

    revision_row = persistence.session.get(
        DesignCaseRevision,
        created.revision.revision_id,
    )
    assert revision_row is not None
    persistence.session.delete(revision_row)
    with pytest.raises(AppendOnlyRecordMutationError):
        persistence.session.commit()
    persistence.session.rollback()

    run_row = persistence.session.get(CalculationRun, persisted.run.run_id)
    assert run_row is not None
    run_row.created_by = "Attempted in-place editor"
    with pytest.raises(AppendOnlyRecordMutationError):
        persistence.session.commit()
    persistence.session.rollback()

    run_row = persistence.session.get(CalculationRun, persisted.run.run_id)
    assert run_row is not None
    persistence.session.delete(run_row)
    with pytest.raises(AppendOnlyRecordMutationError):
        persistence.session.commit()
    persistence.session.rollback()


def test_trusted_calculation_is_executed_then_recorded_with_exact_basis(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    persisted = persistence.service.execute_calculation(
        created.design_case_id,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Test engineer",
        ),
    )

    assert persisted.persistence_performed is True
    assert persisted.run.payload.kind is EngineeringRunKind.CALCULATION
    assert isinstance(persisted.run.payload, CalculationRunPayload)
    assert persisted.run.payload.result == persisted.result
    assert persisted.run.result_fingerprint == persisted.result.result_fingerprint
    assert persisted.run.design_revision_fingerprint == (
        created.revision.revision_fingerprint
    )
    basis = json.loads(persisted.run.payload.fingerprint_basis_json)
    assert basis["method"] == {
        "method_id": persisted.result.method_id,
        "method_version": persisted.result.method_version,
    }

    row = persistence.session.get(CalculationRun, persisted.run.run_id)
    assert row is not None
    assert row.execution_metadata["method_definition"] == (
        persisted.run.payload.method_definition.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
        )
    )
    assert row.execution_metadata["fingerprint_basis_json"] == (
        persisted.run.payload.fingerprint_basis_json
    )
    assert persistence.service.get_run(persisted.run.run_id) == persisted.run


def test_analyzer_stateless_envelope_is_preserved_inside_persisted_record(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    persisted = _record_analyzer(
        persistence,
        design_case_id=created.design_case_id,
        request_id="analyzer-persisted",
    )

    assert persisted.assessment.persistence_performed is False
    assert persisted.run.payload.envelope.persistence_performed is False
    assert persisted.run.persistence_performed is True
    assert persisted.persistence_performed is True
    assert persisted.run.result_fingerprint == (
        persisted.assessment.integration_fingerprint
    )
    assert persistence.service.get_run(persisted.run.run_id) == persisted.run


def test_correction_chain_retains_predecessor_and_rejects_branching(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    first = _record_analyzer(
        persistence,
        design_case_id=created.design_case_id,
        request_id="analyzer-original",
    )
    correction = _record_analyzer(
        persistence,
        design_case_id=created.design_case_id,
        request_id="analyzer-correction",
        supersedes_run_id=first.run.run_id,
    )

    assert correction.run.supersedes_run_id == first.run.run_id
    assert correction.run.supersedes_run_fingerprint == first.run.run_fingerprint

    with pytest.raises(DesignPersistenceConflictError):
        _record_analyzer(
            persistence,
            design_case_id=created.design_case_id,
            request_id="analyzer-conflicting-branch",
            supersedes_run_id=first.run.run_id,
        )

    runs = persistence.service.list_runs(
        created.design_case_id,
        offset=0,
        limit=10,
    )
    assert runs.total == 2
    assert {item.run_id for item in runs.items} == {
        first.run.run_id,
        correction.run.run_id,
    }


def test_correction_chain_rejects_cross_method_lineage(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    first = persistence.service.execute_calculation(
        created.design_case_id,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Test engineer",
        ),
    )

    with pytest.raises(
        DesignPersistenceInputError,
        match="another execution history",
    ):
        persistence.service.execute_calculation(
            created.design_case_id,
            DesignCalculationExecutionCommand(
                design_revision_number=1,
                calculation=_vertical_tank_request(),
                created_by="Test engineer",
                supersedes_run_id=first.run.run_id,
            ),
        )

    correction = persistence.service.execute_calculation(
        created.design_case_id,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_calculation_request(),
            created_by="Test engineer",
            supersedes_run_id=first.run.run_id,
        ),
    )
    assert correction.run.supersedes_run_id == first.run.run_id
    assert correction.run.supersedes_run_fingerprint == first.run.run_fingerprint
    assert persistence.session.scalar(select(func.count(CalculationRun.id))) == 2


def test_tampered_storage_is_rejected_during_hydration(
    persistence: _PersistenceContext,
) -> None:
    created = _create_case(persistence)
    persisted = _record_analyzer(
        persistence,
        design_case_id=created.design_case_id,
        request_id="analyzer-corruption-check",
    )

    # A Core statement deliberately bypasses the ORM append-only listener to
    # simulate corrupted bytes.  PostgreSQL's migration-level trigger is not
    # under test in this SQLite-focused suite.
    persistence.session.execute(
        update(CalculationRun)
        .where(CalculationRun.id == persisted.run.run_id)
        .values(status="failed")
    )
    persistence.session.commit()
    persistence.session.expire_all()

    with pytest.raises(DesignPersistenceCorruptionError):
        persistence.service.get_run(persisted.run.run_id)


def test_repository_and_service_expose_no_in_place_update_or_delete_methods() -> None:
    prohibited = {
        "delete_case",
        "delete_revision",
        "delete_run",
        "update_case",
        "update_revision",
        "update_run",
        "upsert_case",
        "upsert_revision",
        "upsert_run",
    }

    assert prohibited.isdisjoint(DesignRepository.__dict__)
    assert prohibited.isdisjoint(DesignPersistenceService.__dict__)
