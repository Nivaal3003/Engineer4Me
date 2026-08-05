"""Migration contract tests for Phase 7 design persistence.

The static and offline tests always run.  The live PostgreSQL test uses a
fresh, validated schema and is skipped only when an isolated PostgreSQL
connection cannot be established (or the server cannot create that schema).
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection
from sqlalchemy import Engine
from sqlalchemy import create_engine
from sqlalchemy import inspect
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import URL
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool
from sqlalchemy.sql.schema import Column

import app.models  # noqa: F401
from app.db.database import Base


BACKEND_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
MIGRATION_PATH = (
    BACKEND_ROOT
    / "alembic"
    / "versions"
    / "a7f108d9c2e1_add_phase7_design_persistence.py"
)
REVISION = "a7f108d9c2e1"
PARENT_REVISION = "94a2e09dd267"
PHASE_HEAD_REVISION = "b7f110e3d2a1"
PHASE_TABLES = (
    "design_cases",
    "design_case_revisions",
    "calculation_runs",
)
CASE_REFERENCE_INDEX = "uq_design_cases_case_reference_ci"
PHASE_FUNCTIONS = {
    "phase7_guard_design_case_head_update",
    "phase7_validate_design_revision_chain",
    "phase7_validate_design_case_head",
    "phase7_validate_inserted_revision_is_head",
    "phase7_validate_calculation_run_links",
    "phase7_reject_append_only_mutation",
}
PHASE_TRIGGERS = {
    "trg_design_cases_identity_immutable",
    "trg_design_cases_head_integrity",
    "trg_design_case_revisions_chain_integrity",
    "trg_design_case_revisions_head_integrity",
    "trg_design_case_revisions_append_only",
    "trg_calculation_runs_link_integrity",
    "trg_calculation_runs_append_only",
}
TEST_SCHEMA_PATTERN = re.compile(r"\Ae4m_step108_test_[0-9a-f]{32}\Z")
POSTGRES_DIALECT = postgresql.dialect()


@dataclass(frozen=True)
class _RecordedIndex:
    name: str
    table_name: str
    expressions: tuple[object, ...]
    unique: bool


class _MigrationRecorder:
    """Capture migration objects without requiring a database connection."""

    def __init__(self) -> None:
        self.metadata = sa.MetaData()
        self.indexes: list[_RecordedIndex] = []
        self.executed_sql: list[str] = []

    def create_table(
        self,
        name: str,
        *items: object,
        **kwargs: object,
    ) -> sa.Table:
        return sa.Table(name, self.metadata, *items, **kwargs)

    def create_index(
        self,
        name: str,
        table_name: str,
        expressions: list[object],
        *,
        unique: bool = False,
        **_kwargs: object,
    ) -> None:
        self.indexes.append(
            _RecordedIndex(
                name=name,
                table_name=table_name,
                expressions=tuple(expressions),
                unique=unique,
            )
        )

    def execute(self, statement: object, *_args: object, **_kwargs: object) -> None:
        self.executed_sql.append(str(statement))


@dataclass(frozen=True)
class _PostgresSandbox:
    connection: Connection
    engine: Engine
    schema: str
    quoted_schema: str
    alembic_config: Config


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_phase7_design_persistence_migration_contract",
        MIGRATION_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _recorded_migration() -> tuple[ModuleType, _MigrationRecorder]:
    migration = _load_migration()
    recorder = _MigrationRecorder()
    migration.op = recorder
    migration.upgrade()
    return migration, recorder


def _normalize_sql(value: object) -> str:
    return re.sub(r"\s+", " ", str(value)).strip().lower()


def _server_default(column: Column[Any]) -> str | None:
    if column.server_default is None:
        return None
    argument = column.server_default.arg
    if hasattr(argument, "compile"):
        argument = argument.compile(
            dialect=POSTGRES_DIALECT,
            compile_kwargs={"literal_binds": True},
        )
    return _normalize_sql(argument)


def _column_contract(table: sa.Table) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            column.name,
            str(column.type.compile(dialect=POSTGRES_DIALECT)),
            column.nullable,
            _server_default(column),
        )
        for column in table.columns
    )


def _constraint_signature(constraint: sa.Constraint) -> tuple[object, ...]:
    if isinstance(constraint, sa.PrimaryKeyConstraint):
        return (
            "primary-key",
            constraint.name,
            tuple(column.name for column in constraint.columns),
        )
    if isinstance(constraint, sa.UniqueConstraint):
        return (
            "unique",
            constraint.name,
            tuple(column.name for column in constraint.columns),
        )
    if isinstance(constraint, sa.CheckConstraint):
        return (
            "check",
            constraint.name,
            _normalize_sql(constraint.sqltext),
        )
    if isinstance(constraint, sa.ForeignKeyConstraint):
        return (
            "foreign-key",
            constraint.name,
            tuple(element.parent.name for element in constraint.elements),
            tuple(element.target_fullname for element in constraint.elements),
            constraint.ondelete,
        )
    raise AssertionError(f"Unhandled constraint type: {type(constraint)!r}")


def _constraint_contract(table: sa.Table) -> set[tuple[object, ...]]:
    return {_constraint_signature(constraint) for constraint in table.constraints}


def _index_expression(expression: object) -> str:
    if isinstance(expression, str):
        return expression
    if isinstance(expression, Column):
        return expression.name
    if hasattr(expression, "compile"):
        expression = expression.compile(dialect=POSTGRES_DIALECT)
    return _normalize_sql(expression)


def _model_index_contract(table: sa.Table) -> set[tuple[object, ...]]:
    return {
        (
            index.name,
            bool(index.unique),
            tuple(_index_expression(item) for item in index.expressions),
        )
        for index in table.indexes
    }


def _migration_index_contract(
    recorder: _MigrationRecorder,
    table_name: str,
) -> set[tuple[object, ...]]:
    return {
        (
            index.name,
            index.unique,
            tuple(_index_expression(item) for item in index.expressions),
        )
        for index in recorder.indexes
        if index.table_name == table_name
    }


def _offline_sql(
    action: str,
    revision_range: str,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    output = io.StringIO()
    config = Config(str(ALEMBIC_INI), output_buffer=output)
    config.attributes["configure_logger"] = False
    if action == "upgrade":
        command.upgrade(config, revision_range, sql=True)
    elif action == "downgrade":
        command.downgrade(config, revision_range, sql=True)
    else:  # pragma: no cover - test helper misuse
        raise AssertionError(f"Unsupported Alembic action: {action}")
    return _normalize_sql(output.getvalue())


def _assert_in_order(sql: str, fragments: tuple[str, ...]) -> None:
    positions = []
    for fragment in fragments:
        normalized_fragment = _normalize_sql(fragment)
        assert normalized_fragment in sql
        positions.append(sql.index(normalized_fragment))
    assert positions == sorted(positions)


def test_alembic_graph_has_one_phase7_head_with_expected_parent() -> None:
    config = Config(str(ALEMBIC_INI))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == [PHASE_HEAD_REVISION]
    revision = scripts.get_revision(REVISION)
    assert revision is not None
    assert revision.down_revision == PARENT_REVISION
    assert revision.nextrev == frozenset({PHASE_HEAD_REVISION})


def test_orm_and_upgrade_migration_have_exact_postgresql_parity() -> None:
    migration, recorder = _recorded_migration()

    assert migration.revision == REVISION
    assert migration.down_revision == PARENT_REVISION
    assert set(recorder.metadata.tables) == set(PHASE_TABLES)

    for table_name in PHASE_TABLES:
        model_table = Base.metadata.tables[table_name]
        migration_table = recorder.metadata.tables[table_name]
        assert _column_contract(model_table) == _column_contract(migration_table)
        assert _constraint_contract(model_table) == _constraint_contract(
            migration_table
        )
        assert _model_index_contract(model_table) == _migration_index_contract(
            recorder,
            table_name,
        )

    case_columns = recorder.metadata.tables["design_cases"].columns
    assert _server_default(case_columns.current_revision) == "1"
    assert case_columns.current_revision_fingerprint.nullable is False

    revision_columns = recorder.metadata.tables["design_case_revisions"].columns
    assert "prior_revision_fingerprint" in revision_columns

    run_columns = recorder.metadata.tables["calculation_runs"].columns
    assert {
        "design_revision_fingerprint",
        "supersedes_run_fingerprint",
        "executor_id",
        "executor_version",
    }.issubset(run_columns.keys())
    assert "engine_version" not in run_columns

    case_indexes = _migration_index_contract(recorder, "design_cases")
    assert (
        CASE_REFERENCE_INDEX,
        True,
        ("lower(case_reference)",),
    ) in case_indexes


def test_offline_postgresql_upgrade_and_downgrade_are_dependency_ordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrade_sql = _offline_sql(
        "upgrade",
        f"{PARENT_REVISION}:{REVISION}",
        monkeypatch,
    )
    _assert_in_order(
        upgrade_sql,
        (
            "create table design_cases",
            "create unique index uq_design_cases_case_reference_ci",
            "create table design_case_revisions",
            "create table calculation_runs",
            "create function phase7_guard_design_case_head_update()",
            "create trigger trg_design_cases_identity_immutable",
            "create function phase7_validate_design_revision_chain()",
            "create trigger trg_design_case_revisions_chain_integrity",
            "create function phase7_validate_design_case_head()",
            "create constraint trigger trg_design_cases_head_integrity",
            "create function phase7_validate_inserted_revision_is_head()",
            "create constraint trigger trg_design_case_revisions_head_integrity",
            "create function phase7_validate_calculation_run_links()",
            "create trigger trg_calculation_runs_link_integrity",
            "create function phase7_reject_append_only_mutation()",
            "create trigger trg_design_case_revisions_append_only",
            "create trigger trg_calculation_runs_append_only",
        ),
    )
    for column_name in (
        "prior_revision_fingerprint",
        "design_revision_fingerprint",
        "supersedes_run_fingerprint",
        "executor_id",
        "executor_version",
    ):
        assert column_name in upgrade_sql
    assert "lower(case_reference)" in upgrade_sql
    assert "using errcode = '55000'" in upgrade_sql

    downgrade_sql = _offline_sql(
        "downgrade",
        f"{REVISION}:{PARENT_REVISION}",
        monkeypatch,
    )
    _assert_in_order(
        downgrade_sql,
        (
            "drop trigger trg_calculation_runs_append_only",
            "drop trigger trg_calculation_runs_link_integrity",
            "drop trigger trg_design_case_revisions_append_only",
            "drop trigger trg_design_case_revisions_head_integrity",
            "drop trigger trg_design_case_revisions_chain_integrity",
            "drop trigger trg_design_cases_head_integrity",
            "drop trigger trg_design_cases_identity_immutable",
            "drop function phase7_reject_append_only_mutation()",
            "drop function phase7_validate_calculation_run_links()",
            "drop function phase7_validate_inserted_revision_is_head()",
            "drop function phase7_validate_design_case_head()",
            "drop function phase7_validate_design_revision_chain()",
            "drop function phase7_guard_design_case_head_update()",
            "drop table calculation_runs",
            "drop table design_case_revisions",
            "drop index uq_design_cases_case_reference_ci",
            "drop table design_cases",
        ),
    )


def _configured_postgresql_url() -> URL:
    raw_url = (
        os.getenv("ENGINEER4ME_TEST_DATABASE_URL")
        or os.getenv("TEST_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or Config(str(ALEMBIC_INI)).get_main_option("sqlalchemy.url")
    )
    try:
        url = make_url(raw_url)
    except (ArgumentError, TypeError) as exc:
        pytest.skip(
            "Live PostgreSQL migration test unavailable: invalid database URL "
            f"({type(exc).__name__})."
        )
    if url.get_backend_name() != "postgresql":
        pytest.skip(
            "Live PostgreSQL migration test unavailable: configured database "
            "is not PostgreSQL."
        )
    return url


def _new_unoccupied_schema(connection: Connection) -> str:
    for _attempt in range(5):
        schema = f"e4m_step108_test_{uuid4().hex}"
        assert TEST_SCHEMA_PATTERN.fullmatch(schema)
        exists = connection.scalar(
            text(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = :name"
                ")"
            ),
            {"name": schema},
        )
        connection.commit()
        if not exists:
            return schema
    raise AssertionError("Could not allocate a unique Step 108 test schema.")


def _drop_exact_test_schema(
    connection: Connection,
    schema: str,
    quoted_schema: str,
) -> None:
    assert TEST_SCHEMA_PATTERN.fullmatch(schema)
    connection.rollback()
    connection.exec_driver_sql("SET search_path TO pg_catalog")
    exists = connection.scalar(
        text(
            "SELECT EXISTS ("
            "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = :name"
            ")"
        ),
        {"name": schema},
    )
    if exists:
        connection.exec_driver_sql(f"DROP SCHEMA {quoted_schema} CASCADE")
    connection.commit()
    exists = connection.scalar(
        text(
            "SELECT EXISTS ("
            "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = :name"
            ")"
        ),
        {"name": schema},
    )
    assert exists is False
    connection.commit()


def _cleanup_schema(
    connection: Connection,
    engine: Engine,
    schema: str,
    quoted_schema: str,
) -> None:
    assert TEST_SCHEMA_PATTERN.fullmatch(schema)
    if not connection.closed and not connection.invalidated:
        try:
            _drop_exact_test_schema(connection, schema, quoted_schema)
            return
        except (SQLAlchemyError, OSError):
            connection.close()

    with engine.connect() as fallback_connection:
        _drop_exact_test_schema(
            fallback_connection,
            schema,
            quoted_schema,
        )


@pytest.fixture()
def isolated_postgresql_schema() -> Iterator[_PostgresSandbox]:
    url = _configured_postgresql_url()
    try:
        engine = create_engine(
            url,
            poolclass=NullPool,
            connect_args={"connect_timeout": 3},
        )
        connection = engine.connect()
    except (SQLAlchemyError, OSError) as exc:
        if "engine" in locals():
            engine.dispose()
        pytest.skip(
            f"Live PostgreSQL migration test unavailable ({type(exc).__name__})."
        )

    schema = _new_unoccupied_schema(connection)
    quoted_schema = connection.dialect.identifier_preparer.quote(schema)
    created = False
    try:
        try:
            connection.exec_driver_sql(f"CREATE SCHEMA {quoted_schema}")
            connection.commit()
            created = True
        except DBAPIError as exc:
            connection.rollback()
            pytest.skip(
                "Live PostgreSQL migration test unavailable: cannot create "
                f"an isolated schema ({type(exc.orig).__name__})."
            )

        connection.exec_driver_sql(f"SET search_path TO {quoted_schema}, pg_catalog")
        connection.commit()
        assert connection.scalar(text("SELECT current_schema()")) == schema
        connection.commit()

        config = Config(str(ALEMBIC_INI))
        config.attributes["configure_logger"] = False
        config.attributes["connection"] = connection
        yield _PostgresSandbox(
            connection=connection,
            engine=engine,
            schema=schema,
            quoted_schema=quoted_schema,
            alembic_config=config,
        )
    finally:
        try:
            if created:
                _cleanup_schema(
                    connection,
                    engine,
                    schema,
                    quoted_schema,
                )
        finally:
            connection.close()
            engine.dispose()


def _phase_table_names(sandbox: _PostgresSandbox) -> set[str]:
    return set(inspect(sandbox.connection).get_table_names(schema=sandbox.schema))


def _alembic_revision(connection: Connection) -> str:
    revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
    assert isinstance(revision, str)
    connection.commit()
    return revision


def _trigger_names(sandbox: _PostgresSandbox) -> set[str]:
    names = sandbox.connection.scalars(
        text(
            "SELECT trigger.tgname "
            "FROM pg_catalog.pg_trigger AS trigger "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = trigger.tgrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = :schema "
            "AND NOT trigger.tgisinternal"
        ),
        {"schema": sandbox.schema},
    ).all()
    sandbox.connection.commit()
    return set(names)


def _function_names(sandbox: _PostgresSandbox) -> set[str]:
    names = sandbox.connection.scalars(
        text(
            "SELECT function.proname "
            "FROM pg_catalog.pg_proc AS function "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = function.pronamespace "
            "WHERE namespace.nspname = :schema "
        ),
        {"schema": sandbox.schema},
    ).all()
    sandbox.connection.commit()
    return set(names)


def _assert_live_schema_contract(sandbox: _PostgresSandbox) -> None:
    connection = sandbox.connection
    db_inspector = inspect(connection)
    assert set(PHASE_TABLES).issubset(_phase_table_names(sandbox))

    expected_constraints = {
        "design_cases": {
            "ck_design_cases_head_fingerprint_presence",
            "ck_design_cases_current_revision_positive",
            "ck_design_cases_concurrency_matches_revision",
            "ck_design_cases_timestamp_order",
            "uq_design_cases_case_reference",
        },
        "design_case_revisions": {
            "ck_design_case_revisions_prior_fingerprint_presence",
            "ck_design_case_revisions_prior_fingerprint",
            "uq_design_case_revisions_prior_revision",
        },
        "calculation_runs": {
            "ck_calculation_runs_revision_fingerprint_presence",
            "ck_calculation_runs_prior_fingerprint_presence",
            "ck_calculation_runs_revision_fingerprint",
            "ck_calculation_runs_prior_fingerprint",
            "uq_calculation_runs_supersedes_run_id",
        },
    }
    for table_name, expected_names in expected_constraints.items():
        names = {
            item["name"]
            for item in db_inspector.get_check_constraints(
                table_name,
                schema=sandbox.schema,
            )
        }
        names.update(
            item["name"]
            for item in db_inspector.get_unique_constraints(
                table_name,
                schema=sandbox.schema,
            )
        )
        assert expected_names.issubset(names)

    for table_name in ("design_case_revisions", "calculation_runs"):
        foreign_keys = db_inspector.get_foreign_keys(
            table_name,
            schema=sandbox.schema,
        )
        assert foreign_keys
        assert all(
            item.get("options", {}).get("ondelete") == "RESTRICT"
            for item in foreign_keys
        )

    index_definition = connection.scalar(
        text(
            "SELECT indexdef FROM pg_catalog.pg_indexes "
            "WHERE schemaname = :schema AND indexname = :index_name"
        ),
        {"schema": sandbox.schema, "index_name": CASE_REFERENCE_INDEX},
    )
    assert isinstance(index_definition, str)
    normalized_index = _normalize_sql(index_definition)
    assert "create unique index" in normalized_index
    assert "lower" in normalized_index
    assert "case_reference" in normalized_index
    connection.commit()

    assert _trigger_names(sandbox) == PHASE_TRIGGERS
    assert PHASE_FUNCTIONS.issubset(_function_names(sandbox))


def _expect_constraint_rejection(
    connection: Connection,
    statement: sa.TextClause,
    parameters: dict[str, object],
    constraint_name: str,
) -> None:
    with pytest.raises(IntegrityError) as captured:
        connection.execute(statement, parameters)
    connection.rollback()
    diagnostic = getattr(captured.value.orig, "diag", None)
    assert diagnostic is not None
    assert diagnostic.constraint_name == constraint_name


def _expect_append_only_rejection(
    connection: Connection,
    statement: sa.TextClause,
    parameters: dict[str, object],
) -> None:
    with pytest.raises(DBAPIError) as captured:
        connection.execute(statement, parameters)
    connection.rollback()
    sqlstate = getattr(captured.value.orig, "sqlstate", None)
    if sqlstate is None:
        sqlstate = getattr(captured.value.orig, "pgcode", None)
    assert sqlstate == "55000"
    assert "Engineer4Me append-only record mutation is not permitted." in str(
        captured.value.orig
    )


def _expect_sqlstate_rejection(
    connection: Connection,
    statement: sa.TextClause,
    parameters: dict[str, object],
    *,
    sqlstate: str,
    message: str,
) -> None:
    with pytest.raises(DBAPIError) as captured:
        connection.execute(statement, parameters)
    connection.rollback()
    actual_sqlstate = getattr(captured.value.orig, "sqlstate", None)
    if actual_sqlstate is None:
        actual_sqlstate = getattr(captured.value.orig, "pgcode", None)
    assert actual_sqlstate == sqlstate
    assert message in str(captured.value.orig)


def _expect_deferred_constraint_rejection(
    connection: Connection,
    statement: sa.TextClause,
    parameters: dict[str, object],
    constraint_name: str,
) -> None:
    connection.execute(statement, parameters)
    with pytest.raises(IntegrityError) as captured:
        connection.commit()
    connection.rollback()
    diagnostic = getattr(captured.value.orig, "diag", None)
    assert diagnostic is not None
    assert diagnostic.constraint_name == constraint_name


def _revision_parameters(
    *,
    revision_id: UUID,
    case_id: UUID,
    revision_number: int,
    prior_revision_id: UUID | None,
    prior_revision_fingerprint: str | None,
    revision_fingerprint: str,
) -> dict[str, object]:
    return {
        "id": revision_id,
        "design_case_id": case_id,
        "revision_number": revision_number,
        "prior_revision_id": prior_revision_id,
        "prior_revision_fingerprint": prior_revision_fingerprint,
        "change_reason": "Record controlled design evidence.",
        "payload_schema": "engineer4me.design-revision",
        "payload_version": "1.0.0",
        "snapshot": json.dumps({"title": "Isolated migration test"}),
        "source_origins": json.dumps([{"origin": "test"}]),
        "revision_fingerprint": revision_fingerprint,
        "created_by": "Migration contract test",
    }


def _run_parameters(
    *,
    run_id: UUID,
    revision_id: UUID,
    design_revision_fingerprint: str | None,
    supersedes_run_id: UUID | None = None,
    supersedes_run_fingerprint: str | None = None,
    run_kind: str = "calculation",
    calculation_type: str = "level-range",
    method_id: str = "level.hydrostatic.column-pressure",
    method_version: str = "1.0.0",
    executor_id: str = "calculation-engine",
    executor_version: str = "1.0.0",
) -> dict[str, object]:
    return {
        "id": run_id,
        "run_kind": run_kind,
        "design_case_revision_id": revision_id,
        "supersedes_run_id": supersedes_run_id,
        "design_revision_fingerprint": design_revision_fingerprint,
        "supersedes_run_fingerprint": supersedes_run_fingerprint,
        "calculation_type": calculation_type,
        "method_id": method_id,
        "method_version": method_version,
        "executor_id": executor_id,
        "executor_version": executor_version,
        "request_payload": json.dumps({"input": 1}),
        "result_payload": json.dumps({"result": 2}),
        "execution_metadata": json.dumps({"executor": "test"}),
    }


def _exercise_constraints_and_triggers(sandbox: _PostgresSandbox) -> None:
    connection = sandbox.connection
    schema = sandbox.quoted_schema
    case_id = uuid4()
    revision_id = uuid4()
    run_id = uuid4()
    revision_fingerprint = "1" * 64
    run_fingerprint = "4" * 64

    case_insert = text(
        f"""
        INSERT INTO {schema}.design_cases (
            id, case_reference, case_type, current_revision,
            current_revision_fingerprint, concurrency_version,
            created_by
        ) VALUES (
            :id, :case_reference, 'analyzer-application', 1,
            :revision_fingerprint, 1, 'Migration contract test'
        )
        """
    )
    revision_insert = text(
        f"""
        INSERT INTO {schema}.design_case_revisions (
            id, design_case_id, revision_number, prior_revision_id,
            prior_revision_fingerprint, change_reason, payload_schema,
            payload_version, snapshot, source_origins,
            revision_fingerprint, created_by
        ) VALUES (
            :id, :design_case_id, :revision_number, :prior_revision_id,
            :prior_revision_fingerprint, :change_reason, :payload_schema,
            :payload_version, CAST(:snapshot AS jsonb),
            CAST(:source_origins AS jsonb), :revision_fingerprint,
            :created_by
        )
        """
    )
    connection.execute(
        case_insert,
        {
            "id": case_id,
            "case_reference": "STEP108-ISOLATED-CASE",
            "revision_fingerprint": revision_fingerprint,
        },
    )
    connection.execute(
        revision_insert,
        _revision_parameters(
            revision_id=revision_id,
            case_id=case_id,
            revision_number=1,
            prior_revision_id=None,
            prior_revision_fingerprint=None,
            revision_fingerprint=revision_fingerprint,
        ),
    )
    connection.commit()

    _expect_constraint_rejection(
        connection,
        text(
            f"""
            INSERT INTO {schema}.design_cases (
                id, case_reference, case_type, current_revision,
                current_revision_fingerprint, concurrency_version, created_by
            ) VALUES (
                :id, :case_reference, 'analyzer-application', 1,
                :revision_fingerprint, 1,
                'Migration contract test'
            )
            """
        ),
        {
            "id": uuid4(),
            "case_reference": "step108-isolated-case",
            "revision_fingerprint": "7" * 64,
        },
        CASE_REFERENCE_INDEX,
    )

    invalid_case_insert = text(
        f"""
        INSERT INTO {schema}.design_cases (
            id, case_reference, case_type, current_revision,
            current_revision_fingerprint, concurrency_version,
            created_by, created_at, updated_at
        ) VALUES (
            :id, :case_reference, 'analyzer-application',
            :current_revision, :revision_fingerprint,
            :concurrency_version, 'Migration contract test',
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + :updated_offset
        )
        """
    )
    with pytest.raises(IntegrityError) as revision_zero_error:
        connection.execute(
            invalid_case_insert,
            {
                "id": uuid4(),
                "case_reference": "STEP108-REVISION-ZERO",
                "current_revision": 0,
                "revision_fingerprint": "7" * 64,
                "concurrency_version": 1,
                "updated_offset": timedelta(0),
            },
        )
    connection.rollback()
    revision_zero_diagnostic = getattr(revision_zero_error.value.orig, "diag")
    assert revision_zero_diagnostic.constraint_name in {
        "ck_design_cases_current_revision_positive",
        "ck_design_cases_concurrency_matches_revision",
    }

    _expect_constraint_rejection(
        connection,
        invalid_case_insert,
        {
            "id": uuid4(),
            "case_reference": "STEP108-CONCURRENCY-MISMATCH",
            "current_revision": 1,
            "revision_fingerprint": "7" * 64,
            "concurrency_version": 2,
            "updated_offset": timedelta(0),
        },
        "ck_design_cases_concurrency_matches_revision",
    )
    _expect_constraint_rejection(
        connection,
        invalid_case_insert,
        {
            "id": uuid4(),
            "case_reference": "STEP108-TIMESTAMP-ORDER",
            "current_revision": 1,
            "revision_fingerprint": "7" * 64,
            "concurrency_version": 1,
            "updated_offset": -timedelta(seconds=1),
        },
        "ck_design_cases_timestamp_order",
    )

    invalid_revision = _revision_parameters(
        revision_id=uuid4(),
        case_id=case_id,
        revision_number=2,
        prior_revision_id=revision_id,
        prior_revision_fingerprint=None,
        revision_fingerprint="2" * 64,
    )
    _expect_constraint_rejection(
        connection,
        revision_insert,
        invalid_revision,
        "ck_design_case_revisions_prior_fingerprint_presence",
    )

    other_case_id = uuid4()
    other_revision_id = uuid4()
    other_revision_fingerprint = "8" * 64
    connection.execute(
        case_insert,
        {
            "id": other_case_id,
            "case_reference": "STEP108-OTHER-CASE",
            "revision_fingerprint": other_revision_fingerprint,
        },
    )
    connection.execute(
        revision_insert,
        _revision_parameters(
            revision_id=other_revision_id,
            case_id=other_case_id,
            revision_number=1,
            prior_revision_id=None,
            prior_revision_fingerprint=None,
            revision_fingerprint=other_revision_fingerprint,
        ),
    )
    connection.commit()

    coherent_chain_constraint = "ck_design_case_revisions_coherent_chain"
    for invalid_chain in (
        _revision_parameters(
            revision_id=uuid4(),
            case_id=case_id,
            revision_number=2,
            prior_revision_id=other_revision_id,
            prior_revision_fingerprint=other_revision_fingerprint,
            revision_fingerprint="2" * 64,
        ),
        _revision_parameters(
            revision_id=uuid4(),
            case_id=case_id,
            revision_number=3,
            prior_revision_id=revision_id,
            prior_revision_fingerprint=revision_fingerprint,
            revision_fingerprint="3" * 64,
        ),
        _revision_parameters(
            revision_id=uuid4(),
            case_id=case_id,
            revision_number=2,
            prior_revision_id=revision_id,
            prior_revision_fingerprint="f" * 64,
            revision_fingerprint="2" * 64,
        ),
    ):
        _expect_constraint_rejection(
            connection,
            revision_insert,
            invalid_chain,
            coherent_chain_constraint,
        )

    _expect_sqlstate_rejection(
        connection,
        text(
            f"UPDATE {schema}.design_cases "
            "SET case_reference = 'FORGED-IDENTITY' WHERE id = :id"
        ),
        {"id": case_id},
        sqlstate="55000",
        message="Engineer4Me design-case identity is immutable.",
    )

    _expect_deferred_constraint_rejection(
        connection,
        text(
            f"""
            UPDATE {schema}.design_cases
            SET current_revision = 2,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """
        ),
        {"id": case_id, "fingerprint": "9" * 64},
        "ck_design_cases_head_resolves_revision",
    )

    orphan_revision = _revision_parameters(
        revision_id=uuid4(),
        case_id=case_id,
        revision_number=2,
        prior_revision_id=revision_id,
        prior_revision_fingerprint=revision_fingerprint,
        revision_fingerprint="2" * 64,
    )
    _expect_deferred_constraint_rejection(
        connection,
        revision_insert,
        orphan_revision,
        "ck_design_case_revisions_committed_head",
    )

    timestamp_mismatch_fingerprint = "6" * 64
    connection.execute(
        text(
            f"""
            UPDATE {schema}.design_cases
            SET current_revision = 2,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 2,
                updated_at = CURRENT_TIMESTAMP + INTERVAL '1 second'
            WHERE id = :id
            """
        ),
        {"id": case_id, "fingerprint": timestamp_mismatch_fingerprint},
    )
    connection.execute(
        revision_insert,
        _revision_parameters(
            revision_id=uuid4(),
            case_id=case_id,
            revision_number=2,
            prior_revision_id=revision_id,
            prior_revision_fingerprint=revision_fingerprint,
            revision_fingerprint=timestamp_mismatch_fingerprint,
        ),
    )
    with pytest.raises(IntegrityError) as timestamp_mismatch_error:
        connection.commit()
    connection.rollback()
    timestamp_diagnostic = getattr(timestamp_mismatch_error.value.orig, "diag")
    assert (
        timestamp_diagnostic.constraint_name == "ck_design_cases_head_resolves_revision"
    )

    revision_two_id = uuid4()
    revision_two_fingerprint = "2" * 64
    connection.execute(
        revision_insert,
        _revision_parameters(
            revision_id=revision_two_id,
            case_id=case_id,
            revision_number=2,
            prior_revision_id=revision_id,
            prior_revision_fingerprint=revision_fingerprint,
            revision_fingerprint=revision_two_fingerprint,
        ),
    )
    connection.execute(
        text(
            f"""
            UPDATE {schema}.design_cases
            SET current_revision = 2,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            """
        ),
        {"id": case_id, "fingerprint": revision_two_fingerprint},
    )
    connection.commit()

    invalid_linked_run = _run_parameters(
        run_id=uuid4(),
        revision_id=revision_id,
        design_revision_fingerprint=None,
    )
    run_insert = text(
        f"""
        INSERT INTO {schema}.calculation_runs (
            id, run_kind, design_case_revision_id, supersedes_run_id,
            design_revision_fingerprint, supersedes_run_fingerprint,
            calculation_type, method_id, method_version, executor_id,
            executor_version, status, request_schema, result_schema,
            request_payload, result_payload, execution_metadata,
            input_fingerprint, result_fingerprint, run_fingerprint,
            canonicalization, created_by, executed_at
        ) VALUES (
            :id, :run_kind, :design_case_revision_id,
            :supersedes_run_id, :design_revision_fingerprint,
            :supersedes_run_fingerprint, :calculation_type,
            :method_id, :method_version,
            :executor_id, :executor_version, 'completed',
            'engineer4me.calculation-request',
            'engineer4me.calculation-result',
            CAST(:request_payload AS jsonb),
            CAST(:result_payload AS jsonb),
            CAST(:execution_metadata AS jsonb),
            :input_fingerprint, :result_fingerprint, :run_fingerprint,
            'json-c14n-v1', 'Migration contract test', :executed_at
        )
        """
    )
    common_run_values: dict[str, object] = {
        "input_fingerprint": "a" * 64,
        "result_fingerprint": "b" * 64,
        "run_fingerprint": run_fingerprint,
        "executed_at": datetime(2026, 8, 2, 12, 0, tzinfo=UTC),
    }
    _expect_constraint_rejection(
        connection,
        run_insert,
        {**invalid_linked_run, **common_run_values},
        "ck_calculation_runs_revision_fingerprint_presence",
    )
    tampered_revision_link = _run_parameters(
        run_id=uuid4(),
        revision_id=revision_id,
        design_revision_fingerprint="f" * 64,
    )
    _expect_constraint_rejection(
        connection,
        run_insert,
        {**tampered_revision_link, **common_run_values},
        "ck_calculation_runs_coherent_links",
    )

    valid_run = _run_parameters(
        run_id=run_id,
        revision_id=revision_id,
        design_revision_fingerprint=revision_fingerprint,
    )
    connection.execute(run_insert, {**valid_run, **common_run_values})
    connection.commit()

    invalid_successor = _run_parameters(
        run_id=uuid4(),
        revision_id=revision_id,
        design_revision_fingerprint=revision_fingerprint,
        supersedes_run_id=run_id,
        supersedes_run_fingerprint=None,
    )
    _expect_constraint_rejection(
        connection,
        run_insert,
        {
            **invalid_successor,
            **common_run_values,
            "run_fingerprint": "5" * 64,
        },
        "ck_calculation_runs_prior_fingerprint_presence",
    )

    invalid_lineages = (
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint="f" * 64,
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            run_kind="analyzer_assessment",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            calculation_type="other-calculation",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            method_id="other.method",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            method_version="2.0.0",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            executor_id="other-executor",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=revision_two_id,
            design_revision_fingerprint=revision_two_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
            executor_version="2.0.0",
        ),
        _run_parameters(
            run_id=uuid4(),
            revision_id=other_revision_id,
            design_revision_fingerprint=other_revision_fingerprint,
            supersedes_run_id=run_id,
            supersedes_run_fingerprint=run_fingerprint,
        ),
    )
    for invalid_lineage in invalid_lineages:
        _expect_constraint_rejection(
            connection,
            run_insert,
            {
                **invalid_lineage,
                **common_run_values,
                "run_fingerprint": "5" * 64,
            },
            "ck_calculation_runs_coherent_links",
        )

    valid_successor = _run_parameters(
        run_id=uuid4(),
        revision_id=revision_two_id,
        design_revision_fingerprint=revision_two_fingerprint,
        supersedes_run_id=run_id,
        supersedes_run_fingerprint=run_fingerprint,
    )
    connection.execute(
        run_insert,
        {
            **valid_successor,
            **common_run_values,
            "run_fingerprint": "5" * 64,
        },
    )
    connection.commit()

    _expect_constraint_rejection(
        connection,
        text(f"DELETE FROM {schema}.design_cases WHERE id = :id"),
        {"id": case_id},
        "fk_design_case_revisions_design_case_id",
    )

    for statement, parameters in (
        (
            text(
                f"UPDATE {schema}.design_case_revisions "
                "SET change_reason = 'Forbidden update' WHERE id = :id"
            ),
            {"id": revision_id},
        ),
        (
            text(f"DELETE FROM {schema}.design_case_revisions WHERE id = :id"),
            {"id": revision_id},
        ),
        (
            text(
                f"UPDATE {schema}.calculation_runs "
                "SET status = 'blocked' WHERE id = :id"
            ),
            {"id": run_id},
        ),
        (
            text(f"DELETE FROM {schema}.calculation_runs WHERE id = :id"),
            {"id": run_id},
        ),
    ):
        _expect_append_only_rejection(connection, statement, parameters)


def test_postgresql_concurrent_revision_cas_and_run_branch_have_one_winner(
    isolated_postgresql_schema: _PostgresSandbox,
) -> None:
    """Two real sessions cannot create competing revision or run branches."""

    sandbox = isolated_postgresql_schema
    command.upgrade(sandbox.alembic_config, REVISION)
    sandbox.connection.commit()
    schema = sandbox.quoted_schema
    case_id = uuid4()
    revision_id = uuid4()
    revision_fingerprint = "1" * 64

    sandbox.connection.execute(
        text(
            f"""
            INSERT INTO {schema}.design_cases (
                id, case_reference, case_type, current_revision,
                current_revision_fingerprint, concurrency_version,
                created_by
            ) VALUES (
                :id, 'STEP108-CONCURRENT-CASE', 'analyzer-application',
                1, :fingerprint, 1, 'Concurrent migration test'
            )
            """
        ),
        {"id": case_id, "fingerprint": revision_fingerprint},
    )
    revision_insert = text(
        f"""
        INSERT INTO {schema}.design_case_revisions (
            id, design_case_id, revision_number, prior_revision_id,
            prior_revision_fingerprint, change_reason, payload_schema,
            payload_version, snapshot, source_origins,
            revision_fingerprint, created_by
        ) VALUES (
            :id, :design_case_id, :revision_number, :prior_revision_id,
            :prior_revision_fingerprint, :change_reason, :payload_schema,
            :payload_version, CAST(:snapshot AS jsonb),
            CAST(:source_origins AS jsonb), :revision_fingerprint,
            :created_by
        )
        """
    )
    sandbox.connection.execute(
        revision_insert,
        _revision_parameters(
            revision_id=revision_id,
            case_id=case_id,
            revision_number=1,
            prior_revision_id=None,
            prior_revision_fingerprint=None,
            revision_fingerprint=revision_fingerprint,
        ),
    )
    sandbox.connection.commit()

    revision_barrier = Barrier(2)

    def append_competing_revision(
        successor_id: UUID,
        successor_fingerprint: str,
    ) -> str:
        with Session(sandbox.engine) as session:
            try:
                session.execute(text(f"SET LOCAL search_path TO {schema}, pg_catalog"))
                revision_barrier.wait(timeout=10)
                session.execute(
                    revision_insert,
                    _revision_parameters(
                        revision_id=successor_id,
                        case_id=case_id,
                        revision_number=2,
                        prior_revision_id=revision_id,
                        prior_revision_fingerprint=revision_fingerprint,
                        revision_fingerprint=successor_fingerprint,
                    ),
                )
                updated = session.execute(
                    text(
                        f"""
                        UPDATE {schema}.design_cases
                        SET current_revision = 2,
                            current_revision_fingerprint = :fingerprint,
                            concurrency_version = 2,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = :case_id
                          AND current_revision = 1
                          AND current_revision_fingerprint = :prior_fingerprint
                          AND concurrency_version = 1
                        """
                    ),
                    {
                        "case_id": case_id,
                        "fingerprint": successor_fingerprint,
                        "prior_fingerprint": revision_fingerprint,
                    },
                )
                if updated.rowcount != 1:
                    session.rollback()
                    return "conflict"
                session.commit()
                return "committed"
            except DBAPIError:
                session.rollback()
                return "conflict"

    competing_revisions = (
        (uuid4(), "2" * 64),
        (uuid4(), "3" * 64),
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(
            executor.submit(append_competing_revision, *candidate)
            for candidate in competing_revisions
        )
        revision_outcomes = tuple(future.result(timeout=20) for future in futures)
    assert sorted(revision_outcomes) == ["committed", "conflict"]

    winning_revision = sandbox.connection.execute(
        text(
            f"""
            SELECT id, revision_fingerprint
            FROM {schema}.design_case_revisions
            WHERE design_case_id = :case_id AND revision_number = 2
            """
        ),
        {"case_id": case_id},
    ).one()
    assert (
        sandbox.connection.scalar(
            text(
                f"SELECT count(*) FROM {schema}.design_case_revisions "
                "WHERE design_case_id = :case_id"
            ),
            {"case_id": case_id},
        )
        == 2
    )
    sandbox.connection.commit()

    root_run_id = uuid4()
    root_run_fingerprint = "4" * 64
    run_insert = text(
        f"""
        INSERT INTO {schema}.calculation_runs (
            id, run_kind, design_case_revision_id, supersedes_run_id,
            design_revision_fingerprint, supersedes_run_fingerprint,
            calculation_type, method_id, method_version, executor_id,
            executor_version, status, request_schema, result_schema,
            request_payload, result_payload, execution_metadata,
            input_fingerprint, result_fingerprint, run_fingerprint,
            canonicalization, created_by, executed_at
        ) VALUES (
            :id, :run_kind, :design_case_revision_id,
            :supersedes_run_id, :design_revision_fingerprint,
            :supersedes_run_fingerprint, :calculation_type,
            :method_id, :method_version, :executor_id, :executor_version,
            'completed', 'engineer4me.calculation-request',
            'engineer4me.calculation-result', CAST(:request_payload AS jsonb),
            CAST(:result_payload AS jsonb), CAST(:execution_metadata AS jsonb),
            :input_fingerprint, :result_fingerprint, :run_fingerprint,
            'json-c14n-v1', 'Concurrent migration test', :executed_at
        )
        """
    )
    root_parameters = {
        **_run_parameters(
            run_id=root_run_id,
            revision_id=revision_id,
            design_revision_fingerprint=revision_fingerprint,
        ),
        "input_fingerprint": "a" * 64,
        "result_fingerprint": "b" * 64,
        "run_fingerprint": root_run_fingerprint,
        "executed_at": datetime(2026, 8, 2, 13, 0, tzinfo=UTC),
    }
    sandbox.connection.execute(run_insert, root_parameters)
    sandbox.connection.commit()

    run_barrier = Barrier(2)

    def append_competing_run(
        successor_id: UUID,
        successor_fingerprint: str,
    ) -> str:
        with Session(sandbox.engine) as session:
            try:
                session.execute(text(f"SET LOCAL search_path TO {schema}, pg_catalog"))
                run_barrier.wait(timeout=10)
                parameters = {
                    **_run_parameters(
                        run_id=successor_id,
                        revision_id=winning_revision.id,
                        design_revision_fingerprint=(
                            winning_revision.revision_fingerprint
                        ),
                        supersedes_run_id=root_run_id,
                        supersedes_run_fingerprint=root_run_fingerprint,
                    ),
                    "input_fingerprint": "c" * 64,
                    "result_fingerprint": "d" * 64,
                    "run_fingerprint": successor_fingerprint,
                    "executed_at": datetime(
                        2026,
                        8,
                        2,
                        13,
                        1,
                        tzinfo=UTC,
                    ),
                }
                session.execute(run_insert, parameters)
                session.commit()
                return "committed"
            except DBAPIError:
                session.rollback()
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(
            executor.submit(append_competing_run, uuid4(), fingerprint)
            for fingerprint in ("5" * 64, "6" * 64)
        )
        run_outcomes = tuple(future.result(timeout=20) for future in futures)
    assert sorted(run_outcomes) == ["committed", "conflict"]
    assert (
        sandbox.connection.scalar(
            text(f"SELECT count(*) FROM {schema}.calculation_runs")
        )
        == 2
    )
    sandbox.connection.commit()


def test_postgresql_isolated_upgrade_constraints_triggers_and_round_trip(
    isolated_postgresql_schema: _PostgresSandbox,
) -> None:
    sandbox = isolated_postgresql_schema
    connection = sandbox.connection
    config = sandbox.alembic_config

    command.upgrade(config, PARENT_REVISION)
    connection.commit()
    assert set(PHASE_TABLES).isdisjoint(_phase_table_names(sandbox))
    connection.commit()
    assert _alembic_revision(connection) == PARENT_REVISION

    command.upgrade(config, REVISION)
    connection.commit()
    assert _alembic_revision(connection) == REVISION
    _assert_live_schema_contract(sandbox)
    _exercise_constraints_and_triggers(sandbox)

    command.downgrade(config, PARENT_REVISION)
    connection.commit()
    remaining_tables = _phase_table_names(sandbox)
    assert set(PHASE_TABLES).isdisjoint(remaining_tables)
    assert "manufacturers" in remaining_tables
    connection.commit()
    assert _alembic_revision(connection) == PARENT_REVISION
    assert PHASE_FUNCTIONS.isdisjoint(_function_names(sandbox))

    command.upgrade(config, REVISION)
    connection.commit()
    assert _alembic_revision(connection) == REVISION
    _assert_live_schema_contract(sandbox)

    command.downgrade(config, PARENT_REVISION)
    connection.commit()
    assert set(PHASE_TABLES).isdisjoint(_phase_table_names(sandbox))
    connection.commit()
    assert _alembic_revision(connection) == PARENT_REVISION
    assert PHASE_FUNCTIONS.isdisjoint(_function_names(sandbox))
