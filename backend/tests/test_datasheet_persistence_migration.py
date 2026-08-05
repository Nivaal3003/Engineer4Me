"""Static and offline contract tests for the Step 110 datasheet migration."""

from __future__ import annotations

import importlib.util
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.sql.schema import Column

import app.models  # noqa: F401
from app.db.database import Base
from test_design_persistence_migration import (
    _PostgresSandbox,
    _alembic_revision,
    _revision_parameters,
    isolated_postgresql_schema,  # noqa: F401
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
MIGRATION_PATH = (
    BACKEND_ROOT
    / "alembic"
    / "versions"
    / "b7f110e3d2a1_add_phase7_datasheet_persistence.py"
)
REVISION = "b7f110e3d2a1"
PARENT_REVISION = "a7f108d9c2e1"
TABLES = (
    "engineering_datasheets",
    "engineering_datasheet_revisions",
    "engineering_datasheet_calculation_links",
)
FUNCTIONS = {
    "phase7_110_guard_datasheet_head_update",
    "phase7_110_validate_datasheet_revision",
    "phase7_110_validate_datasheet_head",
    "phase7_110_validate_inserted_datasheet_revision",
    "phase7_110_validate_datasheet_calculation_link",
    "phase7_110_validate_datasheet_link_projection",
    "phase7_110_reject_datasheet_mutation",
}
TRIGGERS = {
    "trg_engineering_datasheets_identity_immutable",
    "trg_engineering_datasheets_head_integrity",
    "trg_engineering_datasheets_delete_prohibited",
    "trg_engineering_datasheet_revisions_integrity",
    "trg_engineering_datasheet_revisions_head",
    "trg_engineering_datasheet_revisions_append_only",
    "trg_engineering_datasheet_calculation_links_integrity",
    "trg_engineering_datasheet_revisions_link_projection",
    "trg_engineering_datasheet_calculation_links_projection",
    "trg_engineering_datasheet_calculation_links_append_only",
}
POSTGRES_DIALECT = postgresql.dialect()


@dataclass(frozen=True)
class _RecordedIndex:
    name: str
    table_name: str
    expressions: tuple[object, ...]
    unique: bool


class _MigrationRecorder:
    def __init__(self) -> None:
        self.metadata = sa.MetaData()
        self.indexes: list[_RecordedIndex] = []
        self.executed_sql: list[str] = []

    def create_table(self, name: str, *items: object, **kwargs: object):
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
            _RecordedIndex(name, table_name, tuple(expressions), unique)
        )

    def execute(self, statement: object, *_args: object, **_kwargs: object) -> None:
        self.executed_sql.append(str(statement))


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_step110_datasheet_migration_contract",
        MIGRATION_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _recorded_migration() -> tuple[ModuleType, _MigrationRecorder]:
    migration = _load_migration()
    recorder = _MigrationRecorder()
    migration.op = recorder
    migration.upgrade()
    return migration, recorder


def _normalize(value: object) -> str:
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
    return _normalize(argument)


def _columns(table: sa.Table) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            column.name,
            str(column.type.compile(dialect=POSTGRES_DIALECT)),
            column.nullable,
            _server_default(column),
        )
        for column in table.columns
    )


def _constraint(constraint: sa.Constraint) -> tuple[object, ...]:
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
        return ("check", constraint.name, _normalize(constraint.sqltext))
    if isinstance(constraint, sa.ForeignKeyConstraint):
        return (
            "foreign-key",
            constraint.name,
            tuple(item.parent.name for item in constraint.elements),
            tuple(item.target_fullname for item in constraint.elements),
            constraint.ondelete,
        )
    raise AssertionError(type(constraint))


def _constraints(table: sa.Table) -> set[tuple[object, ...]]:
    return {_constraint(item) for item in table.constraints}


def _index_expression(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Column):
        return value.name
    if hasattr(value, "compile"):
        value = value.compile(dialect=POSTGRES_DIALECT)
    return _normalize(value)


def _model_indexes(table: sa.Table) -> set[tuple[object, ...]]:
    return {
        (
            index.name,
            bool(index.unique),
            tuple(_index_expression(value) for value in index.expressions),
        )
        for index in table.indexes
    }


def _migration_indexes(
    recorder: _MigrationRecorder,
    table_name: str,
) -> set[tuple[object, ...]]:
    return {
        (
            index.name,
            index.unique,
            tuple(_index_expression(value) for value in index.expressions),
        )
        for index in recorder.indexes
        if index.table_name == table_name
    }


def _offline(action: str, revision_range: str) -> str:
    output = io.StringIO()
    config = Config(str(ALEMBIC_INI), output_buffer=output)
    config.attributes["configure_logger"] = False
    if action == "upgrade":
        command.upgrade(config, revision_range, sql=True)
    else:
        command.downgrade(config, revision_range, sql=True)
    return _normalize(output.getvalue())


def _assert_order(sql: str, fragments: tuple[str, ...]) -> None:
    positions = []
    for fragment in fragments:
        normalized = _normalize(fragment)
        assert normalized in sql
        positions.append(sql.index(normalized))
    assert positions == sorted(positions)


def test_step110_is_the_single_alembic_head() -> None:
    scripts = ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))
    assert scripts.get_heads() == [REVISION]
    current = scripts.get_revision(REVISION)
    assert current is not None
    assert current.down_revision == PARENT_REVISION
    assert current.nextrev == frozenset()


def test_migration_and_orm_have_exact_postgresql_parity() -> None:
    migration, recorder = _recorded_migration()
    assert migration.revision == REVISION
    assert migration.down_revision == PARENT_REVISION
    assert tuple(recorder.metadata.tables) == TABLES
    for table_name in TABLES:
        model = Base.metadata.tables[table_name]
        migrated = recorder.metadata.tables[table_name]
        assert _columns(model) == _columns(migrated)
        assert _constraints(model) == _constraints(migrated)
        assert _model_indexes(model) == _migration_indexes(
            recorder,
            table_name,
        )


def test_trigger_contract_is_complete_and_fail_closed() -> None:
    _, recorder = _recorded_migration()
    sql = _normalize("\n".join(recorder.executed_sql))
    for function in FUNCTIONS:
        assert f"create function {function}()" in sql
    for trigger in TRIGGERS:
        assert f"create trigger {trigger}" in sql or (
            f"create constraint trigger {trigger}" in sql
        )
    assert "deferrable initially deferred" in sql
    assert "before update or delete on engineering_datasheet_revisions" in sql
    assert "before update or delete on engineering_datasheet_calculation_links" in sql
    assert "before delete on engineering_datasheets" in sql
    assert "run.result_payload -> 'outputs'" in sql
    assert "link_evidence -> 'output' is distinct from output_evidence" in sql
    assert "is distinct from 'true'::jsonb" in sql
    assert "is distinct from 'false'::jsonb" in sql
    assert "ck_engineering_datasheet_links_projected" in sql
    assert "new.design_revision_number < predecessor.design_revision_number" in sql
    assert "on delete cascade" not in sql


def test_offline_upgrade_and_downgrade_are_dependency_ordered() -> None:
    upgrade = _offline("upgrade", f"{PARENT_REVISION}:{REVISION}")
    _assert_order(
        upgrade,
        (
            "create table engineering_datasheets",
            "create table engineering_datasheet_revisions",
            "create table engineering_datasheet_calculation_links",
            "create function phase7_110_guard_datasheet_head_update()",
            "create function phase7_110_validate_datasheet_revision()",
            "create function phase7_110_validate_datasheet_head()",
            "create function phase7_110_validate_datasheet_calculation_link()",
            "create function phase7_110_validate_datasheet_link_projection()",
            "create function phase7_110_reject_datasheet_mutation()",
            "update alembic_version set version_num='b7f110e3d2a1'",
        ),
    )
    downgrade = _offline("downgrade", f"{REVISION}:{PARENT_REVISION}")
    _assert_order(
        downgrade,
        (
            "drop trigger trg_engineering_datasheet_calculation_links_append_only",
            "drop function phase7_110_reject_datasheet_mutation()",
            "drop table engineering_datasheet_calculation_links",
            "drop table engineering_datasheet_revisions",
            "drop table engineering_datasheets",
            "update alembic_version set version_num='a7f108d9c2e1'",
        ),
    )


def test_migration_uses_only_restrictive_foreign_keys() -> None:
    _, recorder = _recorded_migration()
    foreign_keys = [
        constraint
        for table in recorder.metadata.tables.values()
        for constraint in table.constraints
        if isinstance(constraint, sa.ForeignKeyConstraint)
    ]
    assert len(foreign_keys) == 6
    assert all(item.ondelete == "RESTRICT" for item in foreign_keys)


def test_postgresql_step110_triggers_and_round_trip(
    isolated_postgresql_schema: _PostgresSandbox,  # noqa: F811
) -> None:
    """Execute the Step 110 PL/pgSQL contract in an isolated schema."""

    sandbox = isolated_postgresql_schema
    connection = sandbox.connection
    schema = sandbox.quoted_schema
    config = sandbox.alembic_config
    command.upgrade(config, PARENT_REVISION)
    assert _alembic_revision(connection) == PARENT_REVISION
    command.upgrade(config, REVISION)
    assert _alembic_revision(connection) == REVISION

    table_names = set(sa.inspect(connection).get_table_names(schema=sandbox.schema))
    assert set(TABLES).issubset(table_names)
    trigger_names = set(
        connection.scalars(
            sa.text(
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
    )
    assert TRIGGERS.issubset(trigger_names)
    connection.commit()

    case_id = uuid4()
    design_revision_1 = uuid4()
    design_fingerprint_1 = "1" * 64
    created_at = datetime(2026, 8, 2, 15, 0, tzinfo=UTC)
    case_insert = sa.text(
        f"""
        INSERT INTO {schema}.design_cases (
            id, case_reference, case_type, current_revision,
            current_revision_fingerprint, concurrency_version,
            created_by, created_at, updated_at
        ) VALUES (
            :id, :case_reference, 'datasheet-migration-test', 1,
            :fingerprint, 1, 'Step 110 migration test',
            :created_at, :created_at
        )
        """
    )
    design_revision_insert = sa.text(
        f"""
        INSERT INTO {schema}.design_case_revisions (
            id, design_case_id, revision_number, prior_revision_id,
            prior_revision_fingerprint, change_reason, payload_schema,
            payload_version, snapshot, source_origins,
            revision_fingerprint, created_by, created_at
        ) VALUES (
            :id, :design_case_id, :revision_number, :prior_revision_id,
            :prior_revision_fingerprint, :change_reason, :payload_schema,
            :payload_version, CAST(:snapshot AS jsonb),
            CAST(:source_origins AS jsonb), :revision_fingerprint,
            :created_by, :created_at
        )
        """
    )
    connection.execute(
        case_insert,
        {
            "id": case_id,
            "case_reference": "STEP110-LIVE-DATASHEET",
            "fingerprint": design_fingerprint_1,
            "created_at": created_at,
        },
    )
    connection.execute(
        design_revision_insert,
        {
            **_revision_parameters(
                revision_id=design_revision_1,
                case_id=case_id,
                revision_number=1,
                prior_revision_id=None,
                prior_revision_fingerprint=None,
                revision_fingerprint=design_fingerprint_1,
            ),
            "created_at": created_at,
        },
    )
    connection.commit()

    datasheet_id = uuid4()
    datasheet_revision_1 = uuid4()
    datasheet_fingerprint_1 = "2" * 64
    datasheet_insert = sa.text(
        f"""
        INSERT INTO {schema}.engineering_datasheets (
            id, design_case_id, template_id, template_version,
            template_fingerprint, current_revision,
            current_revision_fingerprint, concurrency_version,
            created_by, created_at, updated_at
        ) VALUES (
            :id, :design_case_id, 'instrument.pressure-transmitter',
            '1.0.0', :template_fingerprint, :current_revision,
            :revision_fingerprint, :current_revision,
            'Step 110 migration test', :created_at, :created_at
        )
        """
    )
    datasheet_revision_insert = sa.text(
        f"""
        INSERT INTO {schema}.engineering_datasheet_revisions (
            id, datasheet_id, design_case_revision_id,
            design_revision_number, design_revision_fingerprint,
            revision_number, prior_revision_id,
            prior_revision_fingerprint, snapshot_schema,
            snapshot_version, snapshot, export_descriptor,
            json_artifact, workbook_artifact,
            revision_fingerprint, change_reason, lifecycle_state,
            completeness_state, ready_for_review, created_by, created_at
        ) VALUES (
            :id, :datasheet_id, :design_case_revision_id,
            :design_revision_number, :design_revision_fingerprint,
            :revision_number, :prior_revision_id,
            :prior_revision_fingerprint,
            'engineer4me.datasheet.revision-snapshot.v1', '1.0.0',
            CAST(:snapshot AS jsonb), CAST(:export_descriptor AS jsonb),
            :json_artifact, :workbook_artifact,
            :revision_fingerprint, :change_reason, 'draft', 'blocked',
            false, 'Step 110 migration test', :created_at
        )
        """
    )

    def revision_values(
        *,
        revision_id: object,
        revision_number: int,
        revision_fingerprint: str,
        prior_id: object | None,
        prior_fingerprint: str | None,
        design_revision_id: object = design_revision_1,
        design_revision_number: int = 1,
        design_revision_fingerprint: str = design_fingerprint_1,
        calculation_links: list[dict[str, object]] | None = None,
        timestamp: datetime = created_at,
    ) -> dict[str, object]:
        return {
            "id": revision_id,
            "datasheet_id": datasheet_id,
            "design_case_revision_id": design_revision_id,
            "design_revision_number": design_revision_number,
            "design_revision_fingerprint": design_revision_fingerprint,
            "revision_number": revision_number,
            "prior_revision_id": prior_id,
            "prior_revision_fingerprint": prior_fingerprint,
            "snapshot": json.dumps(
                {"content": {"calculation_links": calculation_links or []}}
            ),
            "export_descriptor": json.dumps(
                {"schema_id": "engineer4me.datasheet.export.v1"}
            ),
            "json_artifact": b"{}",
            "workbook_artifact": b"PK-step110-migration-fixture",
            "revision_fingerprint": revision_fingerprint,
            "change_reason": f"Create datasheet revision {revision_number}.",
            "created_at": timestamp,
        }

    connection.execute(
        datasheet_insert,
        {
            "id": datasheet_id,
            "design_case_id": case_id,
            "template_fingerprint": "3" * 64,
            "current_revision": 1,
            "revision_fingerprint": datasheet_fingerprint_1,
            "created_at": created_at,
        },
    )
    connection.execute(
        datasheet_revision_insert,
        revision_values(
            revision_id=datasheet_revision_1,
            revision_number=1,
            revision_fingerprint=datasheet_fingerprint_1,
            prior_id=None,
            prior_fingerprint=None,
        ),
    )
    connection.commit()

    with pytest.raises(DBAPIError) as mutation_error:
        connection.execute(
            sa.text(
                f"UPDATE {schema}.engineering_datasheet_revisions "
                "SET change_reason = 'forged' WHERE id = :id"
            ),
            {"id": datasheet_revision_1},
        )
    connection.rollback()
    assert getattr(mutation_error.value.orig, "sqlstate", None) == "55000"

    datasheet_revision_2 = uuid4()
    datasheet_fingerprint_2 = "4" * 64
    revision_2_time = created_at + timedelta(minutes=1)
    connection.execute(
        datasheet_revision_insert,
        revision_values(
            revision_id=datasheet_revision_2,
            revision_number=2,
            revision_fingerprint=datasheet_fingerprint_2,
            prior_id=datasheet_revision_1,
            prior_fingerprint=datasheet_fingerprint_1,
            timestamp=revision_2_time,
        ),
    )
    connection.execute(
        sa.text(
            f"""
            UPDATE {schema}.engineering_datasheets
            SET current_revision = 2,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 2,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": datasheet_id,
            "fingerprint": datasheet_fingerprint_2,
            "updated_at": revision_2_time,
        },
    )
    connection.commit()

    run_id = uuid4()
    run_fingerprint = "5" * 64
    result_fingerprint = "6" * 64
    output = {
        "output_id": "pressure-output",
        "name": "Pressure output",
        "quantity": {
            "quantity_kind": "pressure.differential",
            "value": 42.0,
            "unit": "Pa",
            "uncertainty": None,
            "uncertainty_basis": None,
            "significant_figures": None,
            "decimal_places": None,
        },
        "categorical_value": None,
    }
    run_insert = sa.text(
        f"""
        INSERT INTO {schema}.calculation_runs (
            id, run_kind, design_case_revision_id,
            design_revision_fingerprint, calculation_type, method_id,
            method_version, executor_id, executor_version, status,
            request_schema, result_schema, request_payload, result_payload,
            execution_metadata, input_fingerprint, result_fingerprint,
            run_fingerprint, canonicalization, created_by, executed_at
        ) VALUES (
            :id, 'calculation', :design_revision_id,
            :design_revision_fingerprint, 'pressure-test',
            'pressure.test.method', '1.0.0', 'calculation-engine',
            '1.0.0', 'completed', 'engineer4me.calculation-request',
            'engineer4me.calculation-result', CAST(:request AS jsonb),
            CAST(:result AS jsonb), CAST(:metadata AS jsonb),
            :input_fingerprint, :result_fingerprint, :run_fingerprint,
            'json-c14n-v1', 'Step 110 migration test', :executed_at
        )
        """
    )
    connection.execute(
        run_insert,
        {
            "id": run_id,
            "design_revision_id": design_revision_1,
            "design_revision_fingerprint": design_fingerprint_1,
            "request": json.dumps({"inputs": []}),
            "result": json.dumps({"outputs": [output]}),
            "metadata": json.dumps({"payload_kind": "calculation"}),
            "input_fingerprint": "7" * 64,
            "result_fingerprint": result_fingerprint,
            "run_fingerprint": run_fingerprint,
            "executed_at": revision_2_time,
        },
    )
    connection.commit()

    link = {
        "link_id": "pressure-link",
        "run_id": str(run_id),
        "run_fingerprint": run_fingerprint,
        "result_fingerprint": result_fingerprint,
        "design_case_id": str(case_id),
        "design_revision_id": str(design_revision_1),
        "design_revision_number": 1,
        "design_revision_fingerprint": design_fingerprint_1,
        "calculation_type": "pressure-test",
        "method_id": "pressure.test.method",
        "method_version": "1.0.0",
        "result_status": "completed",
        "output": output,
        "repository_provenance_verified": True,
        "source_record_embedded": False,
        "historical_link_rewritten": False,
    }
    datasheet_revision_3 = uuid4()
    datasheet_fingerprint_3 = "8" * 64
    revision_3_time = created_at + timedelta(minutes=2)
    connection.execute(
        datasheet_revision_insert,
        revision_values(
            revision_id=datasheet_revision_3,
            revision_number=3,
            revision_fingerprint=datasheet_fingerprint_3,
            prior_id=datasheet_revision_2,
            prior_fingerprint=datasheet_fingerprint_2,
            calculation_links=[link],
            timestamp=revision_3_time,
        ),
    )
    calculation_link_insert = sa.text(
        f"""
        INSERT INTO {schema}.engineering_datasheet_calculation_links (
            datasheet_revision_id, link_id, run_id, output_id,
            run_fingerprint, result_fingerprint
        ) VALUES (
            :revision_id, 'pressure-link', :run_id, 'pressure-output',
            :run_fingerprint, :result_fingerprint
        )
        """
    )
    connection.execute(
        calculation_link_insert,
        {
            "revision_id": datasheet_revision_3,
            "run_id": run_id,
            "run_fingerprint": run_fingerprint,
            "result_fingerprint": result_fingerprint,
        },
    )
    connection.execute(
        sa.text(
            f"""
            UPDATE {schema}.engineering_datasheets
            SET current_revision = 3,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 3,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": datasheet_id,
            "fingerprint": datasheet_fingerprint_3,
            "updated_at": revision_3_time,
        },
    )
    connection.commit()

    poisoned_links: list[dict[str, object]] = []
    missing_provenance = dict(link)
    missing_provenance.pop("repository_provenance_verified")
    poisoned_links.append(missing_provenance)
    for field_name, forged_value in (
        ("repository_provenance_verified", None),
        ("repository_provenance_verified", "true"),
        ("source_record_embedded", "false"),
        ("historical_link_rewritten", None),
    ):
        forged_link = dict(link)
        forged_link[field_name] = forged_value
        poisoned_links.append(forged_link)

    for poisoned_link in poisoned_links:
        poisoned_revision_id = uuid4()
        connection.execute(
            datasheet_revision_insert,
            revision_values(
                revision_id=poisoned_revision_id,
                revision_number=4,
                revision_fingerprint="9" * 64,
                prior_id=datasheet_revision_3,
                prior_fingerprint=datasheet_fingerprint_3,
                calculation_links=[poisoned_link],
                timestamp=created_at + timedelta(minutes=3),
            ),
        )
        with pytest.raises(IntegrityError) as provenance_error:
            connection.execute(
                calculation_link_insert,
                {
                    "revision_id": poisoned_revision_id,
                    "run_id": run_id,
                    "run_fingerprint": run_fingerprint,
                    "result_fingerprint": result_fingerprint,
                },
            )
        connection.rollback()
        assert (
            getattr(
                getattr(provenance_error.value.orig, "diag", None),
                "constraint_name",
                None,
            )
            == "ck_engineering_datasheet_calculation_links_trusted"
        )

    datasheet_revision_4 = uuid4()
    datasheet_fingerprint_4 = "9" * 64
    revision_4_time = created_at + timedelta(minutes=3)
    connection.execute(
        datasheet_revision_insert,
        revision_values(
            revision_id=datasheet_revision_4,
            revision_number=4,
            revision_fingerprint=datasheet_fingerprint_4,
            prior_id=datasheet_revision_3,
            prior_fingerprint=datasheet_fingerprint_3,
            calculation_links=[link],
            timestamp=revision_4_time,
        ),
    )
    connection.execute(
        sa.text(
            f"""
            UPDATE {schema}.engineering_datasheets
            SET current_revision = 4,
                current_revision_fingerprint = :fingerprint,
                concurrency_version = 4,
                updated_at = :updated_at
            WHERE id = :id
            """
        ),
        {
            "id": datasheet_id,
            "fingerprint": datasheet_fingerprint_4,
            "updated_at": revision_4_time,
        },
    )
    with pytest.raises(IntegrityError) as projection_error:
        connection.commit()
    connection.rollback()
    assert (
        getattr(
            projection_error.value.orig,
            "diag",
            None,
        ).constraint_name
        == "ck_engineering_datasheet_links_projected"
    )

    command.downgrade(config, PARENT_REVISION)
    assert _alembic_revision(connection) == PARENT_REVISION
    remaining_tables = set(
        sa.inspect(connection).get_table_names(schema=sandbox.schema)
    )
    assert not (set(TABLES) & remaining_tables)
    assert {"design_cases", "design_case_revisions", "calculation_runs"}.issubset(
        remaining_tables
    )
