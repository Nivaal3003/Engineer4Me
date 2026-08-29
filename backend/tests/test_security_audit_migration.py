"""Static and graph contracts for the append-only security audit migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects import postgresql


BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND_ROOT / "alembic" / "versions" / "d9a137b5e6f7_add_security_audit_events.py"


class Recorder:
    def __init__(self):
        self.metadata = sa.MetaData(); self.indexes = []; self.sql = []; self.drops = []
    def create_table(self, name, *items, **kwargs):
        return sa.Table(name, self.metadata, *items, **kwargs)
    def create_index(self, name, table_name, columns, **kwargs):
        self.indexes.append((name, table_name, tuple(map(str, columns)), kwargs.get("unique", False)))
    def execute(self, statement, *args, **kwargs): self.sql.append(str(statement))
    def drop_index(self, name, **kwargs): self.drops.append(("index", name))
    def drop_table(self, name, **kwargs): self.drops.append(("table", name))


def load_migration():
    spec = importlib.util.spec_from_file_location("phase8_audit_migration", MIGRATION)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def recorded_upgrade():
    module = load_migration(); recorder = Recorder(); module.op = recorder; module.upgrade(); return module, recorder


def test_audit_revision_is_the_single_linear_head():
    module = load_migration()
    assert module.revision == "d9a137b5e6f7"
    assert module.down_revision == "c8f123a4d5e6"
    scripts = ScriptDirectory.from_config(Config(str(BACKEND_ROOT / "alembic.ini")))
    assert scripts.get_heads() == ["d9a137b5e6f7"]


def test_upgrade_creates_exact_audit_table_with_named_primary_key():
    _, recorder = recorded_upgrade()
    assert set(recorder.metadata.tables) == {"security_audit_events"}
    assert recorder.metadata.tables["security_audit_events"].primary_key.name == "pk_security_audit_events"


def test_audit_foreign_keys_are_named_and_restrict_deletion():
    _, recorder = recorded_upgrade(); table = recorder.metadata.tables["security_audit_events"]
    values = {(constraint.name, next(iter(constraint.elements)).ondelete) for constraint in table.foreign_key_constraints}
    assert values == {("fk_security_audit_actor_user_id", "RESTRICT"), ("fk_security_audit_organisation_id", "RESTRICT")}


def test_context_is_postgresql_jsonb_and_non_nullable():
    _, recorder = recorded_upgrade(); column = recorder.metadata.tables["security_audit_events"].c.context
    assert column.type.compile(dialect=postgresql.dialect()) == "JSONB"
    assert column.nullable is False


def test_bounded_checks_and_query_indexes_exist():
    _, recorder = recorded_upgrade(); table = recorder.metadata.tables["security_audit_events"]
    checks = {constraint.name for constraint in table.constraints if isinstance(constraint, sa.CheckConstraint)}
    assert checks == {"ck_security_audit_event_type", "ck_security_audit_outcome", "ck_security_audit_reason"}
    assert {item[0] for item in recorder.indexes} == {"ix_security_audit_organisation_occurred", "ix_security_audit_actor_occurred", "ix_security_audit_request"}


def test_append_only_database_trigger_is_created():
    _, recorder = recorded_upgrade(); sql = " ".join(recorder.sql).lower()
    assert "phase8_reject_security_audit_mutation" in sql
    assert "before update or delete" in sql
    assert "trg_security_audit_events_append_only" in sql


def test_audit_model_is_registered_on_shared_metadata():
    import app.models  # noqa: F401
    from app.db.database import Base
    assert "security_audit_events" in Base.metadata.tables


def test_downgrade_drops_trigger_function_indexes_and_table():
    module = load_migration(); recorder = Recorder(); module.op = recorder; module.downgrade()
    sql = " ".join(recorder.sql).lower()
    assert "drop trigger" in sql and "drop function" in sql
    assert recorder.drops[-1] == ("table", "security_audit_events")
