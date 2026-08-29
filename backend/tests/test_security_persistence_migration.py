"""Static and Alembic-graph contracts for the Phase 8 security foundation migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects import postgresql


BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND_ROOT / "alembic" / "versions" / "c8f123a4d5e6_add_phase8_security_foundation.py"


class Recorder:
    def __init__(self):
        self.metadata = sa.MetaData(); self.indexes = []; self.sql = []
    def create_table(self, name, *items, **kwargs):
        return sa.Table(name, self.metadata, *items, **kwargs)
    def create_index(self, name, table_name, columns, **kwargs):
        self.indexes.append((name, table_name, tuple(map(str, columns)), kwargs.get("unique", False)))
    def execute(self, statement, *args, **kwargs):
        self.sql.append(str(statement))
    def drop_index(self, *args, **kwargs): pass
    def drop_table(self, *args, **kwargs): pass


def load_migration():
    spec = importlib.util.spec_from_file_location("phase8_security_migration", MIGRATION)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def recorded_upgrade():
    module = load_migration(); recorder = Recorder(); module.op = recorder; module.upgrade(); return module, recorder


def test_revision_extends_phase7_head_and_remains_in_linear_graph():
    module = load_migration(); assert module.revision == "c8f123a4d5e6"; assert module.down_revision == "b7f110e3d2a1"
    config = Config(str(BACKEND_ROOT / "alembic.ini")); scripts = ScriptDirectory.from_config(config)
    revision = scripts.get_revision("c8f123a4d5e6")
    assert revision is not None and revision.down_revision == "b7f110e3d2a1"


def test_upgrade_creates_exact_security_tables():
    _, recorder = recorded_upgrade()
    assert set(recorder.metadata.tables) == {"security_users", "security_organisations", "security_organisation_memberships", "security_entitlement_snapshots"}


def test_primary_keys_and_foreign_keys_are_named():
    _, recorder = recorded_upgrade()
    for table in recorder.metadata.tables.values():
        assert table.primary_key.name is not None
    membership = recorder.metadata.tables["security_organisation_memberships"]
    assert {constraint.name for constraint in membership.foreign_key_constraints} == {"fk_security_memberships_user_id", "fk_security_memberships_organisation_id"}


def test_identity_and_tenant_uniqueness_contracts_exist():
    _, recorder = recorded_upgrade()
    users = recorder.metadata.tables["security_users"]
    memberships = recorder.metadata.tables["security_organisation_memberships"]
    assert "uq_security_users_issuer_subject" in {item.name for item in users.constraints}
    assert "uq_security_memberships_user_organisation" in {item.name for item in memberships.constraints}
    names = {item[0] for item in recorder.indexes}
    assert "uq_security_users_email_ci" in names
    assert "uq_security_organisations_slug_ci" in names


def test_entitlement_json_is_postgresql_jsonb():
    _, recorder = recorded_upgrade(); table = recorder.metadata.tables["security_entitlement_snapshots"]
    dialect = postgresql.dialect()
    assert table.c.features.type.compile(dialect=dialect) == "JSONB"
    assert table.c.quotas.type.compile(dialect=dialect) == "JSONB"


def test_append_only_database_trigger_is_created():
    _, recorder = recorded_upgrade(); sql = " ".join(recorder.sql).lower()
    assert "phase8_reject_entitlement_snapshot_mutation" in sql
    assert "before update or delete" in sql
    assert "trg_security_entitlement_snapshots_append_only" in sql


def test_models_are_registered_on_shared_metadata():
    import app.models  # noqa: F401
    from app.db.database import Base
    assert {"security_users", "security_organisations", "security_organisation_memberships", "security_entitlement_snapshots"}.issubset(Base.metadata.tables)


def test_downgrade_is_complete_and_reverse_ordered():
    module = load_migration(); recorder = Recorder(); actions = []
    recorder.drop_index = lambda name, **kwargs: actions.append(("index", name))
    recorder.drop_table = lambda name, **kwargs: actions.append(("table", name))
    recorder.execute = lambda sql, *args, **kwargs: actions.append(("sql", str(sql)))
    module.op = recorder; module.downgrade()
    dropped_tables = [name for kind, name in actions if kind == "table"]
    assert dropped_tables == ["security_entitlement_snapshots", "security_organisation_memberships", "security_organisations", "security_users"]
