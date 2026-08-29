"""Isolated PostgreSQL upgrade/downgrade probe for Phase 8 security schema."""

from __future__ import annotations

import os
import re
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError


BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step124_[0-9a-f]{32}\Z")
SECURITY_TABLES = {
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
}


def quoted_identifier(value: str) -> str:
    if SCHEMA_PATTERN.fullmatch(value) is None:
        raise ValueError("temporary schema name is outside the controlled pattern")
    return '"' + value + '"'


def alembic_config(connection) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    return config


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    schema = f"e4m_phase8_step124_{uuid4().hex}"
    quoted = quoted_identifier(schema)
    engine = create_engine(database_url, pool_pre_ping=True)
    created = False
    try:
        with engine.connect() as connection:
            connection.execute(text(f"CREATE SCHEMA {quoted}"))
            connection.commit()
            created = True
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()

            command.upgrade(alembic_config(connection), "head")
            current = connection.scalar(text("SELECT version_num FROM alembic_version"))
            if current != "c8f123a4d5e6":
                raise AssertionError(f"unexpected migration head: {current}")
            tables = set(inspect(connection).get_table_names(schema=schema))
            missing = SECURITY_TABLES - tables
            if missing:
                raise AssertionError(f"missing security tables: {sorted(missing)}")

            trigger_count = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid=t.tgrelid "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname=:schema AND c.relname="
                    "'security_entitlement_snapshots' AND t.tgname="
                    "'trg_security_entitlement_snapshots_append_only' "
                    "AND NOT t.tgisinternal"
                ),
                {"schema": schema},
            )
            if trigger_count != 1:
                raise AssertionError("append-only entitlement trigger is missing")

            organisation_id = uuid4()
            entitlement_id = uuid4()
            connection.execute(
                text(
                    "INSERT INTO security_organisations "
                    "(id,slug,name,status) VALUES "
                    "(:id,'step124-org','Step 124 Organisation','active')"
                ),
                {"id": organisation_id},
            )
            connection.execute(
                text(
                    "INSERT INTO security_entitlement_snapshots "
                    "(id,organisation_id,sequence_number,plan_id,"
                    "subscription_status,features,quotas,effective_at,"
                    "source_reference) VALUES "
                    "(:id,:organisation_id,1,'controlled-plan','active',"
                    "CAST('[\"engineering_calculations\"]' AS jsonb),"
                    "CAST('[]' AS jsonb),CURRENT_TIMESTAMP,'step124 probe')"
                ),
                {"id": entitlement_id, "organisation_id": organisation_id},
            )
            connection.commit()
            try:
                connection.execute(
                    text(
                        "UPDATE security_entitlement_snapshots "
                        "SET plan_id='forged-plan' WHERE id=:id"
                    ),
                    {"id": entitlement_id},
                )
                connection.commit()
            except DBAPIError:
                connection.rollback()
            else:
                raise AssertionError("append-only trigger allowed an update")

            command.downgrade(alembic_config(connection), "b7f110e3d2a1")
            remaining = set(inspect(connection).get_table_names(schema=schema))
            leaked = SECURITY_TABLES & remaining
            if leaked:
                raise AssertionError(f"downgrade retained security tables: {sorted(leaked)}")
            print(f"Temporary schema: {schema}")
            print("Upgrade head: c8f123a4d5e6")
            print("Security tables: 4 verified")
            print("Append-only trigger: update rejected")
            print("Downgrade target: b7f110e3d2a1 verified")
    finally:
        if created:
            with engine.begin() as cleanup:
                cleanup.execute(text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
        engine.dispose()
    print("Temporary schema cleanup: complete")
    print("Operational public schema: not targeted")


if __name__ == "__main__":
    main()
