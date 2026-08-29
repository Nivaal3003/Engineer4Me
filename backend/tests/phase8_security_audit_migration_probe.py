"""Isolated PostgreSQL probe for the append-only security audit migration."""

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
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step138_[0-9a-f]{32}\Z")
AUDIT_TABLE = "security_audit_events"


def quoted_identifier(value: str) -> str:
    if SCHEMA_PATTERN.fullmatch(value) is None:
        raise ValueError("temporary schema name is outside the controlled pattern")
    return '"' + value + '"'


def alembic_config(connection) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    return config


def rejected(connection, statement, parameters) -> None:
    try:
        connection.execute(text(statement), parameters)
        connection.commit()
    except DBAPIError:
        connection.rollback()
    else:
        raise AssertionError("append-only audit trigger allowed mutation")


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    schema = f"e4m_phase8_step138_{uuid4().hex}"
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
            if current != "d9a137b5e6f7":
                raise AssertionError(f"unexpected migration head: {current}")
            tables = set(inspect(connection).get_table_names(schema=schema))
            if AUDIT_TABLE not in tables:
                raise AssertionError("security audit table is missing")

            trigger_count = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid=t.tgrelid "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname=:schema AND c.relname=:table "
                    "AND t.tgname='trg_security_audit_events_append_only' "
                    "AND NOT t.tgisinternal"
                ),
                {"schema": schema, "table": AUDIT_TABLE},
            )
            if trigger_count != 1:
                raise AssertionError("append-only security audit trigger is missing")

            user_id = uuid4()
            organisation_id = uuid4()
            audit_id = uuid4()
            connection.execute(
                text(
                    "INSERT INTO security_users (id,email,display_name,status,issuer,subject) "
                    "VALUES (:id,'step138@example.com','Step 138 User','active','step138-issuer','step138-subject')"
                ),
                {"id": user_id},
            )
            connection.execute(
                text(
                    "INSERT INTO security_organisations (id,slug,name,status) "
                    "VALUES (:id,'step138-org','Step 138 Organisation','active')"
                ),
                {"id": organisation_id},
            )
            connection.execute(
                text(
                    "INSERT INTO security_audit_events "
                    "(id,occurred_at,event_type,outcome,reason_code,request_id,actor_user_id,organisation_id,session_id,permission,resource_kind,resource_id,context) "
                    "VALUES (:id,CURRENT_TIMESTAMP,'access_allowed','succeeded','allowed',:request_id,:user_id,:organisation_id,:session_id,'engineering:read','engineering_case','case-138',CAST('{\"policy_version\":\"1.0.0\"}' AS jsonb))"
                ),
                {"id": audit_id, "request_id": uuid4(), "user_id": user_id, "organisation_id": organisation_id, "session_id": uuid4()},
            )
            connection.commit()
            stored_context = connection.scalar(text("SELECT context FROM security_audit_events WHERE id=:id"), {"id": audit_id})
            if stored_context != {"policy_version": "1.0.0"}:
                raise AssertionError("audit context did not round-trip exactly")

            rejected(connection, "UPDATE security_audit_events SET reason_code='forged' WHERE id=:id", {"id": audit_id})
            rejected(connection, "DELETE FROM security_audit_events WHERE id=:id", {"id": audit_id})
            retained = connection.scalar(text("SELECT count(*) FROM security_audit_events WHERE id=:id"), {"id": audit_id})
            if retained != 1:
                raise AssertionError("append-only audit record was not retained")

            command.downgrade(alembic_config(connection), "c8f123a4d5e6")
            current = connection.scalar(text("SELECT version_num FROM alembic_version"))
            if current != "c8f123a4d5e6":
                raise AssertionError(f"unexpected downgrade revision: {current}")
            remaining = set(inspect(connection).get_table_names(schema=schema))
            if AUDIT_TABLE in remaining:
                raise AssertionError("audit table remained after downgrade")
            if "security_users" not in remaining:
                raise AssertionError("foundation tables were incorrectly removed")

            print(f"Temporary schema: {schema}")
            print("Upgrade head: d9a137b5e6f7")
            print("Audit table: verified")
            print("Append-only trigger: update and delete rejected")
            print("Audit context: exact bounded JSONB round-trip verified")
            print("Downgrade target: c8f123a4d5e6 verified")
    finally:
        if created:
            with engine.begin() as cleanup:
                cleanup.execute(text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
        engine.dispose()
    print("Temporary schema cleanup: complete")
    print("Operational public schema: not targeted")


if __name__ == "__main__":
    main()
