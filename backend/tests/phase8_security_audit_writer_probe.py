"""Isolated PostgreSQL probe for durable audit writes and transaction separation."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker

from app.repositories.security_audit_writer import DurableSecurityAuditWriter
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.security.authorization import ResourceKind
from app.security.identity_models import Permission


BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step144_[0-9a-f]{32}\Z")


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
    schema = f"e4m_phase8_step144_{uuid4().hex}"
    quoted = quoted_identifier(schema)
    administration_engine = create_engine(database_url, pool_pre_ping=True)
    isolated_engine = None
    created = False
    try:
        with administration_engine.connect() as connection:
            connection.execute(text(f"CREATE SCHEMA {quoted}"))
            connection.commit()
            created = True
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.upgrade(alembic_config(connection), "head")
            current = connection.scalar(text("SELECT version_num FROM alembic_version"))
            if current != "d9a137b5e6f7":
                raise AssertionError(f"unexpected migration head: {current}")

        isolated_engine = create_engine(database_url, pool_pre_ping=True)

        @event.listens_for(isolated_engine, "connect")
        def set_isolated_search_path(dbapi_connection, connection_record) -> None:
            del connection_record
            with dbapi_connection.cursor() as cursor:
                cursor.execute(f"SET search_path TO {quoted}")

        organisation_id = uuid4()
        with isolated_engine.begin() as connection:
            connection.execute(
                text("INSERT INTO security_organisations (id,slug,name,status) VALUES (:id,'step144-org','Step 144 Organisation','active')"),
                {"id": organisation_id},
            )

        request_connection = isolated_engine.connect()
        request_transaction = request_connection.begin()
        unrelated_id = uuid4()
        try:
            request_connection.execute(
                text("INSERT INTO security_organisations (id,slug,name,status) VALUES (:id,'step144-uncommitted','Uncommitted Request Work','active')"),
                {"id": unrelated_id},
            )
            audit_id = uuid4()
            request_id = uuid4()
            audit_session_factory = sessionmaker(bind=isolated_engine, expire_on_commit=False)
            writer = DurableSecurityAuditWriter(audit_session_factory)
            value = SecurityAuditEvent(
                event_id=audit_id,
                occurred_at=datetime.now(UTC),
                event_type=SecurityAuditEventType.ACCESS_DENIED,
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="authorization_denied",
                request_id=request_id,
                actor_user_id=None,
                organisation_id=organisation_id,
                session_id=uuid4(),
                permission=Permission.ENGINEERING_READ,
                resource_kind=ResourceKind.ENGINEERING_CASE,
                resource_id="case-144",
                context={"decision_reason": "permission_not_granted", "policy_version": "1.0.0"},
            )
            if writer.append(value) is not value:
                raise AssertionError("durable audit writer did not return the committed contract")
            request_transaction.rollback()
        finally:
            if request_transaction.is_active:
                request_transaction.rollback()
            request_connection.close()

        with isolated_engine.connect() as verification:
            stored = verification.execute(
                text("SELECT event_type,outcome,reason_code,request_id,organisation_id,context FROM security_audit_events WHERE id=:id"),
                {"id": audit_id},
            ).mappings().one()
            if stored["event_type"] != "access_denied" or stored["outcome"] != "denied":
                raise AssertionError("durable audit event did not preserve its trusted decision")
            if stored["request_id"] != request_id or stored["organisation_id"] != organisation_id:
                raise AssertionError("durable audit event lost request or tenant correlation")
            if stored["context"] != {"decision_reason": "permission_not_granted", "policy_version": "1.0.0"}:
                raise AssertionError("durable audit context did not round-trip exactly")
            unrelated_count = verification.scalar(text("SELECT count(*) FROM security_organisations WHERE id=:id"), {"id": unrelated_id})
            if unrelated_count != 0:
                raise AssertionError("audit writer committed unrelated request-session work")

        isolated_engine.dispose()
        isolated_engine = None
        with administration_engine.connect() as connection:
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.downgrade(alembic_config(connection), "b7f110e3d2a1")
            remaining = set(inspect(connection).get_table_names(schema=schema))
            if {"security_audit_events", "security_users", "security_organisations"} & remaining:
                raise AssertionError("security tables remained after isolated downgrade")

        print(f"Temporary schema: {schema}")
        print("Upgrade head: d9a137b5e6f7")
        print("Durable audit commit: verified")
        print("Request transaction rollback: unrelated work removed")
        print("Audit survival after request rollback: verified")
        print("Audit correlation and context: exact round-trip verified")
        print("Downgrade target: b7f110e3d2a1 verified")
    finally:
        if isolated_engine is not None:
            isolated_engine.dispose()
        if created:
            with administration_engine.begin() as cleanup:
                cleanup.execute(text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
        administration_engine.dispose()
    print("Temporary schema cleanup: complete")
    print("Operational public schema: not targeted")


if __name__ == "__main__":
    main()
