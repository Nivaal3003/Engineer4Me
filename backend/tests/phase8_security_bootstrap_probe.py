"""Isolated PostgreSQL probe for one-time atomic security bootstrap execution."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker

from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import ControlledFeature, OrganisationEntitlementSnapshot, QuotaGrant, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.services.security_bootstrap_executor import SecurityBootstrapStateError, TransactionalSecurityBootstrapExecutor


BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step149_[0-9a-f]{32}\Z")


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
    schema = f"e4m_phase8_step149_{uuid4().hex}"
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
            if connection.scalar(text("SELECT version_num FROM alembic_version")) != "d9a137b5e6f7":
                raise AssertionError("isolated bootstrap schema did not reach Phase 8 head")

        isolated_engine = create_engine(database_url, pool_pre_ping=True)

        @event.listens_for(isolated_engine, "connect")
        def set_search_path(dbapi_connection, connection_record) -> None:
            del connection_record
            with dbapi_connection.cursor() as cursor:
                cursor.execute(f"SET search_path TO {quoted}")

        now = datetime.now(UTC)
        bootstrap_id = uuid4()
        request_id = uuid4()
        user_id = uuid4()
        organisation_id = uuid4()
        membership_id = uuid4()
        snapshot_id = uuid4()
        snapshot = OrganisationEntitlementSnapshot(
            snapshot_id=snapshot_id,
            organisation_id=organisation_id,
            plan_id="isolated-probe-plan",
            subscription_status=SubscriptionStatus.TRIAL,
            features=(ControlledFeature.ENGINEERING_CALCULATIONS, ControlledFeature.DOCUMENT_INGESTION),
            quotas=(QuotaGrant(kind=QuotaKind.MONTHLY_CALCULATION_RUNS, limit=25),),
            effective_at=now,
            expires_at=now + timedelta(hours=1),
            source_reference="isolated Step 149 probe only",
        )
        bootstrap = SecurityBootstrapCommand(
            bootstrap_id=bootstrap_id,
            request_id=request_id,
            user_id=user_id,
            organisation_id=organisation_id,
            membership_id=membership_id,
            email="step149@example.com",
            display_name="Step 149 Owner",
            issuer="https://identity.step149.invalid",
            subject="isolated-subject-149",
            organisation_slug="step149-org",
            organisation_name="Step 149 Organisation",
            initial_role=OrganisationRole.OWNER,
            activated_at=now,
            entitlement=snapshot,
        )
        factory = sessionmaker(bind=isolated_engine, expire_on_commit=False)
        receipt = TransactionalSecurityBootstrapExecutor(factory).execute(bootstrap)
        if receipt.bootstrap_id != bootstrap_id or receipt.entitlement_snapshot_id != snapshot_id:
            raise AssertionError("bootstrap receipt lost trusted identity")

        with isolated_engine.connect() as verification:
            table_counts = {
                table: verification.scalar(text(f'SELECT count(*) FROM "{table}"'))
                for table in (
                    "security_users",
                    "security_organisations",
                    "security_organisation_memberships",
                    "security_entitlement_snapshots",
                    "security_audit_events",
                )
            }
            if set(table_counts.values()) != {1}:
                raise AssertionError(f"atomic bootstrap row counts are invalid: {table_counts}")
            membership = verification.execute(
                text("SELECT user_id,organisation_id,role,status,joined_at FROM security_organisation_memberships WHERE id=:id"),
                {"id": membership_id},
            ).mappings().one_or_none()
            if membership is None or membership["user_id"] != user_id or membership["organisation_id"] != organisation_id or membership["role"] != "owner" or membership["status"] != "active":
                raise AssertionError("bootstrap owner membership did not round-trip")
            audit = verification.execute(
                text("SELECT event_type,outcome,reason_code,request_id,actor_user_id,organisation_id,context FROM security_audit_events WHERE id=:id"),
                {"id": bootstrap_id},
            ).mappings().one()
            if audit["event_type"] != "security_state_changed" or audit["outcome"] != "succeeded" or audit["reason_code"] != "initial_security_bootstrap":
                raise AssertionError("bootstrap audit event is invalid")
            if audit["request_id"] != request_id or audit["actor_user_id"] != user_id or audit["organisation_id"] != organisation_id:
                raise AssertionError("bootstrap audit correlation is invalid")
            if set(audit["context"]) != {"membership_role", "entitlement_plan", "subscription_status"}:
                raise AssertionError("bootstrap audit context is not privacy-minimised")

        try:
            TransactionalSecurityBootstrapExecutor(factory).execute(bootstrap)
        except SecurityBootstrapStateError:
            pass
        else:
            raise AssertionError("second bootstrap was not rejected")

        isolated_engine.dispose()
        isolated_engine = None
        with administration_engine.connect() as connection:
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.downgrade(alembic_config(connection), "b7f110e3d2a1")
            remaining = set(inspect(connection).get_table_names(schema=schema))
            if {"security_users", "security_organisations", "security_organisation_memberships", "security_entitlement_snapshots", "security_audit_events"} & remaining:
                raise AssertionError("security bootstrap tables remained after isolated downgrade")

        print(f"Temporary schema: {schema}")
        print("Upgrade head: d9a137b5e6f7")
        print("Atomic bootstrap records: 5 committed")
        print("Initial owner and entitlement: exact correlation verified")
        print("Bootstrap audit event: privacy-minimised and correlated")
        print("Second bootstrap: rejected")
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
