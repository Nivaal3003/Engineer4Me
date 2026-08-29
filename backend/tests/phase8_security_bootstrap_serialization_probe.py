"""Isolated PostgreSQL proof of exclusive concurrent bootstrap serialization."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from uuid import UUID, uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import (
    ControlledFeature,
    OrganisationEntitlementSnapshot,
    SubscriptionStatus,
)
from app.security.identity_models import OrganisationRole
from app.services.security_bootstrap_executor import (
    SecurityBootstrapStateError,
    TransactionalSecurityBootstrapExecutor,
)
from app.services.security_bootstrap_operational import (
    PHASE8_SECURITY_HEAD,
    PostgreSQLSecurityBootstrapTransactionGuard,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step177_[0-9a-f]{32}\Z")
PHASE8_BASE = "b7f110e3d2a1"
SECURITY_TABLES = (
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
    "security_audit_events",
)


def quoted_identifier(value: str) -> str:
    if SCHEMA_PATTERN.fullmatch(value) is None:
        raise ValueError("temporary schema name is outside the controlled pattern")
    return '"' + value + '"'


def alembic_config(connection) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    return config


def public_snapshot(engine) -> tuple[str, tuple[int, ...]]:
    with engine.connect() as connection:
        connection.exec_driver_sql(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        )
        revision = connection.scalar(
            text(
                "SELECT CASE WHEN count(*) = 1 THEN min(version_num) END "
                "FROM public.alembic_version"
            )
        )
        counts = tuple(
            int(connection.scalar(text(f'SELECT count(*) FROM public."{table}"')))
            for table in SECURITY_TABLES
        )
    return str(revision), counts


def isolated_counts(engine, *, expected_schema: str) -> dict[str, int]:
    with engine.connect() as connection:
        if connection.scalar(text("SELECT current_schema()")) != expected_schema:
            raise AssertionError("isolated verification escaped the temporary schema")
        return {
            table: int(connection.scalar(text(f'SELECT count(*) FROM "{table}"')))
            for table in SECURITY_TABLES
        }


def bootstrap_command(
    *, prefix: str, activated_at: datetime
) -> SecurityBootstrapCommand:
    organisation_id = uuid4()
    return SecurityBootstrapCommand(
        bootstrap_id=uuid4(),
        request_id=uuid4(),
        user_id=uuid4(),
        organisation_id=organisation_id,
        membership_id=uuid4(),
        email=f"{prefix}@step177.invalid",
        display_name=f"Step 177 {prefix.title()} Owner",
        issuer="https://identity.step177.invalid/tenant",
        subject=f"isolated-{prefix}-subject-step177",
        organisation_slug=f"step177-{prefix}-organisation",
        organisation_name=f"Step 177 {prefix.title()} Organisation",
        initial_role=OrganisationRole.OWNER,
        activated_at=activated_at,
        entitlement=OrganisationEntitlementSnapshot(
            snapshot_id=uuid4(),
            organisation_id=organisation_id,
            plan_id=f"isolated-{prefix}-plan-step177",
            subscription_status=SubscriptionStatus.TRIAL,
            features=(ControlledFeature.ENGINEERING_CALCULATIONS,),
            quotas=(),
            effective_at=activated_at,
            expires_at=activated_at + timedelta(hours=1),
            source_reference=f"isolated {prefix} Step 177 probe only",
        ),
    )


@dataclass(slots=True)
class RaceTracker:
    revision_attempted: Event
    revision_completed: Event
    lock_attempted: Event
    lock_acquired: Event
    release: Event | None = None


class RaceSession(Session):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.commit_calls = 0
        self.rollback_calls = 0
        self.close_calls = 0

    @property
    def tracker(self) -> RaceTracker:
        value = self.info.get("race_tracker")
        if not isinstance(value, RaceTracker):
            raise AssertionError("race session tracker is missing")
        return value

    def execute(self, statement, *args, **kwargs):
        sql = " ".join(str(statement).split())
        if sql.startswith("LOCK TABLE "):
            self.tracker.lock_attempted.set()
            result = super().execute(statement, *args, **kwargs)
            self.tracker.lock_acquired.set()
            if self.tracker.release is not None and not self.tracker.release.wait(15):
                raise AssertionError(
                    "first bootstrap lock was not released by the probe"
                )
            return result
        return super().execute(statement, *args, **kwargs)

    def scalar(self, statement, *args, **kwargs):
        sql = " ".join(str(statement).split())
        if sql.startswith("SELECT ") and "alembic_version" in sql:
            self.tracker.revision_attempted.set()
            result = super().scalar(statement, *args, **kwargs)
            self.tracker.revision_completed.set()
            return result
        return super().scalar(statement, *args, **kwargs)

    def commit(self) -> None:
        self.commit_calls += 1
        super().commit()

    def rollback(self) -> None:
        self.rollback_calls += 1
        super().rollback()

    def close(self) -> None:
        self.close_calls += 1
        super().close()


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")

    schema = f"e4m_phase8_step177_{uuid4().hex}"
    quoted = quoted_identifier(schema)
    administration_engine = create_engine(database_url, pool_pre_ping=True)
    isolated_engine = None
    created = False
    public_before = None
    first_tracker = RaceTracker(Event(), Event(), Event(), Event(), Event())
    second_tracker = RaceTracker(Event(), Event(), Event(), Event())

    try:
        public_before = public_snapshot(administration_engine)
        if public_before != (PHASE8_SECURITY_HEAD, (0, 0, 0, 0, 0)):
            raise AssertionError(
                "operational public security state is not the accepted empty head"
            )
        with administration_engine.connect() as connection:
            connection.execute(text(f"CREATE SCHEMA {quoted}"))
            connection.commit()
            created = True
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.upgrade(alembic_config(connection), "head")
            revision = connection.scalar(
                text(
                    "SELECT CASE WHEN count(*) = 1 THEN min(version_num) END "
                    "FROM alembic_version"
                )
            )
            if revision != PHASE8_SECURITY_HEAD:
                raise AssertionError(f"unexpected isolated migration head: {revision}")

        isolated_engine = create_engine(database_url, pool_pre_ping=True)

        @event.listens_for(isolated_engine, "connect", insert=True)
        def set_isolated_search_path(dbapi_connection, connection_record) -> None:
            del connection_record
            previous_autocommit = dbapi_connection.autocommit
            try:
                dbapi_connection.autocommit = True
                with dbapi_connection.cursor() as cursor:
                    cursor.execute(f"SET search_path TO {quoted}")
            finally:
                dbapi_connection.autocommit = previous_autocommit

        if isolated_counts(
            isolated_engine,
            expected_schema=schema,
        ) != {table: 0 for table in SECURITY_TABLES}:
            raise AssertionError("isolated security domain was not initially empty")

        maker = sessionmaker(
            bind=isolated_engine,
            class_=RaceSession,
            expire_on_commit=False,
        )
        first_sessions: list[RaceSession] = []
        second_sessions: list[RaceSession] = []

        def session_factory(
            tracker: RaceTracker,
            instances: list[RaceSession],
        ) -> RaceSession:
            session = maker(info={"race_tracker": tracker})
            instances.append(session)
            return session

        guard = PostgreSQLSecurityBootstrapTransactionGuard(
            expected_schema=schema,
            expected_revision=PHASE8_SECURITY_HEAD,
        )
        first_executor = TransactionalSecurityBootstrapExecutor(
            lambda: session_factory(first_tracker, first_sessions),
            transaction_guard=guard,
        )
        second_executor = TransactionalSecurityBootstrapExecutor(
            lambda: session_factory(second_tracker, second_sessions),
            transaction_guard=guard,
        )
        activated_at = datetime.now(UTC).replace(microsecond=0)
        first_command = bootstrap_command(prefix="first", activated_at=activated_at)
        second_command = bootstrap_command(prefix="second", activated_at=activated_at)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(first_executor.execute, first_command)
            if not first_tracker.lock_acquired.wait(10):
                raise AssertionError(
                    "first bootstrap did not acquire the exclusive lock"
                )
            second_future = pool.submit(second_executor.execute, second_command)
            if not second_tracker.revision_attempted.wait(10):
                raise AssertionError(
                    "second bootstrap did not begin its guarded revision read"
                )
            if second_tracker.revision_completed.wait(0.25):
                raise AssertionError(
                    "second bootstrap revision read escaped the first exclusive lock"
                )
            if second_tracker.lock_attempted.is_set():
                raise AssertionError(
                    "second bootstrap reached its lock statement while the first lock was held"
                )
            first_tracker.release.set()
            first_receipt = first_future.result(timeout=15)
            try:
                second_future.result(timeout=15)
            except SecurityBootstrapStateError:
                pass
            else:
                raise AssertionError("second concurrent bootstrap was not rejected")
        if not second_tracker.revision_completed.is_set():
            raise AssertionError(
                "second bootstrap revision read did not resume after the first commit"
            )
        if not second_tracker.lock_attempted.is_set():
            raise AssertionError(
                "second bootstrap did not reach its lock statement after serialization"
            )
        if not second_tracker.lock_acquired.is_set():
            raise AssertionError("second bootstrap never acquired the serialized lock")
        if first_receipt.bootstrap_id != first_command.bootstrap_id:
            raise AssertionError("winning bootstrap receipt lost its correlation")
        if len(first_sessions) != 1 or len(second_sessions) != 1:
            raise AssertionError(
                "concurrent bootstrap did not use two isolated sessions"
            )
        first_session = first_sessions[0]
        second_session = second_sessions[0]
        if (
            first_session.commit_calls != 1
            or first_session.rollback_calls != 0
            or first_session.close_calls != 1
        ):
            raise AssertionError("winning bootstrap session lifecycle is invalid")
        if (
            second_session.commit_calls != 0
            or second_session.rollback_calls != 1
            or second_session.close_calls != 1
        ):
            raise AssertionError("rejected bootstrap session lifecycle is invalid")

        counts = isolated_counts(isolated_engine, expected_schema=schema)
        if counts != {table: 1 for table in SECURITY_TABLES}:
            raise AssertionError(
                f"serialized bootstrap row counts are invalid: {counts}"
            )
        with isolated_engine.connect() as verification:
            if verification.scalar(text("SELECT current_schema()")) != schema:
                raise AssertionError("result verification escaped the temporary schema")
            user = (
                verification.execute(
                    text("SELECT id,issuer,subject FROM security_users")
                )
                .mappings()
                .one()
            )
            organisation = (
                verification.execute(text("SELECT id,slug FROM security_organisations"))
                .mappings()
                .one()
            )
            membership = (
                verification.execute(
                    text(
                        "SELECT id,user_id,organisation_id,role "
                        "FROM security_organisation_memberships"
                    )
                )
                .mappings()
                .one()
            )
            entitlement = (
                verification.execute(
                    text(
                        "SELECT id,organisation_id,plan_id "
                        "FROM security_entitlement_snapshots"
                    )
                )
                .mappings()
                .one()
            )
            audit = (
                verification.execute(
                    text(
                        "SELECT id,request_id,actor_user_id,organisation_id,reason_code "
                        "FROM security_audit_events"
                    )
                )
                .mappings()
                .one()
            )
        if (
            user["id"] != first_command.user_id
            or user["issuer"] != first_command.issuer
            or user["subject"] != first_command.subject
            or organisation["id"] != first_command.organisation_id
            or organisation["slug"] != first_command.organisation_slug
            or membership["id"] != first_command.membership_id
            or membership["user_id"] != first_command.user_id
            or membership["organisation_id"] != first_command.organisation_id
            or membership["role"] != "owner"
            or entitlement["id"] != first_command.entitlement.snapshot_id
            or entitlement["organisation_id"] != first_command.organisation_id
            or entitlement["plan_id"] != first_command.entitlement.plan_id
            or audit["id"] != first_command.bootstrap_id
            or audit["request_id"] != first_command.request_id
            or audit["actor_user_id"] != first_command.user_id
            or audit["organisation_id"] != first_command.organisation_id
            or audit["reason_code"] != "initial_security_bootstrap"
        ):
            raise AssertionError("winning bootstrap records lost exact correlation")
        losing_ids: tuple[UUID, ...] = (
            second_command.bootstrap_id,
            second_command.request_id,
            second_command.user_id,
            second_command.organisation_id,
            second_command.membership_id,
            second_command.entitlement.snapshot_id,
        )
        persisted_text = " ".join(
            str(value)
            for row in (user, organisation, membership, entitlement, audit)
            for value in row.values()
        )
        if any(str(value) in persisted_text for value in losing_ids):
            raise AssertionError("rejected bootstrap identity entered persistence")

        isolated_engine.dispose()
        isolated_engine = None
        with administration_engine.connect() as connection:
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.downgrade(alembic_config(connection), PHASE8_BASE)
            revision = connection.scalar(
                text(
                    "SELECT CASE WHEN count(*) = 1 THEN min(version_num) END "
                    "FROM alembic_version"
                )
            )
            if revision != PHASE8_BASE:
                raise AssertionError(
                    "isolated downgrade did not reach the Phase 8 base"
                )
            remaining = set(inspect(connection).get_table_names(schema=schema))
            if set(SECURITY_TABLES) & remaining:
                raise AssertionError(
                    "security tables remained after isolated downgrade"
                )
            function_count = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_proc AS procedure "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid=procedure.pronamespace "
                    "WHERE namespace.nspname=:schema AND procedure.proname IN "
                    "('phase8_reject_entitlement_snapshot_mutation',"
                    "'phase8_reject_security_audit_mutation')"
                ),
                {"schema": schema},
            )
            if function_count != 0:
                raise AssertionError(
                    "Phase 8 trigger functions remained after downgrade"
                )

        print(f"Temporary schema: {schema}")
        print(f"Upgrade head: {PHASE8_SECURITY_HEAD}")
        print("Concurrent attempts: 2 started against one empty security domain")
        print(
            "Exclusive lock: second revision read blocked until first transaction committed"
        )
        print("Winning bootstrap: exactly 5 correlated records committed")
        print("Rejected bootstrap: empty-domain recheck failed after lock acquisition")
        print("Rejected identity persistence: none")
        print("Session outcomes: one commit; one rollback; both closed")
        print(f"Downgrade target: {PHASE8_BASE} verified")
    finally:
        first_tracker.release.set()
        if isolated_engine is not None:
            isolated_engine.dispose()
        try:
            if created:
                with administration_engine.begin() as cleanup:
                    cleanup.execute(text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
            with administration_engine.connect() as verification:
                schema_count = verification.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.schemata "
                        "WHERE schema_name=:schema"
                    ),
                    {"schema": schema},
                )
            public_after = public_snapshot(administration_engine)
            if schema_count != 0:
                raise AssertionError("temporary schema cleanup was incomplete")
            if public_before is not None and public_after != public_before:
                raise AssertionError(
                    "operational public security state changed during isolated proof"
                )
        finally:
            administration_engine.dispose()

    print("Temporary schema cleanup: complete")
    print("Operational public schema: exact revision and empty security rows unchanged")
    print("Operational app.main activation: not performed")


if __name__ == "__main__":
    main()
