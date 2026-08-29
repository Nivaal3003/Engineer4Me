"""Focused tests for exclusive operational bootstrap transaction serialization."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import (
    ControlledFeature,
    OrganisationEntitlementSnapshot,
    SubscriptionStatus,
)
from app.security.identity_models import OrganisationRole
from app.services.security_bootstrap_executor import (
    SecurityBootstrapPersistenceError,
    SecurityBootstrapStateError,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
    OperationalSecurityBootstrapExecutor,
    PostgreSQLSecurityBootstrapTransactionGuard,
)


NOW = datetime(2026, 8, 9, 14, 0, tzinfo=UTC)


def command() -> SecurityBootstrapCommand:
    organisation_id = uuid4()
    return SecurityBootstrapCommand(
        bootstrap_id=uuid4(),
        request_id=uuid4(),
        user_id=uuid4(),
        organisation_id=organisation_id,
        membership_id=uuid4(),
        email="owner@example.com",
        display_name="Initial Owner",
        issuer="https://identity.engineer4me.test/tenant",
        subject="provider-owner-subject-step176",
        organisation_slug="initial-org-step176",
        organisation_name="Initial Organisation Step 176",
        initial_role=OrganisationRole.OWNER,
        activated_at=NOW,
        entitlement=OrganisationEntitlementSnapshot(
            snapshot_id=uuid4(),
            organisation_id=organisation_id,
            plan_id="reviewed-plan-step176",
            subscription_status=SubscriptionStatus.TRIAL,
            features=(ControlledFeature.ENGINEERING_CALCULATIONS,),
            quotas=(),
            effective_at=NOW,
            expires_at=NOW + timedelta(days=30),
            source_reference="reviewed bootstrap step176",
        ),
    )


class OperationalSession:
    def __init__(
        self,
        *,
        schemas=(OPERATIONAL_SCHEMA, OPERATIONAL_SCHEMA),
        revisions=(PHASE8_SECURITY_HEAD, PHASE8_SECURITY_HEAD),
        counts=(0, 0, 0, 0, 0),
        lock_error: Exception | None = None,
    ) -> None:
        self.schemas = list(schemas)
        self.revisions = list(revisions)
        self.counts = list(counts)
        self.lock_error = lock_error
        self.actions: list[tuple[str, str] | str] = []
        self.added = []

    def scalar(self, statement):
        sql = " ".join(str(statement).split())
        self.actions.append(("scalar", sql))
        if sql == "SELECT current_schema()":
            return self.schemas.pop(0)
        if "alembic_version" in sql and sql.startswith("SELECT"):
            return self.revisions.pop(0)
        if "max(" in sql.lower():
            return None
        return self.counts.pop(0)

    def execute(self, statement):
        sql = " ".join(str(statement).split())
        self.actions.append(("execute", sql))
        if self.lock_error is not None:
            raise self.lock_error

    def add(self, value):
        self.added.append(value)
        self.actions.append("add")

    def flush(self):
        self.actions.append("flush")

    def commit(self):
        self.actions.append("commit")

    def rollback(self):
        self.actions.append("rollback")

    def close(self):
        self.actions.append("close")


def lock_action(session: OperationalSession) -> tuple[str, str] | None:
    return next(
        (
            action
            for action in session.actions
            if isinstance(action, tuple) and action[0] == "execute"
        ),
        None,
    )


def test_operational_executor_locks_every_security_table_before_emptiness_check():
    session = OperationalSession()
    receipt = OperationalSecurityBootstrapExecutor(lambda: session).execute(command())

    assert receipt.bootstrap_id is not None
    assert session.actions[0] == ("scalar", "SELECT current_schema()")
    assert 'FROM "public".alembic_version' in session.actions[1][1]
    lock = lock_action(session)
    assert lock is not None
    lock_index = session.actions.index(lock)
    first_domain_count = next(
        index
        for index, action in enumerate(session.actions)
        if isinstance(action, tuple)
        and action[0] == "scalar"
        and "SELECT count(*)" in action[1]
    )
    assert lock_index < first_domain_count
    assert "IN ACCESS EXCLUSIVE MODE" in lock[1]
    for table in (
        '"public"."alembic_version"',
        '"public"."security_users"',
        '"public"."security_organisations"',
        '"public"."security_organisation_memberships"',
        '"public"."security_entitlement_snapshots"',
        '"public"."security_audit_events"',
    ):
        assert table in lock[1]
    assert session.actions[-2:] == ["commit", "close"]


def test_guard_rechecks_schema_and_revision_after_exclusive_lock():
    session = OperationalSession()
    OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    lock_index = session.actions.index(lock_action(session))
    assert session.actions[lock_index + 1] == ("scalar", "SELECT current_schema()")
    assert 'FROM "public".alembic_version' in session.actions[lock_index + 2][1]


@pytest.mark.parametrize("schema", [None, "private", "e4m_phase8_step176_test"])
def test_non_public_schema_is_rejected_before_lock_or_write(schema):
    session = OperationalSession(schemas=(schema,))
    with pytest.raises(SecurityBootstrapStateError, match="unexpected schema"):
        OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert lock_action(session) is None
    assert session.added == []
    assert session.actions[-2:] == ["rollback", "close"]


@pytest.mark.parametrize("revision", [None, "c8f123a4d5e6", "unknown"])
def test_wrong_or_ambiguous_revision_is_rejected_before_lock_or_write(revision):
    session = OperationalSession(revisions=(revision,))
    with pytest.raises(SecurityBootstrapStateError, match="reviewed migration head"):
        OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert lock_action(session) is None
    assert session.added == []
    assert session.actions[-2:] == ["rollback", "close"]


@pytest.mark.parametrize(
    ("schemas", "revisions"),
    [
        ((OPERATIONAL_SCHEMA, "private"), (PHASE8_SECURITY_HEAD, PHASE8_SECURITY_HEAD)),
        (
            (OPERATIONAL_SCHEMA, OPERATIONAL_SCHEMA),
            (PHASE8_SECURITY_HEAD, "c8f123a4d5e6"),
        ),
    ],
)
def test_state_change_during_lock_acquisition_rolls_back_without_writes(
    schemas,
    revisions,
):
    session = OperationalSession(schemas=schemas, revisions=revisions)
    with pytest.raises(SecurityBootstrapStateError, match="changed while acquiring"):
        OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert lock_action(session) is not None
    assert session.added == []
    assert session.actions[-2:] == ["rollback", "close"]


def test_lock_database_failure_is_sanitized_rolled_back_and_closed():
    session = OperationalSession(
        lock_error=SQLAlchemyError("private database lock detail")
    )
    with pytest.raises(
        SecurityBootstrapPersistenceError,
        match="could not be committed",
    ) as captured:
        OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert "private database" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert session.added == []
    assert session.actions[-2:] == ["rollback", "close"]


def test_occupied_domain_is_checked_only_after_exclusive_lock():
    session = OperationalSession(counts=(0, 1, 0, 0, 0))
    with pytest.raises(SecurityBootstrapStateError, match="empty security domain"):
        OperationalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert lock_action(session) is not None
    assert session.added == []
    assert session.actions[-2:] == ["rollback", "close"]


def test_construction_is_lazy_and_opens_no_database_session():
    calls = []

    def factory():
        calls.append("session")
        return OperationalSession()

    executor = OperationalSecurityBootstrapExecutor(factory)
    assert calls == []
    executor.execute(command())
    assert calls == ["session"]


@pytest.mark.parametrize(
    "schema",
    [None, "", "Public", "private-schema", "private.schema", "a" * 64, 'bad"schema'],
)
def test_custom_guard_rejects_unsafe_schema_identifiers(schema):
    with pytest.raises(ValueError, match="schema is invalid"):
        PostgreSQLSecurityBootstrapTransactionGuard(
            expected_schema=schema,
            expected_revision=PHASE8_SECURITY_HEAD,
        )


@pytest.mark.parametrize("revision", [None, "", "head;drop", "x" * 101])
def test_custom_guard_rejects_unsafe_revision_identifiers(revision):
    with pytest.raises(ValueError, match="revision is invalid"):
        PostgreSQLSecurityBootstrapTransactionGuard(
            expected_schema=OPERATIONAL_SCHEMA,
            expected_revision=revision,
        )


def test_controlled_temporary_schema_guard_uses_only_quoted_exact_identifier():
    schema = "e4m_phase8_step177_0123456789abcdef0123456789abcdef"
    guard = PostgreSQLSecurityBootstrapTransactionGuard(
        expected_schema=schema,
        expected_revision=PHASE8_SECURITY_HEAD,
    )
    session = OperationalSession(schemas=(schema, schema))
    guard(session)
    lock = lock_action(session)
    assert lock is not None
    assert f'"{schema}"."security_users"' in lock[1]
    assert "public" not in lock[1]
