"""Focused tests for atomic, empty-domain-only security bootstrap persistence."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import (
    SecurityEntitlementSnapshot,
    SecurityOrganisation,
    SecurityOrganisationMembership,
    SecurityUser,
)
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
    TransactionalSecurityBootstrapExecutor,
)


NOW = datetime(2026, 8, 9, 0, 0, tzinfo=UTC)
ORGANISATION_ID = uuid4()
USER_ID = uuid4()
MEMBERSHIP_ID = uuid4()
BOOTSTRAP_ID = uuid4()
REQUEST_ID = uuid4()
SNAPSHOT_ID = uuid4()


def command():
    snapshot = OrganisationEntitlementSnapshot(
        snapshot_id=SNAPSHOT_ID,
        organisation_id=ORGANISATION_ID,
        plan_id="reviewed-plan-148",
        subscription_status=SubscriptionStatus.TRIAL,
        features=(ControlledFeature.ENGINEERING_CALCULATIONS,),
        quotas=(),
        effective_at=NOW,
        expires_at=NOW + timedelta(days=30),
        source_reference="approved bootstrap 148",
    )
    return SecurityBootstrapCommand(
        bootstrap_id=BOOTSTRAP_ID,
        request_id=REQUEST_ID,
        user_id=USER_ID,
        organisation_id=ORGANISATION_ID,
        membership_id=MEMBERSHIP_ID,
        email="owner@example.com",
        display_name="Initial Owner",
        issuer="https://identity.engineer4me.test",
        subject="subject-148",
        organisation_slug="initial-org",
        organisation_name="Initial Organisation",
        initial_role=OrganisationRole.OWNER,
        activated_at=NOW,
        entitlement=snapshot,
    )


class Session:
    def __init__(self, counts=None, commit_error=None, flush_error_at=None):
        self.scalar_values = list(counts or [0, 0, 0, 0, 0, None])
        self.commit_error = commit_error
        self.flush_error_at = flush_error_at
        self.flushes = 0
        self.added = []
        self.actions = []

    def scalar(self, statement):
        self.actions.append("scalar")
        return self.scalar_values.pop(0)

    def add(self, value):
        self.added.append(value)
        self.actions.append("add")

    def flush(self):
        self.flushes += 1
        self.actions.append("flush")
        if self.flush_error_at == self.flushes:
            raise SQLAlchemyError("private flush detail")

    def commit(self):
        self.actions.append("commit")
        if self.commit_error:
            raise self.commit_error

    def rollback(self):
        self.actions.append("rollback")

    def close(self):
        self.actions.append("close")


def test_complete_bootstrap_is_committed_once_and_returns_only_correlated_ids():
    session = Session()
    receipt = TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert (
        receipt.bootstrap_id,
        receipt.request_id,
        receipt.user_id,
        receipt.organisation_id,
        receipt.membership_id,
        receipt.entitlement_snapshot_id,
    ) == (
        BOOTSTRAP_ID,
        REQUEST_ID,
        USER_ID,
        ORGANISATION_ID,
        MEMBERSHIP_ID,
        SNAPSHOT_ID,
    )
    assert (
        session.actions[-2:] == ["commit", "close"]
        and "rollback" not in session.actions
    )


def test_all_five_records_share_the_same_atomic_session():
    session = Session()
    TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert [type(value) for value in session.added] == [
        SecurityUser,
        SecurityOrganisation,
        SecurityOrganisationMembership,
        SecurityEntitlementSnapshot,
        SecurityAuditRecord,
    ]
    assert len(session.added) == 5 and session.flushes == 5


@pytest.mark.parametrize("occupied_index", range(5))
def test_any_existing_security_domain_record_rejects_one_time_bootstrap(occupied_index):
    counts = [0, 0, 0, 0, 0]
    counts[occupied_index] = 1
    session = Session(counts=counts)
    with pytest.raises(SecurityBootstrapStateError, match="empty security domain"):
        TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert session.added == [] and session.actions[-2:] == ["rollback", "close"]


def test_flush_failure_rolls_back_closes_and_is_sanitized():
    session = Session(flush_error_at=3)
    with pytest.raises(
        SecurityBootstrapPersistenceError, match="could not be committed"
    ) as captured:
        TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert "private flush detail" not in str(captured.value) and session.actions[
        -2:
    ] == ["rollback", "close"]
    assert captured.value.__cause__ is None


def test_commit_failure_rolls_back_closes_and_returns_no_receipt():
    session = Session(commit_error=SQLAlchemyError("private commit detail"))
    with pytest.raises(
        SecurityBootstrapPersistenceError, match="could not be committed"
    ):
        TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert session.actions[-3:] == ["commit", "rollback", "close"]


def test_session_factory_database_failure_is_sanitized():
    def unavailable():
        raise SQLAlchemyError("private connection detail")

    with pytest.raises(
        SecurityBootstrapPersistenceError, match="could not be committed"
    ):
        TransactionalSecurityBootstrapExecutor(unavailable).execute(command())


def test_non_callable_session_factory_is_rejected():
    with pytest.raises(TypeError, match="must be callable"):
        TransactionalSecurityBootstrapExecutor(None)


def test_non_callable_transaction_guard_is_rejected():
    with pytest.raises(TypeError, match="transaction guard must be callable"):
        TransactionalSecurityBootstrapExecutor(
            lambda: Session(), transaction_guard="not-callable"
        )


def test_optional_transaction_guard_runs_before_empty_domain_queries():
    session = Session()
    guard_calls = []

    def guard(value):
        guard_calls.append(value)
        value.actions.append("guard")

    TransactionalSecurityBootstrapExecutor(
        lambda: session, transaction_guard=guard
    ).execute(command())
    assert guard_calls == [session] and session.actions[0:2] == ["guard", "scalar"]


def test_unexpected_programming_failure_is_not_misreported_as_database_failure():
    class BrokenSession(Session):
        def scalar(self, statement):
            raise RuntimeError("programming defect")

    session = BrokenSession()
    with pytest.raises(RuntimeError, match="programming defect"):
        TransactionalSecurityBootstrapExecutor(lambda: session).execute(command())
    assert session.actions == ["rollback", "close"]
