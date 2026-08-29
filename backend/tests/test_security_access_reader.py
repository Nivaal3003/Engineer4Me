"""Short-lived security access read-session boundary tests."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.repositories.security_repository import (
    SecurityPersistenceCorruptionError,
    SecurityRepository,
)
from app.security.authorization import ResourceKind
from app.security.identity_models import (
    IdentityStatus,
    MembershipStatus,
    OrganisationMembership,
    OrganisationRole,
    Permission,
)
from app.services.security_access_reader import (
    SecurityAccessReadError,
    SessionFactorySecurityAccessService,
)
from app.services.security_access_service import (
    AccessOutcomeReason,
    SecurityAccessCommand,
    TrustedAuthenticationContext,
)


NOW = datetime(2026, 8, 9, 8, 0, tzinfo=UTC)
ORGANISATION_ID = uuid4()
USER_ID = uuid4()


class ProbeSession(Session):
    def __init__(self):
        self.rollbacks = 0
        self.closes = 0
        self.commits = 0

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1

    def commit(self):
        self.commits += 1
        raise AssertionError("security access read session must never commit")


class StubRepository(SecurityRepository):
    def __init__(self, *, user=True, error=None):
        self._user = user
        self._error = error

    def user_by_external_identity(self, *, issuer, subject):
        if self._error is not None:
            raise self._error
        if not self._user:
            return None
        return SimpleNamespace(
            id=USER_ID,
            email="owner@engineer4me.test",
            display_name="Initial Owner",
            status=IdentityStatus.ACTIVE.value,
        )

    def active_membership_contract(self, *, user_id, organisation_id):
        assert user_id == USER_ID and organisation_id == ORGANISATION_ID
        return OrganisationMembership(
            membership_id=uuid4(),
            organisation_id=ORGANISATION_ID,
            role=OrganisationRole.OWNER,
            status=MembershipStatus.ACTIVE,
            joined_at=NOW,
        )


class SessionFactory:
    def __init__(self):
        self.sessions = []

    def __call__(self):
        session = ProbeSession()
        self.sessions.append(session)
        return session


def authentication():
    return TrustedAuthenticationContext(
        issuer="https://identity.engineer4me.test",
        subject="owner-subject",
        authenticated_at=NOW,
        session_id=uuid4(),
    )


def command():
    return SecurityAccessCommand(
        request_id=uuid4(),
        organisation_id=ORGANISATION_ID,
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE,
    )


def test_construction_is_lazy_and_performs_no_session_access():
    factory = SessionFactory()
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(),
    )
    assert isinstance(service, SessionFactorySecurityAccessService)
    assert factory.sessions == []


def test_allowed_decision_uses_one_fresh_session_then_rolls_back_and_closes():
    factory = SessionFactory()
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(),
    )
    outcome = service.evaluate(authentication(), command())
    assert outcome.allowed is True
    assert outcome.reason is AccessOutcomeReason.ALLOWED
    assert len(factory.sessions) == 1
    assert factory.sessions[0].rollbacks == 1
    assert factory.sessions[0].closes == 1
    assert factory.sessions[0].commits == 0


def test_denied_decision_is_also_rolled_back_and_closed_without_commit():
    factory = SessionFactory()
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(user=False),
    )
    outcome = service.evaluate(authentication(), command())
    assert outcome.allowed is False
    assert outcome.reason is AccessOutcomeReason.IDENTITY_NOT_FOUND
    assert factory.sessions[0].rollbacks == 1
    assert factory.sessions[0].closes == 1
    assert factory.sessions[0].commits == 0


def test_each_decision_receives_a_distinct_read_session():
    factory = SessionFactory()
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(),
    )
    service.evaluate(authentication(), command())
    service.evaluate(authentication(), command())
    assert len(factory.sessions) == 2
    assert factory.sessions[0] is not factory.sessions[1]
    assert all(item.rollbacks == 1 and item.closes == 1 for item in factory.sessions)


def test_sqlalchemy_read_failure_is_sanitized_and_session_is_closed():
    factory = SessionFactory()
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(
            error=SQLAlchemyError("private database detail")
        ),
    )
    with pytest.raises(SecurityAccessReadError, match="could not be completed") as captured:
        service.evaluate(authentication(), command())
    assert "private database detail" not in str(captured.value)
    assert factory.sessions[0].rollbacks == 1
    assert factory.sessions[0].closes == 1


def test_trusted_corruption_failure_remains_fail_closed_and_session_is_closed():
    factory = SessionFactory()
    corruption = SecurityPersistenceCorruptionError(
        "persisted membership failed trusted contract validation"
    )
    service = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: StubRepository(error=corruption),
    )
    with pytest.raises(SecurityPersistenceCorruptionError, match="trusted contract"):
        service.evaluate(authentication(), command())
    assert factory.sessions[0].rollbacks == 1
    assert factory.sessions[0].closes == 1


def test_factory_failure_is_sanitized_without_inventing_a_session():
    def unavailable():
        raise SQLAlchemyError("private connection detail")

    service = SessionFactorySecurityAccessService(unavailable)
    with pytest.raises(SecurityAccessReadError, match="could not be completed") as captured:
        service.evaluate(authentication(), command())
    assert "private connection detail" not in str(captured.value)


def test_invalid_session_or_repository_contract_fails_closed():
    invalid_session = SessionFactorySecurityAccessService(lambda: object())
    with pytest.raises(SecurityAccessReadError, match="session is unavailable"):
        invalid_session.evaluate(authentication(), command())
    factory = SessionFactory()
    invalid_repository = SessionFactorySecurityAccessService(
        factory,
        repository_factory=lambda session: object(),
    )
    with pytest.raises(SecurityAccessReadError, match="repository is unavailable"):
        invalid_repository.evaluate(authentication(), command())
    assert factory.sessions[0].rollbacks == 1
    assert factory.sessions[0].closes == 1


@pytest.mark.parametrize("session_factory,repository_factory", [(None, SecurityRepository), (lambda: ProbeSession(), None)])
def test_noncallable_factories_are_rejected(session_factory, repository_factory):
    with pytest.raises(TypeError, match="factory must be callable"):
        SessionFactorySecurityAccessService(
            session_factory,
            repository_factory=repository_factory,
        )
