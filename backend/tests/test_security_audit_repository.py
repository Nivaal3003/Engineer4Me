"""Focused tests for tenant-explicit append-only security audit persistence."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import SecurityOrganisation, SecurityUser
from app.repositories.security_audit_repository import SecurityAuditCorruptionError, SecurityAuditPersistenceError, SecurityAuditRepository
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.security.authorization import ResourceKind
from app.security.identity_models import Permission


NOW = datetime(2026, 8, 8, 18, 0, tzinfo=UTC)


@pytest.fixture
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        yield value
    engine.dispose()


def seed_identity(session, *, organisation_id=None, user_id=None):
    organisation_id = organisation_id or uuid4(); user_id = user_id or uuid4()
    session.add(SecurityUser(id=user_id, email=f"{user_id}@example.com", display_name="Audit User", status="active", issuer="issuer", subject=str(user_id)))
    session.add(SecurityOrganisation(id=organisation_id, slug=f"org-{organisation_id.hex[:12]}", name="Audit Organisation", status="active"))
    session.flush()
    return user_id, organisation_id


def event(*, user_id, organisation_id, occurred_at=NOW, request_id=None, event_id=None):
    return SecurityAuditEvent(
        event_id=event_id or uuid4(), occurred_at=occurred_at, event_type=SecurityAuditEventType.ACCESS_ALLOWED,
        outcome=SecurityAuditOutcome.SUCCEEDED, reason_code="allowed", request_id=request_id or uuid4(),
        actor_user_id=user_id, organisation_id=organisation_id, session_id=uuid4(), permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE, resource_id="case-139", context={"policy_version": "1.0.0"},
    )


def test_append_and_tenant_read_round_trip_exact_contract(session):
    user_id, organisation_id = seed_identity(session)
    repository = SecurityAuditRepository(session); value = event(user_id=user_id, organisation_id=organisation_id)
    assert repository.append(value) is value
    assert repository.for_organisation(organisation_id=organisation_id) == (value,)


def test_organisation_reads_never_cross_tenant_boundary(session):
    user_a, organisation_a = seed_identity(session)
    user_b, organisation_b = seed_identity(session)
    repository = SecurityAuditRepository(session)
    event_a = event(user_id=user_a, organisation_id=organisation_a)
    event_b = event(user_id=user_b, organisation_id=organisation_b)
    repository.append(event_a); repository.append(event_b)
    assert repository.for_organisation(organisation_id=organisation_a) == (event_a,)
    assert repository.for_organisation(organisation_id=organisation_b) == (event_b,)


def test_reads_are_newest_first_and_cursor_is_exclusive(session):
    user_id, organisation_id = seed_identity(session); repository = SecurityAuditRepository(session)
    older = event(user_id=user_id, organisation_id=organisation_id, occurred_at=NOW-timedelta(minutes=2))
    middle = event(user_id=user_id, organisation_id=organisation_id, occurred_at=NOW-timedelta(minutes=1))
    newest = event(user_id=user_id, organisation_id=organisation_id)
    for value in (middle, newest, older): repository.append(value)
    assert repository.for_organisation(organisation_id=organisation_id) == (newest, middle, older)
    assert repository.for_organisation(organisation_id=organisation_id, occurred_before=middle.occurred_at) == (older,)


def test_request_correlation_is_oldest_first(session):
    user_id, organisation_id = seed_identity(session); repository = SecurityAuditRepository(session); request_id = uuid4()
    first = event(user_id=user_id, organisation_id=organisation_id, occurred_at=NOW-timedelta(seconds=1), request_id=request_id)
    second = event(user_id=user_id, organisation_id=organisation_id, request_id=request_id)
    repository.append(second); repository.append(first)
    assert repository.for_request(request_id=request_id) == (first, second)


@pytest.mark.parametrize("limit", [0, 201, True, 1.5])
def test_query_limits_are_strictly_bounded(session, limit):
    repository = SecurityAuditRepository(session)
    with pytest.raises(ValueError, match="between 1 and 200"):
        repository.for_organisation(organisation_id=uuid4(), limit=limit)


def test_naive_cursor_is_rejected(session):
    with pytest.raises(ValueError, match="timezone-aware"):
        SecurityAuditRepository(session).for_organisation(organisation_id=uuid4(), occurred_before=datetime(2026, 8, 8))


def test_duplicate_event_identity_is_sanitized_and_rolled_back(session):
    user_id, organisation_id = seed_identity(session); repository = SecurityAuditRepository(session)
    value = event(user_id=user_id, organisation_id=organisation_id); repository.append(value); session.commit()
    with pytest.raises(SecurityAuditPersistenceError, match="persistence constraint"):
        repository.append(value)
    assert session.in_transaction() is False


def test_sensitive_persisted_context_fails_strict_reconstruction(session):
    user_id, organisation_id = seed_identity(session)
    session.add(SecurityAuditRecord(
        id=uuid4(), occurred_at=NOW, event_type="access_allowed", outcome="succeeded", reason_code="allowed", request_id=uuid4(),
        actor_user_id=user_id, organisation_id=organisation_id, session_id=uuid4(), permission="engineering:read",
        resource_kind="engineering_case", resource_id="case-139", context={"access_token": "forbidden"},
    ))
    session.flush()
    with pytest.raises(SecurityAuditCorruptionError, match="trusted contract"):
        SecurityAuditRepository(session).for_organisation(organisation_id=organisation_id)


def test_repository_exposes_no_update_or_delete_operation(session):
    repository = SecurityAuditRepository(session)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
