"""Focused tests for isolated durable security audit transactions."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.repositories.security_audit_repository import SecurityAuditPersistenceError
from app.repositories.security_audit_writer import DurableSecurityAuditWriter
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome


def event():
    return SecurityAuditEvent(
        event_id=uuid4(),
        occurred_at=datetime(2026, 8, 8, 21, 0, tzinfo=UTC),
        event_type=SecurityAuditEventType.SECURITY_STATE_CHANGED,
        outcome=SecurityAuditOutcome.SUCCEEDED,
        reason_code="writer_probe",
    )


class Session:
    def __init__(self, *, commit_error=None):
        self.actions = []
        self.commit_error = commit_error

    def add(self, value): self.actions.append(("add", value))
    def flush(self): self.actions.append(("flush", None))
    def commit(self):
        self.actions.append(("commit", None))
        if self.commit_error is not None: raise self.commit_error
    def rollback(self): self.actions.append(("rollback", None))
    def close(self): self.actions.append(("close", None))


def test_event_is_returned_only_after_isolated_commit_and_close():
    session = Session();value = event();writer = DurableSecurityAuditWriter(lambda: session)
    assert writer.append(value) is value
    assert [action for action, _ in session.actions] == ["add", "flush", "commit", "close"]


def test_commit_failure_rolls_back_closes_and_is_sanitized():
    session = Session(commit_error=SQLAlchemyError("private database detail"));writer = DurableSecurityAuditWriter(lambda: session)
    with pytest.raises(SecurityAuditPersistenceError, match="could not be committed") as captured: writer.append(event())
    assert "private database detail" not in str(captured.value)
    assert [action for action, _ in session.actions][-3:] == ["commit", "rollback", "close"]


def test_session_factory_failure_is_sanitized_without_fabricated_cleanup():
    def unavailable(): raise SQLAlchemyError("private connection detail")
    with pytest.raises(SecurityAuditPersistenceError, match="could not be committed"):
        DurableSecurityAuditWriter(unavailable).append(event())


def test_each_event_uses_a_fresh_isolated_session():
    sessions = []
    def factory():
        value = Session();sessions.append(value);return value
    writer = DurableSecurityAuditWriter(factory);writer.append(event());writer.append(event())
    assert len(sessions) == 2 and sessions[0] is not sessions[1]


def test_non_callable_session_factory_is_rejected():
    with pytest.raises(TypeError, match="must be callable"): DurableSecurityAuditWriter(None)
