"""Focused contracts and ORM tests for append-only security audit events."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import ImmutableSecurityRecordError, SecurityOrganisation, SecurityUser
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.security.authorization import ResourceKind
from app.security.identity_models import Permission


NOW = datetime(2026, 8, 8, 16, 30, tzinfo=UTC)


def access_event(**overrides):
    values = dict(
        event_id=uuid4(), occurred_at=NOW, event_type=SecurityAuditEventType.ACCESS_ALLOWED,
        outcome=SecurityAuditOutcome.SUCCEEDED, reason_code="allowed", request_id=uuid4(), actor_user_id=uuid4(),
        organisation_id=uuid4(), session_id=uuid4(), permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE, resource_id="case-136",
        context={"policy_version": "1.0.0", "cached_key": True},
    )
    values.update(overrides); return SecurityAuditEvent(**values)


def test_complete_allowed_access_event_is_immutable_and_bounded():
    value = access_event(); assert value.context["cached_key"] is True
    with pytest.raises(ValidationError): value.reason_code = "replacement"


@pytest.mark.parametrize("missing", ["request_id", "organisation_id", "session_id", "permission", "resource_kind"])
def test_access_events_require_complete_trusted_request_context(missing):
    with pytest.raises(ValidationError, match="complete trusted request context"): access_event(**{missing: None})


def test_allowed_access_requires_internal_actor_but_unknown_identity_denial_does_not_invent_one():
    with pytest.raises(ValidationError, match="internal actor"): access_event(actor_user_id=None)
    denied = access_event(event_type=SecurityAuditEventType.ACCESS_DENIED, outcome=SecurityAuditOutcome.DENIED, reason_code="identity_not_found", actor_user_id=None)
    assert denied.actor_user_id is None


@pytest.mark.parametrize("key", ["authorization_header", "bearer_value", "password_hash", "client_secret", "access_token", "raw_jwt", "token_claims"])
def test_sensitive_context_keys_are_rejected(key):
    with pytest.raises(ValidationError, match="forbidden sensitive field"): access_event(context={key: "must-not-be-stored"})


def test_context_count_and_string_length_are_bounded():
    with pytest.raises(ValidationError): access_event(context={f"field_{index}": index for index in range(21)})
    with pytest.raises(ValidationError, match="string values are bounded"): access_event(context={"provider_status": "x" * 301})


@pytest.mark.parametrize(("event_type", "outcome"), [(SecurityAuditEventType.ACCESS_ALLOWED, SecurityAuditOutcome.DENIED), (SecurityAuditEventType.ACCESS_DENIED, SecurityAuditOutcome.SUCCEEDED), (SecurityAuditEventType.AUTHENTICATION_FAILED, SecurityAuditOutcome.SUCCEEDED), (SecurityAuditEventType.AUTHENTICATION_PROVIDER_UNAVAILABLE, SecurityAuditOutcome.DENIED)])
def test_event_type_and_outcome_must_be_consistent(event_type, outcome):
    with pytest.raises(ValidationError): access_event(event_type=event_type, outcome=outcome)


def test_successful_authentication_requires_actor_and_session_ids():
    with pytest.raises(ValidationError, match="actor and session"):
        SecurityAuditEvent(event_id=uuid4(), occurred_at=NOW, event_type=SecurityAuditEventType.AUTHENTICATION_SUCCEEDED, outcome=SecurityAuditOutcome.SUCCEEDED, reason_code="verified")


def test_sqlalchemy_audit_record_is_append_only():
    engine=create_engine("sqlite+pysqlite:///:memory:");Base.metadata.create_all(engine);user_id=uuid4();organisation_id=uuid4()
    with Session(engine) as session:
        session.add(SecurityUser(id=user_id,email="audit@example.com",display_name="Audit User",status="active",issuer="issuer",subject="subject"));session.add(SecurityOrganisation(id=organisation_id,slug="audit-org",name="Audit Organisation",status="active"));session.flush()
        row=SecurityAuditRecord(id=uuid4(),occurred_at=NOW,event_type="access_allowed",outcome="succeeded",reason_code="allowed",request_id=uuid4(),actor_user_id=user_id,organisation_id=organisation_id,session_id=uuid4(),permission="engineering:read",resource_kind="engineering_case",resource_id="case-136",context={"policy_version":"1.0.0"});session.add(row);session.flush();row.reason_code="changed"
        with pytest.raises(ImmutableSecurityRecordError,match="append-only"): session.flush()


def test_sqlalchemy_audit_record_rejects_delete():
    engine=create_engine("sqlite+pysqlite:///:memory:");Base.metadata.create_all(engine)
    with Session(engine) as session:
        row=SecurityAuditRecord(id=uuid4(),occurred_at=NOW,event_type="authentication_failed",outcome="denied",reason_code="invalid_token",context={});session.add(row);session.flush();session.delete(row)
        with pytest.raises(ImmutableSecurityRecordError,match="append-only"): session.flush()
