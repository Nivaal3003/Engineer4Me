"""Focused tests for fail-closed audited access orchestration."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.repositories.security_audit_repository import SecurityAuditPersistenceError
from app.security.audit_models import SecurityAuditEventType, SecurityAuditOutcome
from app.security.authorization import AuthorizationDecision, AuthorizationReason, ResourceKind
from app.security.identity_models import OrganisationRole, Permission
from app.services.security_access_service import AccessOutcomeReason, SecurityAccessCommand, SecurityAccessOutcome, TrustedAuthenticationContext
from app.services.security_audit_service import AuditedSecurityAccessService, SecurityAuditCorrelationError


NOW=datetime(2026,8,8,19,0,tzinfo=UTC);ORGANISATION_ID=uuid4();USER_ID=uuid4();REQUEST_ID=uuid4();EVENT_ID=uuid4()


def authentication(): return TrustedAuthenticationContext(issuer="issuer",subject="subject",authenticated_at=NOW,session_id=uuid4())
def command(): return SecurityAccessCommand(request_id=REQUEST_ID,organisation_id=ORGANISATION_ID,permission=Permission.ENGINEERING_READ,resource_kind=ResourceKind.ENGINEERING_CASE,resource_id="case-140")


class AccessService:
    def __init__(self,outcome): self.outcome=outcome
    def evaluate(self,authentication,command): return self.outcome


class AuditRepository:
    def __init__(self,error=None): self.events=[];self.error=error
    def append(self,event):
        if self.error: raise self.error
        self.events.append(event);return event


def outcome(*,allowed=True,reason=AccessOutcomeReason.ALLOWED,user_id=USER_ID,request_id=REQUEST_ID,organisation_id=ORGANISATION_ID):
    authorization=None
    if allowed:
        authorization=AuthorizationDecision(request_id=request_id,user_id=user_id,organisation_id=organisation_id,permission=Permission.ENGINEERING_READ,resource_kind=ResourceKind.ENGINEERING_CASE,resource_id="case-140",allowed=True,reason=AuthorizationReason.ALLOWED,role=OrganisationRole.ENGINEER)
    return SecurityAccessOutcome(request_id=request_id,organisation_id=organisation_id,user_id=user_id,allowed=allowed,reason=reason,authorization=authorization)


def audited(value,repository=None):
    repository=repository or AuditRepository();service=AuditedSecurityAccessService(access_service=AccessService(value),audit_repository=repository,clock=lambda:NOW,event_id_factory=lambda:EVENT_ID);return service,repository


def test_allowed_outcome_is_recorded_before_return_with_exact_correlation():
    service,repository=audited(outcome());result=service.evaluate(authentication(),command());event=repository.events[0]
    assert result.allowed is True and event.event_id==EVENT_ID and event.request_id==REQUEST_ID
    assert event.event_type is SecurityAuditEventType.ACCESS_ALLOWED and event.outcome is SecurityAuditOutcome.SUCCEEDED
    assert event.actor_user_id==USER_ID and event.context=={"decision_reason":"allowed","policy_version":"1.0.0"}


def test_unknown_identity_denial_is_audited_without_invented_actor_or_external_identity():
    denied=outcome(allowed=False,reason=AccessOutcomeReason.IDENTITY_NOT_FOUND,user_id=None);service,repository=audited(denied);service.evaluate(authentication(),command());event=repository.events[0]
    assert event.event_type is SecurityAuditEventType.ACCESS_DENIED and event.actor_user_id is None
    assert event.reason_code=="identity_not_found" and event.context=={}
    assert "subject" not in event.context and "issuer" not in event.context


@pytest.mark.parametrize("reason",[AccessOutcomeReason.IDENTITY_NOT_ACTIVE,AccessOutcomeReason.AUTHORIZATION_DENIED,AccessOutcomeReason.ENTITLEMENT_NOT_FOUND,AccessOutcomeReason.ENTITLEMENT_DENIED])
def test_all_completed_denial_reasons_are_audited(reason):
    service,repository=audited(outcome(allowed=False,reason=reason));service.evaluate(authentication(),command());assert repository.events[0].reason_code==reason.value


def test_mismatched_request_or_organisation_is_rejected_before_audit_write():
    repository=AuditRepository();service,_=audited(outcome(request_id=uuid4()),repository)
    with pytest.raises(SecurityAuditCorrelationError,match="correlation failed"): service.evaluate(authentication(),command())
    assert repository.events==[]


def test_audit_persistence_failure_fails_closed_instead_of_returning_access():
    repository=AuditRepository(SecurityAuditPersistenceError("storage unavailable"));service,_=audited(outcome(),repository)
    with pytest.raises(SecurityAuditPersistenceError,match="storage unavailable"): service.evaluate(authentication(),command())


def test_unexpected_access_evaluation_failure_produces_no_fabricated_audit_event():
    class BrokenAccess:
        def evaluate(self,authentication,command): raise RuntimeError("evaluation defect")
    repository=AuditRepository();service=AuditedSecurityAccessService(access_service=BrokenAccess(),audit_repository=repository)
    with pytest.raises(RuntimeError,match="evaluation defect"): service.evaluate(authentication(),command())
    assert repository.events==[]
