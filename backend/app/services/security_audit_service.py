"""Fail-closed orchestration that records every completed access decision."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.services.security_access_service import SecurityAccessCommand, SecurityAccessOutcome, SecurityAccessService, TrustedAuthenticationContext


class SecurityAuditCorrelationError(RuntimeError):
    """The evaluated outcome does not match the originating access command."""


class SecurityAuditAppender(Protocol):
    def append(self, event: SecurityAuditEvent) -> SecurityAuditEvent: ...


Clock = Callable[[], datetime]
EventIDFactory = Callable[[], UUID]


class AuditedSecurityAccessService:
    def __init__(self, *, access_service: SecurityAccessService, audit_repository: SecurityAuditAppender, clock: Clock | None = None, event_id_factory: EventIDFactory = uuid4) -> None:
        self._access_service = access_service
        self._audit_repository = audit_repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._event_id_factory = event_id_factory

    def evaluate(self, authentication: TrustedAuthenticationContext, command: SecurityAccessCommand) -> SecurityAccessOutcome:
        outcome = self._access_service.evaluate(authentication, command)
        if outcome.request_id != command.request_id or outcome.organisation_id != command.organisation_id:
            raise SecurityAuditCorrelationError("security access outcome correlation failed")
        context: dict[str, str | int | bool] = {}
        if outcome.authorization is not None:
            context["decision_reason"] = outcome.authorization.reason.value
            context["policy_version"] = outcome.authorization.policy_version
        if outcome.entitlement is not None:
            context["entitlement_reason"] = outcome.entitlement.reason.value
            context["entitlement_plan"] = outcome.entitlement.plan_id
        audit_event = SecurityAuditEvent(
            event_id=self._event_id_factory(),
            occurred_at=self._clock(),
            event_type=SecurityAuditEventType.ACCESS_ALLOWED if outcome.allowed else SecurityAuditEventType.ACCESS_DENIED,
            outcome=SecurityAuditOutcome.SUCCEEDED if outcome.allowed else SecurityAuditOutcome.DENIED,
            reason_code=outcome.reason.value,
            request_id=command.request_id,
            actor_user_id=outcome.user_id,
            organisation_id=command.organisation_id,
            session_id=authentication.session_id,
            permission=command.permission,
            resource_kind=command.resource_kind,
            resource_id=command.resource_id,
            context=context,
        )
        self._audit_repository.append(audit_event)
        return outcome
