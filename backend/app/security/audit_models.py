"""Privacy-minimised immutable contracts for Phase 8 security audit events."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr, StringConstraints, model_validator

from app.security.authorization import ResourceKind
from app.security.identity_models import Permission, SecurityModel


AuditReasonCode = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")]
AuditContextKey = Annotated[str, StringConstraints(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]*$")]
AuditContextValue = StrictStr | StrictInt | StrictBool


class SecurityAuditEventType(StrEnum):
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHENTICATION_PROVIDER_UNAVAILABLE = "authentication_provider_unavailable"
    ACCESS_ALLOWED = "access_allowed"
    ACCESS_DENIED = "access_denied"
    ENTITLEMENT_EVALUATED = "entitlement_evaluated"
    SECURITY_STATE_CHANGED = "security_state_changed"


class SecurityAuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


_FORBIDDEN_CONTEXT_TERMS = frozenset({"authorization", "bearer", "cookie", "password", "secret", "token", "jwt", "claims"})
_ACCESS_EVENTS = frozenset({SecurityAuditEventType.ACCESS_ALLOWED, SecurityAuditEventType.ACCESS_DENIED})


class SecurityAuditEvent(SecurityModel):
    event_id: UUID
    occurred_at: AwareDatetime
    event_type: SecurityAuditEventType
    outcome: SecurityAuditOutcome
    reason_code: AuditReasonCode
    request_id: UUID | None = None
    actor_user_id: UUID | None = None
    organisation_id: UUID | None = None
    session_id: UUID | None = None
    permission: Permission | None = None
    resource_kind: ResourceKind | None = None
    resource_id: str | None = Field(default=None, min_length=1, max_length=300, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    context: dict[AuditContextKey, AuditContextValue] = Field(default_factory=dict, max_length=20)

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        if self.event_type in _ACCESS_EVENTS:
            required = (self.request_id, self.organisation_id, self.session_id, self.permission, self.resource_kind)
            if any(value is None for value in required):
                raise ValueError("access audit events require complete trusted request context")
        if self.event_type is SecurityAuditEventType.ACCESS_ALLOWED:
            if self.outcome is not SecurityAuditOutcome.SUCCEEDED:
                raise ValueError("allowed access requires succeeded outcome")
            if self.actor_user_id is None:
                raise ValueError("allowed access requires an internal actor identifier")
        if self.event_type in {SecurityAuditEventType.ACCESS_DENIED, SecurityAuditEventType.AUTHENTICATION_FAILED} and self.outcome is not SecurityAuditOutcome.DENIED:
            raise ValueError("denied security event requires denied outcome")
        if self.event_type is SecurityAuditEventType.AUTHENTICATION_PROVIDER_UNAVAILABLE and self.outcome is not SecurityAuditOutcome.UNAVAILABLE:
            raise ValueError("provider outage requires unavailable outcome")
        if self.event_type is SecurityAuditEventType.AUTHENTICATION_SUCCEEDED and (self.actor_user_id is None or self.session_id is None):
            raise ValueError("successful authentication requires actor and session identifiers")
        for key, value in self.context.items():
            lowered = key.lower()
            if any(term in lowered for term in _FORBIDDEN_CONTEXT_TERMS):
                raise ValueError("audit context contains a forbidden sensitive field")
            if isinstance(value, str) and len(value) > 300:
                raise ValueError("audit context string values are bounded")
        return self
