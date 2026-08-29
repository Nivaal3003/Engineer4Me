"""Tenant-explicit append-only repository for trusted security audit events."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_audit import SecurityAuditRecord
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.security.authorization import ResourceKind
from app.security.identity_models import Permission


class SecurityAuditPersistenceError(RuntimeError):
    """Sanitized failure while appending an audit event."""


class SecurityAuditCorruptionError(RuntimeError):
    """Persisted audit content cannot satisfy the trusted contract."""


class SecurityAuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, value: SecurityAuditEvent) -> SecurityAuditEvent:
        row = SecurityAuditRecord(
            id=value.event_id,
            occurred_at=value.occurred_at,
            event_type=value.event_type.value,
            outcome=value.outcome.value,
            reason_code=value.reason_code,
            request_id=value.request_id,
            actor_user_id=value.actor_user_id,
            organisation_id=value.organisation_id,
            session_id=value.session_id,
            permission=None if value.permission is None else value.permission.value,
            resource_kind=None if value.resource_kind is None else value.resource_kind.value,
            resource_id=value.resource_id,
            context=dict(value.context),
        )
        try:
            self._session.add(row)
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise SecurityAuditPersistenceError("security audit event violates a persistence constraint") from exc
        return value

    def for_organisation(
        self,
        *,
        organisation_id: UUID,
        occurred_before: datetime | None = None,
        limit: int = 100,
    ) -> tuple[SecurityAuditEvent, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("audit query limit must be between 1 and 200")
        statement = select(SecurityAuditRecord).where(SecurityAuditRecord.organisation_id == organisation_id)
        if occurred_before is not None:
            if occurred_before.tzinfo is None:
                raise ValueError("audit query cursor must be timezone-aware")
            statement = statement.where(SecurityAuditRecord.occurred_at < occurred_before)
        statement = statement.order_by(SecurityAuditRecord.occurred_at.desc(), SecurityAuditRecord.id.desc()).limit(limit)
        return tuple(self._contract(row) for row in self._session.scalars(statement))

    def for_request(self, *, request_id: UUID, limit: int = 100) -> tuple[SecurityAuditEvent, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("audit query limit must be between 1 and 200")
        statement = select(SecurityAuditRecord).where(SecurityAuditRecord.request_id == request_id).order_by(SecurityAuditRecord.occurred_at.asc(), SecurityAuditRecord.id.asc()).limit(limit)
        return tuple(self._contract(row) for row in self._session.scalars(statement))

    @staticmethod
    def _contract(row: SecurityAuditRecord) -> SecurityAuditEvent:
        try:
            occurred_at = row.occurred_at
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=UTC)
            return SecurityAuditEvent(
                event_id=row.id,
                occurred_at=occurred_at,
                event_type=SecurityAuditEventType(row.event_type),
                outcome=SecurityAuditOutcome(row.outcome),
                reason_code=row.reason_code,
                request_id=row.request_id,
                actor_user_id=row.actor_user_id,
                organisation_id=row.organisation_id,
                session_id=row.session_id,
                permission=None if row.permission is None else Permission(row.permission),
                resource_kind=None if row.resource_kind is None else ResourceKind(row.resource_kind),
                resource_id=row.resource_id,
                context=dict(row.context),
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise SecurityAuditCorruptionError("persisted security audit event failed trusted contract validation") from exc
