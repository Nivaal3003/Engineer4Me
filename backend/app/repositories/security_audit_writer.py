"""Dedicated transaction boundary for durable append-only security audit writes."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.repositories.security_audit_repository import SecurityAuditPersistenceError, SecurityAuditRepository
from app.security.audit_models import SecurityAuditEvent


AuditSessionFactory = Callable[[], Session]


class DurableSecurityAuditWriter:
    """Commit one audit event in an isolated session before returning it."""

    def __init__(self, session_factory: AuditSessionFactory) -> None:
        if not callable(session_factory):
            raise TypeError("security audit session factory must be callable")
        self._session_factory = session_factory

    def append(self, event: SecurityAuditEvent) -> SecurityAuditEvent:
        session: Session | None = None
        try:
            session = self._session_factory()
            SecurityAuditRepository(session).append(event)
            session.commit()
            return event
        except SecurityAuditPersistenceError:
            if session is not None:
                session.rollback()
            raise
        except SQLAlchemyError as exc:
            if session is not None:
                session.rollback()
            raise SecurityAuditPersistenceError("security audit event could not be committed") from exc
        finally:
            if session is not None:
                session.close()
