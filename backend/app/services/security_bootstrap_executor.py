"""Atomic, fail-closed persistence boundary for the initial security bootstrap."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import (
    SecurityEntitlementSnapshot,
    SecurityOrganisation,
    SecurityOrganisationMembership,
    SecurityUser,
)
from app.repositories.security_audit_repository import (
    SecurityAuditPersistenceError,
    SecurityAuditRepository,
)
from app.repositories.security_repository import (
    SecurityPersistenceConflictError,
    SecurityRepository,
)
from app.security.bootstrap_models import SecurityBootstrapCommand
from app.services.security_bootstrap_service import build_security_bootstrap_plan


BootstrapSessionFactory = Callable[[], Session]
BootstrapTransactionGuard = Callable[[Session], None]


class SecurityBootstrapStateError(RuntimeError):
    """The one-time bootstrap precondition is no longer satisfied."""


class SecurityBootstrapPersistenceError(RuntimeError):
    """Sanitized failure while atomically committing bootstrap state."""


@dataclass(frozen=True, slots=True)
class SecurityBootstrapReceipt:
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID


class TransactionalSecurityBootstrapExecutor:
    def __init__(
        self,
        session_factory: BootstrapSessionFactory,
        *,
        transaction_guard: BootstrapTransactionGuard | None = None,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("security bootstrap session factory must be callable")
        if transaction_guard is not None and not callable(transaction_guard):
            raise TypeError("security bootstrap transaction guard must be callable")
        self._session_factory = session_factory
        self._transaction_guard = transaction_guard

    def execute(self, command: SecurityBootstrapCommand) -> SecurityBootstrapReceipt:
        session: Session | None = None
        try:
            session = self._session_factory()
            if self._transaction_guard is not None:
                self._transaction_guard(session)
            models = (
                SecurityUser,
                SecurityOrganisation,
                SecurityOrganisationMembership,
                SecurityEntitlementSnapshot,
                SecurityAuditRecord,
            )
            counts = tuple(
                session.scalar(select(func.count()).select_from(model))
                for model in models
            )
            if any(value != 0 for value in counts):
                raise SecurityBootstrapStateError(
                    "security bootstrap requires an empty security domain"
                )
            plan = build_security_bootstrap_plan(command)
            repository = SecurityRepository(session)
            repository.add_user(plan.user)
            repository.add_organisation(plan.organisation)
            repository.add_membership(plan.membership)
            repository.append_entitlement(plan.entitlement)
            SecurityAuditRepository(session).append(plan.audit_event)
            session.commit()
            return SecurityBootstrapReceipt(
                bootstrap_id=command.bootstrap_id,
                request_id=command.request_id,
                user_id=command.user_id,
                organisation_id=command.organisation_id,
                membership_id=command.membership_id,
                entitlement_snapshot_id=command.entitlement.snapshot_id,
            )
        except SecurityBootstrapStateError:
            if session is not None:
                session.rollback()
            raise
        except (
            SecurityPersistenceConflictError,
            SecurityAuditPersistenceError,
            SQLAlchemyError,
        ):
            if session is not None:
                session.rollback()
            raise SecurityBootstrapPersistenceError(
                "security bootstrap could not be committed"
            ) from None
        except Exception:
            if session is not None:
                session.rollback()
            raise
        finally:
            if session is not None:
                session.close()
