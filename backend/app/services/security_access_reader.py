"""Short-lived read-session boundary for trusted security access decisions."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.repositories.security_repository import SecurityRepository
from app.services.security_access_service import (
    SecurityAccessCommand,
    SecurityAccessOutcome,
    SecurityAccessService,
    TrustedAuthenticationContext,
)


AccessSessionFactory = Callable[[], Session]
SecurityRepositoryFactory = Callable[[Session], SecurityRepository]


class SecurityAccessReadError(RuntimeError):
    """Sanitized failure when an isolated security read cannot complete safely."""


class SessionFactorySecurityAccessService(SecurityAccessService):
    """Evaluate one access decision in one fresh, non-committing read session."""

    def __init__(
        self,
        session_factory: AccessSessionFactory,
        *,
        repository_factory: SecurityRepositoryFactory = SecurityRepository,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("security access read session factory must be callable")
        if not callable(repository_factory):
            raise TypeError("security repository factory must be callable")
        self._session_factory = session_factory
        self._repository_factory = repository_factory

    def evaluate(
        self,
        authentication: TrustedAuthenticationContext,
        command: SecurityAccessCommand,
    ) -> SecurityAccessOutcome:
        session: Session | None = None
        try:
            candidate = self._session_factory()
            if not isinstance(candidate, Session):
                raise SecurityAccessReadError(
                    "security access read session is unavailable"
                )
            session = candidate
            repository = self._repository_factory(session)
            if not isinstance(repository, SecurityRepository):
                raise SecurityAccessReadError(
                    "security access repository is unavailable"
                )
            return SecurityAccessService(repository).evaluate(authentication, command)
        except SecurityAccessReadError:
            raise
        except SQLAlchemyError as error:
            raise SecurityAccessReadError(
                "security access read could not be completed"
            ) from error
        finally:
            if session is not None:
                try:
                    session.rollback()
                except SQLAlchemyError as error:
                    raise SecurityAccessReadError(
                        "security access read could not be completed"
                    ) from error
                finally:
                    try:
                        session.close()
                    except SQLAlchemyError as error:
                        raise SecurityAccessReadError(
                            "security access read could not be completed"
                        ) from error


__all__ = [
    "AccessSessionFactory",
    "SecurityAccessReadError",
    "SessionFactorySecurityAccessService",
]
