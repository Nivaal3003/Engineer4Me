"""Exclusive PostgreSQL transaction guard for operational security bootstrap."""

from __future__ import annotations

import re

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.security_bootstrap_executor import (
    BootstrapSessionFactory,
    SecurityBootstrapStateError,
    TransactionalSecurityBootstrapExecutor,
)


OPERATIONAL_SCHEMA = "public"
PHASE8_SECURITY_HEAD = "d9a137b5e6f7"
_SCHEMA_PATTERN = re.compile(r"\A[a-z][a-z0-9_]{0,62}\Z")
_SECURITY_TABLES = (
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
    "security_audit_events",
)


class PostgreSQLSecurityBootstrapTransactionGuard:
    """Validated schema-scoped lock used by operational and isolated executors."""

    def __init__(self, *, expected_schema: str, expected_revision: str) -> None:
        if (
            type(expected_schema) is not str
            or _SCHEMA_PATTERN.fullmatch(expected_schema) is None
        ):
            raise ValueError("security bootstrap schema is invalid")
        if (
            type(expected_revision) is not str
            or not expected_revision
            or len(expected_revision) > 100
            or re.fullmatch(r"[A-Za-z0-9_.-]+", expected_revision) is None
        ):
            raise ValueError("security bootstrap migration revision is invalid")
        quoted_schema = f'"{expected_schema}"'
        tables = ("alembic_version",) + _SECURITY_TABLES
        self._expected_schema = expected_schema
        self._expected_revision = expected_revision
        self._revision_statement = text(
            "SELECT CASE WHEN count(*) = 1 THEN min(version_num) END "
            f"FROM {quoted_schema}.alembic_version"
        )
        self._lock_statement = text(
            "LOCK TABLE "
            + ", ".join(f'{quoted_schema}."{table}"' for table in tables)
            + " IN ACCESS EXCLUSIVE MODE"
        )

    def __call__(self, session: Session) -> None:
        schema = session.scalar(text("SELECT current_schema()"))
        if schema != self._expected_schema:
            raise SecurityBootstrapStateError(
                "security bootstrap transaction entered an unexpected schema"
            )
        revision = session.scalar(self._revision_statement)
        if revision != self._expected_revision:
            raise SecurityBootstrapStateError(
                "security bootstrap requires the reviewed migration head"
            )
        session.execute(self._lock_statement)
        locked_schema = session.scalar(text("SELECT current_schema()"))
        locked_revision = session.scalar(self._revision_statement)
        if (
            locked_schema != self._expected_schema
            or locked_revision != self._expected_revision
        ):
            raise SecurityBootstrapStateError(
                "security bootstrap state changed while acquiring the lock"
            )


_OPERATIONAL_TRANSACTION_GUARD = PostgreSQLSecurityBootstrapTransactionGuard(
    expected_schema=OPERATIONAL_SCHEMA,
    expected_revision=PHASE8_SECURITY_HEAD,
)


def guard_operational_security_bootstrap_transaction(session: Session) -> None:
    """Lock the exact public security domain before its emptiness recheck."""

    _OPERATIONAL_TRANSACTION_GUARD(session)


class OperationalSecurityBootstrapExecutor(TransactionalSecurityBootstrapExecutor):
    """Bootstrap only after one exclusive public-schema serialization lock."""

    def __init__(self, session_factory: BootstrapSessionFactory) -> None:
        super().__init__(
            session_factory,
            transaction_guard=guard_operational_security_bootstrap_transaction,
        )


__all__ = [
    "OPERATIONAL_SCHEMA",
    "PHASE8_SECURITY_HEAD",
    "OperationalSecurityBootstrapExecutor",
    "PostgreSQLSecurityBootstrapTransactionGuard",
    "guard_operational_security_bootstrap_transaction",
]
