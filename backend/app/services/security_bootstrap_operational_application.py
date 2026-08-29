"""Provider-bound, digest-confirmed boundary for operational security bootstrap."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.security.authentication_bootstrap_readiness import (
    AuthenticationBootstrapReadinessReceipt,
    bind_authentication_bootstrap_readiness,
)
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.services.security_bootstrap_executor import (
    BootstrapSessionFactory,
    SecurityBootstrapReceipt,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
    OperationalSecurityBootstrapExecutor,
)


TOKEN_READINESS_MAXIMUM_AGE_SECONDS = 300
BOOTSTRAP_DOCUMENT_MAXIMUM_AGE_SECONDS = 900
BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS = 30


class OperationalSecurityBootstrapApprovalError(ValueError):
    """Sanitized rejection of absent, malformed, or stale approval evidence."""


class OperationalSecurityBootstrapReadinessError(ValueError):
    """Sanitized rejection when time-bound execution preconditions are not met."""


@dataclass(frozen=True, slots=True)
class OperationalSecurityBootstrapReceipt:
    """Correlated evidence returned only after the operational commit succeeds."""

    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    execution_checked_at: datetime
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID
    operational_schema: str = OPERATIONAL_SCHEMA
    migration_revision: str = PHASE8_SECURITY_HEAD

    def __post_init__(self) -> None:
        hashes = (
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
        )
        identifiers = (
            self.bootstrap_id,
            self.request_id,
            self.user_id,
            self.organisation_id,
            self.membership_id,
            self.entitlement_snapshot_id,
        )
        if (
            any(
                type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or not isinstance(self.execution_checked_at, datetime)
            or self.execution_checked_at.tzinfo is None
            or self.execution_checked_at.utcoffset() is None
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or self.operational_schema != OPERATIONAL_SCHEMA
            or self.migration_revision != PHASE8_SECURITY_HEAD
        ):
            raise ValueError("operational security bootstrap receipt is invalid")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str, *, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapApprovalError(
            f"approved {label} digest is invalid"
        )
    return value


def _execution_time(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise OperationalSecurityBootstrapReadinessError(
            "operational security bootstrap execution time is unavailable"
        ) from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise OperationalSecurityBootstrapReadinessError(
            "operational security bootstrap execution time is invalid"
        )
    return value.astimezone(UTC)


def _require_fresh_execution_state(
    *,
    token_readiness: AuthenticationTokenReadinessReceipt,
    bootstrap_document: bytes,
    checked_at: datetime,
) -> None:
    validated = load_security_bootstrap_document(bootstrap_document)
    token_age = checked_at - token_readiness.checked_at.astimezone(UTC)
    future_skew = timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS)
    if token_age < -future_skew or token_age > timedelta(
        seconds=TOKEN_READINESS_MAXIMUM_AGE_SECONDS
    ):
        raise OperationalSecurityBootstrapReadinessError(
            "signed-token readiness evidence is outside the execution window"
        )
    command = validated.command
    document_age = checked_at - command.activated_at.astimezone(UTC)
    if document_age < -future_skew or document_age > timedelta(
        seconds=BOOTSTRAP_DOCUMENT_MAXIMUM_AGE_SECONDS
    ):
        raise OperationalSecurityBootstrapReadinessError(
            "security bootstrap document is outside the execution window"
        )
    entitlement = command.entitlement
    if entitlement.effective_at.astimezone(UTC) > checked_at or (
        entitlement.expires_at is not None
        and entitlement.expires_at.astimezone(UTC) <= checked_at
    ):
        raise OperationalSecurityBootstrapReadinessError(
            "security bootstrap entitlement is not usable at execution time"
        )


def _receipt(
    *,
    readiness: AuthenticationBootstrapReadinessReceipt,
    committed: SecurityBootstrapReceipt,
    checked_at: datetime,
) -> OperationalSecurityBootstrapReceipt:
    expected = (
        readiness.bootstrap_id,
        readiness.request_id,
        readiness.user_id,
        readiness.organisation_id,
        readiness.membership_id,
        readiness.entitlement_snapshot_id,
    )
    actual = (
        committed.bootstrap_id,
        committed.request_id,
        committed.user_id,
        committed.organisation_id,
        committed.membership_id,
        committed.entitlement_snapshot_id,
    )
    if actual != expected:
        raise RuntimeError("operational security bootstrap receipt correlation failed")
    return OperationalSecurityBootstrapReceipt(
        configuration_sha256=readiness.configuration_sha256,
        jwks_document_sha256=readiness.jwks_document_sha256,
        bootstrap_document_sha256=readiness.bootstrap_document_sha256,
        execution_checked_at=checked_at,
        bootstrap_id=committed.bootstrap_id,
        request_id=committed.request_id,
        user_id=committed.user_id,
        organisation_id=committed.organisation_id,
        membership_id=committed.membership_id,
        entitlement_snapshot_id=committed.entitlement_snapshot_id,
    )


class ProviderBoundOperationalSecurityBootstrapApplication:
    """Execute one fresh, exactly approved provider-bound bootstrap command."""

    def __init__(
        self,
        session_factory: BootstrapSessionFactory,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("security bootstrap session factory must be callable")
        if not callable(clock):
            raise TypeError("security bootstrap clock must be callable")
        self._executor = OperationalSecurityBootstrapExecutor(session_factory)
        self._clock = clock

    def preview(
        self,
        *,
        token_readiness: AuthenticationTokenReadinessReceipt,
        bootstrap_document: bytes,
    ) -> AuthenticationBootstrapReadinessReceipt:
        """Bind reviewed identity evidence without opening a database session."""

        return bind_authentication_bootstrap_readiness(
            token_readiness=token_readiness,
            bootstrap_document=bootstrap_document,
        )

    def execute(
        self,
        *,
        token_readiness: AuthenticationTokenReadinessReceipt,
        bootstrap_document: bytes,
        approved_configuration_sha256: str,
        approved_jwks_document_sha256: str,
        approved_bootstrap_document_sha256: str,
    ) -> OperationalSecurityBootstrapReceipt:
        """Commit only the fresh command bound to all three exact approvals."""

        readiness, checked_at = self._prepare(
            token_readiness=token_readiness,
            bootstrap_document=bootstrap_document,
            approved_configuration_sha256=approved_configuration_sha256,
            approved_jwks_document_sha256=approved_jwks_document_sha256,
            approved_bootstrap_document_sha256=approved_bootstrap_document_sha256,
        )
        command = load_security_bootstrap_document(bootstrap_document).command
        committed = self._executor.execute(command)
        return _receipt(
            readiness=readiness,
            committed=committed,
            checked_at=checked_at,
        )

    def prepare(
        self,
        *,
        token_readiness: AuthenticationTokenReadinessReceipt,
        bootstrap_document: bytes,
        approved_configuration_sha256: str,
        approved_jwks_document_sha256: str,
        approved_bootstrap_document_sha256: str,
    ) -> AuthenticationBootstrapReadinessReceipt:
        """Validate approvals and freshness without opening a database session."""

        readiness, _ = self._prepare(
            token_readiness=token_readiness,
            bootstrap_document=bootstrap_document,
            approved_configuration_sha256=approved_configuration_sha256,
            approved_jwks_document_sha256=approved_jwks_document_sha256,
            approved_bootstrap_document_sha256=approved_bootstrap_document_sha256,
        )
        return readiness

    def _prepare(
        self,
        *,
        token_readiness: AuthenticationTokenReadinessReceipt,
        bootstrap_document: bytes,
        approved_configuration_sha256: str,
        approved_jwks_document_sha256: str,
        approved_bootstrap_document_sha256: str,
    ) -> tuple[AuthenticationBootstrapReadinessReceipt, datetime]:

        configuration_digest = _approved_digest(
            approved_configuration_sha256,
            label="authentication configuration",
        )
        jwks_digest = _approved_digest(
            approved_jwks_document_sha256,
            label="authentication JWKS document",
        )
        bootstrap_digest = _approved_digest(
            approved_bootstrap_document_sha256,
            label="security bootstrap document",
        )
        readiness = self.preview(
            token_readiness=token_readiness,
            bootstrap_document=bootstrap_document,
        )
        for actual, approved, label in (
            (readiness.configuration_sha256, configuration_digest, "configuration"),
            (readiness.jwks_document_sha256, jwks_digest, "JWKS document"),
            (
                readiness.bootstrap_document_sha256,
                bootstrap_digest,
                "bootstrap document",
            ),
        ):
            if not hmac.compare_digest(actual, approved):
                raise OperationalSecurityBootstrapApprovalError(
                    f"operational security bootstrap {label} does not match approval"
                )
        checked_at = _execution_time(self._clock)
        _require_fresh_execution_state(
            token_readiness=token_readiness,
            bootstrap_document=bootstrap_document,
            checked_at=checked_at,
        )
        return readiness, checked_at


__all__ = [
    "BOOTSTRAP_DOCUMENT_MAXIMUM_AGE_SECONDS",
    "BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS",
    "TOKEN_READINESS_MAXIMUM_AGE_SECONDS",
    "OperationalSecurityBootstrapApprovalError",
    "OperationalSecurityBootstrapReadinessError",
    "OperationalSecurityBootstrapReceipt",
    "ProviderBoundOperationalSecurityBootstrapApplication",
]
