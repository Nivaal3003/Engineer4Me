"""Fresh read-only readiness verification followed by secured app construction."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from fastapi import FastAPI

from app.main import (
    OperationalReadinessConfirmedApplicationReceipt,
    OperationalSecuredApplicationActivationError,
    create_readiness_confirmed_secured_application,
)
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    AuthenticationReadinessDocumentError,
    load_authentication_readiness_document,
)
from app.security.jwks_http_loader import OpenURL
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessError,
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
    verify_operational_application_activation_readiness,
)
from app.security.security_application_construction import (
    render_operational_application_construction_receipt,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory


OPERATIONAL_SECURED_APPLICATION_STARTUP_SCOPE = (
    "fresh_readiness_verified_secured_application_startup_assembly"
)


class OperationalSecuredApplicationStartupError(RuntimeError):
    """Sanitized rejection before a deployment cutover can be considered."""


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationStartupReceipt:
    """Privacy-minimised evidence for one fresh non-cutover startup assembly."""

    activation_readiness_sha256: str
    construction_receipt_sha256: str
    postflight_receipt_sha256: str
    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    user_id: UUID
    organisation_id: UUID
    entitlement_snapshot_id: UUID
    readiness_checked_at: datetime
    construction_checked_at: datetime
    route_bindings: int
    protected_bindings: int
    public_bindings: int
    database_reverified: bool = True
    readiness_bound: bool = True
    application_constructed: bool = True
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        hashes = (
            self.activation_readiness_sha256,
            self.construction_receipt_sha256,
            self.postflight_receipt_sha256,
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
        )
        identifiers = (
            self.user_id,
            self.organisation_id,
            self.entitlement_snapshot_id,
        )
        timestamps = (
            self.readiness_checked_at,
            self.construction_checked_at,
        )
        if (
            any(
                type(value) is not str
                or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or any(
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() is None
                for value in timestamps
            )
            or self.route_bindings != 93
            or self.protected_bindings != 91
            or self.public_bindings != 2
            or self.database_reverified is not True
            or self.readiness_bound is not True
            or self.application_constructed is not True
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational secured application startup receipt is invalid"
            )


def _same(left, right) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return hmac.compare_digest(left, right)
    return left == right


def _bound_startup_receipt(
    *,
    readiness: OperationalApplicationActivationReadinessReceipt,
    readiness_document: bytes,
    construction: OperationalReadinessConfirmedApplicationReceipt,
) -> OperationalSecuredApplicationStartupReceipt:
    if type(construction) is not OperationalReadinessConfirmedApplicationReceipt:
        raise OperationalSecuredApplicationStartupError(
            "operational secured application construction evidence is invalid"
        )
    try:
        construction_document = (
            render_operational_application_construction_receipt(
                construction
            ).encode("utf-8")
        )
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationStartupError(
            "operational secured application construction evidence is invalid"
        ) from None
    readiness_sha256 = hashlib.sha256(readiness_document).hexdigest()
    pairs = (
        (construction.activation_readiness_sha256, readiness_sha256),
        (construction.postflight_receipt_sha256, readiness.postflight_receipt_sha256),
        (construction.configuration_sha256, readiness.configuration_sha256),
        (construction.jwks_document_sha256, readiness.jwks_document_sha256),
        (construction.bootstrap_document_sha256, readiness.bootstrap_document_sha256),
        (construction.issuer_sha256, readiness.issuer_sha256),
        (construction.user_id, readiness.user_id),
        (construction.organisation_id, readiness.organisation_id),
        (
            construction.entitlement_snapshot_id,
            readiness.entitlement_snapshot_id,
        ),
        (
            construction.readiness_checked_at.astimezone(UTC),
            readiness.checked_at.astimezone(UTC),
        ),
    )
    if any(not _same(left, right) for left, right in pairs):
        raise OperationalSecuredApplicationStartupError(
            "operational readiness and construction evidence do not match"
        )
    return OperationalSecuredApplicationStartupReceipt(
        activation_readiness_sha256=readiness_sha256,
        construction_receipt_sha256=hashlib.sha256(
            construction_document
        ).hexdigest(),
        postflight_receipt_sha256=construction.postflight_receipt_sha256,
        configuration_sha256=construction.configuration_sha256,
        jwks_document_sha256=construction.jwks_document_sha256,
        bootstrap_document_sha256=construction.bootstrap_document_sha256,
        issuer_sha256=construction.issuer_sha256,
        user_id=construction.user_id,
        organisation_id=construction.organisation_id,
        entitlement_snapshot_id=construction.entitlement_snapshot_id,
        readiness_checked_at=construction.readiness_checked_at.astimezone(UTC),
        construction_checked_at=construction.construction_checked_at.astimezone(
            UTC
        ),
        route_bindings=construction.route_bindings,
        protected_bindings=construction.protected_bindings,
        public_bindings=construction.public_bindings,
    )


def create_fresh_readiness_verified_secured_application(
    *,
    authentication_document: bytes,
    postflight_receipt_document: bytes,
    bootstrap_document: bytes,
    approved_postflight_receipt_sha256: str,
    readiness_session_factory: BootstrapSessionFactory,
    access_session_factory: Callable[[], object],
    audit_session_factory: Callable[[], object],
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime],
) -> FastAPI:
    """Reverify committed state and immediately build one separate secured app."""

    if type(authentication_document) is not bytes:
        raise TypeError("operational authentication document must be bytes")
    if type(postflight_receipt_document) is not bytes:
        raise TypeError("operational postflight receipt must be bytes")
    if type(bootstrap_document) is not bytes:
        raise TypeError("operational bootstrap document must be bytes")
    if not callable(readiness_session_factory):
        raise TypeError("operational readiness session factory must be callable")
    if not callable(access_session_factory):
        raise TypeError("operational access session factory must be callable")
    if not callable(audit_session_factory):
        raise TypeError("operational audit session factory must be callable")
    if open_url is not None and not callable(open_url):
        raise TypeError("operational JWKS transport must be callable")
    if not callable(clock):
        raise TypeError("operational secured application startup clock is required")

    try:
        readiness = verify_operational_application_activation_readiness(
            authentication_document=authentication_document,
            postflight_receipt_document=postflight_receipt_document,
            bootstrap_document=bootstrap_document,
            approved_postflight_receipt_sha256=(
                approved_postflight_receipt_sha256
            ),
            session_factory=readiness_session_factory,
            clock=clock,
        )
    except OperationalApplicationActivationReadinessError:
        raise OperationalSecuredApplicationStartupError(
            "operational application startup readiness verification failed"
        ) from None

    try:
        authentication = load_authentication_readiness_document(
            authentication_document
        ).preview
        readiness_document = (
            render_operational_application_activation_readiness(readiness).encode(
                "utf-8"
            )
        )
    except (AuthenticationReadinessDocumentError, TypeError, ValueError):
        raise OperationalSecuredApplicationStartupError(
            "operational application startup evidence is invalid"
        ) from None
    readiness_sha256 = hashlib.sha256(readiness_document).hexdigest()
    try:
        application = create_readiness_confirmed_secured_application(
            authentication_readiness=authentication,
            activation_readiness_document=readiness_document,
            approved_activation_readiness_sha256=readiness_sha256,
            access_session_factory=access_session_factory,
            audit_session_factory=audit_session_factory,
            open_url=open_url,
            clock=clock,
        )
    except (OperationalSecuredApplicationActivationError, TypeError, ValueError):
        raise OperationalSecuredApplicationStartupError(
            "operational secured application construction failed"
        ) from None

    try:
        startup_receipt = _bound_startup_receipt(
            readiness=readiness,
            readiness_document=readiness_document,
            construction=application.state.security_activation,
        )
    except OperationalSecuredApplicationStartupError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise OperationalSecuredApplicationStartupError(
            "operational secured application construction evidence is invalid"
        ) from None
    application.state.security_startup = startup_receipt
    return application


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def render_operational_secured_application_startup_receipt(
    receipt: OperationalSecuredApplicationStartupReceipt,
) -> str:
    """Render canonical non-cutover startup evidence without raw identities."""

    if type(receipt) is not OperationalSecuredApplicationStartupReceipt:
        raise TypeError("operational secured application startup receipt is required")
    try:
        canonical = OperationalSecuredApplicationStartupReceipt(
            activation_readiness_sha256=receipt.activation_readiness_sha256,
            construction_receipt_sha256=receipt.construction_receipt_sha256,
            postflight_receipt_sha256=receipt.postflight_receipt_sha256,
            configuration_sha256=receipt.configuration_sha256,
            jwks_document_sha256=receipt.jwks_document_sha256,
            bootstrap_document_sha256=receipt.bootstrap_document_sha256,
            issuer_sha256=receipt.issuer_sha256,
            user_id=receipt.user_id,
            organisation_id=receipt.organisation_id,
            entitlement_snapshot_id=receipt.entitlement_snapshot_id,
            readiness_checked_at=receipt.readiness_checked_at,
            construction_checked_at=receipt.construction_checked_at,
            route_bindings=receipt.route_bindings,
            protected_bindings=receipt.protected_bindings,
            public_bindings=receipt.public_bindings,
            database_reverified=receipt.database_reverified,
            readiness_bound=receipt.readiness_bound,
            application_constructed=receipt.application_constructed,
            deployment_cutover_performed=receipt.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational secured application startup receipt is invalid"
        ) from None
    if canonical != receipt:
        raise ValueError("operational secured application startup receipt is invalid")
    return json.dumps(
        {
            "scope": OPERATIONAL_SECURED_APPLICATION_STARTUP_SCOPE,
            "activation_readiness_sha256": (
                canonical.activation_readiness_sha256
            ),
            "construction_receipt_sha256": (
                canonical.construction_receipt_sha256
            ),
            "postflight_receipt_sha256": canonical.postflight_receipt_sha256,
            "configuration_sha256": canonical.configuration_sha256,
            "jwks_document_sha256": canonical.jwks_document_sha256,
            "bootstrap_document_sha256": canonical.bootstrap_document_sha256,
            "issuer_sha256": canonical.issuer_sha256,
            "user_id": str(canonical.user_id),
            "organisation_id": str(canonical.organisation_id),
            "entitlement_snapshot_id": str(canonical.entitlement_snapshot_id),
            "readiness_checked_at": _canonical_timestamp(
                canonical.readiness_checked_at
            ),
            "construction_checked_at": _canonical_timestamp(
                canonical.construction_checked_at
            ),
            "route_bindings": canonical.route_bindings,
            "protected_bindings": canonical.protected_bindings,
            "public_bindings": canonical.public_bindings,
            "database_reverified": canonical.database_reverified,
            "readiness_bound": canonical.readiness_bound,
            "application_constructed": canonical.application_constructed,
            "deployment_cutover_performed": (
                canonical.deployment_cutover_performed
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


__all__ = [
    "OPERATIONAL_SECURED_APPLICATION_STARTUP_SCOPE",
    "OperationalSecuredApplicationStartupError",
    "OperationalSecuredApplicationStartupReceipt",
    "create_fresh_readiness_verified_secured_application",
    "render_operational_secured_application_startup_receipt",
]
