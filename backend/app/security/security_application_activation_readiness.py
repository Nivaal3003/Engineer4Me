"""Read-only binding of reviewed configuration to committed bootstrap state."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    AuthenticationReadinessDocumentError,
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.bootstrap_document import (
    SecurityBootstrapDocumentError,
    load_security_bootstrap_document,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightDocumentError,
    OperationalSecurityBootstrapPostflightPersistenceError,
    OperationalSecurityBootstrapPostflightReceipt,
    OperationalSecurityBootstrapPostflightStateError,
    load_operational_security_bootstrap_postflight_receipt,
    reverify_operational_security_bootstrap_postflight,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)


OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE = (
    "read_only_bootstrap_confirmed_application_activation_readiness"
)
MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES = 16_384


class OperationalApplicationActivationReadinessDocumentError(ValueError):
    """Sanitized rejection of malformed activation-readiness evidence."""


class OperationalApplicationActivationReadinessError(RuntimeError):
    """Sanitized rejection of unbound or unusable activation evidence."""


@dataclass(frozen=True, slots=True)
class OperationalApplicationActivationReadinessReceipt:
    """Privacy-minimised evidence for a separately constructed secured app."""

    postflight_receipt_sha256: str
    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    subject_sha256: str
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID
    checked_at: datetime
    operational_schema: str = OPERATIONAL_SCHEMA
    migration_revision: str = PHASE8_SECURITY_HEAD
    database_reverified: bool = True
    entitlement_current: bool = True
    configuration_bound: bool = True
    activation_ready: bool = True

    def __post_init__(self) -> None:
        hashes = (
            self.postflight_receipt_sha256,
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
            self.subject_sha256,
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
                type(value) is not str
                or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or not isinstance(self.checked_at, datetime)
            or self.checked_at.tzinfo is None
            or self.checked_at.utcoffset() is None
            or self.operational_schema != OPERATIONAL_SCHEMA
            or self.migration_revision != PHASE8_SECURITY_HEAD
            or self.database_reverified is not True
            or self.entitlement_current is not True
            or self.configuration_bound is not True
            or self.activation_ready is not True
        ):
            raise ValueError(
                "operational application activation readiness receipt is invalid"
            )


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalApplicationActivationReadinessError(
            "approved postflight receipt digest is invalid"
        )
    return value


def _checked_time(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise OperationalApplicationActivationReadinessError(
            "operational activation readiness time is unavailable"
        ) from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise OperationalApplicationActivationReadinessError(
            "operational activation readiness time is invalid"
        )
    return value.astimezone(UTC)


def _same(actual, expected) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return hmac.compare_digest(actual, expected)
    return actual == expected


def _bind_documents(
    *,
    postflight: OperationalSecurityBootstrapPostflightReceipt,
    bootstrap_document: bytes,
):
    try:
        validated = load_security_bootstrap_document(bootstrap_document)
    except SecurityBootstrapDocumentError:
        raise OperationalApplicationActivationReadinessError(
            "operational activation bootstrap document is invalid"
        ) from None
    command = validated.command
    pairs = (
        (postflight.bootstrap_document_sha256, validated.preview.document_sha256),
        (postflight.issuer_sha256, authentication_identity_sha256(command.issuer)),
        (
            postflight.subject_sha256,
            authentication_identity_sha256(command.issuer, command.subject),
        ),
        (postflight.bootstrap_id, command.bootstrap_id),
        (postflight.request_id, command.request_id),
        (postflight.user_id, command.user_id),
        (postflight.organisation_id, command.organisation_id),
        (postflight.membership_id, command.membership_id),
        (
            postflight.entitlement_snapshot_id,
            command.entitlement.snapshot_id,
        ),
    )
    if any(not _same(actual, expected) for actual, expected in pairs):
        raise OperationalApplicationActivationReadinessError(
            "operational activation evidence does not match bootstrap document"
        )
    return validated


def verify_operational_application_activation_readiness(
    *,
    authentication_document: bytes,
    postflight_receipt_document: bytes,
    bootstrap_document: bytes,
    approved_postflight_receipt_sha256: str,
    session_factory: BootstrapSessionFactory,
    clock: Callable[[], datetime],
) -> OperationalApplicationActivationReadinessReceipt:
    """Rebind public configuration and recheck the exact bootstrap read-only."""

    approved = _approved_digest(approved_postflight_receipt_sha256)
    if type(postflight_receipt_document) is not bytes:
        raise TypeError("operational bootstrap postflight receipt must be bytes")
    if not callable(session_factory):
        raise TypeError("operational activation session factory is required")
    if not callable(clock):
        raise TypeError("operational activation readiness clock must be callable")
    actual = hashlib.sha256(postflight_receipt_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalApplicationActivationReadinessError(
            "operational bootstrap postflight receipt does not match approval"
        )
    try:
        authentication = load_authentication_readiness_document(
            authentication_document
        )
        postflight = load_operational_security_bootstrap_postflight_receipt(
            postflight_receipt_document
        )
    except (
        AuthenticationReadinessDocumentError,
        OperationalSecurityBootstrapPostflightDocumentError,
    ):
        raise OperationalApplicationActivationReadinessError(
            "operational activation evidence is invalid"
        ) from None
    if not hmac.compare_digest(
        authentication.preview.configuration_sha256,
        postflight.configuration_sha256,
    ):
        raise OperationalApplicationActivationReadinessError(
            "operational authentication and bootstrap evidence do not match"
        )
    validated = _bind_documents(
        postflight=postflight,
        bootstrap_document=bootstrap_document,
    )
    checked_at = _checked_time(clock)
    entitlement = validated.command.entitlement
    effective_at = entitlement.effective_at.astimezone(UTC)
    expires_at = (
        entitlement.expires_at.astimezone(UTC)
        if entitlement.expires_at is not None
        else None
    )
    if effective_at > checked_at or (
        expires_at is not None and expires_at <= checked_at
    ):
        raise OperationalApplicationActivationReadinessError(
            "operational bootstrap entitlement is not currently usable"
        )
    try:
        reverified = reverify_operational_security_bootstrap_postflight(
            postflight_receipt_document=postflight_receipt_document,
            bootstrap_document=bootstrap_document,
            approved_postflight_receipt_sha256=approved,
            session_factory=session_factory,
            clock=lambda: checked_at,
        )
    except (
        OperationalSecurityBootstrapPostflightDocumentError,
        OperationalSecurityBootstrapPostflightPersistenceError,
        OperationalSecurityBootstrapPostflightStateError,
    ):
        raise OperationalApplicationActivationReadinessError(
            "operational bootstrap state is not ready for activation"
        ) from None
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256=actual,
        configuration_sha256=reverified.configuration_sha256,
        jwks_document_sha256=reverified.jwks_document_sha256,
        bootstrap_document_sha256=reverified.bootstrap_document_sha256,
        issuer_sha256=reverified.issuer_sha256,
        subject_sha256=reverified.subject_sha256,
        bootstrap_id=reverified.bootstrap_id,
        request_id=reverified.request_id,
        user_id=reverified.user_id,
        organisation_id=reverified.organisation_id,
        membership_id=reverified.membership_id,
        entitlement_snapshot_id=reverified.entitlement_snapshot_id,
        checked_at=reverified.verification_checked_at,
    )


def render_operational_application_activation_readiness(
    receipt: OperationalApplicationActivationReadinessReceipt,
) -> str:
    """Render canonical readiness without raw provider or owner identity."""

    if type(receipt) is not OperationalApplicationActivationReadinessReceipt:
        raise TypeError("operational activation readiness receipt is required")
    output = {
        "activation_ready": receipt.activation_ready,
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_id": str(receipt.bootstrap_id),
        "configuration_bound": receipt.configuration_bound,
        "configuration_sha256": receipt.configuration_sha256,
        "database_reverified": receipt.database_reverified,
        "entitlement_current": receipt.entitlement_current,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "migration_revision": receipt.migration_revision,
        "operational_schema": receipt.operational_schema,
        "organisation_id": str(receipt.organisation_id),
        "postflight_receipt_sha256": receipt.postflight_receipt_sha256,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "request_id": str(receipt.request_id),
        "subject_sha256": receipt.subject_sha256,
        "user_id": str(receipt.user_id),
        "validation_scope": OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE,
        "verified_at": receipt.checked_at.isoformat(),
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _receipt_reject_constant(value: str):
    del value
    raise OperationalApplicationActivationReadinessDocumentError(
        "operational activation readiness receipt contains a non-finite number"
    )


def _receipt_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OperationalApplicationActivationReadinessDocumentError(
                "operational activation readiness receipt contains duplicate keys"
            )
        value[key] = item
    return value


def _receipt_document_text(document: bytes) -> str:
    if type(document) is not bytes:
        raise TypeError("operational activation readiness receipt must be bytes")
    if (
        not document
        or len(document)
        > MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES
    ):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt size is invalid"
        )
    content = document
    if content.endswith(b"\r\n"):
        content = content[:-2]
    elif content.endswith(b"\n"):
        content = content[:-1]
    if not content or b"\r" in content or b"\n" in content:
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt must be one canonical line"
        )
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt is not valid UTF-8"
        ) from None


def _receipt_mapping(document: bytes) -> tuple[Mapping[str, object], str]:
    document_text = _receipt_document_text(document)
    try:
        value = json.loads(
            document_text,
            object_pairs_hook=_receipt_pairs,
            parse_constant=_receipt_reject_constant,
        )
    except OperationalApplicationActivationReadinessDocumentError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt is invalid"
        ) from None
    if type(value) is not dict:
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt must be an object"
        )
    return value, document_text


def _receipt_required(
    value: Mapping[str, object],
    key: str,
    expected_type: type,
):
    item = value.get(key)
    if type(item) is not expected_type:
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        )
    return item


def _receipt_identifier(value: Mapping[str, object], key: str) -> UUID:
    item = _receipt_required(value, key, str)
    try:
        return UUID(item)
    except (AttributeError, ValueError):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        ) from None


def _receipt_timestamp(value: Mapping[str, object], key: str) -> datetime:
    item = _receipt_required(value, key, str)
    try:
        result = datetime.fromisoformat(item)
    except (OverflowError, ValueError):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        ) from None
    if (
        result.tzinfo is None
        or result.utcoffset() is None
        or result.utcoffset() != timedelta(0)
    ):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        )
    return result


def load_operational_application_activation_readiness_receipt(
    document: bytes,
) -> OperationalApplicationActivationReadinessReceipt:
    """Reconstruct only one exact canonical Step 188 readiness receipt."""

    value, document_text = _receipt_mapping(document)
    fixed = {
        "activation_ready": True,
        "configuration_bound": True,
        "database_reverified": True,
        "entitlement_current": True,
        "migration_revision": PHASE8_SECURITY_HEAD,
        "operational_schema": OPERATIONAL_SCHEMA,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "validation_scope": OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE,
    }
    if any(
        type(value.get(key)) is not type(expected)
        or value.get(key) != expected
        for key, expected in fixed.items()
    ):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        )
    try:
        receipt = OperationalApplicationActivationReadinessReceipt(
            postflight_receipt_sha256=_receipt_required(
                value, "postflight_receipt_sha256", str
            ),
            configuration_sha256=_receipt_required(
                value, "configuration_sha256", str
            ),
            jwks_document_sha256=_receipt_required(
                value, "jwks_document_sha256", str
            ),
            bootstrap_document_sha256=_receipt_required(
                value, "bootstrap_document_sha256", str
            ),
            issuer_sha256=_receipt_required(value, "issuer_sha256", str),
            subject_sha256=_receipt_required(value, "subject_sha256", str),
            bootstrap_id=_receipt_identifier(value, "bootstrap_id"),
            request_id=_receipt_identifier(value, "request_id"),
            user_id=_receipt_identifier(value, "user_id"),
            organisation_id=_receipt_identifier(value, "organisation_id"),
            membership_id=_receipt_identifier(value, "membership_id"),
            entitlement_snapshot_id=_receipt_identifier(
                value, "entitlement_snapshot_id"
            ),
            checked_at=_receipt_timestamp(value, "verified_at"),
            operational_schema=_receipt_required(
                value, "operational_schema", str
            ),
            migration_revision=_receipt_required(
                value, "migration_revision", str
            ),
            database_reverified=_receipt_required(
                value, "database_reverified", bool
            ),
            entitlement_current=_receipt_required(
                value, "entitlement_current", bool
            ),
            configuration_bound=_receipt_required(
                value, "configuration_bound", bool
            ),
            activation_ready=_receipt_required(
                value, "activation_ready", bool
            ),
        )
    except OperationalApplicationActivationReadinessDocumentError:
        raise
    except (TypeError, ValueError):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt contract is invalid"
        ) from None
    if not hmac.compare_digest(
        render_operational_application_activation_readiness(receipt),
        document_text,
    ):
        raise OperationalApplicationActivationReadinessDocumentError(
            "operational activation readiness receipt is not canonical"
        )
    return receipt


__all__ = [
    "MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES",
    "OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE",
    "OperationalApplicationActivationReadinessDocumentError",
    "OperationalApplicationActivationReadinessError",
    "OperationalApplicationActivationReadinessReceipt",
    "load_operational_application_activation_readiness_receipt",
    "render_operational_application_activation_readiness",
    "verify_operational_application_activation_readiness",
]
