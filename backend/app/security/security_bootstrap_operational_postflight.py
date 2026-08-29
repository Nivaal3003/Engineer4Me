"""Read-only exact verification of one committed operational bootstrap."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import (
    SecurityEntitlementSnapshot,
    SecurityOrganisation,
    SecurityOrganisationMembership,
    SecurityUser,
)
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.security_bootstrap_operational_execution import (
    OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE,
    OperationalSecurityBootstrapExecutionReceipt,
    render_operational_security_bootstrap_execution_receipt,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)


MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES = 16_384
MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES = 16_384
OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE = (
    "read_only_exact_public_security_bootstrap_postflight"
)
_SECURITY_MODELS = (
    SecurityUser,
    SecurityOrganisation,
    SecurityOrganisationMembership,
    SecurityEntitlementSnapshot,
    SecurityAuditRecord,
)


class OperationalSecurityBootstrapPostflightDocumentError(ValueError):
    """Sanitized rejection of malformed or unapproved postflight evidence."""


class OperationalSecurityBootstrapPostflightStateError(RuntimeError):
    """The operational security domain does not match the reviewed bootstrap."""


class OperationalSecurityBootstrapPostflightPersistenceError(RuntimeError):
    """A sanitized read-only database verification failure."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class OperationalSecurityBootstrapPostflightReceipt:
    """Privacy-minimised evidence returned after exact read-only verification."""

    execution_receipt_sha256: str
    preview_document_sha256: str
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
    execution_checked_at: datetime
    verification_checked_at: datetime
    operational_schema: str = OPERATIONAL_SCHEMA
    migration_revision: str = PHASE8_SECURITY_HEAD
    security_rows_verified: int = 5
    append_only_triggers_verified: int = 2

    def __post_init__(self) -> None:
        hashes = (
            self.execution_receipt_sha256,
            self.preview_document_sha256,
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
        timestamps = (self.execution_checked_at, self.verification_checked_at)
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
            or self.verification_checked_at.astimezone(UTC)
            < self.execution_checked_at.astimezone(UTC)
            or self.operational_schema != OPERATIONAL_SCHEMA
            or self.migration_revision != PHASE8_SECURITY_HEAD
            or self.security_rows_verified != 5
            or self.append_only_triggers_verified != 2
        ):
            raise ValueError(
                "operational security bootstrap postflight receipt is invalid"
            )


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "approved execution receipt digest is invalid"
        )
    return value


def _approved_postflight_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "approved operational bootstrap postflight digest is invalid"
        )
    return value


def _reject_constant(value: str):
    del value
    raise OperationalSecurityBootstrapPostflightDocumentError(
        "operational bootstrap execution receipt contains a non-finite number"
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OperationalSecurityBootstrapPostflightDocumentError(
                "operational bootstrap execution receipt contains duplicate keys"
            )
        value[key] = item
    return value


def _document_text(document: bytes) -> str:
    if type(document) is not bytes:
        raise TypeError("operational bootstrap execution receipt must be bytes")
    if (
        not document
        or len(document) > MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES
    ):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt size is invalid"
        )
    content = document
    if content.endswith(b"\r\n"):
        content = content[:-2]
    elif content.endswith(b"\n"):
        content = content[:-1]
    if not content or b"\r" in content or b"\n" in content:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt must be one canonical line"
        )
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt is not valid UTF-8"
        ) from None


def _mapping(document: bytes) -> tuple[Mapping[str, object], str]:
    document_text = _document_text(document)
    try:
        value = json.loads(
            document_text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except OperationalSecurityBootstrapPostflightDocumentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt is invalid"
        ) from None
    if type(value) is not dict:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt must be an object"
        )
    return value, document_text


def _required(value: Mapping[str, object], key: str, expected_type: type):
    item = value.get(key)
    if type(item) is not expected_type:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        )
    return item


def _timestamp(value: Mapping[str, object], key: str) -> datetime:
    item = _required(value, key, str)
    try:
        result = datetime.fromisoformat(item)
    except ValueError:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        ) from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        )
    return result


def _identifier(value: Mapping[str, object], key: str) -> UUID:
    item = _required(value, key, str)
    try:
        return UUID(item)
    except (AttributeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        ) from None


def load_operational_security_bootstrap_execution_receipt(
    document: bytes,
) -> OperationalSecurityBootstrapExecutionReceipt:
    """Reconstruct only one exact canonical Step 181 post-commit receipt."""

    value, document_text = _mapping(document)
    fixed = {
        "activation_ready": False,
        "bootstrap_committed": True,
        "database_accessed": True,
        "exclusive_lock_and_empty_domain_rechecked": True,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "validation_scope": OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE,
        "operational_schema": OPERATIONAL_SCHEMA,
        "migration_revision": PHASE8_SECURITY_HEAD,
    }
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        )
    try:
        receipt = OperationalSecurityBootstrapExecutionReceipt(
            preview_document_sha256=_required(
                value, "preview_document_sha256", str
            ),
            configuration_sha256=_required(value, "configuration_sha256", str),
            jwks_document_sha256=_required(value, "jwks_document_sha256", str),
            bootstrap_document_sha256=_required(
                value, "bootstrap_document_sha256", str
            ),
            issuer_sha256=_required(value, "issuer_sha256", str),
            subject_sha256=_required(value, "subject_sha256", str),
            preview_approval_checked_at=_timestamp(
                value, "preview_approval_checked_at"
            ),
            execution_checked_at=_timestamp(value, "execution_checked_at"),
            bootstrap_id=_identifier(value, "bootstrap_id"),
            request_id=_identifier(value, "request_id"),
            user_id=_identifier(value, "user_id"),
            organisation_id=_identifier(value, "organisation_id"),
            membership_id=_identifier(value, "membership_id"),
            entitlement_snapshot_id=_identifier(
                value, "entitlement_snapshot_id"
            ),
            operational_schema=_required(value, "operational_schema", str),
            migration_revision=_required(value, "migration_revision", str),
        )
    except OperationalSecurityBootstrapPostflightDocumentError:
        raise
    except (TypeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt contract is invalid"
        ) from None
    if not hmac.compare_digest(
        render_operational_security_bootstrap_execution_receipt(receipt),
        document_text,
    ):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt is not canonical"
        )
    return receipt


def _postflight_reject_constant(value: str):
    del value
    raise OperationalSecurityBootstrapPostflightDocumentError(
        "operational bootstrap postflight receipt contains a non-finite number"
    )


def _postflight_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OperationalSecurityBootstrapPostflightDocumentError(
                "operational bootstrap postflight receipt contains duplicate "
                "keys"
            )
        value[key] = item
    return value


def _postflight_document_text(document: bytes) -> str:
    if type(document) is not bytes:
        raise TypeError("operational bootstrap postflight receipt must be bytes")
    if (
        not document
        or len(document) > MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES
    ):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt size is invalid"
        )
    content = document
    if content.endswith(b"\r\n"):
        content = content[:-2]
    elif content.endswith(b"\n"):
        content = content[:-1]
    if not content or b"\r" in content or b"\n" in content:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt must be one canonical "
            "line"
        )
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt is not valid UTF-8"
        ) from None


def _postflight_mapping(document: bytes) -> tuple[Mapping[str, object], str]:
    document_text = _postflight_document_text(document)
    try:
        value = json.loads(
            document_text,
            object_pairs_hook=_postflight_pairs,
            parse_constant=_postflight_reject_constant,
        )
    except OperationalSecurityBootstrapPostflightDocumentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt is invalid"
        ) from None
    if type(value) is not dict:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt must be an object"
        )
    return value, document_text


def _postflight_required(
    value: Mapping[str, object],
    key: str,
    expected_type: type,
):
    item = value.get(key)
    if type(item) is not expected_type:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        )
    return item


def _postflight_timestamp(
    value: Mapping[str, object],
    key: str,
) -> datetime:
    item = _postflight_required(value, key, str)
    try:
        result = datetime.fromisoformat(item)
    except ValueError:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        ) from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        )
    return result


def _postflight_identifier(
    value: Mapping[str, object],
    key: str,
) -> UUID:
    item = _postflight_required(value, key, str)
    try:
        return UUID(item)
    except (AttributeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        ) from None


def load_operational_security_bootstrap_postflight_receipt(
    document: bytes,
) -> OperationalSecurityBootstrapPostflightReceipt:
    """Reconstruct only one exact canonical Step 184 postflight receipt."""

    value, document_text = _postflight_mapping(document)
    fixed = {
        "activation_ready": False,
        "append_only_triggers_verified": 2,
        "bootstrap_committed": True,
        "bootstrap_verified": True,
        "database_transaction_read_only": True,
        "migration_revision": PHASE8_SECURITY_HEAD,
        "operational_schema": OPERATIONAL_SCHEMA,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "security_rows_verified": 5,
        "validation_scope": OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE,
    }
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        )
    try:
        receipt = OperationalSecurityBootstrapPostflightReceipt(
            execution_receipt_sha256=_postflight_required(
                value, "execution_receipt_sha256", str
            ),
            preview_document_sha256=_postflight_required(
                value, "preview_document_sha256", str
            ),
            configuration_sha256=_postflight_required(
                value, "configuration_sha256", str
            ),
            jwks_document_sha256=_postflight_required(
                value, "jwks_document_sha256", str
            ),
            bootstrap_document_sha256=_postflight_required(
                value, "bootstrap_document_sha256", str
            ),
            issuer_sha256=_postflight_required(value, "issuer_sha256", str),
            subject_sha256=_postflight_required(value, "subject_sha256", str),
            bootstrap_id=_postflight_identifier(value, "bootstrap_id"),
            request_id=_postflight_identifier(value, "request_id"),
            user_id=_postflight_identifier(value, "user_id"),
            organisation_id=_postflight_identifier(value, "organisation_id"),
            membership_id=_postflight_identifier(value, "membership_id"),
            entitlement_snapshot_id=_postflight_identifier(
                value, "entitlement_snapshot_id"
            ),
            execution_checked_at=_postflight_timestamp(
                value, "execution_checked_at"
            ),
            verification_checked_at=_postflight_timestamp(
                value, "verification_checked_at"
            ),
            operational_schema=_postflight_required(
                value, "operational_schema", str
            ),
            migration_revision=_postflight_required(
                value, "migration_revision", str
            ),
            security_rows_verified=_postflight_required(
                value, "security_rows_verified", int
            ),
            append_only_triggers_verified=_postflight_required(
                value, "append_only_triggers_verified", int
            ),
        )
    except OperationalSecurityBootstrapPostflightDocumentError:
        raise
    except (TypeError, ValueError):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt contract is invalid"
        ) from None
    if not hmac.compare_digest(
        render_operational_security_bootstrap_postflight_receipt(receipt),
        document_text,
    ):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt is not canonical"
        )
    return receipt


def _checked_time(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise OperationalSecurityBootstrapPostflightStateError(
            "operational bootstrap postflight time is unavailable"
        ) from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise OperationalSecurityBootstrapPostflightStateError(
            "operational bootstrap postflight time is invalid"
        )
    return value.astimezone(UTC)


def _same(actual, expected, *, label: str) -> None:
    if actual != expected:
        raise OperationalSecurityBootstrapPostflightStateError(
            f"persisted operational bootstrap {label} is inconsistent"
        )


def _verify_user(row: SecurityUser | None, command) -> None:
    if row is None:
        raise OperationalSecurityBootstrapPostflightStateError(
            "persisted operational bootstrap user is missing"
        )
    pairs = (
        (row.id, command.user_id, "user identifier"),
        (row.email, command.email, "user email"),
        (row.display_name, command.display_name, "user display name"),
        (row.status, "active", "user status"),
        (row.issuer, command.issuer, "user issuer"),
        (row.subject, command.subject, "user subject"),
    )
    for actual, expected, label in pairs:
        _same(actual, expected, label=label)


def _verify_organisation(row: SecurityOrganisation | None, command) -> None:
    if row is None:
        raise OperationalSecurityBootstrapPostflightStateError(
            "persisted operational bootstrap organisation is missing"
        )
    pairs = (
        (row.id, command.organisation_id, "organisation identifier"),
        (row.slug, command.organisation_slug, "organisation slug"),
        (row.name, command.organisation_name, "organisation name"),
        (row.status, "active", "organisation status"),
    )
    for actual, expected, label in pairs:
        _same(actual, expected, label=label)


def _verify_membership(
    row: SecurityOrganisationMembership | None,
    command,
) -> None:
    if row is None:
        raise OperationalSecurityBootstrapPostflightStateError(
            "persisted operational bootstrap membership is missing"
        )
    pairs = (
        (row.id, command.membership_id, "membership identifier"),
        (row.user_id, command.user_id, "membership user"),
        (row.organisation_id, command.organisation_id, "membership organisation"),
        (row.role, command.initial_role.value, "membership role"),
        (row.status, "active", "membership status"),
        (row.joined_at, command.activated_at, "membership activation"),
    )
    for actual, expected, label in pairs:
        _same(actual, expected, label=label)


def _verify_entitlement(row: SecurityEntitlementSnapshot | None, command) -> None:
    if row is None:
        raise OperationalSecurityBootstrapPostflightStateError(
            "persisted operational bootstrap entitlement is missing"
        )
    entitlement = command.entitlement
    pairs = (
        (row.id, entitlement.snapshot_id, "entitlement identifier"),
        (row.organisation_id, command.organisation_id, "entitlement organisation"),
        (row.sequence_number, 1, "entitlement sequence"),
        (row.plan_id, entitlement.plan_id, "entitlement plan"),
        (
            row.subscription_status,
            entitlement.subscription_status.value,
            "entitlement status",
        ),
        (
            row.features,
            [item.value for item in entitlement.features],
            "entitlement features",
        ),
        (
            row.quotas,
            [item.model_dump(mode="json") for item in entitlement.quotas],
            "entitlement quotas",
        ),
        (row.effective_at, entitlement.effective_at, "entitlement effective time"),
        (row.expires_at, entitlement.expires_at, "entitlement expiry"),
        (
            row.source_reference,
            entitlement.source_reference,
            "entitlement source",
        ),
    )
    for actual, expected, label in pairs:
        _same(actual, expected, label=label)


def _verify_audit(row: SecurityAuditRecord | None, command) -> None:
    if row is None:
        raise OperationalSecurityBootstrapPostflightStateError(
            "persisted operational bootstrap audit event is missing"
        )
    expected_context = {
        "membership_role": command.initial_role.value,
        "entitlement_plan": command.entitlement.plan_id,
        "subscription_status": command.entitlement.subscription_status.value,
    }
    pairs = (
        (row.id, command.bootstrap_id, "audit identifier"),
        (row.occurred_at, command.activated_at, "audit occurrence time"),
        (row.event_type, "security_state_changed", "audit event type"),
        (row.outcome, "succeeded", "audit outcome"),
        (row.reason_code, "initial_security_bootstrap", "audit reason"),
        (row.request_id, command.request_id, "audit request"),
        (row.actor_user_id, command.user_id, "audit actor"),
        (row.organisation_id, command.organisation_id, "audit organisation"),
        (row.session_id, None, "audit session"),
        (row.permission, None, "audit permission"),
        (row.resource_kind, None, "audit resource kind"),
        (row.resource_id, None, "audit resource identifier"),
        (row.context, expected_context, "audit context"),
    )
    for actual, expected, label in pairs:
        _same(actual, expected, label=label)


def _verify_receipt_binding(execution, command, bootstrap_sha256: str) -> None:
    identifiers = (
        (execution.bootstrap_id, command.bootstrap_id, "bootstrap identifier"),
        (execution.request_id, command.request_id, "request identifier"),
        (execution.user_id, command.user_id, "user identifier"),
        (
            execution.organisation_id,
            command.organisation_id,
            "organisation identifier",
        ),
        (execution.membership_id, command.membership_id, "membership identifier"),
        (
            execution.entitlement_snapshot_id,
            command.entitlement.snapshot_id,
            "entitlement identifier",
        ),
        (
            execution.bootstrap_document_sha256,
            bootstrap_sha256,
            "bootstrap document digest",
        ),
        (
            execution.issuer_sha256,
            authentication_identity_sha256(command.issuer),
            "issuer digest",
        ),
        (
            execution.subject_sha256,
            authentication_identity_sha256(command.issuer, command.subject),
            "subject digest",
        ),
    )
    for actual, expected, label in identifiers:
        _same(actual, expected, label=label)


def _verify_persisted_operational_bootstrap(
    *,
    command,
    session_factory: BootstrapSessionFactory,
) -> None:
    session: Session | None = None
    try:
        session = session_factory()
        session.execute(
            text(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
        )
        schema = session.scalar(text("SELECT current_schema()"))
        revision = session.scalar(
            text(
                "SELECT CASE WHEN count(*) = 1 THEN min(version_num) END "
                'FROM "public".alembic_version'
            )
        )
        if schema != OPERATIONAL_SCHEMA or revision != PHASE8_SECURITY_HEAD:
            raise OperationalSecurityBootstrapPostflightStateError(
                "operational bootstrap postflight requires the reviewed public head"
            )
        trigger_count = session.scalar(
            text(
                "SELECT count(*) FROM pg_trigger AS t "
                "JOIN pg_class AS relation ON relation.oid = t.tgrelid "
                "JOIN pg_namespace AS namespace "
                "ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' "
                "AND NOT t.tgisinternal AND ("
                "(relation.relname = 'security_entitlement_snapshots' "
                "AND t.tgname = "
                "'trg_security_entitlement_snapshots_append_only') OR "
                "(relation.relname = 'security_audit_events' "
                "AND t.tgname = "
                "'trg_security_audit_events_append_only'))"
            )
        )
        if trigger_count != 2:
            raise OperationalSecurityBootstrapPostflightStateError(
                "operational bootstrap postflight requires append-only controls"
            )
        counts = tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in _SECURITY_MODELS
        )
        if counts != (1, 1, 1, 1, 1):
            raise OperationalSecurityBootstrapPostflightStateError(
                "operational bootstrap postflight requires exactly five records"
            )
        _verify_user(session.get(SecurityUser, command.user_id), command)
        _verify_organisation(
            session.get(SecurityOrganisation, command.organisation_id),
            command,
        )
        _verify_membership(
            session.get(SecurityOrganisationMembership, command.membership_id),
            command,
        )
        _verify_entitlement(
            session.get(
                SecurityEntitlementSnapshot,
                command.entitlement.snapshot_id,
            ),
            command,
        )
        _verify_audit(
            session.get(SecurityAuditRecord, command.bootstrap_id),
            command,
        )
        session.rollback()
    except OperationalSecurityBootstrapPostflightStateError:
        if session is not None:
            session.rollback()
        raise
    except SQLAlchemyError:
        if session is not None:
            session.rollback()
        raise OperationalSecurityBootstrapPostflightPersistenceError(
            "operational bootstrap postflight could not be completed"
        ) from None
    finally:
        if session is not None:
            session.close()


def verify_operational_security_bootstrap_postflight(
    *,
    execution_receipt_document: bytes,
    bootstrap_document: bytes,
    approved_execution_receipt_sha256: str,
    session_factory: BootstrapSessionFactory,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPostflightReceipt:
    """Verify the exact five committed records through one read-only session."""

    approved = _approved_digest(approved_execution_receipt_sha256)
    if not callable(session_factory):
        raise TypeError("operational bootstrap postflight session factory is required")
    if not callable(clock):
        raise TypeError("operational bootstrap postflight clock must be callable")
    if type(execution_receipt_document) is not bytes:
        raise TypeError("operational bootstrap execution receipt must be bytes")
    actual_receipt_digest = hashlib.sha256(execution_receipt_document).hexdigest()
    if not hmac.compare_digest(actual_receipt_digest, approved):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt does not match approval"
        )
    execution = load_operational_security_bootstrap_execution_receipt(
        execution_receipt_document
    )
    try:
        validated = load_security_bootstrap_document(bootstrap_document)
    except Exception:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap document is invalid"
        ) from None
    _verify_receipt_binding(
        execution,
        validated.command,
        validated.preview.document_sha256,
    )
    checked_at = _checked_time(clock)
    if checked_at < execution.execution_checked_at.astimezone(UTC):
        raise OperationalSecurityBootstrapPostflightStateError(
            "operational bootstrap postflight precedes execution"
        )

    _verify_persisted_operational_bootstrap(
        command=validated.command,
        session_factory=session_factory,
    )

    return OperationalSecurityBootstrapPostflightReceipt(
        execution_receipt_sha256=actual_receipt_digest,
        preview_document_sha256=execution.preview_document_sha256,
        configuration_sha256=execution.configuration_sha256,
        jwks_document_sha256=execution.jwks_document_sha256,
        bootstrap_document_sha256=execution.bootstrap_document_sha256,
        issuer_sha256=execution.issuer_sha256,
        subject_sha256=execution.subject_sha256,
        bootstrap_id=execution.bootstrap_id,
        request_id=execution.request_id,
        user_id=execution.user_id,
        organisation_id=execution.organisation_id,
        membership_id=execution.membership_id,
        entitlement_snapshot_id=execution.entitlement_snapshot_id,
        execution_checked_at=execution.execution_checked_at,
        verification_checked_at=checked_at,
    )


def reverify_operational_security_bootstrap_postflight(
    *,
    postflight_receipt_document: bytes,
    bootstrap_document: bytes,
    approved_postflight_receipt_sha256: str,
    session_factory: BootstrapSessionFactory,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPostflightReceipt:
    """Revalidate canonical Step 184 evidence against current public records."""

    approved = _approved_postflight_digest(
        approved_postflight_receipt_sha256
    )
    if not callable(session_factory):
        raise TypeError("operational bootstrap postflight session factory is required")
    if not callable(clock):
        raise TypeError("operational bootstrap postflight clock must be callable")
    if type(postflight_receipt_document) is not bytes:
        raise TypeError("operational bootstrap postflight receipt must be bytes")
    actual = hashlib.sha256(postflight_receipt_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap postflight receipt does not match approval"
        )
    receipt = load_operational_security_bootstrap_postflight_receipt(
        postflight_receipt_document
    )
    try:
        validated = load_security_bootstrap_document(bootstrap_document)
    except Exception:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap document is invalid"
        ) from None
    _verify_receipt_binding(
        receipt,
        validated.command,
        validated.preview.document_sha256,
    )
    checked_at = _checked_time(clock)
    if checked_at < receipt.verification_checked_at.astimezone(UTC):
        raise OperationalSecurityBootstrapPostflightStateError(
            "operational bootstrap reverification precedes prior postflight"
        )
    _verify_persisted_operational_bootstrap(
        command=validated.command,
        session_factory=session_factory,
    )
    return replace(receipt, verification_checked_at=checked_at)


def render_operational_security_bootstrap_postflight_receipt(
    receipt: OperationalSecurityBootstrapPostflightReceipt,
) -> str:
    """Render canonical read-only evidence without raw identity values."""

    if type(receipt) is not OperationalSecurityBootstrapPostflightReceipt:
        raise TypeError("operational bootstrap postflight receipt is required")
    output = {
        "activation_ready": False,
        "append_only_triggers_verified": receipt.append_only_triggers_verified,
        "bootstrap_committed": True,
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_id": str(receipt.bootstrap_id),
        "bootstrap_verified": True,
        "configuration_sha256": receipt.configuration_sha256,
        "database_transaction_read_only": True,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "execution_checked_at": receipt.execution_checked_at.isoformat(),
        "execution_receipt_sha256": receipt.execution_receipt_sha256,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "migration_revision": receipt.migration_revision,
        "operational_schema": receipt.operational_schema,
        "organisation_id": str(receipt.organisation_id),
        "preview_document_sha256": receipt.preview_document_sha256,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "request_id": str(receipt.request_id),
        "security_rows_verified": receipt.security_rows_verified,
        "subject_sha256": receipt.subject_sha256,
        "user_id": str(receipt.user_id),
        "validation_scope": OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE,
        "verification_checked_at": receipt.verification_checked_at.isoformat(),
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES",
    "MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES",
    "OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE",
    "OperationalSecurityBootstrapPostflightDocumentError",
    "OperationalSecurityBootstrapPostflightPersistenceError",
    "OperationalSecurityBootstrapPostflightReceipt",
    "OperationalSecurityBootstrapPostflightStateError",
    "load_operational_security_bootstrap_execution_receipt",
    "load_operational_security_bootstrap_postflight_receipt",
    "reverify_operational_security_bootstrap_postflight",
    "render_operational_security_bootstrap_postflight_receipt",
    "verify_operational_security_bootstrap_postflight",
]
