"""Digest-confirmed approval of one operational bootstrap preview document."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.security.security_bootstrap_operational_preview import (
    OperationalSecurityBootstrapPreviewReceipt,
    render_operational_security_bootstrap_preview,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)
from app.services.security_bootstrap_operational_application import (
    BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS,
)


MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES = 16_384
OPERATIONAL_BOOTSTRAP_PREVIEW_APPROVAL_MAXIMUM_AGE_SECONDS = 300
OPERATIONAL_BOOTSTRAP_APPROVAL_SCOPE = (
    "digest_confirmed_operational_bootstrap_preview_only"
)


class OperationalSecurityBootstrapPreviewApprovalFileError(ValueError):
    """Sanitized rejection of an unsafe local preview document file."""


class OperationalSecurityBootstrapPreviewApprovalError(ValueError):
    """Sanitized rejection of malformed, changed, or stale preview evidence."""


@dataclass(frozen=True, slots=True)
class OperationalSecurityBootstrapPreviewApprovalReceipt:
    """Privacy-minimised approval evidence that performs no bootstrap execution."""

    preview_document_sha256: str
    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    subject_sha256: str
    token_checked_at: datetime
    preview_checked_at: datetime
    approval_checked_at: datetime
    token_algorithm: str
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID
    initial_role: OrganisationRole
    entitlement_plan: str
    subscription_status: SubscriptionStatus
    features: tuple[ControlledFeature, ...]
    quota_kinds: tuple[QuotaKind, ...]
    expected_operational_schema: str = OPERATIONAL_SCHEMA
    expected_migration_revision: str = PHASE8_SECURITY_HEAD

    def __post_init__(self) -> None:
        hashes = (
            self.preview_document_sha256,
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
            self.subject_sha256,
        )
        timestamps = (
            self.token_checked_at,
            self.preview_checked_at,
            self.approval_checked_at,
        )
        identifiers = (
            self.bootstrap_id,
            self.request_id,
            self.user_id,
            self.organisation_id,
            self.membership_id,
            self.entitlement_snapshot_id,
        )
        if any(
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
            for value in timestamps
        ):
            raise ValueError(
                "operational security bootstrap preview approval receipt is invalid"
            )
        preview_age = self.approval_checked_at.astimezone(
            UTC
        ) - self.preview_checked_at.astimezone(UTC)
        if (
            any(
                type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or self.token_checked_at.astimezone(UTC)
            > self.preview_checked_at.astimezone(UTC)
            + timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS)
            or preview_age
            < -timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS)
            or preview_age
            > timedelta(
                seconds=OPERATIONAL_BOOTSTRAP_PREVIEW_APPROVAL_MAXIMUM_AGE_SECONDS
            )
            or self.token_algorithm
            not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or self.initial_role is not OrganisationRole.OWNER
            or type(self.entitlement_plan) is not str
            or not self.entitlement_plan
            or self.subscription_status
            not in {SubscriptionStatus.TRIAL, SubscriptionStatus.ACTIVE}
            or type(self.features) is not tuple
            or len(self.features) != len(set(self.features))
            or any(type(value) is not ControlledFeature for value in self.features)
            or type(self.quota_kinds) is not tuple
            or len(self.quota_kinds) != len(set(self.quota_kinds))
            or any(type(value) is not QuotaKind for value in self.quota_kinds)
            or self.expected_operational_schema != OPERATIONAL_SCHEMA
            or self.expected_migration_revision != PHASE8_SECURITY_HEAD
        ):
            raise ValueError(
                "operational security bootstrap preview approval receipt is invalid"
            )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "approved operational bootstrap preview digest is invalid"
        )
    return value


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def _unchanged_file(left: os.stat_result, right: os.stat_result) -> bool:
    unchanged = (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )
    if os.name == "nt":
        return unchanged
    return unchanged and left.st_ctime_ns == right.st_ctime_ns


def read_operational_security_bootstrap_preview_document(
    path: str | os.PathLike[str],
) -> bytes:
    """Read one stable regular non-symlink preview file through a strict bound."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("operational security bootstrap preview path must be path-like")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview input must be a regular "
            "non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file is empty"
        )
    if initial.st_size > MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES:
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file exceeds the byte limit"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(initial, opened):
            raise OperationalSecurityBootstrapPreviewApprovalFileError(
                "operational security bootstrap preview file changed before it "
                "was opened"
            )
        chunks: list[bytes] = []
        remaining = MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OperationalSecurityBootstrapPreviewApprovalFileError:
        raise
    except (OSError, ValueError):
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise OperationalSecurityBootstrapPreviewApprovalFileError(
                    "operational security bootstrap preview file could not be "
                    "closed safely"
                ) from None
    if len(document) > MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES:
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file exceeds the byte limit"
        )
    if not document:
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalSecurityBootstrapPreviewApprovalFileError(
            "operational security bootstrap preview file changed while it was read"
        )
    return document


def _reject_constant(value: str):
    del value
    raise OperationalSecurityBootstrapPreviewApprovalError(
        "operational security bootstrap preview document contains a non-finite number"
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OperationalSecurityBootstrapPreviewApprovalError(
                "operational security bootstrap preview document contains "
                "duplicate keys"
            )
        value[key] = item
    return value


def _document_text(document: bytes) -> str:
    if type(document) is not bytes:
        raise TypeError("operational security bootstrap preview document must be bytes")
    if not document or len(document) > MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document size is invalid"
        )
    content = document
    if content.endswith(b"\r\n"):
        content = content[:-2]
    elif content.endswith(b"\n"):
        content = content[:-1]
    if not content or b"\r" in content or b"\n" in content:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document must be one canonical line"
        )
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document is not valid UTF-8"
        ) from None


def _mapping(document: bytes) -> tuple[Mapping[str, object], str]:
    text = _document_text(document)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except OperationalSecurityBootstrapPreviewApprovalError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document is invalid"
        ) from None
    if type(value) is not dict:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document must be an object"
        )
    return value, text


def _required(value: Mapping[str, object], key: str, expected_type: type):
    item = value.get(key)
    if type(item) is not expected_type:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        )
    return item


def _timestamp(value: Mapping[str, object], key: str) -> datetime:
    text = _required(value, key, str)
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        ) from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        )
    return result


def _identifier(value: Mapping[str, object], key: str) -> UUID:
    text = _required(value, key, str)
    try:
        return UUID(text)
    except (ValueError, AttributeError):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        ) from None


def _enum_tuple(value: Mapping[str, object], key: str, enum_type: type):
    items = _required(value, key, list)
    try:
        result = tuple(enum_type(item) for item in items)
    except (TypeError, ValueError):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        ) from None
    return result


def _preview_receipt(
    value: Mapping[str, object],
) -> OperationalSecurityBootstrapPreviewReceipt:
    try:
        receipt = OperationalSecurityBootstrapPreviewReceipt(
            configuration_sha256=_required(value, "configuration_sha256", str),
            jwks_document_sha256=_required(value, "jwks_document_sha256", str),
            bootstrap_document_sha256=_required(
                value, "bootstrap_document_sha256", str
            ),
            issuer_sha256=_required(value, "issuer_sha256", str),
            subject_sha256=_required(value, "subject_sha256", str),
            token_checked_at=_timestamp(value, "token_checked_at"),
            execution_checked_at=_timestamp(value, "execution_checked_at"),
            token_algorithm=_required(value, "token_algorithm", str),
            bootstrap_id=_identifier(value, "bootstrap_id"),
            request_id=_identifier(value, "request_id"),
            user_id=_identifier(value, "user_id"),
            organisation_id=_identifier(value, "organisation_id"),
            membership_id=_identifier(value, "membership_id"),
            entitlement_snapshot_id=_identifier(value, "entitlement_snapshot_id"),
            initial_role=OrganisationRole(_required(value, "initial_role", str)),
            entitlement_plan=_required(value, "entitlement_plan", str),
            subscription_status=SubscriptionStatus(
                _required(value, "subscription_status", str)
            ),
            features=_enum_tuple(value, "features", ControlledFeature),
            quota_kinds=_enum_tuple(value, "quota_kinds", QuotaKind),
            expected_operational_schema=_required(
                value, "expected_operational_schema", str
            ),
            expected_migration_revision=_required(
                value, "expected_migration_revision", str
            ),
        )
    except OperationalSecurityBootstrapPreviewApprovalError:
        raise
    except (TypeError, ValueError):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document contract is invalid"
        ) from None
    return receipt


def approve_operational_security_bootstrap_preview(
    *,
    preview_document: bytes,
    approved_preview_document_sha256: str,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPreviewApprovalReceipt:
    """Approve one exact, canonical, recent preview without database execution."""

    approved = _approved_digest(approved_preview_document_sha256)
    if type(preview_document) is not bytes:
        raise TypeError("operational security bootstrap preview document must be bytes")
    actual = hashlib.sha256(preview_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document does not match approval"
        )
    value, text = _mapping(preview_document)
    receipt = _preview_receipt(value)
    if render_operational_security_bootstrap_preview(receipt) != text:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview document is not canonical"
        )
    try:
        checked_at = clock()
    except Exception:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview approval time is unavailable"
        ) from None
    if (
        not isinstance(checked_at, datetime)
        or checked_at.tzinfo is None
        or checked_at.utcoffset() is None
    ):
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview approval time is invalid"
        )
    try:
        return OperationalSecurityBootstrapPreviewApprovalReceipt(
            preview_document_sha256=actual,
            configuration_sha256=receipt.configuration_sha256,
            jwks_document_sha256=receipt.jwks_document_sha256,
            bootstrap_document_sha256=receipt.bootstrap_document_sha256,
            issuer_sha256=receipt.issuer_sha256,
            subject_sha256=receipt.subject_sha256,
            token_checked_at=receipt.token_checked_at,
            preview_checked_at=receipt.execution_checked_at,
            approval_checked_at=checked_at.astimezone(UTC),
            token_algorithm=receipt.token_algorithm,
            bootstrap_id=receipt.bootstrap_id,
            request_id=receipt.request_id,
            user_id=receipt.user_id,
            organisation_id=receipt.organisation_id,
            membership_id=receipt.membership_id,
            entitlement_snapshot_id=receipt.entitlement_snapshot_id,
            initial_role=receipt.initial_role,
            entitlement_plan=receipt.entitlement_plan,
            subscription_status=receipt.subscription_status,
            features=receipt.features,
            quota_kinds=receipt.quota_kinds,
        )
    except ValueError:
        raise OperationalSecurityBootstrapPreviewApprovalError(
            "operational security bootstrap preview is outside the approval window"
        ) from None


def approve_local_operational_security_bootstrap_preview(
    *,
    preview_document_path: str | os.PathLike[str],
    approved_preview_document_sha256: str,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPreviewApprovalReceipt:
    """Read and approve one exact local preview document without DB access."""

    approved = _approved_digest(approved_preview_document_sha256)
    document = read_operational_security_bootstrap_preview_document(
        preview_document_path
    )
    return approve_operational_security_bootstrap_preview(
        preview_document=document,
        approved_preview_document_sha256=approved,
        clock=clock,
    )


def render_operational_security_bootstrap_preview_approval(
    receipt: OperationalSecurityBootstrapPreviewApprovalReceipt,
) -> str:
    """Render canonical approval evidence that explicitly performs no execution."""

    if type(receipt) is not OperationalSecurityBootstrapPreviewApprovalReceipt:
        raise TypeError(
            "operational security bootstrap preview approval receipt is required"
        )
    output = {
        "activation_ready": False,
        "approval_checked_at": receipt.approval_checked_at.isoformat(),
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_execution_ready": False,
        "bootstrap_id": str(receipt.bootstrap_id),
        "configuration_sha256": receipt.configuration_sha256,
        "database_accessed": False,
        "entitlement_plan": receipt.entitlement_plan,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "expected_migration_revision": receipt.expected_migration_revision,
        "expected_operational_schema": receipt.expected_operational_schema,
        "features": [value.value for value in receipt.features],
        "initial_role": receipt.initial_role.value,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "migration_revision_checked": False,
        "operational_empty_domain_rechecked": False,
        "operational_schema_checked": False,
        "organisation_id": str(receipt.organisation_id),
        "preview_checked_at": receipt.preview_checked_at.isoformat(),
        "preview_digest_approved": True,
        "preview_document_sha256": receipt.preview_document_sha256,
        "provider_ownership_checked": False,
        "quota_kinds": [value.value for value in receipt.quota_kinds],
        "request_id": str(receipt.request_id),
        "subject_sha256": receipt.subject_sha256,
        "subscription_status": receipt.subscription_status.value,
        "token_algorithm": receipt.token_algorithm,
        "token_checked_at": receipt.token_checked_at.isoformat(),
        "user_id": str(receipt.user_id),
        "validation_scope": OPERATIONAL_BOOTSTRAP_APPROVAL_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Approve one explicit local preview or exit with a sanitized error."""

    parser = argparse.ArgumentParser(
        description="Approve one reviewed Engineer4Me bootstrap preview."
    )
    parser.add_argument("preview_document", help="local canonical preview JSON")
    parser.add_argument("--approve-preview-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        receipt = approve_local_operational_security_bootstrap_preview(
            preview_document_path=options.preview_document,
            approved_preview_document_sha256=options.approve_preview_sha256,
        )
        rendered = render_operational_security_bootstrap_preview_approval(receipt)
    except (
        OperationalSecurityBootstrapPreviewApprovalError,
        OperationalSecurityBootstrapPreviewApprovalFileError,
    ):
        parser.exit(2, "operational security bootstrap preview approval failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES",
    "OPERATIONAL_BOOTSTRAP_APPROVAL_SCOPE",
    "OPERATIONAL_BOOTSTRAP_PREVIEW_APPROVAL_MAXIMUM_AGE_SECONDS",
    "OperationalSecurityBootstrapPreviewApprovalError",
    "OperationalSecurityBootstrapPreviewApprovalFileError",
    "OperationalSecurityBootstrapPreviewApprovalReceipt",
    "approve_local_operational_security_bootstrap_preview",
    "approve_operational_security_bootstrap_preview",
    "main",
    "read_operational_security_bootstrap_preview_document",
    "render_operational_security_bootstrap_preview_approval",
]
