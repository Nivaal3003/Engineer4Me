"""Controlled local preview of provider-bound operational bootstrap inputs."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.security.authentication_bootstrap_readiness import (
    AuthenticationBootstrapReadinessError,
)
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    AuthenticationReadinessDocumentError,
)
from app.security.authentication_readiness_preview import (
    AuthenticationReadinessPreviewFileError,
)
from app.security.authentication_token_readiness import (
    AuthenticationTokenFileError,
    AuthenticationTokenReadinessApprovalError,
    AuthenticationTokenReadinessError,
    probe_authentication_token_readiness,
)
from app.security.bootstrap_document import (
    MAX_BOOTSTRAP_DOCUMENT_BYTES,
    SecurityBootstrapDocumentError,
    load_security_bootstrap_document,
)
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.security.jwks_http_loader import OpenURL
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)
from app.services.security_bootstrap_operational_application import (
    BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS,
    TOKEN_READINESS_MAXIMUM_AGE_SECONDS,
    OperationalSecurityBootstrapApprovalError,
    OperationalSecurityBootstrapReadinessError,
    ProviderBoundOperationalSecurityBootstrapApplication,
)


OPERATIONAL_BOOTSTRAP_PREVIEW_SCOPE = "provider_bound_operational_bootstrap_inputs_only"


class OperationalSecurityBootstrapPreviewFileError(ValueError):
    """Sanitized rejection of an unsafe local bootstrap document file."""


class OperationalSecurityBootstrapPreviewError(RuntimeError):
    """Sanitized failure while assembling pre-execution readiness evidence."""


@dataclass(frozen=True, slots=True)
class OperationalSecurityBootstrapPreviewReceipt:
    """Privacy-minimised evidence from local inputs without database execution."""

    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    subject_sha256: str
    token_checked_at: datetime
    execution_checked_at: datetime
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
        timestamps = (self.token_checked_at, self.execution_checked_at)
        if any(
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
            for value in timestamps
        ):
            raise ValueError(
                "operational security bootstrap preview receipt is invalid"
            )
        token_age = self.execution_checked_at.astimezone(
            UTC
        ) - self.token_checked_at.astimezone(UTC)
        if (
            any(
                type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or self.token_algorithm
            not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
            or token_age < -timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS)
            or token_age > timedelta(seconds=TOKEN_READINESS_MAXIMUM_AGE_SECONDS)
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
                "operational security bootstrap preview receipt is invalid"
            )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str, *, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapApprovalError(
            f"approved {label} digest is invalid"
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


def read_operational_security_bootstrap_document(
    path: str | os.PathLike[str],
) -> bytes:
    """Read one stable regular non-symlink file through an exact byte bound."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("operational security bootstrap path must be path-like")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap input must be a regular non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file is empty"
        )
    if initial.st_size > MAX_BOOTSTRAP_DOCUMENT_BYTES:
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file exceeds the byte limit"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except (OSError, ValueError):
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file could not be opened safely"
        ) from None
    if not stat.S_ISREG(opened.st_mode) or not _same_file(initial, opened):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file changed before it was opened"
        )
    try:
        chunks: list[bytes] = []
        remaining = MAX_BOOTSTRAP_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OSError:
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file could not be read safely"
        ) from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise OperationalSecurityBootstrapPreviewFileError(
                "operational security bootstrap file could not be closed safely"
            ) from None
    if len(document) > MAX_BOOTSTRAP_DOCUMENT_BYTES:
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file exceeds the byte limit"
        )
    if not document:
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalSecurityBootstrapPreviewFileError(
            "operational security bootstrap file changed while it was read"
        )
    return document


def preview_operational_security_bootstrap(
    *,
    authentication_document_path: str | os.PathLike[str],
    token_path: str | os.PathLike[str],
    bootstrap_document_path: str | os.PathLike[str],
    approved_configuration_sha256: str,
    approved_jwks_document_sha256: str,
    approved_bootstrap_document_sha256: str,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPreviewReceipt:
    """Validate real local inputs and live JWKS without opening a DB session."""

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
    bootstrap_document = read_operational_security_bootstrap_document(
        bootstrap_document_path
    )
    validated = load_security_bootstrap_document(bootstrap_document)
    if not hmac.compare_digest(validated.preview.document_sha256, bootstrap_digest):
        raise OperationalSecurityBootstrapApprovalError(
            "operational security bootstrap document does not match approval"
        )
    token_readiness = probe_authentication_token_readiness(
        document_path=authentication_document_path,
        token_path=token_path,
        approved_configuration_sha256=configuration_digest,
        approved_jwks_document_sha256=jwks_digest,
        open_url=open_url,
    )
    checked_times: list[datetime] = []

    def checked_clock() -> datetime:
        value = clock()
        checked_times.append(value)
        return value

    def forbidden_session_factory():
        raise OperationalSecurityBootstrapPreviewError(
            "operational security bootstrap preview attempted database execution"
        )

    readiness = ProviderBoundOperationalSecurityBootstrapApplication(
        forbidden_session_factory,
        clock=checked_clock,
    ).prepare(
        token_readiness=token_readiness,
        bootstrap_document=bootstrap_document,
        approved_configuration_sha256=configuration_digest,
        approved_jwks_document_sha256=jwks_digest,
        approved_bootstrap_document_sha256=bootstrap_digest,
    )
    if len(checked_times) != 1:
        raise OperationalSecurityBootstrapPreviewError(
            "operational security bootstrap preview time correlation failed"
        )
    execution_checked_at = checked_times[0].astimezone(UTC)
    return OperationalSecurityBootstrapPreviewReceipt(
        configuration_sha256=readiness.configuration_sha256,
        jwks_document_sha256=readiness.jwks_document_sha256,
        bootstrap_document_sha256=readiness.bootstrap_document_sha256,
        issuer_sha256=readiness.issuer_sha256,
        subject_sha256=readiness.subject_sha256,
        token_checked_at=token_readiness.checked_at,
        execution_checked_at=execution_checked_at,
        token_algorithm=token_readiness.token_algorithm,
        bootstrap_id=readiness.bootstrap_id,
        request_id=readiness.request_id,
        user_id=readiness.user_id,
        organisation_id=readiness.organisation_id,
        membership_id=readiness.membership_id,
        entitlement_snapshot_id=readiness.entitlement_snapshot_id,
        initial_role=readiness.initial_role,
        entitlement_plan=readiness.entitlement_plan,
        subscription_status=readiness.subscription_status,
        features=readiness.features,
        quota_kinds=readiness.quota_kinds,
    )


def render_operational_security_bootstrap_preview(
    receipt: OperationalSecurityBootstrapPreviewReceipt,
) -> str:
    """Render canonical non-execution evidence without raw private inputs."""

    if type(receipt) is not OperationalSecurityBootstrapPreviewReceipt:
        raise TypeError("operational security bootstrap preview receipt is required")
    output = {
        "activation_ready": False,
        "bootstrap_document_digest_approved": True,
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_execution_ready": False,
        "bootstrap_id": str(receipt.bootstrap_id),
        "configuration_digest_approved": True,
        "configuration_sha256": receipt.configuration_sha256,
        "database_accessed": False,
        "entitlement_plan": receipt.entitlement_plan,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "entitlement_usable_at_preview": True,
        "execution_checked_at": receipt.execution_checked_at.isoformat(),
        "expected_migration_revision": receipt.expected_migration_revision,
        "expected_operational_schema": receipt.expected_operational_schema,
        "features": [value.value for value in receipt.features],
        "freshness_checked": True,
        "identity_binding_checked": True,
        "initial_role": receipt.initial_role.value,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_digest_approved": True,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "migration_revision_checked": False,
        "operational_empty_domain_rechecked": False,
        "operational_schema_checked": False,
        "organisation_id": str(receipt.organisation_id),
        "provider_ownership_checked": False,
        "quota_kinds": [value.value for value in receipt.quota_kinds],
        "request_id": str(receipt.request_id),
        "signed_token_checked": True,
        "signed_token_evidence_bound": True,
        "subject_sha256": receipt.subject_sha256,
        "subscription_status": receipt.subscription_status.value,
        "token_algorithm": receipt.token_algorithm,
        "token_checked_at": receipt.token_checked_at.isoformat(),
        "user_id": str(receipt.user_id),
        "validation_scope": OPERATIONAL_BOOTSTRAP_PREVIEW_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one explicit pre-execution preview or exit with a sanitized error."""

    parser = argparse.ArgumentParser(
        description="Preview reviewed Engineer4Me operational bootstrap inputs."
    )
    parser.add_argument("authentication_document", help="local public auth document")
    parser.add_argument("token", help="local file containing one compact JWT")
    parser.add_argument("bootstrap_document", help="local bootstrap JSON document")
    parser.add_argument("--approve-configuration-sha256", required=True)
    parser.add_argument("--approve-jwks-sha256", required=True)
    parser.add_argument("--approve-bootstrap-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        receipt = preview_operational_security_bootstrap(
            authentication_document_path=options.authentication_document,
            token_path=options.token,
            bootstrap_document_path=options.bootstrap_document,
            approved_configuration_sha256=options.approve_configuration_sha256,
            approved_jwks_document_sha256=options.approve_jwks_sha256,
            approved_bootstrap_document_sha256=options.approve_bootstrap_sha256,
        )
        rendered = render_operational_security_bootstrap_preview(receipt)
    except (
        AuthenticationBootstrapReadinessError,
        AuthenticationReadinessDocumentError,
        AuthenticationReadinessPreviewFileError,
        AuthenticationTokenFileError,
        AuthenticationTokenReadinessApprovalError,
        AuthenticationTokenReadinessError,
        OperationalSecurityBootstrapApprovalError,
        OperationalSecurityBootstrapPreviewError,
        OperationalSecurityBootstrapPreviewFileError,
        OperationalSecurityBootstrapReadinessError,
        SecurityBootstrapDocumentError,
    ):
        parser.exit(2, "operational security bootstrap preview failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OPERATIONAL_BOOTSTRAP_PREVIEW_SCOPE",
    "OperationalSecurityBootstrapPreviewError",
    "OperationalSecurityBootstrapPreviewFileError",
    "OperationalSecurityBootstrapPreviewReceipt",
    "main",
    "preview_operational_security_bootstrap",
    "read_operational_security_bootstrap_document",
    "render_operational_security_bootstrap_preview",
]
