"""Explicit one-time execution boundary for reviewed operational bootstrap."""

from __future__ import annotations

import argparse
import hmac
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
    probe_authentication_token_readiness,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.jwks_http_loader import OpenURL
from app.security.security_bootstrap_operational_approval import (
    OperationalSecurityBootstrapPreviewApprovalReceipt,
    approve_local_operational_security_bootstrap_preview,
)
from app.security.security_bootstrap_operational_preview import (
    read_operational_security_bootstrap_document,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)
from app.services.security_bootstrap_operational_application import (
    OperationalSecurityBootstrapReceipt,
    ProviderBoundOperationalSecurityBootstrapApplication,
)


OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION = (
    "REVIEWED_PROVIDER_OWNERSHIP_AND_APPROVE_ONE_TIME_PUBLIC_SECURITY_BOOTSTRAP"
)
OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE = (
    "one_time_provider_bound_public_security_bootstrap"
)
_EXECUTION_APPROVAL_MAXIMUM_AGE_SECONDS = 300
_EXECUTION_FUTURE_CLOCK_SKEW_SECONDS = 30


class OperationalSecurityBootstrapExecutionApprovalError(ValueError):
    """Sanitized rejection of missing or inconsistent execution approval."""


class OperationalSecurityBootstrapExecutionError(RuntimeError):
    """Sanitized failure before a reviewed bootstrap can enter its transaction."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class OperationalSecurityBootstrapExecutionReceipt:
    """Privacy-minimised evidence returned only after the bootstrap commit."""

    preview_document_sha256: str
    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    subject_sha256: str
    preview_approval_checked_at: datetime
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
            self.preview_document_sha256,
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
            self.subject_sha256,
        )
        timestamps = (
            self.preview_approval_checked_at,
            self.execution_checked_at,
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
                "operational security bootstrap execution receipt is invalid"
            )
        approval_age = self.execution_checked_at.astimezone(
            UTC
        ) - self.preview_approval_checked_at.astimezone(UTC)
        if (
            any(
                type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or approval_age
            < -timedelta(seconds=_EXECUTION_FUTURE_CLOCK_SKEW_SECONDS)
            or approval_age
            > timedelta(seconds=_EXECUTION_APPROVAL_MAXIMUM_AGE_SECONDS)
            or self.operational_schema != OPERATIONAL_SCHEMA
            or self.migration_revision != PHASE8_SECURITY_HEAD
        ):
            raise ValueError(
                "operational security bootstrap execution receipt is invalid"
            )


def _approved_digest(value: str, *, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapExecutionApprovalError(
            f"approved operational bootstrap {label} digest is invalid"
        )
    return value


def _confirmation(value: str) -> None:
    if (
        type(value) is not str
        or not hmac.compare_digest(value, OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION)
    ):
        raise OperationalSecurityBootstrapExecutionApprovalError(
            "operational security bootstrap execution confirmation is invalid"
        )


def _same(left, right, *, label: str) -> None:
    if left != right:
        raise OperationalSecurityBootstrapExecutionApprovalError(
            f"operational security bootstrap {label} does not match approved preview"
        )


def _approved_preview_digests(
    approval: OperationalSecurityBootstrapPreviewApprovalReceipt,
    *,
    configuration_sha256: str,
    jwks_document_sha256: str,
    bootstrap_document_sha256: str,
) -> None:
    for actual, approved, label in (
        (approval.configuration_sha256, configuration_sha256, "configuration"),
        (approval.jwks_document_sha256, jwks_document_sha256, "JWKS document"),
        (
            approval.bootstrap_document_sha256,
            bootstrap_document_sha256,
            "bootstrap document",
        ),
    ):
        if not hmac.compare_digest(actual, approved):
            raise OperationalSecurityBootstrapExecutionApprovalError(
                f"operational security bootstrap {label} approval is inconsistent"
            )


def _current_readiness_matches_approval(
    *,
    approval: OperationalSecurityBootstrapPreviewApprovalReceipt,
    token_readiness: AuthenticationTokenReadinessReceipt,
    application: ProviderBoundOperationalSecurityBootstrapApplication,
    bootstrap_document: bytes,
) -> None:
    current = application.preview(
        token_readiness=token_readiness,
        bootstrap_document=bootstrap_document,
    )
    _same(token_readiness.token_algorithm, approval.token_algorithm, label="algorithm")
    pairs = (
        (current.configuration_sha256, approval.configuration_sha256, "configuration"),
        (current.jwks_document_sha256, approval.jwks_document_sha256, "JWKS document"),
        (
            current.bootstrap_document_sha256,
            approval.bootstrap_document_sha256,
            "bootstrap document",
        ),
        (current.issuer_sha256, approval.issuer_sha256, "issuer"),
        (current.subject_sha256, approval.subject_sha256, "subject"),
        (current.bootstrap_id, approval.bootstrap_id, "bootstrap identifier"),
        (current.request_id, approval.request_id, "request identifier"),
        (current.user_id, approval.user_id, "user identifier"),
        (
            current.organisation_id,
            approval.organisation_id,
            "organisation identifier",
        ),
        (current.membership_id, approval.membership_id, "membership identifier"),
        (
            current.entitlement_snapshot_id,
            approval.entitlement_snapshot_id,
            "entitlement identifier",
        ),
        (current.initial_role, approval.initial_role, "initial role"),
        (current.entitlement_plan, approval.entitlement_plan, "entitlement plan"),
        (
            current.subscription_status,
            approval.subscription_status,
            "subscription status",
        ),
        (current.features, approval.features, "entitlement features"),
        (current.quota_kinds, approval.quota_kinds, "entitlement quotas"),
    )
    for left, right, label in pairs:
        _same(left, right, label=label)


def _operational_session_factory() -> BootstrapSessionFactory:
    from app.db.database import SessionLocal

    return SessionLocal


def _execution_receipt(
    *,
    approval: OperationalSecurityBootstrapPreviewApprovalReceipt,
    committed: OperationalSecurityBootstrapReceipt,
) -> OperationalSecurityBootstrapExecutionReceipt:
    expected = (
        approval.bootstrap_id,
        approval.request_id,
        approval.user_id,
        approval.organisation_id,
        approval.membership_id,
        approval.entitlement_snapshot_id,
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
        raise RuntimeError("operational security bootstrap commit correlation failed")
    return OperationalSecurityBootstrapExecutionReceipt(
        preview_document_sha256=approval.preview_document_sha256,
        configuration_sha256=committed.configuration_sha256,
        jwks_document_sha256=committed.jwks_document_sha256,
        bootstrap_document_sha256=committed.bootstrap_document_sha256,
        issuer_sha256=approval.issuer_sha256,
        subject_sha256=approval.subject_sha256,
        preview_approval_checked_at=approval.approval_checked_at,
        execution_checked_at=committed.execution_checked_at,
        bootstrap_id=committed.bootstrap_id,
        request_id=committed.request_id,
        user_id=committed.user_id,
        organisation_id=committed.organisation_id,
        membership_id=committed.membership_id,
        entitlement_snapshot_id=committed.entitlement_snapshot_id,
    )


def execute_local_operational_security_bootstrap(
    *,
    authentication_document_path: str,
    token_path: str,
    bootstrap_document_path: str,
    preview_document_path: str,
    approved_configuration_sha256: str,
    approved_jwks_document_sha256: str,
    approved_bootstrap_document_sha256: str,
    approved_preview_document_sha256: str,
    execution_confirmation: str,
    session_factory: BootstrapSessionFactory | None = None,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapExecutionReceipt:
    """Execute one exact reviewed bootstrap after all approvals are rebound."""

    _confirmation(execution_confirmation)
    if not callable(clock):
        raise TypeError("operational security bootstrap clock must be callable")
    if session_factory is not None and not callable(session_factory):
        raise TypeError(
            "operational security bootstrap session factory must be callable"
        )
    configuration_digest = _approved_digest(
        approved_configuration_sha256,
        label="configuration",
    )
    jwks_digest = _approved_digest(
        approved_jwks_document_sha256,
        label="JWKS document",
    )
    bootstrap_digest = _approved_digest(
        approved_bootstrap_document_sha256,
        label="bootstrap document",
    )
    preview_digest = _approved_digest(
        approved_preview_document_sha256,
        label="preview document",
    )
    approval = approve_local_operational_security_bootstrap_preview(
        preview_document_path=preview_document_path,
        approved_preview_document_sha256=preview_digest,
        clock=clock,
    )
    _approved_preview_digests(
        approval,
        configuration_sha256=configuration_digest,
        jwks_document_sha256=jwks_digest,
        bootstrap_document_sha256=bootstrap_digest,
    )
    bootstrap_document = read_operational_security_bootstrap_document(
        bootstrap_document_path
    )
    bootstrap = load_security_bootstrap_document(bootstrap_document)
    if not hmac.compare_digest(bootstrap.preview.document_sha256, bootstrap_digest):
        raise OperationalSecurityBootstrapExecutionApprovalError(
            "operational security bootstrap document does not match approval"
        )
    token_readiness = probe_authentication_token_readiness(
        document_path=authentication_document_path,
        token_path=token_path,
        approved_configuration_sha256=configuration_digest,
        approved_jwks_document_sha256=jwks_digest,
        open_url=open_url,
    )
    comparison_application = ProviderBoundOperationalSecurityBootstrapApplication(
        lambda: (_ for _ in ()).throw(
            OperationalSecurityBootstrapExecutionError(
                "operational security bootstrap entered a database session too early"
            )
        ),
        clock=clock,
    )
    _current_readiness_matches_approval(
        approval=approval,
        token_readiness=token_readiness,
        application=comparison_application,
        bootstrap_document=bootstrap_document,
    )
    if session_factory is not None:
        factory = session_factory
    else:
        def factory():
            return _operational_session_factory()()

    application = ProviderBoundOperationalSecurityBootstrapApplication(
        factory,
        clock=clock,
    )
    committed = application.execute(
        token_readiness=token_readiness,
        bootstrap_document=bootstrap_document,
        approved_configuration_sha256=configuration_digest,
        approved_jwks_document_sha256=jwks_digest,
        approved_bootstrap_document_sha256=bootstrap_digest,
    )
    return _execution_receipt(approval=approval, committed=committed)


def render_operational_security_bootstrap_execution_receipt(
    receipt: OperationalSecurityBootstrapExecutionReceipt,
) -> str:
    """Render canonical post-commit evidence without private identity inputs."""

    if type(receipt) is not OperationalSecurityBootstrapExecutionReceipt:
        raise TypeError("operational security bootstrap execution receipt is required")
    output = {
        "activation_ready": False,
        "bootstrap_committed": True,
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_id": str(receipt.bootstrap_id),
        "configuration_sha256": receipt.configuration_sha256,
        "database_accessed": True,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "execution_checked_at": receipt.execution_checked_at.isoformat(),
        "exclusive_lock_and_empty_domain_rechecked": True,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "migration_revision": receipt.migration_revision,
        "operational_schema": receipt.operational_schema,
        "organisation_id": str(receipt.organisation_id),
        "preview_approval_checked_at": receipt.preview_approval_checked_at.isoformat(),
        "preview_document_sha256": receipt.preview_document_sha256,
        "provider_ownership_attested": True,
        "provider_ownership_technically_verified": False,
        "request_id": str(receipt.request_id),
        "subject_sha256": receipt.subject_sha256,
        "user_id": str(receipt.user_id),
        "validation_scope": OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Execute one reviewed bootstrap or exit without disclosing private inputs."""

    parser = argparse.ArgumentParser(
        description="Execute the reviewed Engineer4Me operational bootstrap once."
    )
    parser.add_argument("authentication_document")
    parser.add_argument("token")
    parser.add_argument("bootstrap_document")
    parser.add_argument("preview_document")
    parser.add_argument("--approve-configuration-sha256", required=True)
    parser.add_argument("--approve-jwks-sha256", required=True)
    parser.add_argument("--approve-bootstrap-sha256", required=True)
    parser.add_argument("--approve-preview-sha256", required=True)
    parser.add_argument("--confirm-provider-ownership-and-bootstrap", required=True)
    options = parser.parse_args(arguments)
    try:
        receipt = execute_local_operational_security_bootstrap(
            authentication_document_path=options.authentication_document,
            token_path=options.token,
            bootstrap_document_path=options.bootstrap_document,
            preview_document_path=options.preview_document,
            approved_configuration_sha256=options.approve_configuration_sha256,
            approved_jwks_document_sha256=options.approve_jwks_sha256,
            approved_bootstrap_document_sha256=options.approve_bootstrap_sha256,
            approved_preview_document_sha256=options.approve_preview_sha256,
            execution_confirmation=options.confirm_provider_ownership_and_bootstrap,
            clock=_utc_now,
        )
        rendered = render_operational_security_bootstrap_execution_receipt(receipt)
    except Exception:
        parser.exit(2, "operational security bootstrap execution failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION",
    "OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE",
    "OperationalSecurityBootstrapExecutionApprovalError",
    "OperationalSecurityBootstrapExecutionError",
    "OperationalSecurityBootstrapExecutionReceipt",
    "execute_local_operational_security_bootstrap",
    "main",
    "render_operational_security_bootstrap_execution_receipt",
]
