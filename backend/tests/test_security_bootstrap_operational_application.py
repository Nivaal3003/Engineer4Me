"""Focused tests for provider-bound operational bootstrap application controls."""

from __future__ import annotations

import json
import os
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.security.authentication_bootstrap_readiness import (
    AuthenticationBootstrapReadinessError,
)
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
    authentication_identity_sha256,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.token_verifier import REQUIRED_CLAIMS
from app.services.security_bootstrap_executor import SecurityBootstrapStateError
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)
from app.services.security_bootstrap_operational_application import (
    BOOTSTRAP_DOCUMENT_MAXIMUM_AGE_SECONDS,
    BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS,
    TOKEN_READINESS_MAXIMUM_AGE_SECONDS,
    OperationalSecurityBootstrapApprovalError,
    OperationalSecurityBootstrapReadinessError,
    OperationalSecurityBootstrapReceipt,
    ProviderBoundOperationalSecurityBootstrapApplication,
)


NOW = datetime(2026, 8, 9, 16, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/tenant"
SUBJECT = "private-provider-owner-subject-step178"
IDS = {
    "bootstrap_id": UUID("17800000-0000-4000-8000-000000000001"),
    "request_id": UUID("17800000-0000-4000-8000-000000000002"),
    "user_id": UUID("17800000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("17800000-0000-4000-8000-000000000004"),
    "membership_id": UUID("17800000-0000-4000-8000-000000000005"),
    "snapshot_id": UUID("17800000-0000-4000-8000-000000000006"),
}


def bootstrap_document(
    *,
    issuer: str = ISSUER,
    subject: str = SUBJECT,
    activated_at: datetime | None = None,
    effective_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> bytes:
    activated = activated_at or NOW - timedelta(seconds=30)
    effective = effective_at or NOW - timedelta(seconds=60)
    expires = expires_at or NOW + timedelta(hours=1)
    value = {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": "private-owner@example.com",
        "display_name": "Private Initial Owner",
        "issuer": issuer,
        "subject": subject,
        "organisation_slug": "reviewed-organisation-step178",
        "organisation_name": "Reviewed Organisation Step 178",
        "initial_role": "owner",
        "activated_at": activated.isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step178",
            "subscription_status": "trial",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [
                {"kind": "monthly_calculation_runs", "limit": 100},
                {"kind": "monthly_document_ingestions", "limit": 25},
            ],
            "effective_at": effective.isoformat(),
            "expires_at": expires.isoformat(),
            "source_reference": "private reviewed source step178",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def token_readiness(
    *,
    checked_at: datetime | None = None,
    issuer: str = ISSUER,
    subject: str = SUBJECT,
) -> AuthenticationTokenReadinessReceipt:
    return AuthenticationTokenReadinessReceipt(
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        checked_at=checked_at or NOW - timedelta(seconds=10),
        token_algorithm="RS256",
        issuer_sha256=authentication_identity_sha256(issuer),
        audience_sha256=authentication_identity_sha256("engineer4me-api"),
        subject_sha256=authentication_identity_sha256(issuer, subject),
        required_claims=REQUIRED_CLAIMS,
    )


class OperationalSession:
    def __init__(self, *, schema: str = OPERATIONAL_SCHEMA) -> None:
        self.schema = schema
        self.actions: list[tuple[str, str] | str] = []
        self.added = []

    def scalar(self, statement):
        sql = " ".join(str(statement).split())
        self.actions.append(("scalar", sql))
        if sql == "SELECT current_schema()":
            return self.schema
        if "alembic_version" in sql:
            return PHASE8_SECURITY_HEAD
        if "max(" in sql.lower():
            return None
        return 0

    def execute(self, statement):
        self.actions.append(("execute", " ".join(str(statement).split())))

    def add(self, value):
        self.added.append(value)
        self.actions.append("add")

    def flush(self):
        self.actions.append("flush")

    def commit(self):
        self.actions.append("commit")

    def rollback(self):
        self.actions.append("rollback")

    def close(self):
        self.actions.append("close")


def application(
    sessions: list[OperationalSession],
    clock_calls: list[str],
    *,
    schema: str = OPERATIONAL_SCHEMA,
    clock_value: datetime = NOW,
) -> ProviderBoundOperationalSecurityBootstrapApplication:
    def session_factory():
        session = OperationalSession(schema=schema)
        sessions.append(session)
        return session

    def clock():
        clock_calls.append("clock")
        return clock_value

    return ProviderBoundOperationalSecurityBootstrapApplication(
        session_factory,
        clock=clock,
    )


def approvals(document: bytes) -> dict[str, str]:
    return {
        "approved_configuration_sha256": "1" * 64,
        "approved_jwks_document_sha256": "2" * 64,
        "approved_bootstrap_document_sha256": load_security_bootstrap_document(
            document
        ).preview.document_sha256,
    }


def test_preview_binds_identity_without_clock_or_database_session():
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document()
    preview = application(sessions, clock_calls).preview(
        token_readiness=token_readiness(),
        bootstrap_document=value,
    )

    assert (
        preview.bootstrap_document_sha256
        == approvals(value)["approved_bootstrap_document_sha256"]
    )
    assert preview.bootstrap_id == IDS["bootstrap_id"]
    assert sessions == []
    assert clock_calls == []


def test_prepare_checks_all_approvals_and_freshness_without_database_session():
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document()
    readiness = application(sessions, clock_calls).prepare(
        token_readiness=token_readiness(),
        bootstrap_document=value,
        **approvals(value),
    )

    assert readiness.configuration_sha256 == "1" * 64
    assert readiness.jwks_document_sha256 == "2" * 64
    assert readiness.bootstrap_id == IDS["bootstrap_id"]
    assert clock_calls == ["clock"]
    assert sessions == []


def test_exact_approvals_fresh_evidence_and_usable_entitlement_commit_once():
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document()
    receipt = application(sessions, clock_calls).execute(
        token_readiness=token_readiness(),
        bootstrap_document=value,
        **approvals(value),
    )

    assert receipt.configuration_sha256 == "1" * 64
    assert receipt.jwks_document_sha256 == "2" * 64
    assert (
        receipt.bootstrap_document_sha256
        == approvals(value)["approved_bootstrap_document_sha256"]
    )
    assert receipt.execution_checked_at == NOW
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.entitlement_snapshot_id == IDS["snapshot_id"]
    assert receipt.operational_schema == OPERATIONAL_SCHEMA
    assert receipt.migration_revision == PHASE8_SECURITY_HEAD
    assert clock_calls == ["clock"]
    assert len(sessions) == 1
    session = sessions[0]
    lock_index = next(
        index
        for index, action in enumerate(session.actions)
        if isinstance(action, tuple) and action[1].startswith("LOCK TABLE ")
    )
    count_index = next(
        index
        for index, action in enumerate(session.actions)
        if isinstance(action, tuple) and "SELECT count(*)" in action[1]
    )
    assert lock_index < count_index
    assert len(session.added) == 5
    assert session.actions[-2:] == ["commit", "close"]


@pytest.mark.parametrize(
    ("approval", "value", "message"),
    [
        ("approved_configuration_sha256", "0" * 64, "configuration"),
        ("approved_jwks_document_sha256", "3" * 64, "JWKS"),
        ("approved_bootstrap_document_sha256", "4" * 64, "bootstrap"),
    ],
)
def test_stale_or_mismatched_approval_fails_before_clock_and_database(
    approval,
    value,
    message,
):
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    document = bootstrap_document()
    approved = approvals(document)
    approved[approval] = value

    with pytest.raises(OperationalSecurityBootstrapApprovalError, match=message):
        application(sessions, clock_calls).execute(
            token_readiness=token_readiness(),
            bootstrap_document=document,
            **approved,
        )
    assert sessions == []
    assert clock_calls == []


@pytest.mark.parametrize("digest", [None, "", "0" * 63, "0" * 65, "A" * 64])
def test_malformed_approval_is_rejected_before_other_input_or_io(digest):
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    with pytest.raises(OperationalSecurityBootstrapApprovalError, match="invalid"):
        application(sessions, clock_calls).execute(
            token_readiness={},
            bootstrap_document=b"private malformed document",
            approved_configuration_sha256=digest,
            approved_jwks_document_sha256="2" * 64,
            approved_bootstrap_document_sha256="3" * 64,
        )
    assert sessions == []
    assert clock_calls == []


def test_signed_identity_mismatch_fails_before_clock_or_database():
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document(subject="private-different-subject-step178")
    with pytest.raises(AuthenticationBootstrapReadinessError, match="subject"):
        application(sessions, clock_calls).execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert sessions == []
    assert clock_calls == []


@pytest.mark.parametrize(
    "checked_at",
    [
        NOW - timedelta(seconds=TOKEN_READINESS_MAXIMUM_AGE_SECONDS + 1),
        NOW + timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS + 1),
    ],
)
def test_stale_or_future_signed_token_evidence_fails_before_database(checked_at):
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document()
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="signed-token readiness evidence",
    ):
        application(sessions, clock_calls).execute(
            token_readiness=token_readiness(checked_at=checked_at),
            bootstrap_document=value,
            **approvals(value),
        )
    assert sessions == []
    assert clock_calls == ["clock"]


@pytest.mark.parametrize(
    "activated_at",
    [
        NOW - timedelta(seconds=BOOTSTRAP_DOCUMENT_MAXIMUM_AGE_SECONDS + 1),
        NOW + timedelta(seconds=BOOTSTRAP_FUTURE_CLOCK_SKEW_SECONDS + 1),
    ],
)
def test_stale_or_future_bootstrap_document_fails_before_database(activated_at):
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document(
        activated_at=activated_at,
        effective_at=activated_at - timedelta(seconds=1),
        expires_at=activated_at + timedelta(hours=1),
    )
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="document is outside",
    ):
        application(sessions, clock_calls).execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert sessions == []


@pytest.mark.parametrize(
    ("activated_at", "effective_at", "expires_at"),
    [
        (
            NOW + timedelta(seconds=20),
            NOW + timedelta(seconds=10),
            NOW + timedelta(hours=1),
        ),
        (
            NOW - timedelta(seconds=30),
            NOW - timedelta(seconds=60),
            NOW,
        ),
    ],
)
def test_entitlement_must_be_usable_at_execution_time(
    activated_at,
    effective_at,
    expires_at,
):
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document(
        activated_at=activated_at,
        effective_at=effective_at,
        expires_at=expires_at,
    )
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="entitlement is not usable",
    ):
        application(sessions, clock_calls).execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert sessions == []


def test_operational_schema_failure_rolls_back_and_returns_no_receipt():
    sessions: list[OperationalSession] = []
    clock_calls: list[str] = []
    value = bootstrap_document()
    with pytest.raises(SecurityBootstrapStateError, match="unexpected schema"):
        application(sessions, clock_calls, schema="private").execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert len(sessions) == 1
    assert sessions[0].added == []
    assert sessions[0].actions[-2:] == ["rollback", "close"]


def test_clock_failures_are_sanitized_before_database_access():
    sessions: list[OperationalSession] = []

    def session_factory():
        session = OperationalSession()
        sessions.append(session)
        return session

    def failed_clock():
        raise RuntimeError("private clock detail")

    value = bootstrap_document()
    app = ProviderBoundOperationalSecurityBootstrapApplication(
        session_factory,
        clock=failed_clock,
    )
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="time is unavailable",
    ) as captured:
        app.execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert captured.value.__cause__ is None
    assert "private clock" not in str(captured.value)
    assert sessions == []


@pytest.mark.parametrize(
    "clock_value", [None, "2026-08-09T16:00:00Z", datetime(2026, 8, 9)]
)
def test_invalid_execution_clock_value_fails_before_database(clock_value):
    sessions: list[OperationalSession] = []
    value = bootstrap_document()
    app = ProviderBoundOperationalSecurityBootstrapApplication(
        lambda: sessions.append(OperationalSession()),
        clock=lambda: clock_value,
    )
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="time is invalid",
    ):
        app.execute(
            token_readiness=token_readiness(),
            bootstrap_document=value,
            **approvals(value),
        )
    assert sessions == []


def test_receipt_is_frozen_and_rejects_forged_operational_state():
    sessions: list[OperationalSession] = []
    receipt = application(sessions, []).execute(
        token_readiness=token_readiness(),
        bootstrap_document=(value := bootstrap_document()),
        **approvals(value),
    )
    with pytest.raises(FrozenInstanceError):
        receipt.operational_schema = "private"
    for changes in (
        {"configuration_sha256": "A" * 64},
        {"bootstrap_id": receipt.request_id},
        {"operational_schema": "private"},
        {"migration_revision": "unknown"},
        {"execution_checked_at": datetime(2026, 8, 9)},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)
    with pytest.raises(ValueError, match="receipt is invalid"):
        OperationalSecurityBootstrapReceipt(
            configuration_sha256="1" * 64,
            jwks_document_sha256="2" * 64,
            bootstrap_document_sha256="3" * 64,
            execution_checked_at=NOW,
            bootstrap_id=IDS["bootstrap_id"],
            request_id=IDS["request_id"],
            user_id=IDS["user_id"],
            organisation_id=IDS["organisation_id"],
            membership_id=IDS["membership_id"],
            entitlement_snapshot_id=IDS["membership_id"],
        )


def test_construction_and_preview_do_not_read_hidden_inputs_or_open_sessions(
    monkeypatch,
):
    calls = []

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    def session_factory():
        calls.append("session")
        return OperationalSession()

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    app = ProviderBoundOperationalSecurityBootstrapApplication(
        session_factory,
        clock=forbidden,
    )
    value = bootstrap_document()
    preview = app.preview(
        token_readiness=token_readiness(),
        bootstrap_document=value,
    )
    assert preview.bootstrap_id == IDS["bootstrap_id"]
    assert calls == []


@pytest.mark.parametrize(
    ("session_factory", "clock", "message"),
    [
        (None, lambda: NOW, "session factory"),
        (lambda: OperationalSession(), None, "clock"),
    ],
)
def test_dependencies_must_be_explicit_callables(session_factory, clock, message):
    with pytest.raises(TypeError, match=message):
        ProviderBoundOperationalSecurityBootstrapApplication(
            session_factory,
            clock=clock,
        )
