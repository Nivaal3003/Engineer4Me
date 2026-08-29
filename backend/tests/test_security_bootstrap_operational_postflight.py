"""Tests for exact read-only operational bootstrap postflight verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models.security_audit import SecurityAuditRecord
from app.models.security_identity import (
    SecurityEntitlementSnapshot,
    SecurityOrganisation,
    SecurityOrganisationMembership,
    SecurityUser,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.security_bootstrap_operational_execution import (
    OperationalSecurityBootstrapExecutionReceipt,
    render_operational_security_bootstrap_execution_receipt,
)
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
    OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE,
    OperationalSecurityBootstrapPostflightDocumentError,
    OperationalSecurityBootstrapPostflightPersistenceError,
    OperationalSecurityBootstrapPostflightReceipt,
    OperationalSecurityBootstrapPostflightStateError,
    load_operational_security_bootstrap_execution_receipt,
    load_operational_security_bootstrap_postflight_receipt,
    reverify_operational_security_bootstrap_postflight,
    render_operational_security_bootstrap_postflight_receipt,
    verify_operational_security_bootstrap_postflight,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)


NOW = datetime(2026, 8, 10, 14, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step182"
SUBJECT = "private-provider-owner-subject-step182"
IDS = {
    "bootstrap_id": UUID("18200000-0000-4000-8000-000000000001"),
    "request_id": UUID("18200000-0000-4000-8000-000000000002"),
    "user_id": UUID("18200000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18200000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18200000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID(
        "18200000-0000-4000-8000-000000000006"
    ),
}


def bootstrap_document() -> bytes:
    value = {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": "private-owner-step182@example.com",
        "display_name": "Private Initial Owner Step 182",
        "issuer": ISSUER,
        "subject": SUBJECT,
        "organisation_slug": "reviewed-organisation-step182",
        "organisation_name": "Reviewed Organisation Step 182",
        "initial_role": "owner",
        "activated_at": (NOW - timedelta(seconds=50)).isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["entitlement_snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step182",
            "subscription_status": "active",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [
                {"kind": "monthly_calculation_runs", "limit": 100},
                {"kind": "monthly_document_ingestions", "limit": 25},
            ],
            "effective_at": (NOW - timedelta(seconds=60)).isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "source_reference": "private reviewed source step182",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def execution_receipt() -> OperationalSecurityBootstrapExecutionReceipt:
    preview = load_security_bootstrap_document(bootstrap_document()).preview
    return OperationalSecurityBootstrapExecutionReceipt(
        preview_document_sha256="0" * 64,
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256=preview.document_sha256,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256=authentication_identity_sha256(ISSUER, SUBJECT),
        preview_approval_checked_at=NOW - timedelta(seconds=20),
        execution_checked_at=NOW - timedelta(seconds=10),
        **IDS,
    )


def execution_document(*, newline: bool = True) -> bytes:
    ending = "\n" if newline else ""
    return (
        render_operational_security_bootstrap_execution_receipt(
            execution_receipt()
        )
        + ending
    ).encode()


def persisted_rows() -> dict[type, object]:
    command = load_security_bootstrap_document(bootstrap_document()).command
    entitlement = command.entitlement
    return {
        SecurityUser: SecurityUser(
            id=command.user_id,
            email=command.email,
            display_name=command.display_name,
            status="active",
            issuer=command.issuer,
            subject=command.subject,
        ),
        SecurityOrganisation: SecurityOrganisation(
            id=command.organisation_id,
            slug=command.organisation_slug,
            name=command.organisation_name,
            status="active",
        ),
        SecurityOrganisationMembership: SecurityOrganisationMembership(
            id=command.membership_id,
            user_id=command.user_id,
            organisation_id=command.organisation_id,
            role=command.initial_role.value,
            status="active",
            joined_at=command.activated_at,
        ),
        SecurityEntitlementSnapshot: SecurityEntitlementSnapshot(
            id=entitlement.snapshot_id,
            organisation_id=command.organisation_id,
            sequence_number=1,
            plan_id=entitlement.plan_id,
            subscription_status=entitlement.subscription_status.value,
            features=[item.value for item in entitlement.features],
            quotas=[item.model_dump(mode="json") for item in entitlement.quotas],
            effective_at=entitlement.effective_at,
            expires_at=entitlement.expires_at,
            source_reference=entitlement.source_reference,
        ),
        SecurityAuditRecord: SecurityAuditRecord(
            id=command.bootstrap_id,
            occurred_at=command.activated_at,
            event_type="security_state_changed",
            outcome="succeeded",
            reason_code="initial_security_bootstrap",
            request_id=command.request_id,
            actor_user_id=command.user_id,
            organisation_id=command.organisation_id,
            session_id=None,
            permission=None,
            resource_kind=None,
            resource_id=None,
            context={
                "membership_role": command.initial_role.value,
                "entitlement_plan": entitlement.plan_id,
                "subscription_status": entitlement.subscription_status.value,
            },
        ),
    }


class ReadOnlySession:
    def __init__(
        self,
        *,
        schema: str = OPERATIONAL_SCHEMA,
        revision: str = PHASE8_SECURITY_HEAD,
        counts: tuple[int, ...] = (1, 1, 1, 1, 1),
        rows: dict[type, object] | None = None,
        fail: bool = False,
        trigger_count: int = 2,
    ) -> None:
        self.schema = schema
        self.revision = revision
        self.counts = iter(counts)
        self.rows = rows or persisted_rows()
        self.fail = fail
        self.trigger_count = trigger_count
        self.actions: list[tuple[str, str] | str] = []

    def execute(self, statement):
        sql = " ".join(str(statement).split())
        self.actions.append(("execute", sql))
        if self.fail:
            raise SQLAlchemyError("private database detail")

    def scalar(self, statement):
        sql = " ".join(str(statement).split())
        self.actions.append(("scalar", sql))
        if sql == "SELECT current_schema()":
            return self.schema
        if "alembic_version" in sql:
            return self.revision
        if "pg_trigger" in sql:
            return self.trigger_count
        return next(self.counts)

    def get(self, model, identifier):
        self.actions.append(("get", model.__name__))
        row = self.rows.get(model)
        if row is not None and row.id != identifier:
            return None
        return row

    def rollback(self):
        self.actions.append("rollback")

    def close(self):
        self.actions.append("close")


def verify(
    *,
    session: ReadOnlySession | None = None,
    document: bytes | None = None,
    bootstrap: bytes | None = None,
    digest: str | None = None,
):
    execution = document or execution_document()
    operational_session = session or ReadOnlySession()
    sessions = []

    def factory():
        sessions.append(operational_session)
        return operational_session

    receipt = verify_operational_security_bootstrap_postflight(
        execution_receipt_document=execution,
        bootstrap_document=bootstrap or bootstrap_document(),
        approved_execution_receipt_sha256=(
            digest or hashlib.sha256(execution).hexdigest()
        ),
        session_factory=factory,
        clock=lambda: NOW,
    )
    return receipt, operational_session, sessions


def test_exact_receipt_and_five_records_verify_in_one_read_only_session():
    receipt, session, sessions = verify()

    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.security_rows_verified == 5
    assert sessions == [session]
    assert session.actions[0] == (
        "execute",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
    )
    get_count = sum(
        action[0] == "get"
        for action in session.actions
        if isinstance(action, tuple)
    )
    assert get_count == 5
    assert session.actions[-2:] == ["rollback", "close"]
    assert "commit" not in session.actions


def test_execution_receipt_digest_mismatch_fails_before_session_access():
    sessions = []
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="does not match approval",
    ):
        verify_operational_security_bootstrap_postflight(
            execution_receipt_document=execution_document(),
            bootstrap_document=bootstrap_document(),
            approved_execution_receipt_sha256="f" * 64,
            session_factory=lambda: sessions.append(True),
            clock=lambda: NOW,
        )
    assert sessions == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: {**value, "activation_ready": True},
        lambda value: {**value, "bootstrap_committed": False},
        lambda value: {**value, "unknown": "field"},
        lambda value: {**value, "bootstrap_id": "not-a-uuid"},
    ],
)
def test_forged_or_extended_execution_receipt_is_rejected(mutate):
    value = json.loads(execution_document(newline=False))
    document = json.dumps(
        mutate(value),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        load_operational_security_bootstrap_execution_receipt(document)


@pytest.mark.parametrize(
    "document",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b"[]",
        b"{}\n{}",
        b"\xff",
    ],
)
def test_malformed_execution_receipt_is_sanitized(document):
    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        load_operational_security_bootstrap_execution_receipt(document)


def test_changed_bootstrap_identity_fails_before_session_access():
    value = json.loads(bootstrap_document())
    value["subject"] = "different-private-subject"
    changed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    sessions = []
    execution = execution_document()
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="bootstrap document digest",
    ):
        verify_operational_security_bootstrap_postflight(
            execution_receipt_document=execution,
            bootstrap_document=changed,
            approved_execution_receipt_sha256=hashlib.sha256(execution).hexdigest(),
            session_factory=lambda: sessions.append(True),
            clock=lambda: NOW,
        )
    assert sessions == []


@pytest.mark.parametrize(
    ("schema", "revision"),
    [
        ("private", PHASE8_SECURITY_HEAD),
        (OPERATIONAL_SCHEMA, "older"),
    ],
)
def test_wrong_schema_or_revision_rolls_back_and_closes(schema, revision):
    session = ReadOnlySession(schema=schema, revision=revision)
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="reviewed public head",
    ):
        verify(session=session)
    assert session.actions[-2:] == ["rollback", "close"]


def test_missing_append_only_control_fails_before_record_reads():
    session = ReadOnlySession(trigger_count=1)
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="append-only controls",
    ):
        verify(session=session)
    assert session.actions[-2:] == ["rollback", "close"]
    assert not any(
        isinstance(action, tuple) and action[0] == "get"
        for action in session.actions
    )


@pytest.mark.parametrize("index", range(5))
def test_any_non_exact_table_count_fails_closed(index):
    counts = [1, 1, 1, 1, 1]
    counts[index] = 2
    session = ReadOnlySession(counts=tuple(counts))
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="exactly five records",
    ):
        verify(session=session)
    assert session.actions[-2:] == ["rollback", "close"]
    assert not any(
        isinstance(action, tuple) and action[0] == "get"
        for action in session.actions
    )


@pytest.mark.parametrize(
    ("model", "attribute", "changed", "message"),
    [
        (SecurityUser, "subject", "wrong", "user subject"),
        (SecurityOrganisation, "slug", "wrong", "organisation slug"),
        (SecurityOrganisationMembership, "role", "engineer", "membership role"),
        (SecurityEntitlementSnapshot, "sequence_number", 2, "sequence"),
        (SecurityAuditRecord, "reason_code", "wrong", "audit reason"),
    ],
)
def test_each_persisted_record_is_bound_exactly(
    model,
    attribute,
    changed,
    message,
):
    rows = persisted_rows()
    setattr(rows[model], attribute, changed)
    session = ReadOnlySession(rows=rows)
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match=message,
    ):
        verify(session=session)
    assert session.actions[-2:] == ["rollback", "close"]


def test_database_failure_is_sanitized_and_session_is_closed():
    session = ReadOnlySession(fail=True)
    with pytest.raises(
        OperationalSecurityBootstrapPostflightPersistenceError,
        match="could not be completed",
    ) as captured:
        verify(session=session)
    assert captured.value.__cause__ is None
    assert "private database detail" not in str(captured.value)
    assert session.actions[-2:] == ["rollback", "close"]


def test_invalid_clock_fails_before_session_access():
    execution = execution_document()
    sessions = []
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="time is invalid",
    ):
        verify_operational_security_bootstrap_postflight(
            execution_receipt_document=execution,
            bootstrap_document=bootstrap_document(),
            approved_execution_receipt_sha256=hashlib.sha256(execution).hexdigest(),
            session_factory=lambda: sessions.append(True),
            clock=lambda: datetime(2026, 8, 10),
        )
    assert sessions == []


def test_postflight_receipt_is_frozen_and_rejects_forged_state():
    receipt, _, _ = verify()
    with pytest.raises(FrozenInstanceError):
        receipt.security_rows_verified = 4
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, security_rows_verified=4)
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, append_only_triggers_verified=1)
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(
            receipt,
            verification_checked_at=receipt.execution_checked_at
            - timedelta(seconds=1),
        )


def test_rendered_postflight_is_canonical_and_privacy_minimised():
    receipt, _, _ = verify()
    rendered = render_operational_security_bootstrap_postflight_receipt(receipt)
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["validation_scope"] == OPERATIONAL_BOOTSTRAP_POSTFLIGHT_SCOPE
    assert value["bootstrap_committed"] is True
    assert value["bootstrap_verified"] is True
    assert value["database_transaction_read_only"] is True
    assert value["activation_ready"] is False
    assert value["security_rows_verified"] == 5
    assert value["append_only_triggers_verified"] == 2
    for private in (
        ISSUER,
        SUBJECT,
        "private-owner-step182@example.com",
        "Private Initial Owner Step 182",
        "private reviewed source step182",
    ):
        assert private not in rendered


def test_execution_receipt_parser_accepts_exact_cli_newline_only():
    receipt = load_operational_security_bootstrap_execution_receipt(
        execution_document(newline=True)
    )
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="canonical line",
    ):
        load_operational_security_bootstrap_execution_receipt(
            execution_document(newline=True) + b"\n"
        )


def postflight_document(*, newline: bytes = b"\n") -> bytes:
    receipt, _, _ = verify()
    return (
        render_operational_security_bootstrap_postflight_receipt(
            receipt
        ).encode("utf-8")
        + newline
    )


def test_exact_postflight_document_round_trips_to_frozen_receipt():
    expected, _, _ = verify()

    loaded = load_operational_security_bootstrap_postflight_receipt(
        postflight_document()
    )

    assert loaded == expected
    assert loaded.configuration_sha256 == expected.configuration_sha256
    assert loaded.bootstrap_id == IDS["bootstrap_id"]
    with pytest.raises(FrozenInstanceError):
        loaded.security_rows_verified = 4


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: {**value, "activation_ready": True},
        lambda value: {**value, "bootstrap_committed": False},
        lambda value: {**value, "bootstrap_verified": False},
        lambda value: {**value, "database_transaction_read_only": False},
        lambda value: {**value, "security_rows_verified": 4},
        lambda value: {**value, "append_only_triggers_verified": 1},
        lambda value: {**value, "configuration_sha256": "F" * 64},
        lambda value: {**value, "bootstrap_id": "not-a-uuid"},
        lambda value: {**value, "verification_checked_at": "not-a-time"},
        lambda value: {**value, "unknown": "field"},
    ],
)
def test_forged_or_extended_postflight_receipt_is_rejected(mutate):
    value = json.loads(postflight_document(newline=b""))
    forged = json.dumps(
        mutate(value),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        load_operational_security_bootstrap_postflight_receipt(forged)


@pytest.mark.parametrize(
    "document",
    [
        b'{}',
        b'[]',
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{}\n{}',
        b'\xff',
        b'',
    ],
)
def test_malformed_postflight_receipt_is_sanitized(document):
    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        load_operational_security_bootstrap_postflight_receipt(document)


def test_postflight_receipt_requires_exact_bytes_and_bounded_canonical_line():
    with pytest.raises(TypeError, match="must be bytes"):
        load_operational_security_bootstrap_postflight_receipt("private")
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="size is invalid",
    ):
        load_operational_security_bootstrap_postflight_receipt(
            b"x" * (MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES + 1)
        )
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="canonical line",
    ):
        load_operational_security_bootstrap_postflight_receipt(
            postflight_document() + b"\n"
        )


def test_postflight_receipt_accepts_one_cli_newline_or_crlf_only():
    lf = load_operational_security_bootstrap_postflight_receipt(
        postflight_document(newline=b"\n")
    )
    crlf = load_operational_security_bootstrap_postflight_receipt(
        postflight_document(newline=b"\r\n")
    )
    assert lf == crlf


def test_postflight_receipt_rejects_noncanonical_json_encoding():
    value = json.loads(postflight_document(newline=b""))
    noncanonical = json.dumps(value).encode()
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="not canonical",
    ):
        load_operational_security_bootstrap_postflight_receipt(noncanonical)


def test_loaded_postflight_receipt_contains_no_raw_bootstrap_identity():
    loaded = load_operational_security_bootstrap_postflight_receipt(
        postflight_document()
    )
    rendered = repr(loaded)
    for private in (
        ISSUER,
        SUBJECT,
        "private-owner-step182@example.com",
        "Private Initial Owner Step 182",
        "private reviewed source step182",
    ):
        assert private not in rendered


def test_canonical_postflight_is_reverified_against_fresh_public_snapshot():
    session = ReadOnlySession()
    checked_at = NOW + timedelta(minutes=5)
    document = postflight_document()
    expected = load_operational_security_bootstrap_postflight_receipt(document)

    receipt = reverify_operational_security_bootstrap_postflight(
        postflight_receipt_document=document,
        bootstrap_document=bootstrap_document(),
        approved_postflight_receipt_sha256=hashlib.sha256(
            document
        ).hexdigest(),
        session_factory=lambda: session,
        clock=lambda: checked_at,
    )

    assert receipt.verification_checked_at == checked_at
    assert receipt.execution_receipt_sha256 == expected.execution_receipt_sha256
    assert session.actions[0] == (
        "execute",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
    )
    assert session.actions[-2:] == ["rollback", "close"]
    assert "commit" not in session.actions


def test_postflight_reverification_digest_mismatch_precedes_session_access():
    sessions = []
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="does not match approval",
    ):
        reverify_operational_security_bootstrap_postflight(
            postflight_receipt_document=postflight_document(),
            bootstrap_document=bootstrap_document(),
            approved_postflight_receipt_sha256="f" * 64,
            session_factory=lambda: sessions.append(True),
            clock=lambda: NOW,
        )
    assert sessions == []


def test_postflight_reverification_rejects_changed_bootstrap_before_session():
    changed = json.loads(bootstrap_document())
    changed["organisation_name"] = "Private changed organisation"
    changed_document = json.dumps(
        changed,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    sessions = []
    document = postflight_document()
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="bootstrap document digest",
    ):
        reverify_operational_security_bootstrap_postflight(
            postflight_receipt_document=document,
            bootstrap_document=changed_document,
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=lambda: sessions.append(True),
            clock=lambda: NOW,
        )
    assert sessions == []


def test_postflight_reverification_cannot_precede_prior_verification():
    sessions = []
    document = postflight_document()
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="precedes prior postflight",
    ):
        reverify_operational_security_bootstrap_postflight(
            postflight_receipt_document=document,
            bootstrap_document=bootstrap_document(),
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=lambda: sessions.append(True),
            clock=lambda: NOW - timedelta(seconds=1),
        )
    assert sessions == []


def test_postflight_reverification_database_drift_rolls_back_and_closes():
    session = ReadOnlySession(counts=(1, 1, 1, 1, 2))
    document = postflight_document()
    with pytest.raises(
        OperationalSecurityBootstrapPostflightStateError,
        match="exactly five records",
    ):
        reverify_operational_security_bootstrap_postflight(
            postflight_receipt_document=document,
            bootstrap_document=bootstrap_document(),
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=lambda: session,
            clock=lambda: NOW,
        )
    assert session.actions[-2:] == ["rollback", "close"]
