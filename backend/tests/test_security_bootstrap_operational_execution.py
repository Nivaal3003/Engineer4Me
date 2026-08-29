"""Focused tests for the explicit operational bootstrap execution boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
    authentication_identity_sha256,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.security.security_bootstrap_operational_execution import (
    OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE,
    OperationalSecurityBootstrapExecutionApprovalError,
    OperationalSecurityBootstrapExecutionReceipt,
    execute_local_operational_security_bootstrap,
    main,
    render_operational_security_bootstrap_execution_receipt,
)
from app.security.security_bootstrap_operational_preview import (
    OperationalSecurityBootstrapPreviewReceipt,
    render_operational_security_bootstrap_preview,
)
from app.security.token_verifier import REQUIRED_CLAIMS
from app.services.security_bootstrap_executor import SecurityBootstrapStateError
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/tenant"
SUBJECT = "private-provider-owner-subject-step181"
IDS = {
    "bootstrap_id": UUID("18100000-0000-4000-8000-000000000001"),
    "request_id": UUID("18100000-0000-4000-8000-000000000002"),
    "user_id": UUID("18100000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18100000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18100000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID(
        "18100000-0000-4000-8000-000000000006"
    ),
}


def bootstrap_document() -> bytes:
    value = {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": "private-owner@example.com",
        "display_name": "Private Initial Owner",
        "issuer": ISSUER,
        "subject": SUBJECT,
        "organisation_slug": "reviewed-organisation-step181",
        "organisation_name": "Reviewed Organisation Step 181",
        "initial_role": "owner",
        "activated_at": (NOW - timedelta(seconds=40)).isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["entitlement_snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step181",
            "subscription_status": "trial",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [
                {"kind": "monthly_calculation_runs", "limit": 100},
                {"kind": "monthly_document_ingestions", "limit": 25},
            ],
            "effective_at": (NOW - timedelta(seconds=50)).isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "source_reference": "private reviewed source step181",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def token_readiness(*, algorithm: str = "RS256") -> AuthenticationTokenReadinessReceipt:
    return AuthenticationTokenReadinessReceipt(
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        checked_at=NOW - timedelta(seconds=30),
        token_algorithm=algorithm,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        audience_sha256=authentication_identity_sha256("engineer4me-api"),
        subject_sha256=authentication_identity_sha256(ISSUER, SUBJECT),
        required_claims=REQUIRED_CLAIMS,
    )


def preview_document(*, algorithm: str = "RS256") -> bytes:
    validated = load_security_bootstrap_document(bootstrap_document()).preview
    receipt = OperationalSecurityBootstrapPreviewReceipt(
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256=validated.document_sha256,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256=authentication_identity_sha256(ISSUER, SUBJECT),
        token_checked_at=NOW - timedelta(seconds=30),
        execution_checked_at=NOW - timedelta(seconds=20),
        token_algorithm=algorithm,
        bootstrap_id=validated.bootstrap_id,
        request_id=validated.request_id,
        user_id=validated.user_id,
        organisation_id=validated.organisation_id,
        membership_id=validated.membership_id,
        entitlement_snapshot_id=validated.entitlement_snapshot_id,
        initial_role=OrganisationRole.OWNER,
        entitlement_plan="reviewed-plan-step181",
        subscription_status=SubscriptionStatus.TRIAL,
        features=(
            ControlledFeature.ENGINEERING_CALCULATIONS,
            ControlledFeature.DOCUMENT_INGESTION,
        ),
        quota_kinds=(
            QuotaKind.MONTHLY_CALCULATION_RUNS,
            QuotaKind.MONTHLY_DOCUMENT_INGESTIONS,
        ),
    )
    return render_operational_security_bootstrap_preview(receipt).encode()


class OperationalSession:
    def __init__(self, *, schema: str = OPERATIONAL_SCHEMA, count: int = 0) -> None:
        self.schema = schema
        self.count = count
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
        if "count(" in sql.lower():
            return self.count
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


def write_inputs(tmp_path, *, algorithm: str = "RS256"):
    authentication = tmp_path / "authentication.json"
    token = tmp_path / "token.jwt"
    bootstrap = tmp_path / "bootstrap.json"
    preview = tmp_path / "preview.json"
    authentication.write_bytes(b"explicit public metadata")
    token.write_bytes(b"explicit.private.token")
    bootstrap.write_bytes(bootstrap_document())
    preview.write_bytes(preview_document(algorithm=algorithm))
    return authentication, token, bootstrap, preview


def approvals(preview_path) -> dict[str, str]:
    document = bootstrap_document()
    return {
        "approved_configuration_sha256": "1" * 64,
        "approved_jwks_document_sha256": "2" * 64,
        "approved_bootstrap_document_sha256": load_security_bootstrap_document(
            document
        ).preview.document_sha256,
        "approved_preview_document_sha256": hashlib.sha256(
            preview_path.read_bytes()
        ).hexdigest(),
    }


def execute(
    tmp_path,
    monkeypatch,
    *,
    token_evidence: AuthenticationTokenReadinessReceipt | None = None,
    session: OperationalSession | None = None,
    confirmation: str = OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    algorithm: str = "RS256",
):
    paths = write_inputs(tmp_path, algorithm=algorithm)
    authentication, token, bootstrap, preview = paths
    evidence = token_evidence or token_readiness()
    probe_calls = []

    def probe(**kwargs):
        probe_calls.append(kwargs)
        return evidence

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "probe_authentication_token_readiness",
        probe,
    )
    operational_session = session or OperationalSession()
    sessions = []

    def session_factory():
        sessions.append(operational_session)
        return operational_session

    clock_values = iter((NOW, NOW))
    receipt = execute_local_operational_security_bootstrap(
        authentication_document_path=str(authentication),
        token_path=str(token),
        bootstrap_document_path=str(bootstrap),
        preview_document_path=str(preview),
        **approvals(preview),
        execution_confirmation=confirmation,
        session_factory=session_factory,
        open_url=object(),
        clock=lambda: next(clock_values),
    )
    return receipt, probe_calls, sessions, paths


def test_exact_approved_inputs_commit_once_after_preview_rebinding(
    tmp_path, monkeypatch
):
    receipt, probe_calls, sessions, paths = execute(tmp_path, monkeypatch)

    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.preview_document_sha256 == hashlib.sha256(
        paths[3].read_bytes()
    ).hexdigest()
    assert receipt.operational_schema == OPERATIONAL_SCHEMA
    assert receipt.migration_revision == PHASE8_SECURITY_HEAD
    assert len(probe_calls) == 1
    assert probe_calls[0]["document_path"] == str(paths[0])
    assert probe_calls[0]["token_path"] == str(paths[1])
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


def test_confirmation_and_all_digest_shapes_fail_before_input_access(
    tmp_path, monkeypatch
):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("input or external access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "approve_local_operational_security_bootstrap_preview",
        forbidden,
    )
    common = {
        "authentication_document_path": str(tmp_path / "private-auth"),
        "token_path": str(tmp_path / "private-token"),
        "bootstrap_document_path": str(tmp_path / "private-bootstrap"),
        "preview_document_path": str(tmp_path / "private-preview"),
        "approved_configuration_sha256": "1" * 64,
        "approved_jwks_document_sha256": "2" * 64,
        "approved_bootstrap_document_sha256": "3" * 64,
        "approved_preview_document_sha256": "4" * 64,
        "execution_confirmation": OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    }
    for name, value in (
        ("execution_confirmation", "execute"),
        ("approved_configuration_sha256", "invalid"),
        ("approved_jwks_document_sha256", "invalid"),
        ("approved_bootstrap_document_sha256", "invalid"),
        ("approved_preview_document_sha256", "invalid"),
    ):
        arguments = dict(common)
        arguments[name] = value
        with pytest.raises(OperationalSecurityBootstrapExecutionApprovalError):
            execute_local_operational_security_bootstrap(**arguments)
    assert calls == []


def test_changed_preview_fails_before_token_probe_or_session(tmp_path, monkeypatch):
    paths = write_inputs(tmp_path)
    approval = approvals(paths[3])
    paths[3].write_bytes(paths[3].read_bytes() + b"\n")
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("token or session access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "probe_authentication_token_readiness",
        forbidden,
    )
    with pytest.raises(Exception, match="does not match approval"):
        execute_local_operational_security_bootstrap(
            authentication_document_path=str(paths[0]),
            token_path=str(paths[1]),
            bootstrap_document_path=str(paths[2]),
            preview_document_path=str(paths[3]),
            **approval,
            execution_confirmation=OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
            session_factory=forbidden,
            clock=lambda: NOW,
        )
    assert calls == []


def test_changed_current_algorithm_fails_before_session(tmp_path, monkeypatch):
    sessions = []
    with pytest.raises(
        OperationalSecurityBootstrapExecutionApprovalError,
        match="algorithm",
    ):
        paths = write_inputs(tmp_path, algorithm="RS256")

        def probe(**kwargs):
            del kwargs
            return token_readiness(algorithm="RS384")

        monkeypatch.setattr(
            "app.security.security_bootstrap_operational_execution."
            "probe_authentication_token_readiness",
            probe,
        )
        clocks = iter((NOW, NOW))
        execute_local_operational_security_bootstrap(
            authentication_document_path=str(paths[0]),
            token_path=str(paths[1]),
            bootstrap_document_path=str(paths[2]),
            preview_document_path=str(paths[3]),
            **approvals(paths[3]),
            execution_confirmation=OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
            session_factory=lambda: sessions.append(True),
            clock=lambda: next(clocks),
        )
    assert sessions == []


@pytest.mark.parametrize(
    ("session", "message"),
    [
        (OperationalSession(schema="private"), "unexpected schema"),
        (OperationalSession(count=1), "empty security domain"),
    ],
)
def test_operational_state_failure_rolls_back_and_returns_no_receipt(
    tmp_path, monkeypatch, session, message
):
    with pytest.raises(SecurityBootstrapStateError, match=message):
        execute(tmp_path, monkeypatch, session=session)
    assert session.actions[-2:] == ["rollback", "close"]
    assert "commit" not in session.actions


def test_rendered_receipt_is_canonical_private_and_post_commit_only(
    tmp_path, monkeypatch
):
    receipt, _, _, _ = execute(tmp_path, monkeypatch)
    rendered = render_operational_security_bootstrap_execution_receipt(receipt)
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["validation_scope"] == OPERATIONAL_BOOTSTRAP_EXECUTION_SCOPE
    assert value["bootstrap_committed"] is True
    assert value["database_accessed"] is True
    assert value["exclusive_lock_and_empty_domain_rechecked"] is True
    assert value["provider_ownership_attested"] is True
    assert value["provider_ownership_technically_verified"] is False
    assert value["activation_ready"] is False
    for private in (
        ISSUER,
        SUBJECT,
        "private-owner@example.com",
        "explicit.private.token",
        "source step181",
    ):
        assert private not in rendered


def test_execution_receipt_is_frozen_and_rejects_forged_state(
    tmp_path, monkeypatch
):
    receipt, _, _, _ = execute(tmp_path, monkeypatch)
    with pytest.raises(FrozenInstanceError):
        receipt.bootstrap_id = UUID(int=0)
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, operational_schema="private")


def test_default_operational_factory_is_resolved_only_after_all_evidence_matches(
    tmp_path, monkeypatch
):
    paths = write_inputs(tmp_path, algorithm="RS256")
    calls = []

    def probe(**kwargs):
        del kwargs
        return token_readiness(algorithm="RS384")

    def forbidden_factory():
        calls.append("factory")
        raise AssertionError("operational factory was resolved early")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "probe_authentication_token_readiness",
        probe,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "_operational_session_factory",
        forbidden_factory,
    )
    with pytest.raises(OperationalSecurityBootstrapExecutionApprovalError):
        execute_local_operational_security_bootstrap(
            authentication_document_path=str(paths[0]),
            token_path=str(paths[1]),
            bootstrap_document_path=str(paths[2]),
            preview_document_path=str(paths[3]),
            **approvals(paths[3]),
            execution_confirmation=OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
            clock=lambda: NOW,
        )
    assert calls == []


def test_default_operational_factory_is_resolved_lazily_on_success(
    tmp_path, monkeypatch
):
    paths = write_inputs(tmp_path)
    session = OperationalSession()
    calls = []

    def probe(**kwargs):
        del kwargs
        return token_readiness()

    def resolve_factory():
        calls.append("resolve")
        return lambda: session

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "probe_authentication_token_readiness",
        probe,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_execution."
        "_operational_session_factory",
        resolve_factory,
    )
    clocks = iter((NOW, NOW))
    receipt = execute_local_operational_security_bootstrap(
        authentication_document_path=str(paths[0]),
        token_path=str(paths[1]),
        bootstrap_document_path=str(paths[2]),
        preview_document_path=str(paths[3]),
        **approvals(paths[3]),
        execution_confirmation=OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
        clock=lambda: next(clocks),
    )
    assert calls == ["resolve"]
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert session.actions[-2:] == ["commit", "close"]


def test_cli_failure_is_generic_and_does_not_disclose_paths(tmp_path, capsys):
    private = tmp_path / "private-provider-name.json"
    arguments = [
        str(private),
        str(private),
        str(private),
        str(private),
        "--approve-configuration-sha256",
        "1" * 64,
        "--approve-jwks-sha256",
        "2" * 64,
        "--approve-bootstrap-sha256",
        "3" * 64,
        "--approve-preview-sha256",
        "4" * 64,
        "--confirm-provider-ownership-and-bootstrap",
        "invalid",
    ]
    with pytest.raises(SystemExit) as caught:
        main(arguments)
    output = capsys.readouterr()
    assert caught.value.code == 2
    assert output.out == ""
    assert output.err == "operational security bootstrap execution failed\n"
    assert "private-provider" not in output.err


def test_manual_receipt_requires_exact_public_state_and_distinct_identifiers():
    common = {
        "preview_document_sha256": "0" * 64,
        "configuration_sha256": "1" * 64,
        "jwks_document_sha256": "2" * 64,
        "bootstrap_document_sha256": "3" * 64,
        "issuer_sha256": "4" * 64,
        "subject_sha256": "5" * 64,
        "preview_approval_checked_at": NOW,
        "execution_checked_at": NOW,
        **IDS,
    }
    assert OperationalSecurityBootstrapExecutionReceipt(**common).bootstrap_id
    with pytest.raises(ValueError, match="receipt is invalid"):
        OperationalSecurityBootstrapExecutionReceipt(
            **{**common, "membership_id": IDS["user_id"]}
        )
