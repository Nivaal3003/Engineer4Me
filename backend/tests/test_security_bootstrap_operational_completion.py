"""Tests for the commit-to-postflight operational bootstrap boundary."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.security_bootstrap_operational_completion import (
    OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    OperationalSecurityBootstrapCommitOutcomeUnknownError,
    OperationalSecurityBootstrapPostCommitVerificationError,
    complete_local_operational_security_bootstrap,
    main,
)
from app.security.security_bootstrap_operational_execution import (
    OperationalSecurityBootstrapExecutionReceipt,
    render_operational_security_bootstrap_execution_receipt,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightReceipt,
)


NOW = datetime(2026, 8, 10, 16, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step184"
SUBJECT = "private-provider-owner-subject-step184"
BOOTSTRAP_DOCUMENT = b'{"private":"reviewed-bootstrap-step184"}'
IDS = {
    "bootstrap_id": UUID("18400000-0000-4000-8000-000000000001"),
    "request_id": UUID("18400000-0000-4000-8000-000000000002"),
    "user_id": UUID("18400000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18400000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18400000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID(
        "18400000-0000-4000-8000-000000000006"
    ),
}


def execution_receipt() -> OperationalSecurityBootstrapExecutionReceipt:
    return OperationalSecurityBootstrapExecutionReceipt(
        preview_document_sha256="0" * 64,
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256=authentication_identity_sha256(ISSUER, SUBJECT),
        preview_approval_checked_at=NOW - timedelta(seconds=20),
        execution_checked_at=NOW - timedelta(seconds=10),
        **IDS,
    )


def execution_document() -> bytes:
    return (
        render_operational_security_bootstrap_execution_receipt(
            execution_receipt()
        )
        + "\n"
    ).encode()


def postflight_receipt() -> OperationalSecurityBootstrapPostflightReceipt:
    document = execution_document()
    execution = execution_receipt()
    return OperationalSecurityBootstrapPostflightReceipt(
        execution_receipt_sha256=hashlib.sha256(document).hexdigest(),
        preview_document_sha256=execution.preview_document_sha256,
        configuration_sha256=execution.configuration_sha256,
        jwks_document_sha256=execution.jwks_document_sha256,
        bootstrap_document_sha256=execution.bootstrap_document_sha256,
        issuer_sha256=execution.issuer_sha256,
        subject_sha256=execution.subject_sha256,
        execution_checked_at=execution.execution_checked_at,
        verification_checked_at=NOW,
        **IDS,
    )


def arguments() -> dict[str, object]:
    return {
        "authentication_document_path": "private-authentication.json",
        "token_path": "private-token.jwt",
        "bootstrap_document_path": "private-bootstrap.json",
        "preview_document_path": "private-preview.json",
        "approved_configuration_sha256": "1" * 64,
        "approved_jwks_document_sha256": "2" * 64,
        "approved_bootstrap_document_sha256": "3" * 64,
        "approved_preview_document_sha256": "4" * 64,
        "execution_confirmation": OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
        "clock": lambda: NOW,
    }


def install_successful_boundaries(monkeypatch, *, order=None):
    calls = order if order is not None else []

    def execute(**kwargs):
        calls.append(("execute", kwargs))
        return execution_receipt()

    def read(path):
        calls.append(("read_bootstrap", path))
        return BOOTSTRAP_DOCUMENT

    def verify(**kwargs):
        calls.append(("postflight", kwargs))
        return postflight_receipt()

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "execute_local_operational_security_bootstrap",
        execute,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "read_operational_security_bootstrap_document",
        read,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "verify_operational_security_bootstrap_postflight",
        verify,
    )
    return calls


def test_confirmed_commit_is_immediately_verified_in_separate_session(
    monkeypatch,
):
    order = install_successful_boundaries(monkeypatch)
    write_session = object()
    read_session = object()
    write_factory = lambda: write_session
    read_factory = lambda: read_session

    receipt = complete_local_operational_security_bootstrap(
        **arguments(),
        write_session_factory=write_factory,
        read_session_factory=read_factory,
        open_url=object(),
    )

    assert receipt == postflight_receipt()
    assert [item[0] for item in order] == [
        "execute",
        "read_bootstrap",
        "postflight",
    ]
    execute_kwargs = order[0][1]
    postflight_kwargs = order[2][1]
    assert execute_kwargs["session_factory"] is write_factory
    assert postflight_kwargs["session_factory"] is read_factory
    assert postflight_kwargs["bootstrap_document"] == BOOTSTRAP_DOCUMENT
    assert postflight_kwargs["execution_receipt_document"] == (
        execution_document()
    )
    assert postflight_kwargs["approved_execution_receipt_sha256"] == (
        hashlib.sha256(execution_document()).hexdigest()
    )


def test_execution_failure_never_opens_postflight_boundary(monkeypatch):
    calls = []

    def fail(**kwargs):
        del kwargs
        calls.append("execute")
        raise RuntimeError("private pre-commit detail")

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("postflight access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "execute_local_operational_security_bootstrap",
        fail,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "read_operational_security_bootstrap_document",
        forbidden,
    )
    with pytest.raises(
        OperationalSecurityBootstrapCommitOutcomeUnknownError,
        match="before commit confirmation",
    ) as captured:
        complete_local_operational_security_bootstrap(**arguments())
    assert captured.value.__cause__ is None
    assert "private" not in str(captured.value)
    assert calls == ["execute"]


def test_postflight_failure_is_distinguished_after_commit(monkeypatch):
    order = []

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "execute_local_operational_security_bootstrap",
        lambda **kwargs: order.append("commit") or execution_receipt(),
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "read_operational_security_bootstrap_document",
        lambda path: order.append("read") or BOOTSTRAP_DOCUMENT,
    )

    def fail(**kwargs):
        del kwargs
        order.append("postflight")
        raise RuntimeError("private persisted identity detail")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "verify_operational_security_bootstrap_postflight",
        fail,
    )
    with pytest.raises(
        OperationalSecurityBootstrapPostCommitVerificationError,
        match="committed but postflight failed",
    ) as captured:
        complete_local_operational_security_bootstrap(**arguments())
    assert captured.value.__cause__ is None
    assert "private" not in str(captured.value)
    assert captured.value.execution_receipt_document == execution_document()
    assert order == ["commit", "read", "postflight"]


@pytest.mark.parametrize(
    ("write_factory", "read_factory", "clock", "message"),
    [
        (object(), lambda: None, lambda: NOW, "write session factory"),
        (lambda: None, object(), lambda: NOW, "read session factory"),
        (lambda: None, lambda: None, object(), "clock"),
    ],
)
def test_invalid_collaborators_fail_before_execution(
    monkeypatch,
    write_factory,
    read_factory,
    clock,
    message,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "execute_local_operational_security_bootstrap",
        lambda **kwargs: calls.append(kwargs),
    )
    values = arguments()
    values["clock"] = clock
    with pytest.raises(TypeError, match=message):
        complete_local_operational_security_bootstrap(
            **values,
            write_session_factory=write_factory,
            read_session_factory=read_factory,
        )
    assert calls == []


def test_default_factories_resolve_fresh_write_then_read_sessions(monkeypatch):
    sessions = [object(), object()]
    resolved = []
    observed = []

    def resolver():
        resolved.append(True)
        return lambda: sessions[len(resolved) - 1]

    def execute(**kwargs):
        observed.append(("write", kwargs["session_factory"]()))
        return execution_receipt()

    def verify(**kwargs):
        observed.append(("read", kwargs["session_factory"]()))
        return postflight_receipt()

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "_operational_session_factory",
        resolver,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "execute_local_operational_security_bootstrap",
        execute,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "read_operational_security_bootstrap_document",
        lambda path: BOOTSTRAP_DOCUMENT,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "verify_operational_security_bootstrap_postflight",
        verify,
    )

    receipt = complete_local_operational_security_bootstrap(**arguments())

    assert receipt == postflight_receipt()
    assert len(resolved) == 2
    assert observed == [("write", sessions[0]), ("read", sessions[1])]
    assert sessions[0] is not sessions[1]


def cli_arguments() -> list[str]:
    return [
        "private-authentication.json",
        "private-token.jwt",
        "private-bootstrap.json",
        "private-preview.json",
        "--approve-configuration-sha256",
        "1" * 64,
        "--approve-jwks-sha256",
        "2" * 64,
        "--approve-bootstrap-sha256",
        "3" * 64,
        "--approve-preview-sha256",
        "4" * 64,
        "--confirm-provider-ownership-and-bootstrap",
        OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    ]


def test_cli_success_prints_only_final_postflight_receipt(monkeypatch, capsys):
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "complete_local_operational_security_bootstrap",
        lambda **kwargs: postflight_receipt(),
    )

    assert main(cli_arguments()) == 0
    output = capsys.readouterr()
    value = json.loads(output.out)
    assert value["bootstrap_committed"] is True
    assert value["bootstrap_verified"] is True
    assert value["activation_ready"] is False
    assert output.err == ""
    for private in (
        "private-authentication.json",
        "private-token.jwt",
        "private-bootstrap.json",
        "private-preview.json",
        ISSUER,
        SUBJECT,
    ):
        assert private not in output.out


def test_cli_unknown_commit_outcome_is_nonzero_and_forbids_retry(
    monkeypatch,
    capsys,
):
    def fail(**kwargs):
        del kwargs
        raise OperationalSecurityBootstrapCommitOutcomeUnknownError("private")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "complete_local_operational_security_bootstrap",
        fail,
    )
    with pytest.raises(SystemExit) as captured:
        main(cli_arguments())
    output = capsys.readouterr()

    assert captured.value.code == 2
    assert output.out == ""
    assert "do not retry automatically" in output.err
    assert "inspect the operational security state" in output.err
    assert "private" not in output.err


def test_cli_confirmed_commit_postflight_failure_forbids_bootstrap_retry(
    monkeypatch,
    capsys,
):
    def fail(**kwargs):
        del kwargs
        raise OperationalSecurityBootstrapPostCommitVerificationError(
            execution_document()
        )

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_completion."
        "complete_local_operational_security_bootstrap",
        fail,
    )
    with pytest.raises(SystemExit) as captured:
        main(cli_arguments())
    output = capsys.readouterr()

    assert captured.value.code == 3
    assert output.out.encode() == execution_document()
    recovered = json.loads(output.out)
    assert recovered["bootstrap_committed"] is True
    assert recovered["activation_ready"] is False
    assert "commit was confirmed" in output.err
    assert "do not retry bootstrap" in output.err
    assert "read-only postflight recovery" in output.err
    assert "private" not in output.err


def test_postcommit_error_rejects_missing_recovery_receipt():
    for value in (b"", "not-bytes", None):
        with pytest.raises(ValueError, match="recovery receipt is invalid"):
            OperationalSecurityBootstrapPostCommitVerificationError(value)
