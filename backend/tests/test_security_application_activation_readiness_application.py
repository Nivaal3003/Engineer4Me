"""Tests for the controlled local activation-readiness application."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from app.main import app
from app.security.authentication_readiness_document import (
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
)
from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessError,
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
)
from app.security.security_application_activation_readiness_application import (
    OperationalApplicationActivationReadinessFileError,
    main,
    verify_local_operational_application_activation_readiness,
)
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
)


NOW = datetime(2026, 8, 10, 21, 0, tzinfo=UTC)
AUTHENTICATION = b'{"reviewed":"authentication"}'
POSTFLIGHT = b'{"reviewed":"postflight"}\n'
BOOTSTRAP = b'{"reviewed":"bootstrap"}'


def readiness_receipt() -> OperationalApplicationActivationReadinessReceipt:
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256=hashlib.sha256(POSTFLIGHT).hexdigest(),
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256="4" * 64,
        subject_sha256="5" * 64,
        bootstrap_id=UUID("18800000-0000-4000-8000-000000000001"),
        request_id=UUID("18800000-0000-4000-8000-000000000002"),
        user_id=UUID("18800000-0000-4000-8000-000000000003"),
        organisation_id=UUID("18800000-0000-4000-8000-000000000004"),
        membership_id=UUID("18800000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "18800000-0000-4000-8000-000000000006"
        ),
        checked_at=NOW,
    )


def input_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    authentication = tmp_path / "authentication.json"
    postflight = tmp_path / "postflight.json"
    bootstrap = tmp_path / "bootstrap.json"
    authentication.write_bytes(AUTHENTICATION)
    postflight.write_bytes(POSTFLIGHT)
    bootstrap.write_bytes(BOOTSTRAP)
    return authentication, postflight, bootstrap


class FactoryProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return object()


def invoke(tmp_path: Path, **changes):
    authentication, postflight, bootstrap = input_paths(tmp_path)
    values = {
        "authentication_document_path": authentication,
        "postflight_receipt_path": postflight,
        "bootstrap_document_path": bootstrap,
        "approved_postflight_receipt_sha256": hashlib.sha256(
            POSTFLIGHT
        ).hexdigest(),
        "session_factory": FactoryProbe(),
        "clock": lambda: NOW,
    }
    values.update(changes)
    return verify_local_operational_application_activation_readiness(**values)


def test_exact_local_documents_are_forwarded_after_digest_approval(
    monkeypatch,
    tmp_path,
):
    observed = []
    factory = FactoryProbe()

    def verify(**kwargs):
        observed.append(kwargs)
        return readiness_receipt()

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "verify_operational_application_activation_readiness",
        verify,
    )
    receipt = invoke(tmp_path, session_factory=factory)

    assert receipt == readiness_receipt()
    assert len(observed) == 1
    assert observed[0]["authentication_document"] == AUTHENTICATION
    assert observed[0]["postflight_receipt_document"] == POSTFLIGHT
    assert observed[0]["bootstrap_document"] == BOOTSTRAP
    assert observed[0]["approved_postflight_receipt_sha256"] == hashlib.sha256(
        POSTFLIGHT
    ).hexdigest()
    assert observed[0]["session_factory"] is factory
    assert observed[0]["clock"]() == NOW
    assert factory.calls == 0


def test_invalid_approval_precedes_every_file_and_database_access(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "_read_local_document",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="digest is invalid",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path="private-authentication",
            postflight_receipt_path="private-postflight",
            bootstrap_document_path="private-bootstrap",
            approved_postflight_receipt_sha256="INVALID",
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )
    assert calls == []


def test_postflight_mismatch_precedes_other_file_and_database_access(
    monkeypatch,
    tmp_path,
):
    authentication, postflight, bootstrap = input_paths(tmp_path)
    calls = []
    original = __import__(
        "app.security.security_application_activation_readiness_application",
        fromlist=["_read_local_document"],
    )._read_local_document

    def read(path, **kwargs):
        calls.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "_read_local_document",
        read,
    )
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="does not match approval",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256="f" * 64,
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )
    assert calls == [postflight]


def test_operational_session_factory_is_resolved_only_inside_verification(
    monkeypatch,
    tmp_path,
):
    resolution = []
    sessions = FactoryProbe()

    def resolve():
        resolution.append("resolved")
        return sessions

    def verify(**kwargs):
        assert resolution == []
        assert kwargs["session_factory"]() is not None
        return readiness_receipt()

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "_operational_session_factory",
        resolve,
    )
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "verify_operational_application_activation_readiness",
        verify,
    )
    invoke(tmp_path, session_factory=None)

    assert resolution == ["resolved"]
    assert sessions.calls == 1


@pytest.mark.parametrize(
    "factory,clock,message",
    [
        (object(), lambda: NOW, "session factory"),
        (FactoryProbe(), object(), "clock"),
    ],
)
def test_invalid_runtime_dependencies_fail_before_file_access(
    monkeypatch,
    factory,
    clock,
    message,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "_read_local_document",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(TypeError, match=message):
        verify_local_operational_application_activation_readiness(
            authentication_document_path="private-authentication",
            postflight_receipt_path="private-postflight",
            bootstrap_document_path="private-bootstrap",
            approved_postflight_receipt_sha256="a" * 64,
            session_factory=factory,
            clock=clock,
        )
    assert calls == []


@pytest.mark.parametrize("kind", ["authentication", "postflight", "bootstrap"])
def test_empty_input_files_are_rejected(monkeypatch, tmp_path, kind):
    del monkeypatch
    authentication, postflight, bootstrap = input_paths(tmp_path)
    paths = {
        "authentication": authentication,
        "postflight": postflight,
        "bootstrap": bootstrap,
    }
    paths[kind].write_bytes(b"")

    with pytest.raises(
        OperationalApplicationActivationReadinessFileError,
        match="is empty",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=hashlib.sha256(
                POSTFLIGHT
            ).hexdigest(),
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )


@pytest.mark.parametrize(
    "kind,maximum",
    [
        ("authentication", MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES),
        ("postflight", MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES),
        ("bootstrap", MAX_BOOTSTRAP_DOCUMENT_BYTES),
    ],
)
def test_oversized_input_files_are_rejected(tmp_path, kind, maximum):
    authentication, postflight, bootstrap = input_paths(tmp_path)
    paths = {
        "authentication": authentication,
        "postflight": postflight,
        "bootstrap": bootstrap,
    }
    paths[kind].write_bytes(b"x" * (maximum + 1))

    with pytest.raises(
        OperationalApplicationActivationReadinessFileError,
        match="exceeds the byte limit",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=hashlib.sha256(
                POSTFLIGHT
            ).hexdigest(),
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )


def test_nonregular_postflight_is_rejected(tmp_path):
    authentication, _, bootstrap = input_paths(tmp_path)
    postflight_directory = tmp_path / "postflight-directory"
    postflight_directory.mkdir()

    with pytest.raises(
        OperationalApplicationActivationReadinessFileError,
        match="regular non-symlink",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight_directory,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=hashlib.sha256(
                POSTFLIGHT
            ).hexdigest(),
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )


def test_symlink_postflight_is_rejected_when_supported(tmp_path):
    authentication, postflight, bootstrap = input_paths(tmp_path)
    link = tmp_path / "postflight-link"
    try:
        link.symlink_to(postflight)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(
        OperationalApplicationActivationReadinessFileError,
        match="regular non-symlink",
    ):
        verify_local_operational_application_activation_readiness(
            authentication_document_path=authentication,
            postflight_receipt_path=link,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=hashlib.sha256(
                POSTFLIGHT
            ).hexdigest(),
            session_factory=FactoryProbe(),
            clock=lambda: NOW,
        )


def test_cli_success_emits_one_canonical_privacy_minimised_line(
    monkeypatch,
    capsys,
):
    receipt = readiness_receipt()
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "verify_local_operational_application_activation_readiness",
        lambda **kwargs: receipt,
    )

    assert main([
        "private-authentication-path",
        "private-postflight-path",
        "private-bootstrap-path",
        "--approve-postflight-receipt-sha256",
        "a" * 64,
    ]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == (
        render_operational_application_activation_readiness(receipt) + "\n"
    )
    assert "private-" not in output.out


def test_cli_failure_is_sanitized_without_paths_or_values(monkeypatch, capsys):
    def fail(**kwargs):
        del kwargs
        raise RuntimeError("private-provider-value private-local-path")

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "verify_local_operational_application_activation_readiness",
        fail,
    )
    with pytest.raises(SystemExit) as captured:
        main([
            "private-authentication-path",
            "private-postflight-path",
            "private-bootstrap-path",
            "--approve-postflight-receipt-sha256",
            "a" * 64,
        ])
    output = capsys.readouterr()
    assert captured.value.code == 2
    assert output.out == ""
    assert output.err == "operational application activation readiness failed\n"
    assert "private" not in output.err


def test_local_readiness_application_does_not_mutate_exported_app(
    monkeypatch,
    tmp_path,
):
    before_routes = tuple(id(route) for route in app.routes)
    before_schema = app.openapi()
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness_application."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: readiness_receipt(),
    )

    invoke(tmp_path)

    assert tuple(id(route) for route in app.routes) == before_routes
    assert app.openapi() is before_schema
    assert not hasattr(app.state, "security_activation")
    assert not hasattr(app.state, "security_composition")
