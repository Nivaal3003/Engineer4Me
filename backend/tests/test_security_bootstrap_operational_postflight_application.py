"""Tests for the controlled local operational postflight entry point."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

import app.security.security_bootstrap_operational_postflight_application as postflight_module
from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)

from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES,
    OperationalSecurityBootstrapPostflightDocumentError,
    OperationalSecurityBootstrapPostflightReceipt,
)
from app.security.security_bootstrap_operational_postflight_application import (
    OperationalSecurityBootstrapPostflightFileError,
    main,
    read_operational_security_bootstrap_execution_receipt,
    verify_local_operational_security_bootstrap_postflight,
)


NOW = datetime(2026, 8, 10, 15, 0, tzinfo=UTC)
EXECUTION_DOCUMENT = b'{"exact":"private-step181-receipt"}\n'
BOOTSTRAP_DOCUMENT = b'{"private":"reviewed-step183-bootstrap"}'
APPROVED_RECEIPT_SHA256 = hashlib.sha256(EXECUTION_DOCUMENT).hexdigest()
IDS = {
    "bootstrap_id": UUID("18300000-0000-4000-8000-000000000001"),
    "request_id": UUID("18300000-0000-4000-8000-000000000002"),
    "user_id": UUID("18300000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18300000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18300000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID(
        "18300000-0000-4000-8000-000000000006"
    ),
}


def postflight_receipt() -> OperationalSecurityBootstrapPostflightReceipt:
    return OperationalSecurityBootstrapPostflightReceipt(
        execution_receipt_sha256=APPROVED_RECEIPT_SHA256,
        preview_document_sha256="0" * 64,
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256="4" * 64,
        subject_sha256="5" * 64,
        execution_checked_at=NOW - timedelta(seconds=1),
        verification_checked_at=NOW,
        **IDS,
    )


def write_inputs(tmp_path):
    receipt_path = tmp_path / "private-step181-receipt.json"
    bootstrap_path = tmp_path / "private-step183-bootstrap.json"
    receipt_path.write_bytes(EXECUTION_DOCUMENT)
    bootstrap_path.write_bytes(BOOTSTRAP_DOCUMENT)
    return receipt_path, bootstrap_path


def test_exact_local_files_are_forwarded_to_explicit_read_only_boundary(
    tmp_path,
    monkeypatch,
):
    receipt_path, bootstrap_path = write_inputs(tmp_path)
    session_factory = lambda: object()
    calls = []

    def verify(**kwargs):
        calls.append(kwargs)
        return postflight_receipt()

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "verify_operational_security_bootstrap_postflight",
        verify,
    )
    receipt = verify_local_operational_security_bootstrap_postflight(
        execution_receipt_path=receipt_path,
        bootstrap_document_path=bootstrap_path,
        approved_execution_receipt_sha256=APPROVED_RECEIPT_SHA256,
        session_factory=session_factory,
        clock=lambda: NOW,
    )

    assert receipt == postflight_receipt()
    assert len(calls) == 1
    assert calls[0]["execution_receipt_document"] == EXECUTION_DOCUMENT
    assert calls[0]["bootstrap_document"] == BOOTSTRAP_DOCUMENT
    assert calls[0]["approved_execution_receipt_sha256"] == (
        APPROVED_RECEIPT_SHA256
    )
    assert calls[0]["session_factory"] is session_factory


@pytest.mark.parametrize("digest", ["invalid", "A" * 64, "0" * 63, None])
def test_digest_shape_fails_before_any_file_access(monkeypatch, digest):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("file access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "read_operational_security_bootstrap_execution_receipt",
        forbidden,
    )
    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        verify_local_operational_security_bootstrap_postflight(
            execution_receipt_path="private-receipt",
            bootstrap_document_path="private-bootstrap",
            approved_execution_receipt_sha256=digest,
            session_factory=lambda: None,
        )
    assert calls == []


def test_receipt_digest_mismatch_fails_before_bootstrap_or_session(
    tmp_path,
    monkeypatch,
):
    receipt_path, bootstrap_path = write_inputs(tmp_path)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("bootstrap or session access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "read_operational_security_bootstrap_document",
        forbidden,
    )
    with pytest.raises(
        OperationalSecurityBootstrapPostflightDocumentError,
        match="does not match approval",
    ):
        verify_local_operational_security_bootstrap_postflight(
            execution_receipt_path=receipt_path,
            bootstrap_document_path=bootstrap_path,
            approved_execution_receipt_sha256="f" * 64,
            session_factory=forbidden,
        )
    assert calls == []


@pytest.mark.parametrize(
    ("session_factory", "clock", "message"),
    [
        (object(), lambda: NOW, "session factory"),
        (lambda: None, object(), "clock"),
    ],
)
def test_invalid_collaborators_fail_before_file_access(
    monkeypatch,
    session_factory,
    clock,
    message,
):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("file access occurred")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "read_operational_security_bootstrap_execution_receipt",
        forbidden,
    )
    with pytest.raises(TypeError, match=message):
        verify_local_operational_security_bootstrap_postflight(
            execution_receipt_path="private-receipt",
            bootstrap_document_path="private-bootstrap",
            approved_execution_receipt_sha256="0" * 64,
            session_factory=session_factory,
            clock=clock,
        )
    assert calls == []


def test_receipt_reader_accepts_exact_limit_and_preserves_bytes(tmp_path):
    path = tmp_path / "receipt.json"
    document = b"x" * MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES
    path.write_bytes(document)
    assert read_operational_security_bootstrap_execution_receipt(path) == document


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (b"", "empty"),
        (
            b"x" * (MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES + 1),
            "byte limit",
        ),
    ],
)
def test_receipt_reader_rejects_empty_and_oversized_files(
    tmp_path,
    document,
    message,
):
    path = tmp_path / "receipt.json"
    path.write_bytes(document)
    with pytest.raises(OperationalSecurityBootstrapPostflightFileError, match=message):
        read_operational_security_bootstrap_execution_receipt(path)


def test_receipt_reader_rejects_directory_and_symlink(
    tmp_path, monkeypatch
):
    target = tmp_path / "private-target.json"
    target.write_bytes(EXECUTION_DOCUMENT)
    link = tmp_path / "private-link.json"
    create_or_emulate_file_symlink(
        link=link,
        target=target,
        monkeypatch=monkeypatch,
        module_os=postflight_module.os,
    )

    for path in (tmp_path, link):
        with pytest.raises(
            OperationalSecurityBootstrapPostflightFileError,
            match="regular non-symlink",
        ):
            read_operational_security_bootstrap_execution_receipt(path)


def test_receipt_reader_detects_metadata_change_during_read(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "receipt.json"
    path.write_bytes(EXECUTION_DOCUMENT)
    original_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor):
        nonlocal calls
        calls += 1
        value = original_fstat(descriptor)
        if calls == 1:
            return value
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "os.fstat",
        changed_fstat,
    )
    with pytest.raises(
        OperationalSecurityBootstrapPostflightFileError,
        match="changed while it was read",
    ):
        read_operational_security_bootstrap_execution_receipt(path)


def test_default_operational_session_factory_is_resolved_only_when_called(
    tmp_path,
    monkeypatch,
):
    receipt_path, bootstrap_path = write_inputs(tmp_path)
    session = object()
    calls = []

    def resolve_factory():
        calls.append("resolved")
        return lambda: session

    def verify(**kwargs):
        calls.append("verified")
        assert kwargs["session_factory"]() is session
        return postflight_receipt()

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "_operational_session_factory",
        resolve_factory,
    )
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "verify_operational_security_bootstrap_postflight",
        verify,
    )
    result = verify_local_operational_security_bootstrap_postflight(
        execution_receipt_path=receipt_path,
        bootstrap_document_path=bootstrap_path,
        approved_execution_receipt_sha256=APPROVED_RECEIPT_SHA256,
        clock=lambda: NOW,
    )

    assert result == postflight_receipt()
    assert calls == ["verified", "resolved"]


def test_default_factory_is_not_resolved_for_unapproved_receipt(
    tmp_path,
    monkeypatch,
):
    receipt_path, bootstrap_path = write_inputs(tmp_path)
    calls = []

    def forbidden():
        calls.append(True)
        raise AssertionError("operational session factory was resolved")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "_operational_session_factory",
        forbidden,
    )
    with pytest.raises(OperationalSecurityBootstrapPostflightDocumentError):
        verify_local_operational_security_bootstrap_postflight(
            execution_receipt_path=receipt_path,
            bootstrap_document_path=bootstrap_path,
            approved_execution_receipt_sha256="f" * 64,
            clock=lambda: NOW,
        )
    assert calls == []


def test_cli_success_prints_only_canonical_postflight_receipt(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "verify_local_operational_security_bootstrap_postflight",
        lambda **kwargs: postflight_receipt(),
    )
    result = main(
        [
            "private-receipt-path",
            "private-bootstrap-path",
            "--approve-execution-receipt-sha256",
            APPROVED_RECEIPT_SHA256,
        ]
    )
    output = capsys.readouterr()

    assert result == 0
    value = json.loads(output.out)
    assert value["bootstrap_verified"] is True
    assert value["activation_ready"] is False
    assert output.err == ""
    assert "private-receipt-path" not in output.out
    assert "private-bootstrap-path" not in output.out


def test_cli_failure_is_nonzero_and_does_not_disclose_private_detail(
    monkeypatch,
    capsys,
):
    def fail(**kwargs):
        del kwargs
        raise RuntimeError("private provider subject and database detail")

    monkeypatch.setattr(
        "app.security.security_bootstrap_operational_postflight_application."
        "verify_local_operational_security_bootstrap_postflight",
        fail,
    )
    with pytest.raises(SystemExit) as captured:
        main(
            [
                "private-receipt-path",
                "private-bootstrap-path",
                "--approve-execution-receipt-sha256",
                APPROVED_RECEIPT_SHA256,
            ]
        )
    output = capsys.readouterr()

    assert captured.value.code == 2
    assert output.out == ""
    assert output.err == "operational security bootstrap postflight failed\n"
    assert "private" not in output.err


def test_receipt_reader_requires_a_path_like_value():
    with pytest.raises(TypeError, match="path is invalid"):
        read_operational_security_bootstrap_execution_receipt(object())
