"""Focused tests for digest-confirmed operational bootstrap preview approval."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.security.security_bootstrap_operational_approval import (
    MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES,
    OPERATIONAL_BOOTSTRAP_APPROVAL_SCOPE,
    OperationalSecurityBootstrapPreviewApprovalError,
    OperationalSecurityBootstrapPreviewApprovalFileError,
    approve_local_operational_security_bootstrap_preview,
    approve_operational_security_bootstrap_preview,
    main,
    read_operational_security_bootstrap_preview_document,
    render_operational_security_bootstrap_preview_approval,
)
from app.security.security_bootstrap_operational_preview import (
    OperationalSecurityBootstrapPreviewReceipt,
    render_operational_security_bootstrap_preview,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)


HASHES = {
    "configuration_sha256": "1" * 64,
    "jwks_document_sha256": "2" * 64,
    "bootstrap_document_sha256": "3" * 64,
    "issuer_sha256": "4" * 64,
    "subject_sha256": "5" * 64,
}
IDS = {
    "bootstrap_id": UUID("18000000-0000-4000-8000-000000000001"),
    "request_id": UUID("18000000-0000-4000-8000-000000000002"),
    "user_id": UUID("18000000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18000000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18000000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID("18000000-0000-4000-8000-000000000006"),
}


def preview_receipt(
    *, checked_at: datetime
) -> OperationalSecurityBootstrapPreviewReceipt:
    return OperationalSecurityBootstrapPreviewReceipt(
        **HASHES,
        token_checked_at=checked_at - timedelta(seconds=10),
        execution_checked_at=checked_at,
        token_algorithm="RS256",
        **IDS,
        initial_role=OrganisationRole.OWNER,
        entitlement_plan="reviewed-plan-step180",
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


def preview_document(*, checked_at: datetime, newline: bytes = b"") -> bytes:
    return (
        render_operational_security_bootstrap_preview(
            preview_receipt(checked_at=checked_at)
        ).encode("utf-8")
        + newline
    )


def approve(document: bytes, *, now: datetime):
    return approve_operational_security_bootstrap_preview(
        preview_document=document,
        approved_preview_document_sha256=hashlib.sha256(document).hexdigest(),
        clock=lambda: now,
    )


def test_exact_digest_approves_recent_canonical_preview_without_execution():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now - timedelta(seconds=20))

    receipt = approve(document, now=now)

    assert receipt.preview_document_sha256 == hashlib.sha256(document).hexdigest()
    assert receipt.configuration_sha256 == HASHES["configuration_sha256"]
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.token_algorithm == "RS256"
    assert receipt.initial_role is OrganisationRole.OWNER
    assert receipt.entitlement_plan == "reviewed-plan-step180"
    assert receipt.features == (
        ControlledFeature.ENGINEERING_CALCULATIONS,
        ControlledFeature.DOCUMENT_INGESTION,
    )
    assert receipt.expected_operational_schema == OPERATIONAL_SCHEMA
    assert receipt.expected_migration_revision == PHASE8_SECURITY_HEAD


def test_rendered_approval_is_canonical_private_and_explicitly_non_executing():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now - timedelta(seconds=20))
    rendered = render_operational_security_bootstrap_preview_approval(
        approve(document, now=now)
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["validation_scope"] == OPERATIONAL_BOOTSTRAP_APPROVAL_SCOPE
    assert value["preview_digest_approved"] is True
    assert value["database_accessed"] is False
    assert value["operational_schema_checked"] is False
    assert value["migration_revision_checked"] is False
    assert value["operational_empty_domain_rechecked"] is False
    assert value["bootstrap_execution_ready"] is False
    assert value["activation_ready"] is False


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_one_terminal_newline_is_canonical_but_remains_digest_bound(newline):
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now, newline=newline)
    receipt = approve(document, now=now)
    assert receipt.preview_document_sha256 == hashlib.sha256(document).hexdigest()

    without_newline = document[: -len(newline)]
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="does not match approval",
    ):
        approve_operational_security_bootstrap_preview(
            preview_document=without_newline,
            approved_preview_document_sha256=hashlib.sha256(document).hexdigest(),
            clock=lambda: now,
        )


def test_malformed_approval_is_rejected_before_file_or_clock_access(tmp_path):
    calls = []
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="digest is invalid",
    ):
        approve_local_operational_security_bootstrap_preview(
            preview_document_path=tmp_path / "missing-private-preview.json",
            approved_preview_document_sha256="ABC",
            clock=lambda: calls.append(True),
        )
    assert calls == []


def test_digest_mismatch_is_rejected_before_json_or_clock_processing():
    calls = []
    private = b"private malformed preview content"
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="does not match approval",
    ) as caught:
        approve_operational_security_bootstrap_preview(
            preview_document=private,
            approved_preview_document_sha256="0" * 64,
            clock=lambda: calls.append(True),
        )
    assert calls == []
    assert private.decode() not in str(caught.value)


@pytest.mark.parametrize(
    "replacement",
    [
        {"activation_ready": True},
        {"bootstrap_execution_ready": True},
        {"database_accessed": True},
        {"operational_schema_checked": True},
        {"migration_revision_checked": True},
        {"operational_empty_domain_rechecked": True},
        {"provider_ownership_checked": True},
        {"expected_operational_schema": "private"},
        {"unknown": "private-value"},
    ],
)
def test_changed_or_extended_preview_contract_is_rejected(replacement):
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    value = json.loads(preview_document(checked_at=now))
    value.update(replacement)
    document = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(OperationalSecurityBootstrapPreviewApprovalError):
        approve(document, now=now)


def test_changed_evidence_hash_is_rejected_by_the_original_preview_approval():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    original = preview_document(checked_at=now)
    original_approval = hashlib.sha256(original).hexdigest()
    value = json.loads(original)
    value["configuration_sha256"] = "a" * 64
    changed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="does not match approval",
    ):
        approve_operational_security_bootstrap_preview(
            preview_document=changed,
            approved_preview_document_sha256=original_approval,
            clock=lambda: now,
        )


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"not-json",
        b"[]",
        b'\xff',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1,"x":2}',
        b"{}\n{}",
        b" {}",
    ],
)
def test_malformed_documents_fail_through_sanitized_boundary(document):
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    with pytest.raises(OperationalSecurityBootstrapPreviewApprovalError):
        approve(document, now=now)


@pytest.mark.parametrize("age", [301, 3_600])
def test_stale_preview_is_rejected(age):
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now - timedelta(seconds=age))
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="outside the approval window",
    ):
        approve(document, now=now)


def test_excessively_future_preview_and_invalid_clock_are_rejected():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now + timedelta(seconds=31))
    with pytest.raises(OperationalSecurityBootstrapPreviewApprovalError):
        approve(document, now=now)

    valid = preview_document(checked_at=now)
    digest = hashlib.sha256(valid).hexdigest()
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalError,
        match="time is invalid",
    ):
        approve_operational_security_bootstrap_preview(
            preview_document=valid,
            approved_preview_document_sha256=digest,
            clock=lambda: datetime(2026, 8, 10, 8, 0),
        )


def test_approval_receipt_is_frozen_and_rejects_forged_state():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    receipt = approve(preview_document(checked_at=now), now=now)
    with pytest.raises(FrozenInstanceError):
        receipt.bootstrap_id = UUID(int=0)
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(receipt, expected_operational_schema="private")
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(
            receipt,
            approval_checked_at=receipt.preview_checked_at + timedelta(seconds=301),
        )


def test_local_reader_requires_regular_non_symlink_bounded_stable_file(
    tmp_path, monkeypatch
):
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    directory = tmp_path / "directory"
    directory.mkdir()
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_OPERATIONAL_BOOTSTRAP_PREVIEW_BYTES + 1))
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    symlink = tmp_path / "link.json"
    try:
        symlink.symlink_to(target)
    except OSError:
        symlink = None

    paths = [empty, directory, oversized]
    if symlink is not None:
        paths.append(symlink)
    for path in paths:
        with pytest.raises(OperationalSecurityBootstrapPreviewApprovalFileError):
            read_operational_security_bootstrap_preview_document(path)

    original = os.fstat
    calls = 0

    def changing(descriptor):
        nonlocal calls
        result = original(descriptor)
        calls += 1
        if calls == 2:
            values = list(result)
            values[8] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "fstat", changing)
    with pytest.raises(
        OperationalSecurityBootstrapPreviewApprovalFileError,
        match="changed while",
    ):
        read_operational_security_bootstrap_preview_document(target)


def test_local_approval_reads_only_explicit_file_and_performs_no_database_work(
    tmp_path, monkeypatch
):
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now, newline=b"\n")
    path = tmp_path / "reviewed-preview.json"
    path.write_bytes(document)

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("database or bootstrap execution was attempted")

    monkeypatch.setattr(
        "app.services.security_bootstrap_operational."
        "OperationalSecurityBootstrapExecutor.execute",
        forbidden,
    )
    receipt = approve_local_operational_security_bootstrap_preview(
        preview_document_path=path,
        approved_preview_document_sha256=hashlib.sha256(document).hexdigest(),
        clock=lambda: now,
    )
    assert receipt.bootstrap_id == IDS["bootstrap_id"]


def test_private_values_are_absent_from_approval_output():
    now = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)
    document = preview_document(checked_at=now)
    output = render_operational_security_bootstrap_preview_approval(
        approve(document, now=now)
    )
    for private in (
        "private-provider-owner-subject",
        "private-owner@example.com",
        "private-token",
        "private-key",
        "source-reference",
    ):
        assert private not in output


def test_cli_renders_one_line_and_failure_is_generic(tmp_path, monkeypatch, capsys):
    now = datetime.now(UTC).replace(microsecond=0)
    document = preview_document(checked_at=now, newline=b"\n")
    path = tmp_path / "reviewed-preview.json"
    path.write_bytes(document)
    digest = hashlib.sha256(document).hexdigest()

    assert main([str(path), "--approve-preview-sha256", digest]) == 0
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    assert json.loads(output)["preview_digest_approved"] is True

    private_path = tmp_path / "private-secret-preview-name.json"
    with pytest.raises(SystemExit) as caught:
        main([str(private_path), "--approve-preview-sha256", "0" * 64])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "operational security bootstrap preview approval failed\n"
    assert "private-secret" not in captured.err
