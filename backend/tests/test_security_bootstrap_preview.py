"""Focused tests for explicit local bootstrap preview file handling."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

import app.security.bootstrap_preview as bootstrap_preview_module
from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)

from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES, SecurityBootstrapDocumentError
from app.security.bootstrap_preview import SecurityBootstrapPreviewFileError, main, read_security_bootstrap_preview, render_security_bootstrap_preview


NOW = datetime(2026, 8, 9, 4, 0, tzinfo=UTC)


def document():
    organisation_id = uuid4()
    return json.dumps(
        {
            "bootstrap_id": str(uuid4()),
            "request_id": str(uuid4()),
            "user_id": str(uuid4()),
            "organisation_id": str(organisation_id),
            "membership_id": str(uuid4()),
            "email": "owner@example.com",
            "display_name": "Initial Owner",
            "issuer": "https://identity.engineer4me.test",
            "subject": "private-provider-subject-152",
            "organisation_slug": "initial-organisation",
            "organisation_name": "Initial Organisation",
            "initial_role": "owner",
            "activated_at": NOW.isoformat(),
            "entitlement": {
                "snapshot_id": str(uuid4()),
                "organisation_id": str(organisation_id),
                "plan_id": "reviewed-plan-152",
                "subscription_status": "trial",
                "features": ["engineering_calculations", "document_ingestion"],
                "quotas": [{"kind": "monthly_calculation_runs", "limit": 100}],
                "effective_at": (NOW - timedelta(minutes=1)).isoformat(),
                "expires_at": (NOW + timedelta(days=30)).isoformat(),
                "source_reference": "approved bootstrap request 152",
            },
        }
    ).encode("utf-8")


def write_document(tmp_path: Path) -> Path:
    path = tmp_path / "bootstrap.json"
    path.write_bytes(document())
    return path


def test_explicit_regular_file_produces_the_validated_preview(tmp_path):
    preview = read_security_bootstrap_preview(write_document(tmp_path))
    assert preview.entitlement_plan == "reviewed-plan-152"
    assert len(preview.document_sha256) == 64


def test_rendered_preview_is_canonical_and_excludes_private_identity_fields(tmp_path):
    rendered = render_security_bootstrap_preview(read_security_bootstrap_preview(write_document(tmp_path)))
    assert rendered == json.dumps(json.loads(rendered), sort_keys=True, separators=(",", ":"))
    assert set(json.loads(rendered)) == {
        "bootstrap_id", "document_sha256", "entitlement_plan", "entitlement_snapshot_id", "features", "initial_role",
        "membership_id", "organisation_id", "quota_kinds", "request_id", "subscription_status", "user_id",
    }
    for forbidden in ("owner@example.com", "Initial Owner", "private-provider-subject-152", "identity.engineer4me.test", "initial-organisation", "source_reference"):
        assert forbidden not in rendered


def test_command_line_prints_exactly_one_preview_json_document(tmp_path, capsys):
    path = write_document(tmp_path)
    assert main([str(path)]) == 0
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    assert json.loads(output)["entitlement_plan"] == "reviewed-plan-152"


@pytest.mark.parametrize("value", [None, 1, b"bootstrap.json"])
def test_path_must_be_explicitly_path_like(value):
    with pytest.raises(TypeError, match="path-like"):
        read_security_bootstrap_preview(value)


def test_missing_file_is_rejected_without_disclosing_the_path(tmp_path):
    private_path = tmp_path / "private-name.json"
    with pytest.raises(SecurityBootstrapPreviewFileError) as captured:
        read_security_bootstrap_preview(private_path)
    assert "private-name" not in str(captured.value)


def test_final_symlink_is_not_followed(tmp_path, monkeypatch):
    target = write_document(tmp_path)
    link = tmp_path / "bootstrap-link.json"
    create_or_emulate_file_symlink(
        link=link,
        target=target,
        monkeypatch=monkeypatch,
        module_os=bootstrap_preview_module.os,
    )
    with pytest.raises(SecurityBootstrapPreviewFileError, match="opened safely"):
        read_security_bootstrap_preview(link)


def test_directory_and_empty_file_are_rejected(tmp_path):
    with pytest.raises(SecurityBootstrapPreviewFileError, match="regular file"):
        read_security_bootstrap_preview(tmp_path)
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(SecurityBootstrapPreviewFileError, match="empty"):
        read_security_bootstrap_preview(empty)


def test_oversized_file_is_rejected_before_document_validation(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1))
    with pytest.raises(SecurityBootstrapPreviewFileError, match="byte limit"):
        read_security_bootstrap_preview(path)


def test_invalid_json_contract_propagates_only_the_sanitized_document_error(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(b'{"password":"private-value"}')
    with pytest.raises(SecurityBootstrapDocumentError, match="contract validation") as captured:
        read_security_bootstrap_preview(path)
    assert "private-value" not in str(captured.value)


def test_renderer_requires_a_validated_preview_object():
    with pytest.raises(TypeError, match="preview is required"):
        render_security_bootstrap_preview({})


def test_preview_uses_no_environment_network_or_database_access(tmp_path, monkeypatch):
    path = write_document(tmp_path)

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    monkeypatch.setattr(os, "getenv", forbidden)
    preview = read_security_bootstrap_preview(path)
    assert preview.initial_role.value == "owner"


def test_command_line_requires_the_explicit_document_argument():
    with pytest.raises(SystemExit) as captured:
        main([])
    assert captured.value.code == 2
