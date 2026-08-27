"""Focused tests for the explicit local authentication-readiness preview."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

import app.security.authentication_readiness_preview as preview_module
from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)

from app.security.authentication_readiness_document import (
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
    AuthenticationReadinessDocumentError,
    load_authentication_readiness_document,
    render_authentication_readiness_preview,
)
from app.security.authentication_readiness_preview import (
    AuthenticationReadinessPreviewFileError,
    main,
    read_authentication_readiness_preview,
)


ISSUER = "https://identity.engineer4me.test/tenant"
AUDIENCE = "engineer4me-api"
JWKS_URL = "https://keys.engineer4me.test/.well-known/jwks.json"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def document() -> bytes:
    return json.dumps(
        {
            "document_type": "engineer4me_authentication_readiness",
            "schema_version": 1,
            "authentication": {
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "jwks_url": JWKS_URL,
                "algorithms": ["RS256"],
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_document(tmp_path: Path, content: bytes | None = None) -> Path:
    path = tmp_path / "authentication-readiness.json"
    path.write_bytes(document() if content is None else content)
    return path


def test_explicit_regular_file_matches_the_pure_bytes_contract(tmp_path):
    path = write_document(tmp_path)
    preview = read_authentication_readiness_preview(path)
    expected = load_authentication_readiness_document(document()).preview

    assert preview == expected
    assert preview.configuration_validated is True
    assert preview.jwks_reachability_checked is False
    assert preview.signed_token_checked is False
    assert preview.activation_ready is False


def test_rendered_file_preview_is_exact_canonical_public_json(tmp_path):
    preview = read_authentication_readiness_preview(write_document(tmp_path))
    rendered = render_authentication_readiness_preview(preview)
    parsed = json.loads(rendered)

    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["issuer"] == ISSUER
    assert parsed["audience"] == AUDIENCE
    assert parsed["jwks_url"] == JWKS_URL
    assert parsed["validation_scope"] == "local_configuration_only"
    assert parsed["activation_ready"] is False
    assert len(parsed["configuration_sha256"]) == 64


def test_command_line_prints_exactly_one_canonical_preview(tmp_path, capsys):
    path = write_document(tmp_path)
    assert main([str(path)]) == 0
    output = capsys.readouterr()

    assert output.err == ""
    assert output.out.count("\n") == 1
    assert output.out.rstrip("\n") == render_authentication_readiness_preview(
        read_authentication_readiness_preview(path)
    )


@pytest.mark.parametrize("value", [None, 7, b"readiness.json"])
def test_path_must_be_explicitly_path_like(value):
    with pytest.raises(TypeError, match="path-like"):
        read_authentication_readiness_preview(value)


def test_missing_path_is_rejected_without_path_or_cause_disclosure(tmp_path):
    path = tmp_path / "private-provider-name.json"
    with pytest.raises(AuthenticationReadinessPreviewFileError) as captured:
        read_authentication_readiness_preview(path)

    rendered = "".join(traceback.format_exception(captured.value))
    assert "private-provider-name" not in str(captured.value)
    assert "private-provider-name" not in rendered
    assert captured.value.__cause__ is None


def test_final_symlink_is_rejected_before_file_content_is_read(
    tmp_path, monkeypatch
):
    target = write_document(tmp_path)
    link = tmp_path / "readiness-link.json"
    create_or_emulate_file_symlink(
        link=link,
        target=target,
        monkeypatch=monkeypatch,
        module_os=preview_module.os,
    )

    with pytest.raises(
        AuthenticationReadinessPreviewFileError,
        match="regular non-symlink file",
    ):
        read_authentication_readiness_preview(link)


def test_directory_empty_and_oversized_inputs_are_rejected(tmp_path):
    with pytest.raises(
        AuthenticationReadinessPreviewFileError,
        match="regular non-symlink file",
    ):
        read_authentication_readiness_preview(tmp_path)

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(AuthenticationReadinessPreviewFileError, match="empty"):
        read_authentication_readiness_preview(empty)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES + 1))
    with pytest.raises(
        AuthenticationReadinessPreviewFileError,
        match="byte limit",
    ):
        read_authentication_readiness_preview(oversized)


def test_exact_maximum_size_is_accepted_when_json_is_valid(tmp_path):
    padding = MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES - len(document())
    path = write_document(tmp_path, document() + (b" " * padding))

    assert path.stat().st_size == MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES
    assert read_authentication_readiness_preview(path).audience == AUDIENCE


def test_invalid_document_error_remains_sanitized(tmp_path):
    sentinel = "private-client-secret-value"
    path = write_document(
        tmp_path,
        json.dumps({"client_secret": sentinel}).encode("utf-8"),
    )

    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        read_authentication_readiness_preview(path)
    rendered = "".join(traceback.format_exception(captured.value))

    assert sentinel not in str(captured.value)
    assert sentinel not in rendered
    assert str(path) not in rendered


def test_file_change_during_read_fails_closed(tmp_path, monkeypatch):
    path = write_document(tmp_path)
    original_read = os.read
    changed = False

    def changing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, min(size, 16))
        if chunk and not changed:
            changed = True
            with path.open("ab") as handle:
                handle.write(b" ")
        return chunk

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(
        AuthenticationReadinessPreviewFileError,
        match="changed while it was read",
    ):
        read_authentication_readiness_preview(path)


def test_descriptor_is_closed_when_document_validation_fails(tmp_path):
    path = write_document(tmp_path, b"{")
    descriptor: int | None = None
    original_open = os.open

    def recording_open(*args, **kwargs):
        nonlocal descriptor
        descriptor = original_open(*args, **kwargs)
        return descriptor

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "open", recording_open)
        with pytest.raises(AuthenticationReadinessDocumentError):
            read_authentication_readiness_preview(path)

    assert descriptor is not None
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_cli_failure_is_nonzero_and_discloses_no_path_or_document_value(
    tmp_path,
    capsys,
):
    sentinel = "private-value-step172"
    path = write_document(
        tmp_path,
        json.dumps({"password": sentinel}).encode("utf-8"),
    )

    with pytest.raises(SystemExit) as captured:
        main([str(path)])
    output = capsys.readouterr()

    assert captured.value.code == 2
    assert output.out == ""
    assert output.err == "authentication readiness preview failed\n"
    assert sentinel not in output.err
    assert str(path) not in output.err


def test_cli_requires_the_explicit_document_argument(capsys):
    with pytest.raises(SystemExit) as captured:
        main([])
    output = capsys.readouterr()

    assert captured.value.code == 2
    assert "document" in output.err


def test_read_and_render_use_no_environment_network_or_database_access(
    tmp_path,
    monkeypatch,
):
    path = write_document(tmp_path)

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("app.security.jwks_http_loader._default_open", forbidden)
    database_module = sys.modules.get("app.db.database")
    if database_module is not None:
        monkeypatch.setattr(database_module, "SessionLocal", forbidden)

    preview = read_authentication_readiness_preview(path)
    rendered = render_authentication_readiness_preview(preview)

    assert json.loads(rendered)["jwks_reachability_checked"] is False


def test_fresh_module_import_does_not_read_database_url_or_construct_engine():
    script = """
import os
import sys

original_getenv = os.getenv

def guarded_getenv(key, *args, **kwargs):
    if key == "DATABASE_URL":
        raise AssertionError("preview import read DATABASE_URL")
    return original_getenv(key, *args, **kwargs)

os.getenv = guarded_getenv
from app.security import authentication_readiness_preview
assert "app.db.database" not in sys.modules
assert authentication_readiness_preview.__name__.endswith("readiness_preview")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
