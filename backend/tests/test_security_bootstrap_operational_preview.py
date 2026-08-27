"""Focused tests for the controlled local operational bootstrap preview."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import jwt
import pytest

import app.security.security_bootstrap_operational_preview as operational_preview_module
from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.authentication_bootstrap_readiness import (
    AuthenticationBootstrapReadinessError,
)
from app.security.authentication_readiness_preview import (
    read_authentication_readiness_preview,
)
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessError,
)
from app.security.bootstrap_document import (
    MAX_BOOTSTRAP_DOCUMENT_BYTES,
    SecurityBootstrapDocumentError,
    load_security_bootstrap_document,
)
from app.security.jwks_http_loader import _default_open
from app.security.security_bootstrap_operational_preview import (
    OPERATIONAL_BOOTSTRAP_PREVIEW_SCOPE,
    OperationalSecurityBootstrapPreviewFileError,
    main,
    preview_operational_security_bootstrap,
    read_operational_security_bootstrap_document,
    render_operational_security_bootstrap_preview,
)
from app.services.security_bootstrap_operational import (
    OPERATIONAL_SCHEMA,
    PHASE8_SECURITY_HEAD,
)
from app.services.security_bootstrap_operational_application import (
    OperationalSecurityBootstrapApprovalError,
    OperationalSecurityBootstrapReadinessError,
)


ISSUER = "https://identity.engineer4me.test/tenant"
AUDIENCE = "engineer4me-api"
JWKS_URL = "https://keys.engineer4me.test/.well-known/jwks.json"
KEY_ID = "private-provider-key-step179"
SUBJECT = "private-provider-owner-subject-step179"
TOKEN_ID = "private-provider-jti-step179"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
IDS = {
    "bootstrap_id": UUID("17900000-0000-4000-8000-000000000001"),
    "request_id": UUID("17900000-0000-4000-8000-000000000002"),
    "user_id": UUID("17900000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("17900000-0000-4000-8000-000000000004"),
    "membership_id": UUID("17900000-0000-4000-8000-000000000005"),
    "snapshot_id": UUID("17900000-0000-4000-8000-000000000006"),
}


def readiness_document() -> bytes:
    return json.dumps(
        {
            "document_type": "engineer4me_authentication_readiness",
            "schema_version": 1,
            "authentication": {
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "jwks_url": JWKS_URL,
                "algorithms": ["RS256"],
                "clock_skew_seconds": 0,
                "jwks_timeout_seconds": 3.0,
                "jwks_maximum_response_bytes": 65_536,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def bootstrap_document(
    *,
    now: datetime,
    subject: str = SUBJECT,
    activated_at: datetime | None = None,
) -> bytes:
    activated = activated_at or now - timedelta(seconds=10)
    value = {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": "private-owner@example.com",
        "display_name": "Private Initial Owner",
        "issuer": ISSUER,
        "subject": subject,
        "organisation_slug": "reviewed-organisation-step179",
        "organisation_name": "Reviewed Organisation Step 179",
        "initial_role": "owner",
        "activated_at": activated.isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step179",
            "subscription_status": "trial",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [
                {"kind": "monthly_calculation_runs", "limit": 100},
                {"kind": "monthly_document_ingestions", "limit": 25},
            ],
            "effective_at": (activated - timedelta(seconds=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "source_reference": "private reviewed source step179",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_jwks() -> dict:
    key = jwt.algorithms.RSAAlgorithm.to_jwk(
        PRIVATE_KEY.public_key(),
        as_dict=True,
    )
    key.update(kid=KEY_ID, alg="RS256", use="sig")
    return {"keys": [key]}


def jwks_digest(document: dict) -> str:
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compact_token(*, subject: str = SUBJECT, key=PRIVATE_KEY) -> str:
    now = datetime.now(UTC).replace(microsecond=0)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "jti": TOKEN_ID,
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        key,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.status = 200
        self.headers = {
            "Content-Type": "application/jwk-set+json",
            "Content-Length": str(len(body)),
        }

    def geturl(self) -> str:
        return JWKS_URL

    def read(self, amount: int = -1) -> bytes:
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        del args
        return None


def fake_open_url(calls: list):
    body = json.dumps(public_jwks(), sort_keys=True, separators=(",", ":")).encode()

    def open_url(request, timeout):
        calls.append((request, timeout))
        return FakeResponse(body)

    return open_url


def write_inputs(
    tmp_path: Path,
    *,
    subject: str = SUBJECT,
    token: str | None = None,
    activated_at: datetime | None = None,
):
    now = datetime.now(UTC).replace(microsecond=0)
    authentication_path = tmp_path / "authentication.json"
    token_path = tmp_path / "token.jwt"
    bootstrap_path = tmp_path / "bootstrap.json"
    authentication_path.write_bytes(readiness_document())
    token_path.write_bytes((token or compact_token()).encode("ascii"))
    bootstrap_path.write_bytes(
        bootstrap_document(now=now, subject=subject, activated_at=activated_at)
    )
    configuration_digest = read_authentication_readiness_preview(
        authentication_path
    ).configuration_sha256
    bootstrap_digest = load_security_bootstrap_document(
        bootstrap_path.read_bytes()
    ).preview.document_sha256
    return (
        now,
        authentication_path,
        token_path,
        bootstrap_path,
        configuration_digest,
        jwks_digest(public_jwks()),
        bootstrap_digest,
    )


def run_preview(tmp_path: Path, **changes):
    values = write_inputs(tmp_path, **changes)
    (
        now,
        authentication_path,
        token_path,
        bootstrap_path,
        configuration_digest,
        approved_jwks,
        bootstrap_digest,
    ) = values
    calls = []
    receipt = preview_operational_security_bootstrap(
        authentication_document_path=authentication_path,
        token_path=token_path,
        bootstrap_document_path=bootstrap_path,
        approved_configuration_sha256=configuration_digest,
        approved_jwks_document_sha256=approved_jwks,
        approved_bootstrap_document_sha256=bootstrap_digest,
        open_url=fake_open_url(calls),
        clock=lambda: now,
    )
    return receipt, calls, values


def test_exact_local_inputs_and_approvals_produce_pre_execution_receipt(tmp_path):
    receipt, calls, _ = run_preview(tmp_path)

    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == JWKS_URL
    assert request.get_method() == "GET"
    assert timeout == 3.0
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.organisation_id == IDS["organisation_id"]
    assert receipt.initial_role.value == "owner"
    assert receipt.entitlement_plan == "reviewed-plan-step179"
    assert receipt.token_algorithm == "RS256"
    assert receipt.expected_operational_schema == OPERATIONAL_SCHEMA
    assert receipt.expected_migration_revision == PHASE8_SECURITY_HEAD


def test_preview_never_invokes_operational_executor(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("operational executor was invoked by preview")

    monkeypatch.setattr(
        "app.services.security_bootstrap_operational.OperationalSecurityBootstrapExecutor.execute",
        forbidden,
    )
    receipt, _, _ = run_preview(tmp_path)
    assert receipt.bootstrap_id == IDS["bootstrap_id"]


def test_rendered_preview_is_canonical_private_and_explicitly_not_execution_ready(
    tmp_path,
):
    private_token = compact_token()
    receipt, _, _ = run_preview(tmp_path, token=private_token)
    rendered = render_operational_security_bootstrap_preview(receipt)
    parsed = json.loads(rendered)

    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["validation_scope"] == OPERATIONAL_BOOTSTRAP_PREVIEW_SCOPE
    assert parsed["configuration_digest_approved"] is True
    assert parsed["jwks_document_digest_approved"] is True
    assert parsed["bootstrap_document_digest_approved"] is True
    assert parsed["signed_token_checked"] is True
    assert parsed["identity_binding_checked"] is True
    assert parsed["freshness_checked"] is True
    assert parsed["entitlement_usable_at_preview"] is True
    assert parsed["database_accessed"] is False
    assert parsed["operational_schema_checked"] is False
    assert parsed["migration_revision_checked"] is False
    assert parsed["operational_empty_domain_rechecked"] is False
    assert parsed["bootstrap_execution_ready"] is False
    assert parsed["activation_ready"] is False
    for forbidden in (
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        KEY_ID,
        SUBJECT,
        TOKEN_ID,
        private_token,
        "private-owner@example.com",
        "Private Initial Owner",
        "private reviewed source step179",
        "Reviewed Organisation Step 179",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "which",
    ["configuration", "jwks", "bootstrap"],
)
@pytest.mark.parametrize("value", [None, "", "0" * 63, "A" * 64])
def test_malformed_approval_fails_before_file_or_network(which, value, monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected file or network access")

    monkeypatch.setattr(os, "lstat", forbidden)
    arguments = {
        "authentication_document_path": "not-opened-auth.json",
        "token_path": "not-opened-token.jwt",
        "bootstrap_document_path": "not-opened-bootstrap.json",
        "approved_configuration_sha256": "1" * 64,
        "approved_jwks_document_sha256": "2" * 64,
        "approved_bootstrap_document_sha256": "3" * 64,
        "open_url": forbidden,
    }
    arguments[
        {
            "configuration": "approved_configuration_sha256",
            "jwks": "approved_jwks_document_sha256",
            "bootstrap": "approved_bootstrap_document_sha256",
        }[which]
    ] = value
    with pytest.raises(OperationalSecurityBootstrapApprovalError, match="invalid"):
        preview_operational_security_bootstrap(**arguments)


def test_stale_bootstrap_digest_fails_before_authentication_or_network(tmp_path):
    values = write_inputs(tmp_path)
    _, authentication_path, token_path, bootstrap_path, config, jwks, _ = values
    calls = []
    with pytest.raises(
        OperationalSecurityBootstrapApprovalError, match="does not match"
    ):
        preview_operational_security_bootstrap(
            authentication_document_path=authentication_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_path,
            approved_configuration_sha256=config,
            approved_jwks_document_sha256=jwks,
            approved_bootstrap_document_sha256="0" * 64,
            open_url=fake_open_url(calls),
        )
    assert calls == []


def test_signed_token_identity_must_match_bootstrap_subject(tmp_path):
    values = write_inputs(tmp_path, subject="private-different-subject-step179")
    now, authentication_path, token_path, bootstrap_path, config, jwks, bootstrap = (
        values
    )
    with pytest.raises(
        AuthenticationBootstrapReadinessError,
        match="subject does not match",
    ):
        preview_operational_security_bootstrap(
            authentication_document_path=authentication_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_path,
            approved_configuration_sha256=config,
            approved_jwks_document_sha256=jwks,
            approved_bootstrap_document_sha256=bootstrap,
            open_url=fake_open_url([]),
            clock=lambda: now,
        )


def test_invalid_signed_token_fails_without_database_or_private_detail(tmp_path):
    wrong_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    private_token = compact_token(key=wrong_key)
    values = write_inputs(tmp_path, token=private_token)
    _, authentication_path, token_path, bootstrap_path, config, jwks, bootstrap = values
    with pytest.raises(AuthenticationTokenReadinessError) as captured:
        preview_operational_security_bootstrap(
            authentication_document_path=authentication_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_path,
            approved_configuration_sha256=config,
            approved_jwks_document_sha256=jwks,
            approved_bootstrap_document_sha256=bootstrap,
            open_url=fake_open_url([]),
        )
    assert private_token not in str(captured.value)


def test_stale_bootstrap_document_fails_freshness_without_database(tmp_path):
    now = datetime.now(UTC).replace(microsecond=0)
    values = write_inputs(tmp_path, activated_at=now - timedelta(minutes=16))
    _, authentication_path, token_path, bootstrap_path, config, jwks, bootstrap = values
    with pytest.raises(
        OperationalSecurityBootstrapReadinessError,
        match="outside the execution window",
    ):
        preview_operational_security_bootstrap(
            authentication_document_path=authentication_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_path,
            approved_configuration_sha256=config,
            approved_jwks_document_sha256=jwks,
            approved_bootstrap_document_sha256=bootstrap,
            open_url=fake_open_url([]),
            clock=lambda: now,
        )


@pytest.mark.parametrize("content", [b"", b"[]", b"{", b"\xff"])
def test_invalid_bootstrap_file_content_fails_sanitarily(tmp_path, content):
    values = write_inputs(tmp_path)
    _, authentication_path, token_path, bootstrap_path, config, jwks, _ = values
    bootstrap_path.write_bytes(content)
    error = (
        OperationalSecurityBootstrapPreviewFileError
        if not content
        else SecurityBootstrapDocumentError
    )
    with pytest.raises(error):
        preview_operational_security_bootstrap(
            authentication_document_path=authentication_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_path,
            approved_configuration_sha256=config,
            approved_jwks_document_sha256=jwks,
            approved_bootstrap_document_sha256="3" * 64,
            open_url=fake_open_url([]),
        )


def test_bootstrap_file_symlink_directory_and_oversize_are_rejected(
    tmp_path, monkeypatch
):
    now = datetime.now(UTC).replace(microsecond=0)
    source = tmp_path / "source.json"
    source.write_bytes(bootstrap_document(now=now))
    link = tmp_path / "linked.json"
    create_or_emulate_file_symlink(
        link=link,
        target=source,
        monkeypatch=monkeypatch,
        module_os=operational_preview_module.os,
    )
    for value in (link, tmp_path):
        with pytest.raises(
            OperationalSecurityBootstrapPreviewFileError,
            match="regular non-symlink",
        ):
            read_operational_security_bootstrap_document(value)
    source.write_bytes(b"a" * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1))
    with pytest.raises(
        OperationalSecurityBootstrapPreviewFileError,
        match="byte limit",
    ):
        read_operational_security_bootstrap_document(source)


def test_bootstrap_file_metadata_change_during_read_is_rejected(tmp_path, monkeypatch):
    now = datetime.now(UTC).replace(microsecond=0)
    path = tmp_path / "bootstrap.json"
    path.write_bytes(bootstrap_document(now=now))
    real_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor):
        nonlocal calls
        result = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = list(result)
            values[8] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "fstat", changed_fstat)
    with pytest.raises(
        OperationalSecurityBootstrapPreviewFileError,
        match="changed while",
    ):
        read_operational_security_bootstrap_document(path)


def test_command_line_prints_one_sanitized_preview(tmp_path, monkeypatch, capsys):
    values = write_inputs(tmp_path)
    _, authentication_path, token_path, bootstrap_path, config, jwks, bootstrap = values
    monkeypatch.setattr(
        "app.security.jwks_http_loader._default_open",
        fake_open_url([]),
    )
    assert (
        main(
            [
                str(authentication_path),
                str(token_path),
                str(bootstrap_path),
                "--approve-configuration-sha256",
                config,
                "--approve-jwks-sha256",
                jwks,
                "--approve-bootstrap-sha256",
                bootstrap,
            ]
        )
        == 0
    )
    output = capsys.readouterr().out.strip()
    assert len(output.splitlines()) == 1
    assert json.loads(output)["bootstrap_execution_ready"] is False


def test_command_line_failure_is_generic_and_discloses_no_path(tmp_path, capsys):
    private_path = tmp_path / "private-owner-bootstrap.json"
    with pytest.raises(SystemExit) as captured:
        main(
            [
                "missing-auth.json",
                "missing-token.jwt",
                str(private_path),
                "--approve-configuration-sha256",
                "1" * 64,
                "--approve-jwks-sha256",
                "2" * 64,
                "--approve-bootstrap-sha256",
                "3" * 64,
            ]
        )
    assert captured.value.code == 2
    error = capsys.readouterr().err
    assert error == "operational security bootstrap preview failed\n"
    assert str(private_path) not in error


def test_receipt_is_frozen_and_rejects_forged_execution_claims(tmp_path):
    receipt, _, _ = run_preview(tmp_path)
    with pytest.raises(FrozenInstanceError):
        receipt.expected_operational_schema = "private"
    for changes in (
        {"configuration_sha256": "A" * 64},
        {"bootstrap_id": receipt.request_id},
        {"initial_role": "owner"},
        {"expected_operational_schema": "private"},
        {"expected_migration_revision": "unknown"},
        {"token_checked_at": receipt.execution_checked_at - timedelta(minutes=6)},
        {"execution_checked_at": datetime(2026, 8, 9)},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)
    with pytest.raises(TypeError, match="preview receipt is required"):
        render_operational_security_bootstrap_preview({})


def test_default_transport_symbol_remains_unmodified():
    assert callable(_default_open)
