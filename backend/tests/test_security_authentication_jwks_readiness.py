"""Focused tests for digest-confirmed bounded JWKS readiness probing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from urllib.error import URLError

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.authentication_jwks_readiness import (
    AUTHENTICATION_JWKS_READINESS_SCOPE,
    AuthenticationJWKSReadinessApprovalError,
    AuthenticationJWKSReadinessError,
    authentication_deployment_from_preview,
    main,
    probe_authentication_jwks_readiness,
    render_authentication_jwks_readiness_receipt,
)
from app.security.authentication_readiness_preview import (
    read_authentication_readiness_preview,
)


ISSUER = "https://identity.engineer4me.test/tenant"
AUDIENCE = "engineer4me-api"
JWKS_URL = "https://keys.engineer4me.test/.well-known/jwks.json"
KEY_ID = "provider-private-key-id-step173"
ENTRA_TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
ENTRA_API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
ENTRA_CALLING_CLIENT_APPLICATION_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
ENTRA_ISSUER = f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0"
ENTRA_REQUIRED_DELEGATED_SCOPE = "access_as_user"
ENTRA_REQUIRED_AZPACR = "0"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def readiness_document(*, algorithms: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "document_type": "engineer4me_authentication_readiness",
            "schema_version": 1,
            "authentication": {
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "jwks_url": JWKS_URL,
                "algorithms": algorithms or ["RS256"],
                "jwks_timeout_seconds": 3.0,
                "jwks_maximum_response_bytes": 65_536,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_readiness_document(
    tmp_path: Path,
    *,
    algorithms: list[str] | None = None,
) -> Path:
    path = tmp_path / "authentication-readiness.json"
    path.write_bytes(readiness_document(algorithms=algorithms))
    return path


def write_entra_readiness_document(tmp_path: Path) -> Path:
    path = tmp_path / "entra-authentication-readiness.json"
    path.write_bytes(
        json.dumps(
            {
                "document_type": "engineer4me_authentication_readiness",
                "schema_version": 1,
                "authentication": {
                    "issuer": ENTRA_ISSUER,
                    "audience": ENTRA_API_APPLICATION_ID,
                    "jwks_url": JWKS_URL,
                    "algorithms": ["RS256"],
                    "token_identifier_claim": "uti",
                    "token_profile": "microsoft_entra_v2",
                    "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
                    "microsoft_entra_api_application_id": (
                        ENTRA_API_APPLICATION_ID
                    ),
                    "microsoft_entra_calling_client_application_id": (
                        ENTRA_CALLING_CLIENT_APPLICATION_ID
                    ),
                    "microsoft_entra_required_delegated_scope": (
                        ENTRA_REQUIRED_DELEGATED_SCOPE
                    ),
                    "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
                    "jwks_timeout_seconds": 3.0,
                    "jwks_maximum_response_bytes": 65_536,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return path


def rsa_jwk(*, key_id: str = KEY_ID, algorithm: str = "RS256") -> dict:
    key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=2_048,
    ).public_key()
    value = jwt.algorithms.RSAAlgorithm.to_jwk(key, as_dict=True)
    value.update(kid=key_id, alg=algorithm, use="sig")
    return value


class FakeResponse:
    def __init__(
        self,
        *,
        body: bytes,
        status: int = 200,
        url: str = JWKS_URL,
        content_type: str = "application/jwk-set+json",
    ) -> None:
        self.body = body
        self.status = status
        self.url = url
        self.headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int = -1) -> bytes:
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        del args
        return None


def fake_open_url(document: dict, calls: list | None = None):
    calls = [] if calls is None else calls
    body = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    def open_url(request, timeout):
        calls.append((request, timeout))
        return FakeResponse(body=body)

    return open_url, calls


def approved_digest(path: Path) -> str:
    return read_authentication_readiness_preview(path).configuration_sha256


def test_exact_digest_performs_one_bounded_jwks_request(tmp_path):
    path = write_readiness_document(tmp_path)
    open_url, calls = fake_open_url({"keys": [rsa_jwk()]})

    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=open_url,
    )

    assert receipt.configured_algorithms == ("RS256",)
    assert receipt.usable_algorithms == ("RS256",)
    assert receipt.usable_signing_keys == 1
    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == JWKS_URL
    assert request.get_method() == "GET"
    assert request.get_header("Accept") == (
        "application/jwk-set+json, application/json"
    )
    assert timeout == 3.0


def test_entra_scope_and_calling_client_are_preserved_during_jwks_rehydration(
    tmp_path,
):
    path = write_entra_readiness_document(tmp_path)
    preview = read_authentication_readiness_preview(path)
    deployment = authentication_deployment_from_preview(preview)

    assert (
        deployment.runtime.microsoft_entra_required_delegated_scope
        == ENTRA_REQUIRED_DELEGATED_SCOPE
    )
    assert str(
        deployment.runtime.microsoft_entra_calling_client_application_id
    ) == ENTRA_CALLING_CLIENT_APPLICATION_ID
    assert preview.microsoft_entra_calling_client_application_id == (
        ENTRA_CALLING_CLIENT_APPLICATION_ID
    )
    assert deployment.runtime.microsoft_entra_required_azpacr == ENTRA_REQUIRED_AZPACR
    assert preview.microsoft_entra_required_azpacr == ENTRA_REQUIRED_AZPACR
    assert preview.required_claims[-3:] == ("scp", "azp", "azpacr")

    open_url, calls = fake_open_url({"keys": [rsa_jwk()]})
    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=preview.configuration_sha256,
        open_url=open_url,
    )
    assert receipt.usable_signing_keys == 1
    assert len(calls) == 1


def test_receipt_is_frozen_and_renders_only_sanitized_evidence(tmp_path):
    path = write_readiness_document(tmp_path)
    jwk = rsa_jwk()
    open_url, _ = fake_open_url({"keys": [jwk]})
    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=open_url,
    )

    with pytest.raises(FrozenInstanceError):
        receipt.usable_signing_keys = 2
    rendered = render_authentication_jwks_readiness_receipt(receipt)
    parsed = json.loads(rendered)

    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["validation_scope"] == AUTHENTICATION_JWKS_READINESS_SCOPE
    assert parsed["configuration_digest_approved"] is True
    assert parsed["jwks_reachability_checked"] is True
    assert parsed["signing_keys_checked"] is True
    assert parsed["signed_token_checked"] is False
    assert parsed["provider_ownership_checked"] is False
    assert parsed["discovery_consistency_checked"] is False
    assert parsed["activation_ready"] is False
    for forbidden in (
        KEY_ID,
        JWKS_URL,
        jwk["n"],
        jwk["e"],
        json.dumps(jwk),
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "digest",
    [None, "", "0" * 63, "0" * 65, "A" * 64, "G" * 64],
)
def test_malformed_approval_is_rejected_before_file_or_network_access(
    digest,
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected file or network access")

    monkeypatch.setattr(os, "lstat", forbidden)
    with pytest.raises(
        AuthenticationJWKSReadinessApprovalError,
        match="digest is invalid",
    ):
        probe_authentication_jwks_readiness(
            document_path="not-opened.json",
            approved_configuration_sha256=digest,
            open_url=forbidden,
        )


def test_stale_approval_is_rejected_before_network_access(tmp_path):
    path = write_readiness_document(tmp_path)
    calls = []
    open_url, _ = fake_open_url({"keys": [rsa_jwk()]}, calls)

    with pytest.raises(
        AuthenticationJWKSReadinessApprovalError,
        match="does not match",
    ):
        probe_authentication_jwks_readiness(
            document_path=str(path),
            approved_configuration_sha256="0" * 64,
            open_url=open_url,
        )
    assert calls == []


def test_multiple_configured_signing_keys_are_counted_without_disclosure(tmp_path):
    path = write_readiness_document(tmp_path)
    keys = [rsa_jwk(key_id="rotation-a"), rsa_jwk(key_id="rotation-b")]
    open_url, _ = fake_open_url({"keys": keys})

    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=open_url,
    )

    assert receipt.usable_algorithms == ("RS256",)
    assert receipt.usable_signing_keys == 2
    rendered = render_authentication_jwks_readiness_receipt(receipt)
    assert "rotation-a" not in rendered
    assert "rotation-b" not in rendered


def test_no_configured_algorithm_intersection_fails_closed(tmp_path):
    path = write_readiness_document(tmp_path, algorithms=["ES256"])
    open_url, _ = fake_open_url({"keys": [rsa_jwk()]})

    with pytest.raises(
        AuthenticationJWKSReadinessError,
        match="no usable configured signing key",
    ):
        probe_authentication_jwks_readiness(
            document_path=str(path),
            approved_configuration_sha256=approved_digest(path),
            open_url=open_url,
        )


@pytest.mark.parametrize(
    "keys",
    [
        [rsa_jwk(key_id="duplicate"), rsa_jwk(key_id="duplicate")],
        [{**rsa_jwk(), "kty": "EC"}],
        [{"kid": KEY_ID, "alg": "RS256", "use": "sig", "kty": "RSA"}],
    ],
)
def test_malformed_or_ambiguous_signing_keys_fail_sanitarily(tmp_path, keys):
    path = write_readiness_document(tmp_path)
    open_url, _ = fake_open_url({"keys": keys})

    with pytest.raises(
        AuthenticationJWKSReadinessError,
        match="signing keys failed validation",
    ) as captured:
        probe_authentication_jwks_readiness(
            document_path=str(path),
            approved_configuration_sha256=approved_digest(path),
            open_url=open_url,
        )
    assert captured.value.__cause__ is None
    assert KEY_ID not in str(captured.value)


def test_transport_failure_is_sanitized_and_returns_no_receipt(tmp_path):
    path = write_readiness_document(tmp_path)

    def unavailable(request, timeout):
        del request, timeout
        raise URLError("private DNS and provider detail")

    with pytest.raises(
        AuthenticationJWKSReadinessError,
        match="readiness request failed",
    ) as captured:
        probe_authentication_jwks_readiness(
            document_path=str(path),
            approved_configuration_sha256=approved_digest(path),
            open_url=unavailable,
        )
    assert captured.value.__cause__ is None
    assert "private DNS" not in str(captured.value)


def test_canonical_jwks_digest_ignores_json_layout_and_object_key_order(tmp_path):
    path = write_readiness_document(tmp_path)
    key = rsa_jwk()
    compact_open, _ = fake_open_url({"keys": [key]})
    reordered = dict(reversed(tuple(key.items())))
    body = json.dumps({"keys": [reordered]}, indent=4).encode("utf-8")

    def expanded_open(request, timeout):
        del request, timeout
        return FakeResponse(body=body)

    compact = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=compact_open,
    )
    expanded = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=expanded_open,
    )

    assert compact.jwks_document_sha256 == expanded.jwks_document_sha256


def test_command_line_prints_one_sanitized_receipt(tmp_path, monkeypatch, capsys):
    path = write_readiness_document(tmp_path)
    open_url, _ = fake_open_url({"keys": [rsa_jwk()]})
    monkeypatch.setattr(
        "app.security.jwks_http_loader._default_open",
        open_url,
    )

    assert (
        main(
            [
                str(path),
                "--approve-sha256",
                approved_digest(path),
            ]
        )
        == 0
    )
    output = capsys.readouterr()

    assert output.err == ""
    assert output.out.count("\n") == 1
    assert json.loads(output.out)["signing_keys_checked"] is True
    assert KEY_ID not in output.out


def test_command_line_failure_is_nonzero_and_non_disclosing(
    tmp_path,
    monkeypatch,
    capsys,
):
    path = write_readiness_document(tmp_path)

    def unavailable(request, timeout):
        del request, timeout
        raise URLError("private provider outage")

    monkeypatch.setattr(
        "app.security.jwks_http_loader._default_open",
        unavailable,
    )
    with pytest.raises(SystemExit) as captured:
        main(
            [
                str(path),
                "--approve-sha256",
                approved_digest(path),
            ]
        )
    output = capsys.readouterr()

    assert captured.value.code == 2
    assert output.out == ""
    assert output.err == "authentication JWKS readiness probe failed\n"
    assert str(path) not in output.err
    assert "private provider" not in output.err


def test_probe_uses_no_environment_database_or_application_state(
    tmp_path,
    monkeypatch,
):
    path = write_readiness_document(tmp_path)
    open_url, _ = fake_open_url({"keys": [rsa_jwk()]})

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected global access")

    monkeypatch.setattr(os, "getenv", forbidden)
    database_module = sys.modules.get("app.db.database")
    if database_module is not None:
        monkeypatch.setattr(database_module, "SessionLocal", forbidden)
    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=open_url,
    )

    assert receipt.usable_signing_keys == 1


def test_receipt_rejects_invalid_forged_evidence(tmp_path):
    path = write_readiness_document(tmp_path)
    open_url, _ = fake_open_url({"keys": [rsa_jwk()]})
    receipt = probe_authentication_jwks_readiness(
        document_path=str(path),
        approved_configuration_sha256=approved_digest(path),
        open_url=open_url,
    )

    for changes in (
        {"configuration_sha256": "A" * 64},
        {"usable_algorithms": ()},
        {"usable_algorithms": ("ES256",)},
        {"usable_signing_keys": True},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)
    with pytest.raises(TypeError, match="receipt is required"):
        render_authentication_jwks_readiness_receipt({})


def test_fresh_module_import_does_not_read_database_url_or_construct_engine():
    script = """
import os
import sys

original_getenv = os.getenv

def guarded_getenv(key, *args, **kwargs):
    if key == "DATABASE_URL":
        raise AssertionError("JWKS readiness import read DATABASE_URL")
    return original_getenv(key, *args, **kwargs)

os.getenv = guarded_getenv
from app.security import authentication_jwks_readiness
assert "app.db.database" not in sys.modules
assert authentication_jwks_readiness.__name__.endswith("jwks_readiness")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
