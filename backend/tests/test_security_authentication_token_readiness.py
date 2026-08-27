"""Focused tests for digest-confirmed local signed-token readiness."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest

import app.security.authentication_token_readiness as token_readiness_module
from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.authentication_readiness_preview import (
    read_authentication_readiness_preview,
)
from app.security.authentication_token_readiness import (
    AUTHENTICATION_TOKEN_READINESS_SCOPE,
    MAX_AUTHENTICATION_TOKEN_BYTES,
    AuthenticationTokenFileError,
    AuthenticationTokenReadinessApprovalError,
    AuthenticationTokenReadinessError,
    authentication_identity_sha256,
    main,
    probe_authentication_token_readiness,
    render_authentication_token_readiness_receipt,
)
from app.security.token_verifier import REQUIRED_CLAIMS


ISSUER = "https://identity.engineer4me.test/tenant"
AUDIENCE = "engineer4me-api"
JWKS_URL = "https://keys.engineer4me.test/.well-known/jwks.json"
KEY_ID = "private-provider-key-step174"
SUBJECT = "private-provider-subject-step174"
TOKEN_ID = "private-provider-jti-step174"
ENTRA_TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
ENTRA_API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
ENTRA_CALLING_CLIENT_APPLICATION_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
ENTRA_ISSUER = f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0"
ENTRA_DELEGATED_SCOPE = "access_as_user"
ENTRA_AZPACR = "0"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)


def readiness_document(
    *,
    token_identifier_claim: str = "jti",
    token_profile: str = "provider_neutral",
    microsoft_entra_tenant_id: str | None = None,
    microsoft_entra_api_application_id: str | None = None,
    microsoft_entra_calling_client_application_id: str | None = None,
) -> bytes:
    authentication = {
        "issuer": (
            ENTRA_ISSUER if token_profile == "microsoft_entra_v2" else ISSUER
        ),
        "audience": (
            microsoft_entra_api_application_id
            if token_profile == "microsoft_entra_v2"
            else AUDIENCE
        ),
        "jwks_url": JWKS_URL,
        "algorithms": ["RS256"],
        "token_identifier_claim": token_identifier_claim,
        "token_profile": token_profile,
        "clock_skew_seconds": 0,
        "jwks_timeout_seconds": 3.0,
        "jwks_maximum_response_bytes": 65_536,
    }
    if microsoft_entra_tenant_id is not None:
        authentication["microsoft_entra_tenant_id"] = microsoft_entra_tenant_id
    if microsoft_entra_api_application_id is not None:
        authentication["microsoft_entra_api_application_id"] = (
            microsoft_entra_api_application_id
        )
    if microsoft_entra_calling_client_application_id is not None:
        authentication["microsoft_entra_calling_client_application_id"] = (
            microsoft_entra_calling_client_application_id
        )
    if token_profile == "microsoft_entra_v2":
        authentication["microsoft_entra_required_delegated_scope"] = (
            ENTRA_DELEGATED_SCOPE
        )
        authentication["microsoft_entra_required_azpacr"] = ENTRA_AZPACR
    return json.dumps(
        {
            "document_type": "engineer4me_authentication_readiness",
            "schema_version": 1,
            "authentication": authentication,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def public_jwk(*, key=PRIVATE_KEY, key_id: str = KEY_ID) -> dict:
    value = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    value.update(kid=key_id, alg="RS256", use="sig")
    return value


def jwks_document(*, key=PRIVATE_KEY) -> dict:
    return {"keys": [public_jwk(key=key)]}


def canonical_jwks_digest(document: dict) -> str:
    content = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compact_token(
    *,
    key=PRIVATE_KEY,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    subject: str = SUBJECT,
    token_id: str = TOKEN_ID,
    token_identifier_claim: str = "jti",
    token_profile: str = "provider_neutral",
    microsoft_entra_tenant_id: str | None = None,
    microsoft_entra_api_application_id: str | None = None,
    microsoft_entra_calling_client_application_id: str | None = None,
    issued_at: datetime | None = None,
    additional_claims: dict[str, object] | None = None,
    omitted_claims: tuple[str, ...] = (),
) -> str:
    now = issued_at or datetime.now(UTC).replace(microsecond=0)
    claims = {
            "iss": (
                ENTRA_ISSUER
                if token_profile == "microsoft_entra_v2" and issuer == ISSUER
                else issuer
            ),
            "aud": (
                microsoft_entra_api_application_id
                if token_profile == "microsoft_entra_v2" and audience == AUDIENCE
                else audience
            ),
            "sub": subject,
            token_identifier_claim: token_id,
            "iat": now,
            "exp": now + timedelta(minutes=10),
        }
    if token_profile == "microsoft_entra_v2":
        claims.update(
            tid=microsoft_entra_tenant_id,
            ver="2.0",
            scp=ENTRA_DELEGATED_SCOPE,
            azp=microsoft_entra_calling_client_application_id,
            azpacr=ENTRA_AZPACR,
        )
    if additional_claims is not None:
        claims.update(additional_claims)
    for claim in omitted_claims:
        claims.pop(claim, None)
    return jwt.encode(
        claims,
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


def fake_open_url(document: dict, calls: list | None = None):
    calls = [] if calls is None else calls
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    def open_url(request, timeout):
        calls.append((request, timeout))
        return FakeResponse(body)

    return open_url, calls


def write_inputs(
    tmp_path: Path,
    *,
    token: str | None = None,
    token_identifier_claim: str = "jti",
    token_profile: str = "provider_neutral",
    microsoft_entra_tenant_id: str | None = None,
    microsoft_entra_api_application_id: str | None = None,
    microsoft_entra_calling_client_application_id: str | None = None,
):
    document_path = tmp_path / "readiness.json"
    token_path = tmp_path / "token.jwt"
    document_path.write_bytes(
        readiness_document(
            token_identifier_claim=token_identifier_claim,
            token_profile=token_profile,
            microsoft_entra_tenant_id=microsoft_entra_tenant_id,
            microsoft_entra_api_application_id=(
                microsoft_entra_api_application_id
            ),
            microsoft_entra_calling_client_application_id=(
                microsoft_entra_calling_client_application_id
            ),
        )
    )
    token_path.write_bytes(
        (
            token
            or compact_token(
                token_identifier_claim=token_identifier_claim,
                token_profile=token_profile,
                microsoft_entra_tenant_id=microsoft_entra_tenant_id,
                microsoft_entra_api_application_id=(
                    microsoft_entra_api_application_id
                ),
                microsoft_entra_calling_client_application_id=(
                    microsoft_entra_calling_client_application_id
                ),
            )
        ).encode("ascii")
    )
    configuration_digest = read_authentication_readiness_preview(
        document_path
    ).configuration_sha256
    document = jwks_document()
    return (
        document_path,
        token_path,
        configuration_digest,
        document,
        canonical_jwks_digest(document),
    )


def run_probe(
    tmp_path: Path,
    *,
    token: str | None = None,
    document: dict | None = None,
    token_identifier_claim: str = "jti",
    token_profile: str = "provider_neutral",
    microsoft_entra_tenant_id: str | None = None,
    microsoft_entra_api_application_id: str | None = None,
    microsoft_entra_calling_client_application_id: str | None = None,
):
    document_path, token_path, config_digest, default_jwks, default_digest = (
        write_inputs(
            tmp_path,
            token=token,
            token_identifier_claim=token_identifier_claim,
            token_profile=token_profile,
            microsoft_entra_tenant_id=microsoft_entra_tenant_id,
            microsoft_entra_api_application_id=(
                microsoft_entra_api_application_id
            ),
            microsoft_entra_calling_client_application_id=(
                microsoft_entra_calling_client_application_id
            ),
        )
    )
    selected = default_jwks if document is None else document
    open_url, calls = fake_open_url(selected)
    receipt = probe_authentication_token_readiness(
        document_path=document_path,
        token_path=token_path,
        approved_configuration_sha256=config_digest,
        approved_jwks_document_sha256=(
            default_digest if document is None else canonical_jwks_digest(selected)
        ),
        open_url=open_url,
    )
    return receipt, calls


def test_exact_approvals_verify_one_local_signed_token(tmp_path):
    receipt, calls = run_probe(tmp_path)

    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == JWKS_URL
    assert request.get_method() == "GET"
    assert timeout == 3.0
    assert receipt.token_algorithm == "RS256"
    assert receipt.required_claims == REQUIRED_CLAIMS
    assert receipt.token_identifier_claim == "jti"
    assert receipt.token_profile == "provider_neutral"
    assert receipt.microsoft_entra_tenant_id_sha256 is None
    assert receipt.microsoft_entra_api_application_id_sha256 is None
    assert receipt.microsoft_entra_calling_client_application_id_sha256 is None
    assert receipt.microsoft_entra_azp_verified is False
    assert receipt.microsoft_entra_azpacr_sha256 is None
    assert receipt.microsoft_entra_azpacr_public_client_verified is False
    assert receipt.token_version is None
    assert receipt.configuration_sha256
    assert receipt.jwks_document_sha256


def test_provider_neutral_profile_does_not_inherit_azpacr_restrictions(tmp_path):
    receipt, calls = run_probe(
        tmp_path,
        token=compact_token(additional_claims={"azpacr": "2"}),
    )
    assert len(calls) == 1
    assert receipt.token_profile == "provider_neutral"
    assert receipt.microsoft_entra_azpacr_sha256 is None
    assert receipt.microsoft_entra_azpacr_public_client_verified is False


def test_receipt_is_canonical_privacy_minimised_and_not_activation_ready(tmp_path):
    private_token = compact_token()
    receipt, _ = run_probe(tmp_path, token=private_token)
    with pytest.raises(FrozenInstanceError):
        receipt.token_algorithm = "RS512"

    rendered = render_authentication_token_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert rendered == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert parsed["validation_scope"] == AUTHENTICATION_TOKEN_READINESS_SCOPE
    assert parsed["configuration_digest_approved"] is True
    assert parsed["jwks_document_digest_approved"] is True
    assert parsed["signed_token_checked"] is True
    assert parsed["signature_checked"] is True
    assert parsed["issuer_checked"] is True
    assert parsed["audience_checked"] is True
    assert parsed["provider_ownership_checked"] is False
    assert parsed["discovery_consistency_checked"] is False
    assert parsed["bootstrap_ready"] is False
    assert parsed["activation_ready"] is False
    assert parsed["required_claims"] == list(REQUIRED_CLAIMS)
    assert parsed["token_identifier_claim"] == "jti"
    assert parsed["token_profile"] == "provider_neutral"
    assert parsed["microsoft_entra_tenant_id_sha256"] is None
    assert parsed["microsoft_entra_api_application_id_sha256"] is None
    assert parsed["microsoft_entra_calling_client_application_id_sha256"] is None
    assert parsed["microsoft_entra_azp_verified"] is False
    assert parsed["microsoft_entra_azpacr_sha256"] is None
    assert parsed["microsoft_entra_azpacr_public_client_verified"] is False
    assert parsed["token_version"] is None
    for forbidden in (
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        KEY_ID,
        SUBJECT,
        TOKEN_ID,
        private_token,
    ):
        assert forbidden not in rendered


def test_microsoft_entra_uti_profile_is_verified_and_receipted(tmp_path):
    receipt, calls = run_probe(
        tmp_path,
        token_identifier_claim="uti",
    )

    assert len(calls) == 1
    assert receipt.token_identifier_claim == "uti"
    assert receipt.required_claims == (
        "exp",
        "iat",
        "iss",
        "aud",
        "sub",
        "uti",
    )
    rendered = render_authentication_token_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert parsed["token_identifier_claim"] == "uti"
    assert parsed["required_claims"][-1] == "uti"
    assert TOKEN_ID not in rendered


def test_microsoft_entra_v2_tenant_and_version_are_verified_and_receipted(tmp_path):
    receipt, calls = run_probe(
        tmp_path,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )

    assert len(calls) == 1
    assert receipt.token_profile == "microsoft_entra_v2"
    assert receipt.token_identifier_claim == "uti"
    assert receipt.token_version == "2.0"
    assert receipt.microsoft_entra_tenant_id_sha256
    assert receipt.microsoft_entra_api_application_id_sha256
    assert receipt.microsoft_entra_calling_client_application_id_sha256 == (
        authentication_identity_sha256(
            "microsoft_entra_calling_client_application_id",
            ENTRA_CALLING_CLIENT_APPLICATION_ID,
        )
    )
    assert receipt.microsoft_entra_azp_verified is True
    assert receipt.required_claims[-5:] == ("tid", "ver", "scp", "azp", "azpacr")
    assert receipt.microsoft_entra_azpacr_sha256 == (
        authentication_identity_sha256("microsoft_entra_azpacr", ENTRA_AZPACR)
    )
    assert receipt.microsoft_entra_azpacr_public_client_verified is True
    assert receipt.microsoft_entra_delegated_scope_sha256 == (
        authentication_identity_sha256(
            "microsoft_entra_delegated_scope",
            ENTRA_DELEGATED_SCOPE,
        )
    )
    assert receipt.microsoft_entra_delegated_scope_verified is True
    assert receipt.microsoft_entra_roles_claim_absent is True
    assert receipt.microsoft_entra_app_only_token_rejection_enforced is True
    rendered = render_authentication_token_readiness_receipt(receipt)
    parsed = json.loads(rendered)
    assert parsed["token_profile"] == "microsoft_entra_v2"
    assert parsed["token_version"] == "2.0"
    assert parsed["microsoft_entra_tenant_id_sha256"]
    assert parsed["microsoft_entra_api_application_id_sha256"]
    assert parsed["microsoft_entra_calling_client_application_id_sha256"] == (
        receipt.microsoft_entra_calling_client_application_id_sha256
    )
    assert parsed["microsoft_entra_azp_verified"] is True
    assert parsed["microsoft_entra_azpacr_sha256"] == (
        receipt.microsoft_entra_azpacr_sha256
    )
    assert parsed["microsoft_entra_azpacr_public_client_verified"] is True
    assert parsed["microsoft_entra_delegated_scope_sha256"] == (
        receipt.microsoft_entra_delegated_scope_sha256
    )
    assert parsed["microsoft_entra_delegated_scope_verified"] is True
    assert parsed["microsoft_entra_roles_claim_absent"] is True
    assert parsed["microsoft_entra_app_only_token_rejection_enforced"] is True
    assert ENTRA_TENANT_ID not in rendered
    assert ENTRA_API_APPLICATION_ID not in rendered
    assert ENTRA_CALLING_CLIENT_APPLICATION_ID not in rendered
    assert ENTRA_DELEGATED_SCOPE not in rendered
    assert "azp" not in parsed
    assert "azpacr" not in parsed
    assert "microsoft_entra_required_azpacr" not in parsed


def test_microsoft_entra_v2_accepts_optional_exact_user_idtyp(tmp_path):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims={"idtyp": "user"},
    )
    receipt, calls = run_probe(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )

    assert len(calls) == 1
    assert receipt.microsoft_entra_delegated_scope_verified is True


def test_microsoft_entra_v2_accepts_canonical_azp_uuid_case_insensitively(tmp_path):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims={"azp": ENTRA_CALLING_CLIENT_APPLICATION_ID.upper()},
    )
    receipt, calls = run_probe(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )

    assert len(calls) == 1
    assert receipt.microsoft_entra_azp_verified is True


@pytest.mark.parametrize(
    ("additional_claims", "omitted_claims"),
    [
        ({}, ("azp",)),
        ({"appid": ENTRA_CALLING_CLIENT_APPLICATION_ID}, ("azp",)),
        ({"azp": "00000000-0000-4000-8000-000000000001"}, ()),
        ({"azp": ENTRA_API_APPLICATION_ID}, ()),
        ({"azp": f"{{{ENTRA_CALLING_CLIENT_APPLICATION_ID}}}"}, ()),
        ({"azp": f"urn:uuid:{ENTRA_CALLING_CLIENT_APPLICATION_ID}"}, ()),
        ({"azp": ENTRA_CALLING_CLIENT_APPLICATION_ID.replace("-", "")}, ()),
        ({"azp": f" {ENTRA_CALLING_CLIENT_APPLICATION_ID}"}, ()),
        ({"azp": f"{ENTRA_CALLING_CLIENT_APPLICATION_ID} "}, ()),
        ({"azp": f"api://{ENTRA_CALLING_CLIENT_APPLICATION_ID}"}, ()),
        ({"azp": None}, ()),
        ({"azp": True}, ()),
        ({"azp": 1}, ()),
        ({"azp": [ENTRA_CALLING_CLIENT_APPLICATION_ID]}, ()),
        ({"azp": {"application_id": ENTRA_CALLING_CLIENT_APPLICATION_ID}}, ()),
    ],
    ids=[
        "missing",
        "appid-alias-only",
        "wrong-uuid",
        "api-audience-id",
        "braced-uuid",
        "urn-uuid",
        "hyphenless-uuid",
        "leading-whitespace",
        "trailing-whitespace",
        "api-uri",
        "null",
        "boolean",
        "integer",
        "array",
        "object",
    ],
)
def test_microsoft_entra_v2_rejects_nonexact_azp_sanitarily(
    tmp_path,
    additional_claims,
    omitted_claims,
):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims=additional_claims,
        omitted_claims=omitted_claims,
    )
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ) as captured:
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert captured.value.__cause__ is None
    assert private_token not in str(captured.value)
    assert ENTRA_CALLING_CLIENT_APPLICATION_ID not in str(captured.value)


@pytest.mark.parametrize(
    ("additional_claims", "omitted_claims"),
    [
        ({}, ("azpacr",)),
        ({"appidacr": "0"}, ("azpacr",)),
        ({"acr": "0"}, ("azpacr",)),
        ({"amr": ["public"]}, ("azpacr",)),
        ({"azpacr": None}, ()),
        ({"azpacr": 0}, ()),
        ({"azpacr": 0.0}, ()),
        ({"azpacr": False}, ()),
        ({"azpacr": True}, ()),
        ({"azpacr": []}, ()),
        ({"azpacr": {}}, ()),
        ({"azpacr": ""}, ()),
        ({"azpacr": " "}, ()),
        ({"azpacr": " 0"}, ()),
        ({"azpacr": "0 "}, ()),
        ({"azpacr": "00"}, ()),
        ({"azpacr": "+0"}, ()),
        ({"azpacr": "-0"}, ()),
        ({"azpacr": "0.0"}, ()),
        ({"azpacr": "０"}, ()),
        ({"azpacr": "1"}, ()),
        ({"azpacr": "2"}, ()),
    ],
)
def test_microsoft_entra_v2_rejects_nonpublic_azpacr_sanitarily(
    tmp_path,
    additional_claims,
    omitted_claims,
):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims=additional_claims,
        omitted_claims=omitted_claims,
    )
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ) as captured:
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert captured.value.__cause__ is None
    assert private_token not in str(captured.value)


def test_microsoft_entra_authoritative_azpacr_ignores_conflicting_aliases(tmp_path):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims={"appidacr": "2", "acr": "1", "amr": ["secret"]},
    )
    receipt, calls = run_probe(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    assert len(calls) == 1
    assert receipt.microsoft_entra_azpacr_public_client_verified is True


@pytest.mark.parametrize(
    ("additional_claims", "omitted_claims"),
    [
        ({"scp": "Access_as_user"}, ()),
        ({"scp": "access_as_user extra_scope"}, ()),
        ({"scp": "api://private-app/access_as_user"}, ()),
        ({"scp": ["access_as_user"]}, ()),
        ({"scp": None}, ()),
        ({"roles": ["access_as_user"]}, ("scp",)),
        ({"roles": []}, ()),
        ({"roles": None}, ()),
        ({"roles": "access_as_user"}, ()),
        ({"scp": "access_as_user", "roles": ["private-app-role"]}, ()),
        ({"idtyp": "app"}, ()),
        ({"idtyp": "User"}, ()),
        ({"idtyp": "service"}, ()),
        ({"idtyp": None}, ()),
        ({"idtyp": ["user"]}, ()),
    ],
    ids=[
        "scope-wrong-case",
        "multiple-scopes",
        "fully-qualified-scope",
        "scope-list",
        "scope-null",
        "roles-only",
        "roles-empty",
        "roles-null",
        "roles-string",
        "scope-and-roles",
        "app-idtyp",
        "idtyp-wrong-case",
        "idtyp-other",
        "idtyp-null",
        "idtyp-list",
    ],
)
def test_microsoft_entra_v2_rejects_nonexact_delegated_token_claims_sanitarily(
    tmp_path,
    additional_claims,
    omitted_claims,
):
    private_token = compact_token(
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        additional_claims=additional_claims,
        omitted_claims=omitted_claims,
    )
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ) as captured:
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert captured.value.__cause__ is None
    assert private_token not in str(captured.value)
    assert ENTRA_DELEGATED_SCOPE not in str(captured.value)
    assert "private-app-role" not in str(captured.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"tid": "00000000-0000-4000-8000-000000000001"},
        {"ver": "1.0"},
        {"tid": None},
        {"ver": None},
    ],
)
def test_microsoft_entra_v2_rejects_wrong_tenant_or_version(tmp_path, changes):
    now = datetime.now(UTC).replace(microsecond=0)
    claims = {
        "iss": ENTRA_ISSUER,
        "aud": ENTRA_API_APPLICATION_ID,
        "sub": SUBJECT,
        "uti": TOKEN_ID,
        "tid": ENTRA_TENANT_ID,
        "ver": "2.0",
        "scp": ENTRA_DELEGATED_SCOPE,
        "azp": ENTRA_CALLING_CLIENT_APPLICATION_ID,
        "azpacr": ENTRA_AZPACR,
        "iat": now,
        "exp": now + timedelta(minutes=10),
    }
    claims.update(changes)
    private_token = jwt.encode(
        claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )


@pytest.mark.parametrize(
    "value", [None, "", "0" * 63, "0" * 65, "A" * 64, "g" * 63 + "z"]
)
@pytest.mark.parametrize("which", ["configuration", "jwks"])
def test_malformed_approval_is_rejected_before_file_or_network(
    value, which, monkeypatch
):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected file or network access")

    monkeypatch.setattr(os, "lstat", forbidden)
    arguments = {
        "document_path": "not-opened.json",
        "token_path": "not-opened.jwt",
        "approved_configuration_sha256": "0" * 64,
        "approved_jwks_document_sha256": "1" * 64,
        "open_url": forbidden,
    }
    arguments[
        (
            f"approved_{which}_sha256"
            if which == "configuration"
            else "approved_jwks_document_sha256"
        )
    ] = value
    with pytest.raises(
        AuthenticationTokenReadinessApprovalError, match="digest is invalid"
    ):
        probe_authentication_token_readiness(**arguments)


def test_stale_configuration_approval_is_rejected_before_network_or_token(
    tmp_path, monkeypatch
):
    document_path, token_path, _, document, jwks_digest = write_inputs(tmp_path)
    calls = []
    open_url, _ = fake_open_url(document, calls)
    original_open = os.open

    def guarded_open(path, flags):
        if os.fspath(path) == os.fspath(token_path):
            raise AssertionError("token opened before configuration approval")
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", guarded_open)
    with pytest.raises(
        AuthenticationTokenReadinessApprovalError, match="configuration does not match"
    ):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256="0" * 64,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert calls == []


def test_stale_jwks_approval_is_rejected_before_token_is_opened(tmp_path, monkeypatch):
    document_path, token_path, config_digest, document, _ = write_inputs(tmp_path)
    open_url, calls = fake_open_url(document)
    original_open = os.open

    def guarded_open(path, flags):
        if os.fspath(path) == os.fspath(token_path):
            raise AssertionError("token opened before JWKS approval")
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", guarded_open)
    with pytest.raises(
        AuthenticationTokenReadinessApprovalError, match="JWKS does not match"
    ):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256="0" * 64,
            open_url=open_url,
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "token",
    [
        lambda: compact_token(
            key=rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        ),
        lambda: compact_token(issuer="https://other.example/tenant"),
        lambda: compact_token(audience="other-api"),
        lambda: compact_token(
            issued_at=datetime.now(UTC).replace(microsecond=0) - timedelta(hours=2)
        ),
    ],
)
def test_invalid_signature_or_claims_fail_sanitarily(tmp_path, token):
    private_value = token()
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path, token=private_value
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError, match="failed readiness validation"
    ) as captured:
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert captured.value.__cause__ is None
    assert private_value not in str(captured.value)
    assert SUBJECT not in str(captured.value)


def test_missing_required_jti_claim_fails_sanitarily(tmp_path):
    now = datetime.now(UTC).replace(microsecond=0)
    private_token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": SUBJECT,
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path, token=private_token
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )


def test_entra_profile_does_not_fall_back_from_uti_to_jti(tmp_path):
    private_token = compact_token(token_identifier_claim="jti")
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path,
        token=private_token,
        token_identifier_claim="uti",
    )
    open_url, _ = fake_open_url(document)
    with pytest.raises(
        AuthenticationTokenReadinessError,
        match="failed readiness validation",
    ):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )


@pytest.mark.parametrize(
    "content", [b"", b"a.b", b"a.b.c\n", b"a..c", b"a.b.c.d", b"\xff.b.c"]
)
def test_malformed_token_files_fail_without_disclosure(tmp_path, content):
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path
    )
    token_path.write_bytes(content)
    open_url, _ = fake_open_url(document)
    with pytest.raises(AuthenticationTokenFileError) as captured:
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )
    assert str(token_path) not in str(captured.value)
    assert repr(content) not in str(captured.value)


def test_token_file_symlink_and_oversize_are_rejected(
    tmp_path, monkeypatch
):
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path
    )
    link = tmp_path / "linked.jwt"
    create_or_emulate_file_symlink(
        link=link,
        target=token_path,
        monkeypatch=monkeypatch,
        module_os=token_readiness_module.os,
    )
    open_url, _ = fake_open_url(document)
    common = {
        "document_path": document_path,
        "approved_configuration_sha256": config_digest,
        "approved_jwks_document_sha256": jwks_digest,
        "open_url": open_url,
    }
    with pytest.raises(AuthenticationTokenFileError, match="regular non-symlink"):
        probe_authentication_token_readiness(token_path=link, **common)
    token_path.write_bytes(b"a" * (MAX_AUTHENTICATION_TOKEN_BYTES + 1))
    with pytest.raises(AuthenticationTokenFileError, match="byte limit"):
        probe_authentication_token_readiness(token_path=token_path, **common)


def test_token_file_metadata_change_during_read_is_rejected(tmp_path, monkeypatch):
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path
    )
    open_url, _ = fake_open_url(document)
    real_fstat = os.fstat
    count = 0

    def changed_fstat(descriptor):
        nonlocal count
        result = real_fstat(descriptor)
        count += 1
        if count == 4:
            values = list(result)
            values[8] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "fstat", changed_fstat)
    with pytest.raises(AuthenticationTokenFileError, match="changed while"):
        probe_authentication_token_readiness(
            document_path=document_path,
            token_path=token_path,
            approved_configuration_sha256=config_digest,
            approved_jwks_document_sha256=jwks_digest,
            open_url=open_url,
        )


def test_command_line_prints_one_sanitized_receipt(tmp_path, monkeypatch, capsys):
    private_token = compact_token()
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path, token=private_token
    )
    open_url, _ = fake_open_url(document)
    monkeypatch.setattr("app.security.jwks_http_loader._default_open", open_url)
    assert (
        main(
            [
                str(document_path),
                str(token_path),
                "--approve-configuration-sha256",
                config_digest,
                "--approve-jwks-sha256",
                jwks_digest,
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.count("\n") == 1
    assert json.loads(output.out)["signed_token_checked"] is True
    assert private_token not in output.out
    assert SUBJECT not in output.out


def test_command_line_failure_is_nonzero_and_hides_paths_values_and_token(
    tmp_path, monkeypatch, capsys
):
    private_token = compact_token(audience="wrong-private-audience")
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path, token=private_token
    )
    open_url, _ = fake_open_url(document)
    monkeypatch.setattr("app.security.jwks_http_loader._default_open", open_url)
    with pytest.raises(SystemExit) as captured:
        main(
            [
                str(document_path),
                str(token_path),
                "--approve-configuration-sha256",
                config_digest,
                "--approve-jwks-sha256",
                jwks_digest,
            ]
        )
    output = capsys.readouterr()
    assert captured.value.code == 2
    assert output.out == ""
    assert output.err == "authentication token readiness probe failed\n"
    for forbidden in (
        str(document_path),
        str(token_path),
        private_token,
        SUBJECT,
        TOKEN_ID,
    ):
        assert forbidden not in output.err


def test_receipt_rejects_forged_evidence(tmp_path):
    receipt, _ = run_probe(tmp_path)
    for changes in (
        {"configuration_sha256": "A" * 64},
        {"token_algorithm": "HS256"},
        {"subject_sha256": "0" * 63},
        {"required_claims": tuple(reversed(REQUIRED_CLAIMS))},
        {"token_identifier_claim": "sid"},
        {"token_identifier_claim": "uti"},
        {"microsoft_entra_calling_client_application_id_sha256": "0" * 63},
        {"microsoft_entra_azp_verified": True},
        {"microsoft_entra_azpacr_sha256": "0" * 64},
        {"microsoft_entra_azpacr_public_client_verified": True},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)
    with pytest.raises(TypeError, match="receipt is required"):
        render_authentication_token_readiness_receipt({})


def test_microsoft_entra_receipt_rejects_forged_scope_caller_or_azpacr(tmp_path):
    receipt, _ = run_probe(
        tmp_path,
        token_identifier_claim="uti",
        token_profile="microsoft_entra_v2",
        microsoft_entra_tenant_id=ENTRA_TENANT_ID,
        microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
        microsoft_entra_calling_client_application_id=(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
    )
    for changes in (
        {"microsoft_entra_delegated_scope_sha256": "0" * 64},
        {"microsoft_entra_calling_client_application_id_sha256": "0" * 63},
        {"microsoft_entra_calling_client_application_id_sha256": None},
        {"microsoft_entra_azp_verified": False},
        {"microsoft_entra_azpacr_sha256": "0" * 64},
        {"microsoft_entra_azpacr_sha256": None},
        {"microsoft_entra_azpacr_public_client_verified": False},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)


def test_probe_does_not_read_environment_database_or_application_state(
    tmp_path, monkeypatch
):
    document_path, token_path, config_digest, document, jwks_digest = write_inputs(
        tmp_path
    )
    open_url, _ = fake_open_url(document)

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected global access")

    monkeypatch.setattr(os, "getenv", forbidden)
    database_module = sys.modules.get("app.db.database")
    if database_module is not None:
        monkeypatch.setattr(database_module, "SessionLocal", forbidden)
    receipt = probe_authentication_token_readiness(
        document_path=document_path,
        token_path=token_path,
        approved_configuration_sha256=config_digest,
        approved_jwks_document_sha256=jwks_digest,
        open_url=open_url,
    )
    assert receipt.token_algorithm == "RS256"


def test_fresh_module_import_does_not_read_database_url_or_construct_engine():
    script = """
import os
import sys
original_getenv = os.getenv
def guarded_getenv(key, *args, **kwargs):
    if key == "DATABASE_URL":
        raise AssertionError("token readiness import read DATABASE_URL")
    return original_getenv(key, *args, **kwargs)
os.getenv = guarded_getenv
from app.security import authentication_token_readiness
assert "app.db.database" not in sys.modules
assert authentication_token_readiness.__name__.endswith("token_readiness")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
