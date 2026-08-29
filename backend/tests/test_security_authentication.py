"""Focused tests for the FastAPI bearer authentication boundary."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security.authentication import (
    BearerAuthenticationDependency,
    MAX_AUTHORIZATION_HEADER,
)
from app.security.token_verifier import (
    OIDCTokenVerifier,
    OIDCTokenVerifierConfig,
    StaticVerificationKeyResolver,
)


ISSUER = "https://identity.engineer4me.test"
AUDIENCE = "engineer4me-api"
KEY_ID = "key-130"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()


def dependency(*, issuer=ISSUER, token_identifier_claim="jti"):
    verifier = OIDCTokenVerifier(
        config=OIDCTokenVerifierConfig(
            issuer=issuer,
            audience=AUDIENCE,
            algorithms=("RS256",),
            clock_skew_seconds=5,
            token_identifier_claim=token_identifier_claim,
        ),
        key_resolver=StaticVerificationKeyResolver({(KEY_ID, "RS256"): PUBLIC_KEY}),
    )
    return BearerAuthenticationDependency(verifier)


def token(*, issuer=ISSUER, **overrides):
    now = datetime.now(UTC)
    claims = dict(
        iss=issuer,
        aud=AUDIENCE,
        sub="subject-130",
        jti=str(uuid4()),
        iat=now,
        exp=now + timedelta(minutes=5),
    )
    claims.update(overrides)
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KEY_ID})


def client(*, issuer=ISSUER, token_identifier_claim="jti"):
    app = FastAPI()
    auth = dependency(issuer=issuer, token_identifier_claim=token_identifier_claim)

    @app.get("/protected")
    def protected(context=Depends(auth)):
        return {
            "issuer": context.issuer,
            "subject": context.subject,
            "session_id": str(context.session_id),
        }

    return TestClient(app)


def assert_unauthorized(response):
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_bearer_token_returns_trusted_context():
    response = client().get(
        "/protected", headers={"Authorization": f"Bearer {token()}"}
    )
    assert response.status_code == 200
    assert response.json()["issuer"] == ISSUER
    assert response.json()["subject"] == "subject-130"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Basic abc",
        "Bearer",
        "Bearer  token",
        "Bearer token extra",
        "Bearer token, Bearer other",
        " bearer token",
    ],
)
def test_missing_or_malformed_authorization_is_uniformly_rejected(header):
    headers = {} if header is None else {"Authorization": header}
    assert_unauthorized(client().get("/protected", headers=headers))


def test_invalid_signature_does_not_leak_verification_reason():
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    value = jwt.encode(
        dict(
            iss=ISSUER,
            aud=AUDIENCE,
            sub="subject",
            jti=str(uuid4()),
            iat=now,
            exp=now + timedelta(minutes=5),
        ),
        attacker,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    assert_unauthorized(
        client().get("/protected", headers={"Authorization": f"Bearer {value}"})
    )


def test_provider_neutral_token_identifier_is_accepted_and_correlated():
    token_id = "provider-session-token-130"
    response = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {token(jti=token_id)}"},
    )
    assert response.status_code == 200
    assert response.json()["session_id"] == "a5916911-8b8a-5a27-a974-9f4cec938577"


def test_microsoft_entra_uti_is_used_for_pseudonymous_session_correlation():
    token_id = "entra-uti-token-130"
    now = datetime.now(UTC)
    value = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-130",
            "uti": token_id,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    response = client(token_identifier_claim="uti").get(
        "/protected",
        headers={"Authorization": f"Bearer {value}"},
    )
    assert response.status_code == 200
    assert response.json()["session_id"] != token_id


def test_uuid_form_provider_identifier_is_not_exposed_as_audit_correlation():
    token_id = "13131313-1313-4131-8131-131313131313"
    response = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {token(jti=token_id)}"},
    )
    assert response.status_code == 200
    assert response.json()["session_id"] != token_id


def test_token_session_correlation_is_deterministic_for_repeated_requests():
    token_id = "opaque-jti-130"
    value = token(jti=token_id)
    first = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {value}"},
    )
    second = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {value}"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["session_id"] == second.json()["session_id"]


def test_token_session_correlation_is_issuer_scoped():
    token_id = "shared-provider-jti"
    other_issuer = "https://other-identity.engineer4me.test"
    first = client(issuer=ISSUER).get(
        "/protected",
        headers={"Authorization": f"Bearer {token(issuer=ISSUER, jti=token_id)}"},
    )
    second = client(issuer=other_issuer).get(
        "/protected",
        headers={"Authorization": f"Bearer {token(issuer=other_issuer, jti=token_id)}"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["session_id"] != second.json()["session_id"]


def test_token_session_correlation_is_subject_scoped():
    token_id = "shared-provider-jti"
    first = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {token(jti=token_id, sub='subject-a')}"},
    )
    second = client().get(
        "/protected",
        headers={"Authorization": f"Bearer {token(jti=token_id, sub='subject-b')}"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["session_id"] != second.json()["session_id"]


def test_oversized_header_is_rejected_before_token_verification():
    assert_unauthorized(
        client().get(
            "/protected",
            headers={"Authorization": "Bearer " + ("x" * MAX_AUTHORIZATION_HEADER)},
        )
    )


def test_expired_token_is_rejected():
    now = datetime.now(UTC)
    value = token(iat=now - timedelta(minutes=10), exp=now - timedelta(minutes=5))
    assert_unauthorized(
        client().get("/protected", headers={"Authorization": f"Bearer {value}"})
    )


def test_bearer_scheme_is_case_insensitive_but_exactly_one_token():
    response = client().get(
        "/protected", headers={"Authorization": f"bearer {token()}"}
    )
    assert response.status_code == 200
