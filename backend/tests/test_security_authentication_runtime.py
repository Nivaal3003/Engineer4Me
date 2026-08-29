"""Focused tests for controlled authentication-runtime composition."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.security.authentication_runtime import (
    AuthenticationRuntimeConfiguration,
    build_bearer_authentication_dependency,
)
from app.security.jwks_resolver import JWKSConfiguration, TrustedJWKSResponse


ISSUER = "https://identity.engineer4me.test"
AUDIENCE = "engineer4me-api"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
KEY_ID = "key-131"
ENTRA_TENANT_ID = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200")
ENTRA_API_APPLICATION_ID = UUID("bbbbbbbb-cccc-4ddd-8eee-ffffffff0300")
ENTRA_CALLING_CLIENT_APPLICATION_ID = UUID(
    "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
)
ENTRA_ISSUER = f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0"
ENTRA_REQUIRED_DELEGATED_SCOPE = "access_as_user"
ENTRA_REQUIRED_AZPACR = "0"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_JWK = jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True)
PUBLIC_JWK.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})


def configuration(**overrides):
    values = dict(
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithms=("RS256",),
        jwks=JWKSConfiguration(source_url=JWKS_URL, cache_seconds=60, maximum_keys=5),
    )
    values.update(overrides)
    return AuthenticationRuntimeConfiguration(**values)


def signed_token():
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-131",
            "jti": str(uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def trusted_loader(calls):
    def load(source_url):
        calls.append(source_url)
        return TrustedJWKSResponse(
            source_url=source_url,
            fetched_at=datetime.now(UTC),
            document={"keys": [PUBLIC_JWK]},
        )

    return load


def test_runtime_composes_verified_bearer_authentication_without_eager_io():
    calls = []
    authentication = build_bearer_authentication_dependency(
        config=configuration(), jwks_loader=trusted_loader(calls)
    )
    assert calls == []
    app = FastAPI()

    @app.get("/runtime-probe")
    def runtime_probe(context=Depends(authentication)):
        return {
            "issuer": context.issuer,
            "subject": context.subject,
            "session_id": str(context.session_id),
        }

    response = TestClient(app).get(
        "/runtime-probe", headers={"Authorization": f"Bearer {signed_token()}"}
    )
    assert response.status_code == 200
    assert response.json()["subject"] == "subject-131"
    assert calls == [JWKS_URL]


def test_runtime_reuses_the_bounded_jwks_cache():
    calls = []
    authentication = build_bearer_authentication_dependency(
        config=configuration(), jwks_loader=trusted_loader(calls)
    )
    app = FastAPI()

    @app.get("/runtime-probe")
    def runtime_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    client = TestClient(app)
    assert (
        client.get(
            "/runtime-probe", headers={"Authorization": f"Bearer {signed_token()}"}
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/runtime-probe", headers={"Authorization": f"Bearer {signed_token()}"}
        ).status_code
        == 200
    )
    assert calls == [JWKS_URL]


def test_runtime_propagates_the_microsoft_entra_uti_profile():
    now = datetime.now(UTC)
    value = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-entra",
            "uti": "entra-token-id",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    calls = []
    authentication = build_bearer_authentication_dependency(
        config=configuration(token_identifier_claim="uti"),
        jwks_loader=trusted_loader(calls),
    )
    app = FastAPI()

    @app.get("/entra-runtime-probe")
    def runtime_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get(
        "/entra-runtime-probe",
        headers={"Authorization": f"Bearer {value}"},
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "subject-entra"}
    assert calls == [JWKS_URL]


def test_runtime_propagates_the_tenant_bound_microsoft_entra_v2_profile():
    now = datetime.now(UTC)
    value = jwt.encode(
        {
            "iss": ENTRA_ISSUER,
            "aud": str(ENTRA_API_APPLICATION_ID),
            "sub": "subject-entra-v2",
            "uti": "entra-v2-token-id",
            "tid": str(ENTRA_TENANT_ID),
            "ver": "2.0",
            "scp": ENTRA_REQUIRED_DELEGATED_SCOPE,
            "azp": str(ENTRA_CALLING_CLIENT_APPLICATION_ID),
            "azpacr": ENTRA_REQUIRED_AZPACR,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    calls = []
    authentication = build_bearer_authentication_dependency(
        config=configuration(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        ),
        jwks_loader=trusted_loader(calls),
    )
    app = FastAPI()

    @app.get("/entra-v2-runtime-probe")
    def runtime_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get(
        "/entra-v2-runtime-probe",
        headers={"Authorization": f"Bearer {value}"},
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "subject-entra-v2"}
    assert calls == [JWKS_URL]


@pytest.mark.parametrize(
    "scope",
    [None, "wrong_scope", " access_as_user", "access_as_user "],
)
def test_runtime_rejects_missing_wrong_or_whitespace_entra_scope(scope):
    with pytest.raises(ValidationError):
        configuration(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=scope,
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        )


@pytest.mark.parametrize(
    "calling_client_application_id",
    [None, UUID(int=0), ENTRA_TENANT_ID, ENTRA_API_APPLICATION_ID],
)
def test_runtime_rejects_missing_zero_or_non_distinct_entra_calling_client(
    calling_client_application_id,
):
    with pytest.raises(ValidationError):
        configuration(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                calling_client_application_id
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        )


def test_runtime_rejects_entra_scope_on_provider_neutral_profile():
    with pytest.raises(ValidationError):
        configuration(
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            )
        )


def test_runtime_rejects_entra_calling_client_on_provider_neutral_profile():
    with pytest.raises(ValidationError):
        configuration(
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            )
        )


def test_runtime_rejects_entra_azpacr_on_provider_neutral_profile():
    with pytest.raises(ValidationError):
        configuration(microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR)


@pytest.mark.parametrize("azpacr", [None, 0, False, "", "00", "1", "2"])
def test_runtime_requires_exact_public_client_azpacr(azpacr):
    with pytest.raises(ValidationError):
        configuration(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=azpacr,
        )


@pytest.mark.parametrize("algorithms", [("HS256",), ("RS256", "RS256"), ()])
def test_runtime_rejects_unsafe_duplicate_or_empty_algorithm_configuration(algorithms):
    with pytest.raises(ValidationError):
        configuration(algorithms=algorithms)


def test_runtime_rejects_non_https_jwks_configuration():
    with pytest.raises(ValidationError):
        configuration(jwks=JWKSConfiguration(source_url="http://identity.test/jwks"))


def test_runtime_configuration_is_immutable():
    config = configuration()
    with pytest.raises(ValidationError):
        config.audience = "replacement"
