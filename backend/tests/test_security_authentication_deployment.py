"""Focused tests for fail-closed authentication deployment configuration."""

import json
import traceback
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security.authentication_deployment import (
    AuthenticationDeploymentError,
    build_deployment_bearer_dependency,
    load_authentication_deployment,
)


ISSUER = "https://identity.engineer4me.test"
AUDIENCE = "engineer4me-api"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
KEY_ID = "key-133"
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


def environment(**overrides):
    values = {
        "E4M_AUTH_ISSUER": ISSUER,
        "E4M_AUTH_AUDIENCE": AUDIENCE,
        "E4M_AUTH_JWKS_URL": JWKS_URL,
        "E4M_AUTH_ALGORITHMS": "RS256",
    }
    values.update(overrides)
    return values


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/jwk-set+json"}

    def __init__(self, body):
        self.body = body

    def geturl(self):
        return JWKS_URL

    def read(self, amount=-1):
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def signed_token(identifier_claim="jti"):
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-133",
            identifier_claim: str(uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def test_deployment_loads_explicit_bounded_configuration():
    deployment = load_authentication_deployment(
        environment(
            E4M_AUTH_CLOCK_SKEW_SECONDS="15",
            E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS="900",
            E4M_AUTH_JWKS_CACHE_SECONDS="120",
            E4M_AUTH_JWKS_MAXIMUM_KEYS="10",
            E4M_AUTH_JWKS_TIMEOUT_SECONDS="4.5",
            E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES="65536",
        )
    )
    assert deployment.runtime.clock_skew_seconds == 15
    assert deployment.runtime.maximum_token_age_seconds == 900
    assert deployment.runtime.token_identifier_claim == "jti"
    assert deployment.runtime.token_profile == "provider_neutral"
    assert deployment.runtime.microsoft_entra_tenant_id is None
    assert deployment.runtime.microsoft_entra_required_delegated_scope is None
    assert deployment.runtime.microsoft_entra_calling_client_application_id is None
    assert deployment.runtime.microsoft_entra_required_azpacr is None
    assert deployment.runtime.jwks.cache_seconds == 120
    assert deployment.transport.timeout_seconds == 4.5
    assert deployment.transport.maximum_response_bytes == 65536


def test_deployment_composes_working_authentication_without_eager_io():
    calls = []
    body = json.dumps({"keys": [PUBLIC_JWK]}).encode()

    def open_url(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse(body)

    authentication = build_deployment_bearer_dependency(
        environment=environment(), open_url=open_url
    )
    assert calls == []
    app = FastAPI()

    @app.get("/deployment-probe")
    def deployment_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get(
        "/deployment-probe", headers={"Authorization": f"Bearer {signed_token()}"}
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "subject-133"}
    assert calls == [(JWKS_URL, 5.0)]


def test_deployment_composes_the_explicit_microsoft_entra_uti_profile():
    calls = []
    body = json.dumps({"keys": [PUBLIC_JWK]}).encode()

    def open_url(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse(body)

    authentication = build_deployment_bearer_dependency(
        environment=environment(E4M_AUTH_TOKEN_IDENTIFIER_CLAIM="uti"),
        open_url=open_url,
    )
    app = FastAPI()

    @app.get("/entra-deployment-probe")
    def deployment_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get(
        "/entra-deployment-probe",
        headers={"Authorization": f"Bearer {signed_token('uti')}"},
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "subject-133"}
    assert calls == [(JWKS_URL, 5.0)]


def test_deployment_composes_exact_tenant_bound_microsoft_entra_v2_profile():
    calls = []
    body = json.dumps({"keys": [PUBLIC_JWK]}).encode()

    def open_url(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse(body)

    authentication = build_deployment_bearer_dependency(
        environment=environment(
            E4M_AUTH_TOKEN_IDENTIFIER_CLAIM="uti",
            E4M_AUTH_TOKEN_PROFILE="microsoft_entra_v2",
            E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID=str(ENTRA_TENANT_ID),
            E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID=str(
                ENTRA_API_APPLICATION_ID
            ),
            E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID=str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR=ENTRA_REQUIRED_AZPACR,
            E4M_AUTH_ISSUER=ENTRA_ISSUER,
            E4M_AUTH_AUDIENCE=str(ENTRA_API_APPLICATION_ID),
        ),
        open_url=open_url,
    )
    now = datetime.now(UTC)
    value = jwt.encode(
        {
            "iss": ENTRA_ISSUER,
            "aud": str(ENTRA_API_APPLICATION_ID),
            "sub": "subject-133",
            "uti": str(uuid4()),
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
    app = FastAPI()

    @app.get("/entra-v2-deployment-probe")
    def deployment_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get(
        "/entra-v2-deployment-probe",
        headers={"Authorization": f"Bearer {value}"},
    )
    assert response.status_code == 200
    assert calls == [(JWKS_URL, 5.0)]


def complete_entra_environment(**overrides):
    values = environment(
        E4M_AUTH_TOKEN_IDENTIFIER_CLAIM="uti",
        E4M_AUTH_TOKEN_PROFILE="microsoft_entra_v2",
        E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID=str(ENTRA_TENANT_ID),
        E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID=str(
            ENTRA_API_APPLICATION_ID
        ),
        E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE=(
            ENTRA_REQUIRED_DELEGATED_SCOPE
        ),
        E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID=str(
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR=ENTRA_REQUIRED_AZPACR,
        E4M_AUTH_ISSUER=ENTRA_ISSUER,
        E4M_AUTH_AUDIENCE=str(ENTRA_API_APPLICATION_ID),
    )
    values.update(overrides)
    return values


def test_deployment_preserves_exact_entra_delegated_scope():
    deployment = load_authentication_deployment(complete_entra_environment())
    assert (
        deployment.runtime.microsoft_entra_required_delegated_scope
        == ENTRA_REQUIRED_DELEGATED_SCOPE
    )
    assert (
        deployment.runtime.microsoft_entra_calling_client_application_id
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )
    assert deployment.runtime.microsoft_entra_required_azpacr == ENTRA_REQUIRED_AZPACR


@pytest.mark.parametrize(
    "scope",
    [None, "wrong_scope", " access_as_user", "access_as_user "],
)
def test_deployment_rejects_missing_wrong_or_whitespace_entra_scope(scope):
    values = complete_entra_environment()
    if scope is None:
        del values["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"]
    else:
        values["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"] = scope
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(values)
    assert captured.value.__cause__ is None


def test_deployment_rejects_entra_scope_on_provider_neutral_profile():
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(
            environment(
                E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE=(
                    ENTRA_REQUIRED_DELEGATED_SCOPE
                )
            )
        )
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "calling_client_application_id",
    [
        None,
        "",
        " ",
        True,
        "not-a-guid",
        str(ENTRA_CALLING_CLIENT_APPLICATION_ID).upper(),
        str(ENTRA_CALLING_CLIENT_APPLICATION_ID).replace("c", "C"),
        f"{{{ENTRA_CALLING_CLIENT_APPLICATION_ID}}}",
        f"urn:uuid:{ENTRA_CALLING_CLIENT_APPLICATION_ID}",
        ENTRA_CALLING_CLIENT_APPLICATION_ID.hex,
        str(UUID(int=0)),
        str(ENTRA_TENANT_ID),
        str(ENTRA_API_APPLICATION_ID),
    ],
)
def test_deployment_requires_one_canonical_distinct_entra_calling_client(
    calling_client_application_id,
):
    values = complete_entra_environment()
    key = "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID"
    if calling_client_application_id is None:
        del values[key]
    else:
        values[key] = calling_client_application_id
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(values)
    assert captured.value.__cause__ is None


def test_deployment_rejects_entra_calling_client_on_provider_neutral_profile():
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(
            environment(
                E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID=str(
                    ENTRA_CALLING_CLIENT_APPLICATION_ID
                )
            )
        )
    assert captured.value.__cause__ is None


def test_deployment_rejects_entra_azpacr_on_provider_neutral_profile():
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(
            environment(E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR="0")
        )
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "azpacr",
    [None, "", " ", "00", "+0", "-0", "0.0", "０", "1", "2", True, 0],
)
def test_deployment_requires_exact_string_public_client_azpacr(azpacr):
    values = complete_entra_environment()
    key = "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR"
    if azpacr is None:
        del values[key]
    else:
        values[key] = azpacr
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(values)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2"},
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "jti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID),
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": str(
                ENTRA_API_APPLICATION_ID
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": str(ENTRA_API_APPLICATION_ID),
        },
        {"E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID)},
        {
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": str(
                ENTRA_API_APPLICATION_ID
            )
        },
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "uti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": "not-a-guid",
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": str(
                ENTRA_API_APPLICATION_ID
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": str(ENTRA_API_APPLICATION_ID),
        },
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "uti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID).upper(),
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": str(
                ENTRA_API_APPLICATION_ID
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": str(ENTRA_API_APPLICATION_ID),
        },
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "uti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID),
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": "not-a-guid",
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": str(ENTRA_API_APPLICATION_ID),
        },
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "uti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID),
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": str(ENTRA_API_APPLICATION_ID),
        },
        {
            "E4M_AUTH_TOKEN_PROFILE": "microsoft_entra_v2",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "uti",
            "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID": str(ENTRA_TENANT_ID),
            "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID": str(
                ENTRA_API_APPLICATION_ID
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID": str(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "E4M_AUTH_ISSUER": ENTRA_ISSUER,
            "E4M_AUTH_AUDIENCE": f"api://{ENTRA_API_APPLICATION_ID}",
        },
        {"E4M_AUTH_TOKEN_PROFILE": "microsoft_entra"},
    ],
)
def test_deployment_rejects_incomplete_or_ambiguous_entra_profile(overrides):
    with pytest.raises(AuthenticationDeploymentError) as captured:
        load_authentication_deployment(environment(**overrides))
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "missing",
    [
        "E4M_AUTH_ISSUER",
        "E4M_AUTH_AUDIENCE",
        "E4M_AUTH_JWKS_URL",
        "E4M_AUTH_ALGORITHMS",
    ],
)
def test_deployment_rejects_each_missing_required_value(missing):
    values = environment()
    del values[missing]
    with pytest.raises(AuthenticationDeploymentError, match="required"):
        load_authentication_deployment(values)


def test_deployment_rejects_unknown_prefixed_configuration_to_catch_typos():
    with pytest.raises(AuthenticationDeploymentError, match="unknown"):
        load_authentication_deployment(environment(E4M_AUTH_JWKS_TIMOUT_SECONDS="5"))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("E4M_AUTH_ALGORITHMS", "HS256"),
        ("E4M_AUTH_ALGORITHMS", "RS256,"),
        ("E4M_AUTH_CLOCK_SKEW_SECONDS", "not-an-integer"),
        ("E4M_AUTH_JWKS_TIMEOUT_SECONDS", "not-a-number"),
        ("E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES", "9999999"),
        ("E4M_AUTH_TOKEN_IDENTIFIER_CLAIM", "UTI"),
        ("E4M_AUTH_TOKEN_IDENTIFIER_CLAIM", "uti "),
        ("E4M_AUTH_TOKEN_IDENTIFIER_CLAIM", "sid"),
        ("E4M_AUTH_TOKEN_IDENTIFIER_CLAIM", ""),
    ],
)
def test_deployment_rejects_unsafe_or_invalid_values_without_reflecting_them(
    key, value
):
    with pytest.raises(AuthenticationDeploymentError) as error:
        load_authentication_deployment(environment(**{key: value}))
    if value:
        assert value not in str(error.value)
        assert value not in "".join(traceback.format_exception(error.value))
    assert error.value.__cause__ is None


def test_deployment_ignores_unrelated_process_configuration():
    deployment = load_authentication_deployment(
        environment(POSTGRES_PASSWORD="unrelated-secret")
    )
    assert deployment.runtime.issuer == ISSUER


@pytest.mark.parametrize(
    "issuer",
    [
        "http://identity.engineer4me.test",
        "identity.engineer4me.test",
        "https:///tenant/v2.0",
        "https://user@identity.engineer4me.test/tenant",
        "https://user:password@identity.engineer4me.test/tenant",
        "https://identity.engineer4me.test/tenant?mode=unsafe",
        "https://identity.engineer4me.test/tenant?",
        "https://identity.engineer4me.test/tenant#fragment",
        "https://identity.engineer4me.test/tenant#",
        "https://[invalid",
        "https://identity.engineer4me.test:notaport/tenant",
        "https://identity.engineer4me.test:99999/tenant",
        "https://identity.engineer4me.test:0/tenant",
        "https://@identity.engineer4me.test/tenant",
        "https://identity.engineer4me.test/ten\nant",
        "https://identity.engineer4me.test\\unexpected/tenant",
        "https://identity .engineer4me.test/tenant",
    ],
)
def test_deployment_rejects_issuer_that_is_not_an_exact_public_https_url(issuer):
    with pytest.raises(AuthenticationDeploymentError) as error:
        load_authentication_deployment(environment(E4M_AUTH_ISSUER=issuer))
    assert issuer not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "issuer",
    [
        "https://login.engineer4me.test/tenant/v2.0/",
        "https://login.engineer4me.test:8443/tenant/v2.0/",
        "https://[2001:db8::1]:8443/tenant/v2.0/",
    ],
)
def test_deployment_preserves_exact_https_issuer_and_allows_separate_jwks_host(issuer):
    deployment = load_authentication_deployment(
        environment(
            E4M_AUTH_ISSUER=issuer,
            E4M_AUTH_JWKS_URL="https://keys.engineer4me.test/provider/jwks.json",
        )
    )
    assert deployment.runtime.issuer == issuer
    assert (
        deployment.transport.source.source_url
        == "https://keys.engineer4me.test/provider/jwks.json"
    )
