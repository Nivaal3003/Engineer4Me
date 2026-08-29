"""Focused tests for sanitized authentication availability containment."""

from urllib.error import URLError

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.security.authentication_availability import AvailabilityAwareAuthenticationDependency
from app.security.authentication_deployment import build_deployment_bearer_dependency
from app.security.jwks_http_loader import JWKSHTTPError
from app.security.jwks_resolver import JWKSResolutionError


ENVIRONMENT = {
    "E4M_AUTH_ISSUER": "https://identity.engineer4me.test",
    "E4M_AUTH_AUDIENCE": "engineer4me-api",
    "E4M_AUTH_JWKS_URL": "https://identity.engineer4me.test/.well-known/jwks.json",
    "E4M_AUTH_ALGORITHMS": "RS256",
}


class RaisingDependency:
    def __init__(self, error):
        self.error = error

    def __call__(self, authorization):
        raise self.error


@pytest.mark.parametrize("error", [JWKSHTTPError("internal transport detail"), JWKSResolutionError("internal key detail")])
def test_known_jwks_outages_are_sanitized_as_retryable_503(error):
    dependency = AvailabilityAwareAuthenticationDependency(RaisingDependency(error))
    with pytest.raises(HTTPException) as raised:
        dependency("Bearer token")
    assert raised.value.status_code == 503
    assert raised.value.detail == "Authentication service temporarily unavailable."
    assert raised.value.headers == {"Retry-After": "5"}
    assert "internal" not in raised.value.detail


def test_existing_http_authentication_failures_are_preserved():
    original = HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    dependency = AvailabilityAwareAuthenticationDependency(RaisingDependency(original))
    with pytest.raises(HTTPException) as raised:
        dependency(None)
    assert raised.value is original


def test_unexpected_programming_failures_are_not_masked():
    dependency = AvailabilityAwareAuthenticationDependency(RaisingDependency(RuntimeError("programming defect")))
    with pytest.raises(RuntimeError, match="programming defect"):
        dependency("Bearer token")


def test_deployment_runtime_contains_transport_outage_without_leaking_detail():
    def unavailable_transport(request, timeout):
        raise URLError("private provider and network detail")

    authentication = build_deployment_bearer_dependency(environment=ENVIRONMENT, open_url=unavailable_transport)
    app = FastAPI()

    @app.get("/availability-probe")
    def availability_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xMzQifQ.e30.c2lnbmF0dXJl"
    response = TestClient(app).get("/availability-probe", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service temporarily unavailable."}
    assert response.headers["retry-after"] == "5"
    assert "provider" not in response.text


def test_malformed_bearer_input_remains_a_non_retryable_401():
    authentication = build_deployment_bearer_dependency(environment=ENVIRONMENT, open_url=lambda request, timeout: None)
    app = FastAPI()

    @app.get("/availability-probe")
    def availability_probe(context=Depends(authentication)):
        return {"subject": context.subject}

    response = TestClient(app).get("/availability-probe", headers={"Authorization": "Basic credentials"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "retry-after" not in response.headers
