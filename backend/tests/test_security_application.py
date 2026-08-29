"""Controlled secured-application composition tests."""

from dataclasses import FrozenInstanceError

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.security.application_route_security_registrar import (
    ApplicationRouteSecurityRegistrarError,
)
from app.security.authentication_deployment import AuthenticationDeploymentError
from app.security.security_application import (
    SecuredApplicationComposition,
    compose_reviewed_application_security,
)
from app.services.security_access_reader import SessionFactorySecurityAccessService


ENVIRONMENT = {
    "E4M_AUTH_ISSUER": "https://identity.engineer4me.test",
    "E4M_AUTH_AUDIENCE": "engineer4me-api",
    "E4M_AUTH_JWKS_URL": "https://identity.engineer4me.test/.well-known/jwks.json",
    "E4M_AUTH_ALGORITHMS": "RS256",
}


class SessionFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("unexpected eager database session")


class NetworkProbe:
    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("unexpected eager JWKS request")


def public_application():
    application = FastAPI()

    @application.get("/")
    def root():
        return {"status": "root"}

    @application.get("/health")
    def health():
        return {"status": "healthy"}

    return application


def compose(application=None, *, environment=ENVIRONMENT):
    access_factory = SessionFactory()
    audit_factory = SessionFactory()
    network = NetworkProbe()
    target = application or public_application()
    receipt = compose_reviewed_application_security(
        target,
        environment=environment,
        access_session_factory=access_factory,
        audit_session_factory=audit_factory,
        open_url=network,
    )
    return target, receipt, access_factory, audit_factory, network


def test_composition_finalizes_all_reviewed_routes_without_eager_io():
    application, receipt, access_factory, audit_factory, network = compose()
    assert isinstance(receipt, SecuredApplicationComposition)
    assert len(receipt.manifest.registrations) == 93
    assert len(receipt.manifest.public_registrations()) == 2
    assert len(receipt.manifest.protected_registrations()) == 91
    assert isinstance(
        receipt.runtime._audited_access_service._access_service,
        SessionFactorySecurityAccessService,
    )
    assert access_factory.calls == 0
    assert audit_factory.calls == 0
    assert network.calls == 0
    assert application.openapi_schema is not None


def test_missing_bearer_is_rejected_before_network_or_database_access():
    application, _, access_factory, audit_factory, network = compose()
    response = TestClient(application).get("/api/v1/manufacturers")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert access_factory.calls == 0
    assert audit_factory.calls == 0
    assert network.calls == 0


def test_public_and_framework_routes_remain_available_without_security_io():
    application, _, access_factory, audit_factory, network = compose()
    client = TestClient(application)
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    assert access_factory.calls == 0
    assert audit_factory.calls == 0
    assert network.calls == 0


def test_invalid_configuration_fails_before_any_route_or_io_change():
    application = public_application()
    access_factory = SessionFactory()
    audit_factory = SessionFactory()
    network = NetworkProbe()
    before = tuple(application.routes)
    with pytest.raises(AuthenticationDeploymentError):
        compose_reviewed_application_security(
            application,
            environment={},
            access_session_factory=access_factory,
            audit_session_factory=audit_factory,
            open_url=network,
        )
    assert tuple(application.routes) == before
    assert set(application.openapi()["paths"]) == {"/", "/health"}
    assert access_factory.calls == 0
    assert audit_factory.calls == 0
    assert network.calls == 0


def test_repeated_composition_fails_closed_without_schema_change():
    application, _, _, _, _ = compose()
    schema = application.openapi()
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="uncached OpenAPI"):
        compose_reviewed_application_security(
            application,
            environment=ENVIRONMENT,
            access_session_factory=SessionFactory(),
            audit_session_factory=SessionFactory(),
            open_url=NetworkProbe(),
        )
    assert application.openapi() is schema


def test_receipt_is_immutable_and_contracts_are_strict():
    _, receipt, _, _, _ = compose()
    with pytest.raises(FrozenInstanceError):
        receipt.runtime = receipt.runtime
    with pytest.raises(TypeError, match="requires FastAPI"):
        compose_reviewed_application_security(
            object(),
            environment=ENVIRONMENT,
            access_session_factory=SessionFactory(),
            audit_session_factory=SessionFactory(),
        )
    with pytest.raises(TypeError, match="session factory must be callable"):
        compose_reviewed_application_security(
            public_application(),
            environment=ENVIRONMENT,
            access_session_factory=None,
            audit_session_factory=SessionFactory(),
        )
