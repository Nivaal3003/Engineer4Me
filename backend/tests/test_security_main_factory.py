"""Production-shell integration tests for the reviewed secured application."""

from fastapi.testclient import TestClient
import pytest

from app.main import (
    APPLICATION_VERSION,
    app,
    create_reviewed_secured_application,
    root,
)
from app.security.authentication_deployment import AuthenticationDeploymentError
from app.security.route_inventory import validate_application_route_inventory
from app.security.security_application import SecuredApplicationComposition


ENVIRONMENT = {
    "E4M_AUTH_ISSUER": "https://identity.engineer4me.test",
    "E4M_AUTH_AUDIENCE": "engineer4me-api",
    "E4M_AUTH_JWKS_URL": "https://identity.engineer4me.test/.well-known/jwks.json",
    "E4M_AUTH_ALGORITHMS": "RS256",
}


class SessionFactoryProbe:
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


def build_secured_application(*, environment=ENVIRONMENT):
    access_factory = SessionFactoryProbe()
    audit_factory = SessionFactoryProbe()
    network = NetworkProbe()
    application = create_reviewed_secured_application(
        environment=environment,
        access_session_factory=access_factory,
        audit_session_factory=audit_factory,
        open_url=network,
    )
    return application, access_factory, audit_factory, network


def test_secured_factory_builds_the_exact_reviewed_application_surface():
    application, access_factory, audit_factory, network = build_secured_application()
    composition = application.state.security_composition
    assert isinstance(composition, SecuredApplicationComposition)
    assert len(composition.manifest.registrations) == 93
    assert len(composition.manifest.public_registrations()) == 2
    assert len(composition.manifest.protected_registrations()) == 91
    assert len(validate_application_route_inventory(application)) == 93
    protected = composition.manifest.protected_registrations()
    assert len({registration.key for registration in protected}) == 91
    assert all(callable(registration.binding.dependency) for registration in protected)
    assert access_factory.calls == audit_factory.calls == network.calls == 0


def test_secured_factory_preserves_metadata_middleware_and_public_contracts():
    application, access_factory, audit_factory, network = build_secured_application()
    assert application.title == app.title == "Engineer4Me API"
    assert application.version == app.version == APPLICATION_VERSION == "0.10.0"
    assert application.description == app.description
    assert tuple(item.cls for item in application.user_middleware) == tuple(
        item.cls for item in app.user_middleware
    )
    assert len(application.user_middleware) == 7
    client = TestClient(application)
    assert client.get("/").json() == root()
    assert client.get("/health").json() == {"status": "healthy"}
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    assert access_factory.calls == audit_factory.calls == network.calls == 0


def test_secured_factory_rejects_missing_bearer_before_any_io():
    application, access_factory, audit_factory, network = build_secured_application()
    response = TestClient(application).get("/api/v1/manufacturers")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert access_factory.calls == audit_factory.calls == network.calls == 0


def test_secured_factory_invalid_configuration_fails_without_io():
    access_factory = SessionFactoryProbe()
    audit_factory = SessionFactoryProbe()
    network = NetworkProbe()
    with pytest.raises(
        AuthenticationDeploymentError,
        match="required authentication deployment configuration is missing",
    ):
        create_reviewed_secured_application(
            environment={},
            access_session_factory=access_factory,
            audit_session_factory=audit_factory,
            open_url=network,
        )
    assert access_factory.calls == audit_factory.calls == network.calls == 0


def test_secured_factory_uses_only_the_explicit_environment(monkeypatch):
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    access_factory = SessionFactoryProbe()
    audit_factory = SessionFactoryProbe()
    network = NetworkProbe()
    with pytest.raises(AuthenticationDeploymentError):
        create_reviewed_secured_application(
            environment={},
            access_session_factory=access_factory,
            audit_session_factory=audit_factory,
            open_url=network,
        )
    assert access_factory.calls == audit_factory.calls == network.calls == 0


def test_factory_does_not_mutate_the_pre_activation_application():
    before_routes = tuple(
        (id(route), tuple(getattr(route, "dependencies", ())))
        for route in app.routes
    )
    before_schema = app.openapi()
    application, _, _, _ = build_secured_application()
    assert application is not app
    assert tuple(
        (id(route), tuple(getattr(route, "dependencies", ())))
        for route in app.routes
    ) == before_routes
    assert app.openapi() is before_schema
    assert not hasattr(app.state, "security_composition")
