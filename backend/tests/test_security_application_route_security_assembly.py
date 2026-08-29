"""Production assembly proof for the reviewed Engineer4Me protected routers."""

from fastapi import FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.security.application_route_security_assembly import (
    APPLICATION_PROTECTED_ROUTERS,
    register_reviewed_application_routes,
)
from app.security.application_route_security_registrar import (
    ApplicationRouteSecurityRegistrarError,
)
from app.security.security_deployment import DeploymentSecurityRuntime


class DenyingRuntime(DeploymentSecurityRuntime):
    def __init__(self):
        self.calls = []

    @staticmethod
    def _deny():
        raise HTTPException(status_code=418, detail="assembly probe")

    def organisation_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("path", requirement))
        return self._deny

    def organisation_header_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("header", requirement))
        return self._deny

    def datasheet_export_header_access(self, policy, *, request_id_factory=None):
        self.calls.append(("datasheet_export", policy))
        return self._deny


def public_application():
    application = FastAPI()

    @application.get("/")
    def root():
        return {"status": "root"}

    @application.get("/health")
    def health():
        return {"status": "healthy"}

    return application


def route_state(application):
    return tuple(
        (id(route), tuple(getattr(route, "dependencies", ())))
        for route in application.routes
    )


def test_assembly_registers_exact_authoritative_surface_once():
    runtime = DenyingRuntime()
    application = public_application()
    manifest = register_reviewed_application_routes(application, runtime)
    assert len(APPLICATION_PROTECTED_ROUTERS) == 18
    assert sum(len(router.routes) for router in APPLICATION_PROTECTED_ROUTERS) == 91
    assert len(manifest.protected_registrations()) == 91
    assert len(runtime.calls) == 91


def test_assembly_dependency_rejects_before_endpoint_execution():
    application = public_application()
    register_reviewed_application_routes(application, DenyingRuntime())
    response = TestClient(application).get("/api/v1/manufacturers")
    assert response.status_code == 418
    assert response.json() == {"detail": "assembly probe"}


def test_assembly_preserves_public_and_framework_routes():
    application = public_application()
    register_reviewed_application_routes(application, DenyingRuntime())
    client = TestClient(application)
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    public = [
        route
        for route in application.routes
        if isinstance(route, APIRoute) and route.path in {"/", "/health"}
    ]
    assert len(public) == 2
    assert all(route.dependencies == [] for route in public)


def test_assembly_does_not_mutate_source_application_or_declared_routers():
    before_app = route_state(app)
    before_routers = tuple(
        route_state(router) for router in APPLICATION_PROTECTED_ROUTERS
    )
    application = public_application()
    register_reviewed_application_routes(application, DenyingRuntime())
    assert route_state(app) == before_app
    assert tuple(
        route_state(router) for router in APPLICATION_PROTECTED_ROUTERS
    ) == before_routers


def test_assembly_rejects_duplicate_target_and_invalid_contracts():
    application = public_application()
    register_reviewed_application_routes(application, DenyingRuntime())
    before = route_state(application)
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="uncached OpenAPI"):
        register_reviewed_application_routes(application, DenyingRuntime())
    assert route_state(application) == before
    with pytest.raises(TypeError, match="requires FastAPI"):
        register_reviewed_application_routes(object(), DenyingRuntime())
    with pytest.raises(TypeError, match="requires DeploymentSecurityRuntime"):
        register_reviewed_application_routes(public_application(), object())
    with pytest.raises(ValueError, match="requires /api/v1 prefix"):
        register_reviewed_application_routes(
            public_application(), DenyingRuntime(), prefix="/api/v2"
        )
