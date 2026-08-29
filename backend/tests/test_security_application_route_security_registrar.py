"""Controlled FastAPI registrar tests over the exact Engineer4Me route surface."""

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.analyzers import router as analyzer_router
from app.api.calculations import router as calculation_router
from app.api.control_valves import router as control_valve_router
from app.api.datasheets import router as datasheet_router
from app.api.designs import router as design_router
from app.api.dp_flow import router as dp_flow_router
from app.api.filesystem_document_execution_api import (
    router as filesystem_document_execution_router,
)
from app.api.filesystem_document_upload_api import (
    router as filesystem_document_upload_router,
)
from app.api.ingestion import router as ingestion_router
from app.api.knowledge import router as knowledge_router
from app.api.level_applications import router as level_application_router
from app.api.manufacturers import router as manufacturer_router
from app.api.measurements import router as measurement_router
from app.api.pressure_relief import router as pressure_relief_router
from app.api.product_families import router as product_family_router
from app.api.products import router as product_router
from app.api.protocol import router as protocol_router
from app.api.selections import router as selection_router
from app.main import app
from app.security.application_route_security_plan import (
    build_application_route_security_plan,
)
from app.security.application_route_security_registrar import (
    ApplicationRouteSecurityRegistrar,
    ApplicationRouteSecurityRegistrarError,
)
from app.security.security_deployment import DeploymentSecurityRuntime


class DenyingRuntime(DeploymentSecurityRuntime):
    def __init__(self):
        self.calls = []

    @staticmethod
    def _deny():
        raise HTTPException(status_code=418, detail="registration probe")

    def organisation_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("path", requirement))
        return self._deny

    def organisation_header_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("header", requirement))
        return self._deny

    def datasheet_export_header_access(self, policy, *, request_id_factory=None):
        self.calls.append(("datasheet_export", policy))
        return self._deny


PROTECTED_ROUTERS = (
    manufacturer_router,
    measurement_router,
    protocol_router,
    product_family_router,
    product_router,
    selection_router,
    knowledge_router,
    ingestion_router,
    filesystem_document_upload_router,
    filesystem_document_execution_router,
    calculation_router,
    level_application_router,
    dp_flow_router,
    control_valve_router,
    pressure_relief_router,
    analyzer_router,
    design_router,
    datasheet_router,
)


def include_all_protected_routers(registrar, application):
    for router in PROTECTED_ROUTERS:
        registrar.include_router(application, router, prefix="/api/v1")


def public_application():
    application = FastAPI()

    @application.get("/")
    def root():
        return {"status": "root"}

    @application.get("/health")
    def health():
        return {"status": "healthy"}

    return application


def build_secured_clone():
    runtime = DenyingRuntime()
    plan = build_application_route_security_plan(runtime)
    registrar = ApplicationRouteSecurityRegistrar(plan)
    application = public_application()
    include_all_protected_routers(registrar, application)
    manifest = registrar.finalize(application)
    return application, registrar, manifest, runtime


def route_state(application):
    return tuple(
        (id(route), tuple(getattr(route, "dependencies", ())))
        for route in application.routes
    )


def test_registrar_attaches_all_91_protected_dependencies_exactly_once():
    application, registrar, manifest, runtime = build_secured_clone()
    assert registrar.included_count == 91
    assert registrar.finalized is True
    assert len(manifest.protected_registrations()) == 91
    assert len(runtime.calls) == 91
    assert sum(len(router.routes) for router in PROTECTED_ROUTERS) == 91


def test_registered_dependency_runs_before_existing_protected_endpoint():
    application, _, _, _ = build_secured_clone()
    response = TestClient(application).get("/api/v1/manufacturers")
    assert response.status_code == 418
    assert response.json() == {"detail": "registration probe"}


def test_public_and_framework_routes_remain_unprotected():
    application, _, _, _ = build_secured_clone()
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


def test_registration_copies_routes_without_mutating_authoritative_source_app():
    before_app = route_state(app)
    before_routers = tuple(route_state(router) for router in PROTECTED_ROUTERS)
    application, _, _, _ = build_secured_clone()
    assert route_state(app) == before_app
    assert tuple(route_state(router) for router in PROTECTED_ROUTERS) == before_routers
    assert application is not app


def test_duplicate_registration_fails_before_target_route_mutation():
    plan = build_application_route_security_plan(DenyingRuntime())
    registrar = ApplicationRouteSecurityRegistrar(plan)
    application = public_application()
    source = manufacturer_router
    registrar.include_router(application, source, prefix="/api/v1")
    before = route_state(application)
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="duplicate"):
        registrar.include_router(application, source, prefix="/api/v1")
    assert route_state(application) == before


def test_public_or_unknown_route_cannot_enter_protected_registrar():
    plan = build_application_route_security_plan(DenyingRuntime())
    registrar = ApplicationRouteSecurityRegistrar(plan)
    application = public_application()
    public = APIRouter()

    @public.get("/health")
    def health():
        return {"status": "healthy"}

    before = route_state(application)
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="outside"):
        registrar.include_router(application, public, prefix="")
    assert route_state(application) == before


def test_incomplete_or_repeated_finalization_fails_closed():
    plan = build_application_route_security_plan(DenyingRuntime())
    registrar = ApplicationRouteSecurityRegistrar(plan)
    application = public_application()
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="incomplete"):
        registrar.finalize(application)
    include_all_protected_routers(registrar, application)
    registrar.finalize(application)
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="already finalized"):
        registrar.finalize(application)
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="already finalized"):
        registrar.include_router(application, manufacturer_router, prefix="/api/v1")


def test_cached_openapi_invalid_prefix_and_invalid_contracts_are_rejected():
    plan = build_application_route_security_plan(DenyingRuntime())
    source = manufacturer_router
    cached = public_application()
    cached.openapi()
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="uncached"):
        ApplicationRouteSecurityRegistrar(plan).include_router(
            cached, source, prefix="/api/v1"
        )
    with pytest.raises(ApplicationRouteSecurityRegistrarError, match="prefix"):
        ApplicationRouteSecurityRegistrar(plan).include_router(
            public_application(), source, prefix="api/v1"
        )
    with pytest.raises(TypeError, match="requires ApplicationRouteSecurityPlan"):
        ApplicationRouteSecurityRegistrar(object())
    with pytest.raises(TypeError, match="requires FastAPI"):
        ApplicationRouteSecurityRegistrar(plan).include_router(
            object(), source, prefix=""
        )
    with pytest.raises(TypeError, match="requires APIRouter"):
        ApplicationRouteSecurityRegistrar(plan).include_router(
            public_application(), object(), prefix=""
        )
