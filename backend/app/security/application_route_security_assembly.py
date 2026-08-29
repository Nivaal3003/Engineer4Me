"""Authoritative assembly of the reviewed Engineer4Me protected route surface."""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

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
from app.security.application_route_security_plan import (
    build_application_route_security_plan,
)
from app.security.application_route_security_registrar import (
    ApplicationRouteSecurityRegistrar,
)
from app.security.application_route_security_registration import (
    ApplicationRouteSecurityRegistrationManifest,
)
from app.security.security_deployment import DeploymentSecurityRuntime


APPLICATION_PROTECTED_ROUTERS: tuple[APIRouter, ...] = (
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


def register_reviewed_application_routes(
    application: FastAPI,
    runtime: DeploymentSecurityRuntime,
    *,
    prefix: str = "/api/v1",
) -> ApplicationRouteSecurityRegistrationManifest:
    """Register and finalize the exact reviewed protected application routes."""

    if not isinstance(application, FastAPI):
        raise TypeError("application route security assembly requires FastAPI")
    if not isinstance(runtime, DeploymentSecurityRuntime):
        raise TypeError(
            "application route security assembly requires DeploymentSecurityRuntime"
        )
    if prefix != "/api/v1":
        raise ValueError("application route security assembly requires /api/v1 prefix")

    plan = build_application_route_security_plan(runtime)
    registrar = ApplicationRouteSecurityRegistrar(plan)
    for router in APPLICATION_PROTECTED_ROUTERS:
        registrar.include_router(application, router, prefix=prefix)
    manifest = registrar.finalize(application)
    if registrar.included_count != 91 or not registrar.finalized:
        raise RuntimeError("application route security assembly did not finalize exactly")
    return manifest


__all__ = [
    "APPLICATION_PROTECTED_ROUTERS",
    "register_reviewed_application_routes",
]
