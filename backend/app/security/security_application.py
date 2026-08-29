"""Controlled composition of the reviewed secured FastAPI application surface."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import FastAPI

from app.repositories.security_audit_writer import AuditSessionFactory
from app.security.application_route_security_assembly import (
    register_reviewed_application_routes,
)
from app.security.application_route_security_registration import (
    ApplicationRouteSecurityRegistrationManifest,
)
from app.security.jwks_http_loader import OpenURL
from app.security.security_deployment import (
    DeploymentSecurityRuntime,
    build_session_factory_deployment_security_runtime,
)
from app.services.security_access_reader import AccessSessionFactory


@dataclass(frozen=True, slots=True)
class SecuredApplicationComposition:
    """Immutable receipt for one finalized reviewed security composition."""

    runtime: DeploymentSecurityRuntime
    manifest: ApplicationRouteSecurityRegistrationManifest

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, DeploymentSecurityRuntime):
            raise TypeError("secured application receipt requires deployment runtime")
        if not isinstance(
            self.manifest,
            ApplicationRouteSecurityRegistrationManifest,
        ):
            raise TypeError("secured application receipt requires registration manifest")


def compose_reviewed_application_security(
    application: FastAPI,
    *,
    environment: Mapping[str, str],
    access_session_factory: AccessSessionFactory,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
) -> SecuredApplicationComposition:
    """Attach all reviewed dependencies using explicit deployment inputs."""

    if not isinstance(application, FastAPI):
        raise TypeError("secured application composition requires FastAPI")
    runtime = build_session_factory_deployment_security_runtime(
        environment=environment,
        access_session_factory=access_session_factory,
        audit_session_factory=audit_session_factory,
        open_url=open_url,
    )
    manifest = register_reviewed_application_routes(application, runtime)
    return SecuredApplicationComposition(runtime=runtime, manifest=manifest)


__all__ = [
    "SecuredApplicationComposition",
    "compose_reviewed_application_security",
]
