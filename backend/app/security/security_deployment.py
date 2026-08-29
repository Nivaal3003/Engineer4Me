"""Controlled deployment composition for authenticated, authorised, audited access."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.repositories.security_audit_writer import (
    AuditSessionFactory,
    DurableSecurityAuditWriter,
)
from app.repositories.security_repository import SecurityRepository
from app.security.access_dependency import OrganisationAccessRequirement
from app.security.audited_access_dependency import (
    build_audited_header_organisation_access_dependency,
    build_audited_organisation_access_dependency,
)
from app.security.authentication_availability import (
    AvailabilityAwareAuthenticationDependency,
)
from app.security.authentication_deployment import build_deployment_bearer_dependency
from app.security.datasheet_export_access import (
    build_audited_datasheet_export_access_dependency,
)
from app.security.jwks_http_loader import OpenURL
from app.security.route_policy import RouteSecurityPolicy
from app.services.security_access_reader import (
    AccessSessionFactory,
    SessionFactorySecurityAccessService,
)
from app.services.security_access_service import SecurityAccessService
from app.services.security_audit_service import AuditedSecurityAccessService


class DeploymentSecurityRuntime:
    """One explicit request-security composition; it does not mutate an application."""

    def __init__(
        self,
        *,
        authentication: AvailabilityAwareAuthenticationDependency,
        audited_access_service: AuditedSecurityAccessService,
    ) -> None:
        self._authentication = authentication
        self._audited_access_service = audited_access_service

    def organisation_access(
        self,
        requirement: OrganisationAccessRequirement,
        *,
        request_id_factory: Callable[[], UUID] = uuid4,
    ):
        """Build one unregistered, audited path-scoped route dependency."""

        return build_audited_organisation_access_dependency(
            authentication=self._authentication,
            audited_access_service=self._audited_access_service,
            requirement=requirement,
            request_id_factory=request_id_factory,
        )

    def organisation_header_access(
        self,
        requirement: OrganisationAccessRequirement,
        *,
        request_id_factory: Callable[[], UUID] = uuid4,
    ):
        """Build one unregistered, audited header-scoped route dependency."""

        return build_audited_header_organisation_access_dependency(
            authentication=self._authentication,
            audited_access_service=self._audited_access_service,
            requirement=requirement,
            request_id_factory=request_id_factory,
        )

    def datasheet_export_header_access(
        self,
        policy: RouteSecurityPolicy,
        *,
        request_id_factory: Callable[[], UUID] = uuid4,
    ):
        """Build the unregistered audited JSON/XLSX export dependency."""

        return build_audited_datasheet_export_access_dependency(
            authentication=self._authentication,
            audited_access_service=self._audited_access_service,
            policy=policy,
            request_id_factory=request_id_factory,
        )


def _compose_runtime(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    access_service: SecurityAccessService,
    audit_session_factory: AuditSessionFactory,
) -> DeploymentSecurityRuntime:
    audited_access_service = AuditedSecurityAccessService(
        access_service=access_service,
        audit_repository=DurableSecurityAuditWriter(audit_session_factory),
    )
    return DeploymentSecurityRuntime(
        authentication=authentication,
        audited_access_service=audited_access_service,
    )


def build_deployment_security_runtime(
    *,
    environment: Mapping[str, str],
    session: Session,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
) -> DeploymentSecurityRuntime:
    """Compose an explicit caller-owned read session and isolated audit writer."""

    authentication = build_deployment_bearer_dependency(
        environment=environment,
        open_url=open_url,
    )
    return _compose_runtime(
        authentication=authentication,
        access_service=SecurityAccessService(SecurityRepository(session)),
        audit_session_factory=audit_session_factory,
    )


def build_session_factory_deployment_security_runtime(
    *,
    environment: Mapping[str, str],
    access_session_factory: AccessSessionFactory,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
) -> DeploymentSecurityRuntime:
    """Compose short-lived read sessions and isolated durable audit sessions."""

    authentication = build_deployment_bearer_dependency(
        environment=environment,
        open_url=open_url,
    )
    return _compose_runtime(
        authentication=authentication,
        access_service=SessionFactorySecurityAccessService(access_session_factory),
        audit_session_factory=audit_session_factory,
    )


__all__ = [
    "DeploymentSecurityRuntime",
    "build_deployment_security_runtime",
    "build_session_factory_deployment_security_runtime",
]
