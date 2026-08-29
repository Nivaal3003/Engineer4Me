"""Explicit FastAPI composition for access decisions that must be audit-persisted."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

from app.security.access_dependency import OrganisationAccessRequirement, build_header_organisation_access_dependency, build_organisation_access_dependency
from app.security.authentication_availability import AvailabilityAwareAuthenticationDependency
from app.services.security_audit_service import AuditedSecurityAccessService


RequestIDFactory = Callable[[], UUID]


def _require_audited_service(audited_access_service: AuditedSecurityAccessService) -> None:
    if not isinstance(audited_access_service, AuditedSecurityAccessService):
        raise TypeError("audited organisation access requires AuditedSecurityAccessService")


def build_audited_organisation_access_dependency(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    audited_access_service: AuditedSecurityAccessService,
    requirement: OrganisationAccessRequirement,
    request_id_factory: RequestIDFactory = uuid4,
):
    """Build an unregistered path-scoped dependency with durable audit required."""

    _require_audited_service(audited_access_service)
    return build_organisation_access_dependency(
        authentication=authentication,
        access_service=audited_access_service,
        requirement=requirement,
        request_id_factory=request_id_factory,
    )


def build_audited_header_organisation_access_dependency(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    audited_access_service: AuditedSecurityAccessService,
    requirement: OrganisationAccessRequirement,
    request_id_factory: RequestIDFactory = uuid4,
):
    """Build an unregistered header-scoped dependency with durable audit required."""

    _require_audited_service(audited_access_service)
    return build_header_organisation_access_dependency(
        authentication=authentication,
        access_service=audited_access_service,
        requirement=requirement,
        request_id_factory=request_id_factory,
    )
