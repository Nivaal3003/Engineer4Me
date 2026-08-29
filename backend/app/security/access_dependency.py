"""Organisation-scoped FastAPI access enforcement for trusted Phase 8 policy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, Header, HTTPException, Path, status

from app.security.authentication_availability import AvailabilityAwareAuthenticationDependency
from app.security.authorization import ResourceIdentifier, ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission, SecurityModel
from app.services.security_access_service import SecurityAccessCommand, SecurityAccessOutcome, SecurityAccessService, TrustedAuthenticationContext


ORGANISATION_HEADER_NAME = "X-Engineer4Me-Organisation-ID"


class OrganisationAccessRequirement(SecurityModel):
    permission: Permission
    resource_kind: ResourceKind
    resource_id: ResourceIdentifier | None = None
    feature: ControlledFeature | None = None


RequestIDFactory = Callable[[], UUID]


def _evaluate_access(
    *,
    organisation_id: UUID,
    authentication_context: TrustedAuthenticationContext,
    access_service: SecurityAccessService,
    requirement: OrganisationAccessRequirement,
    request_id_factory: RequestIDFactory,
) -> SecurityAccessOutcome:
    outcome = access_service.evaluate(
        authentication_context,
        SecurityAccessCommand(
            request_id=request_id_factory(),
            organisation_id=organisation_id,
            permission=requirement.permission,
            resource_kind=requirement.resource_kind,
            resource_id=requirement.resource_id,
            feature=requirement.feature,
        ),
    )
    if not outcome.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return outcome


def build_organisation_access_dependency(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    access_service: SecurityAccessService,
    requirement: OrganisationAccessRequirement,
    request_id_factory: RequestIDFactory = uuid4,
):
    """Build one explicit path-scoped route policy without mutating a router."""

    def enforce(
        organisation_id: Annotated[UUID, Path()],
        authentication_context: TrustedAuthenticationContext = Depends(authentication),
    ) -> SecurityAccessOutcome:
        return _evaluate_access(
            organisation_id=organisation_id,
            authentication_context=authentication_context,
            access_service=access_service,
            requirement=requirement,
            request_id_factory=request_id_factory,
        )

    return enforce


def build_header_organisation_access_dependency(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    access_service: SecurityAccessService,
    requirement: OrganisationAccessRequirement,
    request_id_factory: RequestIDFactory = uuid4,
):
    """Build an explicit header-scoped policy for existing non-tenant URLs."""

    def enforce(
        organisation_id: Annotated[UUID, Header(alias=ORGANISATION_HEADER_NAME)],
        authentication_context: TrustedAuthenticationContext = Depends(authentication),
    ) -> SecurityAccessOutcome:
        return _evaluate_access(
            organisation_id=organisation_id,
            authentication_context=authentication_context,
            access_service=access_service,
            requirement=requirement,
            request_id_factory=request_id_factory,
        )

    return enforce
