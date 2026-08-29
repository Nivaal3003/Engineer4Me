"""Pure, fail-closed Phase 8 authorization policy evaluation.

This module has no database, HTTP, token, session, or logging side effects.
Every request produces a structured decision suitable for later audit storage.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from app.security.identity_models import (
    AuthenticatedPrincipal,
    IdentityStatus,
    MembershipStatus,
    OrganisationRole,
    Permission,
    SecurityModel,
)


POLICY_VERSION = "1.0.0"
ResourceIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=300,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    ),
]


class ResourceKind(StrEnum):
    ORGANISATION = "organisation"
    MEMBERSHIP = "membership"
    ENGINEERING_CASE = "engineering_case"
    CALCULATION = "calculation"
    DOCUMENT = "document"
    DATASHEET = "datasheet"
    AUDIT_EVENT = "audit_event"
    BILLING = "billing"


class AuthorizationReason(StrEnum):
    ALLOWED = "allowed"
    IDENTITY_NOT_ACTIVE = "identity_not_active"
    MEMBERSHIP_NOT_FOUND = "membership_not_found"
    MEMBERSHIP_NOT_ACTIVE = "membership_not_active"
    PERMISSION_NOT_GRANTED = "permission_not_granted"


class AuthorizationRequest(SecurityModel):
    organisation_id: UUID
    permission: Permission
    resource_kind: ResourceKind
    resource_id: ResourceIdentifier | None = None
    request_id: UUID


class AuthorizationDecision(SecurityModel):
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    permission: Permission
    resource_kind: ResourceKind
    resource_id: ResourceIdentifier | None = None
    allowed: bool
    reason: AuthorizationReason
    role: OrganisationRole | None = None
    policy_version: str = Field(default=POLICY_VERSION, pattern=r"^\d+\.\d+\.\d+$")
    audit_required: bool = True

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.allowed:
            if self.reason is not AuthorizationReason.ALLOWED:
                raise ValueError("allowed decision requires allowed reason")
            if self.role is None:
                raise ValueError("allowed decision requires an active role")
        else:
            if self.reason is AuthorizationReason.ALLOWED:
                raise ValueError("denied decision cannot use allowed reason")
            if self.reason in {
                AuthorizationReason.IDENTITY_NOT_ACTIVE,
                AuthorizationReason.MEMBERSHIP_NOT_FOUND,
            } and self.role is not None:
                raise ValueError("decision without an active membership cannot expose a role")
        if not self.audit_required:
            raise ValueError("authorization decisions must remain auditable")
        return self


def _decision(
    principal: AuthenticatedPrincipal,
    request: AuthorizationRequest,
    *,
    allowed: bool,
    reason: AuthorizationReason,
    role: OrganisationRole | None = None,
) -> AuthorizationDecision:
    return AuthorizationDecision(
        request_id=request.request_id,
        user_id=principal.user_id,
        organisation_id=request.organisation_id,
        permission=request.permission,
        resource_kind=request.resource_kind,
        resource_id=request.resource_id,
        allowed=allowed,
        reason=reason,
        role=role,
    )


def authorize(
    principal: AuthenticatedPrincipal,
    request: AuthorizationRequest,
) -> AuthorizationDecision:
    """Evaluate one organisation-scoped request without implicit access."""

    if principal.status is not IdentityStatus.ACTIVE:
        return _decision(
            principal,
            request,
            allowed=False,
            reason=AuthorizationReason.IDENTITY_NOT_ACTIVE,
        )

    membership = next(
        (
            item
            for item in principal.memberships
            if item.organisation_id == request.organisation_id
        ),
        None,
    )
    if membership is None:
        return _decision(
            principal,
            request,
            allowed=False,
            reason=AuthorizationReason.MEMBERSHIP_NOT_FOUND,
        )
    if membership.status is not MembershipStatus.ACTIVE:
        return _decision(
            principal,
            request,
            allowed=False,
            reason=AuthorizationReason.MEMBERSHIP_NOT_ACTIVE,
            role=membership.role,
        )
    if request.permission not in membership.permissions:
        return _decision(
            principal,
            request,
            allowed=False,
            reason=AuthorizationReason.PERMISSION_NOT_GRANTED,
            role=membership.role,
        )
    return _decision(
        principal,
        request,
        allowed=True,
        reason=AuthorizationReason.ALLOWED,
        role=membership.role,
    )
