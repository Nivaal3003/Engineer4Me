"""Strict Phase 8 identity and organisation contracts.

These immutable models establish trusted identity vocabulary without providing
authentication, token parsing, persistence, HTTP endpoints, or authorization
side effects.  Caller-supplied actor text remains unverified until later Phase
8 steps bind these contracts to a trusted authentication boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator


IdentityText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
EmailText = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=3, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
SubjectText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class SecurityModel(BaseModel):
    """Frozen, strict base for security-boundary values."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class IdentityStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class MembershipStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class OrganisationRole(StrEnum):
    OWNER = "owner"
    ADMINISTRATOR = "administrator"
    ENGINEER = "engineer"
    TECHNICIAN = "technician"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"
    BILLING_ADMINISTRATOR = "billing_administrator"
    READ_ONLY = "read_only"


class Permission(StrEnum):
    ORGANISATION_READ = "organisation:read"
    ORGANISATION_MANAGE = "organisation:manage"
    MEMBERSHIP_READ = "membership:read"
    MEMBERSHIP_MANAGE = "membership:manage"
    ENGINEERING_READ = "engineering:read"
    ENGINEERING_EXECUTE = "engineering:execute"
    ENGINEERING_CREATE = "engineering:create"
    ENGINEERING_REVIEW = "engineering:review"
    DOCUMENT_READ = "document:read"
    DOCUMENT_INGEST = "document:ingest"
    DATASHEET_EXPORT = "datasheet:export"
    AUDIT_READ = "audit:read"
    BILLING_MANAGE = "billing:manage"


ROLE_PERMISSIONS: dict[OrganisationRole, frozenset[Permission]] = {
    OrganisationRole.OWNER: frozenset(Permission),
    OrganisationRole.ADMINISTRATOR: frozenset(permission for permission in Permission if permission is not Permission.BILLING_MANAGE),
    OrganisationRole.ENGINEER: frozenset({Permission.ORGANISATION_READ, Permission.MEMBERSHIP_READ, Permission.ENGINEERING_READ, Permission.ENGINEERING_EXECUTE, Permission.ENGINEERING_CREATE, Permission.ENGINEERING_REVIEW, Permission.DOCUMENT_READ, Permission.DOCUMENT_INGEST, Permission.DATASHEET_EXPORT}),
    OrganisationRole.TECHNICIAN: frozenset({Permission.ORGANISATION_READ, Permission.ENGINEERING_READ, Permission.ENGINEERING_EXECUTE, Permission.ENGINEERING_CREATE, Permission.DOCUMENT_READ, Permission.DOCUMENT_INGEST}),
    OrganisationRole.REVIEWER: frozenset({Permission.ORGANISATION_READ, Permission.ENGINEERING_READ, Permission.ENGINEERING_REVIEW, Permission.DOCUMENT_READ, Permission.DATASHEET_EXPORT}),
    OrganisationRole.AUDITOR: frozenset({Permission.ORGANISATION_READ, Permission.MEMBERSHIP_READ, Permission.ENGINEERING_READ, Permission.DOCUMENT_READ, Permission.AUDIT_READ}),
    OrganisationRole.BILLING_ADMINISTRATOR: frozenset({Permission.ORGANISATION_READ, Permission.BILLING_MANAGE}),
    OrganisationRole.READ_ONLY: frozenset({Permission.ORGANISATION_READ, Permission.ENGINEERING_READ, Permission.DOCUMENT_READ}),
}


class OrganisationMembership(SecurityModel):
    membership_id: UUID
    organisation_id: UUID
    role: OrganisationRole
    status: MembershipStatus
    joined_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_membership_state(self) -> Self:
        if self.status is MembershipStatus.ACTIVE and self.joined_at is None:
            raise ValueError("active membership requires joined_at")
        if self.status is not MembershipStatus.ACTIVE and self.joined_at is not None:
            raise ValueError("only active membership may contain joined_at")
        return self

    @property
    def permissions(self) -> frozenset[Permission]:
        if self.status is not MembershipStatus.ACTIVE:
            return frozenset()
        return ROLE_PERMISSIONS[self.role]


class AuthenticatedPrincipal(SecurityModel):
    """Trusted identity produced only after successful authentication."""

    user_id: UUID
    email: EmailText
    display_name: IdentityText
    status: IdentityStatus
    issuer: IdentityText
    subject: SubjectText
    authenticated_at: AwareDatetime
    session_id: UUID
    memberships: tuple[OrganisationMembership, ...] = Field(default_factory=tuple, max_length=100)

    @model_validator(mode="after")
    def validate_principal(self) -> Self:
        authenticated_at = self.authenticated_at
        if authenticated_at.utcoffset() is None:
            raise ValueError("authenticated_at must be timezone aware")
        membership_ids = [item.membership_id for item in self.memberships]
        organisation_ids = [item.organisation_id for item in self.memberships]
        if len(membership_ids) != len(set(membership_ids)):
            raise ValueError("membership_id values must be unique")
        if len(organisation_ids) != len(set(organisation_ids)):
            raise ValueError("one principal cannot have duplicate organisation memberships")
        return self

    def active_membership(self, organisation_id: UUID) -> OrganisationMembership | None:
        if self.status is not IdentityStatus.ACTIVE:
            return None
        return next((item for item in self.memberships if item.organisation_id == organisation_id and item.status is MembershipStatus.ACTIVE), None)

    def has_permission(self, organisation_id: UUID, permission: Permission) -> bool:
        membership = self.active_membership(organisation_id)
        return membership is not None and permission in membership.permissions


def utc_now() -> datetime:
    return datetime.now(UTC)
