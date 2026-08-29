"""Strict caller-supplied contracts for initial security bootstrap planning."""

from __future__ import annotations

from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, StringConstraints, field_validator, model_validator

from app.security.entitlements import OrganisationEntitlementSnapshot, SubscriptionStatus
from app.security.identity_models import EmailText, IdentityText, OrganisationRole, SecurityModel, SubjectText


OrganisationSlug = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=2,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
    ),
]


class SecurityBootstrapCommand(SecurityModel):
    """Complete reviewed inputs; this contract performs no persistence."""

    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    email: EmailText
    display_name: IdentityText
    issuer: IdentityText
    subject: SubjectText
    organisation_slug: OrganisationSlug
    organisation_name: IdentityText
    initial_role: OrganisationRole
    activated_at: AwareDatetime
    entitlement: OrganisationEntitlementSnapshot

    @field_validator("organisation_slug", mode="before")
    @classmethod
    def normalize_organisation_slug(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def validate_bootstrap(self) -> Self:
        identifiers = (
            self.bootstrap_id,
            self.request_id,
            self.user_id,
            self.organisation_id,
            self.membership_id,
            self.entitlement.snapshot_id,
        )
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("bootstrap identifiers must be unique")
        if self.initial_role is not OrganisationRole.OWNER:
            raise ValueError("initial bootstrap membership must be organisation owner")
        if self.entitlement.organisation_id != self.organisation_id:
            raise ValueError("bootstrap entitlement organisation mismatch")
        if self.entitlement.subscription_status not in {SubscriptionStatus.TRIAL, SubscriptionStatus.ACTIVE}:
            raise ValueError("bootstrap requires a caller-approved usable entitlement snapshot")
        if self.entitlement.effective_at > self.activated_at:
            raise ValueError("bootstrap entitlement cannot become effective after activation")
        if self.entitlement.expires_at is not None and self.entitlement.expires_at <= self.activated_at:
            raise ValueError("bootstrap entitlement must remain usable at activation")
        return self
