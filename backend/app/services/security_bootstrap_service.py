"""Pure construction of a correlated initial security bootstrap plan."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.security_identity import SecurityOrganisation, SecurityOrganisationMembership, SecurityUser
from app.security.audit_models import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome
from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import OrganisationEntitlementSnapshot
from app.security.identity_models import IdentityStatus, MembershipStatus


@dataclass(frozen=True, slots=True)
class SecurityBootstrapPlan:
    user: SecurityUser
    organisation: SecurityOrganisation
    membership: SecurityOrganisationMembership
    entitlement: OrganisationEntitlementSnapshot
    audit_event: SecurityAuditEvent


def build_security_bootstrap_plan(command: SecurityBootstrapCommand) -> SecurityBootstrapPlan:
    """Translate only validated caller inputs; perform no I/O or implicit grants."""

    user = SecurityUser(
        id=command.user_id,
        email=command.email,
        display_name=command.display_name,
        status=IdentityStatus.ACTIVE.value,
        issuer=command.issuer,
        subject=command.subject,
    )
    organisation = SecurityOrganisation(
        id=command.organisation_id,
        slug=command.organisation_slug,
        name=command.organisation_name,
        status="active",
    )
    membership = SecurityOrganisationMembership(
        id=command.membership_id,
        user_id=command.user_id,
        organisation_id=command.organisation_id,
        role=command.initial_role.value,
        status=MembershipStatus.ACTIVE.value,
        joined_at=command.activated_at,
    )
    audit_event = SecurityAuditEvent(
        event_id=command.bootstrap_id,
        occurred_at=command.activated_at,
        event_type=SecurityAuditEventType.SECURITY_STATE_CHANGED,
        outcome=SecurityAuditOutcome.SUCCEEDED,
        reason_code="initial_security_bootstrap",
        request_id=command.request_id,
        actor_user_id=command.user_id,
        organisation_id=command.organisation_id,
        context={
            "membership_role": command.initial_role.value,
            "entitlement_plan": command.entitlement.plan_id,
            "subscription_status": command.entitlement.subscription_status.value,
        },
    )
    return SecurityBootstrapPlan(
        user=user,
        organisation=organisation,
        membership=membership,
        entitlement=command.entitlement,
        audit_event=audit_event,
    )
