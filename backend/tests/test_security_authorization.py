"""Focused tests for fail-closed Phase 8 authorization decisions."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.security.authorization import AuthorizationDecision, AuthorizationReason, AuthorizationRequest, ResourceKind, authorize
from app.security.identity_models import AuthenticatedPrincipal, IdentityStatus, MembershipStatus, OrganisationMembership, OrganisationRole, Permission


NOW = datetime(2026, 8, 5, 20, 0, tzinfo=UTC)


def membership(organisation_id, *, role=OrganisationRole.ENGINEER, status=MembershipStatus.ACTIVE):
    return OrganisationMembership(membership_id=uuid4(), organisation_id=organisation_id, role=role, status=status, joined_at=NOW if status is MembershipStatus.ACTIVE else None)


def principal(*memberships, status=IdentityStatus.ACTIVE):
    return AuthenticatedPrincipal(user_id=uuid4(), email="engineer@example.com", display_name="Engineer", status=status, issuer="engineer4me", subject="subject-120", authenticated_at=NOW, session_id=uuid4(), memberships=memberships)


def request(organisation_id, permission=Permission.ENGINEERING_READ, resource_kind=ResourceKind.ENGINEERING_CASE):
    return AuthorizationRequest(organisation_id=organisation_id, permission=permission, resource_kind=resource_kind, resource_id="case-120", request_id=uuid4())


def test_engineer_can_read_engineering_case():
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id)), request(organisation_id))
    assert result.allowed is True
    assert result.reason is AuthorizationReason.ALLOWED
    assert result.role is OrganisationRole.ENGINEER
    assert result.audit_required is True


def test_suspended_identity_is_denied_before_membership_evaluation():
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id), status=IdentityStatus.SUSPENDED), request(organisation_id))
    assert result.allowed is False
    assert result.reason is AuthorizationReason.IDENTITY_NOT_ACTIVE
    assert result.role is None


def test_missing_cross_tenant_membership_is_denied():
    result = authorize(principal(membership(uuid4())), request(uuid4()))
    assert result.allowed is False
    assert result.reason is AuthorizationReason.MEMBERSHIP_NOT_FOUND


@pytest.mark.parametrize("status", [MembershipStatus.INVITED, MembershipStatus.SUSPENDED, MembershipStatus.REVOKED])
def test_non_active_memberships_are_denied(status):
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id, status=status)), request(organisation_id))
    assert result.allowed is False
    assert result.reason is AuthorizationReason.MEMBERSHIP_NOT_ACTIVE


def test_permission_not_granted_is_explicit():
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id, role=OrganisationRole.READ_ONLY)), request(organisation_id, Permission.ENGINEERING_EXECUTE))
    assert result.allowed is False
    assert result.reason is AuthorizationReason.PERMISSION_NOT_GRANTED
    assert result.role is OrganisationRole.READ_ONLY


def test_owner_can_manage_billing():
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id, role=OrganisationRole.OWNER)), request(organisation_id, Permission.BILLING_MANAGE, ResourceKind.BILLING))
    assert result.allowed is True


def test_billing_administrator_cannot_execute_engineering():
    organisation_id = uuid4()
    result = authorize(principal(membership(organisation_id, role=OrganisationRole.BILLING_ADMINISTRATOR)), request(organisation_id, Permission.ENGINEERING_EXECUTE, ResourceKind.CALCULATION))
    assert result.allowed is False


def test_request_and_decision_are_frozen():
    organisation_id = uuid4()
    value = request(organisation_id)
    with pytest.raises(ValidationError):
        value.permission = Permission.ORGANISATION_MANAGE
    decision = authorize(principal(membership(organisation_id)), value)
    with pytest.raises(ValidationError):
        decision.allowed = False


def test_allowed_decision_cannot_carry_denial_reason():
    organisation_id = uuid4()
    base = authorize(principal(membership(organisation_id)), request(organisation_id)).model_dump()
    base["reason"] = AuthorizationReason.PERMISSION_NOT_GRANTED
    with pytest.raises(ValidationError, match="allowed decision"):
        AuthorizationDecision(**base)


def test_denied_decision_cannot_carry_allowed_reason():
    organisation_id = uuid4()
    base = authorize(principal(), request(organisation_id)).model_dump()
    base["reason"] = AuthorizationReason.ALLOWED
    with pytest.raises(ValidationError, match="denied decision"):
        AuthorizationDecision(**base)


def test_audit_requirement_cannot_be_disabled():
    organisation_id = uuid4()
    base = authorize(principal(membership(organisation_id)), request(organisation_id)).model_dump()
    base["audit_required"] = False
    with pytest.raises(ValidationError, match="must remain auditable"):
        AuthorizationDecision(**base)


def test_invalid_resource_identifier_is_rejected():
    organisation_id = uuid4()
    with pytest.raises(ValidationError):
        AuthorizationRequest(organisation_id=organisation_id, permission=Permission.ENGINEERING_READ, resource_kind=ResourceKind.ENGINEERING_CASE, resource_id="bad id with spaces", request_id=uuid4())


def test_decision_preserves_request_audit_context():
    organisation_id = uuid4()
    value = request(organisation_id, Permission.DOCUMENT_READ, ResourceKind.DOCUMENT)
    result = authorize(principal(membership(organisation_id)), value)
    assert result.request_id == value.request_id
    assert result.organisation_id == value.organisation_id
    assert result.permission == value.permission
    assert result.resource_kind == value.resource_kind
    assert result.resource_id == value.resource_id
