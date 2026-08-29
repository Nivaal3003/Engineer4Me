"""Focused tests for Phase 8 identity and organisation contracts."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.security.identity_models import AuthenticatedPrincipal, IdentityStatus, MembershipStatus, OrganisationMembership, OrganisationRole, Permission


NOW = datetime(2026, 8, 5, 19, 30, tzinfo=UTC)


def membership(*, role=OrganisationRole.ENGINEER, status=MembershipStatus.ACTIVE, organisation_id=None):
    return OrganisationMembership(membership_id=uuid4(), organisation_id=organisation_id or uuid4(), role=role, status=status, joined_at=NOW if status is MembershipStatus.ACTIVE else None)


def principal(*memberships, status=IdentityStatus.ACTIVE):
    return AuthenticatedPrincipal(user_id=uuid4(), email=" Engineer@Example.COM ", display_name=" Site Engineer ", status=status, issuer="engineer4me", subject="subject-1", authenticated_at=NOW, session_id=uuid4(), memberships=memberships)


def test_normalises_identity_text_and_email():
    value = principal()
    assert value.email == "engineer@example.com"
    assert value.display_name == "Site Engineer"


def test_models_are_frozen_and_reject_extra_fields():
    value = membership()
    with pytest.raises(ValidationError):
        value.role = OrganisationRole.OWNER
    with pytest.raises(ValidationError):
        OrganisationMembership(**value.model_dump(), forged=True)


@pytest.mark.parametrize("status", [MembershipStatus.INVITED, MembershipStatus.SUSPENDED, MembershipStatus.REVOKED])
def test_inactive_membership_cannot_have_joined_at(status):
    with pytest.raises(ValidationError, match="only active"):
        OrganisationMembership(membership_id=uuid4(), organisation_id=uuid4(), role=OrganisationRole.ENGINEER, status=status, joined_at=NOW)


def test_active_membership_requires_joined_at():
    with pytest.raises(ValidationError, match="requires joined_at"):
        OrganisationMembership(membership_id=uuid4(), organisation_id=uuid4(), role=OrganisationRole.ENGINEER, status=MembershipStatus.ACTIVE)


def test_engineer_permissions_are_explicit_and_exclude_admin_and_billing():
    value = membership()
    assert Permission.ENGINEERING_EXECUTE in value.permissions
    assert Permission.ENGINEERING_CREATE in value.permissions
    assert Permission.ORGANISATION_MANAGE not in value.permissions
    assert Permission.BILLING_MANAGE not in value.permissions


def test_owner_receives_complete_controlled_permission_set():
    assert membership(role=OrganisationRole.OWNER).permissions == frozenset(Permission)


def test_inactive_identity_fails_closed():
    organisation_id = uuid4()
    value = principal(membership(organisation_id=organisation_id), status=IdentityStatus.SUSPENDED)
    assert value.active_membership(organisation_id) is None
    assert value.has_permission(organisation_id, Permission.ENGINEERING_READ) is False


def test_inactive_membership_has_no_permissions():
    organisation_id = uuid4()
    value = principal(membership(status=MembershipStatus.SUSPENDED, organisation_id=organisation_id))
    assert value.has_permission(organisation_id, Permission.ENGINEERING_READ) is False


def test_cross_organisation_access_fails_closed():
    value = principal(membership())
    assert value.has_permission(uuid4(), Permission.ENGINEERING_READ) is False


def test_duplicate_organisation_memberships_are_rejected():
    organisation_id = uuid4()
    with pytest.raises(ValidationError, match="duplicate organisation"):
        principal(membership(organisation_id=organisation_id), membership(organisation_id=organisation_id))


def test_invalid_email_is_rejected():
    base = principal().model_dump()
    base["email"] = "not-an-email"
    with pytest.raises(ValidationError):
        AuthenticatedPrincipal(**base)


def test_serialization_contains_no_credentials_or_tokens():
    keys = set(principal(membership()).model_dump(mode="json"))
    assert "password" not in keys
    assert "token" not in keys
    assert "secret" not in keys
