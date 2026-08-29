"""Focused tests for trusted security access orchestration."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.security.authorization import AuthorizationReason, ResourceKind
from app.security.entitlements import ControlledFeature, EntitlementReason, OrganisationEntitlementSnapshot, SubscriptionStatus
from app.security.identity_models import Permission
from app.services.security_access_service import AccessOutcomeReason, SecurityAccessCommand, SecurityAccessService, TrustedAuthenticationContext


NOW=datetime(2026,8,5,22,30,tzinfo=UTC)


class Repository:
    def __init__(self,user=None,membership=None,entitlement=None): self.user=user;self.membership_value=membership;self.entitlement_value=entitlement;self.entitlement_calls=[]
    def user_by_external_identity(self,*,issuer,subject): return self.user if self.user is not None and self.user.issuer==issuer and self.user.subject==subject else None
    def active_membership_contract(self,*,user_id,organisation_id): return self.membership_value if self.membership_value is not None and self.membership_value.organisation_id==organisation_id else None
    def current_entitlement(self,*,organisation_id,effective_at=None): self.entitlement_calls.append((organisation_id,effective_at));return self.entitlement_value if self.entitlement_value is not None and self.entitlement_value.organisation_id==organisation_id else None


class User:
    def __init__(self,status="active"): self.id=uuid4();self.email="engineer@example.com";self.display_name="Engineer";self.status=status;self.issuer="engineer4me";self.subject="subject-126"


def membership(org_id,role="engineer"):
    from app.security.identity_models import MembershipStatus,OrganisationMembership,OrganisationRole
    return OrganisationMembership(membership_id=uuid4(),organisation_id=org_id,role=OrganisationRole(role),status=MembershipStatus.ACTIVE,joined_at=NOW)


def entitlement(org_id,features=(ControlledFeature.ENGINEERING_CALCULATIONS,)):
    return OrganisationEntitlementSnapshot(snapshot_id=uuid4(),organisation_id=org_id,plan_id="controlled-plan",subscription_status=SubscriptionStatus.ACTIVE,features=features,effective_at=NOW-timedelta(days=1),expires_at=NOW+timedelta(days=1),source_reference="trusted record")


def authentication(): return TrustedAuthenticationContext(issuer="engineer4me",subject="subject-126",authenticated_at=NOW,session_id=uuid4())
def command(org_id,*,permission=Permission.ENGINEERING_READ,feature=None): return SecurityAccessCommand(request_id=uuid4(),organisation_id=org_id,permission=permission,resource_kind=ResourceKind.ENGINEERING_CASE,resource_id="case-126",feature=feature)


def test_unknown_identity_is_denied_without_repository_follow_on():
    repo=Repository();result=SecurityAccessService(repo).evaluate(authentication(),command(uuid4()))
    assert result.reason is AccessOutcomeReason.IDENTITY_NOT_FOUND
    assert result.authorization is None and result.entitlement is None


def test_inactive_identity_is_denied():
    org=uuid4();result=SecurityAccessService(Repository(user=User("suspended"),membership=membership(org))).evaluate(authentication(),command(org))
    assert result.reason is AccessOutcomeReason.IDENTITY_NOT_ACTIVE
    assert result.authorization.reason is AuthorizationReason.IDENTITY_NOT_ACTIVE


def test_missing_cross_tenant_membership_is_denied():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(uuid4()))).evaluate(authentication(),command(org))
    assert result.reason is AccessOutcomeReason.AUTHORIZATION_DENIED
    assert result.authorization.allowed is False


def test_role_permission_denial_stops_before_entitlement_lookup():
    org=uuid4();repo=Repository(user=User(),membership=membership(org,"read_only"),entitlement=entitlement(org));result=SecurityAccessService(repo).evaluate(authentication(),command(org,permission=Permission.ENGINEERING_EXECUTE,feature=ControlledFeature.ENGINEERING_CALCULATIONS))
    assert result.reason is AccessOutcomeReason.AUTHORIZATION_DENIED
    assert repo.entitlement_calls == []


def test_authorized_non_entitled_operation_is_allowed():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(org))).evaluate(authentication(),command(org))
    assert result.allowed is True
    assert result.entitlement is None


def test_missing_entitlement_is_denied_after_authorization():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(org))).evaluate(authentication(),command(org,feature=ControlledFeature.ENGINEERING_CALCULATIONS))
    assert result.reason is AccessOutcomeReason.ENTITLEMENT_NOT_FOUND
    assert result.authorization.allowed is True


def test_ungranted_feature_is_denied():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(org),entitlement=entitlement(org))).evaluate(authentication(),command(org,feature=ControlledFeature.DATASHEET_PDF_EXPORT))
    assert result.reason is AccessOutcomeReason.ENTITLEMENT_DENIED
    assert result.entitlement.reason is EntitlementReason.FEATURE_NOT_GRANTED


def test_rbac_and_entitlement_must_both_allow():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(org),entitlement=entitlement(org))).evaluate(authentication(),command(org,feature=ControlledFeature.ENGINEERING_CALCULATIONS))
    assert result.allowed is True
    assert result.authorization.allowed is True
    assert result.entitlement.allowed is True
    assert result.audit_required is True


def test_quota_fields_require_feature_and_complete_pair():
    org=uuid4();base=dict(request_id=uuid4(),organisation_id=org,permission=Permission.ENGINEERING_READ,resource_kind=ResourceKind.CALCULATION)
    from app.security.entitlements import QuotaKind
    with pytest.raises(ValidationError,match="requires a controlled feature"): SecurityAccessCommand(**base,quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS,current_usage=0)
    with pytest.raises(ValidationError,match="supplied together"): SecurityAccessCommand(**base,feature=ControlledFeature.ENGINEERING_CALCULATIONS,quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS)


def test_outcomes_are_frozen_and_request_correlated():
    org=uuid4();result=SecurityAccessService(Repository(user=User(),membership=membership(org))).evaluate(authentication(),command(org))
    assert result.authorization.request_id == result.request_id
    with pytest.raises(ValidationError): result.allowed=False
