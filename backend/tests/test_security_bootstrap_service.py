"""Focused tests for deterministic, side-effect-free security bootstrap planning."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.security.audit_models import SecurityAuditEventType, SecurityAuditOutcome
from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import ControlledFeature, OrganisationEntitlementSnapshot, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.services.security_bootstrap_service import SecurityBootstrapPlan, build_security_bootstrap_plan


NOW=datetime(2026,8,8,23,0,tzinfo=UTC);ORGANISATION_ID=uuid4();USER_ID=uuid4();MEMBERSHIP_ID=uuid4();BOOTSTRAP_ID=uuid4();REQUEST_ID=uuid4();SNAPSHOT_ID=uuid4()


def command():
    snapshot=OrganisationEntitlementSnapshot(snapshot_id=SNAPSHOT_ID,organisation_id=ORGANISATION_ID,plan_id="reviewed-plan-147",subscription_status=SubscriptionStatus.TRIAL,features=(ControlledFeature.ENGINEERING_CALCULATIONS,),quotas=(),effective_at=NOW,expires_at=NOW+timedelta(days=30),source_reference="approved bootstrap 147")
    return SecurityBootstrapCommand(bootstrap_id=BOOTSTRAP_ID,request_id=REQUEST_ID,user_id=USER_ID,organisation_id=ORGANISATION_ID,membership_id=MEMBERSHIP_ID,email="owner@example.com",display_name="Initial Owner",issuer="https://identity.engineer4me.test",subject="subject-147",organisation_slug="initial-org",organisation_name="Initial Organisation",initial_role=OrganisationRole.OWNER,activated_at=NOW,entitlement=snapshot)


def test_plan_constructs_exact_active_identity_organisation_and_owner_membership():
    plan=build_security_bootstrap_plan(command())
    assert isinstance(plan,SecurityBootstrapPlan)
    assert (plan.user.id,plan.user.email,plan.user.status,plan.user.issuer)==(USER_ID,"owner@example.com","active","https://identity.engineer4me.test")
    assert (plan.organisation.id,plan.organisation.slug,plan.organisation.status)==(ORGANISATION_ID,"initial-org","active")
    assert (plan.membership.id,plan.membership.user_id,plan.membership.organisation_id)==(MEMBERSHIP_ID,USER_ID,ORGANISATION_ID)
    assert plan.membership.role=="owner" and plan.membership.status=="active" and plan.membership.joined_at==NOW


def test_plan_preserves_caller_supplied_entitlement_without_default_features_or_quotas():
    value=command();plan=build_security_bootstrap_plan(value)
    assert plan.entitlement is value.entitlement and plan.entitlement.snapshot_id==SNAPSHOT_ID
    assert plan.entitlement.features==(ControlledFeature.ENGINEERING_CALCULATIONS,) and plan.entitlement.quotas==()


def test_plan_creates_correlated_privacy_minimised_security_state_audit_event():
    event=build_security_bootstrap_plan(command()).audit_event
    assert event.event_id==BOOTSTRAP_ID and event.request_id==REQUEST_ID
    assert event.actor_user_id==USER_ID and event.organisation_id==ORGANISATION_ID
    assert event.event_type is SecurityAuditEventType.SECURITY_STATE_CHANGED and event.outcome is SecurityAuditOutcome.SUCCEEDED
    assert event.reason_code=="initial_security_bootstrap"
    assert event.context=={"membership_role":"owner","entitlement_plan":"reviewed-plan-147","subscription_status":"trial"}


def test_audit_context_does_not_copy_external_identity_or_credentials():
    context=build_security_bootstrap_plan(command()).audit_event.context
    assert not set(context)&{"issuer","subject","email","token","jwt","password","secret","authorization"}


def test_plan_has_no_database_session_repository_or_network_dependency():
    plan=build_security_bootstrap_plan(command())
    assert not hasattr(plan,"session") and not hasattr(plan,"repository") and not hasattr(plan,"open_url")


def test_plan_container_is_frozen():
    plan=build_security_bootstrap_plan(command())
    with pytest.raises(FrozenInstanceError): plan.entitlement=None


def test_repeated_planning_is_deterministic_for_the_same_command():
    value=command();first=build_security_bootstrap_plan(value);second=build_security_bootstrap_plan(value)
    assert first.audit_event==second.audit_event
    assert first.user.id==second.user.id and first.organisation.id==second.organisation.id and first.membership.id==second.membership.id


def test_planning_does_not_mutate_the_frozen_source_command():
    value=command();before=value.model_dump(mode="json");build_security_bootstrap_plan(value);assert value.model_dump(mode="json")==before
