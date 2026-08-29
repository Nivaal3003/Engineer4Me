"""Focused tests for explicit, business-policy-neutral bootstrap contracts."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import ControlledFeature, OrganisationEntitlementSnapshot, QuotaGrant, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole


NOW = datetime(2026, 8, 8, 22, 0, tzinfo=UTC)
ORGANISATION_ID = uuid4()


def entitlement(**changes):
    values = dict(
        snapshot_id=uuid4(),
        organisation_id=ORGANISATION_ID,
        plan_id="caller-approved-plan",
        subscription_status=SubscriptionStatus.TRIAL,
        features=(ControlledFeature.ENGINEERING_CALCULATIONS,),
        quotas=(QuotaGrant(kind=QuotaKind.MONTHLY_CALCULATION_RUNS, limit=100),),
        effective_at=NOW,
        expires_at=NOW + timedelta(days=30),
        source_reference="approved bootstrap request 146",
    )
    values.update(changes)
    return OrganisationEntitlementSnapshot(**values)


def command(**changes):
    values = dict(
        bootstrap_id=uuid4(),
        request_id=uuid4(),
        user_id=uuid4(),
        organisation_id=ORGANISATION_ID,
        membership_id=uuid4(),
        email="owner@example.com",
        display_name="Initial Owner",
        issuer="https://identity.engineer4me.test",
        subject="provider-subject-146",
        organisation_slug="initial-organisation",
        organisation_name="Initial Organisation",
        initial_role=OrganisationRole.OWNER,
        activated_at=NOW,
        entitlement=entitlement(),
    )
    values.update(changes)
    return SecurityBootstrapCommand(**values)


def test_complete_caller_supplied_bootstrap_contract_is_accepted_and_frozen():
    value=command();assert value.initial_role is OrganisationRole.OWNER and value.entitlement.plan_id=="caller-approved-plan"
    with pytest.raises(ValidationError): value.email="changed@example.com"


def test_identity_and_organisation_text_is_normalized_without_inventing_values():
    value=command(email=" OWNER@EXAMPLE.COM ",organisation_slug=" INITIAL-ORG ",display_name=" Initial Owner ")
    assert value.email=="owner@example.com" and value.organisation_slug=="initial-org" and value.display_name=="Initial Owner"


@pytest.mark.parametrize("role",[OrganisationRole.ADMINISTRATOR,OrganisationRole.ENGINEER,OrganisationRole.BILLING_ADMINISTRATOR,OrganisationRole.READ_ONLY])
def test_initial_membership_must_be_explicit_owner(role):
    with pytest.raises(ValidationError,match="organisation owner"): command(initial_role=role)


def test_entitlement_must_match_bootstrap_organisation():
    with pytest.raises(ValidationError,match="organisation mismatch"): command(entitlement=entitlement(organisation_id=uuid4()))


@pytest.mark.parametrize("status",[SubscriptionStatus.PAST_DUE,SubscriptionStatus.SUSPENDED,SubscriptionStatus.CANCELLED,SubscriptionStatus.EXPIRED])
def test_unusable_commercial_snapshot_is_rejected_without_default_policy(status):
    with pytest.raises(ValidationError,match="caller-approved usable entitlement"): command(entitlement=entitlement(subscription_status=status))


def test_future_or_expired_entitlement_is_rejected_at_activation():
    with pytest.raises(ValidationError,match="after activation"): command(entitlement=entitlement(effective_at=NOW+timedelta(seconds=1),expires_at=NOW+timedelta(days=1)))
    with pytest.raises(ValidationError,match="remain usable"): command(entitlement=entitlement(effective_at=NOW-timedelta(days=2),expires_at=NOW))


def test_all_security_and_correlation_identifiers_must_be_unique():
    duplicate=uuid4()
    with pytest.raises(ValidationError,match="identifiers must be unique"): command(bootstrap_id=duplicate,request_id=duplicate)


@pytest.mark.parametrize("slug",["A","-invalid","invalid-","invalid_slug","contains space"])
def test_organisation_slug_is_strict_and_url_safe(slug):
    with pytest.raises(ValidationError): command(organisation_slug=slug)


def test_unknown_fields_and_untyped_values_fail_closed():
    with pytest.raises(ValidationError): command(unreviewed_grant=True)
    with pytest.raises(ValidationError): command(activated_at="2026-08-08T22:00:00Z")


def test_serialized_contract_contains_no_token_secret_or_credential_field():
    keys=set(command().model_dump(mode="json"))
    assert not keys & {"token","jwt","password","secret","credential","authorization"}
