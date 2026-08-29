"""Focused tests for organisation subscription entitlement contracts."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.security.entitlements import ControlledFeature, EntitlementReason, EntitlementRequest, OrganisationEntitlementSnapshot, QuotaGrant, QuotaKind, SubscriptionStatus, evaluate_entitlement


NOW = datetime(2026, 8, 5, 20, 30, tzinfo=UTC)


def snapshot(*, organisation_id=None, status=SubscriptionStatus.ACTIVE, features=(ControlledFeature.ENGINEERING_CALCULATIONS,), quotas=(), effective_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=30)):
    return OrganisationEntitlementSnapshot(snapshot_id=uuid4(), organisation_id=organisation_id or uuid4(), plan_id="controlled-plan", subscription_status=status, features=features, quotas=quotas, effective_at=effective_at, expires_at=expires_at, source_reference="internal subscription record")


def request(organisation_id, *, feature=ControlledFeature.ENGINEERING_CALCULATIONS, quota_kind=None, current_usage=None):
    return EntitlementRequest(organisation_id=organisation_id, feature=feature, request_id=uuid4(), quota_kind=quota_kind, current_usage=current_usage)


def test_granted_feature_is_allowed_for_active_subscription():
    value = snapshot()
    result = evaluate_entitlement(value, request(value.organisation_id), evaluated_at=NOW)
    assert result.allowed is True
    assert result.reason is EntitlementReason.ALLOWED
    assert result.audit_required is True


@pytest.mark.parametrize("status", [SubscriptionStatus.PAST_DUE, SubscriptionStatus.SUSPENDED, SubscriptionStatus.CANCELLED, SubscriptionStatus.EXPIRED])
def test_unusable_subscription_statuses_fail_closed(status):
    value = snapshot(status=status)
    result = evaluate_entitlement(value, request(value.organisation_id), evaluated_at=NOW)
    assert result.allowed is False
    assert result.reason is EntitlementReason.SUBSCRIPTION_NOT_USABLE


def test_trial_subscription_can_use_explicit_grant():
    value = snapshot(status=SubscriptionStatus.TRIAL)
    assert evaluate_entitlement(value, request(value.organisation_id), evaluated_at=NOW).allowed is True


def test_cross_organisation_snapshot_fails_closed():
    value = snapshot()
    result = evaluate_entitlement(value, request(uuid4()), evaluated_at=NOW)
    assert result.allowed is False
    assert result.reason is EntitlementReason.ORGANISATION_MISMATCH


def test_future_snapshot_is_not_effective():
    value = snapshot(effective_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(days=1))
    assert evaluate_entitlement(value, request(value.organisation_id), evaluated_at=NOW).reason is EntitlementReason.SNAPSHOT_NOT_EFFECTIVE


def test_expired_snapshot_is_denied():
    value = snapshot(effective_at=NOW - timedelta(days=2), expires_at=NOW)
    assert evaluate_entitlement(value, request(value.organisation_id), evaluated_at=NOW).reason is EntitlementReason.SNAPSHOT_EXPIRED


def test_ungranted_pdf_export_is_denied_without_inventing_tiers():
    value = snapshot()
    result = evaluate_entitlement(value, request(value.organisation_id, feature=ControlledFeature.DATASHEET_PDF_EXPORT), evaluated_at=NOW)
    assert result.reason is EntitlementReason.FEATURE_NOT_GRANTED


def test_quota_below_limit_is_allowed():
    value = snapshot(quotas=(QuotaGrant(kind=QuotaKind.MONTHLY_CALCULATION_RUNS, limit=10),))
    result = evaluate_entitlement(value, request(value.organisation_id, quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS, current_usage=9), evaluated_at=NOW)
    assert result.allowed is True
    assert result.quota_limit == 10


def test_quota_at_limit_is_denied():
    value = snapshot(quotas=(QuotaGrant(kind=QuotaKind.MONTHLY_CALCULATION_RUNS, limit=10),))
    result = evaluate_entitlement(value, request(value.organisation_id, quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS, current_usage=10), evaluated_at=NOW)
    assert result.reason is EntitlementReason.QUOTA_EXCEEDED


def test_missing_quota_grant_is_denied():
    value = snapshot()
    result = evaluate_entitlement(value, request(value.organisation_id, quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS, current_usage=0), evaluated_at=NOW)
    assert result.reason is EntitlementReason.QUOTA_NOT_GRANTED


def test_partial_quota_request_is_rejected():
    value = snapshot()
    with pytest.raises(ValidationError, match="supplied together"):
        request(value.organisation_id, quota_kind=QuotaKind.MONTHLY_CALCULATION_RUNS)


def test_duplicate_features_and_quotas_are_rejected():
    with pytest.raises(ValidationError, match="features must be unique"):
        snapshot(features=(ControlledFeature.DOCUMENT_INGESTION, ControlledFeature.DOCUMENT_INGESTION))
    with pytest.raises(ValidationError, match="quota kinds must be unique"):
        snapshot(quotas=(QuotaGrant(kind=QuotaKind.STORED_DESIGN_CASES, limit=1), QuotaGrant(kind=QuotaKind.STORED_DESIGN_CASES, limit=2)))


def test_snapshot_expiry_must_follow_effective_time():
    with pytest.raises(ValidationError, match="later than"):
        snapshot(effective_at=NOW, expires_at=NOW)


def test_models_are_frozen_and_forbid_extra_fields():
    value = snapshot()
    with pytest.raises(ValidationError):
        value.plan_id = "forged-plan"
    with pytest.raises(ValidationError):
        OrganisationEntitlementSnapshot(**value.model_dump(), price=0)
