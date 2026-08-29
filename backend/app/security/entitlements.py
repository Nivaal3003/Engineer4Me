"""Strict, business-policy-neutral organisation entitlement contracts.

Entitlements answer whether an organisation's controlled subscription snapshot
permits a capability.  They do not authenticate users, authorize roles, charge
customers, invent pricing tiers, or call billing providers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictInt, StringConstraints, model_validator

from app.security.identity_models import SecurityModel


PlanIdentifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
SourceReference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=300)]


class SubscriptionStatus(StrEnum):
    TRIAL = "trial"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ControlledFeature(StrEnum):
    ENGINEERING_CALCULATIONS = "engineering_calculations"
    DESIGN_PERSISTENCE = "design_persistence"
    DOCUMENT_INGESTION = "document_ingestion"
    DATASHEET_JSON_EXPORT = "datasheet_json_export"
    DATASHEET_XLSX_EXPORT = "datasheet_xlsx_export"
    DATASHEET_PDF_EXPORT = "datasheet_pdf_export"
    OFFLINE_CASE_SYNC = "offline_case_sync"
    ENTERPRISE_INTEGRATIONS = "enterprise_integrations"
    SECURITY_AUDIT_EXPORT = "security_audit_export"


class QuotaKind(StrEnum):
    MONTHLY_CALCULATION_RUNS = "monthly_calculation_runs"
    MONTHLY_DOCUMENT_INGESTIONS = "monthly_document_ingestions"
    MONTHLY_DATASHEET_EXPORTS = "monthly_datasheet_exports"
    STORED_DESIGN_CASES = "stored_design_cases"
    ORGANISATION_MEMBERS = "organisation_members"


class EntitlementReason(StrEnum):
    ALLOWED = "allowed"
    ORGANISATION_MISMATCH = "organisation_mismatch"
    SUBSCRIPTION_NOT_USABLE = "subscription_not_usable"
    SNAPSHOT_NOT_EFFECTIVE = "snapshot_not_effective"
    SNAPSHOT_EXPIRED = "snapshot_expired"
    FEATURE_NOT_GRANTED = "feature_not_granted"
    QUOTA_NOT_GRANTED = "quota_not_granted"
    QUOTA_EXCEEDED = "quota_exceeded"


class QuotaGrant(SecurityModel):
    kind: QuotaKind
    limit: StrictInt = Field(ge=1, le=2_147_483_647)


class OrganisationEntitlementSnapshot(SecurityModel):
    snapshot_id: UUID
    organisation_id: UUID
    plan_id: PlanIdentifier
    subscription_status: SubscriptionStatus
    features: tuple[ControlledFeature, ...] = Field(default_factory=tuple, max_length=100)
    quotas: tuple[QuotaGrant, ...] = Field(default_factory=tuple, max_length=100)
    effective_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    source_reference: SourceReference

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.effective_at:
            raise ValueError("expires_at must be later than effective_at")
        if len(self.features) != len(set(self.features)):
            raise ValueError("features must be unique")
        quota_kinds = [item.kind for item in self.quotas]
        if len(quota_kinds) != len(set(quota_kinds)):
            raise ValueError("quota kinds must be unique")
        return self


class EntitlementRequest(SecurityModel):
    organisation_id: UUID
    feature: ControlledFeature
    request_id: UUID
    quota_kind: QuotaKind | None = None
    current_usage: StrictInt | None = Field(default=None, ge=0, le=2_147_483_647)

    @model_validator(mode="after")
    def validate_quota_request(self) -> Self:
        if (self.quota_kind is None) != (self.current_usage is None):
            raise ValueError("quota_kind and current_usage must be supplied together")
        return self


class EntitlementDecision(SecurityModel):
    request_id: UUID
    organisation_id: UUID
    snapshot_id: UUID
    plan_id: PlanIdentifier
    feature: ControlledFeature
    allowed: bool
    reason: EntitlementReason
    quota_kind: QuotaKind | None = None
    quota_limit: StrictInt | None = None
    current_usage: StrictInt | None = None
    audit_required: bool = True

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.allowed != (self.reason is EntitlementReason.ALLOWED):
            raise ValueError("allowed state and reason are inconsistent")
        if not self.audit_required:
            raise ValueError("entitlement decisions must remain auditable")
        return self


def evaluate_entitlement(snapshot: OrganisationEntitlementSnapshot, request: EntitlementRequest, *, evaluated_at: datetime | None = None) -> EntitlementDecision:
    """Evaluate one trusted snapshot with no implicit or default grant."""

    when = evaluated_at or datetime.now(UTC)
    common = dict(request_id=request.request_id, organisation_id=request.organisation_id, snapshot_id=snapshot.snapshot_id, plan_id=snapshot.plan_id, feature=request.feature, quota_kind=request.quota_kind, current_usage=request.current_usage)
    if snapshot.organisation_id != request.organisation_id:
        return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.ORGANISATION_MISMATCH)
    if snapshot.subscription_status not in {SubscriptionStatus.TRIAL, SubscriptionStatus.ACTIVE}:
        return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.SUBSCRIPTION_NOT_USABLE)
    if when < snapshot.effective_at:
        return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.SNAPSHOT_NOT_EFFECTIVE)
    if snapshot.expires_at is not None and when >= snapshot.expires_at:
        return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.SNAPSHOT_EXPIRED)
    if request.feature not in snapshot.features:
        return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.FEATURE_NOT_GRANTED)
    if request.quota_kind is not None:
        grant = next((item for item in snapshot.quotas if item.kind is request.quota_kind), None)
        if grant is None:
            return EntitlementDecision(**common, allowed=False, reason=EntitlementReason.QUOTA_NOT_GRANTED)
        if request.current_usage is not None and request.current_usage >= grant.limit:
            return EntitlementDecision(**common, quota_limit=grant.limit, allowed=False, reason=EntitlementReason.QUOTA_EXCEEDED)
        return EntitlementDecision(**common, quota_limit=grant.limit, allowed=True, reason=EntitlementReason.ALLOWED)
    return EntitlementDecision(**common, allowed=True, reason=EntitlementReason.ALLOWED)
