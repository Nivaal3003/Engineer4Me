"""Tenant-explicit repository for Phase 8 security persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_identity import SecurityEntitlementSnapshot, SecurityOrganisation, SecurityOrganisationMembership, SecurityUser
from app.security.entitlements import ControlledFeature, OrganisationEntitlementSnapshot, QuotaGrant, QuotaKind, SubscriptionStatus
from app.security.identity_models import IdentityStatus, MembershipStatus, OrganisationMembership, OrganisationRole


class SecurityPersistenceConflictError(RuntimeError):
    """Raised when a security uniqueness or integrity boundary rejects a write."""


class SecurityPersistenceCorruptionError(RuntimeError):
    """Raised when persisted security content cannot satisfy trusted contracts."""


class SecurityRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_user(self, user: SecurityUser) -> SecurityUser:
        return self._add(user)

    def add_organisation(self, organisation: SecurityOrganisation) -> SecurityOrganisation:
        return self._add(organisation)

    def add_membership(self, membership: SecurityOrganisationMembership) -> SecurityOrganisationMembership:
        return self._add(membership)

    def _add(self, value):
        try:
            self._session.add(value)
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise SecurityPersistenceConflictError("security record violates a persistence constraint") from exc
        return value

    def user_by_external_identity(self, *, issuer: str, subject: str) -> SecurityUser | None:
        statement = select(SecurityUser).where(SecurityUser.issuer == issuer, SecurityUser.subject == subject)
        return self._session.scalar(statement)

    def organisation(self, organisation_id: UUID) -> SecurityOrganisation | None:
        return self._session.get(SecurityOrganisation, organisation_id)

    def membership(self, *, user_id: UUID, organisation_id: UUID) -> SecurityOrganisationMembership | None:
        statement = select(SecurityOrganisationMembership).where(SecurityOrganisationMembership.user_id == user_id, SecurityOrganisationMembership.organisation_id == organisation_id)
        return self._session.scalar(statement)

    def active_membership_contract(self, *, user_id: UUID, organisation_id: UUID) -> OrganisationMembership | None:
        row = self.membership(user_id=user_id, organisation_id=organisation_id)
        if row is None or row.status != MembershipStatus.ACTIVE.value:
            return None
        try:
            joined_at = row.joined_at
            if joined_at is not None and joined_at.tzinfo is None:
                joined_at = joined_at.replace(tzinfo=UTC)
            return OrganisationMembership(membership_id=row.id, organisation_id=row.organisation_id, role=OrganisationRole(row.role), status=MembershipStatus(row.status), joined_at=joined_at)
        except (ValueError, TypeError) as exc:
            raise SecurityPersistenceCorruptionError("persisted membership failed trusted contract validation") from exc

    def append_entitlement(self, snapshot: OrganisationEntitlementSnapshot) -> SecurityEntitlementSnapshot:
        maximum = self._session.scalar(select(func.max(SecurityEntitlementSnapshot.sequence_number)).where(SecurityEntitlementSnapshot.organisation_id == snapshot.organisation_id))
        row = SecurityEntitlementSnapshot(
            id=snapshot.snapshot_id,
            organisation_id=snapshot.organisation_id,
            sequence_number=(maximum or 0) + 1,
            plan_id=snapshot.plan_id,
            subscription_status=snapshot.subscription_status.value,
            features=[item.value for item in snapshot.features],
            quotas=[item.model_dump(mode="json") for item in snapshot.quotas],
            effective_at=snapshot.effective_at,
            expires_at=snapshot.expires_at,
            source_reference=snapshot.source_reference,
        )
        return self._add(row)

    def current_entitlement(self, *, organisation_id: UUID, effective_at: datetime | None = None) -> OrganisationEntitlementSnapshot | None:
        when = effective_at or datetime.now(UTC)
        statement: Select = select(SecurityEntitlementSnapshot).where(
            SecurityEntitlementSnapshot.organisation_id == organisation_id,
            SecurityEntitlementSnapshot.effective_at <= when,
            (SecurityEntitlementSnapshot.expires_at.is_(None) | (SecurityEntitlementSnapshot.expires_at > when)),
        ).order_by(SecurityEntitlementSnapshot.sequence_number.desc()).limit(1)
        row = self._session.scalar(statement)
        if row is None:
            return None
        try:
            effective_value = row.effective_at
            expires_value = row.expires_at
            if effective_value.tzinfo is None:
                effective_value = effective_value.replace(tzinfo=UTC)
            if expires_value is not None and expires_value.tzinfo is None:
                expires_value = expires_value.replace(tzinfo=UTC)
            return OrganisationEntitlementSnapshot(
                snapshot_id=row.id,
                organisation_id=row.organisation_id,
                plan_id=row.plan_id,
                subscription_status=SubscriptionStatus(row.subscription_status),
                features=tuple(ControlledFeature(item) for item in row.features),
                quotas=tuple(
                    QuotaGrant(
                        kind=QuotaKind(item["kind"]),
                        limit=item["limit"],
                    )
                    for item in row.quotas
                ),
                effective_at=effective_value,
                expires_at=expires_value,
                source_reference=row.source_reference,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise SecurityPersistenceCorruptionError("persisted entitlement failed trusted contract validation") from exc

    def identity_status(self, user_id: UUID) -> IdentityStatus | None:
        value = self._session.scalar(select(SecurityUser.status).where(SecurityUser.id == user_id))
        if value is None:
            return None
        try:
            return IdentityStatus(value)
        except ValueError as exc:
            raise SecurityPersistenceCorruptionError("persisted identity status is invalid") from exc
