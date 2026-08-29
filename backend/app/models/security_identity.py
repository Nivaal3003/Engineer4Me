"""Phase 8 SQLAlchemy identity, organisation, and entitlement records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, PrimaryKeyConstraint, String, UniqueConstraint, Uuid, event, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


_JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class ImmutableSecurityRecordError(RuntimeError):
    """Raised when an append-only security record is changed or deleted."""


class SecurityUser(Base):
    __tablename__ = "security_users"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_security_users"),
        UniqueConstraint("issuer", "subject", name="uq_security_users_issuer_subject"),
        CheckConstraint("length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))", name="ck_security_users_email"),
        CheckConstraint("length(display_name) BETWEEN 1 AND 300 AND display_name = trim(display_name)", name="ck_security_users_display_name"),
        CheckConstraint("status IN ('pending','active','suspended','disabled')", name="ck_security_users_status"),
        CheckConstraint("length(issuer) BETWEEN 1 AND 300 AND issuer = trim(issuer)", name="ck_security_users_issuer"),
        CheckConstraint("length(subject) BETWEEN 1 AND 500 AND subject = trim(subject)", name="ck_security_users_subject"),
        CheckConstraint("updated_at >= created_at", name="ck_security_users_timestamp_order"),
        Index("uq_security_users_email_ci", text("lower(email)"), unique=True),
        Index("ix_security_users_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    issuer: Mapped[str] = mapped_column(String(300), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class SecurityOrganisation(Base):
    __tablename__ = "security_organisations"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_security_organisations"),
        CheckConstraint("length(slug) BETWEEN 2 AND 100 AND slug = lower(trim(slug))", name="ck_security_organisations_slug"),
        CheckConstraint("length(name) BETWEEN 2 AND 300 AND name = trim(name)", name="ck_security_organisations_name"),
        CheckConstraint("status IN ('active','suspended','disabled')", name="ck_security_organisations_status"),
        CheckConstraint("updated_at >= created_at", name="ck_security_organisations_timestamp_order"),
        Index("uq_security_organisations_slug_ci", text("lower(slug)"), unique=True),
        Index("ix_security_organisations_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), default=uuid4)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class SecurityOrganisationMembership(Base):
    __tablename__ = "security_organisation_memberships"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_security_organisation_memberships"),
        UniqueConstraint("user_id", "organisation_id", name="uq_security_memberships_user_organisation"),
        CheckConstraint("role IN ('owner','administrator','engineer','technician','reviewer','auditor','billing_administrator','read_only')", name="ck_security_memberships_role"),
        CheckConstraint("status IN ('invited','active','suspended','revoked')", name="ck_security_memberships_status"),
        CheckConstraint("((status = 'active' AND joined_at IS NOT NULL) OR (status <> 'active' AND joined_at IS NULL))", name="ck_security_memberships_joined_state"),
        CheckConstraint("updated_at >= created_at", name="ck_security_memberships_timestamp_order"),
        Index("ix_security_memberships_organisation_status", "organisation_id", "status"),
        Index("ix_security_memberships_user_status", "user_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), default=uuid4)
    user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("security_users.id", name="fk_security_memberships_user_id", ondelete="RESTRICT"), nullable=False)
    organisation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("security_organisations.id", name="fk_security_memberships_organisation_id", ondelete="RESTRICT"), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class SecurityEntitlementSnapshot(Base):
    __tablename__ = "security_entitlement_snapshots"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_security_entitlement_snapshots"),
        UniqueConstraint("organisation_id", "sequence_number", name="uq_security_entitlements_organisation_sequence"),
        CheckConstraint("sequence_number >= 1", name="ck_security_entitlements_sequence"),
        CheckConstraint("length(plan_id) BETWEEN 2 AND 100 AND plan_id = trim(plan_id)", name="ck_security_entitlements_plan_id"),
        CheckConstraint("subscription_status IN ('trial','active','past_due','suspended','cancelled','expired')", name="ck_security_entitlements_status"),
        CheckConstraint("expires_at IS NULL OR expires_at > effective_at", name="ck_security_entitlements_time_window"),
        CheckConstraint("length(source_reference) BETWEEN 2 AND 300 AND source_reference = trim(source_reference)", name="ck_security_entitlements_source"),
        Index("ix_security_entitlements_organisation_effective", "organisation_id", "effective_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), default=uuid4)
    organisation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("security_organisations.id", name="fk_security_entitlements_organisation_id", ondelete="RESTRICT"), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    subscription_status: Mapped[str] = mapped_column(String(32), nullable=False)
    features: Mapped[list[str]] = mapped_column(_JSON_DOCUMENT, nullable=False)
    quotas: Mapped[list[dict[str, object]]] = mapped_column(_JSON_DOCUMENT, nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_reference: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


def _reject_entitlement_mutation(_mapper, _connection, _target) -> None:
    raise ImmutableSecurityRecordError("security entitlement snapshots are append-only")


event.listen(SecurityEntitlementSnapshot, "before_update", _reject_entitlement_mutation)
event.listen(SecurityEntitlementSnapshot, "before_delete", _reject_entitlement_mutation)
