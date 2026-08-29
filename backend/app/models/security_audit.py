"""Append-only SQLAlchemy record for privacy-minimised security audit events."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, PrimaryKeyConstraint, String, Uuid, event, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.models.security_identity import ImmutableSecurityRecordError


_JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class SecurityAuditRecord(Base):
    __tablename__ = "security_audit_events"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_security_audit_events"),
        CheckConstraint("event_type IN ('authentication_succeeded','authentication_failed','authentication_provider_unavailable','access_allowed','access_denied','entitlement_evaluated','security_state_changed')", name="ck_security_audit_event_type"),
        CheckConstraint("outcome IN ('succeeded','denied','unavailable')", name="ck_security_audit_outcome"),
        CheckConstraint("length(reason_code) BETWEEN 2 AND 100", name="ck_security_audit_reason"),
        Index("ix_security_audit_organisation_occurred", "organisation_id", "occurred_at"),
        Index("ix_security_audit_actor_occurred", "actor_user_id", "occurred_at"),
        Index("ix_security_audit_request", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), default=uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    request_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    actor_user_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("security_users.id", name="fk_security_audit_actor_user_id", ondelete="RESTRICT"), nullable=True)
    organisation_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("security_organisations.id", name="fk_security_audit_organisation_id", ondelete="RESTRICT"), nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    permission: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(300), nullable=True)
    context: Mapped[dict[str, object]] = mapped_column(_JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


def _reject_audit_mutation(_mapper, _connection, _target) -> None:
    raise ImmutableSecurityRecordError("security audit events are append-only")


event.listen(SecurityAuditRecord, "before_update", _reject_audit_mutation)
event.listen(SecurityAuditRecord, "before_delete", _reject_audit_mutation)
