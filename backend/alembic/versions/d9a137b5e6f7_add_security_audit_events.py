"""Add append-only privacy-minimised security audit events.

Revision ID: d9a137b5e6f7
Revises: c8f123a4d5e6
Create Date: 2026-08-08 17:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d9a137b5e6f7"
down_revision: str | Sequence[str] | None = "c8f123a4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=100), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=True),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("organisation_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("permission", sa.String(length=64), nullable=True),
        sa.Column("resource_kind", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=300), nullable=True),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("event_type IN ('authentication_succeeded','authentication_failed','authentication_provider_unavailable','access_allowed','access_denied','entitlement_evaluated','security_state_changed')", name="ck_security_audit_event_type"),
        sa.CheckConstraint("outcome IN ('succeeded','denied','unavailable')", name="ck_security_audit_outcome"),
        sa.CheckConstraint("length(reason_code) BETWEEN 2 AND 100", name="ck_security_audit_reason"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["security_users.id"], name="fk_security_audit_actor_user_id", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organisation_id"], ["security_organisations.id"], name="fk_security_audit_organisation_id", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_security_audit_events"),
    )
    op.create_index("ix_security_audit_organisation_occurred", "security_audit_events", ["organisation_id", "occurred_at"], unique=False)
    op.create_index("ix_security_audit_actor_occurred", "security_audit_events", ["actor_user_id", "occurred_at"], unique=False)
    op.create_index("ix_security_audit_request", "security_audit_events", ["request_id"], unique=False)
    op.execute("""
    CREATE OR REPLACE FUNCTION phase8_reject_security_audit_mutation()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'security audit events are append-only';
    END;
    $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_security_audit_events_append_only
    BEFORE UPDATE OR DELETE ON security_audit_events
    FOR EACH ROW EXECUTE FUNCTION phase8_reject_security_audit_mutation();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_security_audit_events_append_only ON security_audit_events")
    op.execute("DROP FUNCTION IF EXISTS phase8_reject_security_audit_mutation()")
    op.drop_index("ix_security_audit_request", table_name="security_audit_events")
    op.drop_index("ix_security_audit_actor_occurred", table_name="security_audit_events")
    op.drop_index("ix_security_audit_organisation_occurred", table_name="security_audit_events")
    op.drop_table("security_audit_events")
