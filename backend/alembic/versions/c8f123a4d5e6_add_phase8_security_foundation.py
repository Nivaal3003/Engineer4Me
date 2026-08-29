"""Add Phase 8 identity, organisation, membership, and entitlement storage.

Revision ID: c8f123a4d5e6
Revises: b7f110e3d2a1
Create Date: 2026-08-05 21:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c8f123a4d5e6"
down_revision: str | Sequence[str] | None = "b7f110e3d2a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=300), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("issuer", sa.String(length=300), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))", name="ck_security_users_email"),
        sa.CheckConstraint("length(display_name) BETWEEN 1 AND 300 AND display_name = trim(display_name)", name="ck_security_users_display_name"),
        sa.CheckConstraint("status IN ('pending','active','suspended','disabled')", name="ck_security_users_status"),
        sa.CheckConstraint("length(issuer) BETWEEN 1 AND 300 AND issuer = trim(issuer)", name="ck_security_users_issuer"),
        sa.CheckConstraint("length(subject) BETWEEN 1 AND 500 AND subject = trim(subject)", name="ck_security_users_subject"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_security_users_timestamp_order"),
        sa.PrimaryKeyConstraint("id", name="pk_security_users"),
        sa.UniqueConstraint("issuer", "subject", name="uq_security_users_issuer_subject"),
    )
    op.create_index("uq_security_users_email_ci", "security_users", [sa.text("lower(email)")], unique=True)
    op.create_index("ix_security_users_status", "security_users", ["status"], unique=False)

    op.create_table(
        "security_organisations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("length(slug) BETWEEN 2 AND 100 AND slug = lower(trim(slug))", name="ck_security_organisations_slug"),
        sa.CheckConstraint("length(name) BETWEEN 2 AND 300 AND name = trim(name)", name="ck_security_organisations_name"),
        sa.CheckConstraint("status IN ('active','suspended','disabled')", name="ck_security_organisations_status"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_security_organisations_timestamp_order"),
        sa.PrimaryKeyConstraint("id", name="pk_security_organisations"),
    )
    op.create_index("uq_security_organisations_slug_ci", "security_organisations", [sa.text("lower(slug)")], unique=True)
    op.create_index("ix_security_organisations_status", "security_organisations", ["status"], unique=False)

    op.create_table(
        "security_organisation_memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("organisation_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("role IN ('owner','administrator','engineer','technician','reviewer','auditor','billing_administrator','read_only')", name="ck_security_memberships_role"),
        sa.CheckConstraint("status IN ('invited','active','suspended','revoked')", name="ck_security_memberships_status"),
        sa.CheckConstraint("((status = 'active' AND joined_at IS NOT NULL) OR (status <> 'active' AND joined_at IS NULL))", name="ck_security_memberships_joined_state"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_security_memberships_timestamp_order"),
        sa.ForeignKeyConstraint(["user_id"], ["security_users.id"], name="fk_security_memberships_user_id", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organisation_id"], ["security_organisations.id"], name="fk_security_memberships_organisation_id", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_security_organisation_memberships"),
        sa.UniqueConstraint("user_id", "organisation_id", name="uq_security_memberships_user_organisation"),
    )
    op.create_index("ix_security_memberships_organisation_status", "security_organisation_memberships", ["organisation_id", "status"], unique=False)
    op.create_index("ix_security_memberships_user_status", "security_organisation_memberships", ["user_id", "status"], unique=False)

    op.create_table(
        "security_entitlement_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organisation_id", sa.Uuid(), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.String(length=100), nullable=False),
        sa.Column("subscription_status", sa.String(length=32), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("quotas", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_reference", sa.String(length=300), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("sequence_number >= 1", name="ck_security_entitlements_sequence"),
        sa.CheckConstraint("length(plan_id) BETWEEN 2 AND 100 AND plan_id = trim(plan_id)", name="ck_security_entitlements_plan_id"),
        sa.CheckConstraint("subscription_status IN ('trial','active','past_due','suspended','cancelled','expired')", name="ck_security_entitlements_status"),
        sa.CheckConstraint("expires_at IS NULL OR expires_at > effective_at", name="ck_security_entitlements_time_window"),
        sa.CheckConstraint("length(source_reference) BETWEEN 2 AND 300 AND source_reference = trim(source_reference)", name="ck_security_entitlements_source"),
        sa.ForeignKeyConstraint(["organisation_id"], ["security_organisations.id"], name="fk_security_entitlements_organisation_id", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_security_entitlement_snapshots"),
        sa.UniqueConstraint("organisation_id", "sequence_number", name="uq_security_entitlements_organisation_sequence"),
    )
    op.create_index("ix_security_entitlements_organisation_effective", "security_entitlement_snapshots", ["organisation_id", "effective_at"], unique=False)

    op.execute("""
    CREATE OR REPLACE FUNCTION phase8_reject_entitlement_snapshot_mutation()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'security entitlement snapshots are append-only';
    END;
    $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_security_entitlement_snapshots_append_only
    BEFORE UPDATE OR DELETE ON security_entitlement_snapshots
    FOR EACH ROW EXECUTE FUNCTION phase8_reject_entitlement_snapshot_mutation();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_security_entitlement_snapshots_append_only ON security_entitlement_snapshots")
    op.execute("DROP FUNCTION IF EXISTS phase8_reject_entitlement_snapshot_mutation()")
    op.drop_index("ix_security_entitlements_organisation_effective", table_name="security_entitlement_snapshots")
    op.drop_table("security_entitlement_snapshots")
    op.drop_index("ix_security_memberships_user_status", table_name="security_organisation_memberships")
    op.drop_index("ix_security_memberships_organisation_status", table_name="security_organisation_memberships")
    op.drop_table("security_organisation_memberships")
    op.drop_index("ix_security_organisations_status", table_name="security_organisations")
    op.drop_index("uq_security_organisations_slug_ci", table_name="security_organisations")
    op.drop_table("security_organisations")
    op.drop_index("ix_security_users_status", table_name="security_users")
    op.drop_index("uq_security_users_email_ci", table_name="security_users")
    op.drop_table("security_users")
