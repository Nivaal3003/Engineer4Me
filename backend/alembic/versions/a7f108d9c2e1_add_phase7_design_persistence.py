"""Add Phase 7 design-case and calculation-run persistence.

Revision ID: a7f108d9c2e1
Revises: 94a2e09dd267
Create Date: 2026-08-02 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a7f108d9c2e1"
down_revision: str | Sequence[str] | None = "94a2e09dd267"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create versioned cases and database-enforced append-only records."""

    op.create_table(
        "design_cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_reference", sa.String(length=160), nullable=False),
        sa.Column("case_type", sa.String(length=100), nullable=False),
        sa.Column(
            "current_revision",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "current_revision_fingerprint",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "concurrency_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(length=300), nullable=False),
        sa.Column(
            "creator_origin",
            sa.String(length=40),
            server_default=sa.text("'caller_supplied_unverified'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(case_reference) BETWEEN 2 AND 160 "
            "AND case_reference = trim(case_reference)",
            name="ck_design_cases_case_reference",
        ),
        sa.CheckConstraint(
            "length(case_type) BETWEEN 2 AND 100 "
            "AND case_type = trim(case_type)",
            name="ck_design_cases_case_type",
        ),
        sa.CheckConstraint(
            "current_revision >= 1",
            name="ck_design_cases_current_revision_positive",
        ),
        sa.CheckConstraint(
            "current_revision_fingerprint IS NOT NULL",
            name="ck_design_cases_head_fingerprint_presence",
        ),
        sa.CheckConstraint(
            "length(current_revision_fingerprint) = 64 AND "
            "current_revision_fingerprint = "
            "lower(current_revision_fingerprint)",
            name="ck_design_cases_head_fingerprint",
        ),
        sa.CheckConstraint(
            "concurrency_version >= 1",
            name="ck_design_cases_concurrency_version_positive",
        ),
        sa.CheckConstraint(
            "concurrency_version = current_revision",
            name="ck_design_cases_concurrency_matches_revision",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="ck_design_cases_timestamp_order",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_design_cases_created_by",
        ),
        sa.CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_design_cases_creator_origin",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_design_cases"),
        sa.UniqueConstraint(
            "case_reference",
            name="uq_design_cases_case_reference",
        ),
    )
    op.create_index(
        "ix_design_cases_case_type",
        "design_cases",
        ["case_type"],
        unique=False,
    )
    op.create_index(
        "ix_design_cases_updated_at",
        "design_cases",
        ["updated_at"],
        unique=False,
    )
    op.create_index(
        "uq_design_cases_case_reference_ci",
        "design_cases",
        [sa.text("lower(case_reference)")],
        unique=True,
    )

    op.create_table(
        "design_case_revisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("design_case_id", sa.Uuid(), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("prior_revision_id", sa.Uuid(), nullable=True),
        sa.Column(
            "prior_revision_fingerprint",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("change_reason", sa.String(length=1000), nullable=False),
        sa.Column("payload_schema", sa.String(length=160), nullable=False),
        sa.Column("payload_version", sa.String(length=64), nullable=False),
        sa.Column(
            "snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "source_origins",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "revision_fingerprint",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "approval_state",
            sa.String(length=32),
            server_default=sa.text("'unapproved'"),
            nullable=False,
        ),
        sa.Column(
            "final_design_approval_granted",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(length=300), nullable=False),
        sa.Column(
            "creator_origin",
            sa.String(length=40),
            server_default=sa.text("'caller_supplied_unverified'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "revision_number >= 1",
            name="ck_design_case_revisions_revision_positive",
        ),
        sa.CheckConstraint(
            "((revision_number = 1 AND prior_revision_id IS NULL) OR "
            "(revision_number > 1 AND prior_revision_id IS NOT NULL))",
            name="ck_design_case_revisions_prior_presence",
        ),
        sa.CheckConstraint(
            "((prior_revision_id IS NULL AND "
            "prior_revision_fingerprint IS NULL) OR "
            "(prior_revision_id IS NOT NULL AND "
            "prior_revision_fingerprint IS NOT NULL))",
            name="ck_design_case_revisions_prior_fingerprint_presence",
        ),
        sa.CheckConstraint(
            "prior_revision_id IS NULL OR prior_revision_id <> id",
            name="ck_design_case_revisions_prior_not_self",
        ),
        sa.CheckConstraint(
            "length(revision_fingerprint) = 64 AND "
            "revision_fingerprint = lower(revision_fingerprint)",
            name="ck_design_case_revisions_fingerprint",
        ),
        sa.CheckConstraint(
            "prior_revision_fingerprint IS NULL OR "
            "(length(prior_revision_fingerprint) = 64 AND "
            "prior_revision_fingerprint = lower(prior_revision_fingerprint))",
            name="ck_design_case_revisions_prior_fingerprint",
        ),
        sa.CheckConstraint(
            "length(change_reason) BETWEEN 1 AND 1000 "
            "AND change_reason = trim(change_reason)",
            name="ck_design_case_revisions_change_reason",
        ),
        sa.CheckConstraint(
            "length(payload_schema) BETWEEN 2 AND 160 "
            "AND payload_schema = trim(payload_schema)",
            name="ck_design_case_revisions_payload_schema",
        ),
        sa.CheckConstraint(
            "length(payload_version) BETWEEN 3 AND 64 "
            "AND payload_version = trim(payload_version)",
            name="ck_design_case_revisions_payload_version",
        ),
        sa.CheckConstraint(
            "approval_state = 'unapproved'",
            name="ck_design_case_revisions_approval_unapproved",
        ),
        sa.CheckConstraint(
            "final_design_approval_granted = false",
            name="ck_design_case_revisions_no_final_approval",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_design_case_revisions_created_by",
        ),
        sa.CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_design_case_revisions_creator_origin",
        ),
        sa.ForeignKeyConstraint(
            ["design_case_id"],
            ["design_cases.id"],
            name="fk_design_case_revisions_design_case_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["prior_revision_id"],
            ["design_case_revisions.id"],
            name="fk_design_case_revisions_prior_revision_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_design_case_revisions"),
        sa.UniqueConstraint(
            "design_case_id",
            "revision_number",
            name="uq_design_case_revisions_case_revision",
        ),
        sa.UniqueConstraint(
            "prior_revision_id",
            name="uq_design_case_revisions_prior_revision",
        ),
    )
    op.create_index(
        "ix_design_case_revisions_case_created_at",
        "design_case_revisions",
        ["design_case_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "calculation_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_kind", sa.String(length=32), nullable=False),
        sa.Column("design_case_revision_id", sa.Uuid(), nullable=True),
        sa.Column("supersedes_run_id", sa.Uuid(), nullable=True),
        sa.Column(
            "design_revision_fingerprint",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "supersedes_run_fingerprint",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("calculation_type", sa.String(length=100), nullable=False),
        sa.Column("method_id", sa.String(length=160), nullable=False),
        sa.Column("method_version", sa.String(length=64), nullable=False),
        sa.Column("executor_id", sa.String(length=100), nullable=False),
        sa.Column("executor_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("request_schema", sa.String(length=160), nullable=False),
        sa.Column("result_schema", sa.String(length=160), nullable=False),
        sa.Column(
            "request_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "result_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "execution_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("input_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("result_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("run_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("canonicalization", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=300), nullable=False),
        sa.Column(
            "creator_origin",
            sa.String(length=40),
            server_default=sa.text("'caller_supplied_unverified'"),
            nullable=False,
        ),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "run_kind IN ('calculation', 'analyzer_assessment')",
            name="ck_calculation_runs_run_kind",
        ),
        sa.CheckConstraint(
            "status IN ('completed', 'completed_with_warnings', 'blocked', "
            "'insufficient_input', 'not_applicable', 'failed')",
            name="ck_calculation_runs_status",
        ),
        sa.CheckConstraint(
            "supersedes_run_id IS NULL OR supersedes_run_id <> id",
            name="ck_calculation_runs_supersedes_not_self",
        ),
        sa.CheckConstraint(
            "((design_case_revision_id IS NULL AND "
            "design_revision_fingerprint IS NULL) OR "
            "(design_case_revision_id IS NOT NULL AND "
            "design_revision_fingerprint IS NOT NULL))",
            name="ck_calculation_runs_revision_fingerprint_presence",
        ),
        sa.CheckConstraint(
            "((supersedes_run_id IS NULL AND "
            "supersedes_run_fingerprint IS NULL) OR "
            "(supersedes_run_id IS NOT NULL AND "
            "supersedes_run_fingerprint IS NOT NULL))",
            name="ck_calculation_runs_prior_fingerprint_presence",
        ),
        sa.CheckConstraint(
            "length(calculation_type) BETWEEN 2 AND 100 "
            "AND calculation_type = trim(calculation_type)",
            name="ck_calculation_runs_calculation_type",
        ),
        sa.CheckConstraint(
            "length(method_id) BETWEEN 2 AND 160 "
            "AND method_id = trim(method_id)",
            name="ck_calculation_runs_method_id",
        ),
        sa.CheckConstraint(
            "length(method_version) BETWEEN 3 AND 64 "
            "AND method_version = trim(method_version)",
            name="ck_calculation_runs_method_version",
        ),
        sa.CheckConstraint(
            "length(executor_id) BETWEEN 2 AND 100 "
            "AND executor_id = trim(executor_id)",
            name="ck_calculation_runs_executor_id",
        ),
        sa.CheckConstraint(
            "length(executor_version) BETWEEN 3 AND 64 "
            "AND executor_version = trim(executor_version)",
            name="ck_calculation_runs_executor_version",
        ),
        sa.CheckConstraint(
            "length(request_schema) BETWEEN 2 AND 160 "
            "AND request_schema = trim(request_schema)",
            name="ck_calculation_runs_request_schema",
        ),
        sa.CheckConstraint(
            "length(result_schema) BETWEEN 2 AND 160 "
            "AND result_schema = trim(result_schema)",
            name="ck_calculation_runs_result_schema",
        ),
        sa.CheckConstraint(
            "length(input_fingerprint) = 64 AND "
            "input_fingerprint = lower(input_fingerprint)",
            name="ck_calculation_runs_input_fingerprint",
        ),
        sa.CheckConstraint(
            "length(result_fingerprint) = 64 AND "
            "result_fingerprint = lower(result_fingerprint)",
            name="ck_calculation_runs_result_fingerprint",
        ),
        sa.CheckConstraint(
            "length(run_fingerprint) = 64 AND "
            "run_fingerprint = lower(run_fingerprint)",
            name="ck_calculation_runs_run_fingerprint",
        ),
        sa.CheckConstraint(
            "design_revision_fingerprint IS NULL OR "
            "(length(design_revision_fingerprint) = 64 AND "
            "design_revision_fingerprint = lower(design_revision_fingerprint))",
            name="ck_calculation_runs_revision_fingerprint",
        ),
        sa.CheckConstraint(
            "supersedes_run_fingerprint IS NULL OR "
            "(length(supersedes_run_fingerprint) = 64 AND "
            "supersedes_run_fingerprint = lower(supersedes_run_fingerprint))",
            name="ck_calculation_runs_prior_fingerprint",
        ),
        sa.CheckConstraint(
            "length(canonicalization) BETWEEN 3 AND 64 "
            "AND canonicalization = trim(canonicalization)",
            name="ck_calculation_runs_canonicalization",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_calculation_runs_created_by",
        ),
        sa.CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_calculation_runs_creator_origin",
        ),
        sa.ForeignKeyConstraint(
            ["design_case_revision_id"],
            ["design_case_revisions.id"],
            name="fk_calculation_runs_design_case_revision_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_run_id"],
            ["calculation_runs.id"],
            name="fk_calculation_runs_supersedes_run_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_calculation_runs"),
        sa.UniqueConstraint(
            "supersedes_run_id",
            name="uq_calculation_runs_supersedes_run_id",
        ),
    )
    op.create_index(
        "ix_calculation_runs_revision_created_at",
        "calculation_runs",
        ["design_case_revision_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_calculation_runs_method_identity",
        "calculation_runs",
        ["method_id", "method_version"],
        unique=False,
    )
    op.create_index(
        "ix_calculation_runs_run_kind_status",
        "calculation_runs",
        ["run_kind", "status"],
        unique=False,
    )
    op.create_index(
        "ix_calculation_runs_supersedes_run_id",
        "calculation_runs",
        ["supersedes_run_id"],
        unique=False,
    )

    op.execute(
        """
        CREATE FUNCTION phase7_guard_design_case_head_update()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.case_reference IS DISTINCT FROM OLD.case_reference
               OR NEW.case_type IS DISTINCT FROM OLD.case_type
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.creator_origin IS DISTINCT FROM OLD.creator_origin
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                    'Engineer4Me design-case identity is immutable.'
                    USING ERRCODE = '55000';
            END IF;

            IF NEW.current_revision <> OLD.current_revision + 1
               OR NEW.concurrency_version <> OLD.concurrency_version + 1
               OR NEW.current_revision_fingerprint IS NOT DISTINCT FROM
                    OLD.current_revision_fingerprint
               OR NEW.updated_at < OLD.updated_at THEN
                RAISE EXCEPTION
                    'Engineer4Me design-case head update is not a valid CAS transition.'
                    USING ERRCODE = '40001';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_design_cases_identity_immutable
        BEFORE UPDATE ON design_cases
        FOR EACH ROW
        EXECUTE FUNCTION phase7_guard_design_case_head_update()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_validate_design_revision_chain()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            predecessor design_case_revisions%ROWTYPE;
        BEGIN
            IF NEW.revision_number = 1 THEN
                RETURN NEW;
            END IF;
            IF NEW.prior_revision_id IS NULL
               OR NEW.prior_revision_fingerprint IS NULL THEN
                RETURN NEW;
            END IF;

            SELECT * INTO predecessor
            FROM design_case_revisions
            WHERE id = NEW.prior_revision_id;

            IF NOT FOUND
               OR predecessor.design_case_id IS DISTINCT FROM
                    NEW.design_case_id
               OR NEW.revision_number <> predecessor.revision_number + 1
               OR NEW.prior_revision_fingerprint IS DISTINCT FROM
                    predecessor.revision_fingerprint THEN
                RAISE EXCEPTION
                    'Engineer4Me design revision does not extend its exact predecessor.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_design_case_revisions_coherent_chain';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_design_case_revisions_chain_integrity
        BEFORE INSERT ON design_case_revisions
        FOR EACH ROW
        EXECUTE FUNCTION phase7_validate_design_revision_chain()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_validate_design_case_head()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.current_revision > 0 AND NOT EXISTS (
                SELECT 1
                FROM design_case_revisions AS revision
                WHERE revision.design_case_id = NEW.id
                  AND revision.revision_number = NEW.current_revision
                  AND revision.revision_fingerprint =
                        NEW.current_revision_fingerprint
                  AND revision.created_at = NEW.updated_at
            ) THEN
                RAISE EXCEPTION
                    'Engineer4Me design-case head does not resolve to its exact revision.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_design_cases_head_resolves_revision';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_design_cases_head_integrity
        AFTER INSERT OR UPDATE ON design_cases
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_validate_design_case_head()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_validate_inserted_revision_is_head()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM design_cases AS design_case
                WHERE design_case.id = NEW.design_case_id
                  AND design_case.current_revision = NEW.revision_number
                  AND design_case.current_revision_fingerprint =
                        NEW.revision_fingerprint
                  AND design_case.updated_at = NEW.created_at
            ) THEN
                RAISE EXCEPTION
                    'Engineer4Me inserted revision is not the committed design-case head.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_design_case_revisions_committed_head';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_design_case_revisions_head_integrity
        AFTER INSERT ON design_case_revisions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_validate_inserted_revision_is_head()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_validate_calculation_run_links()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            linked_revision design_case_revisions%ROWTYPE;
            predecessor calculation_runs%ROWTYPE;
            linked_case_id uuid;
            predecessor_case_id uuid;
        BEGIN
            IF NEW.design_case_revision_id IS NOT NULL
               AND NEW.design_revision_fingerprint IS NOT NULL THEN
                SELECT * INTO linked_revision
                FROM design_case_revisions
                WHERE id = NEW.design_case_revision_id;

                IF NOT FOUND
                   OR NEW.design_revision_fingerprint IS DISTINCT FROM
                        linked_revision.revision_fingerprint THEN
                    RAISE EXCEPTION
                        'Engineer4Me calculation run does not match its design revision.'
                        USING ERRCODE = '23514',
                              CONSTRAINT = 'ck_calculation_runs_coherent_links';
                END IF;
                linked_case_id := linked_revision.design_case_id;
            END IF;

            IF NEW.supersedes_run_id IS NOT NULL
               AND NEW.supersedes_run_fingerprint IS NOT NULL THEN
                SELECT * INTO predecessor
                FROM calculation_runs
                WHERE id = NEW.supersedes_run_id;

                IF FOUND AND predecessor.design_case_revision_id IS NOT NULL THEN
                    SELECT design_case_id INTO predecessor_case_id
                    FROM design_case_revisions
                    WHERE id = predecessor.design_case_revision_id;
                END IF;

                IF NOT FOUND
                   OR NEW.supersedes_run_fingerprint IS DISTINCT FROM
                        predecessor.run_fingerprint
                   OR NEW.run_kind IS DISTINCT FROM predecessor.run_kind
                   OR NEW.calculation_type IS DISTINCT FROM
                        predecessor.calculation_type
                   OR NEW.method_id IS DISTINCT FROM predecessor.method_id
                   OR NEW.method_version IS DISTINCT FROM
                        predecessor.method_version
                   OR NEW.executor_id IS DISTINCT FROM predecessor.executor_id
                   OR NEW.executor_version IS DISTINCT FROM
                        predecessor.executor_version
                   OR linked_case_id IS DISTINCT FROM
                        predecessor_case_id THEN
                    RAISE EXCEPTION
                        'Engineer4Me calculation run does not extend its exact execution lineage.'
                        USING ERRCODE = '23514',
                              CONSTRAINT = 'ck_calculation_runs_coherent_links';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_calculation_runs_link_integrity
        BEFORE INSERT ON calculation_runs
        FOR EACH ROW
        EXECUTE FUNCTION phase7_validate_calculation_run_links()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_reject_append_only_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                'Engineer4Me append-only record mutation is not permitted.'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_design_case_revisions_append_only
        BEFORE UPDATE OR DELETE ON design_case_revisions
        FOR EACH ROW
        EXECUTE FUNCTION phase7_reject_append_only_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_calculation_runs_append_only
        BEFORE UPDATE OR DELETE ON calculation_runs
        FOR EACH ROW
        EXECUTE FUNCTION phase7_reject_append_only_mutation()
        """
    )


def downgrade() -> None:
    """Remove only the Phase 7 persistence objects."""

    op.execute(
        "DROP TRIGGER trg_calculation_runs_append_only ON calculation_runs"
    )
    op.execute(
        "DROP TRIGGER trg_calculation_runs_link_integrity "
        "ON calculation_runs"
    )
    op.execute(
        "DROP TRIGGER trg_design_case_revisions_append_only "
        "ON design_case_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_design_case_revisions_head_integrity "
        "ON design_case_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_design_case_revisions_chain_integrity "
        "ON design_case_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_design_cases_head_integrity ON design_cases"
    )
    op.execute(
        "DROP TRIGGER trg_design_cases_identity_immutable ON design_cases"
    )
    op.execute("DROP FUNCTION phase7_reject_append_only_mutation()")
    op.execute("DROP FUNCTION phase7_validate_calculation_run_links()")
    op.execute("DROP FUNCTION phase7_validate_inserted_revision_is_head()")
    op.execute("DROP FUNCTION phase7_validate_design_case_head()")
    op.execute("DROP FUNCTION phase7_validate_design_revision_chain()")
    op.execute("DROP FUNCTION phase7_guard_design_case_head_update()")

    op.drop_index(
        "ix_calculation_runs_supersedes_run_id",
        table_name="calculation_runs",
    )
    op.drop_index(
        "ix_calculation_runs_run_kind_status",
        table_name="calculation_runs",
    )
    op.drop_index(
        "ix_calculation_runs_method_identity",
        table_name="calculation_runs",
    )
    op.drop_index(
        "ix_calculation_runs_revision_created_at",
        table_name="calculation_runs",
    )
    op.drop_table("calculation_runs")

    op.drop_index(
        "ix_design_case_revisions_case_created_at",
        table_name="design_case_revisions",
    )
    op.drop_table("design_case_revisions")

    op.drop_index("ix_design_cases_updated_at", table_name="design_cases")
    op.drop_index("ix_design_cases_case_type", table_name="design_cases")
    op.drop_index(
        "uq_design_cases_case_reference_ci",
        table_name="design_cases",
    )
    op.drop_table("design_cases")
