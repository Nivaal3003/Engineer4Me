"""Add Phase 7 controlled datasheet persistence.

Revision ID: b7f110e3d2a1
Revises: a7f108d9c2e1
Create Date: 2026-08-02 15:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b7f110e3d2a1"
down_revision: str | Sequence[str] | None = "a7f108d9c2e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create append-only controlled datasheets and verified run links."""

    op.create_table(
        "engineering_datasheets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("design_case_id", sa.Uuid(), nullable=False),
        sa.Column("template_id", sa.String(length=100), nullable=False),
        sa.Column("template_version", sa.String(length=64), nullable=False),
        sa.Column("template_fingerprint", sa.String(length=64), nullable=False),
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
            "length(template_id) BETWEEN 2 AND 100 AND template_id = trim(template_id)",
            name="ck_engineering_datasheets_template_id",
        ),
        sa.CheckConstraint(
            "length(template_version) BETWEEN 3 AND 64 "
            "AND template_version = trim(template_version)",
            name="ck_engineering_datasheets_template_version",
        ),
        sa.CheckConstraint(
            "length(template_fingerprint) = 64 AND "
            "template_fingerprint = lower(template_fingerprint)",
            name="ck_engineering_datasheets_template_fingerprint",
        ),
        sa.CheckConstraint(
            "current_revision BETWEEN 1 AND 100",
            name="ck_engineering_datasheets_current_revision",
        ),
        sa.CheckConstraint(
            "length(current_revision_fingerprint) = 64 AND "
            "current_revision_fingerprint = "
            "lower(current_revision_fingerprint)",
            name="ck_engineering_datasheets_head_fingerprint",
        ),
        sa.CheckConstraint(
            "concurrency_version = current_revision",
            name="ck_engineering_datasheets_concurrency_revision",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="ck_engineering_datasheets_timestamp_order",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 AND created_by = trim(created_by)",
            name="ck_engineering_datasheets_created_by",
        ),
        sa.CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_engineering_datasheets_creator_origin",
        ),
        sa.ForeignKeyConstraint(
            ["design_case_id"],
            ["design_cases.id"],
            name="fk_engineering_datasheets_design_case_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_engineering_datasheets"),
    )
    op.create_index(
        "ix_engineering_datasheets_case_updated",
        "engineering_datasheets",
        ["design_case_id", "updated_at"],
        unique=False,
    )
    op.create_index(
        "ix_engineering_datasheets_template",
        "engineering_datasheets",
        ["template_id", "template_version"],
        unique=False,
    )

    op.create_table(
        "engineering_datasheet_revisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("datasheet_id", sa.Uuid(), nullable=False),
        sa.Column("design_case_revision_id", sa.Uuid(), nullable=False),
        sa.Column("design_revision_number", sa.Integer(), nullable=False),
        sa.Column(
            "design_revision_fingerprint",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("prior_revision_id", sa.Uuid(), nullable=True),
        sa.Column(
            "prior_revision_fingerprint",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("snapshot_schema", sa.String(length=160), nullable=False),
        sa.Column("snapshot_version", sa.String(length=64), nullable=False),
        sa.Column(
            "snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "export_descriptor",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("json_artifact", sa.LargeBinary(), nullable=False),
        sa.Column("workbook_artifact", sa.LargeBinary(), nullable=False),
        sa.Column("revision_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("change_reason", sa.String(length=1000), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("completeness_state", sa.String(length=40), nullable=False),
        sa.Column("ready_for_review", sa.Boolean(), nullable=False),
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
        sa.Column(
            "standards_conformity_claimed",
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
            "revision_number BETWEEN 1 AND 100",
            name="ck_engineering_datasheet_revisions_number",
        ),
        sa.CheckConstraint(
            "design_revision_number >= 1",
            name="ck_engineering_datasheet_revisions_design_revision_number",
        ),
        sa.CheckConstraint(
            "length(design_revision_fingerprint) = 64 AND "
            "design_revision_fingerprint = "
            "lower(design_revision_fingerprint)",
            name="ck_engineering_datasheet_revisions_design_fingerprint",
        ),
        sa.CheckConstraint(
            "((revision_number = 1 AND prior_revision_id IS NULL) OR "
            "(revision_number > 1 AND prior_revision_id IS NOT NULL))",
            name="ck_engineering_datasheet_revisions_prior_presence",
        ),
        sa.CheckConstraint(
            "((prior_revision_id IS NULL AND "
            "prior_revision_fingerprint IS NULL) OR "
            "(prior_revision_id IS NOT NULL AND "
            "prior_revision_fingerprint IS NOT NULL))",
            name="ck_engineering_datasheet_revisions_prior_fingerprint_presence",
        ),
        sa.CheckConstraint(
            "prior_revision_id IS NULL OR prior_revision_id <> id",
            name="ck_engineering_datasheet_revisions_prior_not_self",
        ),
        sa.CheckConstraint(
            "length(snapshot_schema) BETWEEN 2 AND 160 "
            "AND snapshot_schema = trim(snapshot_schema)",
            name="ck_engineering_datasheet_revisions_snapshot_schema",
        ),
        sa.CheckConstraint(
            "length(snapshot_version) BETWEEN 3 AND 64 "
            "AND snapshot_version = trim(snapshot_version)",
            name="ck_engineering_datasheet_revisions_snapshot_version",
        ),
        sa.CheckConstraint(
            "length(revision_fingerprint) = 64 AND "
            "revision_fingerprint = lower(revision_fingerprint)",
            name="ck_engineering_datasheet_revisions_fingerprint",
        ),
        sa.CheckConstraint(
            "prior_revision_fingerprint IS NULL OR "
            "(length(prior_revision_fingerprint) = 64 AND "
            "prior_revision_fingerprint = "
            "lower(prior_revision_fingerprint))",
            name="ck_engineering_datasheet_revisions_prior_fingerprint",
        ),
        sa.CheckConstraint(
            "length(change_reason) BETWEEN 1 AND 1000 "
            "AND change_reason = trim(change_reason)",
            name="ck_engineering_datasheet_revisions_change_reason",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('draft', 'under_review', 'on_hold', 'archived')",
            name="ck_engineering_datasheet_revisions_lifecycle",
        ),
        sa.CheckConstraint(
            "completeness_state IN ('complete', 'complete_with_open_items', "
            "'incomplete', 'blocked')",
            name="ck_engineering_datasheet_revisions_completeness",
        ),
        sa.CheckConstraint(
            "approval_state = 'unapproved'",
            name="ck_engineering_datasheet_revisions_approval",
        ),
        sa.CheckConstraint(
            "final_design_approval_granted = false",
            name="ck_engineering_datasheet_revisions_no_final_approval",
        ),
        sa.CheckConstraint(
            "standards_conformity_claimed = false",
            name="ck_engineering_datasheet_revisions_no_conformity",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 AND created_by = trim(created_by)",
            name="ck_engineering_datasheet_revisions_created_by",
        ),
        sa.CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_engineering_datasheet_revisions_creator_origin",
        ),
        sa.CheckConstraint(
            "length(json_artifact) BETWEEN 1 AND 8388608",
            name="ck_engineering_datasheet_revisions_json_artifact_size",
        ),
        sa.CheckConstraint(
            "length(workbook_artifact) BETWEEN 1 AND 8388608",
            name="ck_engineering_datasheet_revisions_workbook_artifact_size",
        ),
        sa.ForeignKeyConstraint(
            ["datasheet_id"],
            ["engineering_datasheets.id"],
            name="fk_engineering_datasheet_revisions_datasheet_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["design_case_revision_id"],
            ["design_case_revisions.id"],
            name="fk_engineering_datasheet_revisions_design_revision_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["prior_revision_id"],
            ["engineering_datasheet_revisions.id"],
            name="fk_engineering_datasheet_revisions_prior_revision_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_engineering_datasheet_revisions",
        ),
        sa.UniqueConstraint(
            "datasheet_id",
            "revision_number",
            name="uq_engineering_datasheet_revisions_sheet_revision",
        ),
        sa.UniqueConstraint(
            "prior_revision_id",
            name="uq_engineering_datasheet_revisions_prior_revision",
        ),
    )
    op.create_index(
        "ix_engineering_datasheet_revisions_sheet_created",
        "engineering_datasheet_revisions",
        ["datasheet_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_engineering_datasheet_revisions_design_revision",
        "engineering_datasheet_revisions",
        ["design_case_revision_id"],
        unique=False,
    )

    op.create_table(
        "engineering_datasheet_calculation_links",
        sa.Column("datasheet_revision_id", sa.Uuid(), nullable=False),
        sa.Column("link_id", sa.String(length=100), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("output_id", sa.String(length=100), nullable=False),
        sa.Column("run_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("result_fingerprint", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(link_id) BETWEEN 2 AND 100 AND link_id = trim(link_id)",
            name="ck_engineering_datasheet_calculation_links_id",
        ),
        sa.CheckConstraint(
            "length(output_id) BETWEEN 2 AND 100 AND output_id = trim(output_id)",
            name="ck_engineering_datasheet_calculation_links_output_id",
        ),
        sa.CheckConstraint(
            "length(run_fingerprint) = 64 AND run_fingerprint = lower(run_fingerprint)",
            name="ck_engineering_datasheet_calculation_links_run_fingerprint",
        ),
        sa.CheckConstraint(
            "length(result_fingerprint) = 64 AND "
            "result_fingerprint = lower(result_fingerprint)",
            name="ck_engineering_datasheet_calculation_links_result_fingerprint",
        ),
        sa.ForeignKeyConstraint(
            ["datasheet_revision_id"],
            ["engineering_datasheet_revisions.id"],
            name="fk_engineering_datasheet_calculation_links_revision_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["calculation_runs.id"],
            name="fk_engineering_datasheet_calculation_links_run_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "datasheet_revision_id",
            "link_id",
            name="pk_engineering_datasheet_calculation_links",
        ),
        sa.UniqueConstraint(
            "datasheet_revision_id",
            "run_id",
            "output_id",
            name="uq_engineering_datasheet_calculation_links_output",
        ),
    )
    op.create_index(
        "ix_engineering_datasheet_calculation_links_run",
        "engineering_datasheet_calculation_links",
        ["run_id"],
        unique=False,
    )

    op.execute(
        """
        CREATE FUNCTION phase7_110_guard_datasheet_head_update()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.design_case_id IS DISTINCT FROM OLD.design_case_id
               OR NEW.template_id IS DISTINCT FROM OLD.template_id
               OR NEW.template_version IS DISTINCT FROM OLD.template_version
               OR NEW.template_fingerprint IS DISTINCT FROM
                    OLD.template_fingerprint
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.creator_origin IS DISTINCT FROM OLD.creator_origin
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet identity is immutable.'
                    USING ERRCODE = '55000';
            END IF;

            IF NEW.current_revision <> OLD.current_revision + 1
               OR NEW.concurrency_version <> OLD.concurrency_version + 1
               OR NEW.current_revision_fingerprint IS NOT DISTINCT FROM
                    OLD.current_revision_fingerprint
               OR NEW.updated_at < OLD.updated_at THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet head update is not a valid CAS transition.'
                    USING ERRCODE = '40001';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheets_identity_immutable
        BEFORE UPDATE ON engineering_datasheets
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_guard_datasheet_head_update()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_validate_datasheet_revision()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            predecessor engineering_datasheet_revisions%ROWTYPE;
            parent_sheet engineering_datasheets%ROWTYPE;
            design_revision design_case_revisions%ROWTYPE;
        BEGIN
            SELECT * INTO parent_sheet
            FROM engineering_datasheets
            WHERE id = NEW.datasheet_id;

            SELECT * INTO design_revision
            FROM design_case_revisions
            WHERE id = NEW.design_case_revision_id;

            IF NOT FOUND
               OR parent_sheet.id IS NULL
               OR design_revision.design_case_id IS DISTINCT FROM
                    parent_sheet.design_case_id
               OR design_revision.revision_number IS DISTINCT FROM
                    NEW.design_revision_number
               OR design_revision.revision_fingerprint IS DISTINCT FROM
                    NEW.design_revision_fingerprint THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet does not match its exact design revision.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheet_revisions_design_link';
            END IF;

            IF NEW.revision_number = 1 THEN
                RETURN NEW;
            END IF;

            SELECT * INTO predecessor
            FROM engineering_datasheet_revisions
            WHERE id = NEW.prior_revision_id;

            IF NOT FOUND
               OR predecessor.datasheet_id IS DISTINCT FROM NEW.datasheet_id
               OR NEW.revision_number <> predecessor.revision_number + 1
               OR NEW.prior_revision_fingerprint IS DISTINCT FROM
                    predecessor.revision_fingerprint
               OR NEW.design_revision_number <
                    predecessor.design_revision_number
               OR (
                    NEW.design_revision_number =
                        predecessor.design_revision_number
                    AND (
                        NEW.design_case_revision_id IS DISTINCT FROM
                            predecessor.design_case_revision_id
                        OR NEW.design_revision_fingerprint IS DISTINCT FROM
                            predecessor.design_revision_fingerprint
                    )
               ) THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet revision does not extend its predecessor.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheet_revisions_chain';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheet_revisions_integrity
        BEFORE INSERT ON engineering_datasheet_revisions
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_datasheet_revision()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_validate_datasheet_head()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM engineering_datasheet_revisions AS revision
                WHERE revision.datasheet_id = NEW.id
                  AND revision.revision_number = NEW.current_revision
                  AND revision.revision_fingerprint =
                        NEW.current_revision_fingerprint
                  AND revision.created_at = NEW.updated_at
            ) THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet head does not resolve to its revision.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheets_head_resolves';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_engineering_datasheets_head_integrity
        AFTER INSERT OR UPDATE ON engineering_datasheets
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_datasheet_head()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_validate_inserted_datasheet_revision()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM engineering_datasheets AS datasheet
                WHERE datasheet.id = NEW.datasheet_id
                  AND datasheet.current_revision = NEW.revision_number
                  AND datasheet.current_revision_fingerprint =
                        NEW.revision_fingerprint
                  AND datasheet.updated_at = NEW.created_at
            ) THEN
                RAISE EXCEPTION
                    'Engineer4Me inserted datasheet revision is not the head.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheet_revisions_head';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_engineering_datasheet_revisions_head
        AFTER INSERT ON engineering_datasheet_revisions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_inserted_datasheet_revision()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_validate_datasheet_calculation_link()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            revision engineering_datasheet_revisions%ROWTYPE;
            run calculation_runs%ROWTYPE;
            link_evidence jsonb;
            output_evidence jsonb;
            matching_outputs integer;
        BEGIN
            SELECT * INTO revision
            FROM engineering_datasheet_revisions
            WHERE id = NEW.datasheet_revision_id;

            SELECT * INTO run
            FROM calculation_runs
            WHERE id = NEW.run_id;

            SELECT link.value INTO link_evidence
            FROM jsonb_array_elements(
                COALESCE(
                    revision.snapshot #> '{content,calculation_links}',
                    '[]'::jsonb
                )
            ) AS link(value)
            WHERE link.value ->> 'link_id' = NEW.link_id;

            SELECT count(*), min(output.value::text)::jsonb
            INTO matching_outputs, output_evidence
            FROM jsonb_array_elements(
                COALESCE(run.result_payload -> 'outputs', '[]'::jsonb)
            ) AS output(value)
            WHERE output.value ->> 'output_id' = NEW.output_id;

            IF revision.id IS NULL
               OR run.id IS NULL
               OR run.run_kind <> 'calculation'
               OR run.status NOT IN ('completed', 'completed_with_warnings')
               OR run.design_case_revision_id IS DISTINCT FROM
                    revision.design_case_revision_id
               OR run.run_fingerprint IS DISTINCT FROM NEW.run_fingerprint
               OR run.result_fingerprint IS DISTINCT FROM
                    NEW.result_fingerprint
               OR matching_outputs <> 1
               OR link_evidence IS NULL
               OR link_evidence ->> 'run_id' IS DISTINCT FROM NEW.run_id::text
               OR link_evidence ->> 'run_fingerprint' IS DISTINCT FROM
                    NEW.run_fingerprint
               OR link_evidence ->> 'result_fingerprint' IS DISTINCT FROM
                    NEW.result_fingerprint
               OR link_evidence ->> 'design_revision_id' IS DISTINCT FROM
                    revision.design_case_revision_id::text
               OR link_evidence ->> 'design_revision_number' IS DISTINCT FROM
                    revision.design_revision_number::text
               OR link_evidence ->> 'design_revision_fingerprint' IS DISTINCT FROM
                    revision.design_revision_fingerprint
               OR link_evidence ->> 'design_case_id' IS DISTINCT FROM (
                    SELECT design_case_id::text
                    FROM design_case_revisions
                    WHERE id = revision.design_case_revision_id
               )
               OR link_evidence ->> 'calculation_type' IS DISTINCT FROM
                    run.calculation_type
               OR link_evidence ->> 'method_id' IS DISTINCT FROM run.method_id
               OR link_evidence ->> 'method_version' IS DISTINCT FROM
                    run.method_version
               OR link_evidence ->> 'result_status' IS DISTINCT FROM run.status
               OR link_evidence -> 'repository_provenance_verified'
                    IS DISTINCT FROM 'true'::jsonb
               OR link_evidence -> 'source_record_embedded'
                    IS DISTINCT FROM 'false'::jsonb
               OR link_evidence -> 'historical_link_rewritten'
                    IS DISTINCT FROM 'false'::jsonb
               OR link_evidence -> 'output' IS DISTINCT FROM output_evidence THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet calculation link is not trusted.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheet_calculation_links_trusted';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheet_calculation_links_integrity
        BEFORE INSERT ON engineering_datasheet_calculation_links
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_datasheet_calculation_link()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_validate_datasheet_link_projection()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            revision_key uuid;
            revision engineering_datasheet_revisions%ROWTYPE;
            expected_count integer;
            actual_count integer;
        BEGIN
            IF TG_TABLE_NAME = 'engineering_datasheet_revisions' THEN
                revision_key := NEW.id;
            ELSE
                revision_key := NEW.datasheet_revision_id;
            END IF;

            SELECT * INTO revision
            FROM engineering_datasheet_revisions
            WHERE id = revision_key;

            expected_count := jsonb_array_length(
                COALESCE(
                    revision.snapshot #> '{content,calculation_links}',
                    '[]'::jsonb
                )
            );
            SELECT count(*) INTO actual_count
            FROM engineering_datasheet_calculation_links
            WHERE datasheet_revision_id = revision_key;

            IF revision.id IS NULL
               OR expected_count <> actual_count
               OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(
                        COALESCE(
                            revision.snapshot #>
                                '{content,calculation_links}',
                            '[]'::jsonb
                        )
                    ) AS link(value)
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM engineering_datasheet_calculation_links AS stored
                        WHERE stored.datasheet_revision_id = revision_key
                          AND stored.link_id = link.value ->> 'link_id'
                          AND stored.run_id::text = link.value ->> 'run_id'
                          AND stored.output_id =
                                link.value #>> '{output,output_id}'
                          AND stored.run_fingerprint =
                                link.value ->> 'run_fingerprint'
                          AND stored.result_fingerprint =
                                link.value ->> 'result_fingerprint'
                    )
               ) THEN
                RAISE EXCEPTION
                    'Engineer4Me datasheet link projection is incomplete.'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ck_engineering_datasheet_links_projected';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER
            trg_engineering_datasheet_revisions_link_projection
        AFTER INSERT ON engineering_datasheet_revisions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_datasheet_link_projection()
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER
            trg_engineering_datasheet_calculation_links_projection
        AFTER INSERT ON engineering_datasheet_calculation_links
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_validate_datasheet_link_projection()
        """
    )
    op.execute(
        """
        CREATE FUNCTION phase7_110_reject_datasheet_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                'Engineer4Me controlled datasheet mutation is not permitted.'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheets_delete_prohibited
        BEFORE DELETE ON engineering_datasheets
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_reject_datasheet_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheet_revisions_append_only
        BEFORE UPDATE OR DELETE ON engineering_datasheet_revisions
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_reject_datasheet_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_engineering_datasheet_calculation_links_append_only
        BEFORE UPDATE OR DELETE ON engineering_datasheet_calculation_links
        FOR EACH ROW
        EXECUTE FUNCTION phase7_110_reject_datasheet_mutation()
        """
    )


def downgrade() -> None:
    """Remove only Step 110 datasheet persistence objects."""

    op.execute(
        "DROP TRIGGER "
        "trg_engineering_datasheet_calculation_links_projection "
        "ON engineering_datasheet_calculation_links"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_calculation_links_append_only "
        "ON engineering_datasheet_calculation_links"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_calculation_links_integrity "
        "ON engineering_datasheet_calculation_links"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_revisions_link_projection "
        "ON engineering_datasheet_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_revisions_append_only "
        "ON engineering_datasheet_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_revisions_head "
        "ON engineering_datasheet_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheet_revisions_integrity "
        "ON engineering_datasheet_revisions"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheets_delete_prohibited "
        "ON engineering_datasheets"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheets_head_integrity "
        "ON engineering_datasheets"
    )
    op.execute(
        "DROP TRIGGER trg_engineering_datasheets_identity_immutable "
        "ON engineering_datasheets"
    )
    op.execute("DROP FUNCTION phase7_110_reject_datasheet_mutation()")
    op.execute("DROP FUNCTION phase7_110_validate_datasheet_link_projection()")
    op.execute("DROP FUNCTION phase7_110_validate_datasheet_calculation_link()")
    op.execute("DROP FUNCTION phase7_110_validate_inserted_datasheet_revision()")
    op.execute("DROP FUNCTION phase7_110_validate_datasheet_head()")
    op.execute("DROP FUNCTION phase7_110_validate_datasheet_revision()")
    op.execute("DROP FUNCTION phase7_110_guard_datasheet_head_update()")

    op.drop_index(
        "ix_engineering_datasheet_calculation_links_run",
        table_name="engineering_datasheet_calculation_links",
    )
    op.drop_table("engineering_datasheet_calculation_links")
    op.drop_index(
        "ix_engineering_datasheet_revisions_design_revision",
        table_name="engineering_datasheet_revisions",
    )
    op.drop_index(
        "ix_engineering_datasheet_revisions_sheet_created",
        table_name="engineering_datasheet_revisions",
    )
    op.drop_table("engineering_datasheet_revisions")
    op.drop_index(
        "ix_engineering_datasheets_template",
        table_name="engineering_datasheets",
    )
    op.drop_index(
        "ix_engineering_datasheets_case_updated",
        table_name="engineering_datasheets",
    )
    op.drop_table("engineering_datasheets")
