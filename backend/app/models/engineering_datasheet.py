"""Durable Step 110 engineering datasheet identities and revisions.

Only the datasheet head is mutable through compare-and-swap.  Revision and
calculation-link rows are append-only projections of validated domain records.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    Uuid,
    event,
    func,
    inspect as sqlalchemy_inspect,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.models.design_case import AppendOnlyRecordMutationError

if TYPE_CHECKING:
    from app.models.calculation_run import CalculationRun
    from app.models.design_case import DesignCase, DesignCaseRevision


_JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")
_UNVERIFIED_CREATOR_ORIGIN = "caller_supplied_unverified"
_UNAPPROVED = "unapproved"


class EngineeringDatasheet(Base):
    """Stable identity and controlled current-revision head."""

    __tablename__ = "engineering_datasheets"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_engineering_datasheets"),
        CheckConstraint(
            "length(template_id) BETWEEN 2 AND 100 AND template_id = trim(template_id)",
            name="ck_engineering_datasheets_template_id",
        ),
        CheckConstraint(
            "length(template_version) BETWEEN 3 AND 64 "
            "AND template_version = trim(template_version)",
            name="ck_engineering_datasheets_template_version",
        ),
        CheckConstraint(
            "length(template_fingerprint) = 64 AND "
            "template_fingerprint = lower(template_fingerprint)",
            name="ck_engineering_datasheets_template_fingerprint",
        ),
        CheckConstraint(
            "current_revision BETWEEN 1 AND 100",
            name="ck_engineering_datasheets_current_revision",
        ),
        CheckConstraint(
            "length(current_revision_fingerprint) = 64 AND "
            "current_revision_fingerprint = "
            "lower(current_revision_fingerprint)",
            name="ck_engineering_datasheets_head_fingerprint",
        ),
        CheckConstraint(
            "concurrency_version = current_revision",
            name="ck_engineering_datasheets_concurrency_revision",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="ck_engineering_datasheets_timestamp_order",
        ),
        CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 AND created_by = trim(created_by)",
            name="ck_engineering_datasheets_created_by",
        ),
        CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_engineering_datasheets_creator_origin",
        ),
        Index(
            "ix_engineering_datasheets_case_updated",
            "design_case_id",
            "updated_at",
        ),
        Index(
            "ix_engineering_datasheets_template",
            "template_id",
            "template_version",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    design_case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "design_cases.id",
            name="fk_engineering_datasheets_design_case_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    template_id: Mapped[str] = mapped_column(String(100), nullable=False)
    template_version: Mapped[str] = mapped_column(String(64), nullable=False)
    template_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    current_revision: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    current_revision_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    concurrency_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    created_by: Mapped[str] = mapped_column(String(300), nullable=False)
    creator_origin: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=_UNVERIFIED_CREATOR_ORIGIN,
        server_default=text("'caller_supplied_unverified'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=func.now(),
    )

    design_case: Mapped[DesignCase] = relationship()
    revisions: Mapped[list[EngineeringDatasheetRevision]] = relationship(
        back_populates="datasheet",
        cascade="save-update, merge",
        passive_deletes=True,
        order_by="EngineeringDatasheetRevision.revision_number",
    )

    __mapper_args__ = {"version_id_col": concurrency_version}


class EngineeringDatasheetRevision(Base):
    """One immutable, fully attributed, complete datasheet revision."""

    __tablename__ = "engineering_datasheet_revisions"
    __table_args__ = (
        PrimaryKeyConstraint(
            "id",
            name="pk_engineering_datasheet_revisions",
        ),
        UniqueConstraint(
            "datasheet_id",
            "revision_number",
            name="uq_engineering_datasheet_revisions_sheet_revision",
        ),
        UniqueConstraint(
            "prior_revision_id",
            name="uq_engineering_datasheet_revisions_prior_revision",
        ),
        CheckConstraint(
            "revision_number BETWEEN 1 AND 100",
            name="ck_engineering_datasheet_revisions_number",
        ),
        CheckConstraint(
            "design_revision_number >= 1",
            name="ck_engineering_datasheet_revisions_design_revision_number",
        ),
        CheckConstraint(
            "length(design_revision_fingerprint) = 64 AND "
            "design_revision_fingerprint = "
            "lower(design_revision_fingerprint)",
            name="ck_engineering_datasheet_revisions_design_fingerprint",
        ),
        CheckConstraint(
            "((revision_number = 1 AND prior_revision_id IS NULL) OR "
            "(revision_number > 1 AND prior_revision_id IS NOT NULL))",
            name="ck_engineering_datasheet_revisions_prior_presence",
        ),
        CheckConstraint(
            "((prior_revision_id IS NULL AND "
            "prior_revision_fingerprint IS NULL) OR "
            "(prior_revision_id IS NOT NULL AND "
            "prior_revision_fingerprint IS NOT NULL))",
            name="ck_engineering_datasheet_revisions_prior_fingerprint_presence",
        ),
        CheckConstraint(
            "prior_revision_id IS NULL OR prior_revision_id <> id",
            name="ck_engineering_datasheet_revisions_prior_not_self",
        ),
        CheckConstraint(
            "length(snapshot_schema) BETWEEN 2 AND 160 "
            "AND snapshot_schema = trim(snapshot_schema)",
            name="ck_engineering_datasheet_revisions_snapshot_schema",
        ),
        CheckConstraint(
            "length(snapshot_version) BETWEEN 3 AND 64 "
            "AND snapshot_version = trim(snapshot_version)",
            name="ck_engineering_datasheet_revisions_snapshot_version",
        ),
        CheckConstraint(
            "length(revision_fingerprint) = 64 AND "
            "revision_fingerprint = lower(revision_fingerprint)",
            name="ck_engineering_datasheet_revisions_fingerprint",
        ),
        CheckConstraint(
            "prior_revision_fingerprint IS NULL OR "
            "(length(prior_revision_fingerprint) = 64 AND "
            "prior_revision_fingerprint = "
            "lower(prior_revision_fingerprint))",
            name="ck_engineering_datasheet_revisions_prior_fingerprint",
        ),
        CheckConstraint(
            "length(change_reason) BETWEEN 1 AND 1000 "
            "AND change_reason = trim(change_reason)",
            name="ck_engineering_datasheet_revisions_change_reason",
        ),
        CheckConstraint(
            "lifecycle_state IN ('draft', 'under_review', 'on_hold', 'archived')",
            name="ck_engineering_datasheet_revisions_lifecycle",
        ),
        CheckConstraint(
            "completeness_state IN ('complete', 'complete_with_open_items', "
            "'incomplete', 'blocked')",
            name="ck_engineering_datasheet_revisions_completeness",
        ),
        CheckConstraint(
            "approval_state = 'unapproved'",
            name="ck_engineering_datasheet_revisions_approval",
        ),
        CheckConstraint(
            "final_design_approval_granted = false",
            name="ck_engineering_datasheet_revisions_no_final_approval",
        ),
        CheckConstraint(
            "standards_conformity_claimed = false",
            name="ck_engineering_datasheet_revisions_no_conformity",
        ),
        CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 AND created_by = trim(created_by)",
            name="ck_engineering_datasheet_revisions_created_by",
        ),
        CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_engineering_datasheet_revisions_creator_origin",
        ),
        CheckConstraint(
            "length(json_artifact) BETWEEN 1 AND 8388608",
            name="ck_engineering_datasheet_revisions_json_artifact_size",
        ),
        CheckConstraint(
            "length(workbook_artifact) BETWEEN 1 AND 8388608",
            name="ck_engineering_datasheet_revisions_workbook_artifact_size",
        ),
        Index(
            "ix_engineering_datasheet_revisions_sheet_created",
            "datasheet_id",
            "created_at",
        ),
        Index(
            "ix_engineering_datasheet_revisions_design_revision",
            "design_case_revision_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    datasheet_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "engineering_datasheets.id",
            name="fk_engineering_datasheet_revisions_datasheet_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    design_case_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "design_case_revisions.id",
            name="fk_engineering_datasheet_revisions_design_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    design_revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    design_revision_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_revision_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "engineering_datasheet_revisions.id",
            name="fk_engineering_datasheet_revisions_prior_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    prior_revision_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    snapshot_schema: Mapped[str] = mapped_column(String(160), nullable=False)
    snapshot_version: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    export_descriptor: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    json_artifact: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        deferred=True,
        deferred_group="datasheet_artifacts",
    )
    workbook_artifact: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        deferred=True,
        deferred_group="datasheet_artifacts",
    )
    revision_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    change_reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    completeness_state: Mapped[str] = mapped_column(String(40), nullable=False)
    ready_for_review: Mapped[bool] = mapped_column(Boolean, nullable=False)
    approval_state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=_UNAPPROVED,
        server_default=text("'unapproved'"),
    )
    final_design_approval_granted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    standards_conformity_claimed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    created_by: Mapped[str] = mapped_column(String(300), nullable=False)
    creator_origin: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=_UNVERIFIED_CREATOR_ORIGIN,
        server_default=text("'caller_supplied_unverified'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    datasheet: Mapped[EngineeringDatasheet] = relationship(
        back_populates="revisions",
        foreign_keys=[datasheet_id],
    )
    design_case_revision: Mapped[DesignCaseRevision] = relationship()
    prior_revision: Mapped[EngineeringDatasheetRevision | None] = relationship(
        remote_side=[id],
        foreign_keys=[prior_revision_id],
        back_populates="next_revision",
    )
    next_revision: Mapped[EngineeringDatasheetRevision | None] = relationship(
        foreign_keys=[prior_revision_id],
        back_populates="prior_revision",
        uselist=False,
    )
    calculation_links: Mapped[list[EngineeringDatasheetCalculationLink]] = relationship(
        back_populates="datasheet_revision",
        cascade="save-update, merge",
        passive_deletes=True,
        order_by="EngineeringDatasheetCalculationLink.link_id",
    )


class EngineeringDatasheetCalculationLink(Base):
    """Immutable foreign-key projection for one verified calculation link."""

    __tablename__ = "engineering_datasheet_calculation_links"
    __table_args__ = (
        PrimaryKeyConstraint(
            "datasheet_revision_id",
            "link_id",
            name="pk_engineering_datasheet_calculation_links",
        ),
        UniqueConstraint(
            "datasheet_revision_id",
            "run_id",
            "output_id",
            name="uq_engineering_datasheet_calculation_links_output",
        ),
        CheckConstraint(
            "length(link_id) BETWEEN 2 AND 100 AND link_id = trim(link_id)",
            name="ck_engineering_datasheet_calculation_links_id",
        ),
        CheckConstraint(
            "length(output_id) BETWEEN 2 AND 100 AND output_id = trim(output_id)",
            name="ck_engineering_datasheet_calculation_links_output_id",
        ),
        CheckConstraint(
            "length(run_fingerprint) = 64 AND run_fingerprint = lower(run_fingerprint)",
            name="ck_engineering_datasheet_calculation_links_run_fingerprint",
        ),
        CheckConstraint(
            "length(result_fingerprint) = 64 AND "
            "result_fingerprint = lower(result_fingerprint)",
            name="ck_engineering_datasheet_calculation_links_result_fingerprint",
        ),
        Index(
            "ix_engineering_datasheet_calculation_links_run",
            "run_id",
        ),
    )

    datasheet_revision_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "engineering_datasheet_revisions.id",
            name="fk_engineering_datasheet_calculation_links_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    link_id: Mapped[str] = mapped_column(String(100), nullable=False)
    run_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "calculation_runs.id",
            name="fk_engineering_datasheet_calculation_links_run_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    output_id: Mapped[str] = mapped_column(String(100), nullable=False)
    run_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    result_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    datasheet_revision: Mapped[EngineeringDatasheetRevision] = relationship(
        back_populates="calculation_links"
    )
    calculation_run: Mapped[CalculationRun] = relationship()


_DATASHEET_MUTABLE_HEAD_COLUMNS = frozenset(
    {
        "current_revision",
        "current_revision_fingerprint",
        "concurrency_version",
        "updated_at",
    }
)


def _reject_datasheet_identity_update(
    _mapper: object,
    _connection: object,
    target: EngineeringDatasheet,
) -> None:
    state = sqlalchemy_inspect(target)
    changed = tuple(
        column.key
        for column in target.__table__.columns
        if column.key not in _DATASHEET_MUTABLE_HEAD_COLUMNS
        and state.attrs[column.key].history.has_changes()
    )
    if changed:
        raise AppendOnlyRecordMutationError(
            "Datasheet identity is immutable; only its controlled head may change."
        )


def _reject_append_only_update(
    _mapper: object,
    _connection: object,
    target: EngineeringDatasheetRevision | EngineeringDatasheetCalculationLink,
) -> None:
    state = sqlalchemy_inspect(target)
    if not any(
        state.attrs[column.key].history.has_changes()
        for column in target.__table__.columns
    ):
        return
    raise AppendOnlyRecordMutationError(
        "Datasheet revisions and calculation links are append-only."
    )


def _reject_datasheet_delete(
    _mapper: object,
    _connection: object,
    _target: object,
) -> None:
    raise AppendOnlyRecordMutationError(
        "Datasheet records are controlled and cannot be deleted."
    )


event.listen(
    EngineeringDatasheet,
    "before_update",
    _reject_datasheet_identity_update,
    propagate=True,
)
for model in (
    EngineeringDatasheet,
    EngineeringDatasheetRevision,
    EngineeringDatasheetCalculationLink,
):
    event.listen(
        model,
        "before_delete",
        _reject_datasheet_delete,
        propagate=True,
    )
for model in (
    EngineeringDatasheetRevision,
    EngineeringDatasheetCalculationLink,
):
    event.listen(
        model,
        "before_update",
        _reject_append_only_update,
        propagate=True,
    )


__all__ = [
    "EngineeringDatasheet",
    "EngineeringDatasheetCalculationLink",
    "EngineeringDatasheetRevision",
]
