"""Append-only Phase 7 calculation and analyzer-assessment run records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID
from uuid import uuid4

from sqlalchemy import CheckConstraint
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import JSON
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy import String
from sqlalchemy import Uuid
from sqlalchemy import UniqueConstraint
from sqlalchemy import event
from sqlalchemy import inspect as sqlalchemy_inspect
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.design_case import AppendOnlyRecordMutationError
from app.models.design_case import DesignCaseRevision


_JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")
_UNVERIFIED_CREATOR_ORIGIN = "caller_supplied_unverified"
_CALCULATION_STATUSES = (
    "'completed', 'completed_with_warnings', 'blocked', "
    "'insufficient_input', 'not_applicable', 'failed'"
)


class CalculationRun(Base):
    """Immutable request/result evidence for one controlled execution."""

    __tablename__ = "calculation_runs"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_calculation_runs"),
        CheckConstraint(
            "run_kind IN ('calculation', 'analyzer_assessment')",
            name="ck_calculation_runs_run_kind",
        ),
        CheckConstraint(
            f"status IN ({_CALCULATION_STATUSES})",
            name="ck_calculation_runs_status",
        ),
        CheckConstraint(
            "supersedes_run_id IS NULL OR supersedes_run_id <> id",
            name="ck_calculation_runs_supersedes_not_self",
        ),
        UniqueConstraint(
            "supersedes_run_id",
            name="uq_calculation_runs_supersedes_run_id",
        ),
        CheckConstraint(
            "((design_case_revision_id IS NULL AND "
            "design_revision_fingerprint IS NULL) OR "
            "(design_case_revision_id IS NOT NULL AND "
            "design_revision_fingerprint IS NOT NULL))",
            name="ck_calculation_runs_revision_fingerprint_presence",
        ),
        CheckConstraint(
            "((supersedes_run_id IS NULL AND "
            "supersedes_run_fingerprint IS NULL) OR "
            "(supersedes_run_id IS NOT NULL AND "
            "supersedes_run_fingerprint IS NOT NULL))",
            name="ck_calculation_runs_prior_fingerprint_presence",
        ),
        CheckConstraint(
            "length(calculation_type) BETWEEN 2 AND 100 "
            "AND calculation_type = trim(calculation_type)",
            name="ck_calculation_runs_calculation_type",
        ),
        CheckConstraint(
            "length(method_id) BETWEEN 2 AND 160 "
            "AND method_id = trim(method_id)",
            name="ck_calculation_runs_method_id",
        ),
        CheckConstraint(
            "length(method_version) BETWEEN 3 AND 64 "
            "AND method_version = trim(method_version)",
            name="ck_calculation_runs_method_version",
        ),
        CheckConstraint(
            "length(executor_id) BETWEEN 2 AND 100 "
            "AND executor_id = trim(executor_id)",
            name="ck_calculation_runs_executor_id",
        ),
        CheckConstraint(
            "length(executor_version) BETWEEN 3 AND 64 "
            "AND executor_version = trim(executor_version)",
            name="ck_calculation_runs_executor_version",
        ),
        CheckConstraint(
            "length(request_schema) BETWEEN 2 AND 160 "
            "AND request_schema = trim(request_schema)",
            name="ck_calculation_runs_request_schema",
        ),
        CheckConstraint(
            "length(result_schema) BETWEEN 2 AND 160 "
            "AND result_schema = trim(result_schema)",
            name="ck_calculation_runs_result_schema",
        ),
        CheckConstraint(
            "length(input_fingerprint) = 64 AND "
            "input_fingerprint = lower(input_fingerprint)",
            name="ck_calculation_runs_input_fingerprint",
        ),
        CheckConstraint(
            "length(result_fingerprint) = 64 AND "
            "result_fingerprint = lower(result_fingerprint)",
            name="ck_calculation_runs_result_fingerprint",
        ),
        CheckConstraint(
            "length(run_fingerprint) = 64 AND "
            "run_fingerprint = lower(run_fingerprint)",
            name="ck_calculation_runs_run_fingerprint",
        ),
        CheckConstraint(
            "design_revision_fingerprint IS NULL OR "
            "(length(design_revision_fingerprint) = 64 AND "
            "design_revision_fingerprint = lower(design_revision_fingerprint))",
            name="ck_calculation_runs_revision_fingerprint",
        ),
        CheckConstraint(
            "supersedes_run_fingerprint IS NULL OR "
            "(length(supersedes_run_fingerprint) = 64 AND "
            "supersedes_run_fingerprint = lower(supersedes_run_fingerprint))",
            name="ck_calculation_runs_prior_fingerprint",
        ),
        CheckConstraint(
            "length(canonicalization) BETWEEN 3 AND 64 "
            "AND canonicalization = trim(canonicalization)",
            name="ck_calculation_runs_canonicalization",
        ),
        CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_calculation_runs_created_by",
        ),
        CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_calculation_runs_creator_origin",
        ),
        Index(
            "ix_calculation_runs_revision_created_at",
            "design_case_revision_id",
            "created_at",
        ),
        Index(
            "ix_calculation_runs_method_identity",
            "method_id",
            "method_version",
        ),
        Index(
            "ix_calculation_runs_run_kind_status",
            "run_kind",
            "status",
        ),
        Index(
            "ix_calculation_runs_supersedes_run_id",
            "supersedes_run_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    run_kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    design_case_revision_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "design_case_revisions.id",
            name="fk_calculation_runs_design_case_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    supersedes_run_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "calculation_runs.id",
            name="fk_calculation_runs_supersedes_run_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    design_revision_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    supersedes_run_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    calculation_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    method_id: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    method_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    executor_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    executor_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    request_schema: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    result_schema: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    request_payload: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    result_payload: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    execution_metadata: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    input_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    result_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    run_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    canonicalization: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    created_by: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )
    creator_origin: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=_UNVERIFIED_CREATOR_ORIGIN,
        server_default=text("'caller_supplied_unverified'"),
    )
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    design_case_revision: Mapped[DesignCaseRevision | None] = relationship(
        back_populates="calculation_runs",
        foreign_keys=[design_case_revision_id],
    )
    supersedes_run: Mapped[CalculationRun | None] = relationship(
        remote_side=[id],
        foreign_keys=[supersedes_run_id],
        back_populates="superseded_by_runs",
    )
    superseded_by_runs: Mapped[list[CalculationRun]] = relationship(
        foreign_keys=[supersedes_run_id],
        back_populates="supersedes_run",
        cascade="save-update, merge",
        passive_deletes=True,
    )


def _reject_run_update(
    _mapper: object,
    _connection: object,
    _target: CalculationRun,
) -> None:
    state = sqlalchemy_inspect(_target)
    if not any(
        state.attrs[column.key].history.has_changes()
        for column in _target.__table__.columns
    ):
        return
    raise AppendOnlyRecordMutationError(
        "Calculation runs are append-only; create a new linked run instead."
    )


def _reject_run_delete(
    _mapper: object,
    _connection: object,
    _target: CalculationRun,
) -> None:
    raise AppendOnlyRecordMutationError(
        "Calculation runs are append-only and cannot be deleted."
    )


event.listen(
    CalculationRun,
    "before_update",
    _reject_run_update,
    propagate=True,
)
event.listen(
    CalculationRun,
    "before_delete",
    _reject_run_delete,
    propagate=True,
)


__all__ = ["CalculationRun"]
