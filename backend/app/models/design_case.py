"""Persistent Phase 7 engineering design-case records.

The design-case row is a mutable compare-and-swap head.  Every engineering
snapshot lives in an immutable revision row so a changed fact, assumption, or
approval state never overwrites historical evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID
from uuid import uuid4

from sqlalchemy import Boolean
from sqlalchemy import CheckConstraint
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy import String
from sqlalchemy import UniqueConstraint
from sqlalchemy import Uuid
from sqlalchemy import event
from sqlalchemy import func
from sqlalchemy import inspect as sqlalchemy_inspect
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.calculation_run import CalculationRun


_JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")
_UNVERIFIED_CREATOR_ORIGIN = "caller_supplied_unverified"
_UNAPPROVED = "unapproved"


class AppendOnlyRecordMutationError(RuntimeError):
    """Raised before the ORM can mutate an append-only record."""


class DesignCase(Base):
    """Stable identity and compare-and-swap head for one design case."""

    __tablename__ = "design_cases"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_design_cases"),
        UniqueConstraint(
            "case_reference",
            name="uq_design_cases_case_reference",
        ),
        CheckConstraint(
            "length(case_reference) BETWEEN 2 AND 160 "
            "AND case_reference = trim(case_reference)",
            name="ck_design_cases_case_reference",
        ),
        CheckConstraint(
            "length(case_type) BETWEEN 2 AND 100 "
            "AND case_type = trim(case_type)",
            name="ck_design_cases_case_type",
        ),
        CheckConstraint(
            "current_revision >= 1",
            name="ck_design_cases_current_revision_positive",
        ),
        CheckConstraint(
            "current_revision_fingerprint IS NOT NULL",
            name="ck_design_cases_head_fingerprint_presence",
        ),
        CheckConstraint(
            "length(current_revision_fingerprint) = 64 AND "
            "current_revision_fingerprint = "
            "lower(current_revision_fingerprint)",
            name="ck_design_cases_head_fingerprint",
        ),
        CheckConstraint(
            "concurrency_version >= 1",
            name="ck_design_cases_concurrency_version_positive",
        ),
        CheckConstraint(
            "concurrency_version = current_revision",
            name="ck_design_cases_concurrency_matches_revision",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="ck_design_cases_timestamp_order",
        ),
        CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_design_cases_created_by",
        ),
        CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_design_cases_creator_origin",
        ),
        Index("ix_design_cases_case_type", "case_type"),
        Index("ix_design_cases_updated_at", "updated_at"),
        Index(
            "uq_design_cases_case_reference_ci",
            text("lower(case_reference)"),
            unique=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    case_reference: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    case_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
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

    revisions: Mapped[list[DesignCaseRevision]] = relationship(
        back_populates="design_case",
        cascade="save-update, merge",
        passive_deletes=True,
        order_by="DesignCaseRevision.revision_number",
    )

    __mapper_args__ = {
        "version_id_col": concurrency_version,
    }


class DesignCaseRevision(Base):
    """One immutable, fully attributed design-case snapshot."""

    __tablename__ = "design_case_revisions"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_design_case_revisions"),
        UniqueConstraint(
            "design_case_id",
            "revision_number",
            name="uq_design_case_revisions_case_revision",
        ),
        UniqueConstraint(
            "prior_revision_id",
            name="uq_design_case_revisions_prior_revision",
        ),
        CheckConstraint(
            "revision_number >= 1",
            name="ck_design_case_revisions_revision_positive",
        ),
        CheckConstraint(
            "((revision_number = 1 AND prior_revision_id IS NULL) OR "
            "(revision_number > 1 AND prior_revision_id IS NOT NULL))",
            name="ck_design_case_revisions_prior_presence",
        ),
        CheckConstraint(
            "((prior_revision_id IS NULL AND "
            "prior_revision_fingerprint IS NULL) OR "
            "(prior_revision_id IS NOT NULL AND "
            "prior_revision_fingerprint IS NOT NULL))",
            name="ck_design_case_revisions_prior_fingerprint_presence",
        ),
        CheckConstraint(
            "prior_revision_id IS NULL OR prior_revision_id <> id",
            name="ck_design_case_revisions_prior_not_self",
        ),
        CheckConstraint(
            "length(revision_fingerprint) = 64 AND "
            "revision_fingerprint = lower(revision_fingerprint)",
            name="ck_design_case_revisions_fingerprint",
        ),
        CheckConstraint(
            "prior_revision_fingerprint IS NULL OR "
            "(length(prior_revision_fingerprint) = 64 AND "
            "prior_revision_fingerprint = lower(prior_revision_fingerprint))",
            name="ck_design_case_revisions_prior_fingerprint",
        ),
        CheckConstraint(
            "length(change_reason) BETWEEN 1 AND 1000 "
            "AND change_reason = trim(change_reason)",
            name="ck_design_case_revisions_change_reason",
        ),
        CheckConstraint(
            "length(payload_schema) BETWEEN 2 AND 160 "
            "AND payload_schema = trim(payload_schema)",
            name="ck_design_case_revisions_payload_schema",
        ),
        CheckConstraint(
            "length(payload_version) BETWEEN 3 AND 64 "
            "AND payload_version = trim(payload_version)",
            name="ck_design_case_revisions_payload_version",
        ),
        CheckConstraint(
            "approval_state = 'unapproved'",
            name="ck_design_case_revisions_approval_unapproved",
        ),
        CheckConstraint(
            "final_design_approval_granted = false",
            name="ck_design_case_revisions_no_final_approval",
        ),
        CheckConstraint(
            "length(created_by) BETWEEN 1 AND 300 "
            "AND created_by = trim(created_by)",
            name="ck_design_case_revisions_created_by",
        ),
        CheckConstraint(
            "creator_origin = 'caller_supplied_unverified'",
            name="ck_design_case_revisions_creator_origin",
        ),
        Index(
            "ix_design_case_revisions_case_created_at",
            "design_case_id",
            "created_at",
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
            name="fk_design_case_revisions_design_case_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    revision_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    prior_revision_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "design_case_revisions.id",
            name="fk_design_case_revisions_prior_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    prior_revision_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    change_reason: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    payload_schema: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    payload_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    snapshot: Mapped[dict[str, object]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    source_origins: Mapped[list[dict[str, object]]] = mapped_column(
        _JSON_DOCUMENT,
        nullable=False,
    )
    revision_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    design_case: Mapped[DesignCase] = relationship(
        back_populates="revisions",
        foreign_keys=[design_case_id],
    )
    prior_revision: Mapped[DesignCaseRevision | None] = relationship(
        remote_side=[id],
        foreign_keys=[prior_revision_id],
        back_populates="next_revision",
    )
    next_revision: Mapped[DesignCaseRevision | None] = relationship(
        foreign_keys=[prior_revision_id],
        back_populates="prior_revision",
        uselist=False,
    )
    calculation_runs: Mapped[list[CalculationRun]] = relationship(
        back_populates="design_case_revision",
        cascade="save-update, merge",
        passive_deletes=True,
        order_by="CalculationRun.created_at",
    )


_DESIGN_CASE_MUTABLE_HEAD_COLUMNS = frozenset(
    {
        "current_revision",
        "current_revision_fingerprint",
        "concurrency_version",
        "updated_at",
    }
)


def _reject_design_case_identity_update(
    _mapper: object,
    _connection: object,
    target: DesignCase,
) -> None:
    """Permit only compare-and-swap head fields to change in the ORM."""

    state = sqlalchemy_inspect(target)
    changed_identity_columns = tuple(
        column.key
        for column in target.__table__.columns
        if column.key not in _DESIGN_CASE_MUTABLE_HEAD_COLUMNS
        and state.attrs[column.key].history.has_changes()
    )
    if changed_identity_columns:
        raise AppendOnlyRecordMutationError(
            "Design-case identity is immutable; only the controlled revision "
            "head may change."
        )


def _reject_revision_update(
    _mapper: object,
    _connection: object,
    _target: DesignCaseRevision,
) -> None:
    state = sqlalchemy_inspect(_target)
    if not any(
        state.attrs[column.key].history.has_changes()
        for column in _target.__table__.columns
    ):
        return
    raise AppendOnlyRecordMutationError(
        "Design-case revisions are append-only; create a new revision instead."
    )


def _reject_revision_delete(
    _mapper: object,
    _connection: object,
    _target: DesignCaseRevision,
) -> None:
    raise AppendOnlyRecordMutationError(
        "Design-case revisions are append-only and cannot be deleted."
    )


event.listen(
    DesignCase,
    "before_update",
    _reject_design_case_identity_update,
    propagate=True,
)
event.listen(
    DesignCaseRevision,
    "before_update",
    _reject_revision_update,
    propagate=True,
)
event.listen(
    DesignCaseRevision,
    "before_delete",
    _reject_revision_delete,
    propagate=True,
)


__all__ = [
    "AppendOnlyRecordMutationError",
    "DesignCase",
    "DesignCaseRevision",
]
